#!/usr/bin/env python3
"""Summarize tshark packet fields into per-flow byte and rate metrics."""

from __future__ import annotations

import argparse
import csv
import math
from collections import defaultdict
from pathlib import Path
from typing import Any

from rpki_project import utc_now, write_json


FIELDS = (
    "frame.time_epoch",
    "frame.len",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "_ws.col.Protocol",
    "dns.qry.name",
)

DNS_FIELDS = (
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "udp.srcport",
    "udp.dstport",
    "dns.qry.name",
    "dns.a",
    "dns.aaaa",
    "dns.cname",
)


def parse_float(value: str) -> float | None:
    try:
        return float(value)
    except ValueError:
        return None


def parse_int(value: str) -> int | None:
    try:
        return int(value)
    except ValueError:
        return None


def first_value(value: str) -> str:
    return value.split(",", 1)[0].strip()


def split_values(value: str) -> list[str]:
    return [part.strip().rstrip(".") for part in value.split(",") if part.strip()]


def normalize_protocol(value: str, tcp_src: str, udp_src: str) -> str:
    text = value.strip().upper()
    if text in {"TCP", "UDP"}:
        return text
    if tcp_src:
        return "TCP"
    if udp_src:
        return "UDP"
    return text or "UNKNOWN"


def packet_from_row(row: dict[str, str]) -> dict[str, Any] | None:
    timestamp = parse_float(first_value(row.get("frame.time_epoch", "")))
    length = parse_int(first_value(row.get("frame.len", "")))
    if timestamp is None or length is None:
        return None

    src = first_value(row.get("ip.src", "")) or first_value(row.get("ipv6.src", ""))
    dst = first_value(row.get("ip.dst", "")) or first_value(row.get("ipv6.dst", ""))
    if not src or not dst:
        return None

    tcp_src = first_value(row.get("tcp.srcport", ""))
    tcp_dst = first_value(row.get("tcp.dstport", ""))
    udp_src = first_value(row.get("udp.srcport", ""))
    udp_dst = first_value(row.get("udp.dstport", ""))
    protocol = normalize_protocol(row.get("_ws.col.Protocol", ""), tcp_src, udp_src)

    if protocol == "TCP":
        src_port = parse_int(tcp_src)
        dst_port = parse_int(tcp_dst)
    elif protocol == "UDP":
        src_port = parse_int(udp_src)
        dst_port = parse_int(udp_dst)
    else:
        src_port = parse_int(tcp_src or udp_src)
        dst_port = parse_int(tcp_dst or udp_dst)

    return {
        "time": timestamp,
        "length": length,
        "src": src,
        "dst": dst,
        "srcPort": src_port,
        "dstPort": dst_port,
        "protocol": protocol,
        "dnsName": first_value(row.get("dns.qry.name", "")),
    }


def read_packets(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle, delimiter="\t")
        rows = list(reader)

    if not rows:
        return []

    header = rows[0]
    if header == list(FIELDS):
        data_rows = rows[1:]
        field_names = list(FIELDS)
    else:
        data_rows = rows
        field_names = list(FIELDS)

    packets = []
    for row in data_rows:
        padded = row + [""] * (len(field_names) - len(row))
        packet = packet_from_row(dict(zip(field_names, padded)))
        if packet is not None:
            packets.append(packet)
    return packets


def read_dns_names_by_ip(path: Path) -> dict[str, set[str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle, delimiter="\t")
        rows = list(reader)

    if not rows:
        return {}

    header = rows[0]
    if header == list(DNS_FIELDS):
        data_rows = rows[1:]
        field_names = list(DNS_FIELDS)
    else:
        data_rows = rows
        field_names = list(DNS_FIELDS)

    names_by_ip: dict[str, set[str]] = defaultdict(set)
    for row in data_rows:
        padded = row + [""] * (len(field_names) - len(row))
        item = dict(zip(field_names, padded))
        names = set(split_values(item.get("dns.qry.name", "")))
        names.update(split_values(item.get("dns.cname", "")))
        if not names:
            continue
        for address in split_values(item.get("dns.a", "")):
            names_by_ip[address].update(names)
        for address in split_values(item.get("dns.aaaa", "")):
            names_by_ip[address].update(names)
    return dict(names_by_ip)


def flow_identity(packet: dict[str, Any], container_ips: set[str]) -> dict[str, Any] | None:
    src_is_local = packet["src"] in container_ips
    dst_is_local = packet["dst"] in container_ips

    if container_ips and not src_is_local and not dst_is_local:
        return None

    if src_is_local or not container_ips:
        return {
            "direction": "tx",
            "localAddress": packet["src"],
            "localPort": packet["srcPort"],
            "remoteAddress": packet["dst"],
            "remotePort": packet["dstPort"],
        }
    return {
        "direction": "rx",
        "localAddress": packet["dst"],
        "localPort": packet["dstPort"],
        "remoteAddress": packet["src"],
        "remotePort": packet["srcPort"],
    }


def bucket_index(timestamp: float, first_timestamp: float, bucket_seconds: float) -> int:
    if bucket_seconds <= 0:
        return 0
    return max(0, int(math.floor((timestamp - first_timestamp) / bucket_seconds)))


def summarize_packets(
    packets: list[dict[str, Any]],
    container_ips: list[str],
    bucket_seconds: float,
    dns_names_by_ip: dict[str, set[str]] | None = None,
) -> dict[str, Any]:
    local_ips = {ip for ip in container_ips if ip}
    resolved_names = dns_names_by_ip or {}
    matched_packets = []
    ignored_packets = 0
    seen = set()

    for packet in sorted(packets, key=lambda item: item["time"]):
        identity = flow_identity(packet, local_ips)
        if identity is None:
            ignored_packets += 1
            continue
        dedupe_key = (
            round(packet["time"], 6),
            packet["length"],
            packet["protocol"],
            packet["src"],
            packet["srcPort"],
            packet["dst"],
            packet["dstPort"],
        )
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        matched_packets.append((packet, identity))

    if not matched_packets:
        return {
            "bucketSeconds": bucket_seconds,
            "containerIps": sorted(local_ips),
            "packetCount": len(packets),
            "matchedPacketCount": 0,
            "ignoredPacketCount": ignored_packets,
            "flowCount": 0,
            "totalRxBytes": 0,
            "totalTxBytes": 0,
            "totalBytes": 0,
            "minRxBps": None,
            "maxRxBps": None,
            "minTxBps": None,
            "maxTxBps": None,
            "dnsNameMappingCount": sum(len(names) for names in resolved_names.values()),
            "timeSeries": [],
            "flows": [],
        }

    first_timestamp = matched_packets[0][0]["time"]
    flows: dict[tuple[Any, ...], dict[str, Any]] = {}
    timeline: dict[int, dict[str, Any]] = defaultdict(lambda: {"rxBytes": 0, "txBytes": 0, "packetCount": 0})

    for packet, identity in matched_packets:
        key = (
            packet["protocol"],
            identity["localAddress"],
            identity["localPort"],
            identity["remoteAddress"],
            identity["remotePort"],
        )
        flow = flows.setdefault(
            key,
            {
                "protocol": packet["protocol"],
                "localAddress": identity["localAddress"],
                "localPort": identity["localPort"],
                "remoteAddress": identity["remoteAddress"],
                "remotePort": identity["remotePort"],
                "packetCount": 0,
                "totalRxBytes": 0,
                "totalTxBytes": 0,
                "firstSeen": packet["time"],
                "lastSeen": packet["time"],
                "dnsNames": set(),
                "buckets": defaultdict(lambda: {"rxBytes": 0, "txBytes": 0, "packetCount": 0}),
            },
        )
        direction = identity["direction"]
        byte_key = "txBytes" if direction == "tx" else "rxBytes"
        total_key = "totalTxBytes" if direction == "tx" else "totalRxBytes"
        index = bucket_index(packet["time"], first_timestamp, bucket_seconds)

        flow["packetCount"] += 1
        flow[total_key] += packet["length"]
        flow["firstSeen"] = min(flow["firstSeen"], packet["time"])
        flow["lastSeen"] = max(flow["lastSeen"], packet["time"])
        flow["buckets"][index][byte_key] += packet["length"]
        flow["buckets"][index]["packetCount"] += 1
        if packet["dnsName"]:
            flow["dnsNames"].add(packet["dnsName"])

        timeline[index][byte_key] += packet["length"]
        timeline[index]["packetCount"] += 1

    output_flows = []
    for flow in flows.values():
        samples = []
        for index, bucket in sorted(flow["buckets"].items()):
            rx_bps = bucket["rxBytes"] / bucket_seconds if bucket_seconds > 0 else 0
            tx_bps = bucket["txBytes"] / bucket_seconds if bucket_seconds > 0 else 0
            samples.append(
                {
                    "bucket": index,
                    "startOffsetSeconds": round(index * bucket_seconds, 6),
                    "rxBytes": bucket["rxBytes"],
                    "txBytes": bucket["txBytes"],
                    "rxBps": round(rx_bps, 3),
                    "txBps": round(tx_bps, 3),
                    "packetCount": bucket["packetCount"],
                }
            )

        rx_rates = [sample["rxBps"] for sample in samples]
        tx_rates = [sample["txBps"] for sample in samples]
        total_rx = flow["totalRxBytes"]
        total_tx = flow["totalTxBytes"]
        candidate_dns_names = sorted(resolved_names.get(flow["remoteAddress"], set()))
        direct_dns_names = sorted(flow["dnsNames"])
        output_flows.append(
            {
                "protocol": flow["protocol"],
                "localAddress": flow["localAddress"],
                "localPort": flow["localPort"],
                "remoteAddress": flow["remoteAddress"],
                "remotePort": flow["remotePort"],
                "packetCount": flow["packetCount"],
                "totalRxBytes": total_rx,
                "totalTxBytes": total_tx,
                "totalBytes": total_rx + total_tx,
                "minRxBps": min(rx_rates) if rx_rates else None,
                "maxRxBps": max(rx_rates) if rx_rates else None,
                "minTxBps": min(tx_rates) if tx_rates else None,
                "maxTxBps": max(tx_rates) if tx_rates else None,
                "firstSeenEpoch": flow["firstSeen"],
                "lastSeenEpoch": flow["lastSeen"],
                "dnsNames": sorted(set(direct_dns_names).union(candidate_dns_names)),
                "directDnsNames": direct_dns_names,
                "candidateDnsNames": candidate_dns_names,
                "samples": samples,
            }
        )

    output_flows.sort(key=lambda item: (-item["totalBytes"], item["protocol"], item["remoteAddress"], item["remotePort"] or 0))

    time_series = []
    for index, bucket in sorted(timeline.items()):
        rx_bps = bucket["rxBytes"] / bucket_seconds if bucket_seconds > 0 else 0
        tx_bps = bucket["txBytes"] / bucket_seconds if bucket_seconds > 0 else 0
        time_series.append(
            {
                "bucket": index,
                "startOffsetSeconds": round(index * bucket_seconds, 6),
                "rxBytes": bucket["rxBytes"],
                "txBytes": bucket["txBytes"],
                "rxBps": round(rx_bps, 3),
                "txBps": round(tx_bps, 3),
                "packetCount": bucket["packetCount"],
            }
        )

    total_rx = sum(flow["totalRxBytes"] for flow in output_flows)
    total_tx = sum(flow["totalTxBytes"] for flow in output_flows)
    rx_rates = [sample["rxBps"] for sample in time_series]
    tx_rates = [sample["txBps"] for sample in time_series]
    return {
        "bucketSeconds": bucket_seconds,
        "containerIps": sorted(local_ips),
        "packetCount": len(packets),
        "matchedPacketCount": len(matched_packets),
        "ignoredPacketCount": ignored_packets,
        "flowCount": len(output_flows),
        "totalRxBytes": total_rx,
        "totalTxBytes": total_tx,
        "totalBytes": total_rx + total_tx,
        "minRxBps": min(rx_rates) if rx_rates else None,
        "maxRxBps": max(rx_rates) if rx_rates else None,
        "minTxBps": min(tx_rates) if tx_rates else None,
        "maxTxBps": max(tx_rates) if tx_rates else None,
        "dnsNameMappingCount": sum(len(names) for names in resolved_names.values()),
        "timeSeries": time_series,
        "flows": output_flows,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="tshark TSV packet fields")
    parser.add_argument("--output", required=True, help="JSON flow summary output")
    parser.add_argument("--container-ip", action="append", default=[], help="Container IP to use as local direction")
    parser.add_argument("--dns-input", help="optional DNS TSV report with dns.a/dns.aaaa answer fields")
    parser.add_argument("--bucket-seconds", type=float, default=1.0)
    args = parser.parse_args()

    source = Path(args.input)
    dns_names_by_ip = read_dns_names_by_ip(Path(args.dns_input)) if args.dns_input else {}
    summary = summarize_packets(read_packets(source), args.container_ip, args.bucket_seconds, dns_names_by_ip)
    summary["generatedAt"] = utc_now()
    summary["source"] = source.name
    write_json(args.output, summary)


if __name__ == "__main__":
    main()
