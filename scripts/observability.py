#!/usr/bin/env python3
"""Collect observability preflight data and summarize capture reports."""

from __future__ import annotations

import argparse
import csv
import math
import os
import platform
import re
import shutil
import subprocess
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
    "dns.flags.response",
    "dns.qry.type",
)

LEGACY_DNS_FIELDS = DNS_FIELDS[:9]

COMMANDS = (
    "sudo",
    "tcpdump",
    "tshark",
    "tcptop-bpfcc",
    "tcplife-bpfcc",
    "syscount-bpfcc",
    "memleak-bpfcc",
    "bpftrace",
)

TIMESTAMP_RE = re.compile(r"^\d{2}:\d{2}:\d{2}\b")


def path_status(value: str) -> dict[str, Any]:
    path = Path(value)
    try:
        exists = path.exists()
    except OSError as exc:
        return {"exists": None, "readable": False, "error": f"{type(exc).__name__}: {exc}"}

    readable = False
    error = None
    if exists:
        try:
            path.stat()
            readable = os.access(path, os.R_OK)
        except OSError as exc:
            error = f"{type(exc).__name__}: {exc}"
    return {"exists": exists, "readable": readable, "error": error}


def command_version(command: str) -> str | None:
    path = shutil.which(command)
    if path is None:
        return None
    for args in ((command, "--version"), (command, "-V"), (command, "-h")):
        try:
            completed = subprocess.run(
                list(args),
                text=True,
                capture_output=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        output = "\n".join(part for part in (completed.stdout, completed.stderr) if part).strip()
        if output:
            return output.splitlines()[0][:240]
    return None


def sudo_non_interactive() -> bool:
    if shutil.which("sudo") is None:
        return False
    try:
        completed = subprocess.run(
            ["sudo", "-n", "true"],
            text=True,
            capture_output=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0


def collect_tooling_status() -> dict[str, Any]:
    commands = {}
    for command in COMMANDS:
        path = shutil.which(command)
        commands[command] = {
            "available": path is not None,
            "path": path,
            "version": command_version(command) if path else None,
        }

    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    sudo_available = sudo_non_interactive()
    can_use_privilege = is_root or sudo_available
    paths = {
        "/sys/fs/bpf": path_status("/sys/fs/bpf"),
        "/sys/kernel/debug/tracing": path_status("/sys/kernel/debug/tracing"),
        "/sys/kernel/tracing": path_status("/sys/kernel/tracing"),
    }
    required_for_packet_reports = ("tcpdump", "tshark")
    optional_bpf_reports = ("tcptop-bpfcc", "tcplife-bpfcc", "syscount-bpfcc", "memleak-bpfcc")
    missing = [command for command in required_for_packet_reports if not commands[command]["available"]]
    missing_bpf = [command for command in optional_bpf_reports if not commands[command]["available"]]

    return {
        "generatedAt": utc_now(),
        "platform": platform.platform(),
        "kernel": platform.release(),
        "isRoot": is_root,
        "sudoNonInteractive": sudo_available,
        "canUsePrivilege": can_use_privilege,
        "commands": commands,
        "kernelPaths": paths,
        "canAttemptCapture": can_use_privilege and not missing,
        "canAttemptPacketCapture": can_use_privilege and not missing,
        "canAttemptBpfCapture": can_use_privilege and not missing_bpf,
        "missingRequiredCommands": missing,
        "missingBpfCommands": missing_bpf,
        "note": "This is a non-invasive preflight; it does not start packet capture or eBPF tracing.",
    }


def write_tooling_log(path: Path, status: dict[str, Any]) -> None:
    lines = [
        f"generatedAt={status['generatedAt']}",
        f"platform={status['platform']}",
        f"kernel={status['kernel']}",
        f"isRoot={status['isRoot']}",
        f"sudoNonInteractive={status['sudoNonInteractive']}",
        f"canUsePrivilege={status['canUsePrivilege']}",
        f"canAttemptCapture={status['canAttemptCapture']}",
    ]
    if status["missingRequiredCommands"]:
        lines.append("missingRequiredCommands=" + ",".join(status["missingRequiredCommands"]))
    if status["missingBpfCommands"]:
        lines.append("missingBpfCommands=" + ",".join(status["missingBpfCommands"]))
    for command, item in status["commands"].items():
        value = item["path"] if item["available"] else "missing"
        if item.get("version"):
            value += f" ({item['version']})"
        lines.append(f"command.{command}={value}")
    for name, item in status["kernelPaths"].items():
        line = f"path.{name}.exists={item['exists']} readable={item['readable']}"
        if item.get("error"):
            line += f" error={item['error']}"
        lines.append(line)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_tooling_status(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    status = collect_tooling_status()
    write_json(output_dir / "tooling.json", status)
    write_tooling_log(output_dir / "tooling.log", status)


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


def parse_number(value: str) -> float | None:
    try:
        return float(value)
    except ValueError:
        return None


def parse_endpoint(value: str) -> tuple[str, int | None]:
    if value.count(":") == 1:
        host, port = value.rsplit(":", 1)
        try:
            return host, int(port)
        except ValueError:
            return value, None
    if value.startswith("[") and "]:" in value:
        host, port = value.rsplit("]:", 1)
        try:
            return host.removeprefix("["), int(port)
        except ValueError:
            return value, None
    return value, None


def parse_tcptop_line(line: str) -> dict[str, Any] | None:
    fields = line.split()
    if len(fields) < 6 or not fields[0].isdigit():
        return None

    rx_kb = parse_number(fields[-2])
    tx_kb = parse_number(fields[-1])
    if rx_kb is None or tx_kb is None:
        return None

    pid = int(fields[0])
    command = fields[1]
    if len(fields) >= 8 and fields[-5].isdigit() and fields[-3].isdigit():
        local = f"{fields[-6]}:{fields[-5]}"
        remote = f"{fields[-4]}:{fields[-3]}"
    else:
        local = fields[-4]
        remote = fields[-3]

    local_address, local_port = parse_endpoint(local)
    remote_address, remote_port = parse_endpoint(remote)
    return {
        "pid": pid,
        "command": command,
        "localAddress": local_address,
        "localPort": local_port,
        "remoteAddress": remote_address,
        "remotePort": remote_port,
        "rxBytes": int(rx_kb * 1024),
        "txBytes": int(tx_kb * 1024),
    }


def tcptop_flow_key(sample: dict[str, Any]) -> tuple[Any, ...]:
    return (
        sample["pid"],
        sample["command"],
        sample["localAddress"],
        sample["localPort"],
        sample["remoteAddress"],
        sample["remotePort"],
    )


def summarize_tcptop_samples(samples: list[dict[str, Any]], interval_seconds: float) -> dict[str, Any]:
    flows: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for sample in samples:
        flows[tcptop_flow_key(sample)].append(sample)

    output_flows = []
    for key, flow_samples in sorted(flows.items(), key=lambda item: tuple(str(part) for part in item[0])):
        rates = []
        for sample in flow_samples:
            rx_bps = sample["rxBytes"] / interval_seconds if interval_seconds > 0 else 0
            tx_bps = sample["txBytes"] / interval_seconds if interval_seconds > 0 else 0
            rates.append((rx_bps, tx_bps))
            sample["rxBps"] = round(rx_bps, 3)
            sample["txBps"] = round(tx_bps, 3)

        total_rx = sum(sample["rxBytes"] for sample in flow_samples)
        total_tx = sum(sample["txBytes"] for sample in flow_samples)
        output_flows.append(
            {
                "pid": key[0],
                "command": key[1],
                "localAddress": key[2],
                "localPort": key[3],
                "remoteAddress": key[4],
                "remotePort": key[5],
                "sampleCount": len(flow_samples),
                "totalRxBytes": total_rx,
                "totalTxBytes": total_tx,
                "totalBytes": total_rx + total_tx,
                "minRxBps": round(min(rate[0] for rate in rates), 3),
                "maxRxBps": round(max(rate[0] for rate in rates), 3),
                "minTxBps": round(min(rate[1] for rate in rates), 3),
                "maxTxBps": round(max(rate[1] for rate in rates), 3),
                "samples": flow_samples,
            }
        )

    total_rx = sum(flow["totalRxBytes"] for flow in output_flows)
    total_tx = sum(flow["totalTxBytes"] for flow in output_flows)
    all_rx_rates = [sample["rxBps"] for flow in output_flows for sample in flow["samples"]]
    all_tx_rates = [sample["txBps"] for flow in output_flows for sample in flow["samples"]]
    return {
        "sampleIntervalSeconds": interval_seconds,
        "sampleCount": len(samples),
        "flowCount": len(output_flows),
        "totalRxBytes": total_rx,
        "totalTxBytes": total_tx,
        "totalBytes": total_rx + total_tx,
        "minRxBps": min(all_rx_rates) if all_rx_rates else None,
        "maxRxBps": max(all_rx_rates) if all_rx_rates else None,
        "minTxBps": min(all_tx_rates) if all_tx_rates else None,
        "maxTxBps": max(all_tx_rates) if all_tx_rates else None,
        "flows": output_flows,
    }


def parse_tcptop(text: str, interval_seconds: float) -> dict[str, Any]:
    samples = []
    sample_index = 0
    current_time = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if TIMESTAMP_RE.match(line):
            sample_index += 1
            current_time = line.split()[0]
            continue
        parsed = parse_tcptop_line(line)
        if parsed is None:
            continue
        parsed["sample"] = sample_index or 1
        parsed["time"] = current_time
        samples.append(parsed)

    return summarize_tcptop_samples(samples, interval_seconds)


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
    elif header == list(LEGACY_DNS_FIELDS):
        data_rows = rows[1:]
        field_names = list(LEGACY_DNS_FIELDS)
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


def write_tcptop_summary(input_path: Path, output_path: Path, interval_seconds: float) -> None:
    summary = parse_tcptop(input_path.read_text(encoding="utf-8"), interval_seconds)
    summary["generatedAt"] = utc_now()
    summary["source"] = input_path.name
    write_json(output_path, summary)


def write_packet_summary(input_path: Path, output_path: Path, container_ips: list[str], bucket_seconds: float, dns_input: Path | None) -> None:
    dns_names_by_ip = read_dns_names_by_ip(dns_input) if dns_input else {}
    summary = summarize_packets(read_packets(input_path), container_ips, bucket_seconds, dns_names_by_ip)
    summary["generatedAt"] = utc_now()
    summary["source"] = input_path.name
    write_json(output_path, summary)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    check_parser = subparsers.add_parser("check-tools", help="write tooling.json and tooling.log")
    check_parser.add_argument("--output", required=True, help="directory for tooling.json and tooling.log")

    tcptop_parser = subparsers.add_parser("summarize-tcptop", help="summarize tcptop-bpfcc output")
    tcptop_parser.add_argument("--input", required=True, help="tcptop-bpfcc text output")
    tcptop_parser.add_argument("--output", required=True, help="JSON flow summary output")
    tcptop_parser.add_argument("--interval-seconds", type=float, default=1.0)

    packet_parser = subparsers.add_parser("summarize-packets", help="summarize tshark packet fields")
    packet_parser.add_argument("--input", required=True, help="tshark TSV packet fields")
    packet_parser.add_argument("--output", required=True, help="JSON flow summary output")
    packet_parser.add_argument("--container-ip", action="append", default=[], help="Container IP to use as local direction")
    packet_parser.add_argument("--dns-input", help="optional DNS TSV report with dns.a/dns.aaaa answer fields")
    packet_parser.add_argument("--bucket-seconds", type=float, default=1.0)
    args = parser.parse_args()

    if args.command == "check-tools":
        write_tooling_status(Path(args.output))
    elif args.command == "summarize-tcptop":
        write_tcptop_summary(Path(args.input), Path(args.output), args.interval_seconds)
    elif args.command == "summarize-packets":
        dns_input = Path(args.dns_input) if args.dns_input else None
        write_packet_summary(Path(args.input), Path(args.output), args.container_ip, args.bucket_seconds, dns_input)


if __name__ == "__main__":
    main()
