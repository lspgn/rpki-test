#!/usr/bin/env python3
"""Summarize tcptop-bpfcc output into per-flow byte and rate metrics."""

from __future__ import annotations

import argparse
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from rpki_project import utc_now, write_json


TIMESTAMP_RE = re.compile(r"^\d{2}:\d{2}:\d{2}\b")


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


def flow_key(sample: dict[str, Any]) -> tuple[Any, ...]:
    return (
        sample["pid"],
        sample["command"],
        sample["localAddress"],
        sample["localPort"],
        sample["remoteAddress"],
        sample["remotePort"],
    )


def summarize_samples(samples: list[dict[str, Any]], interval_seconds: float) -> dict[str, Any]:
    flows: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for sample in samples:
        flows[flow_key(sample)].append(sample)

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

    return summarize_samples(samples, interval_seconds)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="tcptop-bpfcc text output")
    parser.add_argument("--output", required=True, help="JSON flow summary output")
    parser.add_argument("--interval-seconds", type=float, default=1.0)
    args = parser.parse_args()

    source = Path(args.input)
    summary = parse_tcptop(source.read_text(encoding="utf-8"), args.interval_seconds)
    summary["generatedAt"] = utc_now()
    summary["source"] = source.name
    write_json(args.output, summary)


if __name__ == "__main__":
    main()
