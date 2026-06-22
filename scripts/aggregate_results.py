#!/usr/bin/env python3
"""Aggregate validator artifacts into a GitHub Pages-ready static site."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shutil
import tarfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from itertools import combinations
from pathlib import Path
from typing import Any

from rpki_project import (
    PAYLOADS,
    copytree_contents,
    directory_size,
    env_int,
    file_inventory,
    payload_counts,
    payload_key,
    read_json,
    utc_now,
    write_json,
)

CHUNK_ROWS = 10000
TIMELINE_BUCKET_SECONDS = 10.0
TIMELINE_LOG_MESSAGE_BYTES = 500

BYTE_UNITS = {
    "B": 1,
    "kB": 1000,
    "KB": 1000,
    "KiB": 1024,
    "MB": 1000**2,
    "MiB": 1024**2,
    "GB": 1000**3,
    "GiB": 1024**3,
    "TB": 1000**4,
    "TiB": 1024**4,
}

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

DNS_QUERY_TYPES = {
    "1": "A",
    "2": "NS",
    "5": "CNAME",
    "6": "SOA",
    "12": "PTR",
    "15": "MX",
    "16": "TXT",
    "28": "AAAA",
    "33": "SRV",
    "43": "DS",
    "46": "RRSIG",
    "47": "NSEC",
    "48": "DNSKEY",
    "52": "TLSA",
    "64": "SVCB",
    "65": "HTTPS",
    "257": "CAA",
}


def write_compact_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, separators=(",", ":"), sort_keys=True)
        handle.write("\n")


def chunk_records(
    base_dir: Path,
    public_base: str,
    records: list[Any],
    chunk_rows: int = CHUNK_ROWS,
) -> list[dict[str, Any]]:
    chunks = []
    for index, start in enumerate(range(0, len(records), chunk_rows)):
        items = records[start : start + chunk_rows]
        path = base_dir / f"{index:04d}.json"
        write_compact_json(path, {"rows": items})
        chunks.append(
            {
                "path": f"{public_base}/{index:04d}.json",
                "rows": len(items),
                "start": start,
            }
        )
    return chunks


def find_result_dirs(results_dir: Path) -> list[Path]:
    result_dirs = set()
    skipped_pages_dirs = 0
    for path in results_dir.rglob("status.json"):
        rel_parts = path.relative_to(results_dir).parts
        if any(left == "data" and right == "runs" for left, right in zip(rel_parts, rel_parts[1:])):
            skipped_pages_dirs += 1
            continue
        result_dirs.add(path.parent)
    if skipped_pages_dirs:
        print(f"Skipped {skipped_pages_dirs} status files from downloaded Pages run trees.")
    return sorted(result_dirs)


def summarize_result_dirs(result_dirs: list[Path]) -> None:
    print(f"Found {len(result_dirs)} validator result directories.")
    ids: list[str] = []
    sources: dict[str, list[str]] = defaultdict(list)
    for result_dir in result_dirs:
        try:
            status = read_json(result_dir / "status.json")
        except Exception as exc:  # noqa: BLE001 - print useful context before the real failure later.
            print(f"  - {result_dir}: unable to read status.json: {exc}")
            continue
        entry_id = str(status.get("id", result_dir.name))
        ids.append(entry_id)
        sources[entry_id].append(result_dir.as_posix())
        print(
            "  - "
            f"{entry_id}: validator={status.get('validator', 'unknown')} "
            f"success={status.get('success', False)} source={result_dir}"
        )
    duplicates = {entry_id: count for entry_id, count in Counter(ids).items() if count > 1}
    if duplicates:
        print("Duplicate validator ids detected; later copies may overwrite earlier copied files:")
        for entry_id, count in sorted(duplicates.items()):
            print(f"  - {entry_id}: {count} copies")
            for source in sources[entry_id]:
                print(f"    {source}")


def cache_tree_from_archive(archive_path: Path, target_path: Path) -> dict[str, Any]:
    roots = ("cache", "tals")
    root_files: dict[str, list[dict[str, Any]]] = {root: [] for root in roots}
    root_sizes = {root: 0 for root in roots}
    total_files = 0
    total_size = 0

    with tarfile.open(archive_path, "r:gz") as tar:
        for member in tar:
            if not member.isfile():
                continue
            parts = Path(member.name).parts
            if len(parts) < 2 or parts[0] not in root_files:
                continue
            stream = tar.extractfile(member)
            if stream is None:
                continue
            digest = hashlib.sha256()
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
            rel = Path(*parts[1:]).as_posix()
            item = {"path": rel, "size": member.size, "sha256": digest.hexdigest()}
            root_files[parts[0]].append(item)
            root_sizes[parts[0]] += member.size
            total_files += 1
            total_size += member.size

    entries = []
    for root in roots:
        entries.append(
            {
                "root": root,
                "files": sorted(root_files[root], key=lambda item: item["path"]),
                "size": root_sizes[root],
            }
        )
    tree = {
        "roots": list(roots),
        "files": total_files,
        "size": total_size,
        "entries": entries,
        "source": {
            "path": "archives/work-cache.tar.gz",
            "size": archive_path.stat().st_size,
        },
    }
    write_json(target_path, tree)
    return {"path": "cache-tree.json", "roots": list(roots), "files": total_files, "size": total_size}


def chunk_cache_tree(tree_path: Path, public_base: str) -> dict[str, Any]:
    tree = read_json(tree_path)
    rows = []
    root_summaries = []
    for entry in tree.get("entries", []):
        root = entry.get("root")
        root_summaries.append(
            {
                "root": root,
                "files": len(entry.get("files", [])),
                "size": entry.get("size", 0),
            }
        )
        for item in entry.get("files", []):
            rows.append([root, item.get("path"), item.get("size"), item.get("sha256")])

    chunk_dir = tree_path.parent / "cache-tree"
    if chunk_dir.exists():
        shutil.rmtree(chunk_dir)
    chunks = chunk_records(chunk_dir, f"{public_base}/cache-tree", rows)
    index = {
        "roots": tree.get("roots", []),
        "files": tree.get("files", len(rows)),
        "size": tree.get("size", sum((row[2] or 0) for row in rows)),
        "rootSummaries": root_summaries,
        "source": tree.get("source"),
        "chunkRows": CHUNK_ROWS,
        "chunks": chunks,
    }
    write_compact_json(tree_path, index)
    return {"path": "cache-tree.json", "roots": index["roots"], "files": index["files"], "size": index["size"]}


def copy_result(result_dir: Path, target_dir: Path) -> dict[str, Any]:
    target_dir.mkdir(parents=True, exist_ok=True)
    for name in (
        "status.json",
        "config.json",
        "normalized.json",
        "stdout.log",
        "stderr.log",
        "log-events.json",
        "cache-tree.json",
        "resource-usage.json",
        "docker-stats.jsonl",
    ):
        source = result_dir / name
        if source.exists():
            shutil.copy2(source, target_dir / name)
    if not (target_dir / "cache-tree.json").exists():
        archive_path = result_dir / "archives" / "work-cache.tar.gz"
        if archive_path.exists():
            print(f"Deriving cache-tree.json from {archive_path}")
            cache_tree_from_archive(archive_path, target_dir / "cache-tree.json")
    ebpf_out = target_dir / "ebpf"
    for name in (
        "tooling.json",
        "tooling.log",
        "capture-status.json",
        "capture.log",
        "tcpdump.log",
        "network-tcpdump.log",
        "dns-queries.tsv",
        "network-flows.json",
        "tcp-bps.log",
        "tcp-flows.json",
        "tcp-life.log",
        "syscalls.log",
        "memory-allocations.log",
    ):
        source = result_dir / "ebpf" / name
        if source.exists():
            ebpf_out.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, ebpf_out / name)
    for source in sorted(result_dir.glob("*.log")):
        if source.name not in {"stdout.log", "stderr.log"}:
            shutil.copy2(source, target_dir / source.name)
    raw_out = target_dir / "raw"
    for source in sorted((result_dir / "raw").glob("*.json.gz")):
        raw_out.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, raw_out / source.name)
    return read_json(target_dir / "status.json")


def config_from_status(status: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": status["id"],
        "validator": status["validator"],
        "version": status["version"],
        "label": status.get("label", status["id"]),
        "image": status.get("image"),
        "timeoutSeconds": status.get("timeoutSeconds"),
        "threads": status.get("threads"),
        "payloads": status.get("payloads", {}),
        "unsupported": status.get("unsupported", []),
        "script": status.get("command"),
    }


def empty_normalized(status: dict[str, Any]) -> dict[str, Any]:
    return {
        "metadata": {
            "id": status["id"],
            "validator": status["validator"],
            "version": status["version"],
            "label": status.get("label", status["id"]),
            "image": status.get("image"),
            "generatedAt": status.get("finishedAt"),
            "payloads": status.get("payloads", {}),
            "unsupported": status.get("unsupported", []),
        },
        "routeOrigins": [],
        "routerKeys": [],
        "aspas": [],
    }


def load_normalized(result_dir: Path, status: dict[str, Any]) -> dict[str, Any]:
    path = result_dir / "normalized.json"
    if path.exists():
        return read_json(path)
    normalized = empty_normalized(status)
    write_json(path, normalized)
    return normalized


def compare_payload(payload: str, left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    left_items = {payload_key(payload, item): item for item in left.get(payload, [])}
    right_items = {payload_key(payload, item): item for item in right.get(payload, [])}
    only_left = sorted(set(left_items) - set(right_items))
    only_right = sorted(set(right_items) - set(left_items))
    return {
        "onlyLeft": len(only_left),
        "onlyRight": len(only_right),
        "sampleOnlyLeft": [left_items[key] for key in only_left[:20]],
        "sampleOnlyRight": [right_items[key] for key in only_right[:20]],
    }


def build_comparisons(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    comparisons = []
    for left, right in combinations(entries, 2):
        payloads = {}
        for payload in PAYLOADS:
            payloads[payload] = compare_payload(payload, left["normalized"], right["normalized"])
        comparisons.append(
            {
                "left": left["id"],
                "right": right["id"],
                "sameValidator": left["validator"] == right["validator"],
                "payloads": payloads,
            }
        )
    return comparisons


def object_label(payload: str, item: dict[str, Any]) -> str:
    if payload == "routeOrigins":
        return f"{item.get('prefix')} AS{item.get('asn')} maxLength {item.get('maxLength')}"
    if payload == "routerKeys":
        return f"AS{item.get('asn')} {item.get('ski')}"
    if payload == "aspas":
        providers = ", ".join(f"AS{provider}" for provider in item.get("providers", []))
        return f"AS{item.get('customer')} providers {providers}"
    raise ValueError(f"unknown payload: {payload}")


def source_files(item: dict[str, Any]) -> list[dict[str, Any]]:
    candidates = []
    for key in ("sourceFiles", "source_files", "files"):
        value = item.get(key)
        if isinstance(value, list):
            candidates.extend(value)
    source = item.get("source")
    if isinstance(source, dict):
        for key in ("path", "uri", "url", "sha256"):
            if key in source:
                candidates.append(source)
                break
    elif isinstance(source, list):
        candidates.extend(value for value in source if isinstance(value, (str, dict)))
    output = []
    for value in candidates:
        if isinstance(value, str):
            output.append({"path": value})
        elif isinstance(value, dict):
            path = value.get("path") or value.get("uri") or value.get("url")
            sha256 = value.get("sha256") or value.get("hash")
            if path or sha256:
                output.append({"path": path, "sha256": sha256})
    return output


def report_object_key(payload: str, item: dict[str, Any]) -> str:
    if payload == "routeOrigins":
        return f"{item.get('asn')}|{item.get('prefix')}|{item.get('maxLength')}"
    if payload == "routerKeys":
        return f"{item.get('asn')}|{item.get('ski')}|{item.get('routerPublicKey')}"
    if payload == "aspas":
        providers = ",".join(str(provider) for provider in item.get("providers", []))
        return f"{item.get('customer')}|{item.get('afi')}|{providers}"
    raise ValueError(f"unknown payload: {payload}")


def build_object_report(payload: str, entries: list[dict[str, Any]]) -> dict[str, Any]:
    eligible = [
        entry
        for entry in entries
        if entry["success"] and payload not in (entry.get("unsupported") or [])
    ]
    excluded = []
    for entry in entries:
        reason = None
        if not entry["success"]:
            reason = f"failed {entry.get('exitCode')}"
        elif payload in (entry.get("unsupported") or []):
            reason = "unsupported"
        if reason:
            excluded.append({"id": entry["id"], "label": entry["label"], "reason": reason})
    eligible_ids = [entry["id"] for entry in eligible]
    objects: dict[str, dict[str, Any]] = {}
    seen_by: dict[str, set[str]] = {}

    for entry in eligible:
        for item in entry["normalized"].get(payload, []):
            key = report_object_key(payload, item)
            objects.setdefault(key, item)
            seen_by.setdefault(key, set()).add(entry["id"])

    rows = []
    for key, item in objects.items():
        seen = sorted(seen_by.get(key, set()))
        missing = [entry_id for entry_id in eligible_ids if entry_id not in seen]
        rows.append(
            {
                "key": key,
                "label": object_label(payload, item),
                "object": item,
                "seenBy": seen,
                "missingFrom": missing,
                "divergent": bool(missing),
                "sourceFiles": source_files(item),
            }
        )
    rows.sort(key=lambda row: (not row["divergent"], row["label"], row["key"]))
    differing = sum(1 for row in rows if row["divergent"])
    return {
        "payload": payload,
        "eligibleValidators": eligible_ids,
        "excludedValidators": excluded,
        "totalObjects": len(rows),
        "differingObjects": differing,
        "includedRows": len(rows),
        "rows": rows,
    }


def encode_resource_row(row: dict[str, Any]) -> list[Any]:
    return [
        row["key"],
        row["label"],
        row["seenBy"],
        row["missingFrom"],
        row["divergent"],
        row["sourceFiles"],
        row["object"],
    ]


def write_object_reports(run_dir: Path, run_id: str, entries: list[dict[str, Any]]) -> dict[str, Any]:
    report_dir = run_dir / "reports"
    reports = {}
    for payload in PAYLOADS:
        report = build_object_report(payload, entries)
        path = report_dir / f"{payload}.json"
        chunk_dir = report_dir / payload
        if chunk_dir.exists():
            shutil.rmtree(chunk_dir)
        chunks = chunk_records(
            chunk_dir,
            f"data/runs/{run_id}/reports/{payload}",
            [encode_resource_row(row) for row in report["rows"]],
        )
        report_index = {key: value for key, value in report.items() if key != "rows"}
        report_index["chunkRows"] = CHUNK_ROWS
        report_index["chunks"] = chunks
        write_compact_json(path, report_index)
        reports[payload] = {
            "path": f"data/runs/{run_id}/reports/{payload}.json",
            "eligibleValidators": report["eligibleValidators"],
            "excludedValidators": report["excludedValidators"],
            "totalObjects": report["totalObjects"],
            "differingObjects": report["differingObjects"],
            "includedRows": report["includedRows"],
            "chunks": len(chunks),
        }
    return reports


def parse_timestamp(value: Any) -> float | None:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def parse_percent(value: Any) -> float | None:
    if value is None:
        return None
    text = str(value).strip().rstrip("%")
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        return None


def parse_bytes(value: Any) -> int | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    number = ""
    unit = ""
    for char in text:
        if char.isdigit() or char == ".":
            number += char
        elif char.strip():
            unit += char
    if not number or not unit:
        return None
    multiplier = BYTE_UNITS.get(unit)
    if multiplier is None:
        return None
    try:
        return int(float(number) * multiplier)
    except ValueError:
        return None


def parse_io_pair(value: Any) -> tuple[int | None, int | None]:
    parts = [part.strip() for part in str(value or "").split("/", 1)]
    if len(parts) != 2:
        return None, None
    return parse_bytes(parts[0]), parse_bytes(parts[1])


def mean(values: list[float]) -> float | None:
    if not values:
        return None
    return round(sum(values) / len(values), 3)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            text = line.strip()
            if not text:
                continue
            try:
                item = json.loads(text)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                rows.append(item)
    return rows


def numeric_offset(value: Any) -> float | None:
    try:
        offset = float(value)
    except (TypeError, ValueError):
        return None
    if offset < 0:
        return 0.0
    return offset


def bucket_index(offset: float, bucket_seconds: float) -> int:
    if bucket_seconds <= 0:
        return 0
    return max(0, int(offset // bucket_seconds))


def initial_bucket(index: int, bucket_seconds: float, disk_bytes: int | None) -> dict[str, Any]:
    return {
        "index": index,
        "startOffsetSeconds": round(index * bucket_seconds, 3),
        "endOffsetSeconds": round((index + 1) * bucket_seconds, 3),
        "cpu": [],
        "memory": [],
        "networkRx": [],
        "networkTx": [],
        "flowRx": 0,
        "flowTx": 0,
        "pids": [],
        "diskBytes": disk_bytes,
        "stdoutCount": 0,
        "stderrCount": 0,
        "dnsQueryCount": 0,
        "flowKeys": set(),
    }


def ensure_bucket(buckets: dict[int, dict[str, Any]], index: int, bucket_seconds: float, disk_bytes: int | None) -> dict[str, Any]:
    if index not in buckets:
        buckets[index] = initial_bucket(index, bucket_seconds, disk_bytes)
    return buckets[index]


def load_log_events(entry_dir: Path, start_epoch: float | None) -> list[dict[str, Any]]:
    path = entry_dir / "log-events.json"
    if not path.exists():
        return []
    try:
        data = read_json(path)
    except Exception:  # noqa: BLE001 - timeline generation should tolerate partial artifacts.
        return []
    if not isinstance(data, list):
        return []
    events = []
    for item in data:
        if not isinstance(item, dict):
            continue
        offset = numeric_offset(item.get("offsetSeconds"))
        if offset is None and start_epoch is not None:
            observed = parse_timestamp(item.get("observedAt"))
            if observed is not None:
                offset = max(0.0, observed - start_epoch)
        if offset is None:
            continue
        stream = str(item.get("stream") or "").strip()
        if stream not in {"stdout", "stderr"}:
            continue
        message = str(item.get("message") or "")
        encoded = message.encode("utf-8")[:TIMELINE_LOG_MESSAGE_BYTES]
        message = encoded.decode("utf-8", errors="ignore")
        events.append(
            {
                "offsetSeconds": round(offset, 3),
                "stream": stream,
                "message": message,
            }
        )
    events.sort(key=lambda item: (item["offsetSeconds"], item["stream"]))
    return events


def first_field_value(value: Any) -> str:
    return str(value or "").split(",", 1)[0].strip()


def dns_direction(response_flag: Any, answers: list[str]) -> str:
    flag = first_field_value(response_flag).lower()
    if flag in {"1", "true"}:
        return "response"
    if flag in {"0", "false"}:
        return "query"
    return "response" if answers else "query"


def dns_query_type(value: Any) -> str:
    text = first_field_value(value)
    if not text:
        return ""
    return DNS_QUERY_TYPES.get(text, text.upper())


def read_dns_queries(path: Path, start_epoch: float | None) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        with path.open("r", encoding="utf-8", newline="") as handle:
            rows = list(csv.reader(handle, delimiter="\t"))
    except OSError:
        return []
    if not rows:
        return []
    header = rows[0]
    if header == list(DNS_FIELDS):
        field_names = list(DNS_FIELDS)
        data_rows = rows[1:]
    elif header == list(LEGACY_DNS_FIELDS):
        field_names = list(LEGACY_DNS_FIELDS)
        data_rows = rows[1:]
    else:
        field_names = list(DNS_FIELDS)
        data_rows = rows
    queries = []
    first_epoch = None
    for row in data_rows:
        padded = row + [""] * (len(field_names) - len(row))
        item = dict(zip(field_names, padded))
        try:
            epoch = float(str(item.get("frame.time_epoch") or "").split(",", 1)[0])
        except ValueError:
            continue
        if first_epoch is None:
            first_epoch = epoch
        if start_epoch is not None:
            offset = max(0.0, epoch - start_epoch)
        else:
            offset = max(0.0, epoch - first_epoch)
        query = str(item.get("dns.qry.name") or "").split(",", 1)[0].strip().rstrip(".")
        answers = []
        for key in ("dns.a", "dns.aaaa", "dns.cname"):
            answers.extend(part.strip().rstrip(".") for part in str(item.get(key) or "").split(",") if part.strip())
        if not query and not answers:
            continue
        answers = sorted(set(answers))
        queries.append(
            {
                "offsetSeconds": round(offset, 3),
                "direction": dns_direction(item.get("dns.flags.response"), answers),
                "queryType": dns_query_type(item.get("dns.qry.type")),
                "query": query,
                "answers": answers,
                "source": str(item.get("ip.src") or ""),
                "destination": str(item.get("ip.dst") or ""),
            }
        )
    queries.sort(key=lambda item: (item["offsetSeconds"], item["query"]))
    return queries


def load_network_flows(path: Path, start_epoch: float | None) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        data = read_json(path)
    except Exception:  # noqa: BLE001 - optional observability must not break aggregation.
        return []
    flows = data.get("flows") if isinstance(data, dict) else None
    if not isinstance(flows, list):
        return []
    first_epoch = None
    for flow in flows:
        if isinstance(flow, dict) and isinstance(flow.get("firstSeenEpoch"), (int, float)):
            value = float(flow["firstSeenEpoch"])
            first_epoch = value if first_epoch is None else min(first_epoch, value)
    capture_base_offset = 0.0
    if start_epoch is not None and first_epoch is not None:
        capture_base_offset = max(0.0, first_epoch - start_epoch)
    output = []
    for flow in flows:
        if not isinstance(flow, dict):
            continue
        flow_first = float(flow.get("firstSeenEpoch") or first_epoch or 0.0)
        flow_last = float(flow.get("lastSeenEpoch") or flow_first or 0.0)
        base_offset = 0.0
        last_offset = 0.0
        if start_epoch is not None and flow_first:
            base_offset = max(0.0, flow_first - start_epoch)
            last_offset = max(base_offset, flow_last - start_epoch) if flow_last else base_offset
        elif first_epoch is not None and flow_first:
            base_offset = max(0.0, flow_first - first_epoch)
            last_offset = max(base_offset, flow_last - first_epoch) if flow_last else base_offset
        samples = []
        for sample in flow.get("samples") or []:
            if not isinstance(sample, dict):
                continue
            sample_offset = numeric_offset(sample.get("startOffsetSeconds")) or 0.0
            samples.append(
                {
                    "offsetSeconds": round(capture_base_offset + sample_offset, 3),
                    "rxBytes": sample.get("rxBytes") or 0,
                    "txBytes": sample.get("txBytes") or 0,
                    "rxBps": sample.get("rxBps") or 0,
                    "txBps": sample.get("txBps") or 0,
                    "packetCount": sample.get("packetCount") or 0,
                }
            )
        output.append(
            {
                "protocol": flow.get("protocol"),
                "remoteAddress": flow.get("remoteAddress"),
                "remotePort": flow.get("remotePort"),
                "dnsNames": flow.get("dnsNames") or [],
                "directDnsNames": flow.get("directDnsNames") or [],
                "candidateDnsNames": flow.get("candidateDnsNames") or [],
                "totalRxBytes": flow.get("totalRxBytes") or 0,
                "totalTxBytes": flow.get("totalTxBytes") or 0,
                "totalBytes": flow.get("totalBytes") or ((flow.get("totalRxBytes") or 0) + (flow.get("totalTxBytes") or 0)),
                "packetCount": flow.get("packetCount") or 0,
                "firstSeenOffsetSeconds": round(base_offset, 3),
                "lastSeenOffsetSeconds": round(last_offset, 3),
                "samples": samples,
            }
        )
    output.sort(key=lambda item: (-(item.get("totalBytes") or 0), item.get("protocol") or "", item.get("remoteAddress") or ""))
    return output


def build_timeline(entry_dir: Path, status: dict[str, Any], cache_tree: dict[str, Any] | None) -> dict[str, Any]:
    bucket_seconds = TIMELINE_BUCKET_SECONDS
    start_epoch = parse_timestamp(status.get("startedAt"))
    duration = status.get("durationSeconds") if isinstance(status.get("durationSeconds"), (int, float)) else 0
    disk_bytes = cache_tree.get("size") if cache_tree else None
    buckets: dict[int, dict[str, Any]] = {}

    stats = read_jsonl(entry_dir / "docker-stats.jsonl")
    first_monotonic = None
    parsed_stats = []
    for sample in stats:
        observed = parse_timestamp(sample.get("_observedAt"))
        offset = None
        if observed is not None and start_epoch is not None:
            offset = max(0.0, observed - start_epoch)
        elif sample.get("_monotonic") is not None:
            try:
                monotonic = float(sample["_monotonic"])
            except (TypeError, ValueError):
                monotonic = None
            if monotonic is not None:
                if first_monotonic is None:
                    first_monotonic = monotonic
                offset = max(0.0, monotonic - first_monotonic)
        if offset is None:
            offset = len(parsed_stats) * 2.0
        cpu = parse_percent(sample.get("CPUPerc"))
        memory, _memory_limit = parse_io_pair(sample.get("MemUsage"))
        rx, tx = parse_io_pair(sample.get("NetIO"))
        try:
            pids = int(str(sample.get("PIDs", "")).strip())
        except ValueError:
            pids = None
        parsed = {"offset": offset, "cpu": cpu, "memory": memory, "rx": rx, "tx": tx, "pids": pids}
        parsed_stats.append(parsed)
        bucket = ensure_bucket(buckets, bucket_index(offset, bucket_seconds), bucket_seconds, disk_bytes)
        if cpu is not None:
            bucket["cpu"].append(cpu)
        if memory is not None:
            bucket["memory"].append(memory)
        if pids is not None:
            bucket["pids"].append(pids)

    for previous, current in zip(parsed_stats, parsed_stats[1:]):
        span = current["offset"] - previous["offset"]
        if span <= 0:
            continue
        bucket = ensure_bucket(buckets, bucket_index(current["offset"], bucket_seconds), bucket_seconds, disk_bytes)
        if previous["rx"] is not None and current["rx"] is not None and current["rx"] >= previous["rx"]:
            bucket["networkRx"].append((current["rx"] - previous["rx"]) / span)
        if previous["tx"] is not None and current["tx"] is not None and current["tx"] >= previous["tx"]:
            bucket["networkTx"].append((current["tx"] - previous["tx"]) / span)

    events = load_log_events(entry_dir, start_epoch)
    for event in events:
        bucket = ensure_bucket(buckets, bucket_index(event["offsetSeconds"], bucket_seconds), bucket_seconds, disk_bytes)
        if event["stream"] == "stdout":
            bucket["stdoutCount"] += 1
        else:
            bucket["stderrCount"] += 1

    dns_queries = read_dns_queries(entry_dir / "ebpf" / "dns-queries.tsv", start_epoch)
    for query in dns_queries:
        bucket = ensure_bucket(buckets, bucket_index(query["offsetSeconds"], bucket_seconds), bucket_seconds, disk_bytes)
        bucket["dnsQueryCount"] += 1

    flows = load_network_flows(entry_dir / "ebpf" / "network-flows.json", start_epoch)
    for flow in flows:
        flow_key = f"{flow.get('protocol')}|{flow.get('remoteAddress')}|{flow.get('remotePort')}"
        for sample in flow.get("samples") or []:
            bucket = ensure_bucket(buckets, bucket_index(sample["offsetSeconds"], bucket_seconds), bucket_seconds, disk_bytes)
            bucket["flowRx"] += sample.get("rxBytes") or 0
            bucket["flowTx"] += sample.get("txBytes") or 0
            bucket["flowKeys"].add(flow_key)

    if not buckets:
        max_index = max(0, int((float(duration) if duration else 0) // bucket_seconds))
        ensure_bucket(buckets, max_index, bucket_seconds, disk_bytes)

    output_buckets = []
    for index in sorted(buckets):
        bucket = buckets[index]
        output_buckets.append(
            {
                "index": index,
                "startOffsetSeconds": bucket["startOffsetSeconds"],
                "endOffsetSeconds": bucket["endOffsetSeconds"],
                "cpuPercent": mean(bucket["cpu"]),
                "memoryBytes": max(bucket["memory"]) if bucket["memory"] else None,
                "networkRxBps": mean(bucket["networkRx"]),
                "networkTxBps": mean(bucket["networkTx"]),
                "flowRxBytes": bucket["flowRx"],
                "flowTxBytes": bucket["flowTx"],
                "diskBytes": bucket["diskBytes"],
                "pids": max(bucket["pids"]) if bucket["pids"] else None,
                "stdoutCount": bucket["stdoutCount"],
                "stderrCount": bucket["stderrCount"],
                "dnsQueryCount": bucket["dnsQueryCount"],
                "flowCount": len(bucket["flowKeys"]),
            }
        )

    return {
        "schemaVersion": 1,
        "bucketSeconds": bucket_seconds,
        "startedAt": status.get("startedAt"),
        "finishedAt": status.get("finishedAt"),
        "durationSeconds": status.get("durationSeconds"),
        "buckets": output_buckets,
        "events": events,
        "network": {
            "dnsQueries": dns_queries,
            "flows": flows,
        },
    }


def validator_metrics(status: dict[str, Any], cache_tree: dict[str, Any] | None) -> dict[str, Any]:
    usage = status.get("resourceUsage") or {}
    rx = usage.get("networkRxBytes")
    tx = usage.get("networkTxBytes")
    exchanged = None
    if isinstance(rx, int) or isinstance(tx, int):
        exchanged = (rx or 0) + (tx or 0)
    return {
        "durationSeconds": status.get("durationSeconds"),
        "bytesExchanged": exchanged,
        "networkRxBytes": rx,
        "networkTxBytes": tx,
        "bytesOnDisk": cache_tree.get("size") if cache_tree else None,
        "memoryPeakBytes": usage.get("peakMemoryBytes"),
        "memoryMeanBytes": usage.get("meanMemoryBytes"),
        "cpuPeakPercent": usage.get("peakCpuPercent"),
        "cpuMeanPercent": usage.get("meanCpuPercent"),
    }


def load_resource_usage(entry_dir: Path, status: dict[str, Any]) -> dict[str, Any]:
    usage = status.get("resourceUsage")
    if isinstance(usage, dict):
        return usage
    path = entry_dir / "resource-usage.json"
    if path.exists():
        value = read_json(path)
        if isinstance(value, dict):
            return value
    return {}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", required=True)
    parser.add_argument("--site", default="site")
    parser.add_argument("--output", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--max-site-bytes", type=int, default=env_int("MAX_PAGES_BYTES", 950 * 1024 * 1024))
    args = parser.parse_args()

    results_dir = Path(args.results)
    public_dir = Path(args.output)
    print(f"Aggregating validator results from {results_dir}")
    print(f"Writing site to {public_dir}")
    if public_dir.exists():
        shutil.rmtree(public_dir)
    public_dir.mkdir(parents=True)

    copytree_contents(args.site, public_dir)
    print(f"Copied static site assets from {args.site}")

    run_id = args.run_id
    run_dir = public_dir / "data" / "runs" / run_id
    entries = []
    result_dirs = find_result_dirs(results_dir)
    summarize_result_dirs(result_dirs)

    for result_dir in result_dirs:
        status = read_json(result_dir / "status.json")
        entry_dir = run_dir / status["id"]
        copied_status = copy_result(result_dir, entry_dir)
        config_path = entry_dir / "config.json"
        if not config_path.exists():
            write_json(config_path, config_from_status(copied_status))
        normalized = load_normalized(entry_dir, copied_status)
        counts = payload_counts(normalized)
        raw_paths = [
            f"data/runs/{run_id}/{copied_status['id']}/raw/{path.name}"
            for path in sorted((entry_dir / "raw").glob("*.json.gz"))
        ]
        extra_logs = [
            f"data/runs/{run_id}/{copied_status['id']}/{path.name}"
            for path in sorted(entry_dir.glob("*.log"))
            if path.name not in {"stdout.log", "stderr.log"}
        ]
        support_files = [
            f"data/runs/{run_id}/{copied_status['id']}/{path.name}"
            for path in (entry_dir / "resource-usage.json", entry_dir / "docker-stats.jsonl", entry_dir / "log-events.json")
            if path.exists()
        ]
        observability_paths = [
            f"data/runs/{run_id}/{copied_status['id']}/{name}"
            for name in ("resource-usage.json", "docker-stats.jsonl", "log-events.json")
            if (entry_dir / name).exists()
        ]
        observability_paths.extend(
            f"data/runs/{run_id}/{copied_status['id']}/ebpf/{name}"
            for name in (
                "tooling.json",
                "tooling.log",
                "capture-status.json",
                "capture.log",
                "tcpdump.log",
                "network-tcpdump.log",
                "dns-queries.tsv",
                "network-flows.json",
                "tcp-bps.log",
                "tcp-flows.json",
                "tcp-life.log",
                "syscalls.log",
                "memory-allocations.log",
            )
            if (entry_dir / "ebpf" / name).exists()
        )
        cache_tree_path = None
        cache_tree_metadata = copied_status.get("cacheTree") or None
        cache_tree_file = entry_dir / "cache-tree.json"
        if cache_tree_file.exists():
            existing_tree = read_json(cache_tree_file)
            if "chunks" not in existing_tree:
                cache_tree_metadata = chunk_cache_tree(
                    cache_tree_file,
                    f"data/runs/{run_id}/{copied_status['id']}",
                )
            cache_tree_path = f"data/runs/{run_id}/{copied_status['id']}/cache-tree.json"
            if cache_tree_metadata is None:
                tree = read_json(cache_tree_file)
                cache_tree_metadata = {
                    "path": "cache-tree.json",
                    "roots": tree.get("roots", []),
                    "files": tree.get("files", 0),
                    "size": tree.get("size", 0),
                }
        status_cache_tree = cache_tree_metadata or {}
        cache_tree_summary = "cacheTree=missing"
        if cache_tree_path:
            cache_tree_summary = (
                f"cacheTree={status_cache_tree.get('files', '?')} files "
                f"{status_cache_tree.get('size', '?')} bytes"
            )
        timeline_path = f"data/runs/{run_id}/{copied_status['id']}/timeline.json"
        write_compact_json(entry_dir / "timeline.json", build_timeline(entry_dir, copied_status, cache_tree_metadata))
        observability_paths.append(timeline_path)
        print(
            "Copied "
            f"{copied_status['id']}: "
            f"success={copied_status.get('success', False)} "
            f"routeOrigins={counts['routeOrigins']} "
            f"routerKeys={counts['routerKeys']} "
            f"aspas={counts['aspas']} "
            f"raw={len(raw_paths)} "
            f"{cache_tree_summary}"
        )
        entries.append(
            {
                "id": copied_status["id"],
                "validator": copied_status["validator"],
                "version": copied_status["version"],
                "label": copied_status.get("label", copied_status["id"]),
                "success": copied_status.get("success", False),
                "exitCode": copied_status.get("exitCode"),
                "durationSeconds": copied_status.get("durationSeconds"),
                "resourceUsage": copied_status.get("resourceUsage", {}),
                "payloads": copied_status.get("payloads", {}),
                "unsupported": copied_status.get("unsupported", []),
                "counts": counts,
                "cacheTree": cache_tree_metadata,
                "metrics": validator_metrics({**copied_status, "resourceUsage": load_resource_usage(entry_dir, copied_status)}, cache_tree_metadata),
                "paths": {
                    "config": f"data/runs/{run_id}/{copied_status['id']}/config.json",
                    "status": f"data/runs/{run_id}/{copied_status['id']}/status.json",
                    "normalized": f"data/runs/{run_id}/{copied_status['id']}/normalized.json",
                    "stdout": f"data/runs/{run_id}/{copied_status['id']}/stdout.log",
                    "stderr": f"data/runs/{run_id}/{copied_status['id']}/stderr.log",
                    "raw": raw_paths,
                    "logs": extra_logs,
                    "support": support_files,
                    "cacheTree": cache_tree_path,
                    "timeline": timeline_path,
                    "observability": observability_paths,
                },
                "normalized": normalized,
            }
        )

    entries.sort(key=lambda item: item["id"])
    generated_at = utc_now()
    summary_entries = [{key: value for key, value in entry.items() if key != "normalized"} for entry in entries]
    reports = write_object_reports(run_dir, run_id, entries)
    for payload, report in reports.items():
        print(
            "Report "
            f"{payload}: totalObjects={report['totalObjects']} "
            f"differingObjects={report['differingObjects']} "
            f"eligibleValidators={len(report['eligibleValidators'])} "
            f"path={report['path']}"
        )
    summary = {
        "id": run_id,
        "generatedAt": generated_at,
        "success": all(entry["success"] for entry in entries) and bool(entries),
        "entries": summary_entries,
        "comparisons": build_comparisons(entries),
        "reports": reports,
    }
    write_json(run_dir / "summary.json", summary)
    write_json(public_dir / "data" / "latest.json", summary)
    print(f"Wrote run summary: {run_dir / 'summary.json'}")
    print(f"Wrote latest summary: {public_dir / 'data' / 'latest.json'}")

    current_run = {
        "id": run_id,
        "generatedAt": generated_at,
        "success": summary["success"],
        "entries": summary_entries,
        "files": file_inventory(run_dir),
        "size": directory_size(run_dir),
    }
    manifest_path = public_dir / "data" / "manifest.json"
    runs = [current_run]
    for run in runs:
        run_dir_for_manifest = public_dir / "data" / "runs" / run["id"]
        run["files"] = file_inventory(run_dir_for_manifest)
        run["size"] = directory_size(run_dir_for_manifest)
    manifest = {
        "generatedAt": utc_now(),
        "latestRun": runs[0]["id"] if runs else None,
        "maxSiteBytes": args.max_site_bytes,
        "siteBytes": directory_size(public_dir),
        "runs": runs,
    }
    write_json(manifest_path, manifest)
    print(f"Wrote manifest: {manifest_path}")
    print(f"Published {len(entries)} entries in run {run_id}; siteBytes={manifest['siteBytes']}")

    index = public_dir / "index.html"
    if not index.exists():
        raise SystemExit("site/index.html was not copied into the public output")


if __name__ == "__main__":
    main()
