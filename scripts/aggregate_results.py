#!/usr/bin/env python3
"""Aggregate validator artifacts into a GitHub Pages-ready static site."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import tarfile
from collections import Counter, defaultdict
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
            for path in (entry_dir / "resource-usage.json", entry_dir / "docker-stats.jsonl")
            if path.exists()
        ]
        observability_paths = [
            f"data/runs/{run_id}/{copied_status['id']}/{name}"
            for name in ("resource-usage.json", "docker-stats.jsonl")
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
