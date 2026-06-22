#!/usr/bin/env python3
"""Aggregate validator artifacts into a GitHub Pages-ready static site."""

from __future__ import annotations

import argparse
import json
import shutil
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


def find_result_dirs(results_dir: Path) -> list[Path]:
    return sorted({path.parent for path in results_dir.rglob("status.json")})


def copy_result(result_dir: Path, target_dir: Path) -> dict[str, Any]:
    target_dir.mkdir(parents=True, exist_ok=True)
    for name in ("status.json", "normalized.json", "stdout.log", "stderr.log", "resource-usage.json", "docker-stats.jsonl"):
        source = result_dir / name
        if source.exists():
            shutil.copy2(source, target_dir / name)
    ebpf_out = target_dir / "ebpf"
    for name in ("dns-queries.tsv", "tcp-bps.log", "tcp-flows.json", "tcp-life.log"):
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


def previous_runs(manifest_path: Path, current_id: str) -> list[dict[str, Any]]:
    if not manifest_path.exists():
        return []
    manifest = read_json(manifest_path)
    return [run for run in manifest.get("runs", []) if run.get("id") != current_id]


def prune_runs(public_dir: Path, runs: list[dict[str, Any]], max_bytes: int) -> list[dict[str, Any]]:
    if max_bytes <= 0:
        return runs
    kept = list(runs)
    runs_dir = public_dir / "data" / "runs"
    while len(kept) > 1 and directory_size(public_dir) > max_bytes:
        victim = kept.pop()
        victim_dir = runs_dir / victim["id"]
        if victim_dir.exists():
            shutil.rmtree(victim_dir)
    return kept


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", required=True)
    parser.add_argument("--site", default="site")
    parser.add_argument("--previous", default="")
    parser.add_argument("--output", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--max-site-bytes", type=int, default=env_int("MAX_PAGES_BYTES", 950 * 1024 * 1024))
    args = parser.parse_args()

    results_dir = Path(args.results)
    public_dir = Path(args.output)
    if public_dir.exists():
        shutil.rmtree(public_dir)
    public_dir.mkdir(parents=True)

    copytree_contents(args.site, public_dir)
    if args.previous:
        copytree_contents(args.previous, public_dir)

    run_id = args.run_id
    run_dir = public_dir / "data" / "runs" / run_id
    entries = []

    for result_dir in find_result_dirs(results_dir):
        status = read_json(result_dir / "status.json")
        entry_dir = run_dir / status["id"]
        copied_status = copy_result(result_dir, entry_dir)
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
        observability_paths = [
            f"data/runs/{run_id}/{copied_status['id']}/{name}"
            for name in ("resource-usage.json", "docker-stats.jsonl")
            if (entry_dir / name).exists()
        ]
        observability_paths.extend(
            f"data/runs/{run_id}/{copied_status['id']}/ebpf/{name}"
            for name in ("dns-queries.tsv", "tcp-bps.log", "tcp-flows.json", "tcp-life.log")
            if (entry_dir / "ebpf" / name).exists()
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
                "paths": {
                    "status": f"data/runs/{run_id}/{copied_status['id']}/status.json",
                    "normalized": f"data/runs/{run_id}/{copied_status['id']}/normalized.json",
                    "stdout": f"data/runs/{run_id}/{copied_status['id']}/stdout.log",
                    "stderr": f"data/runs/{run_id}/{copied_status['id']}/stderr.log",
                    "raw": raw_paths,
                    "logs": extra_logs,
                    "observability": observability_paths,
                },
                "normalized": normalized,
            }
        )

    entries.sort(key=lambda item: item["id"])
    generated_at = utc_now()
    summary_entries = [{key: value for key, value in entry.items() if key != "normalized"} for entry in entries]
    summary = {
        "id": run_id,
        "generatedAt": generated_at,
        "success": all(entry["success"] for entry in entries) and bool(entries),
        "entries": summary_entries,
        "comparisons": build_comparisons(entries),
    }
    write_json(run_dir / "summary.json", summary)
    write_json(public_dir / "data" / "latest.json", summary)

    current_run = {
        "id": run_id,
        "generatedAt": generated_at,
        "success": summary["success"],
        "entries": summary_entries,
        "files": file_inventory(run_dir),
        "size": directory_size(run_dir),
    }
    manifest_path = public_dir / "data" / "manifest.json"
    runs = [current_run] + previous_runs(manifest_path, run_id)
    runs = prune_runs(public_dir, runs, args.max_site_bytes)
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

    index = public_dir / "index.html"
    if not index.exists():
        raise SystemExit("site/index.html was not copied into the public output")


if __name__ == "__main__":
    main()
