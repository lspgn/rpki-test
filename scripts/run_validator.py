#!/usr/bin/env python3
"""Run one validator matrix entry and normalize its output."""

from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path
from typing import Any

from rpki_project import (
    find_validator,
    gzip_file,
    load_config,
    normalize_payloads,
    read_json,
    sha256_file,
    utc_now,
    write_json,
)


def docker_command(entry: dict[str, Any], output_dir: Path) -> list[str]:
    return [
        "docker",
        "run",
        "--rm",
        "--entrypoint",
        "/bin/sh",
        "-v",
        f"{output_dir.resolve()}:/out",
        entry["image"],
        "-lc",
        entry["script"],
    ]


def read_raw_json(raw_dir: Path) -> list[Any]:
    values = []
    for path in sorted(raw_dir.glob("*.json")):
        values.append(read_json(path))
    return values


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="validators.yml")
    parser.add_argument("--entry-id", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    entry = find_validator(load_config(args.config), args.entry_id)
    output_dir = Path(args.output)
    raw_dir = output_dir / "raw"
    output_dir.mkdir(parents=True, exist_ok=True)
    raw_dir.mkdir(parents=True, exist_ok=True)

    command = docker_command(entry, output_dir)
    started_at = utc_now()
    started = time.monotonic()
    timed_out = False
    returncode = 0

    try:
        completed = subprocess.run(
            command,
            text=True,
            capture_output=True,
            timeout=int(entry.get("timeout_seconds", 7200)),
            check=False,
        )
        stdout = completed.stdout
        stderr = completed.stderr
        returncode = completed.returncode
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        returncode = 124
        stdout = exc.stdout or ""
        stderr = (exc.stderr or "") + f"\nTimed out after {entry.get('timeout_seconds')} seconds.\n"

    finished_at = utc_now()
    duration = round(time.monotonic() - started, 3)
    (output_dir / "stdout.log").write_text(stdout, encoding="utf-8")
    (output_dir / "stderr.log").write_text(stderr, encoding="utf-8")

    raw_files = []
    raw_values = []
    normalization_error = None
    if returncode == 0:
        try:
            raw_values = read_raw_json(raw_dir)
        except Exception as exc:  # noqa: BLE001 - record parse failures for the dashboard.
            normalization_error = str(exc)
            returncode = 65

    if returncode == 0:
        normalized = normalize_payloads(raw_values, entry)
        write_json(output_dir / "normalized.json", normalized)

    for path in sorted(raw_dir.glob("*.json")):
        gz_path = gzip_file(path)
        raw_files.append(
            {
                "path": f"raw/{path.name}",
                "compressedPath": f"raw/{gz_path.name}",
                "size": path.stat().st_size,
                "compressedSize": gz_path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )

    status = {
        "id": entry["id"],
        "validator": entry["validator"],
        "version": entry["version"],
        "label": entry.get("label", entry["id"]),
        "image": entry.get("image"),
        "payloads": entry.get("payloads", {}),
        "unsupported": [name for name, supported in entry.get("payloads", {}).items() if supported is False],
        "startedAt": started_at,
        "finishedAt": finished_at,
        "durationSeconds": duration,
        "exitCode": returncode,
        "timedOut": timed_out,
        "success": returncode == 0,
        "command": entry.get("script"),
        "rawFiles": raw_files,
        "normalizationError": normalization_error,
    }
    write_json(output_dir / "status.json", status)

    if returncode != 0:
        raise SystemExit(returncode)


if __name__ == "__main__":
    main()
