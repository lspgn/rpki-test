#!/usr/bin/env python3
"""Run one validator matrix entry and normalize its output."""

from __future__ import annotations

import argparse
import json
import re
import shlex
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import shutil
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


def docker_command(entry: dict[str, Any], output_dir: Path, work_dir: Path, container_name: str | None = None) -> list[str]:
    command = [
        "docker",
        "run",
        "--rm",
    ]
    if container_name:
        command.extend(["--name", container_name])
    command.extend(
        [
            "--entrypoint",
            "/bin/sh",
            "-v",
            f"{output_dir.resolve()}:/out",
            "-v",
            f"{work_dir.resolve()}:/work",
            entry["image"],
            "-lc",
            entry["script"],
        ]
    )
    return command


def permission_command(entry: dict[str, Any], output_dir: Path, work_dir: Path) -> list[str]:
    return [
        "docker",
        "run",
        "--rm",
        "--user",
        "0",
        "--entrypoint",
        "/bin/sh",
        "-v",
        f"{output_dir.resolve()}:/out",
        "-v",
        f"{work_dir.resolve()}:/work",
        entry["image"],
        "-lc",
        "chmod -R a+rwX /out /work",
    ]


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
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)\s*([A-Za-z]+)", text)
    if not match:
        return None
    unit = match.group(2)
    multiplier = BYTE_UNITS.get(unit)
    if multiplier is None:
        return None
    return int(float(match.group(1)) * multiplier)


def parse_io_pair(value: Any) -> tuple[int | None, int | None]:
    parts = [part.strip() for part in str(value or "").split("/", 1)]
    if len(parts) != 2:
        return None, None
    return parse_bytes(parts[0]), parse_bytes(parts[1])


def mean(values: list[float]) -> float | None:
    if not values:
        return None
    return round(sum(values) / len(values), 3)


def summarize_docker_stats(samples: list[dict[str, Any]]) -> dict[str, Any]:
    cpu_values: list[float] = []
    memory_values: list[int] = []
    memory_limits: list[int] = []
    rx_values: list[int] = []
    tx_values: list[int] = []
    pid_values: list[int] = []

    for sample in samples:
        cpu = parse_percent(sample.get("CPUPerc"))
        if cpu is not None:
            cpu_values.append(cpu)
        memory, memory_limit = parse_io_pair(sample.get("MemUsage"))
        if memory is not None:
            memory_values.append(memory)
        if memory_limit is not None:
            memory_limits.append(memory_limit)
        rx, tx = parse_io_pair(sample.get("NetIO"))
        if rx is not None:
            rx_values.append(rx)
        if tx is not None:
            tx_values.append(tx)
        try:
            pid_values.append(int(str(sample.get("PIDs", "")).strip()))
        except ValueError:
            pass

    duration = 0.0
    if len(samples) >= 2:
        duration = max(0.0, float(samples[-1].get("_monotonic", 0)) - float(samples[0].get("_monotonic", 0)))
    network_rx_delta = max(rx_values) - min(rx_values) if rx_values else None
    network_tx_delta = max(tx_values) - min(tx_values) if tx_values else None

    return {
        "sampleCount": len(samples),
        "sampleSpanSeconds": round(duration, 3),
        "meanCpuPercent": mean(cpu_values),
        "peakCpuPercent": max(cpu_values) if cpu_values else None,
        "meanProcessorCores": round(mean(cpu_values) / 100, 3) if cpu_values else None,
        "peakProcessorCores": round(max(cpu_values) / 100, 3) if cpu_values else None,
        "meanMemoryBytes": round(sum(memory_values) / len(memory_values)) if memory_values else None,
        "peakMemoryBytes": max(memory_values) if memory_values else None,
        "memoryLimitBytes": memory_limits[-1] if memory_limits else None,
        "networkRxBytes": max(rx_values) if rx_values else None,
        "networkTxBytes": max(tx_values) if tx_values else None,
        "meanNetworkRxBps": round(network_rx_delta / duration, 3) if network_rx_delta is not None and duration > 0 else None,
        "meanNetworkTxBps": round(network_tx_delta / duration, 3) if network_tx_delta is not None and duration > 0 else None,
        "peakPids": max(pid_values) if pid_values else None,
    }


class DockerStatsSampler:
    def __init__(self, container_name: str, interval_seconds: float = 2.0) -> None:
        self.container_name = container_name
        self.interval_seconds = interval_seconds
        self.samples: list[dict[str, Any]] = []
        self.errors: list[str] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name=f"stats-{container_name}", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=max(10, self.interval_seconds * 3))

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                completed = subprocess.run(
                    ["docker", "stats", "--no-stream", "--format", "{{json .}}", self.container_name],
                    text=True,
                    capture_output=True,
                    timeout=10,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                self.errors.append("docker stats timed out")
                self._stop.wait(self.interval_seconds)
                continue
            if completed.returncode == 0 and completed.stdout.strip():
                for line in completed.stdout.splitlines():
                    try:
                        sample = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    sample["_observedAt"] = utc_now()
                    sample["_monotonic"] = time.monotonic()
                    self.samples.append(sample)
            elif completed.stderr.strip() and self.samples:
                self.errors.append(completed.stderr.strip())
            self._stop.wait(self.interval_seconds)

    def write(self, output_dir: Path) -> dict[str, Any]:
        stats_path = output_dir / "docker-stats.jsonl"
        with stats_path.open("w", encoding="utf-8") as handle:
            for sample in self.samples:
                handle.write(json.dumps(sample, sort_keys=True) + "\n")
        summary = summarize_docker_stats(self.samples)
        if self.errors:
            summary["errors"] = self.errors[-3:]
        write_json(output_dir / "resource-usage.json", summary)
        return summary


def run_with_tee(command: list[str], timeout: int, sampler: DockerStatsSampler | None = None) -> tuple[int, str, str, bool]:
    print("::group::Validator command", flush=True)
    print(" ".join(shlex.quote(part) for part in command), flush=True)
    print("::endgroup::", flush=True)

    process = subprocess.Popen(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=1,
    )
    stdout_chunks: list[str] = []
    stderr_chunks: list[str] = []

    def reader(stream: Any, target: Any, chunks: list[str]) -> None:
        try:
            for line in stream:
                chunks.append(line)
                target.write(line)
                target.flush()
        finally:
            stream.close()

    stdout_thread = threading.Thread(target=reader, args=(process.stdout, sys.stdout, stdout_chunks))
    stderr_thread = threading.Thread(target=reader, args=(process.stderr, sys.stderr, stderr_chunks))
    stdout_thread.start()
    stderr_thread.start()
    if sampler is not None:
        sampler.start()

    timed_out = False
    try:
        returncode = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        returncode = 124
        process.kill()
        process.wait()
        timeout_line = f"\nTimed out after {timeout} seconds.\n"
        stderr_chunks.append(timeout_line)
        sys.stderr.write(timeout_line)
        sys.stderr.flush()

    stdout_thread.join(timeout=10)
    stderr_thread.join(timeout=10)
    if sampler is not None:
        sampler.stop()
    return returncode, "".join(stdout_chunks), "".join(stderr_chunks), timed_out


def run_quiet(command: list[str], timeout: int) -> tuple[int, str]:
    completed = subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)
    output = (completed.stdout or "") + (completed.stderr or "")
    return completed.returncode, output


def normalize_permissions(entry: dict[str, Any], output_dir: Path, work_dir: Path) -> tuple[int, str]:
    return run_quiet(permission_command(entry, output_dir, work_dir), 300)


def read_raw_json(raw_dir: Path) -> list[Any]:
    values = []
    for path in sorted(raw_dir.glob("*.json")):
        values.append(read_json(path))
    return values


def prepare_output_dir(output_dir: Path) -> None:
    # Validator images may run as non-root users, so the bind-mounted /out tree
    # needs to be writable by more than the GitHub runner uid.
    for path in [output_dir, *output_dir.rglob("*")]:
        if path.is_dir():
            path.chmod(0o777)


def archive_work_dir(work_dir: Path, output_dir: Path) -> list[dict[str, Any]]:
    archive_dir = output_dir / "archives"
    archive_dir.mkdir(parents=True, exist_ok=True)
    archive_path = archive_dir / "work-cache.tar.gz"
    with tarfile.open(archive_path, "w:gz") as tar:
        for name in ("cache", "tals"):
            source = work_dir / name
            if source.exists():
                tar.add(source, arcname=name)
    return [
        {
            "path": "archives/work-cache.tar.gz",
            "size": archive_path.stat().st_size,
            "sha256": sha256_file(archive_path),
        }
    ]


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
    prepare_output_dir(output_dir)

    work_dir = Path(tempfile.mkdtemp(prefix=f"rpki-{entry['id']}-"))
    archives: list[dict[str, Any]] = []
    resource_usage: dict[str, Any] = summarize_docker_stats([])
    try:
        prepare_output_dir(work_dir)
        container_name = f"rpki-{entry['id']}-{int(time.time())}"
        command = docker_command(entry, output_dir, work_dir, container_name)
        stats_sampler = DockerStatsSampler(container_name)
        started_at = utc_now()
        started = time.monotonic()
        returncode, stdout, stderr, timed_out = run_with_tee(command, int(entry.get("timeout_seconds", 7200)), stats_sampler)
        resource_usage = stats_sampler.write(output_dir)
        permission_returncode, permission_output = normalize_permissions(entry, output_dir, work_dir)
        if permission_output:
            stderr += "\n::permission-normalization::\n" + permission_output
        if permission_returncode != 0 and returncode == 0:
            returncode = permission_returncode
            stderr += "\nPermission normalization failed before cache archiving.\n"
        if permission_returncode == 0:
            try:
                archives = archive_work_dir(work_dir, output_dir)
            except Exception as exc:  # noqa: BLE001 - keep validator status artifacts on archive failures.
                stderr += f"\nCache archive failed: {exc}\n"
                if returncode == 0:
                    returncode = 66
        else:
            stderr += "\nCache archive skipped because permission normalization failed.\n"
    finally:
        normalize_permissions(entry, output_dir, work_dir)
        shutil.rmtree(work_dir, ignore_errors=True)

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
        "archives": archives,
        "resourceUsage": resource_usage,
        "normalizationError": normalization_error,
    }
    write_json(output_dir / "status.json", status)

    if returncode != 0:
        raise SystemExit(returncode)


if __name__ == "__main__":
    main()
