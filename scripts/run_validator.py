#!/usr/bin/env python3
"""Run one validator matrix entry and normalize its output."""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import threading
import time
import shutil
from pathlib import Path
from typing import Any

from rpki_project import (
    directory_size,
    file_inventory,
    find_validator,
    gzip_file,
    load_config,
    normalize_payloads,
    read_json,
    sha256_file,
    utc_now,
    write_json,
)
from summarize_network_packets import DNS_FIELDS, FIELDS as NETWORK_PACKET_FIELDS
from summarize_network_packets import read_dns_names_by_ip, read_packets, summarize_packets
from summarize_tcp_bps import parse_tcptop


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
    if entry.get("threads") is not None:
        command.extend(["-e", f"RPKI_VALIDATOR_THREADS={entry['threads']}"])
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


def sudo_command(command: list[str]) -> list[str]:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return command
    return ["sudo", "-n", *command]


def read_tooling_status(output_dir: Path) -> dict[str, Any] | None:
    path = output_dir / "ebpf" / "tooling.json"
    if not path.exists():
        return None
    try:
        return read_json(path)
    except Exception:  # noqa: BLE001 - capture setup should never fail validation.
        return None


def tcpdump_container_filter(base_expression: list[str], container_ips: list[str]) -> list[str] | None:
    host_terms: list[str] = []
    for ip in sorted({item.strip() for item in container_ips if item.strip()}):
        if host_terms:
            host_terms.append("or")
        host_terms.extend(["host", ip])
    if not host_terms:
        return None
    return ["(", *base_expression, ")", "and", "(", *host_terms, ")"]


class ObservabilityCapture:
    def __init__(self, container_name: str, output_dir: Path, enabled: bool) -> None:
        self.container_name = container_name
        self.output_dir = output_dir
        self.enabled = enabled
        self.ebpf_dir = output_dir / "ebpf"
        self.log_path = self.ebpf_dir / "capture.log"
        self.processes: list[tuple[str, subprocess.Popen[Any], Any]] = []
        self.errors: list[str] = []
        self.container_pid: int | None = None
        self.container_ips: list[str] = []
        self.started = False

    def log(self, message: str) -> None:
        self.ebpf_dir.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(f"{utc_now()} {message}\n")

    def inspect_container_pid(self) -> int | None:
        try:
            completed = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Pid}}", self.container_name],
                text=True,
                capture_output=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            self.log(f"docker inspect failed: {exc}")
            return None
        if completed.returncode != 0:
            return None
        try:
            pid = int(completed.stdout.strip())
        except ValueError:
            return None
        return pid if pid > 0 else None

    def inspect_container_ips(self) -> list[str]:
        try:
            completed = subprocess.run(
                ["docker", "inspect", self.container_name],
                text=True,
                capture_output=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            self.log(f"docker inspect networks failed: {exc}")
            return []
        if completed.returncode != 0:
            self.log(f"docker inspect networks failed: {completed.stderr.strip()}")
            return []
        try:
            data = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            self.log(f"docker inspect networks JSON failed: {exc}")
            return []

        ips = []
        for container in data:
            networks = container.get("NetworkSettings", {}).get("Networks", {})
            if not isinstance(networks, dict):
                continue
            for network in networks.values():
                if not isinstance(network, dict):
                    continue
                for key in ("IPAddress", "GlobalIPv6Address"):
                    value = str(network.get(key) or "").strip()
                    if value:
                        ips.append(value)
        return sorted(set(ips))

    def wait_for_container_pid(self, timeout_seconds: float = 120.0) -> int | None:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            pid = self.inspect_container_pid()
            if pid is not None:
                return pid
            time.sleep(0.5)
        return None

    def start_process(self, name: str, command: list[str], output: Path) -> None:
        output.parent.mkdir(parents=True, exist_ok=True)
        handle = output.open("w", encoding="utf-8")
        self.log(f"starting {name}: {' '.join(shlex.quote(part) for part in command)}")
        try:
            process = subprocess.Popen(
                command,
                text=True,
                stdout=handle,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        except Exception as exc:  # noqa: BLE001 - capture failures are non-fatal.
            handle.close()
            self.errors.append(f"{name}: {exc}")
            self.log(f"failed {name}: {exc}")
            return
        self.processes.append((name, process, handle))

    def start(self) -> None:
        self.ebpf_dir.mkdir(parents=True, exist_ok=True)
        self.log("capture setup started")
        if not self.enabled:
            self.log("capture disabled")
            return
        tooling = read_tooling_status(self.output_dir)
        if tooling is not None and not tooling.get("canAttemptCapture", False):
            self.log("capture skipped because tooling preflight reported canAttemptCapture=False")
            return
        commands = tooling.get("commands", {}) if isinstance(tooling, dict) else {}

        def tool_available(name: str) -> bool:
            if not commands:
                return True
            item = commands.get(name, {})
            return bool(item.get("available"))

        pid = self.wait_for_container_pid()
        if pid is None:
            self.errors.append("container PID was not available")
            self.log("capture skipped because container PID was not available")
            return
        self.container_pid = pid
        self.container_ips = self.inspect_container_ips()
        self.started = True
        self.log(f"container pid={pid}")
        self.log(f"container ips={','.join(self.container_ips) if self.container_ips else 'unknown'}")

        dns_filter = tcpdump_container_filter(["udp", "port", "53", "or", "tcp", "port", "53"], self.container_ips)
        network_filter = tcpdump_container_filter(["tcp", "or", "udp"], self.container_ips)
        if not tool_available("tcpdump"):
            self.log("packet capture skipped because tcpdump is unavailable")
        elif dns_filter is None or network_filter is None:
            self.errors.append("container IP was not available for packet capture")
            self.log("packet capture skipped because container IP was not available")
        else:
            self.start_process(
                "dns-pcap",
                sudo_command(["tcpdump", "-i", "any", "-nn", "-s", "0", "-w", str(self.ebpf_dir / "dns.pcap"), *dns_filter]),
                self.ebpf_dir / "tcpdump.log",
            )
            self.start_process(
                "network-pcap",
                sudo_command(["tcpdump", "-i", "any", "-nn", "-s", "128", "-w", str(self.ebpf_dir / "network.pcap"), *network_filter]),
                self.ebpf_dir / "network-tcpdump.log",
            )
        if tool_available("tcptop-bpfcc"):
            self.start_process("tcp-bps", sudo_command(["tcptop-bpfcc", "-p", str(pid), "-C", "1"]), self.ebpf_dir / "tcp-bps.log")
        else:
            self.log("tcp-bps skipped because tcptop-bpfcc is unavailable")
        if tool_available("tcplife-bpfcc"):
            self.start_process("tcp-life", sudo_command(["tcplife-bpfcc", "-p", str(pid), "-T"]), self.ebpf_dir / "tcp-life.log")
        else:
            self.log("tcp-life skipped because tcplife-bpfcc is unavailable")
        if tool_available("syscount-bpfcc"):
            self.start_process("syscalls", sudo_command(["syscount-bpfcc", "-p", str(pid), "-i", "10"]), self.ebpf_dir / "syscalls.log")
        else:
            self.log("syscalls skipped because syscount-bpfcc is unavailable")
        if tool_available("memleak-bpfcc"):
            self.start_process("memory-allocations", sudo_command(["memleak-bpfcc", "-p", str(pid), "-a", "-o", "10"]), self.ebpf_dir / "memory-allocations.log")
        else:
            self.log("memory-allocations skipped because memleak-bpfcc is unavailable")

    def stop_processes(self) -> None:
        for name, process, handle in self.processes:
            if process.poll() is None:
                self.log(f"stopping {name}")
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except OSError as exc:
                    self.log(f"failed to signal {name}: {exc}")
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.log(f"killing {name}")
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except OSError as exc:
                    self.log(f"failed to kill {name}: {exc}")
                process.wait(timeout=5)
            handle.close()
            self.log(f"{name} exit={process.returncode}")

    def derive_dns_report(self) -> None:
        pcap = self.ebpf_dir / "dns.pcap"
        output = self.ebpf_dir / "dns-queries.tsv"
        if not pcap.exists() or pcap.stat().st_size == 0:
            self.log("dns report skipped because dns.pcap is missing or empty")
            return
        command = [
            "tshark",
            "-r",
            str(pcap),
            "-Y",
            "dns",
            "-T",
            "fields",
            "-E",
            "separator=/t",
        ]
        for field in DNS_FIELDS:
            command.extend(["-e", field])
        try:
            with output.open("w", encoding="utf-8") as handle:
                completed = subprocess.run(command, text=True, stdout=handle, stderr=subprocess.PIPE, timeout=120, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            self.errors.append(f"tshark: {exc}")
            self.log(f"tshark failed: {exc}")
            return
        if completed.returncode != 0:
            self.errors.append(f"tshark: {completed.stderr.strip()}")
            self.log(f"tshark failed: {completed.stderr.strip()}")
        else:
            self.log(f"wrote {output.name}")

    def derive_tcp_flow_report(self) -> None:
        source = self.ebpf_dir / "tcp-bps.log"
        output = self.ebpf_dir / "tcp-flows.json"
        if not source.exists() or source.stat().st_size == 0:
            self.log("tcp flow report skipped because tcp-bps.log is missing or empty")
            return
        try:
            summary = parse_tcptop(source.read_text(encoding="utf-8", errors="replace"), interval_seconds=1.0)
            summary["generatedAt"] = utc_now()
            summary["source"] = source.name
            write_json(output, summary)
            self.log(f"wrote {output.name}")
        except Exception as exc:  # noqa: BLE001 - keep validation status independent of report parsing.
            self.errors.append(f"tcp flow summary: {exc}")
            self.log(f"tcp flow summary failed: {exc}")

    def derive_network_packet_report(self) -> Path | None:
        pcap = self.ebpf_dir / "network.pcap"
        output = self.ebpf_dir / "network-packets.tsv"
        if not pcap.exists() or pcap.stat().st_size == 0:
            self.log("network packet report skipped because network.pcap is missing or empty")
            return None
        command = [
            "tshark",
            "-r",
            str(pcap),
            "-Y",
            "tcp or udp",
            "-T",
            "fields",
            "-E",
            "header=y",
            "-E",
            "separator=/t",
        ]
        for field in NETWORK_PACKET_FIELDS:
            command.extend(["-e", field])
        try:
            with output.open("w", encoding="utf-8") as handle:
                completed = subprocess.run(command, text=True, stdout=handle, stderr=subprocess.PIPE, timeout=180, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            self.errors.append(f"network tshark: {exc}")
            self.log(f"network tshark failed: {exc}")
            return None
        if completed.returncode != 0:
            self.errors.append(f"network tshark: {completed.stderr.strip()}")
            self.log(f"network tshark failed: {completed.stderr.strip()}")
            return None
        self.log(f"wrote {output.name}")
        return output

    def derive_network_flow_report(self) -> None:
        source = self.derive_network_packet_report()
        output = self.ebpf_dir / "network-flows.json"
        if source is None or not source.exists() or source.stat().st_size == 0:
            self.log("network flow report skipped because packet TSV is missing or empty")
            return
        try:
            dns_report = self.ebpf_dir / "dns-queries.tsv"
            dns_names_by_ip = read_dns_names_by_ip(dns_report) if dns_report.exists() else {}
            summary = summarize_packets(read_packets(source), self.container_ips, bucket_seconds=1.0, dns_names_by_ip=dns_names_by_ip)
            summary["generatedAt"] = utc_now()
            summary["source"] = source.name
            write_json(output, summary)
            self.log(f"wrote {output.name}")
            try:
                source.unlink()
                self.log(f"removed {source.name}")
            except OSError as exc:
                self.log(f"failed to remove {source.name}: {exc}")
        except Exception as exc:  # noqa: BLE001 - keep validation status independent of report parsing.
            self.errors.append(f"network flow summary: {exc}")
            self.log(f"network flow summary failed: {exc}")

    def stop(self) -> dict[str, Any]:
        self.stop_processes()
        self.derive_dns_report()
        self.derive_tcp_flow_report()
        self.derive_network_flow_report()
        summary = {
            "enabled": self.enabled,
            "started": self.started,
            "containerPid": self.container_pid,
            "containerIps": self.container_ips,
            "processes": [{"name": name, "exitCode": process.returncode} for name, process, _handle in self.processes],
            "errors": self.errors,
            "generatedAt": utc_now(),
        }
        write_json(self.ebpf_dir / "capture-status.json", summary)
        self.log("capture finished")
        return summary


def run_with_tee(
    command: list[str],
    timeout: int,
    sampler: DockerStatsSampler | None = None,
    capture: ObservabilityCapture | None = None,
) -> tuple[int, str, str, bool, list[dict[str, Any]]]:
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
    log_events: list[dict[str, Any]] = []
    log_lock = threading.Lock()
    started_at = time.monotonic()

    def reader(stream: Any, target: Any, chunks: list[str], stream_name: str) -> None:
        try:
            for line in stream:
                observed_at = utc_now()
                offset = round(time.monotonic() - started_at, 3)
                chunks.append(line)
                with log_lock:
                    log_events.append(
                        {
                            "stream": stream_name,
                            "observedAt": observed_at,
                            "offsetSeconds": offset,
                            "message": line.rstrip("\n"),
                        }
                    )
                target.write(line)
                target.flush()
        finally:
            stream.close()

    stdout_thread = threading.Thread(target=reader, args=(process.stdout, sys.stdout, stdout_chunks, "stdout"))
    stderr_thread = threading.Thread(target=reader, args=(process.stderr, sys.stderr, stderr_chunks, "stderr"))
    stdout_thread.start()
    stderr_thread.start()
    if sampler is not None:
        sampler.start()
    if capture is not None:
        try:
            capture.start()
        except Exception as exc:  # noqa: BLE001 - observability must not change validator behavior.
            capture.errors.append(f"capture start: {exc}")
            capture.log(f"capture start failed: {exc}")

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
        log_events.append(
            {
                "stream": "stderr",
                "observedAt": utc_now(),
                "offsetSeconds": round(time.monotonic() - started_at, 3),
                "message": timeout_line.strip(),
            }
        )
        sys.stderr.write(timeout_line)
        sys.stderr.flush()

    stdout_thread.join(timeout=10)
    stderr_thread.join(timeout=10)
    if sampler is not None:
        sampler.stop()
    if capture is not None:
        try:
            capture.stop()
        except Exception as exc:  # noqa: BLE001 - observability must not change validator behavior.
            capture.errors.append(f"capture stop: {exc}")
            capture.log(f"capture stop failed: {exc}")
    log_events.sort(key=lambda item: (item.get("offsetSeconds", 0), item.get("stream", "")))
    return returncode, "".join(stdout_chunks), "".join(stderr_chunks), timed_out, log_events


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


def normalize_raw_output(raw_dir: Path, output_dir: Path, entry: dict[str, Any], required: bool) -> str | None:
    if not required and not any(raw_dir.glob("*.json")):
        return None
    try:
        raw_values = read_raw_json(raw_dir)
    except Exception as exc:  # noqa: BLE001 - record parse failures for the dashboard.
        return str(exc)
    normalized = normalize_payloads(raw_values, entry)
    write_json(output_dir / "normalized.json", normalized)
    return None


def validator_config(entry: dict[str, Any], docker_command_value: list[str]) -> dict[str, Any]:
    return {
        "id": entry["id"],
        "validator": entry["validator"],
        "version": entry["version"],
        "label": entry.get("label", entry["id"]),
        "image": entry.get("image"),
        "timeoutSeconds": entry.get("timeout_seconds"),
        "threads": entry.get("threads"),
        "payloads": entry.get("payloads", {}),
        "unsupported": [name for name, supported in entry.get("payloads", {}).items() if supported is False],
        "script": entry.get("script"),
        "dockerCommand": docker_command_value,
    }


def prepare_output_dir(output_dir: Path) -> None:
    # Validator images may run as non-root users, so the bind-mounted /out tree
    # needs to be writable by more than the GitHub runner uid.
    for path in [output_dir, *output_dir.rglob("*")]:
        if path.is_dir():
            path.chmod(0o777)


def write_cache_tree(work_dir: Path, output_dir: Path) -> dict[str, Any]:
    roots = ("cache", "tals")
    root_entries = []
    total_files = 0
    total_size = 0
    for name in roots:
        source = work_dir / name
        files = file_inventory(source)
        size = directory_size(source)
        total_files += len(files)
        total_size += size
        root_entries.append({"root": name, "files": files, "size": size})

    tree = {
        "roots": list(roots),
        "files": total_files,
        "size": total_size,
        "entries": root_entries,
    }
    write_json(output_dir / "cache-tree.json", tree)
    return {"path": "cache-tree.json", "roots": list(roots), "files": total_files, "size": total_size}


def compress_raw_files(raw_dir: Path) -> list[dict[str, Any]]:
    raw_files = []
    for path in sorted(raw_dir.glob("*.json")):
        content_size = path.stat().st_size
        content_sha256 = sha256_file(path)
        gz_path = gzip_file(path)
        path.unlink()
        raw_files.append(
            {
                "path": f"raw/{gz_path.name}",
                "size": gz_path.stat().st_size,
                "sha256": sha256_file(gz_path),
                "contentSize": content_size,
                "contentSha256": content_sha256,
            }
        )
    return raw_files


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="validators.yml")
    parser.add_argument("--entry-id", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--capture-observability", action="store_true")
    args = parser.parse_args()

    entry = find_validator(load_config(args.config), args.entry_id)
    output_dir = Path(args.output)
    raw_dir = output_dir / "raw"
    output_dir.mkdir(parents=True, exist_ok=True)
    raw_dir.mkdir(parents=True, exist_ok=True)
    prepare_output_dir(output_dir)

    work_dir = Path(tempfile.mkdtemp(prefix=f"rpki-{entry['id']}-"))
    cache_tree: dict[str, Any] | None = None
    resource_usage: dict[str, Any] = summarize_docker_stats([])
    try:
        prepare_output_dir(work_dir)
        container_name = f"rpki-{entry['id']}-{int(time.time())}"
        command = docker_command(entry, output_dir, work_dir, container_name)
        write_json(output_dir / "config.json", validator_config(entry, command))
        stats_sampler = DockerStatsSampler(container_name)
        capture = ObservabilityCapture(container_name, output_dir, args.capture_observability)
        started_at = utc_now()
        started = time.monotonic()
        returncode, stdout, stderr, timed_out, log_events = run_with_tee(
            command,
            int(entry.get("timeout_seconds", 7200)),
            stats_sampler,
            capture,
        )
        resource_usage = stats_sampler.write(output_dir)
        permission_returncode, permission_output = normalize_permissions(entry, output_dir, work_dir)
        if permission_output:
            stderr += "\n::permission-normalization::\n" + permission_output
        if permission_returncode != 0 and returncode == 0:
            returncode = permission_returncode
            stderr += "\nPermission normalization failed before cache tree inventory.\n"
        if permission_returncode == 0:
            try:
                cache_tree = write_cache_tree(work_dir, output_dir)
            except Exception as exc:  # noqa: BLE001 - keep validator status artifacts on inventory failures.
                stderr += f"\nCache tree inventory failed: {exc}\n"
                if returncode == 0:
                    returncode = 66
        else:
            stderr += "\nCache tree inventory skipped because permission normalization failed.\n"
    finally:
        normalize_permissions(entry, output_dir, work_dir)
        shutil.rmtree(work_dir, ignore_errors=True)

    finished_at = utc_now()
    duration = round(time.monotonic() - started, 3)
    (output_dir / "stdout.log").write_text(stdout, encoding="utf-8")
    (output_dir / "stderr.log").write_text(stderr, encoding="utf-8")
    write_json(output_dir / "log-events.json", log_events)

    normalization_error = normalize_raw_output(raw_dir, output_dir, entry, required=returncode == 0)
    if normalization_error is not None and returncode == 0:
        returncode = 65

    raw_files = compress_raw_files(raw_dir)

    status = {
        "id": entry["id"],
        "validator": entry["validator"],
        "version": entry["version"],
        "label": entry.get("label", entry["id"]),
        "image": entry.get("image"),
        "timeoutSeconds": entry.get("timeout_seconds"),
        "threads": entry.get("threads"),
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
        "archives": [],
        "cacheTree": cache_tree,
        "resourceUsage": resource_usage,
        "normalizationError": normalization_error,
    }
    write_json(output_dir / "status.json", status)

    if returncode != 0:
        raise SystemExit(returncode)


if __name__ == "__main__":
    main()
