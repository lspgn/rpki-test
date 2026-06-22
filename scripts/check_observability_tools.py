#!/usr/bin/env python3
"""Record whether optional privileged observability tooling is available."""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Any

from rpki_project import utc_now, write_json


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
    kernel = platform.release()
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
        "kernel": kernel,
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


def write_log(path: Path, status: dict[str, Any]) -> None:
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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, help="directory for tooling.json and tooling.log")
    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    status = collect_tooling_status()
    write_json(output_dir / "tooling.json", status)
    write_log(output_dir / "tooling.log", status)


if __name__ == "__main__":
    main()
