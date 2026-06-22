#!/usr/bin/env python3

from __future__ import annotations

import json
import shutil
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from aggregate_results import build_timeline, cache_tree_from_archive, main as aggregate_main, source_files  # noqa: E402
from check_observability_tools import collect_tooling_status  # noqa: E402
from rpki_project import load_config, normalize_payloads, payload_counts, read_json, validators, write_json  # noqa: E402
from run_validator import (  # noqa: E402
    ObservabilityCapture,
    compress_raw_files,
    docker_command,
    normalize_raw_output,
    parse_bytes,
    summarize_docker_stats,
    tcpdump_container_filter,
    validator_config,
    write_cache_tree,
)
from summarize_network_packets import DNS_FIELDS, FIELDS as NETWORK_PACKET_FIELDS  # noqa: E402
from summarize_network_packets import read_dns_names_by_ip, read_packets, summarize_packets  # noqa: E402
from summarize_tcp_bps import parse_tcptop  # noqa: E402


class NormalizationTests(unittest.TestCase):
    def test_routinator_all_payloads(self) -> None:
        raw = read_json(ROOT / "tests/fixtures/routinator/raw.json")
        raw["roas"][0]["source"] = [
            {"type": "roa", "uri": "rsync://example.net/repository/route.roa", "tal": "arin"}
        ]
        entry = {
            "id": "routinator-test",
            "validator": "routinator",
            "version": "test",
            "payloads": {"routeOrigins": True, "routerKeys": True, "aspas": True},
        }
        normalized = normalize_payloads([raw], entry)
        self.assertEqual(payload_counts(normalized), {"routeOrigins": 1, "routerKeys": 1, "aspas": 1})
        self.assertEqual(normalized["routeOrigins"][0]["asn"], 64496)
        self.assertEqual(normalized["routeOrigins"][0]["ta"], "arin")
        self.assertEqual(
            normalized["routeOrigins"][0]["sourceFiles"],
            [{"path": "rsync://example.net/repository/route.roa"}],
        )
        self.assertEqual(normalized["aspas"][0]["providers"], [64497, 64498])

    def test_rpki_client_payload_aliases(self) -> None:
        raw = read_json(ROOT / "tests/fixtures/rpki-client/raw.json")
        entry = {
            "id": "rpki-client-test",
            "validator": "rpki-client",
            "version": "test",
            "payloads": {"routeOrigins": True, "routerKeys": True, "aspas": True},
        }
        normalized = normalize_payloads([raw], entry)
        self.assertEqual(payload_counts(normalized), {"routeOrigins": 1, "routerKeys": 1, "aspas": 1})
        self.assertEqual(normalized["routerKeys"][0]["ski"], "001122")

    def test_fort_aspa_unsupported(self) -> None:
        roas = read_json(ROOT / "tests/fixtures/fort/roas.json")
        bgpsec = read_json(ROOT / "tests/fixtures/fort/bgpsec.json")
        entry = {
            "id": "fort-test",
            "validator": "fort",
            "version": "test",
            "payloads": {"routeOrigins": True, "routerKeys": True, "aspas": False},
        }
        normalized = normalize_payloads([roas, bgpsec], entry)
        self.assertEqual(payload_counts(normalized), {"routeOrigins": 1, "routerKeys": 1, "aspas": 0})
        self.assertEqual(normalized["metadata"]["unsupported"], ["aspas"])


class ConfigTests(unittest.TestCase):
    def test_matrix_config_has_pinned_entries(self) -> None:
        entries = validators(load_config(ROOT / "validators.yml"))
        self.assertEqual({entry["validator"] for entry in entries}, {"fort", "routinator", "rpki-client"})
        for entry in entries:
            self.assertIn("@sha256:", entry["image"])
            self.assertIn("payloads", entry)
            self.assertEqual(entry["threads"], 4)
            command = docker_command(entry, Path("/tmp/out"), Path("/tmp/work"), "test-container")
            self.assertIn("-e", command)
            self.assertIn("RPKI_VALIDATOR_THREADS=4", command)
        routinator = next(entry for entry in entries if entry["validator"] == "routinator")
        self.assertIn('--validation-threads="$RPKI_VALIDATOR_THREADS"', routinator["script"])
        self.assertNotIn("--complete", routinator["script"])
        self.assertNotIn("--logfile", routinator["script"])
        self.assertIn("2>&1", routinator["script"])
        rpki_client = next(entry for entry in entries if entry["validator"] == "rpki-client")
        self.assertEqual(rpki_client["id"], "rpki-client-9_8")
        self.assertEqual(rpki_client["version"], "9.8")
        self.assertIn("rpki-client-9.8.tar.gz", rpki_client["script"])
        self.assertIn("rpki-client-portable 9.8", rpki_client["script"])
        self.assertIn('rpki-client -j -p "$RPKI_VALIDATOR_THREADS"', rpki_client["script"])

    def test_validator_config_records_cli_and_entry_settings(self) -> None:
        entry = {
            "id": "routinator-test",
            "validator": "routinator",
            "version": "test",
            "label": "Routinator Test",
            "image": "example/routinator@sha256:abc",
            "timeout_seconds": 120,
            "threads": 4,
            "payloads": {"routeOrigins": True, "routerKeys": True, "aspas": True},
            "script": "routinator vrps -f jsonext",
        }
        config = validator_config(entry, ["docker", "run", "example/routinator"])

        self.assertEqual(config["timeoutSeconds"], 120)
        self.assertEqual(config["threads"], 4)
        self.assertEqual(config["script"], "routinator vrps -f jsonext")
        self.assertEqual(config["dockerCommand"], ["docker", "run", "example/routinator"])

    def test_normalizes_raw_output_for_failed_validator_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            raw_dir = output / "raw"
            raw_dir.mkdir()
            shutil.copy2(ROOT / "tests/fixtures/routinator/raw.json", raw_dir / "routinator.json")
            entry = {
                "id": "routinator-test",
                "validator": "routinator",
                "version": "test",
                "payloads": {"routeOrigins": True, "routerKeys": True, "aspas": True},
            }

            error = normalize_raw_output(raw_dir, output, entry, required=False)
            normalized = read_json(output / "normalized.json")

        self.assertIsNone(error)
        self.assertEqual(payload_counts(normalized), {"routeOrigins": 1, "routerKeys": 1, "aspas": 1})

    def test_skips_optional_normalization_when_failed_run_has_no_raw_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            raw_dir = output / "raw"
            raw_dir.mkdir()
            entry = {
                "id": "routinator-test",
                "validator": "routinator",
                "version": "test",
                "payloads": {"routeOrigins": True, "routerKeys": True, "aspas": True},
            }

            error = normalize_raw_output(raw_dir, output, entry, required=False)
            normalized_exists = (output / "normalized.json").exists()

        self.assertIsNone(error)
        self.assertFalse(normalized_exists)


class ResourceUsageTests(unittest.TestCase):
    def test_parse_docker_byte_units(self) -> None:
        self.assertEqual(parse_bytes("1.5MiB"), 1572864)
        self.assertEqual(parse_bytes("2 GB"), 2000000000)
        self.assertIsNone(parse_bytes("unknown"))

    def test_summarize_docker_stats_calculates_peaks_and_rates(self) -> None:
        samples = [
            {
                "_monotonic": 10.0,
                "CPUPerc": "25.00%",
                "MemUsage": "128MiB / 2GiB",
                "NetIO": "100B / 200B",
                "PIDs": "4",
            },
            {
                "_monotonic": 14.0,
                "CPUPerc": "150.00%",
                "MemUsage": "256MiB / 2GiB",
                "NetIO": "500B / 1000B",
                "PIDs": "8",
            },
        ]

        summary = summarize_docker_stats(samples)

        self.assertEqual(summary["sampleCount"], 2)
        self.assertEqual(summary["peakProcessorCores"], 1.5)
        self.assertEqual(summary["peakMemoryBytes"], 268435456)
        self.assertEqual(summary["meanNetworkRxBps"], 100)
        self.assertEqual(summary["meanNetworkTxBps"], 200)
        self.assertEqual(summary["peakPids"], 8)


class TcpFlowSummaryTests(unittest.TestCase):
    def test_parse_tcptop_summarizes_flow_bytes_and_rates(self) -> None:
        text = """Tracing... Output every 1 secs. Hit Ctrl-C to end
12:00:00 loadavg: 0.00 0.01 0.05 1/100 1234
PID    COMM         LADDR                 RADDR                  RX_KB TX_KB
42     validator    10.0.0.2:50000        203.0.113.10:443       4     1
12:00:01 loadavg: 0.00 0.01 0.05 1/100 1234
PID    COMM         LADDR                 RADDR                  RX_KB TX_KB
42     validator    10.0.0.2:50000        203.0.113.10:443       8     2
42     validator    10.0.0.2:50001        192.0.2.53:53          1     0
"""

        summary = parse_tcptop(text, interval_seconds=1.0)

        self.assertEqual(summary["sampleCount"], 3)
        self.assertEqual(summary["flowCount"], 2)
        self.assertEqual(summary["totalRxBytes"], 13 * 1024)
        self.assertEqual(summary["totalTxBytes"], 3 * 1024)
        flow = next(item for item in summary["flows"] if item["remotePort"] == 443)
        self.assertEqual(flow["sampleCount"], 2)
        self.assertEqual(flow["totalRxBytes"], 12 * 1024)
        self.assertEqual(flow["totalTxBytes"], 3 * 1024)
        self.assertEqual(flow["minRxBps"], 4 * 1024)
        self.assertEqual(flow["maxRxBps"], 8 * 1024)
        self.assertEqual(flow["samples"][0]["time"], "12:00:00")


class NetworkFlowSummaryTests(unittest.TestCase):
    def test_packet_fields_summarize_container_flows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "packets.tsv"
            source.write_text(
                "\t".join(NETWORK_PACKET_FIELDS)
                + "\n"
                + "100.0\t60\t172.17.0.2\t192.0.2.53\t\t\t\t\t50000\t53\tDNS\texample.net\n"
                + "100.5\t120\t192.0.2.53\t172.17.0.2\t\t\t\t\t53\t50000\tDNS\texample.net\n"
                + "101.2\t1000\t203.0.113.10\t172.17.0.2\t\t\t443\t40000\t\t\tTCP\t\n"
                + "101.4\t500\t172.17.0.2\t203.0.113.10\t\t\t40000\t443\t\t\tTCP\t\n"
                + "101.4\t500\t172.17.0.2\t203.0.113.10\t\t\t40000\t443\t\t\tTCP\t\n"
                + "101.8\t900\t10.1.0.1\t198.51.100.1\t\t\t12345\t443\t\t\tTCP\t\n",
                encoding="utf-8",
            )
            dns = Path(tmp) / "dns.tsv"
            dns.write_text(
                "\t".join(DNS_FIELDS)
                + "\n"
                + "100.5\t192.0.2.53\t172.17.0.2\t53\t50000\trepo.example.net\t203.0.113.10\t\tcdn.example.net\n",
                encoding="utf-8",
            )

            summary = summarize_packets(
                read_packets(source),
                ["172.17.0.2"],
                bucket_seconds=1.0,
                dns_names_by_ip=read_dns_names_by_ip(dns),
            )

        self.assertEqual(summary["packetCount"], 6)
        self.assertEqual(summary["matchedPacketCount"], 4)
        self.assertEqual(summary["ignoredPacketCount"], 1)
        self.assertEqual(summary["flowCount"], 2)
        self.assertEqual(summary["totalRxBytes"], 1120)
        self.assertEqual(summary["totalTxBytes"], 560)
        self.assertEqual(summary["maxRxBps"], 1000)
        self.assertEqual(summary["maxTxBps"], 500)
        tcp_flow = next(flow for flow in summary["flows"] if flow["protocol"] == "TCP")
        self.assertEqual(tcp_flow["remoteAddress"], "203.0.113.10")
        self.assertEqual(tcp_flow["remotePort"], 443)
        self.assertEqual(tcp_flow["totalRxBytes"], 1000)
        self.assertEqual(tcp_flow["totalTxBytes"], 500)
        self.assertEqual(tcp_flow["candidateDnsNames"], ["cdn.example.net", "repo.example.net"])
        self.assertEqual(tcp_flow["dnsNames"], ["cdn.example.net", "repo.example.net"])
        dns_flow = next(flow for flow in summary["flows"] if flow["protocol"] == "UDP")
        self.assertEqual(dns_flow["dnsNames"], ["example.net"])
        self.assertEqual(dns_flow["directDnsNames"], ["example.net"])


class TimelineTests(unittest.TestCase):
    def test_build_timeline_buckets_resources_events_dns_and_flows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ebpf = root / "ebpf"
            ebpf.mkdir()
            status = {
                "startedAt": "2026-06-22T00:00:00Z",
                "finishedAt": "2026-06-22T00:00:24Z",
                "durationSeconds": 24,
            }
            samples = [
                {
                    "_observedAt": "2026-06-22T00:00:01Z",
                    "CPUPerc": "50.00%",
                    "MemUsage": "128MiB / 2GiB",
                    "NetIO": "100B / 200B",
                    "PIDs": "4",
                },
                {
                    "_observedAt": "2026-06-22T00:00:11Z",
                    "CPUPerc": "150.00%",
                    "MemUsage": "256MiB / 2GiB",
                    "NetIO": "1100B / 2200B",
                    "PIDs": "8",
                },
            ]
            (root / "docker-stats.jsonl").write_text(
                "\n".join(json.dumps(sample) for sample in samples) + "\n",
                encoding="utf-8",
            )
            write_json(
                root / "log-events.json",
                [
                    {
                        "stream": "stdout",
                        "observedAt": "2026-06-22T00:00:04Z",
                        "offsetSeconds": 4,
                        "message": "started",
                    },
                    {
                        "stream": "stderr",
                        "observedAt": "2026-06-22T00:00:12Z",
                        "offsetSeconds": 12,
                        "message": "warning",
                    },
                ],
            )
            (ebpf / "dns-queries.tsv").write_text(
                "\t".join(DNS_FIELDS)
                + "\n"
                + "1782086403.0\t192.0.2.53\t172.17.0.2\t53\t50000\trepo.example.net\t203.0.113.10\t\tcdn.example.net\n",
                encoding="utf-8",
            )
            write_json(
                ebpf / "network-flows.json",
                {
                    "flows": [
                        {
                            "protocol": "TCP",
                            "remoteAddress": "203.0.113.10",
                            "remotePort": 443,
                            "dnsNames": ["repo.example.net"],
                            "totalRxBytes": 1000,
                            "totalTxBytes": 500,
                            "packetCount": 2,
                            "firstSeenEpoch": 1782086405.0,
                            "lastSeenEpoch": 1782086407.5,
                            "samples": [
                                {
                                    "startOffsetSeconds": 0,
                                    "rxBytes": 1000,
                                    "txBytes": 500,
                                    "rxBps": 1000,
                                    "txBps": 500,
                                    "packetCount": 2,
                                }
                            ],
                        }
                    ]
                },
            )

            timeline = build_timeline(root, status, {"size": 4096})

        self.assertEqual(timeline["bucketSeconds"], 10.0)
        self.assertEqual(timeline["buckets"][0]["cpuPercent"], 50)
        self.assertEqual(timeline["buckets"][0]["memoryBytes"], 134217728)
        self.assertEqual(timeline["buckets"][0]["diskBytes"], 4096)
        self.assertEqual(timeline["buckets"][0]["stdoutCount"], 1)
        self.assertEqual(timeline["buckets"][0]["dnsQueryCount"], 1)
        self.assertEqual(timeline["buckets"][0]["flowCount"], 1)
        self.assertEqual(timeline["buckets"][1]["networkRxBps"], 100)
        self.assertEqual(timeline["buckets"][1]["networkTxBps"], 200)
        self.assertEqual(timeline["buckets"][1]["pids"], 8)
        self.assertEqual(timeline["buckets"][1]["stderrCount"], 1)
        self.assertEqual(timeline["events"][0]["message"], "started")
        self.assertEqual(timeline["network"]["dnsQueries"][0]["query"], "repo.example.net")
        self.assertEqual(timeline["network"]["dnsQueries"][0]["answers"], ["203.0.113.10", "cdn.example.net"])
        self.assertEqual(timeline["network"]["flows"][0]["dnsNames"], ["repo.example.net"])
        self.assertEqual(timeline["network"]["flows"][0]["firstSeenOffsetSeconds"], 5)
        self.assertEqual(timeline["network"]["flows"][0]["lastSeenOffsetSeconds"], 7.5)


class ObservabilityToolingTests(unittest.TestCase):
    def test_collect_tooling_status_reports_required_commands(self) -> None:
        status = collect_tooling_status()

        self.assertIn("generatedAt", status)
        self.assertIn("isRoot", status)
        self.assertIn("sudoNonInteractive", status)
        self.assertIn("canUsePrivilege", status)
        self.assertIn("canAttemptCapture", status)
        self.assertIn("/sys/kernel/debug/tracing", status["kernelPaths"])
        self.assertIn("exists", status["kernelPaths"]["/sys/kernel/debug/tracing"])
        for command in ("tcpdump", "tshark", "tcptop-bpfcc", "tcplife-bpfcc"):
            self.assertIn(command, status["commands"])
            self.assertIn("available", status["commands"][command])

    def test_tcpdump_filter_limits_capture_to_container_ips(self) -> None:
        expression = tcpdump_container_filter(["udp", "port", "53"], ["172.17.0.2", "2001:db8::10", "172.17.0.2"])

        self.assertEqual(
            expression,
            [
                "(",
                "udp",
                "port",
                "53",
                ")",
                "and",
                "(",
                "host",
                "172.17.0.2",
                "or",
                "host",
                "2001:db8::10",
                ")",
            ],
        )
        self.assertIsNone(tcpdump_container_filter(["udp", "port", "53"], []))

    def test_observability_capture_skips_packet_capture_without_container_ip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            ebpf_dir = output / "ebpf"
            tooling = {
                "canAttemptCapture": True,
                "commands": {
                    "tcpdump": {"available": True},
                    "tcptop-bpfcc": {"available": False},
                    "tcplife-bpfcc": {"available": False},
                    "syscount-bpfcc": {"available": False},
                    "memleak-bpfcc": {"available": False},
                },
            }
            write_json(ebpf_dir / "tooling.json", tooling)
            capture = ObservabilityCapture("validator", output, True)
            capture.wait_for_container_pid = lambda: 1234  # type: ignore[method-assign]
            capture.inspect_container_ips = lambda: []  # type: ignore[method-assign]
            started: list[str] = []
            capture.start_process = lambda name, command, log: started.append(name)  # type: ignore[method-assign]

            capture.start()

        self.assertNotIn("dns-pcap", started)
        self.assertNotIn("network-pcap", started)
        self.assertIn("container IP was not available for packet capture", capture.errors)

    def test_observability_capture_scopes_packet_capture_to_container_ip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            ebpf_dir = output / "ebpf"
            tooling = {
                "canAttemptCapture": True,
                "commands": {
                    "tcpdump": {"available": True},
                    "tcptop-bpfcc": {"available": False},
                    "tcplife-bpfcc": {"available": False},
                    "syscount-bpfcc": {"available": False},
                    "memleak-bpfcc": {"available": False},
                },
            }
            write_json(ebpf_dir / "tooling.json", tooling)
            capture = ObservabilityCapture("validator", output, True)
            capture.wait_for_container_pid = lambda: 1234  # type: ignore[method-assign]
            capture.inspect_container_ips = lambda: ["172.17.0.2"]  # type: ignore[method-assign]
            started: dict[str, list[str]] = {}
            capture.start_process = lambda name, command, log: started.setdefault(name, command)  # type: ignore[method-assign]

            capture.start()

        dns_command = started["dns-pcap"]
        network_command = started["network-pcap"]
        self.assertEqual(
            dns_command[dns_command.index("-w") + 2 :],
            ["(", "udp", "port", "53", "or", "tcp", "port", "53", ")", "and", "(", "host", "172.17.0.2", ")"],
        )
        self.assertEqual(
            network_command[network_command.index("-w") + 2 :],
            ["(", "tcp", "or", "udp", ")", "and", "(", "host", "172.17.0.2", ")"],
        )


class AggregateTests(unittest.TestCase):
    def test_source_files_accepts_source_list(self) -> None:
        self.assertEqual(
            source_files(
                {
                    "source": [
                        {"type": "roa", "uri": "rsync://example.net/repository/route.roa"},
                        {"path": "cache/repository/route.roa", "sha256": "abc123"},
                    ]
                }
            ),
            [
                {"path": "rsync://example.net/repository/route.roa", "sha256": None},
                {"path": "cache/repository/route.roa", "sha256": "abc123"},
            ],
        )

    def test_fixture_site_build(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            results = tmp_path / "results"
            site = tmp_path / "site"
            public = tmp_path / "public"
            shutil.copytree(ROOT / "site", site)

            entries = [
                ("routinator-test", ROOT / "tests/fixtures/routinator/raw.json", {"routeOrigins": True, "routerKeys": True, "aspas": True}),
                ("fort-test", ROOT / "tests/fixtures/fort/roas.json", {"routeOrigins": True, "routerKeys": True, "aspas": False}),
            ]
            for entry_id, raw_path, payloads in entries:
                out = results / f"validator-{entry_id}"
                raw_dir = out / "raw"
                raw_dir.mkdir(parents=True)
                shutil.copy2(raw_path, raw_dir / raw_path.name)
                raw = read_json(raw_path)
                status = {
                    "id": entry_id,
                    "validator": entry_id.split("-")[0],
                    "version": "test",
                    "label": entry_id,
                    "success": True,
                    "exitCode": 0,
                    "startedAt": "2026-06-22T00:00:00Z",
                    "finishedAt": "2026-06-22T00:00:12Z",
                    "durationSeconds": 1,
                    "resourceUsage": {
                        "peakProcessorCores": 1.25,
                        "peakMemoryBytes": 268435456,
                        "sampleCount": 2,
                    },
                    "payloads": payloads,
                    "unsupported": [name for name, supported in payloads.items() if supported is False],
                }
                write_json(out / "status.json", status)
                normalized = normalize_payloads([raw], {**status, "image": "fixture"})
                if entry_id == "routinator-test":
                    normalized["routeOrigins"].append(
                        {"asn": 64500, "prefix": "198.51.100.0/24", "maxLength": 24, "ta": "arin"}
                    )
                write_json(out / "normalized.json", normalized)
                compress_raw_files(raw_dir)
                write_json(out / "resource-usage.json", status["resourceUsage"])
                write_json(
                    out / "log-events.json",
                    [{"stream": "stdout", "observedAt": "2026-06-22T00:00:01Z", "offsetSeconds": 1, "message": "ok"}],
                )
                (out / "docker-stats.jsonl").write_text(
                    json.dumps(
                        {
                            "_observedAt": "2026-06-22T00:00:01Z",
                            "CPUPerc": "10.00%",
                            "MemUsage": "64MiB / 2GiB",
                            "NetIO": "100B / 200B",
                            "PIDs": "2",
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )
                ebpf_dir = out / "ebpf"
                ebpf_dir.mkdir()
                write_json(ebpf_dir / "tooling.json", {"canAttemptCapture": False})
                (ebpf_dir / "tooling.log").write_text("canAttemptCapture=False\n", encoding="utf-8")
                write_json(ebpf_dir / "capture-status.json", {"started": True})
                (ebpf_dir / "capture.log").write_text("capture finished\n", encoding="utf-8")
                (ebpf_dir / "tcpdump.log").write_text("1 packet captured\n", encoding="utf-8")
                (ebpf_dir / "network-tcpdump.log").write_text("2 packets captured\n", encoding="utf-8")
                (ebpf_dir / "dns-queries.tsv").write_text(
                    "\t".join(DNS_FIELDS)
                    + "\n"
                    + "1782086401.0\t192.0.2.53\t172.17.0.2\t53\t50000\trepo.example.net\t203.0.113.10\t\t\n",
                    encoding="utf-8",
                )
                write_json(
                    ebpf_dir / "network-flows.json",
                    {
                        "flowCount": 1,
                        "flows": [
                            {
                                "protocol": "TCP",
                                "remoteAddress": "203.0.113.10",
                                "remotePort": 443,
                                "dnsNames": ["repo.example.net"],
                                "totalRxBytes": 1000,
                                "totalTxBytes": 500,
                                "packetCount": 2,
                                "firstSeenEpoch": 1782086402.0,
                                "lastSeenEpoch": 1782086404.0,
                                "samples": [{"startOffsetSeconds": 0, "rxBytes": 1000, "txBytes": 500}],
                            }
                        ],
                    },
                )
                (ebpf_dir / "tcp-bps.log").write_text("127.0.0.1:443 1024\n", encoding="utf-8")
                write_json(ebpf_dir / "tcp-flows.json", {"flowCount": 1, "flows": []})
                (ebpf_dir / "syscalls.log").write_text("syscall count\n", encoding="utf-8")
                (ebpf_dir / "memory-allocations.log").write_text("allocation stack\n", encoding="utf-8")
                (ebpf_dir / "dns.pcap").write_bytes(b"not published")
                (out / "stdout.log").write_text("", encoding="utf-8")
                (out / "stderr.log").write_text("", encoding="utf-8")
                write_json(out / "cache-tree.json", {"roots": ["cache", "tals"], "files": 0, "size": 0, "entries": []})

            old_argv = sys.argv
            try:
                sys.argv = [
                    "aggregate_results.py",
                    "--results",
                    str(results),
                    "--site",
                    str(site),
                    "--output",
                    str(public),
                    "--run-id",
                    "fixture-run",
                    "--max-site-bytes",
                    "10000000",
                ]
                aggregate_main()
            finally:
                sys.argv = old_argv

            manifest = read_json(public / "data/manifest.json")
            latest = read_json(public / "data/latest.json")
            report = read_json(public / "data/runs/fixture-run/reports/routeOrigins.json")
            report_rows = read_json(public / "data/runs/fixture-run/reports/routeOrigins/0000.json")["rows"]
            self.assertEqual(manifest["latestRun"], "fixture-run")
            self.assertEqual(len(manifest["runs"]), 1)
            self.assertEqual(len(latest["entries"]), 2)
            for entry in latest["entries"]:
                self.assertIn("config", entry["paths"])
                config_path = public / entry["paths"]["config"]
                self.assertTrue(config_path.exists())
                config = read_json(config_path)
                self.assertEqual(config["id"], entry["id"])
                self.assertIn("script", config)
            self.assertEqual(latest["reports"]["routeOrigins"]["totalObjects"], 2)
            self.assertEqual(latest["reports"]["routeOrigins"]["differingObjects"], 1)
            self.assertEqual(latest["reports"]["routeOrigins"]["includedRows"], 2)
            self.assertEqual(latest["reports"]["routeOrigins"]["chunks"], 1)
            self.assertEqual(latest["reports"]["aspas"]["excludedValidators"][0]["reason"], "unsupported")
            self.assertEqual(report["chunks"][0]["path"], "data/runs/fixture-run/reports/routeOrigins/0000.json")
            extra = [row for row in report_rows if row[6]["prefix"] == "198.51.100.0/24"][0]
            self.assertEqual(extra[2], ["routinator-test"])
            self.assertEqual(extra[3], ["fort-test"])
            self.assertTrue((public / "data/runs/fixture-run/routinator-test/raw/raw.json.gz").exists())
            self.assertFalse((public / "data/runs/fixture-run/routinator-test/raw/raw.json").exists())
            self.assertEqual(latest["entries"][0]["resourceUsage"]["peakProcessorCores"], 1.25)
            self.assertIn("timeline", latest["entries"][0]["paths"])
            timeline_path = public / latest["entries"][0]["paths"]["timeline"]
            self.assertTrue(timeline_path.exists())
            timeline = read_json(timeline_path)
            self.assertIn("network", timeline)
            self.assertEqual(timeline["events"][0]["message"], "ok")
            self.assertEqual(timeline["network"]["dnsQueries"][0]["query"], "repo.example.net")
            self.assertEqual(timeline["network"]["flows"][0]["remoteAddress"], "203.0.113.10")
            observability = latest["entries"][0]["paths"]["observability"]
            self.assertTrue(any(path.endswith("timeline.json") for path in observability))
            self.assertTrue(any(path.endswith("resource-usage.json") for path in observability))
            self.assertTrue(any(path.endswith("log-events.json") for path in observability))
            self.assertTrue(any(path.endswith("ebpf/tooling.json") for path in observability))
            self.assertTrue(any(path.endswith("ebpf/tooling.log") for path in observability))
            self.assertTrue(any(path.endswith("ebpf/capture-status.json") for path in observability))
            self.assertTrue(any(path.endswith("ebpf/capture.log") for path in observability))
            self.assertTrue(any(path.endswith("ebpf/tcpdump.log") for path in observability))
            self.assertTrue(any(path.endswith("ebpf/network-tcpdump.log") for path in observability))
            self.assertTrue(any(path.endswith("ebpf/dns-queries.tsv") for path in observability))
            self.assertTrue(any(path.endswith("ebpf/network-flows.json") for path in observability))
            self.assertTrue(any(path.endswith("ebpf/tcp-bps.log") for path in observability))
            self.assertTrue(any(path.endswith("ebpf/tcp-flows.json") for path in observability))
            self.assertTrue(any(path.endswith("ebpf/syscalls.log") for path in observability))
            self.assertTrue(any(path.endswith("ebpf/memory-allocations.log") for path in observability))
            self.assertFalse(any(path.endswith("dns.pcap") for path in observability))
            self.assertFalse(any(path.endswith("network.pcap") for path in observability))
            self.assertTrue((public / "index.html").exists())


class ArtifactTests(unittest.TestCase):
    def test_cache_tree_includes_cache_and_tal_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work = root / "work"
            output = root / "out"
            colon_path = work / "cache/repository/ripe-ncc.tal/https/krill.ipgua.com:3030/rrdp"
            colon_path.mkdir(parents=True)
            (colon_path / "notification.xml").write_text("<notification />", encoding="utf-8")
            tal_path = work / "tals/arin.tal"
            tal_path.parent.mkdir(parents=True)
            tal_path.write_text("rsync://example.invalid/arin.cer\n", encoding="utf-8")

            summary = write_cache_tree(work, output)
            tree = read_json(output / "cache-tree.json")

            self.assertEqual(summary["path"], "cache-tree.json")
            self.assertEqual(summary["roots"], ["cache", "tals"])
            self.assertEqual(summary["files"], 2)
            paths = {
                f"{entry['root']}/{item['path']}": item
                for entry in tree["entries"]
                for item in entry["files"]
            }
            self.assertIn("cache/repository/ripe-ncc.tal/https/krill.ipgua.com:3030/rrdp/notification.xml", paths)
            self.assertIn("tals/arin.tal", paths)
            self.assertIn("sha256", paths["tals/arin.tal"])
            self.assertFalse((output / "archives/work-cache.tar.gz").exists())

    def test_raw_json_is_compressed_and_removed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            raw_dir = Path(tmp) / "raw"
            raw_dir.mkdir()
            raw = raw_dir / "validator.json"
            raw.write_text(json.dumps({"ok": True}), encoding="utf-8")

            raw_files = compress_raw_files(raw_dir)

            self.assertEqual(raw_files[0]["path"], "raw/validator.json.gz")
            self.assertIn("contentSha256", raw_files[0])
            self.assertTrue((raw_dir / "validator.json.gz").exists())
            self.assertFalse(raw.exists())

    def test_cache_tree_can_be_derived_from_legacy_archive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            archive = root / "work-cache.tar.gz"
            target = root / "cache-tree.json"
            cache_file = source / "cache/repository/example/roa.cer"
            tal_file = source / "tals/example.tal"
            cache_file.parent.mkdir(parents=True)
            tal_file.parent.mkdir(parents=True)
            cache_file.write_text("certificate", encoding="utf-8")
            tal_file.write_text("tal", encoding="utf-8")
            with tarfile.open(archive, "w:gz") as tar:
                tar.add(source / "cache", arcname="cache")
                tar.add(source / "tals", arcname="tals")

            summary = cache_tree_from_archive(archive, target)
            tree = read_json(target)

            self.assertEqual(summary["files"], 2)
            paths = {
                f"{entry['root']}/{item['path']}": item
                for entry in tree["entries"]
                for item in entry["files"]
            }
            self.assertIn("cache/repository/example/roa.cer", paths)
            self.assertIn("tals/example.tal", paths)
            self.assertIn("sha256", paths["cache/repository/example/roa.cer"])


if __name__ == "__main__":
    unittest.main()
