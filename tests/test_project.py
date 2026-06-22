#!/usr/bin/env python3

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from aggregate_results import main as aggregate_main  # noqa: E402
from check_observability_tools import collect_tooling_status  # noqa: E402
from rpki_project import load_config, normalize_payloads, payload_counts, read_json, validators, write_json  # noqa: E402
from run_validator import archive_work_dir, parse_bytes, summarize_docker_stats  # noqa: E402
from summarize_network_packets import read_packets, summarize_packets  # noqa: E402
from summarize_tcp_bps import parse_tcptop  # noqa: E402


class NormalizationTests(unittest.TestCase):
    def test_routinator_all_payloads(self) -> None:
        raw = read_json(ROOT / "tests/fixtures/routinator/raw.json")
        entry = {
            "id": "routinator-test",
            "validator": "routinator",
            "version": "test",
            "payloads": {"routeOrigins": True, "routerKeys": True, "aspas": True},
        }
        normalized = normalize_payloads([raw], entry)
        self.assertEqual(payload_counts(normalized), {"routeOrigins": 1, "routerKeys": 1, "aspas": 1})
        self.assertEqual(normalized["routeOrigins"][0]["asn"], 64496)
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
                "\t".join(
                    (
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
                )
                + "\n"
                + "100.0\t60\t172.17.0.2\t192.0.2.53\t\t\t\t\t50000\t53\tDNS\texample.net\n"
                + "100.5\t120\t192.0.2.53\t172.17.0.2\t\t\t\t\t53\t50000\tDNS\texample.net\n"
                + "101.2\t1000\t203.0.113.10\t172.17.0.2\t\t\t443\t40000\t\t\tTCP\t\n"
                + "101.4\t500\t172.17.0.2\t203.0.113.10\t\t\t40000\t443\t\t\tTCP\t\n"
                + "101.4\t500\t172.17.0.2\t203.0.113.10\t\t\t40000\t443\t\t\tTCP\t\n"
                + "101.8\t900\t10.1.0.1\t198.51.100.1\t\t\t12345\t443\t\t\tTCP\t\n",
                encoding="utf-8",
            )

            summary = summarize_packets(read_packets(source), ["172.17.0.2"], bucket_seconds=1.0)

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
        dns_flow = next(flow for flow in summary["flows"] if flow["protocol"] == "UDP")
        self.assertEqual(dns_flow["dnsNames"], ["example.net"])


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


class AggregateTests(unittest.TestCase):
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
                write_json(out / "resource-usage.json", status["resourceUsage"])
                (out / "docker-stats.jsonl").write_text("", encoding="utf-8")
                ebpf_dir = out / "ebpf"
                ebpf_dir.mkdir()
                write_json(ebpf_dir / "tooling.json", {"canAttemptCapture": False})
                (ebpf_dir / "tooling.log").write_text("canAttemptCapture=False\n", encoding="utf-8")
                write_json(ebpf_dir / "capture-status.json", {"started": True})
                (ebpf_dir / "capture.log").write_text("capture finished\n", encoding="utf-8")
                (ebpf_dir / "tcpdump.log").write_text("1 packet captured\n", encoding="utf-8")
                (ebpf_dir / "network-tcpdump.log").write_text("2 packets captured\n", encoding="utf-8")
                (ebpf_dir / "dns-queries.tsv").write_text("time\tsrc\tdst\tquery\n", encoding="utf-8")
                write_json(ebpf_dir / "network-flows.json", {"flowCount": 1, "flows": []})
                (ebpf_dir / "tcp-bps.log").write_text("127.0.0.1:443 1024\n", encoding="utf-8")
                write_json(ebpf_dir / "tcp-flows.json", {"flowCount": 1, "flows": []})
                (ebpf_dir / "syscalls.log").write_text("syscall count\n", encoding="utf-8")
                (ebpf_dir / "memory-allocations.log").write_text("allocation stack\n", encoding="utf-8")
                (ebpf_dir / "dns.pcap").write_bytes(b"not published")
                write_json(out / "normalized.json", normalize_payloads([raw], {**status, "image": "fixture"}))
                (out / "stdout.log").write_text("", encoding="utf-8")
                (out / "stderr.log").write_text("", encoding="utf-8")

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
            self.assertEqual(manifest["latestRun"], "fixture-run")
            self.assertEqual(len(latest["entries"]), 2)
            self.assertEqual(latest["entries"][0]["resourceUsage"]["peakProcessorCores"], 1.25)
            observability = latest["entries"][0]["paths"]["observability"]
            self.assertTrue(any(path.endswith("resource-usage.json") for path in observability))
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


class ArchiveTests(unittest.TestCase):
    def test_work_cache_archive_uses_safe_artifact_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work = root / "work"
            output = root / "out"
            colon_path = work / "cache/repository/ripe-ncc.tal/https/krill.ipgua.com:3030/rrdp"
            colon_path.mkdir(parents=True)
            (colon_path / "notification.xml").write_text("<notification />", encoding="utf-8")

            archives = archive_work_dir(work, output)

            self.assertEqual(archives[0]["path"], "archives/work-cache.tar.gz")
            self.assertTrue((output / "archives/work-cache.tar.gz").exists())
            self.assertNotIn(":", archives[0]["path"])


if __name__ == "__main__":
    unittest.main()
