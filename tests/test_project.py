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

from aggregate_results import cache_tree_from_archive, main as aggregate_main  # noqa: E402
from rpki_project import load_config, normalize_payloads, payload_counts, read_json, validators, write_json  # noqa: E402
from run_validator import compress_raw_files, write_cache_tree  # noqa: E402


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
            self.assertEqual(manifest["latestRun"], "fixture-run")
            self.assertEqual(len(manifest["runs"]), 1)
            self.assertEqual(len(latest["entries"]), 2)
            self.assertEqual(latest["reports"]["routeOrigins"]["totalObjects"], 2)
            self.assertEqual(latest["reports"]["routeOrigins"]["differingObjects"], 1)
            self.assertEqual(latest["reports"]["routeOrigins"]["includedRows"], 2)
            self.assertEqual(latest["reports"]["aspas"]["excludedValidators"][0]["reason"], "unsupported")
            extra = [row for row in report["rows"] if row["object"]["prefix"] == "198.51.100.0/24"][0]
            self.assertEqual(extra["seenBy"], ["routinator-test"])
            self.assertEqual(extra["missingFrom"], ["fort-test"])
            self.assertTrue((public / "data/runs/fixture-run/routinator-test/raw/raw.json.gz").exists())
            self.assertFalse((public / "data/runs/fixture-run/routinator-test/raw/raw.json").exists())
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
