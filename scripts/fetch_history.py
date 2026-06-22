#!/usr/bin/env python3
"""Fetch previously published Pages data so new deployments can retain history."""

from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urljoin

from rpki_project import write_json


def fetch_bytes(url: str, timeout: int = 30) -> bytes | None:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310 - URL is operator-provided.
            return response.read()
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError):
        return None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/") + "/"
    output = Path(args.output)
    manifest_url = urljoin(base_url, "data/manifest.json")
    manifest_bytes = fetch_bytes(manifest_url)
    if manifest_bytes is None:
        write_json(output / "fetch-history.json", {"baseUrl": base_url, "status": "no-previous-manifest"})
        return

    manifest = json.loads(manifest_bytes.decode("utf-8"))
    paths = {"data/manifest.json", "data/latest.json"}
    for run in manifest.get("runs", []):
        for item in run.get("files", []):
            paths.add("data/runs/" + run["id"].strip("/") + "/" + item["path"].lstrip("/"))

    fetched = []
    missed = []
    for rel in sorted(paths):
        body = fetch_bytes(urljoin(base_url, rel))
        if body is None:
            missed.append(rel)
            continue
        target = output / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
        fetched.append(rel)

    write_json(
        output / "fetch-history.json",
        {"baseUrl": base_url, "status": "ok", "fetched": len(fetched), "missed": missed},
    )


if __name__ == "__main__":
    main()
