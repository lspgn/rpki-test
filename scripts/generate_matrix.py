#!/usr/bin/env python3
"""Emit a GitHub Actions matrix from validators.yml."""

from __future__ import annotations

import argparse
import json

from rpki_project import load_config, validators


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("config", nargs="?", default="validators.yml")
    args = parser.parse_args()

    entries = []
    for item in validators(load_config(args.config)):
        entries.append(
            {
                "id": item["id"],
                "validator": item["validator"],
                "version": item["version"],
                "label": item.get("label", item["id"]),
            }
        )
    matrix = {"include": entries}
    print(f"matrix={json.dumps(matrix, separators=(',', ':'))}")


if __name__ == "__main__":
    main()
