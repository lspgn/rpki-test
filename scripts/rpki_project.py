#!/usr/bin/env python3
"""Shared helpers for the RPKI validator Pages project."""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PAYLOADS = ("routeOrigins", "routerKeys", "aspas")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_config(path: str | Path) -> dict[str, Any]:
    """Load validators.yml.

    The file is JSON-compatible YAML so the project does not need PyYAML on
    GitHub-hosted runners.
    """
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def validators(config: dict[str, Any]) -> list[dict[str, Any]]:
    defaults = config.get("defaults", {})
    result = []
    for item in config.get("validators", []):
        merged = dict(item)
        merged.setdefault("timeout_seconds", defaults.get("timeout_seconds", 7200))
        if "threads" in defaults:
            merged.setdefault("threads", defaults["threads"])
        payloads = dict(defaults.get("payloads", {}))
        payloads.update(item.get("payloads", {}))
        merged["payloads"] = payloads
        result.append(merged)
    return result


def find_validator(config: dict[str, Any], entry_id: str) -> dict[str, Any]:
    for item in validators(config):
        if item["id"] == entry_id:
            return item
    raise SystemExit(f"validator entry not found: {entry_id}")


def read_json(path: str | Path) -> Any:
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: str | Path, data: Any) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write("\n")


def gzip_file(path: str | Path) -> Path:
    source = Path(path)
    target = source.with_suffix(source.suffix + ".gz")
    with source.open("rb") as src, gzip.open(target, "wb", compresslevel=9) as dst:
        shutil.copyfileobj(src, dst)
    return target


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def directory_size(path: str | Path) -> int:
    root = Path(path)
    if not root.exists():
        return 0
    return sum(item.stat().st_size for item in root.rglob("*") if item.is_file())


def file_inventory(root: str | Path) -> list[dict[str, Any]]:
    base = Path(root)
    files = []
    if not base.exists():
        return files
    for item in sorted(base.rglob("*")):
        if item.is_file():
            rel = item.relative_to(base).as_posix()
            files.append({"path": rel, "size": item.stat().st_size, "sha256": sha256_file(item)})
    return files


def as_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if text.upper().startswith("AS"):
        text = text[2:]
    try:
        return int(text)
    except ValueError:
        return None


def first_present(data: dict[str, Any], names: tuple[str, ...]) -> Any:
    for name in names:
        if name in data and data[name] not in (None, ""):
            return data[name]
    return None


def source_ta(data: dict[str, Any]) -> str | None:
    value = first_present(data, ("ta", "tal", "trustAnchor", "trust_anchor", "trust-anchor"))
    if value is not None:
        return str(value)
    source = data.get("source")
    if isinstance(source, dict):
        return source_ta(source)
    if isinstance(source, list):
        for item in source:
            if isinstance(item, dict):
                value = source_ta(item)
                if value is not None:
                    return value
    return None


def compact_source_files(data: dict[str, Any]) -> list[dict[str, Any]]:
    candidates = []
    source = data.get("source")
    if isinstance(source, dict):
        candidates.append(source)
    elif isinstance(source, list):
        candidates.extend(item for item in source if isinstance(item, dict))
    for key in ("sourceFiles", "source_files", "files"):
        value = data.get(key)
        if isinstance(value, list):
            candidates.extend(value)

    output = []
    for value in candidates:
        if isinstance(value, str):
            output.append({"path": value})
        elif isinstance(value, dict):
            path = value.get("path") or value.get("uri") or value.get("url")
            sha256 = value.get("sha256") or value.get("hash")
            if path or sha256:
                entry = {}
                if path:
                    entry["path"] = path
                if sha256:
                    entry["sha256"] = sha256
                output.append(entry)
    return output


def add_source_files(normalized: dict[str, Any], data: dict[str, Any]) -> dict[str, Any]:
    files = compact_source_files(data)
    if files:
        normalized["sourceFiles"] = files
    return normalized


def normalize_route_origin(data: dict[str, Any]) -> dict[str, Any] | None:
    prefix = first_present(data, ("prefix", "ipPrefix", "ip_prefix", "routeOrigin", "route_origin"))
    asn = first_present(data, ("asn", "asID", "asid", "origin", "originAsn", "origin_asn"))
    max_length = first_present(data, ("maxLength", "max_length", "max-len", "maxlen", "maxlength"))
    if prefix is None or asn is None:
        return None
    parsed_asn = as_int(asn)
    parsed_max = as_int(max_length)
    return add_source_files({
        "asn": parsed_asn if parsed_asn is not None else asn,
        "prefix": str(prefix),
        "maxLength": parsed_max,
        "ta": source_ta(data),
    }, data)


def normalize_router_key(data: dict[str, Any]) -> dict[str, Any] | None:
    ski = first_present(data, ("SKI", "ski", "keyIdentifier", "key_identifier", "key-identifier"))
    key = first_present(data, ("routerPublicKey", "router_public_key", "publicKey", "public_key"))
    asn = first_present(data, ("asn", "asID", "asid", "routerAsn", "router_asn"))
    if ski is None or key is None or asn is None:
        return None
    parsed_asn = as_int(asn)
    return add_source_files({
        "asn": parsed_asn if parsed_asn is not None else asn,
        "ski": str(ski),
        "routerPublicKey": str(key),
        "ta": source_ta(data),
    }, data)


def normalize_aspa(data: dict[str, Any]) -> dict[str, Any] | None:
    customer = first_present(data, ("customer", "customerAsid", "customer_asid", "customerAsn", "customer_asn"))
    providers = first_present(data, ("providers", "providerAsns", "provider_asns", "providerSet", "provider_set"))
    if customer is None or providers is None:
        return None
    if isinstance(providers, dict):
        providers = providers.get("asns", providers.get("providers", []))
    if not isinstance(providers, list):
        providers = [providers]
    parsed_customer = as_int(customer)
    parsed_providers = [as_int(provider) for provider in providers]
    return add_source_files({
        "customer": parsed_customer if parsed_customer is not None else customer,
        "afi": first_present(data, ("afi", "addressFamily", "address_family")),
        "providers": [provider for provider in parsed_providers if provider is not None],
        "ta": source_ta(data),
    }, data)


def walk_json(value: Any) -> list[dict[str, Any]]:
    found = []
    if isinstance(value, dict):
        found.append(value)
        for child in value.values():
            found.extend(walk_json(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(walk_json(child))
    return found


def dedupe(items: list[dict[str, Any]], keys: tuple[str, ...]) -> list[dict[str, Any]]:
    seen = set()
    output = []
    for item in items:
        marker = tuple(json.dumps(item.get(key), sort_keys=True) for key in keys)
        if marker in seen:
            continue
        seen.add(marker)
        output.append(item)
    return sorted(output, key=lambda item: tuple(str(item.get(key, "")) for key in keys))


def normalize_payloads(raw_values: list[Any], entry: dict[str, Any]) -> dict[str, Any]:
    routes: list[dict[str, Any]] = []
    keys: list[dict[str, Any]] = []
    aspas: list[dict[str, Any]] = []

    for raw in raw_values:
        for data in walk_json(raw):
            route = normalize_route_origin(data)
            if route is not None:
                routes.append(route)
            router_key = normalize_router_key(data)
            if router_key is not None:
                keys.append(router_key)
            aspa = normalize_aspa(data)
            if aspa is not None:
                aspas.append(aspa)

    payloads = entry.get("payloads", {})
    unsupported = [name for name in PAYLOADS if payloads.get(name) is False]
    generated_at = utc_now()
    normalized = {
        "metadata": {
            "id": entry["id"],
            "validator": entry["validator"],
            "version": entry["version"],
            "label": entry.get("label", entry["id"]),
            "image": entry.get("image"),
            "generatedAt": generated_at,
            "payloads": payloads,
            "unsupported": unsupported,
        },
        "routeOrigins": dedupe(routes, ("asn", "prefix", "maxLength", "ta")),
        "routerKeys": dedupe(keys, ("asn", "ski", "routerPublicKey", "ta")),
        "aspas": dedupe(aspas, ("customer", "afi", "providers", "ta")),
    }
    return normalized


def payload_key(payload: str, item: dict[str, Any]) -> str:
    if payload == "routeOrigins":
        return f"{item.get('asn')}|{item.get('prefix')}|{item.get('maxLength')}|{item.get('ta')}"
    if payload == "routerKeys":
        return f"{item.get('asn')}|{item.get('ski')}|{item.get('routerPublicKey')}|{item.get('ta')}"
    if payload == "aspas":
        providers = ",".join(str(provider) for provider in item.get("providers", []))
        return f"{item.get('customer')}|{item.get('afi')}|{providers}|{item.get('ta')}"
    raise ValueError(f"unknown payload: {payload}")


def payload_counts(normalized: dict[str, Any]) -> dict[str, int]:
    return {payload: len(normalized.get(payload, [])) for payload in PAYLOADS}


def copytree_contents(source: str | Path, target: str | Path) -> None:
    src = Path(source)
    dst = Path(target)
    if not src.exists():
        return
    for item in src.rglob("*"):
        rel = item.relative_to(src)
        out = dst / rel
        if item.is_dir():
            out.mkdir(parents=True, exist_ok=True)
        elif item.is_file():
            out.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, out)


def env_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    if not value:
        return default
    try:
        return int(value)
    except ValueError:
        return default
