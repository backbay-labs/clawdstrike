#!/usr/bin/env python3
"""Sign Spider-Sense example assets (pattern DB + manifest + trust stores)."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from nacl.signing import SigningKey


def _normalize_hex(value: str) -> str:
    return value.strip().lower().removeprefix("0x")


def _derive_key_id(public_key_hex: str) -> str:
    normalized = _normalize_hex(public_key_hex)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


def _trusted_keys_digest(entries: list[dict[str, Any]]) -> str:
    if not entries:
        return hashlib.sha256(b"").hexdigest()

    normalized_entries: list[str] = []
    for entry in entries:
        key_id = _normalize_hex(str(entry.get("key_id", "")))
        public_key = _normalize_hex(str(entry.get("public_key", "")))
        status = str(entry.get("status", "")).strip().lower()
        not_before = str(entry.get("not_before", "")).strip()
        not_after = str(entry.get("not_after", "")).strip()
        normalized_entries.append(f"{key_id}|{public_key}|{status}|{not_before}|{not_after}")

    normalized_entries.sort()
    return hashlib.sha256(";".join(normalized_entries).encode("utf-8")).hexdigest()


def _manifest_signing_message(manifest: dict[str, Any]) -> bytes:
    payload = (
        "spider_sense_manifest:v1:"
        f"{str(manifest.get('pattern_db_path', '')).strip()}:"
        f"{str(manifest.get('pattern_db_version', '')).strip()}:"
        f"{_normalize_hex(str(manifest.get('pattern_db_checksum', '')))}:"
        f"{_normalize_hex(str(manifest.get('pattern_db_signature', '')))}:"
        f"{_normalize_hex(str(manifest.get('pattern_db_signature_key_id', '')))}:"
        f"{_normalize_hex(str(manifest.get('pattern_db_public_key', '')))}:"
        f"{str(manifest.get('pattern_db_trust_store_path', '')).strip()}:"
        f"{_trusted_keys_digest(manifest.get('pattern_db_trusted_keys', []) if isinstance(manifest.get('pattern_db_trusted_keys'), list) else [])}:"
        f"{str(manifest.get('not_before', '')).strip()}:"
        f"{str(manifest.get('not_after', '')).strip()}"
    )
    return payload.encode("utf-8")


def _seed_to_signing_key(seed_label: str) -> SigningKey:
    seed = hashlib.sha256(seed_label.encode("utf-8")).digest()
    return SigningKey(seed)


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def _update_baseline_policy_checksum(path: Path, checksum: str) -> None:
    raw = path.read_text(encoding="utf-8")
    updated = re.sub(
        r'(?m)^(\s*pattern_db_checksum:\s*")[^"]*(")\s*$',
        lambda match: f'{match.group(1)}{checksum}{match.group(2)}',
        raw,
    )
    path.write_text(updated, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--example-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Path to examples/spider-sense-threat-intel",
    )
    parser.add_argument(
        "--db-seed-label",
        default="clawdstrike-spider-sense-example-db-key",
        help="Deterministic seed label for DB signing key",
    )
    parser.add_argument(
        "--manifest-seed-label",
        default="clawdstrike-spider-sense-example-manifest-key",
        help="Deterministic seed label for manifest signing key",
    )
    parser.add_argument(
        "--not-before",
        default="2025-01-01T00:00:00Z",
        help="RFC3339 not_before used in trust stores/manifest",
    )
    parser.add_argument(
        "--not-after",
        default="2030-01-01T00:00:00Z",
        help="RFC3339 not_after used in trust stores/manifest",
    )
    args = parser.parse_args()

    root = args.example_root.resolve()
    data_dir = root / "data"
    pattern_db_path = data_dir / "pattern_db.s2intel-v1.json"
    manifest_path = data_dir / "pattern_db.manifest.json"
    db_trust_store_path = data_dir / "pattern_db.trust-store.json"
    manifest_trust_store_path = data_dir / "manifest.trust-store.json"
    baseline_policy_path = root / "policy.baseline.yaml"

    pattern_db_bytes = pattern_db_path.read_bytes()
    checksum = hashlib.sha256(pattern_db_bytes).hexdigest()
    version = "s2intel-v1"

    db_signing_key = _seed_to_signing_key(args.db_seed_label)
    manifest_signing_key = _seed_to_signing_key(args.manifest_seed_label)

    db_public_key = db_signing_key.verify_key.encode().hex()
    manifest_public_key = manifest_signing_key.verify_key.encode().hex()
    db_key_id = _derive_key_id(db_public_key)
    manifest_key_id = _derive_key_id(manifest_public_key)

    db_message = f"spider_sense_db:v1:{version}:{checksum}".encode("utf-8")
    db_signature = db_signing_key.sign(db_message).signature.hex()

    db_trust_store = {
        "keys": [
            {
                "key_id": db_key_id,
                "public_key": db_public_key,
                "status": "active",
                "not_before": args.not_before,
                "not_after": args.not_after,
            }
        ]
    }
    _write_json(db_trust_store_path, db_trust_store)

    manifest = {
        "pattern_db_path": pattern_db_path.name,
        "pattern_db_version": version,
        "pattern_db_checksum": checksum,
        "pattern_db_signature": db_signature,
        "pattern_db_signature_key_id": db_key_id,
        "pattern_db_trust_store_path": db_trust_store_path.name,
        "pattern_db_trusted_keys": [],
        "manifest_signature_key_id": manifest_key_id,
        "not_before": args.not_before,
        "not_after": args.not_after,
    }
    manifest_signature = manifest_signing_key.sign(
        _manifest_signing_message(manifest),
    ).signature.hex()
    manifest["manifest_signature"] = manifest_signature
    _write_json(manifest_path, manifest)

    manifest_trust_store = {
        "keys": [
            {
                "key_id": manifest_key_id,
                "public_key": manifest_public_key,
                "status": "active",
                "not_before": args.not_before,
                "not_after": args.not_after,
            }
        ]
    }
    _write_json(manifest_trust_store_path, manifest_trust_store)

    _update_baseline_policy_checksum(baseline_policy_path, checksum)

    print("Signed Spider-Sense example assets:")
    print(f"- pattern DB checksum: {checksum}")
    print(f"- DB key_id: {db_key_id}")
    print(f"- manifest key_id: {manifest_key_id}")
    print(f"- wrote: {db_trust_store_path}")
    print(f"- wrote: {manifest_path}")
    print(f"- wrote: {manifest_trust_store_path}")
    print(f"- updated: {baseline_policy_path}")


if __name__ == "__main__":
    main()
