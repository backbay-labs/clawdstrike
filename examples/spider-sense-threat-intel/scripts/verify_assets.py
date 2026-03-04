#!/usr/bin/env python3
"""Verify Spider-Sense example integrity assets."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nacl.signing import VerifyKey


def _normalize_hex(value: str) -> str:
    return value.strip().lower().removeprefix("0x")


def _derive_key_id(public_key_hex: str) -> str:
    normalized = _normalize_hex(public_key_hex)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


def _parse_rfc3339(value: str, label: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"invalid {label}: {value!r}") from exc
    if dt.tzinfo is None:
        raise ValueError(f"{label} must include timezone")
    return dt.astimezone(UTC)


def _trusted_keys_digest(entries: list[dict[str, Any]]) -> str:
    if not entries:
        return hashlib.sha256(b"").hexdigest()
    parts: list[str] = []
    for entry in entries:
        key_id = _normalize_hex(str(entry.get("key_id", "")))
        public_key = _normalize_hex(str(entry.get("public_key", "")))
        status = str(entry.get("status", "")).strip().lower()
        not_before = str(entry.get("not_before", "")).strip()
        not_after = str(entry.get("not_after", "")).strip()
        parts.append(f"{key_id}|{public_key}|{status}|{not_before}|{not_after}")
    parts.sort()
    return hashlib.sha256(";".join(parts).encode("utf-8")).hexdigest()


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


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _assert_key_validity(key: dict[str, Any], now: datetime) -> None:
    key_id = _normalize_hex(str(key.get("key_id", "")))
    public_key = _normalize_hex(str(key.get("public_key", "")))
    derived = _derive_key_id(public_key)
    if key_id != derived:
        raise ValueError(f"trust-store key_id mismatch for {key_id!r}: expected {derived!r}")
    status = str(key.get("status", "active")).strip().lower()
    if status == "revoked":
        raise ValueError(f"trust-store key {key_id} is revoked")

    not_before_raw = str(key.get("not_before", "")).strip()
    if not_before_raw:
        not_before = _parse_rfc3339(not_before_raw, f"not_before for key {key_id}")
        if now < not_before:
            raise ValueError(f"trust-store key {key_id} not yet valid")

    not_after_raw = str(key.get("not_after", "")).strip()
    if not_after_raw:
        not_after = _parse_rfc3339(not_after_raw, f"not_after for key {key_id}")
        if now > not_after:
            raise ValueError(f"trust-store key {key_id} is expired")


def _extract_baseline_checksum(policy_text: str) -> str:
    match = re.search(r'(?m)^\s*pattern_db_checksum:\s*"([^"]+)"\s*$', policy_text)
    if not match:
        raise ValueError("could not extract pattern_db_checksum from policy.baseline.yaml")
    return _normalize_hex(match.group(1))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--example-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Path to examples/spider-sense-threat-intel",
    )
    args = parser.parse_args()

    root = args.example_root.resolve()
    data_dir = root / "data"
    pattern_db_path = data_dir / "pattern_db.s2intel-v1.json"
    manifest_path = data_dir / "pattern_db.manifest.json"
    db_trust_store_path = data_dir / "pattern_db.trust-store.json"
    manifest_trust_store_path = data_dir / "manifest.trust-store.json"
    baseline_policy_path = root / "policy.baseline.yaml"

    now = datetime.now(tz=UTC)

    pattern_db_bytes = pattern_db_path.read_bytes()
    checksum = hashlib.sha256(pattern_db_bytes).hexdigest()

    baseline_checksum = _extract_baseline_checksum(baseline_policy_path.read_text(encoding="utf-8"))
    if baseline_checksum != checksum:
        raise ValueError(
            f"baseline policy checksum mismatch: expected {checksum}, found {baseline_checksum}",
        )

    manifest = _load_json(manifest_path)
    db_store = _load_json(db_trust_store_path)
    manifest_store = _load_json(manifest_trust_store_path)

    if not isinstance(manifest, dict):
        raise ValueError("manifest must be a JSON object")
    if not isinstance(db_store, dict) or not isinstance(db_store.get("keys"), list):
        raise ValueError("DB trust store must be an object with keys[]")
    if not isinstance(manifest_store, dict) or not isinstance(manifest_store.get("keys"), list):
        raise ValueError("manifest trust store must be an object with keys[]")

    manifest_db_checksum = _normalize_hex(str(manifest.get("pattern_db_checksum", "")))
    if manifest_db_checksum != checksum:
        raise ValueError(
            f"manifest checksum mismatch: expected {checksum}, found {manifest_db_checksum}",
        )

    manifest_not_before = str(manifest.get("not_before", "")).strip()
    if manifest_not_before and now < _parse_rfc3339(manifest_not_before, "manifest not_before"):
        raise ValueError("manifest not yet valid")

    manifest_not_after = str(manifest.get("not_after", "")).strip()
    if manifest_not_after and now > _parse_rfc3339(manifest_not_after, "manifest not_after"):
        raise ValueError("manifest expired")

    db_keys = db_store["keys"]
    if len(db_keys) != 1:
        raise ValueError(f"expected exactly one DB trust key, found {len(db_keys)}")
    db_key = db_keys[0]
    _assert_key_validity(db_key, now)
    db_key_id = _normalize_hex(str(db_key.get("key_id", "")))
    db_signature_key_id = _normalize_hex(str(manifest.get("pattern_db_signature_key_id", "")))
    if db_signature_key_id != db_key_id:
        raise ValueError(
            f"DB signature key_id mismatch: expected {db_key_id}, found {db_signature_key_id}",
        )

    db_message = (
        f"spider_sense_db:v1:{manifest.get('pattern_db_version', '').strip()}:{manifest_db_checksum}"
    ).encode("utf-8")
    db_signature = bytes.fromhex(_normalize_hex(str(manifest.get("pattern_db_signature", ""))))
    db_public_key = bytes.fromhex(_normalize_hex(str(db_key.get("public_key", ""))))
    VerifyKey(db_public_key).verify(db_message, db_signature)

    manifest_keys = manifest_store["keys"]
    if len(manifest_keys) != 1:
        raise ValueError(f"expected exactly one manifest trust key, found {len(manifest_keys)}")
    manifest_key = manifest_keys[0]
    _assert_key_validity(manifest_key, now)
    manifest_key_id = _normalize_hex(str(manifest_key.get("key_id", "")))
    manifest_signature_key_id = _normalize_hex(str(manifest.get("manifest_signature_key_id", "")))
    if manifest_signature_key_id != manifest_key_id:
        raise ValueError(
            f"manifest signature key_id mismatch: expected {manifest_key_id}, found {manifest_signature_key_id}",
        )

    manifest_signature = bytes.fromhex(_normalize_hex(str(manifest.get("manifest_signature", ""))))
    manifest_public_key = bytes.fromhex(_normalize_hex(str(manifest_key.get("public_key", ""))))
    VerifyKey(manifest_public_key).verify(_manifest_signing_message(manifest), manifest_signature)

    print("Spider-Sense example assets verified:")
    print(f"- pattern DB checksum: {checksum}")
    print(f"- DB signature key_id: {db_key_id}")
    print(f"- manifest signature key_id: {manifest_key_id}")
    print("- manifest validity window: OK")
    print("- signature chain: OK")


if __name__ == "__main__":
    main()
