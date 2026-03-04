#!/usr/bin/env python3
"""Refresh Spider-Sense example embeddings from a provider or deterministic mode."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any
from urllib import error as urllib_error
from urllib import request as urllib_request


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def _deterministic_embedding(text: str, dims: int) -> list[float]:
    values: list[float] = []
    text_bytes = text.encode("utf-8")
    for i in range(dims):
        digest = hashlib.sha256(text_bytes + f"|{i}|clawdstrike-spider-sense".encode("utf-8")).digest()
        # Spread in [-1, 1] for realistic cosine behavior.
        raw = int.from_bytes(digest[:8], "big") / float(2**64 - 1)
        values.append((raw * 2.0) - 1.0)
    return values


def _provider_embedding(url: str, api_key: str, model: str, text: str, timeout_secs: float) -> list[float]:
    body = json.dumps({"input": text, "model": model}).encode("utf-8")
    req = urllib_request.Request(
        url=url,
        data=body,
        headers={
            "content-type": "application/json",
            "accept": "application/json",
            "authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    try:
        with urllib_request.urlopen(req, timeout=timeout_secs) as resp:
            raw = resp.read().decode("utf-8")
    except urllib_error.HTTPError as exc:
        payload = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"provider HTTP {exc.code}: {payload}") from exc
    except urllib_error.URLError as exc:
        raise RuntimeError(f"provider request failed: {exc}") from exc

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"provider returned invalid JSON: {exc}") from exc

    data = parsed.get("data")
    if not isinstance(data, list) or not data:
        raise RuntimeError("provider response missing data[0]")
    first = data[0]
    if not isinstance(first, dict):
        raise RuntimeError("provider response data[0] must be an object")
    emb = first.get("embedding")
    if not isinstance(emb, list) or not emb:
        raise RuntimeError("provider response missing non-empty embedding")

    result: list[float] = []
    for value in emb:
        if not isinstance(value, (int, float)):
            raise RuntimeError("provider embedding must contain only numbers")
        result.append(float(value))
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--example-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Path to examples/spider-sense-threat-intel",
    )
    parser.add_argument(
        "--deterministic",
        action="store_true",
        help="Use deterministic local embeddings (no API calls).",
    )
    parser.add_argument(
        "--dims",
        type=int,
        default=6,
        help="Embedding dimensions in deterministic mode.",
    )
    parser.add_argument(
        "--provider-url",
        default=os.getenv("SPIDER_SENSE_EMBEDDING_URL", ""),
        help="Embedding API URL (OpenAI-compatible).",
    )
    parser.add_argument(
        "--provider-key",
        default=os.getenv("SPIDER_SENSE_EMBEDDING_KEY", ""),
        help="Embedding API key.",
    )
    parser.add_argument(
        "--model",
        default=os.getenv("SPIDER_SENSE_EMBEDDING_MODEL", "text-embedding-3-small"),
        help="Embedding model identifier.",
    )
    parser.add_argument(
        "--timeout-secs",
        type=float,
        default=15.0,
        help="Per-request timeout in seconds.",
    )
    args = parser.parse_args()

    if args.deterministic and args.dims < 2:
        raise ValueError("--dims must be >= 2 in deterministic mode")

    if not args.deterministic:
        if not args.provider_url or not args.provider_key:
            print(
                "error: --provider-url and --provider-key (or SPIDER_SENSE_EMBEDDING_URL/KEY) "
                "are required unless --deterministic is set",
                file=sys.stderr,
            )
            sys.exit(2)

    root = args.example_root.resolve()
    data_dir = root / "data"
    catalog_path = data_dir / "threat_intel_catalog.json"
    profiles_path = data_dir / "behavior_profiles.json"
    scenarios_path = data_dir / "scenarios.json"
    pattern_db_path = data_dir / "pattern_db.s2intel-v1.json"

    catalog = _load_json(catalog_path)
    profiles_doc = _load_json(profiles_path)
    scenarios_doc = _load_json(scenarios_path)

    if not isinstance(catalog, list):
        raise ValueError("threat_intel_catalog.json must be a list")
    if not isinstance(profiles_doc, dict) or not isinstance(profiles_doc.get("profiles"), list):
        raise ValueError("behavior_profiles.json must contain profiles[]")
    if not isinstance(scenarios_doc, dict) or not isinstance(scenarios_doc.get("scenarios"), list):
        raise ValueError("scenarios.json must contain scenarios[]")

    def embed_text(text: str) -> list[float]:
        if args.deterministic:
            return _deterministic_embedding(text, args.dims)
        return _provider_embedding(
            url=args.provider_url,
            api_key=args.provider_key,
            model=args.model,
            text=text,
            timeout_secs=args.timeout_secs,
        )

    for entry in catalog:
        if not isinstance(entry, dict):
            raise ValueError("catalog entries must be objects")
        text = str(entry.get("intel_text", "")).strip()
        if not text:
            raise ValueError(f"catalog entry {entry.get('id', '<unknown>')} missing intel_text")
        entry["embedding"] = embed_text(text)

    for profile in profiles_doc["profiles"]:
        if not isinstance(profile, dict):
            raise ValueError("profiles entries must be objects")
        text = str(profile.get("profile_text", "")).strip()
        if not text:
            raise ValueError(f"profile {profile.get('profile_id', '<unknown>')} missing profile_text")
        profile["embedding"] = embed_text(text)
    profiles_doc["model"] = args.model

    for scenario in scenarios_doc["scenarios"]:
        if not isinstance(scenario, dict):
            raise ValueError("scenarios entries must be objects")
        text = str(scenario.get("action_text", "")).strip()
        if not text:
            raise ValueError(f"scenario {scenario.get('scenario_id', '<unknown>')} missing action_text")
        scenario["embedding"] = embed_text(text)
    scenarios_doc["model"] = args.model

    pattern_db: list[dict[str, Any]] = []
    for entry in catalog:
        pattern_db.append(
            {
                "id": str(entry["id"]),
                "category": str(entry["category"]),
                "stage": str(entry["stage"]),
                "label": str(entry["label"]),
                "embedding": entry["embedding"],
            },
        )

    _write_json(catalog_path, catalog)
    _write_json(profiles_path, profiles_doc)
    _write_json(scenarios_path, scenarios_doc)
    _write_json(pattern_db_path, pattern_db)

    print("Refreshed Spider-Sense example embeddings:")
    print(f"- catalog: {catalog_path}")
    print(f"- profiles: {profiles_path}")
    print(f"- scenarios: {scenarios_path}")
    print(f"- pattern DB: {pattern_db_path}")
    print("Next: run scripts/sign_artifacts.py to re-pin checksums/signatures.")


if __name__ == "__main__":
    main()
