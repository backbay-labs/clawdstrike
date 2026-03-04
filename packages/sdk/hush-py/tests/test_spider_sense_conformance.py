"""Cross-SDK Spider-Sense conformance vectors."""

from __future__ import annotations

import json
from pathlib import Path

from clawdstrike.guards.base import CustomAction, GuardContext
from clawdstrike.guards.spider_sense import SpiderSenseConfig, SpiderSenseGuard


def test_spider_sense_conformance_vectors() -> None:
    repo_root = Path(__file__).resolve().parents[4]
    vectors_path = repo_root / "fixtures" / "spider-sense" / "conformance_vectors.json"
    vectors = json.loads(vectors_path.read_text(encoding="utf-8"))

    for vector in vectors:
        guard = SpiderSenseGuard(SpiderSenseConfig(**vector["config"]))
        for check in vector["checks"]:
            result = guard.check(
                CustomAction(
                    custom_type="spider_sense",
                    custom_data={"embedding": check["embedding"]},
                ),
                GuardContext(),
            )
            assert result.allowed == check["expected_allowed"], f'{vector["name"]}:{check["name"]}'
            assert result.severity.value == check["expected_severity"]
            assert result.details is not None
            assert result.details["verdict"] == check["expected_verdict"]
            assert result.details["embedding_from"] == check["expected_embedding_from"]
            assert result.details["analysis"] == check["expected_analysis"]
            top_score = float(result.details["top_score"])
            assert check["top_score_min"] <= top_score <= check["top_score_max"]
            assert isinstance(result.details["top_matches"], list)
            assert len(result.details["top_matches"]) == check["expected_top_matches_len"]
            first = result.details["top_matches"][0]
            assert "id" in first
            assert "category" in first
            assert "stage" in first
            assert "label" in first
            assert "score" in first
