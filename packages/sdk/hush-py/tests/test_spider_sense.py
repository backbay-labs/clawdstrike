"""Tests for Spider Sense detection guard."""

import hashlib
import json
from urllib import error as urllib_error

import pytest

from clawdstrike.guards.base import CustomAction, GuardContext, Severity
from clawdstrike.guards.spider_sense import (
    PatternDb,
    ScreeningVerdict,
    SpiderSenseConfig,
    SpiderSenseDetector,
    SpiderSenseDetectorConfig,
    SpiderSenseGuard,
    cosine_similarity,
)


# ── Helpers ───────────────────────────────────────────────────────────────

def _test_pattern_json() -> str:
    """Return a 3-entry pattern DB JSON string with 3-dimensional embeddings."""
    return json.dumps([
        {"id": "p1", "category": "prompt_injection", "stage": "perception", "label": "ignore previous", "embedding": [1.0, 0.0, 0.0]},
        {"id": "p2", "category": "data_exfiltration", "stage": "action", "label": "exfil data", "embedding": [0.0, 1.0, 0.0]},
        {"id": "p3", "category": "privilege_escalation", "stage": "cognition", "label": "escalate", "embedding": [0.0, 0.0, 1.0]},
    ])


def _test_pattern_db() -> PatternDb:
    return PatternDb.from_json(_test_pattern_json())


def _test_patterns_as_dicts() -> list[dict]:
    return json.loads(_test_pattern_json())


def _checksum_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ── Cosine Similarity ─────────────────────────────────────────────────────


class TestCosineSimilarity:
    def test_identical_vectors(self) -> None:
        a = [1.0, 0.0, 0.0]
        assert abs(cosine_similarity(a, a) - 1.0) < 1e-10

    def test_orthogonal_vectors(self) -> None:
        a = [1.0, 0.0, 0.0]
        b = [0.0, 1.0, 0.0]
        assert abs(cosine_similarity(a, b)) < 1e-10

    def test_zero_vector(self) -> None:
        a = [0.0, 0.0, 0.0]
        b = [1.0, 2.0, 3.0]
        assert cosine_similarity(a, b) == 0.0

    def test_different_lengths(self) -> None:
        a = [1.0, 0.0]
        b = [1.0, 0.0, 0.0]
        assert cosine_similarity(a, b) == 0.0

    def test_opposite_vectors(self) -> None:
        a = [1.0, 0.0]
        b = [-1.0, 0.0]
        assert abs(cosine_similarity(a, b) - (-1.0)) < 1e-10

    def test_both_zero_vectors(self) -> None:
        a = [0.0, 0.0]
        b = [0.0, 0.0]
        assert cosine_similarity(a, b) == 0.0

    def test_empty_vectors(self) -> None:
        assert cosine_similarity([], []) == 0.0

    def test_parallel_vectors(self) -> None:
        a = [1.0, 2.0, 3.0]
        b = [2.0, 4.0, 6.0]
        assert abs(cosine_similarity(a, b) - 1.0) < 1e-10


# ── PatternDb ─────────────────────────────────────────────────────────────


class TestPatternDb:
    def test_from_json_valid(self) -> None:
        db = _test_pattern_db()
        assert len(db) == 3
        assert db.expected_dim == 3
        assert db.is_empty is False

    def test_from_json_empty_array(self) -> None:
        with pytest.raises(ValueError, match="must contain at least one entry"):
            PatternDb.from_json("[]")

    def test_from_json_dimension_mismatch(self) -> None:
        data = json.dumps([
            {"id": "p1", "category": "a", "stage": "b", "label": "c", "embedding": [0.1, 0.2]},
            {"id": "p2", "category": "a", "stage": "b", "label": "d", "embedding": [0.1]},
        ])
        with pytest.raises(ValueError, match="dimension mismatch"):
            PatternDb.from_json(data)

    def test_from_json_invalid_json(self) -> None:
        with pytest.raises(ValueError, match="failed to parse"):
            PatternDb.from_json("{not valid json")

    def test_from_json_rejects_non_finite_embedding(self) -> None:
        data = """
[
  {
    "id": "p1",
    "category": "a",
    "stage": "b",
    "label": "c",
    "embedding": [1.0, NaN, 0.0]
  }
]
"""
        with pytest.raises(ValueError, match="invalid embedding values"):
            PatternDb.from_json(data)

    def test_search_returns_top_k(self) -> None:
        db = _test_pattern_db()
        query = [1.0, 0.0, 0.0]
        results = db.search(query, 2)
        assert len(results) == 2
        assert results[0].entry.id == "p1"
        assert abs(results[0].score - 1.0) < 1e-6

    def test_search_sorted_descending(self) -> None:
        db = _test_pattern_db()
        query = [0.8, 0.6, 0.0]
        results = db.search(query, 3)
        for i in range(len(results) - 1):
            assert results[i].score >= results[i + 1].score

    def test_expected_dim_property(self) -> None:
        db = _test_pattern_db()
        assert db.expected_dim == 3


# ── SpiderSenseDetector ──────────────────────────────────────────────────


class TestSpiderSenseDetector:
    def test_screen_deny_identical_vector(self) -> None:
        db = _test_pattern_db()
        config = SpiderSenseDetectorConfig(
            similarity_threshold=0.85, ambiguity_band=0.10, top_k=5,
        )
        detector = SpiderSenseDetector(db, config)
        # Identical vector -> score 1.0, above upper bound 0.95
        result = detector.screen([1.0, 0.0, 0.0])
        assert result.verdict == ScreeningVerdict.DENY
        assert abs(result.top_score - 1.0) < 1e-6

    def test_screen_allow_low_similarity(self) -> None:
        db = _test_pattern_db()
        config = SpiderSenseDetectorConfig(
            similarity_threshold=0.85, ambiguity_band=0.10, top_k=5,
        )
        detector = SpiderSenseDetector(db, config)
        # Equally similar to all 3 orthogonal patterns -> score ~0.577
        # Below lower bound 0.75 -> allow
        result = detector.screen([0.577, 0.577, 0.577])
        assert result.verdict == ScreeningVerdict.ALLOW

    def test_screen_ambiguous_partial_similarity(self) -> None:
        db = _test_pattern_db()
        config = SpiderSenseDetectorConfig(
            similarity_threshold=0.50, ambiguity_band=0.10, top_k=5,
        )
        detector = SpiderSenseDetector(db, config)
        # Score ~0.577, within band [0.40, 0.60]
        result = detector.screen([0.577, 0.577, 0.577])
        assert result.verdict == ScreeningVerdict.AMBIGUOUS

    def test_expected_dim_and_pattern_count(self) -> None:
        db = _test_pattern_db()
        detector = SpiderSenseDetector(db)
        assert detector.expected_dim == 3
        assert detector.pattern_count == 3

    def test_default_config(self) -> None:
        db = _test_pattern_db()
        detector = SpiderSenseDetector(db)
        result = detector.screen([1.0, 0.0, 0.0])
        assert result.threshold == 0.85
        assert result.ambiguity_band == 0.10

    def test_invalid_threshold_rejected(self) -> None:
        db = _test_pattern_db()
        config = SpiderSenseDetectorConfig(similarity_threshold=1.5)
        with pytest.raises(ValueError, match="similarity_threshold"):
            SpiderSenseDetector(db, config)

    def test_zero_top_k_rejected(self) -> None:
        db = _test_pattern_db()
        config = SpiderSenseDetectorConfig(top_k=0)
        with pytest.raises(ValueError, match="top_k"):
            SpiderSenseDetector(db, config)

    def test_out_of_range_bounds_rejected(self) -> None:
        db = _test_pattern_db()
        config = SpiderSenseDetectorConfig(
            similarity_threshold=0.95, ambiguity_band=0.10,
        )
        with pytest.raises(ValueError, match="invalid decision range"):
            SpiderSenseDetector(db, config)

    def test_screening_result_fields(self) -> None:
        db = _test_pattern_db()
        detector = SpiderSenseDetector(db)
        result = detector.screen([1.0, 0.0, 0.0])
        assert result.threshold == 0.85
        assert result.ambiguity_band == 0.10
        assert len(result.top_matches) > 0
        assert result.top_matches[0].entry.id == "p1"


# ── SpiderSenseGuard ─────────────────────────────────────────────────────


class TestSpiderSenseGuard:
    def test_name(self) -> None:
        guard = SpiderSenseGuard()
        assert guard.name == "spider_sense"

    def test_handles_all_action_types(self) -> None:
        guard = SpiderSenseGuard()
        action = CustomAction(custom_type="anything", custom_data={})
        assert guard.handles(action) is True

    def test_disabled_guard_does_not_handle(self) -> None:
        guard = SpiderSenseGuard(SpiderSenseConfig(enabled=False))
        action = CustomAction(custom_type="anything", custom_data={})
        assert guard.handles(action) is False

    def test_embedding_deny(self) -> None:
        config = SpiderSenseConfig(
            patterns=_test_patterns_as_dicts(),
            similarity_threshold=0.85,
            ambiguity_band=0.10,
        )
        guard = SpiderSenseGuard(config)
        context = GuardContext()

        action = CustomAction(
            custom_type="user_input",
            custom_data={"embedding": [1.0, 0.0, 0.0]},
        )

        result = guard.check(action, context)
        assert result.allowed is False
        assert result.guard == "spider_sense"
        assert result.severity == Severity.ERROR
        assert result.details is not None
        assert result.details["verdict"] == ScreeningVerdict.DENY

    def test_embedding_allow(self) -> None:
        config = SpiderSenseConfig(
            patterns=_test_patterns_as_dicts(),
            similarity_threshold=0.85,
            ambiguity_band=0.10,
        )
        guard = SpiderSenseGuard(config)
        context = GuardContext()

        action = CustomAction(
            custom_type="user_input",
            custom_data={"embedding": [0.577, 0.577, 0.577]},
        )

        result = guard.check(action, context)
        assert result.allowed is True

    def test_embedding_ambiguous(self) -> None:
        config = SpiderSenseConfig(
            patterns=_test_patterns_as_dicts(),
            similarity_threshold=0.50,
            ambiguity_band=0.10,
        )
        guard = SpiderSenseGuard(config)
        context = GuardContext()

        action = CustomAction(
            custom_type="user_input",
            custom_data={"embedding": [0.577, 0.577, 0.577]},
        )

        result = guard.check(action, context)
        assert result.allowed is True  # warn = allowed but logged
        assert result.severity == Severity.WARNING
        assert result.details is not None
        assert result.details["verdict"] == ScreeningVerdict.AMBIGUOUS

    def test_no_embedding_allows(self) -> None:
        config = SpiderSenseConfig(patterns=_test_patterns_as_dicts())
        guard = SpiderSenseGuard(config)
        context = GuardContext()

        action = CustomAction(
            custom_type="user_input",
            custom_data={"text": "no embedding here"},
        )

        result = guard.check(action, context)
        assert result.allowed is True

    def test_no_custom_data_allows(self) -> None:
        """Actions without custom_data (e.g. FileAccessAction) are allowed."""
        from clawdstrike.guards.base import FileAccessAction

        config = SpiderSenseConfig(patterns=_test_patterns_as_dicts())
        guard = SpiderSenseGuard(config)
        context = GuardContext()

        action = FileAccessAction(path="/tmp/test.txt")
        result = guard.check(action, context)
        assert result.allowed is True

    def test_disabled_guard_allows(self) -> None:
        config = SpiderSenseConfig(
            enabled=False,
            patterns=_test_patterns_as_dicts(),
        )
        guard = SpiderSenseGuard(config)
        context = GuardContext()

        action = CustomAction(
            custom_type="user_input",
            custom_data={"embedding": [1.0, 0.0, 0.0]},
        )

        result = guard.check(action, context)
        assert result.allowed is True

    def test_no_patterns_allows(self) -> None:
        """Guard without patterns loaded always allows."""
        guard = SpiderSenseGuard(SpiderSenseConfig())
        context = GuardContext()

        action = CustomAction(
            custom_type="user_input",
            custom_data={"embedding": [1.0, 0.0, 0.0]},
        )

        result = guard.check(action, context)
        assert result.allowed is True

    def test_mixed_type_embedding_is_ignored(self) -> None:
        config = SpiderSenseConfig(
            patterns=_test_patterns_as_dicts(),
            similarity_threshold=0.85,
            ambiguity_band=0.10,
        )
        guard = SpiderSenseGuard(config)
        context = GuardContext()

        action = CustomAction(
            custom_type="user_input",
            custom_data={"embedding": [1.0, "bad", 0.0]},
        )

        result = guard.check(action, context)
        assert result.allowed is True

    def test_non_finite_embedding_is_ignored(self) -> None:
        config = SpiderSenseConfig(
            patterns=_test_patterns_as_dicts(),
            similarity_threshold=0.85,
            ambiguity_band=0.10,
        )
        guard = SpiderSenseGuard(config)
        context = GuardContext()

        action = CustomAction(
            custom_type="user_input",
            custom_data={"embedding": [1.0, float("nan"), 0.0]},
        )

        result = guard.check(action, context)
        assert result.allowed is True

    def test_details_contain_top_matches(self) -> None:
        config = SpiderSenseConfig(
            patterns=_test_patterns_as_dicts(),
            similarity_threshold=0.85,
            ambiguity_band=0.10,
        )
        guard = SpiderSenseGuard(config)
        context = GuardContext()

        action = CustomAction(
            custom_type="user_input",
            custom_data={"embedding": [1.0, 0.0, 0.0]},
        )

        result = guard.check(action, context)
        assert result.details is not None
        matches = result.details["top_matches"]
        assert len(matches) > 0
        assert matches[0]["id"] == "p1"
        assert matches[0]["category"] == "prompt_injection"
        assert "score" in matches[0]

    def test_provider_embedding_used_when_embedding_missing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class _FakeResponse:
            def __enter__(self) -> "_FakeResponse":
                return self

            def __exit__(self, exc_type, exc, tb) -> None:  # type: ignore[override]
                return None

            def getcode(self) -> int:
                return 200

            def read(self, _size: int = -1) -> bytes:
                return json.dumps(
                    {"data": [{"embedding": [1.0, 0.0, 0.0]}]}
                ).encode("utf-8")

        def _fake_urlopen(*_args: object, **_kwargs: object) -> _FakeResponse:
            return _FakeResponse()

        monkeypatch.setattr("clawdstrike.guards.spider_sense.urllib_request.urlopen", _fake_urlopen)

        config = SpiderSenseConfig(
            patterns=_test_patterns_as_dicts(),
            embedding_api_url="https://api.openai.com/v1/embeddings",
            embedding_api_key="test-key",
            embedding_model="text-embedding-3-small",
        )
        guard = SpiderSenseGuard(config)
        result = guard.check(
            CustomAction(custom_type="user_input", custom_data={"text": "hello"}),
            GuardContext(),
        )
        assert result.allowed is False
        assert result.details is not None
        assert result.details["embedding_from"] == "provider"

    def test_provider_failure_is_fail_closed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _fake_urlopen(*_args: object, **_kwargs: object) -> object:
            raise urllib_error.URLError("network down")

        monkeypatch.setattr("clawdstrike.guards.spider_sense.urllib_request.urlopen", _fake_urlopen)

        config = SpiderSenseConfig(
            patterns=_test_patterns_as_dicts(),
            embedding_api_url="https://api.openai.com/v1/embeddings",
            embedding_api_key="test-key",
            embedding_model="text-embedding-3-small",
        )
        guard = SpiderSenseGuard(config)
        result = guard.check(
            CustomAction(custom_type="user_input", custom_data={"text": "hello"}),
            GuardContext(),
        )
        assert result.allowed is False
        assert result.severity == Severity.ERROR
        assert result.details is not None
        assert result.details["analysis"] == "provider"

    def test_pattern_db_path_integrity_controls(self, tmp_path) -> None:
        db_path = tmp_path / "patterns.json"
        db_bytes = b'[{\"id\":\"p1\",\"category\":\"test\",\"stage\":\"perception\",\"label\":\"x\",\"embedding\":[1.0,0.0,0.0]}]'
        db_path.write_bytes(db_bytes)

        guard = SpiderSenseGuard(
            SpiderSenseConfig(
                pattern_db_path=str(db_path),
                pattern_db_version="test-v1",
                pattern_db_checksum=_checksum_hex(db_bytes),
            )
        )
        deny_result = guard.check(
            CustomAction(custom_type="user_input", custom_data={"embedding": [1.0, 0.0, 0.0]}),
            GuardContext(),
        )
        assert deny_result.allowed is False

        with pytest.raises(ValueError, match="checksum mismatch"):
            SpiderSenseGuard(
                SpiderSenseConfig(
                    pattern_db_path=str(db_path),
                    pattern_db_version="test-v1",
                    pattern_db_checksum="deadbeef",
                )
            )

    def test_pattern_db_signature_pair_validation(self, tmp_path) -> None:
        db_path = tmp_path / "patterns.json"
        db_bytes = b'[{\"id\":\"p1\",\"category\":\"test\",\"stage\":\"perception\",\"label\":\"x\",\"embedding\":[1.0,0.0,0.0]}]'
        db_path.write_bytes(db_bytes)

        with pytest.raises(ValueError, match="must either both be set"):
            SpiderSenseGuard(
                SpiderSenseConfig(
                    pattern_db_path=str(db_path),
                    pattern_db_version="test-v1",
                    pattern_db_checksum=_checksum_hex(db_bytes),
                    pattern_db_signature="abcd",
                )
            )

    def test_metrics_hook_emits_counts(self) -> None:
        snapshots = []

        def _hook(snapshot) -> None:
            snapshots.append(snapshot)

        guard = SpiderSenseGuard(
            SpiderSenseConfig(
                patterns=_test_patterns_as_dicts(),
                metrics_hook=_hook,
            )
        )
        context = GuardContext()
        guard.check(
            CustomAction(custom_type="user_input", custom_data={"embedding": [1.0, 0.0, 0.0]}),
            context,
        )
        guard.check(
            CustomAction(custom_type="user_input", custom_data={"embedding": [0.577, 0.577, 0.577]}),
            context,
        )
        assert len(snapshots) == 2
        assert snapshots[0].top_score >= 0.0
        assert snapshots[1].total_count == 2
