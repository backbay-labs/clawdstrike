"""Tests for Spider Sense detection guard."""

import hashlib
import io
import json
from pathlib import Path
from urllib import error as urllib_error

import pytest
from nacl.signing import SigningKey

from clawdstrike.guards.base import CustomAction, GuardContext, Severity
from clawdstrike.guards.spider_sense import (
    PatternDb,
    ScreeningVerdict,
    SpiderSenseConfig,
    SpiderSenseDetector,
    SpiderSenseDetectorConfig,
    SpiderSenseGuard,
    _manifest_signing_message,
    cosine_similarity,
)


# -- Helpers ---------------------------------------------------------------

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


def _manifest_tamper_vectors() -> list[dict[str, str]]:
    repo_root = Path(__file__).resolve().parents[4]
    vectors_path = repo_root / "fixtures" / "spider-sense" / "manifest_tamper_vectors.json"
    vectors = json.loads(vectors_path.read_text(encoding="utf-8"))
    if not isinstance(vectors, list) or not vectors:
        raise AssertionError("manifest tamper vectors fixture must be a non-empty list")
    return vectors


# -- Cosine Similarity -----------------------------------------------------


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


# -- PatternDb -------------------------------------------------------------


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


# -- SpiderSenseDetector ---------------------------------------------------


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


# -- SpiderSenseGuard ------------------------------------------------------


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

    def test_embedding_cache_reduces_provider_calls(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        call_count = 0

        class _FakeResponse:
            def __enter__(self) -> "_FakeResponse":
                return self

            def __exit__(self, exc_type, exc, tb) -> None:  # type: ignore[override]
                return None

            def getcode(self) -> int:
                return 200

            def read(self, _size: int = -1) -> bytes:
                return json.dumps({"data": [{"embedding": [1.0, 0.0, 0.0]}]}).encode("utf-8")

        def _fake_urlopen(*_args: object, **_kwargs: object) -> _FakeResponse:
            nonlocal call_count
            call_count += 1
            return _FakeResponse()

        monkeypatch.setattr("clawdstrike.guards.spider_sense.urllib_request.urlopen", _fake_urlopen)

        guard = SpiderSenseGuard(
            SpiderSenseConfig(
                patterns=_test_patterns_as_dicts(),
                embedding_api_url="https://api.openai.com/v1/embeddings?unused=true",
                embedding_api_key="test-key",
                embedding_model="text-embedding-3-small",
                async_config={"cache": {"enabled": True, "ttl_seconds": 3600}},
            )
        )
        action = CustomAction(custom_type="user_input", custom_data={"text": "   hello world   "})
        first = guard.check(action, GuardContext())
        second = guard.check(action, GuardContext())
        assert first.allowed is False
        assert second.allowed is False
        assert call_count == 1

    def test_provider_retry_backoff(self, monkeypatch: pytest.MonkeyPatch) -> None:
        call_count = 0

        class _FakeResponse:
            def __enter__(self) -> "_FakeResponse":
                return self

            def __exit__(self, exc_type, exc, tb) -> None:  # type: ignore[override]
                return None

            def getcode(self) -> int:
                return 200

            def read(self, _size: int = -1) -> bytes:
                return json.dumps({"data": [{"embedding": [1.0, 0.0, 0.0]}]}).encode("utf-8")

        def _fake_urlopen(*_args: object, **_kwargs: object) -> _FakeResponse:
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise urllib_error.URLError("temporary")
            return _FakeResponse()

        monkeypatch.setattr("clawdstrike.guards.spider_sense.urllib_request.urlopen", _fake_urlopen)

        guard = SpiderSenseGuard(
            SpiderSenseConfig(
                patterns=_test_patterns_as_dicts(),
                embedding_api_url="https://api.openai.com/v1/embeddings",
                embedding_api_key="test-key",
                embedding_model="text-embedding-3-small",
                async_config={
                    "retry": {
                        "max_retries": 2,
                        "initial_backoff_ms": 1,
                        "max_backoff_ms": 2,
                        "multiplier": 1.0,
                    }
                },
            )
        )

        result = guard.check(
            CustomAction(custom_type="user_input", custom_data={"text": "hello"}),
            GuardContext(),
        )
        assert result.allowed is False
        assert result.details is not None
        assert result.details["embedding_from"] == "provider"
        assert call_count == 3

    def test_provider_retry_after_header_with_cap(self, monkeypatch: pytest.MonkeyPatch) -> None:
        call_count = 0
        sleeps: list[float] = []

        class _FakeResponse:
            def __enter__(self) -> "_FakeResponse":
                return self

            def __exit__(self, exc_type, exc, tb) -> None:  # type: ignore[override]
                return None

            def getcode(self) -> int:
                return 200

            @property
            def headers(self) -> dict[str, str]:
                return {}

            def read(self, _size: int = -1) -> bytes:
                return json.dumps({"data": [{"embedding": [1.0, 0.0, 0.0]}]}).encode("utf-8")

        def _fake_urlopen(req, timeout=None):  # type: ignore[no-untyped-def]
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise urllib_error.HTTPError(
                    req.full_url,
                    429,
                    "too many requests",
                    {"Retry-After": "1"},
                    io.BytesIO(b"rate limited"),
                )
            return _FakeResponse()

        monkeypatch.setattr("clawdstrike.guards.spider_sense.urllib_request.urlopen", _fake_urlopen)
        monkeypatch.setattr("clawdstrike.guards.spider_sense.time.sleep", lambda delay: sleeps.append(delay))

        guard = SpiderSenseGuard(
            SpiderSenseConfig(
                patterns=_test_patterns_as_dicts(),
                embedding_api_url="https://api.openai.com/v1/embeddings",
                embedding_api_key="test-key",
                embedding_model="text-embedding-3-small",
                async_config={
                    "retry": {
                        "max_retries": 1,
                        "initial_backoff_ms": 1,
                        "max_backoff_ms": 2,
                        "multiplier": 1.0,
                        "honor_retry_after": True,
                        "retry_after_cap_ms": 5,
                    }
                },
            )
        )
        result = guard.check(
            CustomAction(custom_type="user_input", custom_data={"text": "hello"}),
            GuardContext(),
        )
        assert result.allowed is False
        assert call_count == 2
        assert len(sleeps) == 1
        assert sleeps[0] >= 0.004

    def test_provider_circuit_breaker_warn_mode(self, monkeypatch: pytest.MonkeyPatch) -> None:
        call_count = 0

        def _fake_urlopen(*_args: object, **_kwargs: object) -> object:
            nonlocal call_count
            call_count += 1
            raise urllib_error.URLError("network down")

        monkeypatch.setattr("clawdstrike.guards.spider_sense.urllib_request.urlopen", _fake_urlopen)

        guard = SpiderSenseGuard(
            SpiderSenseConfig(
                patterns=_test_patterns_as_dicts(),
                embedding_api_url="https://api.openai.com/v1/embeddings",
                embedding_api_key="test-key",
                embedding_model="text-embedding-3-small",
                async_config={
                    "retry": {"max_retries": 0},
                    "circuit_breaker": {
                        "failure_threshold": 1,
                        "reset_timeout_ms": 60000,
                        "success_threshold": 1,
                        "on_open": "warn",
                    },
                },
            )
        )

        first = guard.check(
            CustomAction(custom_type="user_input", custom_data={"text": "first"}),
            GuardContext(),
        )
        assert first.allowed is False

        second = guard.check(
            CustomAction(custom_type="user_input", custom_data={"text": "second"}),
            GuardContext(),
        )
        assert second.allowed is True
        assert second.severity == Severity.WARNING
        assert second.details is not None
        assert second.details["on_open"] == "warn"
        assert call_count == 1

    def test_trust_store_signature_key_id_verification(self, tmp_path) -> None:
        db_path = tmp_path / "patterns.json"
        trust_store_path = tmp_path / "trust-store.json"
        db_bytes = b'[{"id":"p1","category":"test","stage":"perception","label":"x","embedding":[1.0,0.0,0.0]}]'
        db_path.write_bytes(db_bytes)
        checksum = _checksum_hex(db_bytes)

        signing_key = SigningKey.generate()
        public_key_hex = signing_key.verify_key.encode().hex()
        key_id = hashlib.sha256(public_key_hex.lower().encode("utf-8")).hexdigest()[:16]
        message = f"spider_sense_db:v1:test-v1:{checksum}".encode()
        signature = signing_key.sign(message).signature.hex()

        trust_store_path.write_text(
            json.dumps({"keys": [{"key_id": key_id, "public_key": public_key_hex, "status": "active"}]}),
            encoding="utf-8",
        )

        guard = SpiderSenseGuard(
            SpiderSenseConfig(
                pattern_db_path=str(db_path),
                pattern_db_version="test-v1",
                pattern_db_checksum=checksum,
                pattern_db_signature=signature,
                pattern_db_signature_key_id=key_id,
                pattern_db_trust_store_path=str(trust_store_path),
            )
        )

        result = guard.check(
            CustomAction(custom_type="user_input", custom_data={"embedding": [1.0, 0.0, 0.0]}),
            GuardContext(),
        )
        assert result.allowed is False

    def test_signed_pattern_manifest_support(self, tmp_path) -> None:
        db_path = tmp_path / "patterns.json"
        trust_store_path = tmp_path / "trust-store.json"
        manifest_path = tmp_path / "manifest.json"

        db_bytes = b'[{"id":"p1","category":"test","stage":"perception","label":"x","embedding":[1.0,0.0,0.0]}]'
        db_path.write_bytes(db_bytes)
        checksum = _checksum_hex(db_bytes)

        db_signing_key = SigningKey.generate()
        db_public_key_hex = db_signing_key.verify_key.encode().hex()
        db_key_id = hashlib.sha256(db_public_key_hex.lower().encode("utf-8")).hexdigest()[:16]
        db_message = f"spider_sense_db:v1:test-v1:{checksum}".encode()
        db_signature = db_signing_key.sign(db_message).signature.hex()

        trust_store_path.write_text(
            json.dumps({"keys": [{"key_id": db_key_id, "public_key": db_public_key_hex, "status": "active"}]}),
            encoding="utf-8",
        )

        root_signing_key = SigningKey.generate()
        root_public_key_hex = root_signing_key.verify_key.encode().hex()
        root_key_id = hashlib.sha256(root_public_key_hex.lower().encode("utf-8")).hexdigest()[:16]

        manifest: dict[str, Any] = {
            "pattern_db_path": db_path.name,
            "pattern_db_version": "test-v1",
            "pattern_db_checksum": checksum,
            "pattern_db_signature": db_signature,
            "pattern_db_signature_key_id": db_key_id,
            "pattern_db_trust_store_path": trust_store_path.name,
            "manifest_signature_key_id": root_key_id,
        }
        manifest_signature = root_signing_key.sign(_manifest_signing_message(manifest)).signature.hex()
        manifest["manifest_signature"] = manifest_signature
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        guard = SpiderSenseGuard(
            SpiderSenseConfig(
                pattern_db_manifest_path=str(manifest_path),
                pattern_db_manifest_trusted_keys=[
                    {"key_id": root_key_id, "public_key": root_public_key_hex, "status": "active"}
                ],
            )
        )
        result = guard.check(
            CustomAction(custom_type="user_input", custom_data={"embedding": [1.0, 0.0, 0.0]}),
            GuardContext(),
        )
        assert result.allowed is False

        def _assert_manifest_tamper_fails(tampered: dict[str, object]) -> None:
            manifest_path.write_text(json.dumps(tampered), encoding="utf-8")
            with pytest.raises(ValueError, match="manifest signature verification failed"):
                SpiderSenseGuard(
                    SpiderSenseConfig(
                        pattern_db_manifest_path=str(manifest_path),
                        pattern_db_manifest_trusted_keys=[
                            {"key_id": root_key_id, "public_key": root_public_key_hex, "status": "active"}
                        ],
                    )
                )

        for vector in _manifest_tamper_vectors():
            field = str(vector.get("field", ""))
            value = str(vector.get("value", ""))
            if field not in {"pattern_db_version", "not_before", "not_after"}:
                raise AssertionError(f"unsupported tamper field in fixture: {field}")
            _assert_manifest_tamper_fails({**manifest, field: value})

    def test_deep_path_deny_on_ambiguous(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class _FakeResponse:
            def __enter__(self) -> "_FakeResponse":
                return self

            def __exit__(self, exc_type, exc, tb) -> None:  # type: ignore[override]
                return None

            def getcode(self) -> int:
                return 200

            def read(self, _size: int = -1) -> bytes:
                return json.dumps(
                    {
                        "choices": [
                            {
                                "message": {
                                    "content": json.dumps(
                                        {"verdict": "deny", "reason": "policy confidence high"}
                                    )
                                }
                            }
                        ]
                    }
                ).encode("utf-8")

        def _fake_urlopen(*_args: object, **_kwargs: object) -> _FakeResponse:
            return _FakeResponse()

        monkeypatch.setattr("clawdstrike.guards.spider_sense.urllib_request.urlopen", _fake_urlopen)

        guard = SpiderSenseGuard(
            SpiderSenseConfig(
                patterns=_test_patterns_as_dicts(),
                similarity_threshold=0.5,
                ambiguity_band=0.1,
                llm_api_url="https://api.openai.com/v1/chat/completions",
                llm_api_key="llm-key",
                llm_model="gpt-4.1-mini",
                llm_prompt_template_id="spider_sense.deep_path.json_classifier",
                llm_prompt_template_version="1.0.0",
            )
        )
        result = guard.check(
            CustomAction(custom_type="user_input", custom_data={"embedding": [0.577, 0.577, 0.577]}),
            GuardContext(),
        )
        assert result.allowed is False
        assert result.details is not None
        assert result.details["analysis"] == "deep_path"
        assert result.details["verdict"] == "deny"

    def test_deep_path_fail_mode_allow(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _fake_urlopen(*_args: object, **_kwargs: object) -> object:
            raise urllib_error.URLError("llm down")

        monkeypatch.setattr("clawdstrike.guards.spider_sense.urllib_request.urlopen", _fake_urlopen)

        guard = SpiderSenseGuard(
            SpiderSenseConfig(
                patterns=_test_patterns_as_dicts(),
                similarity_threshold=0.5,
                ambiguity_band=0.1,
                llm_api_url="https://api.openai.com/v1/chat/completions",
                llm_api_key="llm-key",
                llm_fail_mode="allow",
                llm_prompt_template_id="spider_sense.deep_path.json_classifier",
                llm_prompt_template_version="1.0.0",
            )
        )
        result = guard.check(
            CustomAction(custom_type="user_input", custom_data={"embedding": [0.577, 0.577, 0.577]}),
            GuardContext(),
        )
        assert result.allowed is True
        assert result.details is not None
        assert result.details["analysis"] == "deep_path_error"
        assert result.details["fail_mode"] == "allow"

    def test_deep_path_requires_template_id_and_version(self) -> None:
        with pytest.raises(ValueError, match="llm_prompt_template_id and llm_prompt_template_version"):
            SpiderSenseGuard(
                SpiderSenseConfig(
                    patterns=_test_patterns_as_dicts(),
                    llm_api_url="https://api.openai.com/v1/chat/completions",
                    llm_api_key="llm-key",
                )
            )

    def test_deep_path_rejects_unknown_template(self) -> None:
        with pytest.raises(ValueError, match="unsupported llm prompt template"):
            SpiderSenseGuard(
                SpiderSenseConfig(
                    patterns=_test_patterns_as_dicts(),
                    llm_api_url="https://api.openai.com/v1/chat/completions",
                    llm_api_key="llm-key",
                    llm_prompt_template_id="spider_sense.deep_path.unknown",
                    llm_prompt_template_version="9.9.9",
                )
            )

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
        assert snapshots[0].db_source in {"inline", ""}
