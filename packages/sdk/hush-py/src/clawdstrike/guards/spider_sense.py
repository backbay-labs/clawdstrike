"""Spider Sense detection guard - embedding-based threat screening.

Pure-Python implementation of the Spider-Sense detector, matching the Rust
``SpiderSenseDetector`` behaviour (cosine similarity search over a pre-computed
pattern database).
"""

from __future__ import annotations

import hashlib
import importlib.resources as importlib_resources
import json
import math
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from clawdstrike.guards.base import (
    Action,
    CustomAction,
    FileAccessAction,
    FileWriteAction,
    Guard,
    GuardContext,
    GuardResult,
    McpToolAction,
    NetworkEgressAction,
    PatchAction,
    Severity,
    ShellCommandAction,
)

DEFAULT_SIMILARITY_THRESHOLD = 0.85
DEFAULT_AMBIGUITY_BAND = 0.10
DEFAULT_TOP_K = 5
DEFAULT_EMBEDDING_TIMEOUT_SECS = 15.0
MAX_EMBEDDING_RESPONSE_BYTES = 2 * 1024 * 1024

DEFAULT_ASYNC_CACHE_TTL_SECS = 3600.0
DEFAULT_ASYNC_CACHE_MAX_SIZE_BYTES = 64 * 1024 * 1024
DEFAULT_RETRY_INITIAL_BACKOFF_SECS = 0.25
DEFAULT_RETRY_MAX_BACKOFF_SECS = 2.0
DEFAULT_RETRY_MULTIPLIER = 2.0
DEFAULT_RETRY_AFTER_CAP_SECS = 10.0
DEFAULT_RATE_LIMIT_RESET_GRACE_SECS = 0.25
DEFAULT_LLM_TIMEOUT_SECS = 1.5
DEFAULT_LLM_OPENAI_MODEL = "gpt-4.1-mini"
DEFAULT_LLM_ANTHROPIC_MODEL = "claude-haiku-4-5-20251001"
DEFAULT_PROMPT_TEMPLATE_ID = "spider_sense.deep_path.json_classifier"
DEFAULT_PROMPT_TEMPLATE_VERSION = "1.0.0"


# -- Cosine Similarity -----------------------------------------------------


def cosine_similarity(a: list[float], b: list[float]) -> float:
    """Compute cosine similarity between two vectors.

    Uses float (f64-equivalent in CPython) accumulation. Returns 0.0 for
    zero-norm or mismatched-length vectors.
    """
    if len(a) != len(b):
        return 0.0

    dot = 0.0
    norm_a = 0.0
    norm_b = 0.0

    for x, y in zip(a, b, strict=False):
        dot += x * y
        norm_a += x * x
        norm_b += y * y

    denom = math.sqrt(norm_a) * math.sqrt(norm_b)
    if denom == 0.0 or not math.isfinite(denom):
        return 0.0

    result = dot / denom
    if not math.isfinite(result):
        return 0.0
    return result


def _coerce_embedding(value: Any) -> list[float] | None:
    """Validate and coerce an embedding-like value into a finite float list."""
    if not isinstance(value, list):
        return None

    out: list[float] = []
    for item in value:
        if isinstance(item, bool) or not isinstance(item, int | float):
            return None
        number = float(item)
        if not math.isfinite(number):
            return None
        out.append(number)
    return out


def _truncate(value: str, max_bytes: int = 512) -> str:
    trimmed = value.strip()
    if len(trimmed) <= max_bytes:
        return trimmed
    return trimmed[:max_bytes]


def _normalize_hex(value: str) -> str:
    return value.strip().lower().removeprefix("0x")


def _derive_key_id(public_key_hex: str) -> str:
    normalized = _normalize_hex(public_key_hex)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


def _parse_rfc3339(value: str, *, field_name: str, key_id: str) -> datetime:
    candidate = value.strip()
    if candidate.endswith("Z"):
        candidate = f"{candidate[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ValueError(f"invalid {field_name} for key_id {key_id!r}: {exc}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _extract_json_object(raw: str) -> str | None:
    start = raw.find("{")
    if start < 0:
        return None
    depth = 0
    for i in range(start, len(raw)):
        char = raw[i]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return raw[start:i + 1]
    return None


def _normalize_provider_url(raw_url: str) -> str:
    trimmed = raw_url.strip()
    try:
        parsed = urllib_parse.urlparse(trimmed)
    except Exception:
        return trimmed.lower()
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path.strip()
    normalized_path = "/" if path == "" else f"/{path.strip('/')}"
    rebuilt = urllib_parse.urlunparse((scheme, netloc, normalized_path, "", "", ""))
    return rebuilt


def _embedding_cache_key(provider_url: str, model: str, text: str) -> str:
    payload = f"v1|{_normalize_provider_url(provider_url)}|{model.strip()}|{text.strip()}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _is_retryable_http_status(status: int) -> bool:
    return status in {408, 429} or 500 <= status <= 599


def _is_retryable_transport_error(exc: Exception) -> bool:
    if isinstance(exc, TimeoutError):
        return True
    if isinstance(exc, urllib_error.URLError):
        return True
    return False


def _parse_retry_after_secs(raw: str, *, now: datetime) -> float | None:
    value = raw.strip()
    if value == "":
        return None
    try:
        seconds = float(value)
    except ValueError:
        seconds = None
    if seconds is not None:
        if seconds <= 0:
            return None
        return seconds

    try:
        parsed = parsedate_to_datetime(value)
    except Exception:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    delta = (parsed.astimezone(timezone.utc) - now).total_seconds()
    if delta <= 0:
        return None
    return delta


def _rate_limit_value_to_delay_secs(raw_value: float, *, now: datetime, grace_secs: float) -> float | None:
    if not math.isfinite(raw_value) or raw_value <= 0:
        return None
    if raw_value >= 1e12:
        target = datetime.fromtimestamp(raw_value / 1000.0, tz=timezone.utc)
        delay = (target - now).total_seconds() + grace_secs
        return delay if delay > 0 else None
    if raw_value >= 1e9:
        target = datetime.fromtimestamp(raw_value, tz=timezone.utc)
        delay = (target - now).total_seconds() + grace_secs
        return delay if delay > 0 else None
    return raw_value + grace_secs


def _parse_rate_limit_reset_secs(raw: str, *, now: datetime, grace_secs: float) -> float | None:
    value = raw.strip()
    if value == "":
        return None
    try:
        parsed = float(value)
        return _rate_limit_value_to_delay_secs(parsed, now=now, grace_secs=grace_secs)
    except ValueError:
        pass

    for parser in (datetime.fromisoformat, parsedate_to_datetime):
        try:
            parsed_dt = parser(value)  # type: ignore[arg-type]
        except Exception:
            continue
        if parsed_dt.tzinfo is None:
            parsed_dt = parsed_dt.replace(tzinfo=timezone.utc)
        delay = (parsed_dt.astimezone(timezone.utc) - now).total_seconds() + grace_secs
        if delay > 0:
            return delay
    return None


def _resolve_provider_retry_delay(
    fallback_secs: float,
    provider_error: "_SpiderSenseProviderError | None",
    retry_config: "_SpiderSenseRetryConfig",
) -> float:
    delay = fallback_secs
    hint = provider_error.retry_after_secs if provider_error is not None else None
    if hint is not None and hint > 0:
        if retry_config.retry_after_cap_secs > 0:
            hint = min(hint, retry_config.retry_after_cap_secs)
        if hint > delay:
            delay = hint
    if delay <= 0:
        return fallback_secs
    return delay


def _headers_retry_delay_secs(
    headers: Any,
    retry_config: "_SpiderSenseRetryConfig",
) -> float | None:
    now = datetime.now(timezone.utc)
    best: float | None = None

    def _consider(value: float | None) -> None:
        nonlocal best
        if value is None:
            return
        if best is None or value > best:
            best = value

    if retry_config.honor_retry_after:
        retry_after = headers.get("Retry-After") if headers is not None else None
        if isinstance(retry_after, str):
            _consider(_parse_retry_after_secs(retry_after, now=now))

    if retry_config.honor_rate_limit_reset:
        for key in ("RateLimit-Reset", "X-RateLimit-Reset", "X-Rate-Limit-Reset", "x-ratelimit-reset-requests"):
            raw = headers.get(key) if headers is not None else None
            if isinstance(raw, str):
                _consider(
                    _parse_rate_limit_reset_secs(
                        raw,
                        now=now,
                        grace_secs=retry_config.rate_limit_reset_grace_secs,
                    )
                )

    if best is not None and retry_config.retry_after_cap_secs > 0:
        best = min(best, retry_config.retry_after_cap_secs)
    return best


def _resolve_path_relative(base_file: str, raw_path: str) -> str:
    trimmed = raw_path.strip()
    if trimmed == "" or trimmed.startswith("builtin:"):
        return trimmed
    candidate = Path(trimmed)
    if candidate.is_absolute():
        return str(candidate)
    return str((Path(base_file).resolve().parent / candidate).resolve())


def _trusted_keys_digest(entries: list[dict[str, Any]]) -> str:
    if len(entries) == 0:
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


def _default_prompt_template(action_text: str) -> str:
    return (
        "You are a security classifier. Classify the AI-agent action below and return JSON only.\n"
        "Allowed verdicts: allow, warn, deny.\n"
        'JSON schema: {"verdict":"allow|warn|deny","reason":"..."}\n\n'
        f"Action:\n{action_text}"
    ).strip()


_DEEP_PATH_PROMPT_TEMPLATES: dict[tuple[str, str], Callable[[str], str]] = {
    (DEFAULT_PROMPT_TEMPLATE_ID, DEFAULT_PROMPT_TEMPLATE_VERSION): _default_prompt_template
}


# -- Pattern Database ------------------------------------------------------


@dataclass
class PatternEntry:
    """A single entry in the pattern database."""

    id: str
    category: str
    stage: str
    label: str
    embedding: list[float]


@dataclass
class PatternMatch:
    """A scored match from the pattern database."""

    entry: PatternEntry
    score: float


class PatternDb:
    """In-memory pattern database for vector similarity search."""

    def __init__(self, entries: list[PatternEntry]) -> None:
        self._entries = entries
        self._expected_dim: int | None = len(entries[0].embedding) if entries else None

    @classmethod
    def from_json(cls, json_str: str) -> PatternDb:
        """Parse a JSON string containing a pattern array.

        Raises ``ValueError`` if the JSON is invalid, the array is empty, or
        embedding dimensions are inconsistent.
        """
        try:
            raw = json.loads(json_str)
        except json.JSONDecodeError as exc:
            raise ValueError(f"failed to parse pattern DB: {exc}") from exc

        if not isinstance(raw, list) or len(raw) == 0:
            raise ValueError("pattern DB must contain at least one entry")

        entries: list[PatternEntry] = []
        for i, item in enumerate(raw):
            if not isinstance(item, dict):
                raise ValueError(f"pattern DB entry {i} must be an object")
            embedding = _coerce_embedding(item.get("embedding"))
            if embedding is None:
                raise ValueError(
                    f"pattern DB entry {i} has invalid embedding values "
                    "(must be finite numbers)"
                )
            entries.append(
                PatternEntry(
                    id=str(item.get("id", "")),
                    category=str(item.get("category", "")),
                    stage=str(item.get("stage", "")),
                    label=str(item.get("label", "")),
                    embedding=embedding,
                )
            )

        dim = len(entries[0].embedding)
        if dim == 0:
            raise ValueError("pattern DB entries must have non-empty embeddings")

        for i, entry in enumerate(entries):
            if len(entry.embedding) != dim:
                raise ValueError(
                    f"pattern DB dimension mismatch at index {i}: "
                    f"expected {dim}, got {len(entry.embedding)}"
                )

        return cls(entries)

    def search(self, query: list[float], top_k: int) -> list[PatternMatch]:
        """Brute-force cosine similarity search.

        Returns the top-k matches sorted by descending similarity score.
        """
        scored = [
            PatternMatch(entry=entry, score=cosine_similarity(query, entry.embedding))
            for entry in self._entries
        ]
        scored.sort(key=lambda m: m.score, reverse=True)
        return scored[:top_k]

    def __len__(self) -> int:
        return len(self._entries)

    @property
    def is_empty(self) -> bool:
        """Whether the database is empty."""
        return len(self._entries) == 0

    @property
    def expected_dim(self) -> int | None:
        """Expected embedding dimension, if known."""
        return self._expected_dim


# -- Screening -------------------------------------------------------------


class ScreeningVerdict:
    """String constants for screening verdicts."""

    DENY: str = "deny"
    AMBIGUOUS: str = "ambiguous"
    ALLOW: str = "allow"


@dataclass
class ScreeningResult:
    """Result of a :meth:`SpiderSenseDetector.screen` call."""

    verdict: str
    top_score: float
    threshold: float
    ambiguity_band: float
    top_matches: list[PatternMatch]


@dataclass
class SpiderSenseDetectorConfig:
    """Configuration for the standalone Spider-Sense detector."""

    similarity_threshold: float = DEFAULT_SIMILARITY_THRESHOLD
    ambiguity_band: float = DEFAULT_AMBIGUITY_BAND
    top_k: int = DEFAULT_TOP_K


def _validate_detector_config(
    config: SpiderSenseDetectorConfig,
) -> tuple[float, float]:
    """Validate configuration and return (upper_bound, lower_bound).

    Raises ``ValueError`` on invalid configuration.
    """
    if not math.isfinite(config.similarity_threshold):
        raise ValueError("similarity_threshold must be a finite number")
    if not (0.0 <= config.similarity_threshold <= 1.0):
        raise ValueError(
            f"similarity_threshold must be in [0.0, 1.0], got {config.similarity_threshold}"
        )

    if not math.isfinite(config.ambiguity_band):
        raise ValueError("ambiguity_band must be a finite number")
    if not (0.0 <= config.ambiguity_band <= 1.0):
        raise ValueError(
            f"ambiguity_band must be in [0.0, 1.0], got {config.ambiguity_band}"
        )

    upper_bound = config.similarity_threshold + config.ambiguity_band
    lower_bound = config.similarity_threshold - config.ambiguity_band

    if not (0.0 <= lower_bound <= 1.0) or not (0.0 <= upper_bound <= 1.0):
        raise ValueError(
            f"threshold/band produce invalid decision range: "
            f"lower={lower_bound:.3f}, upper={upper_bound:.3f}; "
            f"expected both in [0.0, 1.0]"
        )

    if config.top_k < 1:
        raise ValueError("top_k must be at least 1")

    return upper_bound, lower_bound


class SpiderSenseDetector:
    """Standalone Spider-Sense detector for embedding-based screening.

    Wraps a :class:`PatternDb` and screening thresholds. Operates synchronously
    with no I/O -- the caller is responsible for obtaining embeddings.
    """

    def __init__(
        self,
        pattern_db: PatternDb,
        config: SpiderSenseDetectorConfig | None = None,
    ) -> None:
        cfg = config or SpiderSenseDetectorConfig()
        upper_bound, lower_bound = _validate_detector_config(cfg)
        self._pattern_db = pattern_db
        self._upper_bound = upper_bound
        self._lower_bound = lower_bound
        self._top_k = cfg.top_k
        self._threshold = cfg.similarity_threshold
        self._ambiguity_band = cfg.ambiguity_band

    def screen(self, embedding: list[float]) -> ScreeningResult:
        """Screen an embedding vector against the pattern database."""
        matches = self._pattern_db.search(embedding, self._top_k)
        top_score = matches[0].score if matches else 0.0

        if top_score >= self._upper_bound:
            verdict = ScreeningVerdict.DENY
        elif top_score <= self._lower_bound:
            verdict = ScreeningVerdict.ALLOW
        else:
            verdict = ScreeningVerdict.AMBIGUOUS

        return ScreeningResult(
            verdict=verdict,
            top_score=top_score,
            threshold=self._threshold,
            ambiguity_band=self._ambiguity_band,
            top_matches=matches,
        )

    @property
    def expected_dim(self) -> int | None:
        """Expected embedding dimension from the pattern DB."""
        return self._pattern_db.expected_dim

    @property
    def pattern_count(self) -> int:
        """Number of patterns in the database."""
        return len(self._pattern_db)


# -- Guard Integration -----------------------------------------------------


@dataclass
class SpiderSenseMetrics:
    """One point-in-time metric snapshot emitted after each check."""

    verdict: str
    top_score: float
    severity: str
    db_source: str
    db_version: str
    allow_count: int
    ambiguous_count: int
    deny_count: int
    total_count: int
    ambiguity_rate: float
    screened: bool
    skip_reason: str | None = None
    embedding_source: str | None = None
    cache_hit: bool | None = None
    provider_attempts: int | None = None
    retry_count: int | None = None
    circuit_state: str | None = None
    deep_path_used: bool | None = None
    deep_path_verdict: str | None = None
    trust_key_id: str | None = None
    embedding_latency_ms: int | None = None
    deep_path_latency_ms: int | None = None


SpiderSenseMetricsHook = Callable[[SpiderSenseMetrics], None]


@dataclass
class SpiderSenseConfig:
    """Configuration for :class:`SpiderSenseGuard`."""

    enabled: bool = True
    similarity_threshold: float = DEFAULT_SIMILARITY_THRESHOLD
    ambiguity_band: float = DEFAULT_AMBIGUITY_BAND
    top_k: int = DEFAULT_TOP_K
    patterns: list[dict[str, Any]] | None = None

    embedding_api_url: str | None = None
    embedding_api_key: str | None = None
    embedding_model: str | None = None

    pattern_db_path: str | None = None
    pattern_db_version: str | None = None
    pattern_db_checksum: str | None = None
    pattern_db_signature: str | None = None
    pattern_db_signature_key_id: str | None = None
    pattern_db_public_key: str | None = None
    pattern_db_trust_store_path: str | None = None
    pattern_db_trusted_keys: list[dict[str, Any]] | None = None
    pattern_db_manifest_path: str | None = None
    pattern_db_manifest_trust_store_path: str | None = None
    pattern_db_manifest_trusted_keys: list[dict[str, Any]] | None = None

    llm_api_url: str | None = None
    llm_api_key: str | None = None
    llm_model: str | None = None
    llm_prompt_template_id: str | None = None
    llm_prompt_template_version: str | None = None
    llm_timeout_ms: int | None = None
    llm_fail_mode: str | None = None
    async_config: dict[str, Any] | None = None

    embedding_timeout_secs: float = DEFAULT_EMBEDDING_TIMEOUT_SECS
    metrics_hook: SpiderSenseMetricsHook | None = None


@dataclass
class _SpiderSenseRetryConfig:
    enabled: bool = False
    max_retries: int = 0
    initial_backoff_secs: float = DEFAULT_RETRY_INITIAL_BACKOFF_SECS
    max_backoff_secs: float = DEFAULT_RETRY_MAX_BACKOFF_SECS
    multiplier: float = DEFAULT_RETRY_MULTIPLIER
    honor_retry_after: bool = True
    retry_after_cap_secs: float = DEFAULT_RETRY_AFTER_CAP_SECS
    honor_rate_limit_reset: bool = True
    rate_limit_reset_grace_secs: float = DEFAULT_RATE_LIMIT_RESET_GRACE_SECS


@dataclass
class _SpiderSenseCircuitBreakerConfig:
    failure_threshold: int
    reset_timeout_secs: float
    success_threshold: int


@dataclass
class _SpiderSenseAsyncRuntimeConfig:
    timeout_secs: float
    has_timeout: bool
    cache_enabled: bool
    cache_ttl_secs: float
    cache_max_size_bytes: int
    retry: _SpiderSenseRetryConfig
    circuit_breaker: _SpiderSenseCircuitBreakerConfig | None
    on_circuit_open: str


@dataclass
class _SpiderSenseDeepPathConfig:
    enabled: bool
    api_url: str
    api_key: str
    model: str
    provider: str
    timeout_secs: float
    fail_mode: str
    template_id: str
    template_version: str
    template_renderer: Callable[[str], str]


@dataclass
class _SpiderSenseProviderStats:
    attempts: int = 0
    retries: int = 0
    circuit_state: str = "closed"
    latency_ms: int = 0
    circuit_opened: bool = False


@dataclass
class _SpiderSenseDeepPathStats:
    used: bool = True
    attempts: int = 0
    retries: int = 0
    circuit_state: str = "closed"
    latency_ms: int = 0
    verdict: str = ""


@dataclass
class _SpiderSenseMetricRuntime:
    cache_hit: bool | None = None
    provider_attempts: int | None = None
    retry_count: int | None = None
    circuit_state: str | None = None
    deep_path_used: bool | None = None
    deep_path_verdict: str | None = None
    trust_key_id: str | None = None
    embedding_latency_ms: int | None = None
    deep_path_latency_ms: int | None = None


@dataclass
class _SpiderSenseTrustedKey:
    key_id: str
    public_key: str
    status: str
    not_before: datetime | None = None
    not_after: datetime | None = None


@dataclass
class _SpiderSenseLLMVerdict:
    verdict: str
    reason: str


class _SpiderSenseProviderError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        retryable: bool,
        status: int | None = None,
        retry_after_secs: float | None = None,
    ) -> None:
        super().__init__(message)
        self.retryable = retryable
        self.status = status
        self.retry_after_secs = retry_after_secs


class _SpiderSenseCircuitBreaker:
    def __init__(self, config: _SpiderSenseCircuitBreakerConfig) -> None:
        self._config = config
        self._state = "closed"
        self._failures = 0
        self._successes = 0
        self._open_until = 0.0

    def allow(self) -> tuple[bool, str]:
        now = time.monotonic()
        if self._state == "open":
            if now < self._open_until:
                return False, self._state
            self._state = "half_open"
            self._failures = 0
            self._successes = 0
            return True, self._state
        return True, self._state

    def record_success(self) -> None:
        if self._state == "half_open":
            self._successes += 1
            if self._successes >= self._config.success_threshold:
                self._state = "closed"
                self._failures = 0
                self._successes = 0
            return
        self._state = "closed"
        self._failures = 0
        self._successes = 0

    def record_failure(self) -> None:
        now = time.monotonic()
        if self._state == "half_open":
            self._state = "open"
            self._open_until = now + self._config.reset_timeout_secs
            self._failures = 0
            self._successes = 0
            return
        self._failures += 1
        if self._failures >= self._config.failure_threshold:
            self._state = "open"
            self._open_until = now + self._config.reset_timeout_secs
            self._failures = 0
            self._successes = 0

    @property
    def state(self) -> str:
        return self._state


class _SpiderSenseEmbeddingCache:
    def __init__(self, enabled: bool, ttl_secs: float, max_size_bytes: int) -> None:
        self._enabled = enabled
        self._ttl_secs = ttl_secs
        self._max_size_bytes = max_size_bytes
        self._entries: OrderedDict[str, tuple[list[float], float, int]] = OrderedDict()
        self._current_size = 0

    def get(self, key: str) -> list[float] | None:
        if not self._enabled:
            return None
        entry = self._entries.get(key)
        if entry is None:
            return None
        embedding, expires_at, size_bytes = entry
        if expires_at <= time.time():
            self._delete(key)
            return None
        self._entries.move_to_end(key)
        _ = size_bytes
        return list(embedding)

    def set(self, key: str, embedding: list[float]) -> None:
        if not self._enabled or len(embedding) == 0:
            return
        size_bytes = len(key) + len(embedding) * 8 + 64
        if size_bytes > self._max_size_bytes:
            return
        if key in self._entries:
            self._delete(key)

        while self._current_size + size_bytes > self._max_size_bytes and len(self._entries) > 0:
            oldest_key = next(iter(self._entries.keys()))
            self._delete(oldest_key)

        self._entries[key] = (list(embedding), time.time() + self._ttl_secs, size_bytes)
        self._current_size += size_bytes

    def _delete(self, key: str) -> None:
        entry = self._entries.pop(key, None)
        if entry is None:
            return
        self._current_size -= entry[2]
        if self._current_size < 0:
            self._current_size = 0


def _as_map(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return value
    return None


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            return None
        return int(value)
    return None


def _as_float(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        number = float(value)
        if not math.isfinite(number):
            return None
        return number
    return None


def _as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    return None


def _validate_provider_config(config: SpiderSenseConfig) -> tuple[bool, str]:
    url = (config.embedding_api_url or "").strip()
    key = (config.embedding_api_key or "").strip()
    model = (config.embedding_model or "").strip()

    has_url = url != ""
    has_key = key != ""
    has_model = model != ""

    if not has_url and not has_key and not has_model:
        return False, "openai"
    if not has_url or not has_key or not has_model:
        raise ValueError(
            "embedding_api_url, embedding_api_key, and embedding_model "
            "must all be set when any is provided"
        )

    parsed = urllib_parse.urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("embedding_api_url must be absolute and include host")

    host = parsed.netloc.lower()
    if "cohere" in host:
        return True, "cohere"
    if "voyage" in host:
        return True, "voyage"
    return True, "openai"


def _parse_async_runtime_config(config: SpiderSenseConfig) -> _SpiderSenseAsyncRuntimeConfig:
    out = _SpiderSenseAsyncRuntimeConfig(
        timeout_secs=DEFAULT_EMBEDDING_TIMEOUT_SECS,
        has_timeout=False,
        cache_enabled=True,
        cache_ttl_secs=DEFAULT_ASYNC_CACHE_TTL_SECS,
        cache_max_size_bytes=DEFAULT_ASYNC_CACHE_MAX_SIZE_BYTES,
        retry=_SpiderSenseRetryConfig(),
        circuit_breaker=None,
        on_circuit_open="deny",
    )
    async_map = _as_map(config.async_config)
    if async_map is None:
        return out

    timeout_ms = _as_int(async_map.get("timeout_ms"))
    if timeout_ms is not None and timeout_ms > 0:
        out.timeout_secs = float(timeout_ms) / 1000.0
        out.has_timeout = True

    cache_map = _as_map(async_map.get("cache"))
    if cache_map is not None:
        cache_enabled = _as_bool(cache_map.get("enabled"))
        if cache_enabled is not None:
            out.cache_enabled = cache_enabled
        ttl_seconds = _as_int(cache_map.get("ttl_seconds"))
        if ttl_seconds is not None and ttl_seconds > 0:
            out.cache_ttl_secs = float(ttl_seconds)
        max_size_mb = _as_int(cache_map.get("max_size_mb"))
        if max_size_mb is not None and max_size_mb > 0:
            out.cache_max_size_bytes = max_size_mb * 1024 * 1024

    retry_map = _as_map(async_map.get("retry"))
    if retry_map is not None:
        out.retry.enabled = True
        out.retry.max_retries = 2
        retries = _as_int(retry_map.get("max_retries"))
        if retries is not None and retries >= 0:
            out.retry.max_retries = retries
        initial_backoff_ms = _as_int(retry_map.get("initial_backoff_ms"))
        if initial_backoff_ms is not None and initial_backoff_ms > 0:
            out.retry.initial_backoff_secs = float(initial_backoff_ms) / 1000.0
        max_backoff_ms = _as_int(retry_map.get("max_backoff_ms"))
        if max_backoff_ms is not None and max_backoff_ms > 0:
            out.retry.max_backoff_secs = float(max_backoff_ms) / 1000.0
        multiplier = _as_float(retry_map.get("multiplier"))
        if multiplier is not None and multiplier >= 1.0:
            out.retry.multiplier = multiplier
        honor_retry_after = _as_bool(retry_map.get("honor_retry_after"))
        if honor_retry_after is not None:
            out.retry.honor_retry_after = honor_retry_after
        retry_after_cap_ms = _as_int(retry_map.get("retry_after_cap_ms"))
        if retry_after_cap_ms is not None and retry_after_cap_ms > 0:
            out.retry.retry_after_cap_secs = float(retry_after_cap_ms) / 1000.0
        honor_rate_limit_reset = _as_bool(retry_map.get("honor_rate_limit_reset"))
        if honor_rate_limit_reset is not None:
            out.retry.honor_rate_limit_reset = honor_rate_limit_reset
        reset_grace_ms = _as_int(retry_map.get("rate_limit_reset_grace_ms"))
        if reset_grace_ms is not None and reset_grace_ms >= 0:
            out.retry.rate_limit_reset_grace_secs = float(reset_grace_ms) / 1000.0
        if out.retry.max_backoff_secs < out.retry.initial_backoff_secs:
            out.retry.max_backoff_secs = out.retry.initial_backoff_secs
        if out.retry.retry_after_cap_secs <= 0:
            out.retry.retry_after_cap_secs = out.retry.max_backoff_secs

    cb_map = _as_map(async_map.get("circuit_breaker"))
    if cb_map is not None:
        cb = _SpiderSenseCircuitBreakerConfig(
            failure_threshold=5,
            reset_timeout_secs=30.0,
            success_threshold=2,
        )
        failure_threshold = _as_int(cb_map.get("failure_threshold"))
        if failure_threshold is not None and failure_threshold > 0:
            cb.failure_threshold = failure_threshold
        reset_timeout_ms = _as_int(cb_map.get("reset_timeout_ms"))
        if reset_timeout_ms is not None and reset_timeout_ms > 0:
            cb.reset_timeout_secs = float(reset_timeout_ms) / 1000.0
        success_threshold = _as_int(cb_map.get("success_threshold"))
        if success_threshold is not None and success_threshold > 0:
            cb.success_threshold = success_threshold

        mode = str(cb_map.get("on_open", "")).strip().lower()
        if mode in {"", "deny"}:
            out.on_circuit_open = "deny"
        elif mode == "warn":
            out.on_circuit_open = "warn"
        elif mode == "allow":
            out.on_circuit_open = "allow"
        else:
            raise ValueError("async.circuit_breaker.on_open must be one of allow|warn|deny")
        out.circuit_breaker = cb

    return out


def _parse_deep_path_config(
    config: SpiderSenseConfig,
    async_config: _SpiderSenseAsyncRuntimeConfig,
) -> _SpiderSenseDeepPathConfig:
    timeout_secs = DEFAULT_LLM_TIMEOUT_SECS
    if async_config.has_timeout:
        timeout_secs = async_config.timeout_secs
    out = _SpiderSenseDeepPathConfig(
        enabled=False,
        api_url="",
        api_key="",
        model="",
        provider="openai",
        timeout_secs=timeout_secs,
        fail_mode="warn",
        template_id="",
        template_version="",
        template_renderer=_default_prompt_template,
    )

    url = (config.llm_api_url or "").strip()
    key = (config.llm_api_key or "").strip()
    model = (config.llm_model or "").strip()
    template_id = (config.llm_prompt_template_id or "").strip()
    template_version = (config.llm_prompt_template_version or "").strip()
    has_url = url != ""
    has_key = key != ""
    has_model = model != ""
    has_template_id = template_id != ""
    has_template_version = template_version != ""
    if has_template_id != has_template_version:
        raise ValueError(
            "llm_prompt_template_id and llm_prompt_template_version must be set together"
        )
    if not has_url and not has_key and not has_model:
        if has_template_id or has_template_version:
            raise ValueError(
                "llm_prompt_template_id/version require llm_api_url and llm_api_key"
            )
        return out
    if not has_url or not has_key:
        raise ValueError("llm_api_url and llm_api_key must both be set when deep path is configured")
    if not has_template_id or not has_template_version:
        raise ValueError(
            "llm_prompt_template_id and llm_prompt_template_version are required when deep path is configured"
        )

    parsed = urllib_parse.urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("llm_api_url must be absolute and include host")

    renderer = _DEEP_PATH_PROMPT_TEMPLATES.get((template_id, template_version))
    if renderer is None:
        raise ValueError(
            f"unsupported llm prompt template {template_id!r} version {template_version!r}"
        )

    provider = "anthropic" if "anthropic" in parsed.netloc.lower() else "openai"
    out.enabled = True
    out.api_url = url
    out.api_key = key
    out.provider = provider
    out.template_id = template_id
    out.template_version = template_version
    out.template_renderer = renderer
    if has_model:
        out.model = model
    elif provider == "anthropic":
        out.model = DEFAULT_LLM_ANTHROPIC_MODEL
    else:
        out.model = DEFAULT_LLM_OPENAI_MODEL

    if config.llm_timeout_ms is not None and config.llm_timeout_ms > 0:
        out.timeout_secs = float(config.llm_timeout_ms) / 1000.0

    mode = (config.llm_fail_mode or "").strip().lower()
    if mode in {"", "warn"}:
        out.fail_mode = "warn"
    elif mode == "deny":
        out.fail_mode = "deny"
    elif mode == "allow":
        out.fail_mode = "allow"
    else:
        raise ValueError("llm_fail_mode must be one of allow|warn|deny")
    return out


def _builtin_pattern_db_bytes(name: str) -> bytes:
    try:
        base = importlib_resources.files("clawdstrike.guards")
        return (base / "patterns" / name).read_bytes()
    except Exception:
        # Monorepo fallback used by local SDK tests.
        repo_root = Path(__file__).resolve().parents[6]
        fallback = repo_root / "packages" / "sdk" / "hush-go" / "guards" / "patterns" / name
        return fallback.read_bytes()


def _normalize_trusted_key(entry: dict[str, Any]) -> _SpiderSenseTrustedKey:
    public_key_raw = str(entry.get("public_key", "")).strip()
    public_key = _normalize_hex(public_key_raw)
    if public_key == "":
        raise ValueError("trust store entry is missing public_key")
    try:
        key_bytes = bytes.fromhex(public_key)
        VerifyKey(key_bytes)
    except Exception as exc:
        raise ValueError("invalid trusted public_key") from exc

    derived_key_id = _derive_key_id(public_key)
    key_id = _normalize_hex(str(entry.get("key_id", derived_key_id)))
    if key_id != derived_key_id:
        raise ValueError(
            f"trusted key_id {key_id!r} does not match derived key_id {derived_key_id!r}"
        )

    status_raw = str(entry.get("status", "")).strip().lower()
    if status_raw in {"", "active"}:
        status = "active"
    elif status_raw == "deprecated":
        status = "deprecated"
    elif status_raw == "revoked":
        status = "revoked"
    else:
        raise ValueError(f"unsupported trusted key status {entry.get('status')!r}")

    not_before = None
    not_after = None
    if str(entry.get("not_before", "")).strip() != "":
        not_before = _parse_rfc3339(str(entry["not_before"]), field_name="not_before", key_id=key_id)
    if str(entry.get("not_after", "")).strip() != "":
        not_after = _parse_rfc3339(str(entry["not_after"]), field_name="not_after", key_id=key_id)
    if not_before is not None and not_after is not None and not_after < not_before:
        raise ValueError(f"invalid trusted key window for key_id {key_id!r}")

    return _SpiderSenseTrustedKey(
        key_id=key_id,
        public_key=public_key,
        status=status,
        not_before=not_before,
        not_after=not_after,
    )


def _parse_trust_store_file(path: str) -> list[dict[str, Any]]:
    try:
        parsed = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"read trust store {path!r}: {exc}") from exc
    if isinstance(parsed, list):
        out: list[dict[str, Any]] = []
        for entry in parsed:
            if isinstance(entry, dict):
                out.append(entry)
        return out
    if isinstance(parsed, dict) and isinstance(parsed.get("keys"), list):
        out = []
        for entry in parsed["keys"]:
            if isinstance(entry, dict):
                out.append(entry)
        return out
    raise ValueError("trust store must be a JSON array or object with keys[]")


def _load_trust_store(
    path: str,
    inline: list[dict[str, Any]],
) -> dict[str, _SpiderSenseTrustedKey]:
    store: dict[str, _SpiderSenseTrustedKey] = {}
    entries: list[dict[str, Any]] = []
    if path != "":
        entries.extend(_parse_trust_store_file(path))
    entries.extend(inline)
    for entry in entries:
        normalized = _normalize_trusted_key(entry)
        store[normalized.key_id] = normalized
    if len(store) == 0:
        raise ValueError("trust store is empty")
    return store


def _select_trusted_key(
    store: dict[str, _SpiderSenseTrustedKey],
    key_id: str,
) -> _SpiderSenseTrustedKey:
    normalized_id = _normalize_hex(key_id)
    selected = store.get(normalized_id)
    if selected is None:
        raise ValueError(f"pattern DB signature key_id {normalized_id!r} not found in trust store")
    if selected.status == "revoked":
        raise ValueError(f"pattern DB signature key_id {normalized_id!r} is revoked")
    now = datetime.now(timezone.utc)
    if selected.not_before is not None and now < selected.not_before:
        raise ValueError(f"pattern DB signature key_id {normalized_id!r} is not yet valid")
    if selected.not_after is not None and now > selected.not_after:
        raise ValueError(f"pattern DB signature key_id {normalized_id!r} is expired")
    return selected


def _verify_pattern_db_integrity(
    data: bytes,
    *,
    version: str,
    expected_checksum: str,
    signature: str,
    public_key: str,
    signature_key_id: str,
    trust_store_path: str,
    trusted_keys: list[dict[str, Any]],
) -> str:
    actual_checksum = hashlib.sha256(data).hexdigest().lower()
    normalized_expected = _normalize_hex(expected_checksum)
    if actual_checksum != normalized_expected:
        raise ValueError(
            f"pattern DB checksum mismatch: expected {normalized_expected}, "
            f"got {actual_checksum}"
        )

    normalized_signature = _normalize_hex(signature)
    normalized_public_key = _normalize_hex(public_key)
    normalized_signature_key_id = _normalize_hex(signature_key_id)
    use_trust_store = (
        normalized_signature_key_id != "" or trust_store_path.strip() != "" or len(trusted_keys) > 0
    )
    use_legacy_pair = normalized_signature != "" and normalized_public_key != ""

    if use_trust_store and normalized_public_key != "":
        raise ValueError("pattern_db_public_key cannot be combined with trust-store based verification")
    if use_trust_store:
        if normalized_signature == "":
            raise ValueError("pattern_db_signature is required when trust-store fields are set")
        if normalized_signature_key_id == "":
            raise ValueError("pattern_db_signature_key_id is required when trust-store fields are set")
    elif bool(normalized_signature) != bool(normalized_public_key):
        raise ValueError(
            "pattern_db_signature and pattern_db_public_key must either both "
            "be set or both be omitted"
        )

    message = f"spider_sense_db:v1:{version}:{normalized_expected}".encode()

    if use_legacy_pair:
        try:
            verify_key = VerifyKey(bytes.fromhex(normalized_public_key))
            signature_bytes = bytes.fromhex(normalized_signature)
            verify_key.verify(message, signature_bytes)
        except BadSignatureError as exc:
            raise ValueError("pattern DB signature verification failed") from exc
        except Exception as exc:
            raise ValueError(f"invalid pattern DB signature material: {exc}") from exc
        return ""

    if use_trust_store:
        store = _load_trust_store(trust_store_path.strip(), trusted_keys)
        selected = _select_trusted_key(store, normalized_signature_key_id)
        try:
            verify_key = VerifyKey(bytes.fromhex(selected.public_key))
            signature_bytes = bytes.fromhex(normalized_signature)
            verify_key.verify(message, signature_bytes)
        except BadSignatureError as exc:
            raise ValueError(
                f"pattern DB signature verification failed for key_id {selected.key_id!r}"
            ) from exc
        except Exception as exc:
            raise ValueError(f"invalid pattern DB signature material: {exc}") from exc
        return selected.key_id

    return ""


def _load_pattern_db_from_path(
    config: SpiderSenseConfig,
) -> tuple[PatternDb, str, str, str]:
    manifest_path = (config.pattern_db_manifest_path or "").strip()
    if manifest_path != "":
        return _load_pattern_db_from_manifest(config, manifest_path)

    path = (config.pattern_db_path or "").strip()
    if not path:
        raise ValueError("pattern_db_path cannot be empty")

    version = (config.pattern_db_version or "").strip()
    checksum = (config.pattern_db_checksum or "").strip()
    signature = (config.pattern_db_signature or "").strip()
    signature_key_id = (config.pattern_db_signature_key_id or "").strip()
    public_key = (config.pattern_db_public_key or "").strip()
    trust_store_path = (config.pattern_db_trust_store_path or "").strip()
    trusted_keys = config.pattern_db_trusted_keys or []

    if not version or not checksum:
        raise ValueError(
            "pattern_db_version and pattern_db_checksum are required when "
            "pattern_db_path is set"
        )

    if path == "builtin:s2bench-v1":
        source = "builtin:s2bench-v1"
        data = _builtin_pattern_db_bytes("s2bench-v1.json")
    else:
        source = path
        data = Path(path).read_bytes()

    trust_key_id = _verify_pattern_db_integrity(
        data,
        version=version,
        expected_checksum=checksum,
        signature=signature,
        public_key=public_key,
        signature_key_id=signature_key_id,
        trust_store_path=trust_store_path,
        trusted_keys=trusted_keys,
    )
    db = PatternDb.from_json(data.decode("utf-8"))
    return db, source, version, trust_key_id


def _verify_pattern_manifest_signature(
    manifest: dict[str, Any],
    *,
    trust_store_path: str,
    trusted_keys: list[dict[str, Any]],
) -> None:
    manifest_signature = _normalize_hex(str(manifest.get("manifest_signature", "")))
    manifest_signature_key_id = _normalize_hex(str(manifest.get("manifest_signature_key_id", "")))
    if manifest_signature == "":
        raise ValueError("pattern DB manifest missing manifest_signature")
    if manifest_signature_key_id == "":
        raise ValueError("pattern DB manifest missing manifest_signature_key_id")

    not_before_raw = str(manifest.get("not_before", "")).strip()
    if not_before_raw != "":
        not_before = _parse_rfc3339(not_before_raw, field_name="not_before", key_id="manifest")
        if datetime.now(timezone.utc) < not_before:
            raise ValueError("pattern DB manifest is not yet valid")
    not_after_raw = str(manifest.get("not_after", "")).strip()
    if not_after_raw != "":
        not_after = _parse_rfc3339(not_after_raw, field_name="not_after", key_id="manifest")
        if datetime.now(timezone.utc) > not_after:
            raise ValueError("pattern DB manifest is expired")

    roots = _load_trust_store(trust_store_path, trusted_keys)
    selected_root = _select_trusted_key(roots, manifest_signature_key_id)
    try:
        verify_key = VerifyKey(bytes.fromhex(selected_root.public_key))
        signature_bytes = bytes.fromhex(manifest_signature)
        verify_key.verify(_manifest_signing_message(manifest), signature_bytes)
    except BadSignatureError as exc:
        raise ValueError(
            f"pattern DB manifest signature verification failed for key_id {selected_root.key_id!r}"
        ) from exc
    except Exception as exc:
        raise ValueError(f"invalid pattern DB manifest signature material: {exc}") from exc


def _load_pattern_db_from_manifest(
    config: SpiderSenseConfig,
    manifest_path: str,
) -> tuple[PatternDb, str, str, str]:
    try:
        manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"read pattern DB manifest {manifest_path!r}: {exc}") from exc
    if not isinstance(manifest, dict):
        raise ValueError("pattern DB manifest must be a JSON object")

    manifest_trust_store_path_raw = (config.pattern_db_manifest_trust_store_path or "").strip()
    manifest_trust_store_path = (
        _resolve_path_relative(manifest_path, manifest_trust_store_path_raw)
        if manifest_trust_store_path_raw != ""
        else ""
    )
    manifest_trusted_keys = config.pattern_db_manifest_trusted_keys or []
    if manifest_trust_store_path == "" and len(manifest_trusted_keys) == 0:
        raise ValueError(
            "pattern_db_manifest_path requires pattern_db_manifest_trust_store_path "
            "or pattern_db_manifest_trusted_keys"
        )
    _verify_pattern_manifest_signature(
        manifest,
        trust_store_path=manifest_trust_store_path,
        trusted_keys=manifest_trusted_keys,
    )

    path_raw = str(manifest.get("pattern_db_path", "")).strip()
    if path_raw == "":
        raise ValueError("pattern DB manifest missing pattern_db_path")
    path = _resolve_path_relative(manifest_path, path_raw)
    version = str(manifest.get("pattern_db_version", "")).strip()
    checksum = str(manifest.get("pattern_db_checksum", "")).strip()
    signature = str(manifest.get("pattern_db_signature", "")).strip()
    signature_key_id = str(manifest.get("pattern_db_signature_key_id", "")).strip()
    public_key = str(manifest.get("pattern_db_public_key", "")).strip()
    trust_store_path_raw = str(manifest.get("pattern_db_trust_store_path", "")).strip()
    trust_store_path = (
        _resolve_path_relative(manifest_path, trust_store_path_raw)
        if trust_store_path_raw != ""
        else ""
    )
    trusted_keys = (
        [entry for entry in manifest.get("pattern_db_trusted_keys", []) if isinstance(entry, dict)]
        if isinstance(manifest.get("pattern_db_trusted_keys"), list)
        else []
    )

    if not version or not checksum:
        raise ValueError(
            "pattern DB manifest must include pattern_db_version and pattern_db_checksum"
        )

    if path == "builtin:s2bench-v1":
        source = "builtin:s2bench-v1"
        data = _builtin_pattern_db_bytes("s2bench-v1.json")
    else:
        source = path
        data = Path(path).read_bytes()

    trust_key_id = _verify_pattern_db_integrity(
        data,
        version=version,
        expected_checksum=checksum,
        signature=signature,
        public_key=public_key,
        signature_key_id=signature_key_id,
        trust_store_path=trust_store_path,
        trusted_keys=trusted_keys,
    )
    db = PatternDb.from_json(data.decode("utf-8"))
    return db, source, version, trust_key_id


class SpiderSenseGuard(Guard):
    """Guard that screens action embeddings against a threat-pattern database."""

    def __init__(self, config: SpiderSenseConfig | None = None) -> None:
        self._config = config or SpiderSenseConfig()
        self._detector: SpiderSenseDetector | None = None
        self._db_source = ""
        self._db_version = ""
        self._trust_key_id = ""

        self._embedding_enabled, self._embedding_provider = _validate_provider_config(
            self._config
        )
        self._async_config = _parse_async_runtime_config(self._config)
        self._deep_path_config = _parse_deep_path_config(self._config, self._async_config)

        embedding_timeout = self._config.embedding_timeout_secs
        if not math.isfinite(embedding_timeout) or embedding_timeout <= 0:
            if self._async_config.has_timeout:
                embedding_timeout = self._async_config.timeout_secs
            else:
                embedding_timeout = DEFAULT_EMBEDDING_TIMEOUT_SECS
        self._embedding_timeout_secs = embedding_timeout

        self._embedding_cache = _SpiderSenseEmbeddingCache(
            self._async_config.cache_enabled,
            self._async_config.cache_ttl_secs,
            self._async_config.cache_max_size_bytes,
        )
        self._embedding_breaker = (
            _SpiderSenseCircuitBreaker(self._async_config.circuit_breaker)
            if self._async_config.circuit_breaker is not None
            else None
        )
        self._llm_breaker = (
            _SpiderSenseCircuitBreaker(self._async_config.circuit_breaker)
            if self._async_config.circuit_breaker is not None
            else None
        )

        if self._config.patterns is not None:
            if len(self._config.patterns) == 0:
                raise ValueError("patterns must contain at least one entry when set")
            db = PatternDb.from_json(json.dumps(self._config.patterns))
            self._db_source = "inline"
            self._db_version = "inline"
        elif (self._config.pattern_db_manifest_path or "").strip() or (self._config.pattern_db_path or "").strip():
            db, source, version, trust_key_id = _load_pattern_db_from_path(self._config)
            self._db_source = source
            self._db_version = version
            self._trust_key_id = trust_key_id
        else:
            db = None

        if db is not None:
            detector_config = SpiderSenseDetectorConfig(
                similarity_threshold=self._config.similarity_threshold,
                ambiguity_band=self._config.ambiguity_band,
                top_k=self._config.top_k,
            )
            self._detector = SpiderSenseDetector(db, detector_config)

        self._allow_count = 0
        self._ambiguous_count = 0
        self._deny_count = 0
        self._total_count = 0

    @property
    def name(self) -> str:
        return "spider_sense"

    def handles(self, action: Action) -> bool:
        _ = action
        return self._config.enabled

    def check(self, action: Action, context: GuardContext) -> GuardResult:
        runtime = _SpiderSenseMetricRuntime(trust_key_id=self._trust_key_id)

        if not self._config.enabled:
            result = GuardResult.allow(self.name)
            self._emit_metrics(
                verdict=ScreeningVerdict.ALLOW,
                top_score=0.0,
                severity=result.severity,
                screened=False,
                skip_reason="disabled",
                embedding_source=None,
                runtime=runtime,
            )
            return result

        if self._detector is None:
            result = GuardResult.allow(self.name)
            self._emit_metrics(
                verdict=ScreeningVerdict.ALLOW,
                top_score=0.0,
                severity=result.severity,
                screened=False,
                skip_reason="pattern_db_missing",
                embedding_source=None,
                runtime=runtime,
            )
            return result

        embedding = self._extract_embedding(action)
        embedding_source = "action"

        if embedding is None:
            if not self._embedding_enabled:
                result = GuardResult.allow(self.name)
                self._emit_metrics(
                    verdict=ScreeningVerdict.ALLOW,
                    top_score=0.0,
                    severity=result.severity,
                    screened=False,
                    skip_reason="embedding_missing",
                    embedding_source=None,
                    runtime=runtime,
                )
                return result

            text = self._action_to_text(action)
            cache_key = _embedding_cache_key(
                self._config.embedding_api_url or "",
                self._config.embedding_model or "",
                text,
            )
            cached = self._embedding_cache.get(cache_key)
            if cached is not None:
                embedding = cached
                embedding_source = "provider"
                runtime.cache_hit = True
                runtime.circuit_state = (
                    self._embedding_breaker.state if self._embedding_breaker is not None else "closed"
                )
            else:
                fetched, stats, error = self._fetch_embedding_with_retry(text, context)
                runtime.provider_attempts = stats.attempts
                runtime.retry_count = stats.retries
                runtime.circuit_state = stats.circuit_state
                runtime.embedding_latency_ms = stats.latency_ms
                if error is not None or fetched is None:
                    err = error or RuntimeError("embedding request failed")
                    if stats.circuit_opened:
                        result = self._circuit_open_provider_result(err)
                        self._emit_metrics(
                            verdict=self._verdict_from_result(result),
                            top_score=0.0,
                            severity=result.severity,
                            screened=False,
                            skip_reason="provider_circuit_open",
                            embedding_source="provider",
                            runtime=runtime,
                        )
                        return result

                    details = {
                        "analysis": "provider",
                        "error": str(err),
                        "db_source": self._db_source,
                        "db_version": self._db_version,
                        "embedding_from": "provider",
                    }
                    result = GuardResult.block(
                        self.name,
                        Severity.ERROR,
                        "Spider-Sense embedding provider error (fail-closed)",
                    ).with_details(details)
                    self._emit_metrics(
                        verdict=ScreeningVerdict.DENY,
                        top_score=0.0,
                        severity=result.severity,
                        screened=True,
                        skip_reason="provider_error",
                        embedding_source="provider",
                        runtime=runtime,
                    )
                    return result

                embedding = fetched
                embedding_source = "provider"
                self._embedding_cache.set(cache_key, embedding)

        expected_dim = self._detector.expected_dim
        if expected_dim is not None and len(embedding) != expected_dim:
            details = {
                "analysis": "validation",
                "error": (
                    f"embedding dimension mismatch: got {len(embedding)}, expected {expected_dim}"
                ),
                "db_source": self._db_source,
                "db_version": self._db_version,
                "embedding_from": embedding_source,
            }
            result = GuardResult.block(
                self.name,
                Severity.ERROR,
                "Spider-Sense embedding dimension mismatch (fail-closed)",
            ).with_details(details)
            self._emit_metrics(
                verdict=ScreeningVerdict.DENY,
                top_score=0.0,
                severity=result.severity,
                screened=True,
                skip_reason="dimension_mismatch",
                embedding_source=embedding_source,
                runtime=runtime,
            )
            return result

        screening = self._detector.screen(embedding)
        details = self._result_details(screening, embedding_source)

        if screening.verdict == ScreeningVerdict.AMBIGUOUS and self._deep_path_config.enabled:
            deep_result, deep_stats, deep_error = self._run_deep_path(
                self._action_to_text(action),
                screening,
                embedding_source,
                context,
            )
            runtime.deep_path_used = deep_stats.used
            runtime.deep_path_verdict = deep_stats.verdict
            runtime.deep_path_latency_ms = deep_stats.latency_ms
            runtime.retry_count = (runtime.retry_count or 0) + deep_stats.retries
            if runtime.circuit_state is None:
                runtime.circuit_state = deep_stats.circuit_state

            if deep_error is not None or deep_result is None:
                fallback = self._deep_path_failure_result(
                    deep_error or RuntimeError("deep path failed"),
                    screening,
                    embedding_source,
                    details,
                )
                self._emit_metrics(
                    verdict=self._verdict_from_result(fallback),
                    top_score=screening.top_score,
                    severity=fallback.severity,
                    screened=True,
                    skip_reason="deep_path_error",
                    embedding_source=embedding_source,
                    runtime=runtime,
                )
                return fallback

            self._emit_metrics(
                verdict=self._verdict_from_result(deep_result),
                top_score=screening.top_score,
                severity=deep_result.severity,
                screened=True,
                skip_reason=None,
                embedding_source=embedding_source,
                runtime=runtime,
            )
            return deep_result

        if screening.verdict == ScreeningVerdict.DENY:
            top_label = screening.top_matches[0].entry.label if screening.top_matches else ""
            result = GuardResult.block(
                self.name,
                Severity.ERROR,
                (
                    "Spider-Sense threat detected "
                    f'(score={screening.top_score:.3f}, label="{top_label}")'
                ),
            ).with_details(details)
            self._emit_metrics(
                verdict=screening.verdict,
                top_score=screening.top_score,
                severity=result.severity,
                screened=True,
                skip_reason=None,
                embedding_source=embedding_source,
                runtime=runtime,
            )
            return result

        if screening.verdict == ScreeningVerdict.AMBIGUOUS:
            result = GuardResult.warn(
                self.name,
                f"Spider-Sense ambiguous match detected (score={screening.top_score:.3f})",
            ).with_details(details)
            self._emit_metrics(
                verdict=screening.verdict,
                top_score=screening.top_score,
                severity=result.severity,
                screened=True,
                skip_reason=None,
                embedding_source=embedding_source,
                runtime=runtime,
            )
            return result

        result = GuardResult.allow(self.name).with_details(details)
        self._emit_metrics(
            verdict=screening.verdict,
            top_score=screening.top_score,
            severity=result.severity,
            screened=True,
            skip_reason=None,
            embedding_source=embedding_source,
            runtime=runtime,
        )
        return result

    def _result_details(
        self,
        result: ScreeningResult,
        embedding_source: str,
    ) -> dict[str, Any]:
        matches = [
            {
                "id": m.entry.id,
                "category": m.entry.category,
                "stage": m.entry.stage,
                "label": m.entry.label,
                "score": m.score,
            }
            for m in result.top_matches
        ]

        details: dict[str, Any] = {
            "analysis": "fast_path",
            "verdict": result.verdict,
            "top_score": result.top_score,
            "threshold": result.threshold,
            "ambiguity_band": result.ambiguity_band,
            "top_matches": matches,
            "db_source": self._db_source,
            "db_version": self._db_version,
            "embedding_from": embedding_source,
        }
        if matches:
            details["top_match"] = matches[0]
        return details

    def _emit_metrics(
        self,
        *,
        verdict: str,
        top_score: float,
        severity: Severity,
        screened: bool,
        skip_reason: str | None,
        embedding_source: str | None,
        runtime: _SpiderSenseMetricRuntime,
    ) -> None:
        hook = self._config.metrics_hook
        if hook is None:
            return

        self._total_count += 1
        if verdict == ScreeningVerdict.DENY:
            self._deny_count += 1
        elif verdict == ScreeningVerdict.AMBIGUOUS:
            self._ambiguous_count += 1
        else:
            self._allow_count += 1

        ambiguity_rate = (
            float(self._ambiguous_count) / float(self._total_count)
            if self._total_count > 0
            else 0.0
        )
        snapshot = SpiderSenseMetrics(
            verdict=verdict,
            top_score=top_score,
            severity=severity.value,
            db_source=self._db_source,
            db_version=self._db_version,
            allow_count=self._allow_count,
            ambiguous_count=self._ambiguous_count,
            deny_count=self._deny_count,
            total_count=self._total_count,
            ambiguity_rate=ambiguity_rate,
            screened=screened,
            skip_reason=skip_reason,
            embedding_source=embedding_source,
            cache_hit=runtime.cache_hit,
            provider_attempts=runtime.provider_attempts,
            retry_count=runtime.retry_count,
            circuit_state=runtime.circuit_state,
            deep_path_used=runtime.deep_path_used,
            deep_path_verdict=runtime.deep_path_verdict,
            trust_key_id=runtime.trust_key_id,
            embedding_latency_ms=runtime.embedding_latency_ms,
            deep_path_latency_ms=runtime.deep_path_latency_ms,
        )
        try:
            hook(snapshot)
        except Exception:
            # Metrics hooks should never affect policy decisions.
            return

    def _extract_embedding(self, action: Action) -> list[float] | None:
        if not isinstance(action, CustomAction):
            return None
        return _coerce_embedding(action.custom_data.get("embedding"))

    def _action_to_text(self, action: Action) -> str:
        if isinstance(action, CustomAction):
            custom_type = action.custom_type.strip() or "custom"
            body = json.dumps(action.custom_data, ensure_ascii=False, sort_keys=True)
            return f"[custom:{custom_type}] {body}"
        if isinstance(action, McpToolAction):
            body = json.dumps(action.args, ensure_ascii=False, sort_keys=True)
            return f"[mcp_tool:{action.tool}] {body}"
        if isinstance(action, ShellCommandAction):
            return f"[shell_command] {action.command.strip()}"
        if isinstance(action, FileWriteAction):
            preview = _truncate(action.content.decode("utf-8", errors="replace"))
            return f"[file_write:{action.path.strip()}] {preview}"
        if isinstance(action, NetworkEgressAction):
            return f"[network_egress:{action.host.strip()}:{action.port}]"
        if isinstance(action, FileAccessAction):
            return f"[file_access] {action.path.strip()}"
        if isinstance(action, PatchAction):
            preview = _truncate(action.diff)
            return f"[patch:{action.path.strip()}] {preview}"
        return f"[action:{getattr(action, 'action_type', 'unknown')}]"

    def _fetch_embedding_with_retry(
        self,
        text: str,
        _context: GuardContext,
    ) -> tuple[list[float] | None, _SpiderSenseProviderStats, Exception | None]:
        stats = _SpiderSenseProviderStats(
            circuit_state=self._embedding_breaker.state if self._embedding_breaker is not None else "closed"
        )
        if self._embedding_breaker is not None:
            allowed, state = self._embedding_breaker.allow()
            stats.circuit_state = state
            if not allowed:
                stats.circuit_opened = True
                return None, stats, RuntimeError("embedding provider circuit breaker open")

        max_retries = self._async_config.retry.max_retries if self._async_config.retry.enabled else 0
        backoff_secs = self._async_config.retry.initial_backoff_secs
        start = time.time()
        last_error: Exception | None = None

        for attempt in range(max_retries + 1):
            stats.attempts = attempt + 1
            try:
                embedding = self._fetch_embedding_once(text)
                if self._embedding_breaker is not None:
                    self._embedding_breaker.record_success()
                    stats.circuit_state = self._embedding_breaker.state
                stats.retries = attempt
                stats.latency_ms = int((time.time() - start) * 1000)
                return embedding, stats, None
            except Exception as exc:
                last_error = exc
                retryable = isinstance(exc, _SpiderSenseProviderError) and exc.retryable
                if attempt >= max_retries or not retryable:
                    if self._embedding_breaker is not None:
                        self._embedding_breaker.record_failure()
                        stats.circuit_state = self._embedding_breaker.state
                    stats.retries = attempt
                    stats.latency_ms = int((time.time() - start) * 1000)
                    return None, stats, exc
                provider_error = exc if isinstance(exc, _SpiderSenseProviderError) else None
                wait_secs = _resolve_provider_retry_delay(
                    backoff_secs,
                    provider_error,
                    self._async_config.retry,
                )
                time.sleep(wait_secs)
                backoff_secs = min(
                    wait_secs * self._async_config.retry.multiplier,
                    self._async_config.retry.max_backoff_secs,
                )

        if self._embedding_breaker is not None:
            self._embedding_breaker.record_failure()
            stats.circuit_state = self._embedding_breaker.state
        stats.retries = max_retries
        stats.latency_ms = int((time.time() - start) * 1000)
        return None, stats, last_error or RuntimeError("embedding request failed")

    def _fetch_embedding_once(self, text: str) -> list[float]:
        if not self._embedding_enabled:
            raise ValueError("embedding provider is not configured")

        url = (self._config.embedding_api_url or "").strip()
        key = (self._config.embedding_api_key or "").strip()
        model = (self._config.embedding_model or "").strip()
        timeout = self._embedding_timeout_secs

        if self._embedding_provider == "cohere":
            payload: dict[str, Any] = {
                "texts": [text],
                "model": model,
                "embedding_types": ["float"],
                "input_type": "classification",
            }
        elif self._embedding_provider == "voyage":
            payload = {
                "input": [text],
                "model": model,
            }
        else:
            payload = {
                "input": text,
                "model": model,
            }

        body = json.dumps(payload).encode("utf-8")
        req = urllib_request.Request(
            url=url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": f"Bearer {key}",
            },
        )
        if self._embedding_provider == "cohere":
            req.add_header("X-Client-Name", "clawdstrike-py")

        try:
            with urllib_request.urlopen(req, timeout=timeout) as resp:
                status = resp.getcode()
                response_body = resp.read(MAX_EMBEDDING_RESPONSE_BYTES)
        except urllib_error.HTTPError as exc:
            error_body = exc.read(MAX_EMBEDDING_RESPONSE_BYTES).decode("utf-8", errors="replace")
            retry_after_secs = _headers_retry_delay_secs(exc.headers, self._async_config.retry)
            raise _SpiderSenseProviderError(
                f"embedding API returned HTTP {exc.code}: {error_body or 'empty response body'}",
                retryable=_is_retryable_http_status(exc.code),
                status=exc.code,
                retry_after_secs=retry_after_secs,
            ) from exc
        except Exception as exc:
            raise _SpiderSenseProviderError(
                f"embedding request failed: {exc}",
                retryable=_is_retryable_transport_error(exc),
            ) from exc

        if status < 200 or status >= 300:
            msg = response_body.decode("utf-8", errors="replace")
            retry_after_secs = _headers_retry_delay_secs(resp.headers, self._async_config.retry)
            raise _SpiderSenseProviderError(
                f"embedding API returned HTTP {status}: {msg or 'empty response body'}",
                retryable=_is_retryable_http_status(status),
                status=status,
                retry_after_secs=retry_after_secs,
            )

        try:
            parsed = json.loads(response_body.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise _SpiderSenseProviderError(
                f"parse embedding response: {exc}",
                retryable=False,
            ) from exc

        embedding: list[float] | None = None
        if self._embedding_provider == "cohere":
            embeddings = parsed.get("embeddings") if isinstance(parsed, dict) else None
            if isinstance(embeddings, list) and embeddings:
                embedding = _coerce_embedding(embeddings[0])
            elif isinstance(embeddings, dict):
                float_embeddings = embeddings.get("float")
                if isinstance(float_embeddings, list) and float_embeddings:
                    embedding = _coerce_embedding(float_embeddings[0])
        else:
            data = parsed.get("data") if isinstance(parsed, dict) else None
            if isinstance(data, list) and data:
                item0 = data[0]
                if isinstance(item0, dict):
                    embedding = _coerce_embedding(item0.get("embedding"))

        if not embedding:
            raise _SpiderSenseProviderError(
                "embedding API returned an empty or invalid embedding",
                retryable=False,
            )
        return embedding

    def _deep_path_prompt(self, text: str) -> str:
        return self._deep_path_config.template_renderer(text)

    def _deep_path_request_material(self, prompt: str) -> tuple[dict[str, Any], dict[str, str]]:
        if self._deep_path_config.provider == "anthropic":
            payload = {
                "model": self._deep_path_config.model,
                "max_tokens": 256,
                "messages": [{"role": "user", "content": prompt}],
            }
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "x-api-key": self._deep_path_config.api_key,
                "anthropic-version": "2023-06-01",
            }
            return payload, headers

        payload = {
            "model": self._deep_path_config.model,
            "max_tokens": 256,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": "Return JSON only."},
                {"role": "user", "content": prompt},
            ],
        }
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {self._deep_path_config.api_key}",
        }
        return payload, headers

    def _deep_path_content(self, payload: dict[str, Any]) -> str:
        if self._deep_path_config.provider == "anthropic":
            content = payload.get("content")
            if not isinstance(content, list) or len(content) == 0:
                raise _SpiderSenseProviderError(
                    "parse deep-path response: missing content[0].text",
                    retryable=False,
                )
            first = content[0]
            if not isinstance(first, dict) or not isinstance(first.get("text"), str):
                raise _SpiderSenseProviderError(
                    "parse deep-path response: missing content[0].text",
                    retryable=False,
                )
            return first["text"]

        choices = payload.get("choices")
        if not isinstance(choices, list) or len(choices) == 0:
            raise _SpiderSenseProviderError(
                "parse deep-path response: missing choices[0].message.content",
                retryable=False,
            )
        first = choices[0]
        if not isinstance(first, dict):
            raise _SpiderSenseProviderError(
                "parse deep-path response: missing choices[0].message.content",
                retryable=False,
            )
        message = first.get("message")
        if not isinstance(message, dict) or not isinstance(message.get("content"), str):
            raise _SpiderSenseProviderError(
                "parse deep-path response: missing choices[0].message.content",
                retryable=False,
            )
        return message["content"]

    def _parse_deep_path_verdict(self, content: str) -> _SpiderSenseLLMVerdict:
        raw = content.strip()
        if raw == "":
            raise _SpiderSenseProviderError("parse deep-path verdict: empty response", retryable=False)
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            extracted = _extract_json_object(raw)
            if extracted is None:
                raise _SpiderSenseProviderError("parse deep-path verdict: invalid JSON", retryable=False)
            parsed = json.loads(extracted)

        if not isinstance(parsed, dict):
            raise _SpiderSenseProviderError("parse deep-path verdict: invalid JSON", retryable=False)
        verdict_raw = str(parsed.get("verdict", "")).strip().lower()
        reason = str(parsed.get("reason", "")).strip()
        if verdict_raw not in {"allow", "warn", "deny"}:
            if verdict_raw == "":
                verdict_raw = "warn"
            else:
                reason = (reason + f"; unknown verdict {verdict_raw}").strip()
                verdict_raw = "warn"
        return _SpiderSenseLLMVerdict(verdict=verdict_raw, reason=reason)

    def _deep_path_verdict_once(self, text: str, _context: GuardContext) -> _SpiderSenseLLMVerdict:
        prompt = self._deep_path_prompt(text)
        payload, headers = self._deep_path_request_material(prompt)
        body = json.dumps(payload).encode("utf-8")
        req = urllib_request.Request(
            url=self._deep_path_config.api_url,
            data=body,
            method="POST",
            headers=headers,
        )
        timeout = self._deep_path_config.timeout_secs

        try:
            with urllib_request.urlopen(req, timeout=timeout) as resp:
                status = resp.getcode()
                response_body = resp.read(MAX_EMBEDDING_RESPONSE_BYTES)
        except urllib_error.HTTPError as exc:
            error_body = exc.read(MAX_EMBEDDING_RESPONSE_BYTES).decode("utf-8", errors="replace")
            retry_after_secs = _headers_retry_delay_secs(exc.headers, self._async_config.retry)
            raise _SpiderSenseProviderError(
                f"deep-path API returned HTTP {exc.code}: {error_body or 'empty response body'}",
                retryable=_is_retryable_http_status(exc.code),
                status=exc.code,
                retry_after_secs=retry_after_secs,
            ) from exc
        except Exception as exc:
            raise _SpiderSenseProviderError(
                f"deep-path request failed: {exc}",
                retryable=_is_retryable_transport_error(exc),
            ) from exc

        if status < 200 or status >= 300:
            msg = response_body.decode("utf-8", errors="replace")
            retry_after_secs = _headers_retry_delay_secs(resp.headers, self._async_config.retry)
            raise _SpiderSenseProviderError(
                f"deep-path API returned HTTP {status}: {msg or 'empty response body'}",
                retryable=_is_retryable_http_status(status),
                status=status,
                retry_after_secs=retry_after_secs,
            )

        try:
            parsed = json.loads(response_body.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise _SpiderSenseProviderError(
                f"parse deep-path response: {exc}",
                retryable=False,
            ) from exc
        if not isinstance(parsed, dict):
            raise _SpiderSenseProviderError("parse deep-path response: invalid payload", retryable=False)

        content = self._deep_path_content(parsed)
        return self._parse_deep_path_verdict(content)

    def _deep_path_decision(
        self,
        verdict: _SpiderSenseLLMVerdict,
        fast: ScreeningResult,
        embedding_source: str,
    ) -> GuardResult:
        matches = [
            {
                "id": m.entry.id,
                "category": m.entry.category,
                "stage": m.entry.stage,
                "label": m.entry.label,
                "score": m.score,
            }
            for m in fast.top_matches
        ]
        reason = verdict.reason or "no reason provided"
        details: dict[str, Any] = {
            "analysis": "deep_path",
            "verdict": verdict.verdict,
            "reason": reason,
            "template_id": self._deep_path_config.template_id,
            "template_version": self._deep_path_config.template_version,
            "top_score": fast.top_score,
            "threshold": fast.threshold,
            "ambiguity_band": fast.ambiguity_band,
            "top_matches": matches,
            "db_source": self._db_source,
            "db_version": self._db_version,
            "embedding_from": embedding_source,
        }
        if len(matches) > 0:
            details["top_match"] = matches[0]

        if verdict.verdict == "deny":
            return GuardResult.block(
                self.name,
                Severity.ERROR,
                f"Spider-Sense deep analysis: threat confirmed - {reason}",
            ).with_details(details)
        if verdict.verdict == "allow":
            return GuardResult.allow(self.name).with_details(details)
        details["verdict"] = "warn"
        return GuardResult.warn(
            self.name,
            f"Spider-Sense deep analysis: suspicious/ambiguous - {reason}",
        ).with_details(details)

    def _deep_path_failure_result(
        self,
        error: Exception,
        fast: ScreeningResult,
        embedding_source: str,
        base_details: dict[str, Any],
    ) -> GuardResult:
        details: dict[str, Any] = {
            "analysis": "deep_path_error",
            "error": str(error),
            "fail_mode": self._deep_path_config.fail_mode,
            "template_id": self._deep_path_config.template_id,
            "template_version": self._deep_path_config.template_version,
            "top_score": fast.top_score,
            "threshold": fast.threshold,
            "ambiguity_band": fast.ambiguity_band,
            "top_matches": base_details.get("top_matches"),
            "db_source": self._db_source,
            "db_version": self._db_version,
            "embedding_from": embedding_source,
        }
        if "top_match" in base_details:
            details["top_match"] = base_details["top_match"]

        if self._deep_path_config.fail_mode == "allow":
            return GuardResult.allow(self.name).with_details(details)
        if self._deep_path_config.fail_mode == "deny":
            return GuardResult.block(
                self.name,
                Severity.ERROR,
                "Spider-Sense deep-path error (fail-closed)",
            ).with_details(details)
        return GuardResult.warn(
            self.name,
            "Spider-Sense deep-path error; treating as ambiguous",
        ).with_details(details)

    def _run_deep_path(
        self,
        text: str,
        fast: ScreeningResult,
        embedding_source: str,
        context: GuardContext,
    ) -> tuple[GuardResult | None, _SpiderSenseDeepPathStats, Exception | None]:
        stats = _SpiderSenseDeepPathStats(
            circuit_state=self._llm_breaker.state if self._llm_breaker is not None else "closed"
        )
        if self._llm_breaker is not None:
            allowed, state = self._llm_breaker.allow()
            stats.circuit_state = state
            if not allowed:
                return None, stats, RuntimeError("deep path circuit breaker open")

        max_retries = self._async_config.retry.max_retries if self._async_config.retry.enabled else 0
        backoff_secs = self._async_config.retry.initial_backoff_secs
        start = time.time()
        last_error: Exception | None = None

        for attempt in range(max_retries + 1):
            stats.attempts = attempt + 1
            try:
                verdict = self._deep_path_verdict_once(text, context)
                if self._llm_breaker is not None:
                    self._llm_breaker.record_success()
                    stats.circuit_state = self._llm_breaker.state
                stats.retries = attempt
                stats.latency_ms = int((time.time() - start) * 1000)
                stats.verdict = verdict.verdict
                return self._deep_path_decision(verdict, fast, embedding_source), stats, None
            except Exception as exc:
                last_error = exc
                retryable = isinstance(exc, _SpiderSenseProviderError) and exc.retryable
                if attempt >= max_retries or not retryable:
                    if self._llm_breaker is not None:
                        self._llm_breaker.record_failure()
                        stats.circuit_state = self._llm_breaker.state
                    stats.retries = attempt
                    stats.latency_ms = int((time.time() - start) * 1000)
                    return None, stats, exc
                provider_error = exc if isinstance(exc, _SpiderSenseProviderError) else None
                wait_secs = _resolve_provider_retry_delay(
                    backoff_secs,
                    provider_error,
                    self._async_config.retry,
                )
                time.sleep(wait_secs)
                backoff_secs = min(
                    wait_secs * self._async_config.retry.multiplier,
                    self._async_config.retry.max_backoff_secs,
                )

        if self._llm_breaker is not None:
            self._llm_breaker.record_failure()
            stats.circuit_state = self._llm_breaker.state
        stats.retries = max_retries
        stats.latency_ms = int((time.time() - start) * 1000)
        return None, stats, last_error or RuntimeError("deep path request failed")

    def _circuit_open_provider_result(self, error: Exception) -> GuardResult:
        details = {
            "analysis": "provider",
            "error": str(error),
            "on_open": self._async_config.on_circuit_open,
            "db_source": self._db_source,
            "db_version": self._db_version,
            "embedding_from": "provider",
        }
        if self._async_config.on_circuit_open == "allow":
            return GuardResult.allow(self.name).with_details(details)
        if self._async_config.on_circuit_open == "warn":
            return GuardResult.warn(self.name, "Spider-Sense provider circuit breaker open").with_details(details)
        return GuardResult.block(
            self.name,
            Severity.ERROR,
            "Spider-Sense embedding provider circuit breaker open",
        ).with_details(details)

    def _verdict_from_result(self, result: GuardResult) -> str:
        if not result.allowed:
            return ScreeningVerdict.DENY
        if result.severity == Severity.WARNING:
            return ScreeningVerdict.AMBIGUOUS
        return ScreeningVerdict.ALLOW


__all__ = [
    "cosine_similarity",
    "PatternEntry",
    "PatternMatch",
    "PatternDb",
    "SpiderSenseDetectorConfig",
    "ScreeningVerdict",
    "ScreeningResult",
    "SpiderSenseDetector",
    "SpiderSenseMetrics",
    "SpiderSenseMetricsHook",
    "SpiderSenseConfig",
    "SpiderSenseGuard",
]
