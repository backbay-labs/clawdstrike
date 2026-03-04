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
from collections.abc import Callable
from dataclasses import dataclass
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


# ── Cosine Similarity ─────────────────────────────────────────────────────


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


# ── Pattern Database ──────────────────────────────────────────────────────


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


# ── Screening ─────────────────────────────────────────────────────────────


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


# ── Guard Integration ─────────────────────────────────────────────────────


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
    pattern_db_public_key: str | None = None

    llm_api_url: str | None = None
    llm_api_key: str | None = None
    llm_model: str | None = None
    async_config: dict[str, Any] | None = None

    embedding_timeout_secs: float = DEFAULT_EMBEDDING_TIMEOUT_SECS
    metrics_hook: SpiderSenseMetricsHook | None = None


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


def _builtin_pattern_db_bytes(name: str) -> bytes:
    try:
        base = importlib_resources.files("clawdstrike.guards")
        return (base / "patterns" / name).read_bytes()
    except Exception:
        # Monorepo fallback used by local SDK tests.
        repo_root = Path(__file__).resolve().parents[6]
        fallback = repo_root / "packages" / "sdk" / "hush-go" / "guards" / "patterns" / name
        return fallback.read_bytes()


def _verify_pattern_db_integrity(
    data: bytes,
    version: str,
    expected_checksum: str,
    signature: str,
    public_key: str,
) -> None:
    actual_checksum = hashlib.sha256(data).hexdigest().lower()
    normalized_expected = expected_checksum.lower().removeprefix("0x")
    if actual_checksum != normalized_expected:
        raise ValueError(
            f"pattern DB checksum mismatch: expected {normalized_expected}, "
            f"got {actual_checksum}"
        )

    if signature and public_key:
        verify_key = VerifyKey(bytes.fromhex(public_key.removeprefix("0x")))
        message = f"spider_sense_db:v1:{version}:{normalized_expected}".encode()
        signature_bytes = bytes.fromhex(signature.removeprefix("0x"))
        try:
            verify_key.verify(message, signature_bytes)
        except BadSignatureError as exc:
            raise ValueError("pattern DB signature verification failed") from exc


def _load_pattern_db_from_path(
    config: SpiderSenseConfig,
) -> tuple[PatternDb, str, str]:
    path = (config.pattern_db_path or "").strip()
    if not path:
        raise ValueError("pattern_db_path cannot be empty")

    version = (config.pattern_db_version or "").strip()
    checksum = (config.pattern_db_checksum or "").strip()
    signature = (config.pattern_db_signature or "").strip()
    public_key = (config.pattern_db_public_key or "").strip()

    if not version or not checksum:
        raise ValueError(
            "pattern_db_version and pattern_db_checksum are required when "
            "pattern_db_path is set"
        )
    if bool(signature) != bool(public_key):
        raise ValueError(
            "pattern_db_signature and pattern_db_public_key must either both "
            "be set or both be omitted"
        )

    if path == "builtin:s2bench-v1":
        source = "builtin:s2bench-v1"
        data = _builtin_pattern_db_bytes("s2bench-v1.json")
    else:
        source = path
        data = Path(path).read_bytes()

    _verify_pattern_db_integrity(data, version, checksum, signature, public_key)
    db = PatternDb.from_json(data.decode("utf-8"))
    return db, source, version


class SpiderSenseGuard(Guard):
    """Guard that screens action embeddings against a threat-pattern database."""

    def __init__(self, config: SpiderSenseConfig | None = None) -> None:
        self._config = config or SpiderSenseConfig()
        self._detector: SpiderSenseDetector | None = None
        self._db_source = ""
        self._db_version = ""

        self._embedding_enabled, self._embedding_provider = _validate_provider_config(
            self._config
        )

        if self._config.patterns is not None:
            if len(self._config.patterns) == 0:
                raise ValueError("patterns must contain at least one entry when set")
            db = PatternDb.from_json(json.dumps(self._config.patterns))
            self._db_source = "inline"
            self._db_version = "inline"
        elif (self._config.pattern_db_path or "").strip():
            db, source, version = _load_pattern_db_from_path(self._config)
            self._db_source = source
            self._db_version = version
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
        return self._config.enabled

    def check(self, action: Action, context: GuardContext) -> GuardResult:
        if not self._config.enabled:
            result = GuardResult.allow(self.name)
            self._emit_metrics(
                verdict=ScreeningVerdict.ALLOW,
                top_score=0.0,
                severity=result.severity,
                screened=False,
                skip_reason="disabled",
                embedding_source=None,
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
                )
                return result

            try:
                embedding = self._fetch_embedding(self._action_to_text(action), context)
            except Exception as exc:
                details = {
                    "analysis": "provider",
                    "error": str(exc),
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
                )
                return result
            embedding_source = "provider"

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
            )
            return result

        screening = self._detector.screen(embedding)
        details = self._result_details(screening, embedding_source)

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

    def _fetch_embedding(self, text: str, _context: GuardContext) -> list[float]:
        if not self._embedding_enabled:
            raise ValueError("embedding provider is not configured")

        url = (self._config.embedding_api_url or "").strip()
        key = (self._config.embedding_api_key or "").strip()
        model = (self._config.embedding_model or "").strip()
        timeout = self._config.embedding_timeout_secs
        if not math.isfinite(timeout) or timeout <= 0:
            timeout = DEFAULT_EMBEDDING_TIMEOUT_SECS

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
            raise RuntimeError(
                f"embedding API returned HTTP {exc.code}: {error_body or 'empty response body'}"
            ) from exc
        except urllib_error.URLError as exc:
            raise RuntimeError(f"embedding request failed: {exc.reason}") from exc

        if status < 200 or status >= 300:
            msg = response_body.decode("utf-8", errors="replace")
            raise RuntimeError(
                f"embedding API returned HTTP {status}: {msg or 'empty response body'}"
            )

        try:
            parsed = json.loads(response_body.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"parse embedding response: {exc}") from exc

        embedding: list[float] | None = None
        if self._embedding_provider == "cohere":
            embeddings = parsed.get("embeddings")
            if isinstance(embeddings, list) and embeddings:
                embedding = _coerce_embedding(embeddings[0])
            elif isinstance(embeddings, dict):
                float_embeddings = embeddings.get("float")
                if isinstance(float_embeddings, list) and float_embeddings:
                    embedding = _coerce_embedding(float_embeddings[0])
        else:
            data = parsed.get("data")
            if isinstance(data, list) and data:
                item0 = data[0]
                if isinstance(item0, dict):
                    embedding = _coerce_embedding(item0.get("embedding"))

        if not embedding:
            raise RuntimeError("embedding API returned an empty or invalid embedding")
        return embedding


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
