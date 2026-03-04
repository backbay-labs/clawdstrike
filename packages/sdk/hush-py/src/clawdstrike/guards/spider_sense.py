"""Spider Sense detection guard - embedding-based threat screening.

Pure-Python implementation of the Spider-Sense detector, matching the Rust
``SpiderSenseDetector`` behaviour (cosine similarity search over a pre-computed
pattern database).
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from typing import Any

from clawdstrike.guards.base import (
    Action,
    Guard,
    GuardContext,
    GuardResult,
    Severity,
)

# ── Cosine Similarity ─────────────────────────────────────────────────────


def cosine_similarity(a: list[float], b: list[float]) -> float:
    """Compute cosine similarity between two vectors.

    Uses float (f64-equivalent in CPython) accumulation.  Returns 0.0 for
    zero-norm or mismatched-length vectors.
    """
    if len(a) != len(b):
        return 0.0

    dot = 0.0
    norm_a = 0.0
    norm_b = 0.0

    for x, y in zip(a, b):
        dot += x * y
        norm_a += x * x
        norm_b += y * y

    denom = math.sqrt(norm_a) * math.sqrt(norm_b)
    if denom == 0.0:
        return 0.0

    return dot / denom


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
        self._expected_dim: int | None = entries[0].embedding.__len__() if entries else None

    @classmethod
    def from_json(cls, json_str: str) -> PatternDb:
        """Parse a JSON string containing a pattern array.

        Raises ``ValueError`` if the JSON is invalid, the array is empty, or
        embedding dimensions are inconsistent.
        """
        try:
            raw: list[dict[str, Any]] = json.loads(json_str)
        except json.JSONDecodeError as exc:
            raise ValueError(f"failed to parse pattern DB: {exc}") from exc

        if not isinstance(raw, list) or len(raw) == 0:
            raise ValueError("pattern DB must contain at least one entry")

        entries: list[PatternEntry] = []
        for item in raw:
            entries.append(
                PatternEntry(
                    id=item["id"],
                    category=item["category"],
                    stage=item["stage"],
                    label=item["label"],
                    embedding=[float(v) for v in item["embedding"]],
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

    similarity_threshold: float = 0.85
    ambiguity_band: float = 0.10
    top_k: int = 5


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

    Wraps a :class:`PatternDb` and screening thresholds.  Operates
    synchronously with no I/O -- the caller is responsible for obtaining
    embeddings.
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
        """Screen an embedding vector against the pattern database.

        This is a pure, sync operation with no I/O.
        """
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
class SpiderSenseConfig:
    """Configuration for :class:`SpiderSenseGuard`."""

    enabled: bool = True
    similarity_threshold: float = 0.85
    ambiguity_band: float = 0.10
    top_k: int = 5
    patterns: list[dict[str, Any]] | None = None


class SpiderSenseGuard(Guard):
    """Guard that screens action embeddings against a threat-pattern database.

    Handles *all* action types.  The embedding must be supplied via
    ``action.custom_data["embedding"]`` (for ``CustomAction``) -- if the
    embedding is absent the guard allows the action (it cannot screen without
    one).
    """

    def __init__(self, config: SpiderSenseConfig | None = None) -> None:
        self._config = config or SpiderSenseConfig()
        self._detector: SpiderSenseDetector | None = None

        if self._config.patterns is not None:
            db = PatternDb.from_json(json.dumps(self._config.patterns))
            detector_config = SpiderSenseDetectorConfig(
                similarity_threshold=self._config.similarity_threshold,
                ambiguity_band=self._config.ambiguity_band,
                top_k=self._config.top_k,
            )
            self._detector = SpiderSenseDetector(db, detector_config)

    @property
    def name(self) -> str:
        return "spider_sense"

    def handles(self, action: Action) -> bool:
        if not self._config.enabled:
            return False
        return True

    def check(self, action: Action, context: GuardContext) -> GuardResult:
        if not self._config.enabled:
            return GuardResult.allow(self.name)

        if self._detector is None:
            return GuardResult.allow(self.name)

        # Extract embedding from action
        custom_data: dict[str, Any] | None = getattr(action, "custom_data", None)
        if custom_data is None:
            return GuardResult.allow(self.name)

        embedding = custom_data.get("embedding")
        if embedding is None or not isinstance(embedding, list):
            return GuardResult.allow(self.name)

        result = self._detector.screen(embedding)

        details: dict[str, Any] = {
            "verdict": result.verdict,
            "top_score": result.top_score,
            "threshold": result.threshold,
            "ambiguity_band": result.ambiguity_band,
            "top_matches": [
                {
                    "id": m.entry.id,
                    "category": m.entry.category,
                    "stage": m.entry.stage,
                    "label": m.entry.label,
                    "score": m.score,
                }
                for m in result.top_matches
            ],
        }

        if result.verdict == ScreeningVerdict.DENY:
            return GuardResult.block(
                self.name,
                Severity.ERROR,
                "Spider-Sense threat detected",
            ).with_details(details)

        if result.verdict == ScreeningVerdict.AMBIGUOUS:
            return GuardResult.warn(
                self.name,
                "Spider-Sense ambiguous match detected",
            ).with_details(details)

        return GuardResult.allow(self.name)


__all__ = [
    "cosine_similarity",
    "PatternEntry",
    "PatternMatch",
    "PatternDb",
    "SpiderSenseDetectorConfig",
    "ScreeningVerdict",
    "ScreeningResult",
    "SpiderSenseDetector",
    "SpiderSenseConfig",
    "SpiderSenseGuard",
]
