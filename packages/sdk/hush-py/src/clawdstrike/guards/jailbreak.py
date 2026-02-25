"""Jailbreak detection guard - detects jailbreak attempts in user input.

This is a pure-Python implementation of the heuristic + statistical detection layers,
matching the Rust JailbreakGuard's behavior.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from clawdstrike.guards.base import Guard, GuardAction, GuardContext, GuardResult, Severity


# Heuristic signal patterns (case-insensitive)
_SIGNALS: List[tuple[str, str, int]] = [
    # (signal_id, pattern, score_contribution)
    ("dan_persona", r"(?i)\b(DAN|do\s+anything\s+now)\b", 30),
    ("ignore_safety", r"(?i)ignore\s+(all\s+)?(safety|ethical|moral|content)\s+(policies|guidelines|restrictions|filters|rules)", 35),
    ("roleplay_override", r"(?i)(pretend|act\s+as\s+if|imagine|suppose)\s+(you\s+)?(are|have|don't\s+have|no\s+longer)\s+(restrict|filter|limit|bound|constraint|rule)", 25),
    ("system_override", r"(?i)(override|disable|remove|bypass|turn\s+off)\s+(your|the|all)\s+(restrictions|filters|safety|limits|guidelines|rules)", 35),
    ("evil_persona", r"(?i)(evil|unrestricted|unfiltered|uncensored|jailbroken?)\s+(mode|version|personality|AI|assistant)", 30),
    ("token_smuggling", r"(?i)(token|prompt)\s*(smuggl|inject|manipulat)", 25),
    ("hypothetical_bypass", r"(?i)(hypothetical|theoretical|fictional)\s+(scenario|situation)\s+(where|in\s+which)\s+(you|AI)", 15),
    ("developer_mode", r"(?i)(developer|dev|debug|admin|root|sudo)\s*(mode|access|override|privilege)", 25),
    ("opposite_day", r"(?i)(opposite\s+day|opposite\s+mode|reverse\s+psychology|anti[_\-]?filter)", 20),
    ("prompt_leak", r"(?i)(show|reveal|display|output|print)\s+(me\s+)?(your|the)\s+(system\s+)?(prompt|instructions|rules|guidelines)", 30),
]

_COMPILED_SIGNALS = [(sid, re.compile(pat), score) for sid, pat, score in _SIGNALS]


def _detect(text: str, max_input_bytes: int = 200_000) -> tuple[int, List[str]]:
    """Run heuristic detection on text prefix.

    Returns (risk_score 0-100, list_of_signal_ids).
    """
    scanned = text[:max_input_bytes]
    total_score = 0
    matched_signals: List[str] = []

    for signal_id, compiled, score in _COMPILED_SIGNALS:
        if compiled.search(scanned):
            total_score += score
            matched_signals.append(signal_id)

    # Clamp to 0-100
    risk_score = min(total_score, 100)
    return risk_score, matched_signals


@dataclass
class JailbreakConfig:
    """Configuration for JailbreakGuard."""

    enabled: bool = True
    block_threshold: int = 70
    warn_threshold: int = 30
    max_input_bytes: int = 200_000
    # session_aggregation is accepted in configuration but not yet implemented.
    # Matching Rust's exponential decay model is non-trivial; this field is
    # reserved for future use.
    session_aggregation: bool = True


class JailbreakGuard(Guard):
    """Guard that evaluates jailbreak risk for user input.

    Handles custom actions with type 'user_input' or 'hushclaw.user_input'.
    """

    USER_INPUT_KINDS = {"user_input", "hushclaw.user_input"}

    def __init__(self, config: Optional[JailbreakConfig] = None) -> None:
        self._config = config or JailbreakConfig()

    @property
    def name(self) -> str:
        return "jailbreak_detection"

    def handles(self, action: GuardAction) -> bool:
        if not self._config.enabled:
            return False
        return (
            action.action_type == "custom"
            and action.custom_type is not None
            and action.custom_type in self.USER_INPUT_KINDS
        )

    def _extract_text(self, action: GuardAction) -> Optional[str]:
        """Extract text from action payload."""
        data = action.custom_data
        if data is None:
            return None
        text = data.get("text")
        if isinstance(text, str):
            return text
        return None

    def check(self, action: GuardAction, context: GuardContext) -> GuardResult:
        if not self._config.enabled:
            return GuardResult.allow(self.name)

        if not self.handles(action):
            return GuardResult.allow(self.name)

        text = self._extract_text(action)
        if text is None:
            return GuardResult.block(
                self.name,
                Severity.ERROR,
                "Invalid user_input payload: missing text field",
            )

        risk_score, signals = _detect(text, self._config.max_input_bytes)

        details: Dict[str, Any] = {
            "risk_score": risk_score,
            "signals": signals,
        }

        if risk_score >= self._config.block_threshold:
            sev = Severity.CRITICAL if risk_score >= 90 else Severity.ERROR
            return GuardResult.block(
                self.name,
                sev,
                "Jailbreak attempt detected",
            ).with_details(details)

        if risk_score >= self._config.warn_threshold:
            return GuardResult.warn(
                self.name,
                "Potential jailbreak attempt detected",
            ).with_details(details)

        return GuardResult.allow(self.name)


__all__ = ["JailbreakGuard", "JailbreakConfig"]
