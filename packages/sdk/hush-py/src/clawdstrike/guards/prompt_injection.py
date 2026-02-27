"""Prompt injection guard - detects common prompt-injection patterns in untrusted text.

This is a pure-Python implementation of the heuristic + statistical detection layers,
matching the Rust PromptInjectionGuard's behavior.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import IntEnum
from typing import Any

from clawdstrike.guards.base import (
    Action,
    Guard,
    GuardContext,
    GuardResult,
    Severity,
)


class PromptInjectionLevel(IntEnum):
    """Detection confidence level."""

    SAFE = 0
    SUSPICIOUS = 1
    HIGH = 2
    CRITICAL = 3


# Heuristic signal patterns (case-insensitive)
_SIGNALS: list[tuple[str, str, int]] = [  # noqa: E501
    # (signal_id, pattern, score_contribution)
    ("ignore_previous_instructions", r"(?i)ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules)", 40),  # noqa: E501
    ("reveal_system_prompt", r"(?i)(reveal|show|display|output|print|repeat)\s+(the\s+)?(system\s+)?(prompt|instructions|rules)", 35),  # noqa: E501
    ("new_instructions", r"(?i)(new|updated|override|replacement)\s+(system\s+)?(instructions|prompt|rules)", 30),  # noqa: E501
    ("you_are_now", r"(?i)you\s+are\s+now\s+(a|an|the|my)\s+(unrestricted|unfiltered|uncensored|jailbroken?|evil|new|different)\s", 25),  # noqa: E501
    ("do_anything_now", r"(?i)(DAN|do\s+anything\s+now)", 30),
    ("jailbreak_prefix", r"(?i)(ignore\s+safety|bypass\s+restrictions|disable\s+filter)", 35),
    ("role_play_override", r"(?i)pretend\s+(you\s+are|to\s+be|you're)\s+", 20),
    ("encoding_evasion", r"(?i)(base64|rot13|hex|unicode)\s*(encode|decode|convert)", 15),
    ("delimiter_injection", r"(?i)(<\|im_start\|>|<\|im_end\|>|\[INST\]|\[/INST\]|<\|system\|>|<\|user\|>|<\|assistant\|>)", 25),  # noqa: E501
    ("exfiltration_request", r"(?i)(send|transmit|exfiltrate|post)\s+(to|data|secrets|keys)\s+(http|url|endpoint|server)", 40),  # noqa: E501
]

_COMPILED_SIGNALS = [(sid, re.compile(pat), score) for sid, pat, score in _SIGNALS]


def _detect(
    text: str, max_scan_bytes: int = 200_000,
) -> tuple[PromptInjectionLevel, int, list[str]]:
    """Run heuristic detection on text prefix.

    Returns (level, score, list_of_signal_ids).
    """
    scanned = text[:max_scan_bytes]
    total_score = 0
    matched_signals: list[str] = []

    for signal_id, compiled, score in _COMPILED_SIGNALS:
        if compiled.search(scanned):
            total_score += score
            matched_signals.append(signal_id)

    if total_score >= 60:
        level = PromptInjectionLevel.CRITICAL
    elif total_score >= 35:
        level = PromptInjectionLevel.HIGH
    elif total_score >= 15:
        level = PromptInjectionLevel.SUSPICIOUS
    else:
        level = PromptInjectionLevel.SAFE

    return level, total_score, matched_signals


@dataclass
class PromptInjectionConfig:
    """Configuration for PromptInjectionGuard."""

    enabled: bool = True
    warn_at_or_above: str = "suspicious"
    block_at_or_above: str = "high"
    max_scan_bytes: int = 200_000


def _level_from_str(s: str) -> PromptInjectionLevel:
    mapping = {
        "safe": PromptInjectionLevel.SAFE,
        "suspicious": PromptInjectionLevel.SUSPICIOUS,
        "high": PromptInjectionLevel.HIGH,
        "critical": PromptInjectionLevel.CRITICAL,
    }
    return mapping.get(s.lower(), PromptInjectionLevel.HIGH)


class PromptInjectionGuard(Guard):
    """Guard that evaluates prompt-injection risk for untrusted text.

    Handles custom actions with type 'untrusted_text' or 'hushclaw.untrusted_text'.
    """

    UNTRUSTED_TEXT_KINDS = {"untrusted_text", "hushclaw.untrusted_text"}

    def __init__(self, config: PromptInjectionConfig | None = None) -> None:
        self._config = config or PromptInjectionConfig()
        self._warn_level = _level_from_str(self._config.warn_at_or_above)
        self._block_level = _level_from_str(self._config.block_at_or_above)

    @property
    def name(self) -> str:
        return "prompt_injection"

    def handles(self, action: Action) -> bool:
        if not self._config.enabled:
            return False
        custom_type: str | None = getattr(action, "custom_type", None)
        return (
            action.action_type == "custom"
            and custom_type is not None
            and custom_type in self.UNTRUSTED_TEXT_KINDS
        )

    def _extract_text(self, action: Action) -> str | None:
        """Extract text from action payload."""
        data: dict | None = getattr(action, "custom_data", None)
        if data is None:
            return None
        text = data.get("text")
        if isinstance(text, str):
            return text
        return None

    def check(self, action: Action, context: GuardContext) -> GuardResult:
        if not self._config.enabled:
            return GuardResult.allow(self.name)

        if not self.handles(action):
            return GuardResult.allow(self.name)

        text = self._extract_text(action)
        if text is None:
            return GuardResult.block(
                self.name,
                Severity.ERROR,
                "Invalid untrusted_text payload: missing text field",
            )

        level, score, signals = _detect(text, self._config.max_scan_bytes)

        details: dict[str, Any] = {
            "level": level.name.lower(),
            "score": score,
            "signals": signals,
        }
        custom_data: dict | None = getattr(action, "custom_data", None)
        source = custom_data.get("source") if custom_data else None
        if source:
            details["source"] = source

        if level >= self._block_level:
            sev = {
                PromptInjectionLevel.CRITICAL: Severity.CRITICAL,
                PromptInjectionLevel.HIGH: Severity.ERROR,
            }.get(level, Severity.ERROR)
            return GuardResult.block(
                self.name,
                sev,
                f"Untrusted text contains prompt-injection signals ({level.name})",
            ).with_details(details)

        if level >= self._warn_level:
            return GuardResult.warn(
                self.name,
                f"Untrusted text contains prompt-injection signals ({level.name})",
            ).with_details(details)

        return GuardResult.allow(self.name)


__all__ = [
    "PromptInjectionGuard",
    "PromptInjectionConfig",
    "PromptInjectionLevel",
]
