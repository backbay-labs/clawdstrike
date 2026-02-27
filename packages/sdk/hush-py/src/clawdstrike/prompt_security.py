"""Prompt-security utilities (native-backed).

This module requires the optional native extension `hush_native` and fails closed when it is
missing. Install/build `packages/sdk/hush-py/hush-native` to enable.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from clawdstrike.native import (
    NATIVE_AVAILABLE,
    detect_jailbreak_native,
    extract_watermark_native,
    sanitize_output_native,
    watermark_prompt_native,
    watermark_public_key_native,
)


def _require_native() -> None:
    missing: list[str] = []
    if not NATIVE_AVAILABLE:
        missing.append("hush_native (module)")
    if detect_jailbreak_native is None:
        missing.append("detect_jailbreak_native")
    if sanitize_output_native is None:
        missing.append("sanitize_output_native")
    if watermark_public_key_native is None:
        missing.append("watermark_public_key_native")
    if watermark_prompt_native is None:
        missing.append("watermark_prompt_native")
    if extract_watermark_native is None:
        missing.append("extract_watermark_native")

    if missing:
        raise ImportError(
            "clawdstrike.prompt_security requires the optional native extension (hush-native). "
            f"Missing: {', '.join(missing)}. "
            "Build/install it from `packages/sdk/hush-py/hush-native`."
        )


class JailbreakDetector:
    """Detect jailbreak attempts in user input (native-backed)."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        _require_native()
        self._config_json = json.dumps(config) if config is not None else None

    def detect(self, text: str, *, session_id: str | None = None) -> dict[str, Any]:
        assert detect_jailbreak_native is not None
        return detect_jailbreak_native(text, session_id, self._config_json)


class OutputSanitizer:
    """Sanitize model output for secret/PII leakage (native-backed)."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        _require_native()
        self._config_json = json.dumps(config) if config is not None else None

    def sanitize(self, text: str) -> dict[str, Any]:
        assert sanitize_output_native is not None
        return sanitize_output_native(text, self._config_json)

    def create_stream(self) -> SanitizationStream:
        return SanitizationStream(self)


@dataclass
class SanitizationStream:
    """Chunked streaming helper (best-effort).

    This is not a true incremental sanitizer yet; it re-sanitizes the buffered output and returns a
    safe delta when possible.
    """

    sanitizer: OutputSanitizer
    _raw: str = ""
    _emitted: str = ""

    def write(self, chunk: str) -> str:
        self._raw += chunk
        r = self.sanitizer.sanitize(self._raw)
        sanitized = str(r.get("sanitized", ""))

        if sanitized.startswith(self._emitted):
            delta = sanitized[len(self._emitted) :]
        else:
            # If redaction reshapes previously-emitted bytes, fall back to emitting the full
            # sanitized buffer (callers may choose to re-render).
            delta = sanitized

        self._emitted = sanitized
        return delta

    def flush(self) -> str:
        return self.write("")


class PromptWatermarker:
    """Embed a signed watermark in prompts (native-backed)."""

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        *,
        application_id: str = "unknown",
        session_id: str = "unknown",
    ) -> None:
        _require_native()
        self._config_json = json.dumps(config or {})
        self._application_id = application_id
        self._session_id = session_id

    def public_key_hex(self) -> str:
        assert watermark_public_key_native is not None
        return watermark_public_key_native(self._config_json)

    def watermark(self, prompt: str, *, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        if payload is not None:
            raise NotImplementedError("Custom payload override is not supported yet")
        assert watermark_prompt_native is not None
        return watermark_prompt_native(
            prompt,
            self._config_json,
            self._application_id,
            self._session_id,
        )


class WatermarkExtractor:
    """Extract and verify watermarks (native-backed)."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        _require_native()
        self._config_json = json.dumps(config or {})

    def extract(self, text: str) -> dict[str, Any]:
        assert extract_watermark_native is not None
        return extract_watermark_native(text, self._config_json)

