"""Shared fake backend used by facade/session tests."""

from __future__ import annotations

from typing import Any


class RecordingBackend:
    name = "recording"

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []

    def _allow(self, action: str, *args: Any, ctx: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((action, args, ctx))
        return {
            "overall": {
                "allowed": True,
                "guard": action,
                "severity": "info",
                "message": "ok",
                "details": None,
            },
            "per_guard": [],
        }

    def check_file_access(self, path: str, ctx: dict[str, Any]) -> dict[str, Any]:
        return self._allow("file_access", path, ctx=ctx)

    def check_file_write(self, path: str, content: bytes, ctx: dict[str, Any]) -> dict[str, Any]:
        return self._allow("file_write", path, content, ctx=ctx)

    def check_shell(self, command: str, ctx: dict[str, Any]) -> dict[str, Any]:
        return self._allow("shell", command, ctx=ctx)

    def check_network(self, host: str, port: int, ctx: dict[str, Any]) -> dict[str, Any]:
        return self._allow("egress", host, port, ctx=ctx)

    def check_mcp_tool(
        self,
        tool: str,
        args: dict[str, Any],
        ctx: dict[str, Any],
    ) -> dict[str, Any]:
        return self._allow("mcp_tool", tool, args, ctx=ctx)

    def check_patch(self, path: str, diff: str, ctx: dict[str, Any]) -> dict[str, Any]:
        return self._allow("patch", path, diff, ctx=ctx)

    def check_untrusted_text(
        self, source: str | None, text: str, ctx: dict[str, Any],
    ) -> dict[str, Any]:
        return self._allow("untrusted_text", source, text, ctx=ctx)

    def check_custom(
        self, custom_type: str, custom_data: dict[str, Any], ctx: dict[str, Any],
    ) -> dict[str, Any]:
        return self._allow(custom_type, custom_data, ctx=ctx)

    def policy_yaml(self) -> str:
        return ""
