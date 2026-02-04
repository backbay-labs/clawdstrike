"""Tests for hush.guards base types."""

import pytest
from clawdstrike.guards.base import (
    Guard,
    GuardResult,
    GuardContext,
    GuardAction,
    Severity,
)


class TestSeverity:
    def test_severity_ordering(self) -> None:
        assert Severity.INFO.value == "info"
        assert Severity.WARNING.value == "warning"
        assert Severity.ERROR.value == "error"
        assert Severity.CRITICAL.value == "critical"


class TestGuardResult:
    def test_allow_result(self) -> None:
        result = GuardResult.allow("test_guard")
        assert result.allowed is True
        assert result.guard == "test_guard"
        assert result.severity == Severity.INFO

    def test_block_result(self) -> None:
        result = GuardResult.block("test_guard", Severity.ERROR, "blocked")
        assert result.allowed is False
        assert result.guard == "test_guard"
        assert result.severity == Severity.ERROR
        assert result.message == "blocked"

    def test_warn_result(self) -> None:
        result = GuardResult.warn("test_guard", "warning message")
        assert result.allowed is True
        assert result.severity == Severity.WARNING

    def test_with_details(self) -> None:
        result = GuardResult.block("test_guard", Severity.ERROR, "blocked")
        result = result.with_details({"path": "/secret"})
        assert result.details == {"path": "/secret"}


class TestGuardContext:
    def test_default_context(self) -> None:
        ctx = GuardContext()
        assert ctx.cwd is None
        assert ctx.session_id is None

    def test_context_with_values(self) -> None:
        ctx = GuardContext(
            cwd="/app",
            session_id="sess-123",
            agent_id="agent-456",
        )
        assert ctx.cwd == "/app"
        assert ctx.session_id == "sess-123"
        assert ctx.agent_id == "agent-456"


class TestGuardAction:
    def test_file_access_action(self) -> None:
        action = GuardAction.file_access("/path/to/file")
        assert action.action_type == "file_access"
        assert action.path == "/path/to/file"

    def test_file_write_action(self) -> None:
        action = GuardAction.file_write("/path/to/file", b"content")
        assert action.action_type == "file_write"
        assert action.path == "/path/to/file"
        assert action.content == b"content"

    def test_network_egress_action(self) -> None:
        action = GuardAction.network_egress("api.example.com", 443)
        assert action.action_type == "network_egress"
        assert action.host == "api.example.com"
        assert action.port == 443

    def test_mcp_tool_action(self) -> None:
        action = GuardAction.mcp_tool("read_file", {"path": "/test"})
        assert action.action_type == "mcp_tool"
        assert action.tool == "read_file"
        assert action.args == {"path": "/test"}
