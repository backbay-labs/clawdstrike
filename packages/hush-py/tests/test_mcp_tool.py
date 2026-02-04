"""Tests for McpToolGuard."""

import pytest
from clawdstrike.guards.mcp_tool import McpToolGuard, McpToolConfig
from clawdstrike.guards.base import GuardAction, GuardContext, Severity


class TestMcpToolConfig:
    def test_default_config(self) -> None:
        config = McpToolConfig()
        assert config.allow == []
        assert config.block == []
        assert config.default_action == "block"


class TestMcpToolGuard:
    def test_allow_listed_tool(self) -> None:
        config = McpToolConfig(
            allow=["read_file", "search", "list_*"],
            default_action="block",
        )
        guard = McpToolGuard(config)
        context = GuardContext()

        result = guard.check(
            GuardAction.mcp_tool("read_file", {"path": "/test"}),
            context,
        )
        assert result.allowed is True

    def test_allow_wildcard_pattern(self) -> None:
        config = McpToolConfig(
            allow=["list_*"],
            default_action="block",
        )
        guard = McpToolGuard(config)
        context = GuardContext()

        result = guard.check(
            GuardAction.mcp_tool("list_directory", {}),
            context,
        )
        assert result.allowed is True

        result = guard.check(
            GuardAction.mcp_tool("list_files", {}),
            context,
        )
        assert result.allowed is True

    def test_block_explicit_tool(self) -> None:
        config = McpToolConfig(
            allow=["*"],
            block=["execute_command"],
            default_action="allow",
        )
        guard = McpToolGuard(config)
        context = GuardContext()

        result = guard.check(
            GuardAction.mcp_tool("execute_command", {"cmd": "rm -rf /"}),
            context,
        )
        assert result.allowed is False
        assert result.severity == Severity.ERROR

    def test_default_block(self) -> None:
        config = McpToolConfig(
            allow=["safe_tool"],
            default_action="block",
        )
        guard = McpToolGuard(config)
        context = GuardContext()

        result = guard.check(
            GuardAction.mcp_tool("unknown_tool", {}),
            context,
        )
        assert result.allowed is False

    def test_default_allow(self) -> None:
        config = McpToolConfig(
            block=["dangerous_tool"],
            default_action="allow",
        )
        guard = McpToolGuard(config)
        context = GuardContext()

        result = guard.check(
            GuardAction.mcp_tool("unknown_tool", {}),
            context,
        )
        assert result.allowed is True

    def test_handles_mcp_tool_actions(self) -> None:
        guard = McpToolGuard()

        assert guard.handles(GuardAction.mcp_tool("tool", {})) is True
        assert guard.handles(GuardAction.file_access("/test")) is False

    def test_guard_name(self) -> None:
        guard = McpToolGuard()
        assert guard.name == "mcp_tool"

    def test_empty_allow_list_blocks_all(self) -> None:
        config = McpToolConfig(
            allow=[],
            default_action="block",
        )
        guard = McpToolGuard(config)
        context = GuardContext()

        result = guard.check(
            GuardAction.mcp_tool("any_tool", {}),
            context,
        )
        assert result.allowed is False
