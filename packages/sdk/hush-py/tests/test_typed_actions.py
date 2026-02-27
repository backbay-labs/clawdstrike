"""Tests for typed action variants."""

from clawdstrike.guards.base import (
    FileAccessAction,
    FileWriteAction,
    GuardAction,
    McpToolAction,
    NetworkEgressAction,
    PatchAction,
    CustomAction,
    ShellCommandAction,
)


class TestTypedActions:
    def test_file_access_action(self) -> None:
        a = FileAccessAction(path="/test")
        assert a.path == "/test"
        assert a.action_type == "file_access"

    def test_file_write_action(self) -> None:
        a = FileWriteAction(path="/test", content=b"hello")
        assert a.path == "/test"
        assert a.content == b"hello"
        assert a.action_type == "file_write"

    def test_network_egress_action(self) -> None:
        a = NetworkEgressAction(host="example.com", port=443)
        assert a.host == "example.com"
        assert a.port == 443
        assert a.action_type == "network_egress"

    def test_shell_command_action(self) -> None:
        a = ShellCommandAction(command="ls")
        assert a.command == "ls"
        assert a.action_type == "shell_command"

    def test_mcp_tool_action(self) -> None:
        a = McpToolAction(tool="read_file", args={"path": "/test"})
        assert a.tool == "read_file"
        assert a.action_type == "mcp_tool"

    def test_patch_action(self) -> None:
        a = PatchAction(path="/test", diff="+new line")
        assert a.path == "/test"
        assert a.diff == "+new line"
        assert a.action_type == "patch"

    def test_custom_action(self) -> None:
        a = CustomAction(custom_type="output", custom_data={"text": "hello"})
        assert a.custom_type == "output"
        assert a.action_type == "custom"

    def test_actions_are_frozen(self) -> None:
        import pytest
        a = FileAccessAction(path="/test")
        with pytest.raises(AttributeError):
            a.path = "/other"  # type: ignore[misc]

    def test_guard_action_factory_creates_typed_actions(self) -> None:
        # GuardAction is a backward-compatible factory
        assert isinstance(GuardAction.file_access("/test"), FileAccessAction)
        assert isinstance(GuardAction.network_egress("host", 80), NetworkEgressAction)
        assert isinstance(GuardAction.mcp_tool("t", {}), McpToolAction)
