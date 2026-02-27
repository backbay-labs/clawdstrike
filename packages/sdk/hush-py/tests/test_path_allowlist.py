"""Tests for PathAllowlistGuard."""

from clawdstrike.guards.path_allowlist import PathAllowlistGuard, PathAllowlistConfig
from clawdstrike.guards.base import GuardContext, FileAccessAction


class TestPathAllowlistGuard:
    def test_empty_allowlist_allows_all(self) -> None:
        guard = PathAllowlistGuard()
        action = FileAccessAction(path="/any/path")
        result = guard.check(action, GuardContext())
        assert result.allowed

    def test_allowlist_blocks_unlisted(self) -> None:
        config = PathAllowlistConfig(allowed_paths=["/app/**"])
        guard = PathAllowlistGuard(config)
        action = FileAccessAction(path="/etc/shadow")
        result = guard.check(action, GuardContext())
        assert not result.allowed

    def test_allowlist_allows_listed(self) -> None:
        config = PathAllowlistConfig(allowed_paths=["/app/**"])
        guard = PathAllowlistGuard(config)
        action = FileAccessAction(path="/app/src/main.py")
        result = guard.check(action, GuardContext())
        assert result.allowed

    def test_multiple_patterns(self) -> None:
        config = PathAllowlistConfig(allowed_paths=["/app/**", "/tmp/**"])
        guard = PathAllowlistGuard(config)

        assert guard.check(FileAccessAction(path="/app/file.txt"), GuardContext()).allowed
        assert guard.check(FileAccessAction(path="/tmp/file.txt"), GuardContext()).allowed
        assert not guard.check(FileAccessAction(path="/etc/passwd"), GuardContext()).allowed

    def test_disabled_guard(self) -> None:
        config = PathAllowlistConfig(allowed_paths=["/app/**"], enabled=False)
        guard = PathAllowlistGuard(config)
        action = FileAccessAction(path="/etc/shadow")
        result = guard.check(action, GuardContext())
        assert result.allowed

    def test_guard_name(self) -> None:
        guard = PathAllowlistGuard()
        assert guard.name == "path_allowlist"
