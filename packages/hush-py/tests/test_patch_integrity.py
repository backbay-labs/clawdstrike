"""Tests for PatchIntegrityGuard."""

import pytest
from clawdstrike.guards.patch_integrity import PatchIntegrityGuard, PatchIntegrityConfig
from clawdstrike.guards.base import GuardAction, GuardContext, Severity


class TestPatchIntegrityConfig:
    def test_default_config(self) -> None:
        config = PatchIntegrityConfig()
        assert config.max_additions == 1000
        assert config.max_deletions == 500
        assert config.require_balance is False


class TestPatchIntegrityGuard:
    def test_within_limits(self) -> None:
        config = PatchIntegrityConfig(
            max_additions=100,
            max_deletions=50,
        )
        guard = PatchIntegrityGuard(config)
        context = GuardContext()

        # Small patch well within limits
        diff = """
+line 1
+line 2
-old line
"""
        result = guard.check(GuardAction.patch("/file.py", diff), context)
        assert result.allowed is True

    def test_exceeds_additions(self) -> None:
        config = PatchIntegrityConfig(max_additions=5)
        guard = PatchIntegrityGuard(config)
        context = GuardContext()

        # Patch with 10 additions
        diff = "\n".join([f"+line {i}" for i in range(10)])

        result = guard.check(GuardAction.patch("/file.py", diff), context)
        assert result.allowed is False
        assert "additions" in result.message.lower()

    def test_exceeds_deletions(self) -> None:
        config = PatchIntegrityConfig(max_deletions=3)
        guard = PatchIntegrityGuard(config)
        context = GuardContext()

        # Patch with 5 deletions
        diff = "\n".join([f"-line {i}" for i in range(5)])

        result = guard.check(GuardAction.patch("/file.py", diff), context)
        assert result.allowed is False
        assert "deletions" in result.message.lower()

    def test_balance_required_balanced(self) -> None:
        config = PatchIntegrityConfig(
            max_additions=100,
            max_deletions=100,
            require_balance=True,
            max_imbalance_ratio=2.0,
        )
        guard = PatchIntegrityGuard(config)
        context = GuardContext()

        # Balanced patch (10 additions, 8 deletions)
        diff = "\n".join([f"+line {i}" for i in range(10)])
        diff += "\n" + "\n".join([f"-line {i}" for i in range(8)])

        result = guard.check(GuardAction.patch("/file.py", diff), context)
        assert result.allowed is True

    def test_balance_required_imbalanced(self) -> None:
        config = PatchIntegrityConfig(
            max_additions=100,
            max_deletions=100,
            require_balance=True,
            max_imbalance_ratio=2.0,
        )
        guard = PatchIntegrityGuard(config)
        context = GuardContext()

        # Very imbalanced patch (20 additions, 2 deletions)
        diff = "\n".join([f"+line {i}" for i in range(20)])
        diff += "\n-line 1\n-line 2"

        result = guard.check(GuardAction.patch("/file.py", diff), context)
        assert result.allowed is False
        assert "imbalance" in result.message.lower()

    def test_handles_patch_actions(self) -> None:
        guard = PatchIntegrityGuard()

        assert guard.handles(GuardAction.patch("/file", "diff")) is True
        assert guard.handles(GuardAction.file_access("/test")) is False

    def test_guard_name(self) -> None:
        guard = PatchIntegrityGuard()
        assert guard.name == "patch_integrity"

    def test_counts_only_actual_changes(self) -> None:
        guard = PatchIntegrityGuard()
        context = GuardContext()

        # Diff with context lines (no + or - prefix)
        diff = """
@@ -1,5 +1,6 @@
 context line
+added line
 more context
-removed line
 final context
"""
        result = guard.check(GuardAction.patch("/file.py", diff), context)
        assert result.allowed is True
        assert result.details is not None
        assert result.details.get("additions") == 1
        assert result.details.get("deletions") == 1
