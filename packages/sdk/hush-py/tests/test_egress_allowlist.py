"""Tests for EgressAllowlistGuard."""

import pytest
from clawdstrike.guards.egress_allowlist import EgressAllowlistGuard, EgressAllowlistConfig
from clawdstrike.guards.base import GuardAction, GuardContext, Severity


class TestEgressAllowlistConfig:
    def test_default_config(self) -> None:
        config = EgressAllowlistConfig()
        assert config.allow == []
        assert config.block == []
        assert config.default_action == "block"

    def test_custom_config(self) -> None:
        config = EgressAllowlistConfig(
            allow=["*.github.com", "api.example.com"],
            block=["malicious.com"],
            default_action="allow",
        )
        assert "*.github.com" in config.allow
        assert "malicious.com" in config.block


class TestEgressAllowlistGuard:
    def test_allow_matching_domain(self) -> None:
        config = EgressAllowlistConfig(
            allow=["api.example.com", "*.github.com"],
            default_action="block",
        )
        guard = EgressAllowlistGuard(config)
        context = GuardContext()

        result = guard.check(
            GuardAction.network_egress("api.example.com", 443),
            context,
        )
        assert result.allowed is True

    def test_allow_wildcard_subdomain(self) -> None:
        config = EgressAllowlistConfig(
            allow=["*.github.com"],
            default_action="block",
        )
        guard = EgressAllowlistGuard(config)
        context = GuardContext()

        result = guard.check(
            GuardAction.network_egress("api.github.com", 443),
            context,
        )
        assert result.allowed is True

        result = guard.check(
            GuardAction.network_egress("raw.githubusercontent.com", 443),
            context,
        )
        assert result.allowed is False  # Different domain

    def test_block_explicit_domain(self) -> None:
        config = EgressAllowlistConfig(
            allow=["*"],
            block=["malicious.com"],
            default_action="allow",
        )
        guard = EgressAllowlistGuard(config)
        context = GuardContext()

        result = guard.check(
            GuardAction.network_egress("malicious.com", 80),
            context,
        )
        assert result.allowed is False
        assert result.severity == Severity.ERROR

    def test_default_block(self) -> None:
        config = EgressAllowlistConfig(
            allow=["allowed.com"],
            default_action="block",
        )
        guard = EgressAllowlistGuard(config)
        context = GuardContext()

        result = guard.check(
            GuardAction.network_egress("unknown.com", 443),
            context,
        )
        assert result.allowed is False

    def test_default_allow(self) -> None:
        config = EgressAllowlistConfig(
            block=["blocked.com"],
            default_action="allow",
        )
        guard = EgressAllowlistGuard(config)
        context = GuardContext()

        result = guard.check(
            GuardAction.network_egress("unknown.com", 443),
            context,
        )
        assert result.allowed is True

    def test_handles_network_actions(self) -> None:
        guard = EgressAllowlistGuard()

        assert guard.handles(GuardAction.network_egress("host", 80)) is True
        assert guard.handles(GuardAction.file_access("/test")) is False

    def test_guard_name(self) -> None:
        guard = EgressAllowlistGuard()
        assert guard.name == "egress_allowlist"

    def test_subdomain_matching(self) -> None:
        config = EgressAllowlistConfig(
            allow=["github.com"],
            default_action="block",
        )
        guard = EgressAllowlistGuard(config)
        context = GuardContext()

        # Exact match
        result = guard.check(
            GuardAction.network_egress("github.com", 443),
            context,
        )
        assert result.allowed is True

        # Subdomain should NOT match without an explicit glob
        result = guard.check(
            GuardAction.network_egress("api.github.com", 443),
            context,
        )
        assert result.allowed is False

    def test_glob_features_case_insensitive(self) -> None:
        config = EgressAllowlistConfig(
            allow=["api-?.example.com", "api-[a-z].example.com"],
            default_action="block",
        )
        guard = EgressAllowlistGuard(config)
        context = GuardContext()

        assert (
            guard.check(GuardAction.network_egress("api-1.example.com", 443), context).allowed
            is True
        )
        assert (
            guard.check(GuardAction.network_egress("API-a.EXAMPLE.com", 443), context).allowed
            is True
        )
        assert (
            guard.check(GuardAction.network_egress("api-aa.example.com", 443), context).allowed
            is False
        )
