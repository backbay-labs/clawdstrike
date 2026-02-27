"""Tests for ClawdstrikeSession."""

from clawdstrike import Clawdstrike


class TestClawdstrikeSession:
    def test_session_creation(self) -> None:
        cs = Clawdstrike.with_defaults("default")
        session = cs.session(agent_id="test-agent")
        assert session is not None

    def test_session_tracks_counts(self) -> None:
        cs = Clawdstrike.with_defaults("default")
        session = cs.session(agent_id="test")

        session.check_file("/app/safe.txt")
        session.check_file("/home/user/.ssh/id_rsa")

        summary = session.get_summary()
        assert summary.check_count == 2
        assert summary.allow_count + summary.deny_count == 2

    def test_session_tracks_blocked_actions(self) -> None:
        cs = Clawdstrike.with_defaults("strict")
        session = cs.session(agent_id="test")

        session.check_file("/home/user/.ssh/id_rsa")
        summary = session.get_summary()
        assert summary.deny_count >= 1
        assert len(summary.blocked_actions) >= 1

    def test_session_check_network(self) -> None:
        cs = Clawdstrike.with_defaults("default")
        session = cs.session()

        d = session.check_network("api.openai.com")
        assert d.allowed

        summary = session.get_summary()
        assert summary.check_count == 1

    def test_session_summary_frozen(self) -> None:
        cs = Clawdstrike.with_defaults("default")
        session = cs.session()
        session.check_file("/app/safe.txt")
        summary = session.get_summary()
        import pytest
        with pytest.raises(AttributeError):
            summary.check_count = 999  # type: ignore[misc]
