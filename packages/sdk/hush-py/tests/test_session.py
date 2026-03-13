"""Tests for ClawdstrikeSession."""

from __future__ import annotations

from clawdstrike import Clawdstrike
from tests._recording_backend import RecordingBackend


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

    def test_session_check_output_send_preserves_origin_override(self) -> None:
        backend = RecordingBackend()
        cs = Clawdstrike(backend)
        session = cs.session(agent_id="agent-1", session_id="sess-1")

        decision = session.check_output_send(
            "ship it",
            target="slack://incident-room",
            origin={"provider": "slack", "tenantId": "T123"},
        )

        assert decision.allowed
        action, args, ctx = backend.calls[-1]
        assert action == "origin.output_send"
        assert args[0]["target"] == "slack://incident-room"
        assert ctx["session_id"] == "sess-1"
        assert ctx["agent_id"] == "agent-1"
        assert ctx["origin"] == {
            "provider": "slack",
            "tenant_id": "T123",
        }

    def test_session_check_output_send_keeps_session_metadata_separate(self) -> None:
        backend = RecordingBackend()
        cs = Clawdstrike(backend)
        session = cs.session(session_id="sess-2", metadata={"scope": "prod"})

        decision = session.check_output_send(
            "ship it",
            metadata={"thread_id": "abc"},
            origin={"provider": "slack"},
        )

        assert decision.allowed
        action, args, ctx = backend.calls[-1]
        assert action == "origin.output_send"
        assert args[0]["metadata"] == {"thread_id": "abc"}
        assert ctx["metadata"] == {"scope": "prod"}

    def test_session_pins_session_and_agent_ids(self) -> None:
        backend = RecordingBackend()
        cs = Clawdstrike(backend)
        session = cs.session(session_id="sess-locked", agent_id="agent-locked")

        decision = session.check_file(
            "/app/safe.txt",
            session_id="sess-other",
            agent_id="agent-other",
            origin={"provider": "github", "spaceId": "R1"},
        )

        assert decision.allowed
        _, _, ctx = backend.calls[-1]
        assert ctx["session_id"] == "sess-locked"
        assert ctx["agent_id"] == "agent-locked"
        assert ctx["origin"] == {
            "provider": "github",
            "space_id": "R1",
        }

    def test_session_check_file_allows_per_check_origin_override(self) -> None:
        backend = RecordingBackend()
        cs = Clawdstrike(backend)
        session = cs.session(session_id="sess-9")

        session.check_file("/app/safe.txt", origin={"provider": "github", "spaceId": "R1"})

        _, _, ctx = backend.calls[-1]
        assert ctx["session_id"] == "sess-9"
        assert ctx["origin"] == {
            "provider": "github",
            "space_id": "R1",
        }
