"""Tests for clawdstrike.hunt.local."""

import json
from datetime import datetime
from pathlib import Path

from clawdstrike.hunt.local import default_local_dirs, hunt, query_local_files
from clawdstrike.hunt.types import HuntQuery


def _make_envelope(schema: str, ts: str, decision: str, summary_text: str) -> dict:
    return {
        "issued_at": ts,
        "fact": {
            "schema": schema,
            "decision": decision,
            "guard": "TestGuard",
            "action_type": "file_open",
            "severity": "info",
            "event_type": "PROCESS_EXEC",
            "process": {"binary": "/usr/bin/cat"},
            "verdict": decision.upper(),
            "traffic_direction": "EGRESS",
            "summary": summary_text,
            "scan_type": "vulnerability",
            "status": decision,
            "source": {
                "namespace": "default",
                "pod_name": "test-pod",
            },
        },
    }


class TestDefaultLocalDirs:
    def test_returns_list(self) -> None:
        dirs = default_local_dirs()
        assert isinstance(dirs, list)

    def test_all_returned_dirs_exist(self) -> None:
        dirs = default_local_dirs()
        for d in dirs:
            assert Path(d).is_dir()


class TestQueryLocalFilesJsonSingle:
    def test_single_envelope(self, tmp_path: Path) -> None:
        envelope = _make_envelope(
            "clawdstrike.sdr.fact.tetragon_event.v1",
            "2025-01-15T10:00:00Z",
            "allow",
            "file_open /etc/passwd",
        )
        path = tmp_path / "envelope.json"
        path.write_text(json.dumps(envelope))

        events = query_local_files(HuntQuery(), [str(tmp_path)])
        assert len(events) == 1
        assert "process_exec" in events[0].summary


class TestQueryLocalFilesJsonArray:
    def test_array_of_envelopes(self, tmp_path: Path) -> None:
        envelopes = [
            _make_envelope(
                "clawdstrike.sdr.fact.receipt.v1",
                "2025-01-15T10:00:00Z",
                "deny",
                "blocked rm -rf /",
            ),
            _make_envelope(
                "clawdstrike.sdr.fact.receipt.v1",
                "2025-01-15T10:01:00Z",
                "allow",
                "write to /tmp/output",
            ),
        ]
        path = tmp_path / "envelopes.json"
        path.write_text(json.dumps(envelopes))

        events = query_local_files(HuntQuery(), [str(tmp_path)])
        assert len(events) == 2


class TestQueryLocalFilesJsonl:
    def test_jsonl_lines(self, tmp_path: Path) -> None:
        e1 = _make_envelope(
            "clawdstrike.sdr.fact.tetragon_event.v1",
            "2025-01-15T10:00:00Z",
            "allow",
            "open /etc/hosts",
        )
        e2 = _make_envelope(
            "clawdstrike.sdr.fact.tetragon_event.v1",
            "2025-01-15T10:01:00Z",
            "deny",
            "egress to evil.com",
        )
        lines = [json.dumps(e1), "", json.dumps(e2)]
        path = tmp_path / "events.jsonl"
        path.write_text("\n".join(lines))

        events = query_local_files(HuntQuery(), [str(tmp_path)])
        assert len(events) == 2

    def test_skips_invalid_lines(self, tmp_path: Path) -> None:
        e1 = _make_envelope(
            "clawdstrike.sdr.fact.receipt.v1",
            "2025-01-15T10:00:00Z",
            "allow",
            "read /tmp/data",
        )
        e2 = _make_envelope(
            "clawdstrike.sdr.fact.receipt.v1",
            "2025-01-15T10:02:00Z",
            "allow",
            "echo hello",
        )
        lines = [json.dumps(e1), "not valid json {{{", json.dumps(e2)]
        path = tmp_path / "mixed.jsonl"
        path.write_text("\n".join(lines))

        events = query_local_files(HuntQuery(), [str(tmp_path)])
        assert len(events) == 2


class TestQueryLocalFilesEdgeCases:
    def test_skips_non_json_files(self, tmp_path: Path) -> None:
        (tmp_path / "notes.txt").write_text("not an envelope")
        envelope = _make_envelope(
            "clawdstrike.sdr.fact.receipt.v1",
            "2025-01-15T10:00:00Z",
            "allow",
            "test",
        )
        (tmp_path / "envelope.json").write_text(json.dumps(envelope))

        events = query_local_files(HuntQuery(), [str(tmp_path)])
        assert len(events) == 1

    def test_skips_corrupt_json_file(self, tmp_path: Path) -> None:
        envelope = _make_envelope(
            "clawdstrike.sdr.fact.receipt.v1",
            "2025-01-15T10:00:00Z",
            "allow",
            "test",
        )
        (tmp_path / "valid.json").write_text(json.dumps(envelope))
        (tmp_path / "corrupt.json").write_text("{not valid json")

        events = query_local_files(HuntQuery(), [str(tmp_path)])
        assert len(events) == 1

    def test_skips_nonexistent_dirs(self) -> None:
        events = query_local_files(
            HuntQuery(), ["/nonexistent/path/that/does/not/exist"]
        )
        assert events == []

    def test_limit_keeps_newest(self, tmp_path: Path) -> None:
        lines = [
            json.dumps(
                _make_envelope(
                    "clawdstrike.sdr.fact.receipt.v1",
                    "2025-01-15T10:00:00Z",
                    "allow",
                    "event-1",
                )
            ),
            json.dumps(
                _make_envelope(
                    "clawdstrike.sdr.fact.receipt.v1",
                    "2025-01-15T10:01:00Z",
                    "allow",
                    "event-2",
                )
            ),
            json.dumps(
                _make_envelope(
                    "clawdstrike.sdr.fact.receipt.v1",
                    "2025-01-15T10:02:00Z",
                    "allow",
                    "event-3",
                )
            ),
        ]
        (tmp_path / "events.jsonl").write_text("\n".join(lines))

        events = query_local_files(HuntQuery(limit=2), [str(tmp_path)])
        assert len(events) == 2
        assert events[0].timestamp.isoformat() == "2025-01-15T10:01:00+00:00"
        assert events[1].timestamp.isoformat() == "2025-01-15T10:02:00+00:00"

    def test_limit_zero_returns_empty(self, tmp_path: Path) -> None:
        lines = [
            json.dumps(
                _make_envelope(
                    "clawdstrike.sdr.fact.receipt.v1",
                    "2025-01-15T10:00:00Z",
                    "allow",
                    "event-1",
                )
            ),
            json.dumps(
                _make_envelope(
                    "clawdstrike.sdr.fact.receipt.v1",
                    "2025-01-15T10:01:00Z",
                    "allow",
                    "event-2",
                )
            ),
        ]
        (tmp_path / "events.jsonl").write_text("\n".join(lines))

        events = query_local_files(HuntQuery(limit=0), [str(tmp_path)])
        assert events == []


class TestHuntFunction:
    def test_queries_with_explicit_dirs(self, tmp_path: Path) -> None:
        envelope = _make_envelope(
            "clawdstrike.sdr.fact.receipt.v1",
            "2025-01-15T10:00:00Z",
            "deny",
            "blocked",
        )
        (tmp_path / "test.json").write_text(json.dumps(envelope))

        events = hunt(dirs=[str(tmp_path)])
        assert len(events) == 1

    def test_accepts_duration_string_for_start(self, tmp_path: Path) -> None:
        from datetime import datetime, timezone

        envelope = _make_envelope(
            "clawdstrike.sdr.fact.receipt.v1",
            datetime.now(tz=timezone.utc).isoformat(),
            "allow",
            "recent event",
        )
        (tmp_path / "recent.json").write_text(json.dumps(envelope))

        events = hunt(start="1h", dirs=[str(tmp_path)])
        assert len(events) == 1

    def test_normalizes_naive_start_datetime(self, tmp_path: Path) -> None:
        envelope = _make_envelope(
            "clawdstrike.sdr.fact.receipt.v1",
            "2025-01-15T10:00:00Z",
            "allow",
            "bounded event",
        )
        (tmp_path / "bounded.json").write_text(json.dumps(envelope))

        events = hunt(
            start=datetime(2025, 1, 15, 9, 59, 59),
            dirs=[str(tmp_path)],
        )
        assert len(events) == 1

    def test_normalizes_naive_end_datetime(self, tmp_path: Path) -> None:
        envelope = _make_envelope(
            "clawdstrike.sdr.fact.receipt.v1",
            "2025-01-15T10:00:00Z",
            "allow",
            "bounded event",
        )
        (tmp_path / "bounded.json").write_text(json.dumps(envelope))

        events = hunt(
            end=datetime(2025, 1, 15, 10, 0, 1),
            dirs=[str(tmp_path)],
        )
        assert len(events) == 1
