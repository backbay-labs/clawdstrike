"""Tests for clawdstrike.hunt.ioc — IOC detection, word boundaries, and database."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from clawdstrike.hunt.ioc import (
    IocDatabase,
    contains_word_bounded,
    detect_ioc_type,
)
from clawdstrike.hunt.types import (
    EventSourceType,
    IocEntry,
    IocType,
    NormalizedVerdict,
    TimelineEvent,
    TimelineEventKind,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_event(
    summary: str,
    process: str | None = None,
    raw: object | None = None,
) -> TimelineEvent:
    return TimelineEvent(
        timestamp=datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc),
        source=EventSourceType.TETRAGON,
        kind=TimelineEventKind.PROCESS_EXEC,
        verdict=NormalizedVerdict.NONE,
        summary=summary,
        process=process,
        raw=raw,
    )


# ---------------------------------------------------------------------------
# detect_ioc_type
# ---------------------------------------------------------------------------


class TestDetectIocType:
    def test_sha256(self) -> None:
        assert detect_ioc_type("a" * 64) == IocType.SHA256

    def test_sha1(self) -> None:
        assert detect_ioc_type("b" * 40) == IocType.SHA1

    def test_md5(self) -> None:
        assert detect_ioc_type("c" * 32) == IocType.MD5

    def test_domain(self) -> None:
        assert detect_ioc_type("evil.com") == IocType.DOMAIN
        assert detect_ioc_type("sub.evil.com") == IocType.DOMAIN

    def test_ipv4(self) -> None:
        assert detect_ioc_type("192.168.1.1") == IocType.IPV4
        assert detect_ioc_type("10.0.0.1") == IocType.IPV4

    def test_ipv6(self) -> None:
        assert detect_ioc_type("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == IocType.IPV6

    def test_url(self) -> None:
        assert detect_ioc_type("http://evil.com/payload") == IocType.URL
        assert detect_ioc_type("https://malware.example.org/dl") == IocType.URL

    def test_empty_returns_none(self) -> None:
        assert detect_ioc_type("") is None
        assert detect_ioc_type("   ") is None


# ---------------------------------------------------------------------------
# Word-boundary matching
# ---------------------------------------------------------------------------


class TestContainsWordBounded:
    def test_domain_at_word_boundary(self) -> None:
        assert contains_word_bounded("connect to evil.com:443", "evil.com")

    def test_domain_not_at_boundary_prefix(self) -> None:
        assert not contains_word_bounded("connect to notevil.com", "evil.com")

    def test_domain_not_at_boundary_hyphen(self) -> None:
        assert not contains_word_bounded("connect to cdn-evil.com", "evil.com")

    def test_ip_at_word_boundary(self) -> None:
        assert contains_word_bounded("ip 10.0.0.1:80", "10.0.0.1")

    def test_ip_not_at_boundary_prefix(self) -> None:
        assert not contains_word_bounded("ip 210.0.0.1:80", "10.0.0.1")

    def test_ip_not_at_boundary_suffix(self) -> None:
        assert not contains_word_bounded("ip 10.0.0.100:80", "10.0.0.1")

    def test_empty_needle(self) -> None:
        assert not contains_word_bounded("abc", "")
        assert not contains_word_bounded("", "")

    def test_unicode_prefix_counts_as_boundary_for_ts_parity(self) -> None:
        # Match TS behavior: only ASCII alnum are IOC "word" chars.
        # The accented character does not block a boundary before evil.com.
        assert contains_word_bounded("prefixéevil.com", "evil.com")


# ---------------------------------------------------------------------------
# IocDatabase — CRUD
# ---------------------------------------------------------------------------


class TestIocDatabaseCrud:
    def test_add_and_len(self) -> None:
        db = IocDatabase()
        assert db.is_empty()
        db.add_entry(IocEntry(
            indicator="evil.com", ioc_type=IocType.DOMAIN,
            description=None, source=None,
        ))
        assert len(db) == 1
        assert not db.is_empty()

    def test_add_empty_ignored(self) -> None:
        db = IocDatabase()
        db.add_entry(IocEntry(
            indicator="   ", ioc_type=IocType.DOMAIN,
            description=None, source=None,
        ))
        assert len(db) == 0

    def test_merge(self) -> None:
        db1 = IocDatabase()
        db1.add_entry(IocEntry(
            indicator="evil.com", ioc_type=IocType.DOMAIN,
            description=None, source=None,
        ))
        db2 = IocDatabase()
        db2.add_entry(IocEntry(
            indicator="10.0.0.99", ioc_type=IocType.IPV4,
            description=None, source=None,
        ))
        db1.merge(db2)
        assert len(db1) == 2


# ---------------------------------------------------------------------------
# IocDatabase — text loading
# ---------------------------------------------------------------------------


class TestIocDatabaseTextLoad:
    def test_load_text_file(self, tmp_path) -> None:
        p = tmp_path / "iocs.txt"
        sha = "a" * 64
        p.write_text(f"# comment\n{sha}\n\nevil.com\n192.168.1.1\n")

        db = IocDatabase.load_text_file(str(p))
        assert len(db) == 3


# ---------------------------------------------------------------------------
# IocDatabase — CSV loading
# ---------------------------------------------------------------------------


class TestIocDatabaseCsvLoad:
    def test_load_csv_with_header(self, tmp_path) -> None:
        p = tmp_path / "iocs.csv"
        sha = "a" * 64
        p.write_text(
            f"indicator,type,description,source\n"
            f"{sha},sha256,Bad file,ThreatFeed\n"
            f"evil.com,domain,C2 domain,Intel\n"
        )
        db = IocDatabase.load_csv_file(str(p))
        assert len(db) == 2

    def test_load_csv_quoted_fields(self, tmp_path) -> None:
        p = tmp_path / "iocs_quoted.csv"
        p.write_text(
            'indicator,type,description,source\n'
            '"evil.com",domain,"Known C2, very bad","Intel, Inc"\n'
        )
        db = IocDatabase.load_csv_file(str(p))
        assert len(db) == 1

    def test_load_csv_no_header(self, tmp_path) -> None:
        p = tmp_path / "iocs_no_header.csv"
        sha = "a" * 64
        p.write_text(
            f"{sha},sha256,Malware hash,Feed1\n"
            f"evil.com,domain,C2 domain,Feed2\n"
        )
        db = IocDatabase.load_csv_file(str(p))
        assert len(db) == 2

    def test_load_csv_unknown_type_falls_back(self, tmp_path) -> None:
        p = tmp_path / "iocs_unknown.csv"
        sha = "a" * 64
        p.write_text(
            f"indicator,type,description,source\n"
            f"{sha},hash,Malware hash,Feed1\n"
            f"evil.com,hostname,C2 domain,Feed2\n"
        )
        db = IocDatabase.load_csv_file(str(p))
        assert len(db) == 2


# ---------------------------------------------------------------------------
# IocDatabase — STIX loading
# ---------------------------------------------------------------------------


class TestIocDatabaseStixLoad:
    def test_load_stix_bundle(self, tmp_path) -> None:
        sha = "a" * 64
        bundle = {
            "type": "bundle",
            "id": "bundle--1",
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--1",
                    "name": "Malware hash",
                    "description": "Known bad hash",
                    "pattern": f"[file:hashes.SHA-256 = '{sha}']",
                    "pattern_type": "stix",
                    "valid_from": "2025-01-01T00:00:00Z",
                },
                {
                    "type": "indicator",
                    "id": "indicator--2",
                    "name": "C2 domain",
                    "pattern": "[domain-name:value = 'evil.example.com']",
                    "pattern_type": "stix",
                    "valid_from": "2025-01-01T00:00:00Z",
                },
                {
                    "type": "indicator",
                    "id": "indicator--3",
                    "name": "C2 IP",
                    "pattern": "[ipv4-addr:value = '10.0.0.99']",
                    "pattern_type": "stix",
                    "valid_from": "2025-01-01T00:00:00Z",
                },
                {
                    "type": "malware",
                    "id": "malware--1",
                    "name": "Should be skipped",
                },
            ],
        }
        p = tmp_path / "stix.json"
        p.write_text(json.dumps(bundle))
        db = IocDatabase.load_stix_bundle(str(p))
        assert len(db) == 3

    def test_stix_missing_objects_errors(self, tmp_path) -> None:
        p = tmp_path / "bad.json"
        p.write_text('{"type": "bundle"}')
        from clawdstrike.hunt.errors import IocError
        with pytest.raises(IocError, match="objects"):
            IocDatabase.load_stix_bundle(str(p))

    def test_stix_non_object_entries_are_ignored(self, tmp_path) -> None:
        bundle = {
            "type": "bundle",
            "id": "bundle--mixed",
            "objects": [
                "not-an-object",
                123,
                {"type": "indicator", "pattern": "[domain-name:value = 'evil.example.com']"},
            ],
        }
        p = tmp_path / "stix_mixed.json"
        p.write_text(json.dumps(bundle))
        db = IocDatabase.load_stix_bundle(str(p))
        assert len(db) == 1


# ---------------------------------------------------------------------------
# Event matching
# ---------------------------------------------------------------------------


class TestIocDatabaseMatching:
    def test_match_domain_in_summary(self) -> None:
        db = IocDatabase()
        db.add_entry(IocEntry(
            indicator="evil.com", ioc_type=IocType.DOMAIN,
            description=None, source=None,
        ))
        event = _make_event("egress TCP 10.0.0.1 -> evil.com:443")
        result = db.match_event(event)
        assert result is not None
        assert result.match_field == "summary"

    def test_match_hash_in_raw(self) -> None:
        sha = "a" * 64
        db = IocDatabase()
        db.add_entry(IocEntry(
            indicator=sha, ioc_type=IocType.SHA256,
            description=None, source=None,
        ))
        event = _make_event("curl something", None, {"file_hash": sha})
        result = db.match_event(event)
        assert result is not None
        assert result.match_field == "raw"

    def test_match_ip_in_summary(self) -> None:
        db = IocDatabase()
        db.add_entry(IocEntry(
            indicator="10.0.0.99", ioc_type=IocType.IPV4,
            description=None, source=None,
        ))
        event = _make_event("egress TCP -> 10.0.0.99:8080")
        result = db.match_event(event)
        assert result is not None
        assert result.match_field == "summary"

    def test_no_match(self) -> None:
        db = IocDatabase()
        db.add_entry(IocEntry(
            indicator="evil.com", ioc_type=IocType.DOMAIN,
            description=None, source=None,
        ))
        event = _make_event("normal activity on good.com")
        result = db.match_event(event)
        assert result is None

    def test_no_false_positive_subdomain(self) -> None:
        db = IocDatabase()
        db.add_entry(IocEntry(
            indicator="evil.com", ioc_type=IocType.DOMAIN,
            description=None, source=None,
        ))
        event = _make_event("connection to notevil.com")
        assert db.match_event(event) is None

    def test_ip_no_false_positive_prefix(self) -> None:
        db = IocDatabase()
        db.add_entry(IocEntry(
            indicator="10.0.0.1", ioc_type=IocType.IPV4,
            description=None, source=None,
        ))
        event = _make_event("egress TCP -> 210.0.0.1:8080")
        assert db.match_event(event) is None

    def test_match_events_batch(self) -> None:
        db = IocDatabase()
        db.add_entry(IocEntry(
            indicator="evil.com", ioc_type=IocType.DOMAIN,
            description=None, source=None,
        ))
        events = [
            _make_event("connection to evil.com"),
            _make_event("normal traffic"),
            _make_event("dns query evil.com"),
        ]
        results = db.match_events(events)
        assert len(results) == 2

    def test_unserializable_raw_payload_does_not_break_matching(self) -> None:
        db = IocDatabase()
        db.add_entry(IocEntry(
            indicator="evil.com", ioc_type=IocType.DOMAIN,
            description=None, source=None,
        ))
        circular: dict[str, object] = {}
        circular["self"] = circular
        event = _make_event("connection to evil.com", raw=circular)
        result = db.match_event(event)
        assert result is not None
        assert result.match_field == "summary"
