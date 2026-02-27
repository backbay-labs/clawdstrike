"""Tests for version parsing utility."""

from clawdstrike._version import parse_semver_strict


class TestParseSemverStrict:
    def test_valid_version(self) -> None:
        assert parse_semver_strict("1.0.0") == (1, 0, 0)
        assert parse_semver_strict("1.2.3") == (1, 2, 3)
        assert parse_semver_strict("0.0.0") == (0, 0, 0)
        assert parse_semver_strict("10.20.30") == (10, 20, 30)

    def test_rejects_leading_zeros(self) -> None:
        assert parse_semver_strict("01.0.0") is None
        assert parse_semver_strict("1.00.0") is None
        assert parse_semver_strict("1.0.00") is None

    def test_rejects_incomplete(self) -> None:
        assert parse_semver_strict("1.0") is None
        assert parse_semver_strict("1") is None
        assert parse_semver_strict("") is None

    def test_rejects_non_numeric(self) -> None:
        assert parse_semver_strict("1.0.a") is None
        assert parse_semver_strict("a.b.c") is None
        assert parse_semver_strict("1.0.0-beta") is None

    def test_rejects_extra_parts(self) -> None:
        assert parse_semver_strict("1.0.0.0") is None

    def test_rejects_empty_parts(self) -> None:
        assert parse_semver_strict("1..0") is None
        assert parse_semver_strict(".1.0") is None
