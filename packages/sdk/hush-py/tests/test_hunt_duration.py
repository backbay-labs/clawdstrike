"""Tests for clawdstrike.hunt.duration."""

from datetime import timedelta

from clawdstrike.hunt.duration import parse_human_duration


class TestParseHumanDurationShortUnits:
    def test_seconds(self) -> None:
        assert parse_human_duration("30s") == timedelta(seconds=30)

    def test_minutes(self) -> None:
        assert parse_human_duration("5m") == timedelta(minutes=5)

    def test_hours(self) -> None:
        assert parse_human_duration("1h") == timedelta(hours=1)

    def test_days(self) -> None:
        assert parse_human_duration("2d") == timedelta(days=2)


class TestParseHumanDurationLongUnits:
    def test_sec(self) -> None:
        assert parse_human_duration("30sec") == timedelta(seconds=30)

    def test_secs(self) -> None:
        assert parse_human_duration("30secs") == timedelta(seconds=30)

    def test_second(self) -> None:
        assert parse_human_duration("1second") == timedelta(seconds=1)

    def test_seconds(self) -> None:
        assert parse_human_duration("10seconds") == timedelta(seconds=10)

    def test_min(self) -> None:
        assert parse_human_duration("5min") == timedelta(minutes=5)

    def test_mins(self) -> None:
        assert parse_human_duration("5mins") == timedelta(minutes=5)

    def test_minute(self) -> None:
        assert parse_human_duration("1minute") == timedelta(minutes=1)

    def test_minutes(self) -> None:
        assert parse_human_duration("3minutes") == timedelta(minutes=3)

    def test_hr(self) -> None:
        assert parse_human_duration("2hr") == timedelta(hours=2)

    def test_hrs(self) -> None:
        assert parse_human_duration("2hrs") == timedelta(hours=2)

    def test_hour(self) -> None:
        assert parse_human_duration("1hour") == timedelta(hours=1)

    def test_hours(self) -> None:
        assert parse_human_duration("4hours") == timedelta(hours=4)

    def test_day(self) -> None:
        assert parse_human_duration("1day") == timedelta(days=1)

    def test_days(self) -> None:
        assert parse_human_duration("3days") == timedelta(days=3)


class TestParseHumanDurationEdgeCases:
    def test_zero_seconds(self) -> None:
        assert parse_human_duration("0s") == timedelta(seconds=0)

    def test_zero_days(self) -> None:
        assert parse_human_duration("0d") == timedelta(days=0)

    def test_whitespace_trimmed(self) -> None:
        assert parse_human_duration("  5m  ") == timedelta(minutes=5)

    def test_suffix_with_space(self) -> None:
        assert parse_human_duration("5 m") == timedelta(minutes=5)

    def test_large_value(self) -> None:
        assert parse_human_duration("86400s") == timedelta(seconds=86400)


class TestParseHumanDurationInvalid:
    def test_empty(self) -> None:
        assert parse_human_duration("") is None

    def test_only_whitespace(self) -> None:
        assert parse_human_duration("   ") is None

    def test_no_suffix(self) -> None:
        assert parse_human_duration("1") is None

    def test_no_digits(self) -> None:
        assert parse_human_duration("abc") is None

    def test_unknown_suffix(self) -> None:
        assert parse_human_duration("10x") is None

    def test_non_ascii_suffix(self) -> None:
        assert parse_human_duration("30\u79d2") is None

    def test_only_suffix(self) -> None:
        assert parse_human_duration("hours") is None
