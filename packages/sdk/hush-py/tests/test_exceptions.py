"""Tests for exception hierarchy."""

from clawdstrike.exceptions import (
    ClawdstrikeError,
    PolicyError,
    GuardError,
    ReceiptError,
    ConfigurationError,
    NativeBackendError,
)


class TestExceptionHierarchy:
    def test_all_inherit_from_clawdstrike_error(self) -> None:
        for exc_cls in [PolicyError, GuardError, ReceiptError, ConfigurationError, NativeBackendError]:
            assert issubclass(exc_cls, ClawdstrikeError)
            assert issubclass(exc_cls, Exception)

    def test_clawdstrike_error_is_exception(self) -> None:
        assert issubclass(ClawdstrikeError, Exception)

    def test_policy_error_catchable_as_clawdstrike_error(self) -> None:
        try:
            raise PolicyError("test")
        except ClawdstrikeError as e:
            assert str(e) == "test"

    def test_receipt_error_catchable_as_clawdstrike_error(self) -> None:
        try:
            raise ReceiptError("test")
        except ClawdstrikeError as e:
            assert str(e) == "test"

    def test_exceptions_are_distinct(self) -> None:
        import pytest
        with pytest.raises(PolicyError):
            raise PolicyError("p")
        with pytest.raises(ReceiptError):
            raise ReceiptError("r")
