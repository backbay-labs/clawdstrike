"""Tests for exception hierarchy."""

from clawdstrike.exceptions import (
    ClawdstrikeError,
    ConfigurationError,
    GuardError,
    NativeBackendError,
    PolicyError,
    ReceiptError,
    UnsupportedOriginFeatureError,
)


class TestExceptionHierarchy:
    def test_all_inherit_from_clawdstrike_error(self) -> None:
        for exc_cls in [
            PolicyError,
            GuardError,
            ReceiptError,
            ConfigurationError,
            NativeBackendError,
            UnsupportedOriginFeatureError,
        ]:
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
        assert not issubclass(PolicyError, ReceiptError)
        assert not issubclass(ReceiptError, PolicyError)
        assert not issubclass(GuardError, PolicyError)
        assert not issubclass(ConfigurationError, PolicyError)

    def test_unsupported_origin_feature_error_is_a_policy_error(self) -> None:
        assert issubclass(UnsupportedOriginFeatureError, PolicyError)
