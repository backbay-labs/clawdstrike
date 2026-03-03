"""Error hierarchy for hunt operations."""

from __future__ import annotations


class HuntError(Exception):
    """Base error for hunt operations."""

    def __init__(self, message: str, code: str = "HUNT_ERROR") -> None:
        super().__init__(message)
        self.code = code


class QueryError(HuntError):
    """Error during query construction or execution."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="QUERY_ERROR")


class ParseError(HuntError):
    """Error parsing envelope or event data."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="PARSE_ERROR")


class IoError(HuntError):
    """Error during file or network I/O."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="IO_ERROR")


class CorrelationError(HuntError):
    """Error during event correlation."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="CORRELATION_ERROR")


class IocError(HuntError):
    """Error during IOC matching."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="IOC_ERROR")


class WatchError(HuntError):
    """Error during watch/subscription operations."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="WATCH_ERROR")


class ReportError(HuntError):
    """Error during report generation."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="REPORT_ERROR")


class HuntAlertError(HuntError):
    """Raised when a guarded function triggers an alert in deny mode."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="ALERT_DENIED")


class PlaybookError(HuntError):
    """Error during playbook execution."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="PLAYBOOK_ERROR")


class ExportError(HuntError):
    """Error during export operations."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="EXPORT_ERROR")
