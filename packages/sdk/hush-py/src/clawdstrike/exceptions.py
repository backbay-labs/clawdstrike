"""Clawdstrike exception hierarchy."""


class ClawdstrikeError(Exception):
    """Base exception for all Clawdstrike errors."""


class PolicyError(ClawdstrikeError, ValueError):
    """Error in policy loading, parsing, or validation."""


class GuardError(ClawdstrikeError):
    """Error during guard evaluation."""


class ReceiptError(ClawdstrikeError, ValueError):
    """Error in receipt creation, signing, or verification."""


class ConfigurationError(ClawdstrikeError):
    """Error in SDK configuration."""


class NativeBackendError(ClawdstrikeError):
    """Error in the native Rust backend."""
