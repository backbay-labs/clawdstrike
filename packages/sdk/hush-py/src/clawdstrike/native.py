"""Native Rust backend detection and imports.

This module attempts to load the native Rust bindings (hush_native).
If unavailable, NATIVE_AVAILABLE will be False and native_* functions
will be None.
"""
from __future__ import annotations

from collections.abc import Callable

# Try to import native bindings
NATIVE_AVAILABLE: bool = False
is_native_available: Callable[[], bool] | None = None
sha256_native: Callable[[bytes], bytes] | None = None
keccak256_native: Callable[[bytes], bytes] | None = None
merkle_root_native: Callable[[list[bytes]], bytes] | None = None
verify_receipt_native: Callable[[str, str, str], bool] | None = None
verify_ed25519_native: Callable[[bytes, bytes, bytes], bool] | None = None
generate_merkle_proof_native: Callable[[list[bytes], int], tuple[int, int, list[str]]] | None = None
canonicalize_native: Callable[[str], str] | None = None
detect_jailbreak_native: Callable[..., dict] | None = None
sanitize_output_native: Callable[..., dict] | None = None
watermark_public_key_native: Callable[[str], str] | None = None
watermark_prompt_native: Callable[..., dict] | None = None
extract_watermark_native: Callable[..., dict] | None = None

try:
    from hush_native import (
        is_native_available as _is_native_available,
    )
    from hush_native import (
        merkle_root_native as _merkle_root_native,
    )
    from hush_native import (
        sha256_native as _sha256_native,
    )
    from hush_native import (
        verify_receipt_native as _verify_receipt_native,
    )

    NATIVE_AVAILABLE = True
    is_native_available = _is_native_available
    sha256_native = _sha256_native
    merkle_root_native = _merkle_root_native
    verify_receipt_native = _verify_receipt_native

    # Import optional functions that may not exist in older versions.
    # Uses getattr to avoid repetitive try/except ImportError blocks.
    import hush_native as _hush_native_mod

    _OPTIONAL_BINDINGS = [
        "keccak256_native",
        "verify_ed25519_native",
        "generate_merkle_proof_native",
        "canonicalize_native",
        "detect_jailbreak_native",
        "sanitize_output_native",
        "watermark_public_key_native",
        "watermark_prompt_native",
        "extract_watermark_native",
    ]
    for _name in _OPTIONAL_BINDINGS:
        _fn = getattr(_hush_native_mod, _name, None)
        if _fn is not None:
            globals()[_name] = _fn

    del _hush_native_mod, _OPTIONAL_BINDINGS, _name, _fn

except ImportError:
    # hush_native is not installed; all native_* bindings remain None.
    NATIVE_AVAILABLE = False


def get_native_module():
    """Return the hush_native module, raising NativeBackendError if unavailable."""
    if not NATIVE_AVAILABLE:
        from clawdstrike.exceptions import NativeBackendError
        raise NativeBackendError("hush-native extension not installed")
    import hush_native
    return hush_native


def init_native() -> bool:
    """Check if the native backend is available and has the NativeEngine class.

    Returns:
        True if native engine is available, False otherwise.
    """
    try:
        import hush_native
        return hasattr(hush_native, "NativeEngine")
    except ImportError:
        return False


__all__ = [
    "NATIVE_AVAILABLE",
    "get_native_module",
    "init_native",
    "is_native_available",
    "sha256_native",
    "keccak256_native",
    "merkle_root_native",
    "verify_receipt_native",
    "verify_ed25519_native",
    "generate_merkle_proof_native",
    "canonicalize_native",
    "detect_jailbreak_native",
    "sanitize_output_native",
    "watermark_public_key_native",
    "watermark_prompt_native",
    "extract_watermark_native",
]
