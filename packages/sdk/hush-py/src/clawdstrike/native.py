"""Native Rust backend detection and imports.

This module attempts to load the native Rust bindings (hush_native).
If unavailable, NATIVE_AVAILABLE will be False and native_* functions
will be None.
"""
from __future__ import annotations

from typing import Callable, Optional, Tuple, List

# Try to import native bindings
NATIVE_AVAILABLE: bool = False
is_native_available: Optional[Callable[[], bool]] = None
sha256_native: Optional[Callable[[bytes], bytes]] = None
keccak256_native: Optional[Callable[[bytes], bytes]] = None
merkle_root_native: Optional[Callable[[List[bytes]], bytes]] = None
verify_receipt_native: Optional[Callable[[str, str, str], bool]] = None
verify_ed25519_native: Optional[Callable[[bytes, bytes, bytes], bool]] = None
generate_merkle_proof_native: Optional[Callable[[List[bytes], int], Tuple[int, int, List[str]]]] = None
canonicalize_native: Optional[Callable[[str], str]] = None
detect_jailbreak_native: Optional[Callable[..., dict]] = None
sanitize_output_native: Optional[Callable[..., dict]] = None
watermark_public_key_native: Optional[Callable[[str], str]] = None
watermark_prompt_native: Optional[Callable[..., dict]] = None
extract_watermark_native: Optional[Callable[..., dict]] = None

try:
    from hush_native import (
        is_native_available as _is_native_available,
        sha256_native as _sha256_native,
        merkle_root_native as _merkle_root_native,
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


__all__ = [
    "NATIVE_AVAILABLE",
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
