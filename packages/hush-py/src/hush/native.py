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

    # Try to import optional functions that may not exist in older versions
    try:
        from hush_native import keccak256_native as _keccak256_native
        keccak256_native = _keccak256_native
    except ImportError:
        pass

    try:
        from hush_native import verify_ed25519_native as _verify_ed25519_native
        verify_ed25519_native = _verify_ed25519_native
    except ImportError:
        pass

    try:
        from hush_native import generate_merkle_proof_native as _generate_merkle_proof_native
        generate_merkle_proof_native = _generate_merkle_proof_native
    except ImportError:
        pass

    try:
        from hush_native import canonicalize_native as _canonicalize_native
        canonicalize_native = _canonicalize_native
    except ImportError:
        pass

    try:
        from hush_native import detect_jailbreak_native as _detect_jailbreak_native
        detect_jailbreak_native = _detect_jailbreak_native
    except ImportError:
        pass

    try:
        from hush_native import sanitize_output_native as _sanitize_output_native
        sanitize_output_native = _sanitize_output_native
    except ImportError:
        pass

    try:
        from hush_native import watermark_public_key_native as _watermark_public_key_native
        watermark_public_key_native = _watermark_public_key_native
    except ImportError:
        pass

    try:
        from hush_native import watermark_prompt_native as _watermark_prompt_native
        watermark_prompt_native = _watermark_prompt_native
    except ImportError:
        pass

    try:
        from hush_native import extract_watermark_native as _extract_watermark_native
        extract_watermark_native = _extract_watermark_native
    except ImportError:
        pass

except ImportError:
    pass


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
