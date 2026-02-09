"""RFC 8785 (JCS) canonical JSON implementation.

Provides deterministic JSON serialization for hashing and signing:
- No whitespace between elements
- Object keys sorted lexicographically (UTF-16 code units)
- Numbers in shortest form (no trailing zeros)
- Unicode preserved (except control characters escaped)
"""
from __future__ import annotations

import math
import json
from typing import Any


def canonicalize(obj: Any) -> str:
    """Serialize object to canonical JSON per RFC 8785 (JCS).

    Args:
        obj: Python object to serialize (dict, list, str, int, float, bool, None)

    Returns:
        Canonical JSON string

    Raises:
        ValueError: If object contains non-finite floats (inf, nan)
    """
    if obj is None:
        return "null"

    if obj is True:
        return "true"

    if obj is False:
        return "false"

    if isinstance(obj, int) and not isinstance(obj, bool):
        return str(obj)

    if isinstance(obj, float):
        return _canonicalize_f64(obj)

    if isinstance(obj, str):
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), allow_nan=False)

    if isinstance(obj, (list, tuple)):
        return "[" + ",".join(canonicalize(v) for v in obj) + "]"

    if isinstance(obj, dict):
        for k in obj.keys():
            if not isinstance(k, str):
                raise TypeError("JSON object keys must be strings")

        items: list[tuple[str, Any]] = sorted(obj.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        parts = []
        for k, v in items:
            key_json = json.dumps(k, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
            parts.append(key_json + ":" + canonicalize(v))
        return "{" + ",".join(parts) + "}"

    raise TypeError(f"Unsupported type for canonical JSON: {type(obj).__name__}")


def _canonicalize_f64(v: float) -> str:
    if not math.isfinite(v):
        raise ValueError("Non-finite numbers are not valid JSON")

    if v == 0.0:
        return "0"

    sign = "-" if math.copysign(1.0, v) < 0 else ""
    abs_v = abs(v)
    use_exponential = not (1e-6 <= abs_v < 1e21)

    digits, sci_exp = _parse_to_scientific_parts(repr(abs_v))

    if not use_exponential:
        return sign + _render_decimal(digits, sci_exp)

    mantissa = digits if len(digits) == 1 else f"{digits[0]}.{digits[1:]}"
    exp_sign = "+" if sci_exp >= 0 else ""
    return f"{sign}{mantissa}e{exp_sign}{sci_exp}"


def _parse_to_scientific_parts(s: str) -> tuple[str, int]:
    s = s.strip()
    if not s:
        raise ValueError("Empty number string")

    if "e" in s or "E" in s:
        mantissa, exp_str = s.replace("E", "e").split("e", 1)
        exp = int(exp_str)
    else:
        mantissa = s
        exp = 0

    if "." in mantissa:
        before, after = mantissa.split(".", 1)
        after = after.rstrip("0")
        digits_before_dot = len(before)
        digits = before + after
    else:
        digits_before_dot = len(mantissa)
        digits = mantissa

    digits = digits.lstrip("0") or "0"
    digits = digits.rstrip("0") or "0"

    if "e" in s or "E" in s:
        sci_exp = exp + (digits_before_dot - 1)
        return digits, sci_exp

    # Decimal form: compute exponent from position of first significant digit.
    if "." in mantissa:
        int_part, frac_part_raw = mantissa.split(".", 1)
        frac_part = frac_part_raw.rstrip("0")

        int_stripped = int_part.lstrip("0")
        if int_stripped:
            sci_exp = len(int_stripped) - 1
        else:
            leading_zeros = 0
            for c in frac_part:
                if c != "0":
                    break
                leading_zeros += 1
            sci_exp = -(leading_zeros + 1)
        return digits, sci_exp

    # Integer form (no dot)
    sci_exp = len(mantissa.lstrip("0")) - 1
    return digits, sci_exp


def _render_decimal(digits: str, sci_exp: int) -> str:
    digits_len = len(digits)
    shift = sci_exp - (digits_len - 1)

    if shift >= 0:
        return digits + ("0" * shift)

    pos = digits_len + shift
    if pos > 0:
        out = digits[:pos] + "." + digits[pos:]
        return _trim_decimal(out)

    zeros = -pos
    out = "0." + ("0" * zeros) + digits
    return _trim_decimal(out)


def _trim_decimal(s: str) -> str:
    if "." not in s:
        return s
    s = s.rstrip("0")
    if s.endswith("."):
        s = s[:-1]
    return s


def canonical_hash(obj: Any, algorithm: str = "sha256") -> bytes:
    """Hash object using canonical JSON serialization.

    Args:
        obj: Python object to serialize and hash
        algorithm: Hash algorithm ("sha256" or "keccak256")

    Returns:
        32-byte hash digest

    Raises:
        ValueError: If algorithm is not supported
    """
    from .core import sha256, keccak256

    canonical = canonicalize(obj).encode("utf-8")

    if algorithm == "sha256":
        return sha256(canonical)
    elif algorithm == "keccak256":
        return keccak256(canonical)
    else:
        raise ValueError(f"Unknown algorithm: {algorithm}")


__all__ = [
    "canonicalize",
    "canonical_hash",
]
