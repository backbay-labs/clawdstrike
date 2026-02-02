# hush-py Python SDK Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Create a Python SDK for clawdstrike with pure Python guards and optional PyO3 native bindings.

**Architecture:** Pure Python implementation with fallback to native Rust bindings when available. Guards mirror the Rust clawdstrike crate. Policy engine loads YAML and instantiates guards. Receipt types match hush-core for cross-language verification.

**Tech Stack:** Python 3.10+, pynacl (Ed25519), pyyaml, httpx (async HTTP), pytest, maturin (PyO3 build)

---

## Task 1: Package Structure and pyproject.toml

**Files:**
- Create: `packages/hush-py/pyproject.toml`
- Create: `packages/hush-py/src/hush/__init__.py`
- Create: `packages/hush-py/src/hush/py.typed`

**Step 1: Create the package directory structure**

```bash
mkdir -p packages/hush-py/src/hush/guards
mkdir -p packages/hush-py/src/hush/attestation
mkdir -p packages/hush-py/tests
```

**Step 2: Write pyproject.toml**

```toml
[project]
name = "hush"
version = "0.1.0"
description = "Python SDK for clawdstrike security verification"
readme = "README.md"
license = { text = "MIT" }
requires-python = ">=3.10"
authors = [
    { name = "Clawdstrike Team" }
]
classifiers = [
    "Development Status :: 3 - Alpha",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Topic :: Security",
]
dependencies = [
    "pynacl>=1.5.0",
    "pyyaml>=6.0",
]

[project.optional-dependencies]
native = ["hush-native"]
attestation = ["httpx>=0.25"]
dev = [
    "pytest>=7.0",
    "pytest-cov>=4.0",
    "pytest-asyncio>=0.21",
    "mypy>=1.5",
    "ruff>=0.1",
]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/hush"]

[tool.pytest.ini_options]
testpaths = ["tests"]
asyncio_mode = "auto"

[tool.mypy]
python_version = "3.10"
warn_return_any = true
warn_unused_ignores = true
strict = true

[tool.ruff]
target-version = "py310"
line-length = 100
select = ["E", "F", "I", "UP", "B", "SIM"]
```

**Step 3: Write src/hush/__init__.py**

```python
"""Hush Python SDK for clawdstrike security verification."""

from hush.core import sha256, keccak256, verify_signature
from hush.receipt import Receipt, SignedReceipt, Verdict

__version__ = "0.1.0"
__all__ = [
    "sha256",
    "keccak256",
    "verify_signature",
    "Receipt",
    "SignedReceipt",
    "Verdict",
    "__version__",
]
```

**Step 4: Create py.typed marker**

```bash
touch packages/hush-py/src/hush/py.typed
```

**Step 5: Commit**

```bash
git add packages/hush-py/
git commit -m "feat(hush-py): add package structure and pyproject.toml"
```

---

## Task 2: Core Cryptographic Primitives

**Files:**
- Create: `packages/hush-py/src/hush/core.py`
- Create: `packages/hush-py/tests/test_core.py`

**Step 1: Write the failing test**

```python
# packages/hush-py/tests/test_core.py
"""Tests for core cryptographic primitives."""

import pytest
from nacl.signing import SigningKey


class TestSha256:
    def test_hash_bytes(self):
        from hush.core import sha256
        result = sha256(b"hello")
        assert isinstance(result, bytes)
        assert len(result) == 32
        # Known SHA-256 hash of "hello"
        assert result.hex() == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

    def test_hash_string(self):
        from hush.core import sha256
        result = sha256("hello")
        assert result.hex() == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

    def test_hash_empty(self):
        from hush.core import sha256
        result = sha256(b"")
        # SHA-256 of empty string
        assert result.hex() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


class TestKeccak256:
    def test_hash_bytes(self):
        from hush.core import keccak256
        result = keccak256(b"hello")
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_hash_string(self):
        from hush.core import keccak256
        result = keccak256("hello")
        assert isinstance(result, bytes)


class TestSignature:
    def test_verify_valid_signature(self):
        from hush.core import verify_signature

        key = SigningKey.generate()
        message = b"test message"
        signature = key.sign(message).signature
        public_key = bytes(key.verify_key)

        assert verify_signature(message, signature, public_key) is True

    def test_verify_invalid_signature(self):
        from hush.core import verify_signature

        key = SigningKey.generate()
        wrong_key = SigningKey.generate()
        message = b"test message"
        signature = key.sign(message).signature
        public_key = bytes(wrong_key.verify_key)

        assert verify_signature(message, signature, public_key) is False

    def test_verify_tampered_message(self):
        from hush.core import verify_signature

        key = SigningKey.generate()
        message = b"test message"
        signature = key.sign(message).signature
        public_key = bytes(key.verify_key)

        assert verify_signature(b"tampered", signature, public_key) is False


class TestHash:
    def test_from_hex(self):
        from hush.core import Hash
        h = Hash.from_hex("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        assert len(h.bytes) == 32

    def test_from_hex_with_prefix(self):
        from hush.core import Hash
        h = Hash.from_hex("0x2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        assert len(h.bytes) == 32

    def test_to_hex(self):
        from hush.core import Hash
        h = Hash.from_hex("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        assert h.to_hex() == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

    def test_to_hex_prefixed(self):
        from hush.core import Hash
        h = Hash.from_hex("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        assert h.to_hex_prefixed() == "0x2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

    def test_zero(self):
        from hush.core import Hash
        h = Hash.zero()
        assert h.bytes == b"\x00" * 32

    def test_from_data(self):
        from hush.core import Hash
        h = Hash.from_data(b"hello")
        assert h.to_hex() == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
```

**Step 2: Run test to verify it fails**

```bash
cd packages/hush-py && python -m pytest tests/test_core.py -v
```
Expected: FAIL with "ModuleNotFoundError: No module named 'hush.core'"

**Step 3: Write minimal implementation**

```python
# packages/hush-py/src/hush/core.py
"""Pure Python cryptographic primitives."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Union

from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError


def sha256(data: Union[bytes, str]) -> bytes:
    """Compute SHA-256 hash."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).digest()


def keccak256(data: Union[bytes, str]) -> bytes:
    """Compute Keccak-256 hash (Ethereum-style)."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    # Note: sha3_256 in hashlib is actually Keccak-256
    return hashlib.new("sha3_256", data).digest()


def verify_signature(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify Ed25519 signature."""
    try:
        vk = VerifyKey(public_key)
        vk.verify(message, signature)
        return True
    except (BadSignatureError, Exception):
        return False


@dataclass
class Hash:
    """32-byte hash value with hex encoding support."""

    bytes: bytes

    def __post_init__(self) -> None:
        if len(self.bytes) != 32:
            raise ValueError(f"Hash must be 32 bytes, got {len(self.bytes)}")

    @classmethod
    def from_hex(cls, hex_str: str) -> "Hash":
        """Create from hex string (with or without 0x prefix)."""
        hex_str = hex_str.removeprefix("0x")
        return cls(bytes=bytes.fromhex(hex_str))

    @classmethod
    def from_data(cls, data: bytes) -> "Hash":
        """Create by hashing data with SHA-256."""
        return cls(bytes=sha256(data))

    @classmethod
    def zero(cls) -> "Hash":
        """Create a zero hash."""
        return cls(bytes=b"\x00" * 32)

    def to_hex(self) -> str:
        """Return hex string without prefix."""
        return self.bytes.hex()

    def to_hex_prefixed(self) -> str:
        """Return hex string with 0x prefix."""
        return "0x" + self.bytes.hex()

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Hash):
            return self.bytes == other.bytes
        return False

    def __hash__(self) -> int:
        return hash(self.bytes)


__all__ = ["sha256", "keccak256", "verify_signature", "Hash"]
```

**Step 4: Run test to verify it passes**

```bash
cd packages/hush-py && python -m pytest tests/test_core.py -v
```
Expected: PASS

**Step 5: Commit**

```bash
git add packages/hush-py/src/hush/core.py packages/hush-py/tests/test_core.py
git commit -m "feat(hush-py): add core cryptographic primitives"
```

---

## Task 3: Canonical JSON Implementation

**Files:**
- Create: `packages/hush-py/src/hush/canonical.py`
- Create: `packages/hush-py/tests/test_canonical.py`

**Step 1: Write the failing test**

```python
# packages/hush-py/tests/test_canonical.py
"""Tests for canonical JSON encoding (RFC 8785 JCS)."""

import pytest


class TestCanonicalize:
    def test_simple_object(self):
        from hush.canonical import canonicalize
        result = canonicalize({"b": 1, "a": 2})
        assert result == '{"a":2,"b":1}'

    def test_nested_object(self):
        from hush.canonical import canonicalize
        result = canonicalize({"z": {"b": 1, "a": 2}, "y": 3})
        assert result == '{"y":3,"z":{"a":2,"b":1}}'

    def test_array(self):
        from hush.canonical import canonicalize
        result = canonicalize([3, 1, 2])
        assert result == "[3,1,2]"

    def test_null(self):
        from hush.canonical import canonicalize
        assert canonicalize(None) == "null"

    def test_boolean(self):
        from hush.canonical import canonicalize
        assert canonicalize(True) == "true"
        assert canonicalize(False) == "false"

    def test_integer(self):
        from hush.canonical import canonicalize
        assert canonicalize(42) == "42"
        assert canonicalize(-17) == "-17"

    def test_float_simple(self):
        from hush.canonical import canonicalize
        assert canonicalize(3.14) == "3.14"

    def test_float_zero(self):
        from hush.canonical import canonicalize
        assert canonicalize(0.0) == "0"
        assert canonicalize(-0.0) == "0"

    def test_string_simple(self):
        from hush.canonical import canonicalize
        assert canonicalize("hello") == '"hello"'

    def test_string_escaping(self):
        from hush.canonical import canonicalize
        assert canonicalize("a\"b") == '"a\\"b"'
        assert canonicalize("a\\b") == '"a\\\\b"'
        assert canonicalize("a\nb") == '"a\\nb"'
        assert canonicalize("a\tb") == '"a\\tb"'

    def test_control_characters(self):
        from hush.canonical import canonicalize
        # Control character U+001F should be escaped as \u001f
        assert canonicalize("\x1f") == '"\\u001f"'

    def test_deterministic(self):
        from hush.canonical import canonicalize
        obj = {"c": 3, "a": 1, "b": 2}
        result1 = canonicalize(obj)
        result2 = canonicalize(obj)
        assert result1 == result2

    def test_unsupported_type_raises(self):
        from hush.canonical import canonicalize, CanonicalJsonError
        with pytest.raises(CanonicalJsonError):
            canonicalize(object())

    def test_non_string_key_raises(self):
        from hush.canonical import canonicalize, CanonicalJsonError
        with pytest.raises(CanonicalJsonError):
            canonicalize({1: "value"})

    def test_non_finite_float_raises(self):
        from hush.canonical import canonicalize, CanonicalJsonError
        import math
        with pytest.raises(CanonicalJsonError):
            canonicalize(math.inf)
        with pytest.raises(CanonicalJsonError):
            canonicalize(math.nan)
```

**Step 2: Run test to verify it fails**

```bash
cd packages/hush-py && python -m pytest tests/test_canonical.py -v
```
Expected: FAIL with "ModuleNotFoundError"

**Step 3: Write minimal implementation**

```python
# packages/hush-py/src/hush/canonical.py
"""Canonical JSON for hashing/signatures (RFC 8785 JCS).

Implements CCJ v1 (RFC 8785 JSON Canonicalization Scheme) for the
subset of Python values that map cleanly to JSON:

- dict (string keys), list/tuple
- str, int, float, bool, None

Matches ECMAScript JSON.stringify() number formatting and string escaping,
so hashes and Ed25519 signatures verify across Python/Rust/TypeScript.
"""

from __future__ import annotations

import math
from typing import Any


class CanonicalJsonError(ValueError):
    """Error during canonical JSON encoding."""
    pass


def canonicalize(value: Any) -> str:
    """Return RFC 8785 canonical JSON for value."""
    return _canon(value)


def _canon(value: Any) -> str:
    if value is None:
        return "null"

    # bool is a subclass of int in Python; check it first.
    if isinstance(value, bool):
        return "true" if value else "false"

    if isinstance(value, int):
        return str(value)

    if isinstance(value, float):
        return _js_number_string(value)

    if isinstance(value, str):
        return '"' + _escape_json_string(value) + '"'

    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_canon(v) for v in value) + "]"

    if isinstance(value, dict):
        items: list[str] = []
        for k in sorted(value.keys()):
            if not isinstance(k, str):
                raise CanonicalJsonError("JSON object keys must be strings")
            items.append('"' + _escape_json_string(k) + '":' + _canon(value[k]))
        return "{" + ",".join(items) + "}"

    raise CanonicalJsonError(f"Unsupported type for canonical JSON: {type(value)!r}")


def _escape_json_string(s: str) -> str:
    """Escape string for JSON (JCS aligns with ECMAScript JSON.stringify)."""
    out: list[str] = []
    for ch in s:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif code == 0x08:
            out.append("\\b")
        elif code == 0x0C:
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif code <= 0x1F:
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    return "".join(out)


def _js_number_string(x: float) -> str:
    """ECMAScript JSON.stringify() number string for finite doubles."""
    if not math.isfinite(x):
        raise CanonicalJsonError("Non-finite numbers are not valid JSON")

    if x == 0.0:
        # Normalize -0 to 0.
        return "0"

    sign = "-" if math.copysign(1.0, x) < 0 else ""
    x_abs = abs(x)

    use_exp = x_abs >= 1e21 or x_abs < 1e-6

    digits, sci_exp = _scientific_parts_from_repr(repr(x_abs))

    if not use_exp:
        rendered = _render_decimal(digits, sci_exp)
        return sign + rendered

    if len(digits) == 1:
        mantissa = digits
    else:
        mantissa = digits[0] + "." + digits[1:]

    exp_sign = "+" if sci_exp >= 0 else ""
    return f"{sign}{mantissa}e{exp_sign}{sci_exp}"


def _scientific_parts_from_repr(s: str) -> tuple[str, int]:
    """Parse Python's float repr() into (digits, scientific_exponent)."""
    s = s.strip().lower()
    if "e" in s:
        mantissa, exp_str = s.split("e", 1)
        exp = int(exp_str)
        if "." in mantissa:
            a, b = mantissa.split(".", 1)
            digits = a + b
        else:
            digits = mantissa
        digits = digits.lstrip("0") or "0"
        digits = digits.rstrip("0") or "0"
        return digits, exp

    # Decimal form.
    if "." in s:
        int_part, frac_part = s.split(".", 1)
    else:
        int_part, frac_part = s, ""

    frac_part = frac_part.rstrip("0")
    int_stripped = int_part.lstrip("0")

    if int_stripped:
        digits = int_stripped + frac_part
        sci_exp = len(int_stripped) - 1
    else:
        # number < 1
        leading_zeros = 0
        while leading_zeros < len(frac_part) and frac_part[leading_zeros] == "0":
            leading_zeros += 1
        digits = frac_part[leading_zeros:]
        sci_exp = -(leading_zeros + 1)

    digits = digits.lstrip("0") or "0"
    digits = digits.rstrip("0") or "0"
    return digits, sci_exp


def _render_decimal(digits: str, sci_exp: int) -> str:
    """Render number in decimal notation."""
    digits_len = len(digits)
    shift = sci_exp - (digits_len - 1)

    if shift >= 0:
        return digits + ("0" * shift)

    pos = digits_len + shift
    if pos > 0:
        out = digits[:pos] + "." + digits[pos:]
    else:
        out = "0." + ("0" * (-pos)) + digits

    if "." in out:
        out = out.rstrip("0").rstrip(".")
    return out


__all__ = ["CanonicalJsonError", "canonicalize"]
```

**Step 4: Run test to verify it passes**

```bash
cd packages/hush-py && python -m pytest tests/test_canonical.py -v
```
Expected: PASS

**Step 5: Commit**

```bash
git add packages/hush-py/src/hush/canonical.py packages/hush-py/tests/test_canonical.py
git commit -m "feat(hush-py): add canonical JSON encoding (RFC 8785)"
```

---

## Task 4: Receipt Types

**Files:**
- Create: `packages/hush-py/src/hush/receipt.py`
- Create: `packages/hush-py/tests/test_receipt.py`

**Step 1: Write the failing test**

```python
# packages/hush-py/tests/test_receipt.py
"""Tests for receipt types and signing."""

import pytest
from nacl.signing import SigningKey


class TestVerdict:
    def test_pass(self):
        from hush.receipt import Verdict
        v = Verdict.passing()
        assert v.passed is True
        assert v.gate_id is None

    def test_fail(self):
        from hush.receipt import Verdict
        v = Verdict.failing()
        assert v.passed is False

    def test_with_gate(self):
        from hush.receipt import Verdict
        v = Verdict.passing(gate_id="my-gate")
        assert v.gate_id == "my-gate"

    def test_to_dict(self):
        from hush.receipt import Verdict
        v = Verdict.passing(gate_id="test")
        d = v.to_dict()
        assert d["passed"] is True
        assert d["gate_id"] == "test"


class TestReceipt:
    def test_create(self):
        from hush.receipt import Receipt, Verdict
        from hush.core import Hash

        r = Receipt(
            content_hash=Hash.zero(),
            verdict=Verdict.passing(),
        )
        assert r.version == "1.0.0"
        assert r.verdict.passed is True

    def test_with_id(self):
        from hush.receipt import Receipt, Verdict
        from hush.core import Hash

        r = Receipt(
            content_hash=Hash.zero(),
            verdict=Verdict.passing(),
        ).with_id("test-001")
        assert r.receipt_id == "test-001"

    def test_canonical_json(self):
        from hush.receipt import Receipt, Verdict
        from hush.core import Hash

        r = Receipt(
            content_hash=Hash.zero(),
            verdict=Verdict.passing(),
            timestamp="2026-01-01T00:00:00Z",
        )
        json1 = r.to_canonical_json()
        json2 = r.to_canonical_json()
        assert json1 == json2
        assert '"content_hash"' in json1
        assert '"verdict"' in json1

    def test_hash_sha256(self):
        from hush.receipt import Receipt, Verdict
        from hush.core import Hash

        r = Receipt(
            content_hash=Hash.zero(),
            verdict=Verdict.passing(),
            timestamp="2026-01-01T00:00:00Z",
        )
        h = r.hash_sha256()
        assert isinstance(h, Hash)
        assert len(h.bytes) == 32


class TestSignedReceipt:
    def test_sign_and_verify(self):
        from hush.receipt import Receipt, SignedReceipt, Verdict
        from hush.core import Hash

        key = SigningKey.generate()
        r = Receipt(
            content_hash=Hash.zero(),
            verdict=Verdict.passing(),
            timestamp="2026-01-01T00:00:00Z",
        )

        signed = SignedReceipt.sign(r, key)
        result = signed.verify(bytes(key.verify_key))

        assert result.valid is True
        assert result.signer_valid is True

    def test_wrong_key_fails(self):
        from hush.receipt import Receipt, SignedReceipt, Verdict
        from hush.core import Hash

        key = SigningKey.generate()
        wrong_key = SigningKey.generate()
        r = Receipt(
            content_hash=Hash.zero(),
            verdict=Verdict.passing(),
            timestamp="2026-01-01T00:00:00Z",
        )

        signed = SignedReceipt.sign(r, key)
        result = signed.verify(bytes(wrong_key.verify_key))

        assert result.valid is False
        assert "Invalid signer signature" in result.errors

    def test_json_roundtrip(self):
        from hush.receipt import Receipt, SignedReceipt, Verdict
        from hush.core import Hash

        key = SigningKey.generate()
        r = Receipt(
            content_hash=Hash.zero(),
            verdict=Verdict.passing(),
            timestamp="2026-01-01T00:00:00Z",
        )

        signed = SignedReceipt.sign(r, key)
        json_str = signed.to_json()
        restored = SignedReceipt.from_json(json_str)

        result = restored.verify(bytes(key.verify_key))
        assert result.valid is True
```

**Step 2: Run test to verify it fails**

```bash
cd packages/hush-py && python -m pytest tests/test_receipt.py -v
```
Expected: FAIL

**Step 3: Write minimal implementation**

```python
# packages/hush-py/src/hush/receipt.py
"""Receipt types and signing for attestation."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from nacl.signing import SigningKey

from hush.canonical import canonicalize
from hush.core import Hash, sha256, keccak256, verify_signature


@dataclass
class Verdict:
    """Verdict result from quality gates or guards."""

    passed: bool
    gate_id: Optional[str] = None
    scores: Optional[dict[str, Any]] = None
    threshold: Optional[float] = None

    @classmethod
    def passing(cls, gate_id: Optional[str] = None) -> "Verdict":
        """Create a passing verdict."""
        return cls(passed=True, gate_id=gate_id)

    @classmethod
    def failing(cls, gate_id: Optional[str] = None) -> "Verdict":
        """Create a failing verdict."""
        return cls(passed=False, gate_id=gate_id)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        result: dict[str, Any] = {"passed": self.passed}
        if self.gate_id is not None:
            result["gate_id"] = self.gate_id
        if self.scores is not None:
            result["scores"] = self.scores
        if self.threshold is not None:
            result["threshold"] = self.threshold
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Verdict":
        """Create from dictionary."""
        return cls(
            passed=data["passed"],
            gate_id=data.get("gate_id"),
            scores=data.get("scores"),
            threshold=data.get("threshold"),
        )


@dataclass
class ViolationRef:
    """Violation reference from a guard."""

    guard: str
    severity: str
    message: str
    action: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        result: dict[str, Any] = {
            "guard": self.guard,
            "severity": self.severity,
            "message": self.message,
        }
        if self.action is not None:
            result["action"] = self.action
        return result


@dataclass
class Provenance:
    """Provenance information about execution environment."""

    clawdstrike_version: Optional[str] = None
    provider: Optional[str] = None
    policy_hash: Optional[Hash] = None
    ruleset: Optional[str] = None
    violations: list[ViolationRef] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        result: dict[str, Any] = {}
        if self.clawdstrike_version is not None:
            result["clawdstrike_version"] = self.clawdstrike_version
        if self.provider is not None:
            result["provider"] = self.provider
        if self.policy_hash is not None:
            result["policy_hash"] = self.policy_hash.to_hex_prefixed()
        if self.ruleset is not None:
            result["ruleset"] = self.ruleset
        if self.violations:
            result["violations"] = [v.to_dict() for v in self.violations]
        return result


@dataclass
class Receipt:
    """Receipt for an attested execution (unsigned)."""

    content_hash: Hash
    verdict: Verdict
    version: str = "1.0.0"
    receipt_id: Optional[str] = None
    timestamp: Optional[str] = None
    provenance: Optional[Provenance] = None
    metadata: Optional[dict[str, Any]] = None

    def __post_init__(self) -> None:
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def with_id(self, receipt_id: str) -> "Receipt":
        """Set receipt ID."""
        self.receipt_id = receipt_id
        return self

    def with_provenance(self, provenance: Provenance) -> "Receipt":
        """Set provenance."""
        self.provenance = provenance
        return self

    def with_metadata(self, metadata: dict[str, Any]) -> "Receipt":
        """Set metadata."""
        self.metadata = metadata
        return self

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        result: dict[str, Any] = {
            "version": self.version,
            "timestamp": self.timestamp,
            "content_hash": self.content_hash.to_hex_prefixed(),
            "verdict": self.verdict.to_dict(),
        }
        if self.receipt_id is not None:
            result["receipt_id"] = self.receipt_id
        if self.provenance is not None:
            result["provenance"] = self.provenance.to_dict()
        if self.metadata is not None:
            result["metadata"] = self.metadata
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Receipt":
        """Create from dictionary."""
        provenance = None
        if "provenance" in data:
            prov_data = data["provenance"]
            provenance = Provenance(
                clawdstrike_version=prov_data.get("clawdstrike_version"),
                provider=prov_data.get("provider"),
                policy_hash=Hash.from_hex(prov_data["policy_hash"]) if prov_data.get("policy_hash") else None,
                ruleset=prov_data.get("ruleset"),
            )

        return cls(
            version=data.get("version", "1.0.0"),
            receipt_id=data.get("receipt_id"),
            timestamp=data.get("timestamp"),
            content_hash=Hash.from_hex(data["content_hash"]),
            verdict=Verdict.from_dict(data["verdict"]),
            provenance=provenance,
            metadata=data.get("metadata"),
        )

    def to_canonical_json(self) -> str:
        """Serialize to canonical JSON (sorted keys, no extra whitespace)."""
        return canonicalize(self.to_dict())

    def hash_sha256(self) -> Hash:
        """Compute SHA-256 hash of canonical JSON."""
        canonical = self.to_canonical_json()
        return Hash(bytes=sha256(canonical.encode("utf-8")))

    def hash_keccak256(self) -> Hash:
        """Compute Keccak-256 hash of canonical JSON (for Ethereum)."""
        canonical = self.to_canonical_json()
        return Hash(bytes=keccak256(canonical.encode("utf-8")))


@dataclass
class Signature:
    """Ed25519 signature with public key."""

    signature: bytes
    public_key: bytes

    def to_dict(self) -> dict[str, str]:
        """Convert to dictionary."""
        return {
            "signature": self.signature.hex(),
            "public_key": self.public_key.hex(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> "Signature":
        """Create from dictionary."""
        return cls(
            signature=bytes.fromhex(data["signature"]),
            public_key=bytes.fromhex(data["public_key"]),
        )


@dataclass
class Signatures:
    """Signatures on a receipt."""

    signer: Signature
    cosigner: Optional[Signature] = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        result: dict[str, Any] = {"signer": self.signer.to_dict()}
        if self.cosigner is not None:
            result["cosigner"] = self.cosigner.to_dict()
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Signatures":
        """Create from dictionary."""
        return cls(
            signer=Signature.from_dict(data["signer"]),
            cosigner=Signature.from_dict(data["cosigner"]) if data.get("cosigner") else None,
        )


@dataclass
class VerificationResult:
    """Result of receipt verification."""

    valid: bool
    signer_valid: bool
    cosigner_valid: Optional[bool] = None
    errors: list[str] = field(default_factory=list)


@dataclass
class SignedReceipt:
    """Signed receipt."""

    receipt: Receipt
    signatures: Signatures

    @classmethod
    def sign(cls, receipt: Receipt, signing_key: SigningKey) -> "SignedReceipt":
        """Sign a receipt."""
        canonical = receipt.to_canonical_json()
        signed = signing_key.sign(canonical.encode("utf-8"))

        return cls(
            receipt=receipt,
            signatures=Signatures(
                signer=Signature(
                    signature=signed.signature,
                    public_key=bytes(signing_key.verify_key),
                )
            ),
        )

    def add_cosigner(self, signing_key: SigningKey) -> None:
        """Add co-signer signature."""
        canonical = self.receipt.to_canonical_json()
        signed = signing_key.sign(canonical.encode("utf-8"))
        self.signatures.cosigner = Signature(
            signature=signed.signature,
            public_key=bytes(signing_key.verify_key),
        )

    def verify(self, public_key: bytes, cosigner_public_key: Optional[bytes] = None) -> VerificationResult:
        """Verify signatures."""
        result = VerificationResult(valid=True, signer_valid=False)

        try:
            canonical = self.receipt.to_canonical_json()
            message = canonical.encode("utf-8")
        except Exception as e:
            return VerificationResult(
                valid=False,
                signer_valid=False,
                errors=[f"Failed to serialize receipt: {e}"],
            )

        # Verify primary signature
        result.signer_valid = verify_signature(
            message,
            self.signatures.signer.signature,
            public_key,
        )
        if not result.signer_valid:
            result.valid = False
            result.errors.append("Invalid signer signature")

        # Verify co-signer if present
        if self.signatures.cosigner is not None and cosigner_public_key is not None:
            cosigner_valid = verify_signature(
                message,
                self.signatures.cosigner.signature,
                cosigner_public_key,
            )
            result.cosigner_valid = cosigner_valid
            if not cosigner_valid:
                result.valid = False
                result.errors.append("Invalid cosigner signature")

        return result

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "receipt": self.receipt.to_dict(),
            "signatures": self.signatures.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SignedReceipt":
        """Create from dictionary."""
        return cls(
            receipt=Receipt.from_dict(data["receipt"]),
            signatures=Signatures.from_dict(data["signatures"]),
        )

    def to_json(self) -> str:
        """Serialize to JSON."""
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_json(cls, json_str: str) -> "SignedReceipt":
        """Parse from JSON."""
        return cls.from_dict(json.loads(json_str))


__all__ = [
    "Verdict",
    "ViolationRef",
    "Provenance",
    "Receipt",
    "Signature",
    "Signatures",
    "SignedReceipt",
    "VerificationResult",
]
```

**Step 4: Run test to verify it passes**

```bash
cd packages/hush-py && python -m pytest tests/test_receipt.py -v
```
Expected: PASS

**Step 5: Commit**

```bash
git add packages/hush-py/src/hush/receipt.py packages/hush-py/tests/test_receipt.py
git commit -m "feat(hush-py): add receipt types and signing"
```

---

## Task 5: Guard Base Classes

**Files:**
- Create: `packages/hush-py/src/hush/guards/__init__.py`
- Create: `packages/hush-py/src/hush/guards/base.py`
- Create: `packages/hush-py/tests/test_guards_base.py`

**Step 1: Write the failing test**

```python
# packages/hush-py/tests/test_guards_base.py
"""Tests for guard base classes."""

import pytest


class TestSeverity:
    def test_values(self):
        from hush.guards.base import Severity
        assert Severity.INFO.value == "info"
        assert Severity.WARNING.value == "warning"
        assert Severity.ERROR.value == "error"
        assert Severity.CRITICAL.value == "critical"


class TestGuardResult:
    def test_allow(self):
        from hush.guards.base import GuardResult
        result = GuardResult.allow("test_guard")
        assert result.allowed is True
        assert result.guard == "test_guard"

    def test_block(self):
        from hush.guards.base import GuardResult, Severity
        result = GuardResult.block("test_guard", Severity.ERROR, "blocked")
        assert result.allowed is False
        assert result.severity == Severity.ERROR

    def test_warn(self):
        from hush.guards.base import GuardResult, Severity
        result = GuardResult.warn("test_guard", "warning message")
        assert result.allowed is True
        assert result.severity == Severity.WARNING

    def test_with_details(self):
        from hush.guards.base import GuardResult
        result = GuardResult.allow("test").with_details({"path": "/etc"})
        assert result.details == {"path": "/etc"}

    def test_to_dict(self):
        from hush.guards.base import GuardResult
        result = GuardResult.allow("test")
        d = result.to_dict()
        assert d["allowed"] is True
        assert d["guard"] == "test"


class TestGuardContext:
    def test_default(self):
        from hush.guards.base import GuardContext
        ctx = GuardContext()
        assert ctx.cwd is None
        assert ctx.session_id is None

    def test_with_cwd(self):
        from hush.guards.base import GuardContext
        ctx = GuardContext().with_cwd("/app")
        assert ctx.cwd == "/app"

    def test_with_session_id(self):
        from hush.guards.base import GuardContext
        ctx = GuardContext().with_session_id("session-123")
        assert ctx.session_id == "session-123"


class TestGuardAction:
    def test_file_access(self):
        from hush.guards.base import GuardAction
        action = GuardAction.file_access("/etc/passwd")
        assert action.action_type == "file_access"
        assert action.path == "/etc/passwd"

    def test_file_write(self):
        from hush.guards.base import GuardAction
        action = GuardAction.file_write("/app/data.txt", b"content")
        assert action.action_type == "file_write"
        assert action.content == b"content"

    def test_network_egress(self):
        from hush.guards.base import GuardAction
        action = GuardAction.network_egress("api.example.com", 443)
        assert action.action_type == "network_egress"
        assert action.host == "api.example.com"
        assert action.port == 443

    def test_mcp_tool(self):
        from hush.guards.base import GuardAction
        action = GuardAction.mcp_tool("read_file", {"path": "/app"})
        assert action.action_type == "mcp_tool"
        assert action.tool_name == "read_file"
```

**Step 2: Run test to verify it fails**

```bash
cd packages/hush-py && python -m pytest tests/test_guards_base.py -v
```
Expected: FAIL

**Step 3: Write minimal implementation**

```python
# packages/hush-py/src/hush/guards/__init__.py
"""Security guards for AI agent execution."""

from hush.guards.base import (
    Severity,
    GuardResult,
    GuardContext,
    GuardAction,
    Guard,
)

__all__ = [
    "Severity",
    "GuardResult",
    "GuardContext",
    "GuardAction",
    "Guard",
]
```

```python
# packages/hush-py/src/hush/guards/base.py
"""Base classes for security guards."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    """Severity level for violations."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class GuardResult:
    """Result of a guard check."""

    allowed: bool
    guard: str
    severity: Severity
    message: str
    details: Optional[dict[str, Any]] = None

    @classmethod
    def allow(cls, guard: str) -> "GuardResult":
        """Create an allow result."""
        return cls(
            allowed=True,
            guard=guard,
            severity=Severity.INFO,
            message="Allowed",
        )

    @classmethod
    def block(cls, guard: str, severity: Severity, message: str) -> "GuardResult":
        """Create a block result."""
        return cls(
            allowed=False,
            guard=guard,
            severity=severity,
            message=message,
        )

    @classmethod
    def warn(cls, guard: str, message: str) -> "GuardResult":
        """Create a warning result (allowed but logged)."""
        return cls(
            allowed=True,
            guard=guard,
            severity=Severity.WARNING,
            message=message,
        )

    def with_details(self, details: dict[str, Any]) -> "GuardResult":
        """Add details to the result."""
        self.details = details
        return self

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        result: dict[str, Any] = {
            "allowed": self.allowed,
            "guard": self.guard,
            "severity": self.severity.value,
            "message": self.message,
        }
        if self.details is not None:
            result["details"] = self.details
        return result


@dataclass
class GuardContext:
    """Context passed to guards for evaluation."""

    cwd: Optional[str] = None
    session_id: Optional[str] = None
    agent_id: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None

    def with_cwd(self, cwd: str) -> "GuardContext":
        """Set the working directory."""
        self.cwd = cwd
        return self

    def with_session_id(self, session_id: str) -> "GuardContext":
        """Set the session ID."""
        self.session_id = session_id
        return self

    def with_agent_id(self, agent_id: str) -> "GuardContext":
        """Set the agent ID."""
        self.agent_id = agent_id
        return self


@dataclass
class GuardAction:
    """Action to be checked by guards."""

    action_type: str
    path: Optional[str] = None
    content: Optional[bytes] = None
    host: Optional[str] = None
    port: Optional[int] = None
    tool_name: Optional[str] = None
    tool_args: Optional[dict[str, Any]] = None
    command: Optional[str] = None
    diff: Optional[str] = None
    custom_data: Optional[dict[str, Any]] = None

    @classmethod
    def file_access(cls, path: str) -> "GuardAction":
        """Create a file access action."""
        return cls(action_type="file_access", path=path)

    @classmethod
    def file_write(cls, path: str, content: bytes) -> "GuardAction":
        """Create a file write action."""
        return cls(action_type="file_write", path=path, content=content)

    @classmethod
    def network_egress(cls, host: str, port: int) -> "GuardAction":
        """Create a network egress action."""
        return cls(action_type="network_egress", host=host, port=port)

    @classmethod
    def shell_command(cls, command: str) -> "GuardAction":
        """Create a shell command action."""
        return cls(action_type="shell_command", command=command)

    @classmethod
    def mcp_tool(cls, tool_name: str, args: dict[str, Any]) -> "GuardAction":
        """Create an MCP tool invocation action."""
        return cls(action_type="mcp_tool", tool_name=tool_name, tool_args=args)

    @classmethod
    def patch(cls, path: str, diff: str) -> "GuardAction":
        """Create a patch application action."""
        return cls(action_type="patch", path=path, diff=diff)

    @classmethod
    def custom(cls, action_type: str, data: dict[str, Any]) -> "GuardAction":
        """Create a custom action."""
        return cls(action_type=action_type, custom_data=data)


class Guard(ABC):
    """Base class for security guards."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the guard."""
        ...

    @abstractmethod
    def handles(self, action: GuardAction) -> bool:
        """Check if this guard handles the given action type."""
        ...

    @abstractmethod
    def check(self, action: GuardAction, context: GuardContext) -> GuardResult:
        """Evaluate the action."""
        ...


__all__ = [
    "Severity",
    "GuardResult",
    "GuardContext",
    "GuardAction",
    "Guard",
]
```

**Step 4: Run test to verify it passes**

```bash
cd packages/hush-py && python -m pytest tests/test_guards_base.py -v
```
Expected: PASS

**Step 5: Commit**

```bash
git add packages/hush-py/src/hush/guards/
git add packages/hush-py/tests/test_guards_base.py
git commit -m "feat(hush-py): add guard base classes"
```

---

## Task 6: Forbidden Path Guard

**Files:**
- Create: `packages/hush-py/src/hush/guards/forbidden_path.py`
- Create: `packages/hush-py/tests/test_guards_forbidden_path.py`

**Step 1: Write the failing test**

```python
# packages/hush-py/tests/test_guards_forbidden_path.py
"""Tests for forbidden path guard."""

import pytest


class TestForbiddenPathConfig:
    def test_default_patterns(self):
        from hush.guards.forbidden_path import ForbiddenPathConfig
        config = ForbiddenPathConfig()
        assert len(config.patterns) > 0
        assert "**/.ssh/**" in config.patterns

    def test_custom_patterns(self):
        from hush.guards.forbidden_path import ForbiddenPathConfig
        config = ForbiddenPathConfig(patterns=["**/secret/**"])
        assert config.patterns == ["**/secret/**"]


class TestForbiddenPathGuard:
    def test_default_forbidden_paths(self):
        from hush.guards.forbidden_path import ForbiddenPathGuard
        guard = ForbiddenPathGuard()

        # SSH keys
        assert guard.is_forbidden("/home/user/.ssh/id_rsa") is True
        assert guard.is_forbidden("/home/user/.ssh/authorized_keys") is True

        # AWS credentials
        assert guard.is_forbidden("/home/user/.aws/credentials") is True

        # Environment files
        assert guard.is_forbidden("/app/.env") is True
        assert guard.is_forbidden("/app/.env.local") is True

        # Normal files should be allowed
        assert guard.is_forbidden("/app/src/main.rs") is False
        assert guard.is_forbidden("/home/user/project/README.md") is False

    def test_exceptions(self):
        from hush.guards.forbidden_path import ForbiddenPathGuard, ForbiddenPathConfig
        config = ForbiddenPathConfig(
            patterns=["**/.env"],
            exceptions=["**/project/.env"],
        )
        guard = ForbiddenPathGuard(config)

        assert guard.is_forbidden("/app/.env") is True
        assert guard.is_forbidden("/app/project/.env") is False

    def test_check_file_access(self):
        from hush.guards.forbidden_path import ForbiddenPathGuard
        from hush.guards.base import GuardAction, GuardContext

        guard = ForbiddenPathGuard()
        context = GuardContext()

        # Forbidden path
        action = GuardAction.file_access("/home/user/.ssh/id_rsa")
        result = guard.check(action, context)
        assert result.allowed is False
        assert "forbidden" in result.message.lower()

        # Allowed path
        action = GuardAction.file_access("/app/src/main.rs")
        result = guard.check(action, context)
        assert result.allowed is True

    def test_check_file_write(self):
        from hush.guards.forbidden_path import ForbiddenPathGuard
        from hush.guards.base import GuardAction, GuardContext

        guard = ForbiddenPathGuard()
        context = GuardContext()

        action = GuardAction.file_write("/home/user/.aws/credentials", b"secret")
        result = guard.check(action, context)
        assert result.allowed is False

    def test_handles_file_actions(self):
        from hush.guards.forbidden_path import ForbiddenPathGuard
        from hush.guards.base import GuardAction

        guard = ForbiddenPathGuard()

        assert guard.handles(GuardAction.file_access("/path")) is True
        assert guard.handles(GuardAction.file_write("/path", b"")) is True
        assert guard.handles(GuardAction.patch("/path", "diff")) is True
        assert guard.handles(GuardAction.network_egress("host", 80)) is False

    def test_windows_path_normalization(self):
        from hush.guards.forbidden_path import ForbiddenPathGuard
        guard = ForbiddenPathGuard()

        # Windows-style paths should be normalized
        assert guard.is_forbidden("C:\\Users\\user\\.ssh\\id_rsa") is True
```

**Step 2: Run test to verify it fails**

```bash
cd packages/hush-py && python -m pytest tests/test_guards_forbidden_path.py -v
```
Expected: FAIL

**Step 3: Write minimal implementation**

```python
# packages/hush-py/src/hush/guards/forbidden_path.py
"""Forbidden path guard - blocks access to sensitive paths."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Optional

from hush.guards.base import Guard, GuardAction, GuardContext, GuardResult, Severity


def _default_forbidden_patterns() -> list[str]:
    """Default patterns for sensitive paths."""
    return [
        # SSH keys
        "**/.ssh/**",
        "**/id_rsa*",
        "**/id_ed25519*",
        "**/id_ecdsa*",
        # AWS credentials
        "**/.aws/**",
        # Environment files
        "**/.env",
        "**/.env.*",
        # Git credentials
        "**/.git-credentials",
        "**/.gitconfig",
        # GPG keys
        "**/.gnupg/**",
        # Kubernetes
        "**/.kube/**",
        # Docker
        "**/.docker/**",
        # NPM tokens
        "**/.npmrc",
        # Password stores
        "**/.password-store/**",
        "**/pass/**",
        # 1Password
        "**/.1password/**",
        # System paths
        "/etc/shadow",
        "/etc/passwd",
        "/etc/sudoers",
    ]


@dataclass
class ForbiddenPathConfig:
    """Configuration for ForbiddenPathGuard."""

    patterns: list[str] = field(default_factory=_default_forbidden_patterns)
    exceptions: list[str] = field(default_factory=list)


class ForbiddenPathGuard(Guard):
    """Guard that blocks access to sensitive paths."""

    def __init__(self, config: Optional[ForbiddenPathConfig] = None) -> None:
        if config is None:
            config = ForbiddenPathConfig()
        self._config = config
        self._name = "forbidden_path"

    @property
    def name(self) -> str:
        return self._name

    def handles(self, action: GuardAction) -> bool:
        """Check if this guard handles the given action type."""
        return action.action_type in ("file_access", "file_write", "patch")

    def check(self, action: GuardAction, context: GuardContext) -> GuardResult:
        """Evaluate the action."""
        if not self.handles(action):
            return GuardResult.allow(self.name)

        path = action.path
        if path is None:
            return GuardResult.allow(self.name)

        if self.is_forbidden(path):
            return GuardResult.block(
                self.name,
                Severity.CRITICAL,
                f"Access to forbidden path: {path}",
            ).with_details({
                "path": path,
                "reason": "matches_forbidden_pattern",
            })

        return GuardResult.allow(self.name)

    def is_forbidden(self, path: str) -> bool:
        """Check if a path is forbidden."""
        # Normalize path (Windows -> Unix style)
        path = path.replace("\\", "/")

        # Check exceptions first
        for exception in self._config.exceptions:
            if fnmatch.fnmatch(path, exception):
                return False

        # Check forbidden patterns
        for pattern in self._config.patterns:
            if fnmatch.fnmatch(path, pattern):
                return True

        return False


__all__ = ["ForbiddenPathConfig", "ForbiddenPathGuard"]
```

**Step 4: Run test to verify it passes**

```bash
cd packages/hush-py && python -m pytest tests/test_guards_forbidden_path.py -v
```
Expected: PASS

**Step 5: Commit**

```bash
git add packages/hush-py/src/hush/guards/forbidden_path.py
git add packages/hush-py/tests/test_guards_forbidden_path.py
git commit -m "feat(hush-py): add forbidden path guard"
```

---

## Task 7: Egress Allowlist Guard

**Files:**
- Create: `packages/hush-py/src/hush/guards/egress.py`
- Create: `packages/hush-py/tests/test_guards_egress.py`

**Step 1: Write the failing test**

```python
# packages/hush-py/tests/test_guards_egress.py
"""Tests for egress allowlist guard."""

import pytest


class TestEgressConfig:
    def test_default(self):
        from hush.guards.egress import EgressConfig
        config = EgressConfig()
        assert config.default_action == "allow"

    def test_allowlist_mode(self):
        from hush.guards.egress import EgressConfig
        config = EgressConfig(
            allow=["api.example.com"],
            default_action="block",
        )
        assert "api.example.com" in config.allow


class TestEgressGuard:
    def test_allow_all_by_default(self):
        from hush.guards.egress import EgressGuard
        from hush.guards.base import GuardAction, GuardContext

        guard = EgressGuard()
        context = GuardContext()

        action = GuardAction.network_egress("api.example.com", 443)
        result = guard.check(action, context)
        assert result.allowed is True

    def test_allowlist_mode(self):
        from hush.guards.egress import EgressGuard, EgressConfig
        from hush.guards.base import GuardAction, GuardContext

        config = EgressConfig(
            allow=["api.example.com", "*.github.com"],
            default_action="block",
        )
        guard = EgressGuard(config)
        context = GuardContext()

        # Allowed domain
        action = GuardAction.network_egress("api.example.com", 443)
        result = guard.check(action, context)
        assert result.allowed is True

        # Blocked domain
        action = GuardAction.network_egress("malicious.com", 443)
        result = guard.check(action, context)
        assert result.allowed is False

    def test_subdomain_matching(self):
        from hush.guards.egress import EgressGuard, EgressConfig
        from hush.guards.base import GuardAction, GuardContext

        config = EgressConfig(
            allow=["github.com"],
            default_action="block",
        )
        guard = EgressGuard(config)
        context = GuardContext()

        # Exact match
        action = GuardAction.network_egress("github.com", 443)
        result = guard.check(action, context)
        assert result.allowed is True

        # Subdomain
        action = GuardAction.network_egress("api.github.com", 443)
        result = guard.check(action, context)
        assert result.allowed is True

        # Different domain
        action = GuardAction.network_egress("notgithub.com", 443)
        result = guard.check(action, context)
        assert result.allowed is False

    def test_block_list(self):
        from hush.guards.egress import EgressGuard, EgressConfig
        from hush.guards.base import GuardAction, GuardContext

        config = EgressConfig(
            block=["evil.com", "*.malware.net"],
            default_action="allow",
        )
        guard = EgressGuard(config)
        context = GuardContext()

        # Blocked
        action = GuardAction.network_egress("evil.com", 80)
        result = guard.check(action, context)
        assert result.allowed is False

        # Blocked subdomain
        action = GuardAction.network_egress("download.malware.net", 80)
        result = guard.check(action, context)
        assert result.allowed is False

        # Allowed
        action = GuardAction.network_egress("good.com", 443)
        result = guard.check(action, context)
        assert result.allowed is True

    def test_handles_network_actions(self):
        from hush.guards.egress import EgressGuard
        from hush.guards.base import GuardAction

        guard = EgressGuard()

        assert guard.handles(GuardAction.network_egress("host", 80)) is True
        assert guard.handles(GuardAction.file_access("/path")) is False
```

**Step 2: Run test to verify it fails**

```bash
cd packages/hush-py && python -m pytest tests/test_guards_egress.py -v
```
Expected: FAIL

**Step 3: Write minimal implementation**

```python
# packages/hush-py/src/hush/guards/egress.py
"""Egress allowlist guard - controls network access."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Optional

from hush.guards.base import Guard, GuardAction, GuardContext, GuardResult, Severity


@dataclass
class EgressConfig:
    """Configuration for EgressGuard."""

    allow: list[str] = field(default_factory=list)
    block: list[str] = field(default_factory=list)
    default_action: str = "allow"  # "allow" or "block"


class EgressGuard(Guard):
    """Guard that controls network egress."""

    def __init__(self, config: Optional[EgressConfig] = None) -> None:
        if config is None:
            config = EgressConfig()
        self._config = config
        self._name = "egress_allowlist"

    @property
    def name(self) -> str:
        return self._name

    def handles(self, action: GuardAction) -> bool:
        """Check if this guard handles the given action type."""
        return action.action_type == "network_egress"

    def check(self, action: GuardAction, context: GuardContext) -> GuardResult:
        """Evaluate the action."""
        if not self.handles(action):
            return GuardResult.allow(self.name)

        host = action.host
        if host is None:
            return GuardResult.allow(self.name)

        # Check block list first
        if self._matches_any(host, self._config.block):
            return GuardResult.block(
                self.name,
                Severity.ERROR,
                f"Destination is explicitly blocked: {host}",
            ).with_details({
                "host": host,
                "port": action.port,
            })

        # Check allow list
        if self._config.allow:
            if self._matches_any(host, self._config.allow):
                return GuardResult.allow(self.name)
            if self._config.default_action == "block":
                return GuardResult.block(
                    self.name,
                    Severity.ERROR,
                    f"Destination not in allowlist: {host}",
                ).with_details({
                    "host": host,
                    "port": action.port,
                })

        # Default action
        if self._config.default_action == "block":
            return GuardResult.block(
                self.name,
                Severity.ERROR,
                f"Network egress blocked by default: {host}",
            ).with_details({
                "host": host,
                "port": action.port,
            })

        return GuardResult.allow(self.name)

    def _matches_any(self, host: str, patterns: list[str]) -> bool:
        """Check if host matches any pattern."""
        for pattern in patterns:
            if self._matches_destination(host, pattern):
                return True
        return False

    def _matches_destination(self, host: str, pattern: str) -> bool:
        """Check if host matches pattern (supports subdomains and wildcards)."""
        if not pattern:
            return False

        # Wildcard pattern
        if pattern.startswith("*."):
            # Match subdomain
            suffix = pattern[1:]  # ".domain.com"
            return host.endswith(suffix) or host == pattern[2:]

        # Exact match
        if host == pattern:
            return True

        # Subdomain match (e.g., "api.github.com" matches "github.com")
        if host.endswith("." + pattern):
            return True

        return False


__all__ = ["EgressConfig", "EgressGuard"]
```

**Step 4: Run test to verify it passes**

```bash
cd packages/hush-py && python -m pytest tests/test_guards_egress.py -v
```
Expected: PASS

**Step 5: Commit**

```bash
git add packages/hush-py/src/hush/guards/egress.py
git add packages/hush-py/tests/test_guards_egress.py
git commit -m "feat(hush-py): add egress allowlist guard"
```

---

## Task 8: Secret Leak Guard

**Files:**
- Create: `packages/hush-py/src/hush/guards/secret_leak.py`
- Create: `packages/hush-py/tests/test_guards_secret_leak.py`

**Step 1: Write the failing test**

```python
# packages/hush-py/tests/test_guards_secret_leak.py
"""Tests for secret leak guard."""

import pytest


class TestSecretLeakGuard:
    def test_no_secrets(self):
        from hush.guards.secret_leak import SecretLeakGuard
        guard = SecretLeakGuard([])
        assert guard.contains_secret("any content") is False

    def test_detect_secret(self):
        from hush.guards.secret_leak import SecretLeakGuard
        guard = SecretLeakGuard(["supersecretkey123"])
        assert guard.contains_secret("Found the supersecretkey123 in logs") is True
        assert guard.contains_secret("No secrets here") is False

    def test_empty_secrets_ignored(self):
        from hush.guards.secret_leak import SecretLeakGuard
        guard = SecretLeakGuard(["", "  ", "valid_secret"])
        assert guard.contains_secret("valid_secret leaked") is True
        assert guard.contains_secret("no leak") is False

    def test_check_shell_output(self):
        from hush.guards.secret_leak import SecretLeakGuard
        from hush.guards.base import GuardAction, GuardContext

        guard = SecretLeakGuard(["API_KEY_12345"])
        context = GuardContext()

        # Create a custom action for shell output
        action = GuardAction.custom("bash_output", {"output": "Error: API_KEY_12345 invalid"})
        result = guard.check(action, context)
        assert result.allowed is False
        assert "secret" in result.message.lower()

    def test_check_file_write_content(self):
        from hush.guards.secret_leak import SecretLeakGuard
        from hush.guards.base import GuardAction, GuardContext

        guard = SecretLeakGuard(["mysecret"])
        context = GuardContext()

        action = GuardAction.file_write("/app/log.txt", b"mysecret was exposed")
        result = guard.check(action, context)
        assert result.allowed is False

    def test_allow_safe_content(self):
        from hush.guards.secret_leak import SecretLeakGuard
        from hush.guards.base import GuardAction, GuardContext

        guard = SecretLeakGuard(["secret123"])
        context = GuardContext()

        action = GuardAction.file_write("/app/data.txt", b"no secrets here")
        result = guard.check(action, context)
        assert result.allowed is True

    def test_handles_output_actions(self):
        from hush.guards.secret_leak import SecretLeakGuard
        from hush.guards.base import GuardAction

        guard = SecretLeakGuard(["secret"])

        assert guard.handles(GuardAction.file_write("/path", b"")) is True
        assert guard.handles(GuardAction.custom("bash_output", {})) is True
        assert guard.handles(GuardAction.custom("response_chunk", {})) is True
        assert guard.handles(GuardAction.custom("tool_result", {})) is True
        assert guard.handles(GuardAction.file_access("/path")) is False

    def test_secret_hint_in_details(self):
        from hush.guards.secret_leak import SecretLeakGuard
        from hush.guards.base import GuardAction, GuardContext

        guard = SecretLeakGuard(["longsecretvalue"])
        context = GuardContext()

        action = GuardAction.custom("bash_output", {"output": "Error: longsecretvalue"})
        result = guard.check(action, context)

        assert result.details is not None
        assert "secret_hint" in result.details
        assert result.details["secret_hint"] == "long..."
```

**Step 2: Run test to verify it fails**

```bash
cd packages/hush-py && python -m pytest tests/test_guards_secret_leak.py -v
```
Expected: FAIL

**Step 3: Write minimal implementation**

```python
# packages/hush-py/src/hush/guards/secret_leak.py
"""Secret leak guard - detects secret values in outputs."""

from __future__ import annotations

from typing import Any, Optional

from hush.guards.base import Guard, GuardAction, GuardContext, GuardResult, Severity


class SecretLeakGuard(Guard):
    """Guard that detects secret values in output streams."""

    OUTPUT_ACTIONS = {
        "file_write",
        "bash_output",
        "response_chunk",
        "response_complete",
        "tool_result",
    }

    def __init__(self, secret_values: list[str]) -> None:
        """Initialize with list of secret values to detect."""
        # Filter out empty/whitespace-only values
        self._secrets = [v for v in secret_values if v and v.strip()]
        self._name = "secret_leak"

    @property
    def name(self) -> str:
        return self._name

    def handles(self, action: GuardAction) -> bool:
        """Check if this guard handles the given action type."""
        return action.action_type in self.OUTPUT_ACTIONS

    def check(self, action: GuardAction, context: GuardContext) -> GuardResult:
        """Evaluate the action."""
        if not self._secrets:
            return GuardResult.allow(self.name)

        if not self.handles(action):
            return GuardResult.allow(self.name)

        # Extract text content
        text = self._extract_text(action)
        if not text:
            return GuardResult.allow(self.name)

        # Check for secrets
        for secret in self._secrets:
            if secret and secret in text:
                return GuardResult.block(
                    self.name,
                    Severity.CRITICAL,
                    "Secret value exposed in output",
                ).with_details({
                    "secret_hint": secret[:4] + "...",
                })

        return GuardResult.allow(self.name)

    def _extract_text(self, action: GuardAction) -> str:
        """Extract text content from action."""
        # File write content
        if action.content is not None:
            try:
                return action.content.decode("utf-8", errors="replace")
            except Exception:
                return ""

        # Custom action data
        if action.custom_data is not None:
            for key in ("output", "content", "result", "error"):
                value = action.custom_data.get(key)
                if isinstance(value, str) and value:
                    return value

        return ""

    def contains_secret(self, text: str) -> bool:
        """Check if text contains any secret value."""
        for secret in self._secrets:
            if secret and secret in text:
                return True
        return False


__all__ = ["SecretLeakGuard"]
```

**Step 4: Run test to verify it passes**

```bash
cd packages/hush-py && python -m pytest tests/test_guards_secret_leak.py -v
```
Expected: PASS

**Step 5: Commit**

```bash
git add packages/hush-py/src/hush/guards/secret_leak.py
git add packages/hush-py/tests/test_guards_secret_leak.py
git commit -m "feat(hush-py): add secret leak guard"
```

---

## Task 9: MCP Tool Guard

**Files:**
- Create: `packages/hush-py/src/hush/guards/mcp_tool.py`
- Create: `packages/hush-py/tests/test_guards_mcp_tool.py`

**Step 1: Write the failing test**

```python
# packages/hush-py/tests/test_guards_mcp_tool.py
"""Tests for MCP tool guard."""

import pytest


class TestMcpToolConfig:
    def test_default(self):
        from hush.guards.mcp_tool import McpToolConfig
        config = McpToolConfig()
        assert config.default_action == "allow"


class TestMcpToolGuard:
    def test_allow_all_by_default(self):
        from hush.guards.mcp_tool import McpToolGuard
        from hush.guards.base import GuardAction, GuardContext

        guard = McpToolGuard()
        context = GuardContext()

        action = GuardAction.mcp_tool("any_tool", {"arg": "value"})
        result = guard.check(action, context)
        assert result.allowed is True

    def test_allowlist_mode(self):
        from hush.guards.mcp_tool import McpToolGuard, McpToolConfig
        from hush.guards.base import GuardAction, GuardContext

        config = McpToolConfig(
            allow=["read_file", "list_directory"],
            default_action="block",
        )
        guard = McpToolGuard(config)
        context = GuardContext()

        # Allowed tool
        action = GuardAction.mcp_tool("read_file", {"path": "/app"})
        result = guard.check(action, context)
        assert result.allowed is True

        # Blocked tool
        action = GuardAction.mcp_tool("execute_command", {"cmd": "rm -rf"})
        result = guard.check(action, context)
        assert result.allowed is False

    def test_wildcard_matching(self):
        from hush.guards.mcp_tool import McpToolGuard, McpToolConfig
        from hush.guards.base import GuardAction, GuardContext

        config = McpToolConfig(
            allow=["file_*", "search"],
            default_action="block",
        )
        guard = McpToolGuard(config)
        context = GuardContext()

        # Matches wildcard
        action = GuardAction.mcp_tool("file_read", {})
        result = guard.check(action, context)
        assert result.allowed is True

        action = GuardAction.mcp_tool("file_write", {})
        result = guard.check(action, context)
        assert result.allowed is True

        # Exact match
        action = GuardAction.mcp_tool("search", {})
        result = guard.check(action, context)
        assert result.allowed is True

        # No match
        action = GuardAction.mcp_tool("execute", {})
        result = guard.check(action, context)
        assert result.allowed is False

    def test_block_list(self):
        from hush.guards.mcp_tool import McpToolGuard, McpToolConfig
        from hush.guards.base import GuardAction, GuardContext

        config = McpToolConfig(
            block=["dangerous_*", "system_call"],
            default_action="allow",
        )
        guard = McpToolGuard(config)
        context = GuardContext()

        # Blocked
        action = GuardAction.mcp_tool("dangerous_operation", {})
        result = guard.check(action, context)
        assert result.allowed is False

        action = GuardAction.mcp_tool("system_call", {})
        result = guard.check(action, context)
        assert result.allowed is False

        # Allowed
        action = GuardAction.mcp_tool("read_file", {})
        result = guard.check(action, context)
        assert result.allowed is True

    def test_handles_mcp_actions(self):
        from hush.guards.mcp_tool import McpToolGuard
        from hush.guards.base import GuardAction

        guard = McpToolGuard()

        assert guard.handles(GuardAction.mcp_tool("tool", {})) is True
        assert guard.handles(GuardAction.file_access("/path")) is False
```

**Step 2: Run test to verify it fails**

```bash
cd packages/hush-py && python -m pytest tests/test_guards_mcp_tool.py -v
```
Expected: FAIL

**Step 3: Write minimal implementation**

```python
# packages/hush-py/src/hush/guards/mcp_tool.py
"""MCP tool guard - controls tool invocations."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Any, Optional

from hush.guards.base import Guard, GuardAction, GuardContext, GuardResult, Severity


@dataclass
class McpToolConfig:
    """Configuration for McpToolGuard."""

    allow: list[str] = field(default_factory=list)
    block: list[str] = field(default_factory=list)
    require_confirmation: list[str] = field(default_factory=list)
    default_action: str = "allow"  # "allow" or "block"
    max_args_size: int = 10 * 1024 * 1024  # 10 MB default


class McpToolGuard(Guard):
    """Guard that controls MCP tool invocations."""

    def __init__(self, config: Optional[McpToolConfig] = None) -> None:
        if config is None:
            config = McpToolConfig()
        self._config = config
        self._name = "mcp_tool"

    @property
    def name(self) -> str:
        return self._name

    def handles(self, action: GuardAction) -> bool:
        """Check if this guard handles the given action type."""
        return action.action_type == "mcp_tool"

    def check(self, action: GuardAction, context: GuardContext) -> GuardResult:
        """Evaluate the action."""
        if not self.handles(action):
            return GuardResult.allow(self.name)

        tool_name = action.tool_name
        if tool_name is None:
            return GuardResult.allow(self.name)

        # Check block list first
        if self._matches_any(tool_name, self._config.block):
            return GuardResult.block(
                self.name,
                Severity.ERROR,
                f"Tool is blocked: {tool_name}",
            ).with_details({
                "tool": tool_name,
            })

        # Check allow list
        if self._config.allow:
            if self._matches_any(tool_name, self._config.allow):
                return GuardResult.allow(self.name)
            if self._config.default_action == "block":
                return GuardResult.block(
                    self.name,
                    Severity.ERROR,
                    f"Tool not in allowlist: {tool_name}",
                ).with_details({
                    "tool": tool_name,
                })

        # Default action
        if self._config.default_action == "block":
            return GuardResult.block(
                self.name,
                Severity.ERROR,
                f"Tool blocked by default: {tool_name}",
            ).with_details({
                "tool": tool_name,
            })

        return GuardResult.allow(self.name)

    def _matches_any(self, tool_name: str, patterns: list[str]) -> bool:
        """Check if tool name matches any pattern."""
        for pattern in patterns:
            if fnmatch.fnmatch(tool_name, pattern):
                return True
        return False


__all__ = ["McpToolConfig", "McpToolGuard"]
```

**Step 4: Run test to verify it passes**

```bash
cd packages/hush-py && python -m pytest tests/test_guards_mcp_tool.py -v
```
Expected: PASS

**Step 5: Commit**

```bash
git add packages/hush-py/src/hush/guards/mcp_tool.py
git add packages/hush-py/tests/test_guards_mcp_tool.py
git commit -m "feat(hush-py): add MCP tool guard"
```

---

## Task 10: Patch Integrity Guard

**Files:**
- Create: `packages/hush-py/src/hush/guards/patch_integrity.py`
- Create: `packages/hush-py/tests/test_guards_patch_integrity.py`

**Step 1: Write the failing test**

```python
# packages/hush-py/tests/test_guards_patch_integrity.py
"""Tests for patch integrity guard."""

import pytest


class TestPatchIntegrityConfig:
    def test_default(self):
        from hush.guards.patch_integrity import PatchIntegrityConfig
        config = PatchIntegrityConfig()
        assert config.max_additions > 0
        assert config.max_deletions > 0


class TestPatchIntegrityGuard:
    def test_allow_small_patch(self):
        from hush.guards.patch_integrity import PatchIntegrityGuard
        from hush.guards.base import GuardAction, GuardContext

        guard = PatchIntegrityGuard()
        context = GuardContext()

        diff = """
@@ -1,3 +1,4 @@
 line1
+new line
 line2
 line3
"""
        action = GuardAction.patch("/app/file.py", diff)
        result = guard.check(action, context)
        assert result.allowed is True

    def test_block_large_additions(self):
        from hush.guards.patch_integrity import PatchIntegrityGuard, PatchIntegrityConfig
        from hush.guards.base import GuardAction, GuardContext

        config = PatchIntegrityConfig(max_additions=5)
        guard = PatchIntegrityGuard(config)
        context = GuardContext()

        # Create diff with many additions
        additions = "\n".join([f"+line{i}" for i in range(10)])
        diff = f"@@ -1,1 +1,11 @@\n{additions}"

        action = GuardAction.patch("/app/file.py", diff)
        result = guard.check(action, context)
        assert result.allowed is False
        assert "additions" in result.message.lower()

    def test_block_large_deletions(self):
        from hush.guards.patch_integrity import PatchIntegrityGuard, PatchIntegrityConfig
        from hush.guards.base import GuardAction, GuardContext

        config = PatchIntegrityConfig(max_deletions=5)
        guard = PatchIntegrityGuard(config)
        context = GuardContext()

        # Create diff with many deletions
        deletions = "\n".join([f"-line{i}" for i in range(10)])
        diff = f"@@ -1,10 +1,1 @@\n{deletions}"

        action = GuardAction.patch("/app/file.py", diff)
        result = guard.check(action, context)
        assert result.allowed is False
        assert "deletions" in result.message.lower()

    def test_imbalance_check(self):
        from hush.guards.patch_integrity import PatchIntegrityGuard, PatchIntegrityConfig
        from hush.guards.base import GuardAction, GuardContext

        config = PatchIntegrityConfig(
            require_balance=True,
            max_imbalance_ratio=2.0,
            max_additions=1000,
            max_deletions=1000,
        )
        guard = PatchIntegrityGuard(config)
        context = GuardContext()

        # Many additions, few deletions (high imbalance)
        additions = "\n".join([f"+line{i}" for i in range(20)])
        deletions = "-old_line"
        diff = f"@@ -1,1 +1,21 @@\n{deletions}\n{additions}"

        action = GuardAction.patch("/app/file.py", diff)
        result = guard.check(action, context)
        assert result.allowed is False
        assert "imbalance" in result.message.lower()

    def test_count_diff_lines(self):
        from hush.guards.patch_integrity import PatchIntegrityGuard

        guard = PatchIntegrityGuard()
        diff = """
@@ -1,5 +1,6 @@
 context
+added1
+added2
-removed1
 more context
"""
        additions, deletions = guard._count_diff_lines(diff)
        assert additions == 2
        assert deletions == 1

    def test_handles_patch_actions(self):
        from hush.guards.patch_integrity import PatchIntegrityGuard
        from hush.guards.base import GuardAction

        guard = PatchIntegrityGuard()

        assert guard.handles(GuardAction.patch("/path", "diff")) is True
        assert guard.handles(GuardAction.file_access("/path")) is False
```

**Step 2: Run test to verify it fails**

```bash
cd packages/hush-py && python -m pytest tests/test_guards_patch_integrity.py -v
```
Expected: FAIL

**Step 3: Write minimal implementation**

```python
# packages/hush-py/src/hush/guards/patch_integrity.py
"""Patch integrity guard - validates patch size and balance."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from hush.guards.base import Guard, GuardAction, GuardContext, GuardResult, Severity


@dataclass
class PatchIntegrityConfig:
    """Configuration for PatchIntegrityGuard."""

    max_additions: int = 1000
    max_deletions: int = 500
    require_balance: bool = False
    max_imbalance_ratio: float = 10.0


class PatchIntegrityGuard(Guard):
    """Guard that validates patch size and balance."""

    def __init__(self, config: Optional[PatchIntegrityConfig] = None) -> None:
        if config is None:
            config = PatchIntegrityConfig()
        self._config = config
        self._name = "patch_integrity"

    @property
    def name(self) -> str:
        return self._name

    def handles(self, action: GuardAction) -> bool:
        """Check if this guard handles the given action type."""
        return action.action_type == "patch"

    def check(self, action: GuardAction, context: GuardContext) -> GuardResult:
        """Evaluate the action."""
        if not self.handles(action):
            return GuardResult.allow(self.name)

        diff = action.diff
        if diff is None:
            return GuardResult.allow(self.name)

        additions, deletions = self._count_diff_lines(diff)

        # Check additions limit
        if additions > self._config.max_additions:
            return GuardResult.block(
                self.name,
                Severity.ERROR,
                f"Too many additions: {additions} (max: {self._config.max_additions})",
            ).with_details({
                "additions": additions,
                "deletions": deletions,
                "max_additions": self._config.max_additions,
            })

        # Check deletions limit
        if deletions > self._config.max_deletions:
            return GuardResult.block(
                self.name,
                Severity.ERROR,
                f"Too many deletions: {deletions} (max: {self._config.max_deletions})",
            ).with_details({
                "additions": additions,
                "deletions": deletions,
                "max_deletions": self._config.max_deletions,
            })

        # Check balance
        if self._config.require_balance and additions > 0 and deletions > 0:
            ratio = max(additions / deletions, deletions / additions)
            if ratio > self._config.max_imbalance_ratio:
                return GuardResult.block(
                    self.name,
                    Severity.WARNING,
                    f"Patch imbalance too high: {ratio:.1f}x (max: {self._config.max_imbalance_ratio}x)",
                ).with_details({
                    "additions": additions,
                    "deletions": deletions,
                    "ratio": ratio,
                })
        elif self._config.require_balance and (additions > 0 or deletions > 0):
            # One-sided patches when balance is required
            total = additions + deletions
            if total > 10:  # Allow small one-sided patches
                ratio = total  # Treat as max imbalance
                if ratio > self._config.max_imbalance_ratio:
                    return GuardResult.block(
                        self.name,
                        Severity.WARNING,
                        f"Patch imbalance too high: one-sided with {total} lines",
                    ).with_details({
                        "additions": additions,
                        "deletions": deletions,
                    })

        return GuardResult.allow(self.name)

    def _count_diff_lines(self, diff: str) -> tuple[int, int]:
        """Count additions and deletions in a unified diff."""
        additions = 0
        deletions = 0

        for line in diff.split("\n"):
            if line.startswith("+") and not line.startswith("+++"):
                additions += 1
            elif line.startswith("-") and not line.startswith("---"):
                deletions += 1

        return additions, deletions


__all__ = ["PatchIntegrityConfig", "PatchIntegrityGuard"]
```

**Step 4: Run test to verify it passes**

```bash
cd packages/hush-py && python -m pytest tests/test_guards_patch_integrity.py -v
```
Expected: PASS

**Step 5: Commit**

```bash
git add packages/hush-py/src/hush/guards/patch_integrity.py
git add packages/hush-py/tests/test_guards_patch_integrity.py
git commit -m "feat(hush-py): add patch integrity guard"
```

---

## Task 11: Policy Engine

**Files:**
- Create: `packages/hush-py/src/hush/policy.py`
- Create: `packages/hush-py/tests/test_policy.py`

**Step 1: Write the failing test**

```python
# packages/hush-py/tests/test_policy.py
"""Tests for policy engine."""

import pytest


class TestPolicy:
    def test_default(self):
        from hush.policy import Policy
        policy = Policy()
        assert policy.version == "1.0.0"

    def test_from_yaml(self):
        from hush.policy import Policy
        yaml_content = """
version: "1.0.0"
name: "test-policy"
guards:
  forbidden_path:
    patterns:
      - "**/.env"
  egress_allowlist:
    allow:
      - "api.example.com"
    default_action: "block"
"""
        policy = Policy.from_yaml(yaml_content)
        assert policy.name == "test-policy"
        assert policy.guards.forbidden_path is not None
        assert policy.guards.egress is not None

    def test_to_yaml(self):
        from hush.policy import Policy
        policy = Policy(name="my-policy")
        yaml_str = policy.to_yaml()
        assert "version:" in yaml_str
        assert "my-policy" in yaml_str

    def test_create_guards(self):
        from hush.policy import Policy
        policy = Policy()
        guards = policy.create_guards()
        assert guards.forbidden_path is not None
        assert guards.egress is not None
        assert guards.secret_leak is not None
        assert guards.mcp_tool is not None
        assert guards.patch_integrity is not None


class TestPolicyGuards:
    def test_check_all(self):
        from hush.policy import Policy
        from hush.guards.base import GuardAction, GuardContext

        policy = Policy()
        guards = policy.create_guards()
        context = GuardContext()

        # Check allowed path
        action = GuardAction.file_access("/app/main.py")
        results = guards.check_all(action, context)
        assert all(r.allowed for r in results)

        # Check forbidden path
        action = GuardAction.file_access("/home/user/.ssh/id_rsa")
        results = guards.check_all(action, context)
        # At least one guard should block
        assert any(not r.allowed for r in results)

    def test_check_all_fail_fast(self):
        from hush.policy import Policy, PolicySettings
        from hush.guards.base import GuardAction, GuardContext

        policy = Policy(settings=PolicySettings(fail_fast=True))
        guards = policy.create_guards()
        context = GuardContext()

        action = GuardAction.file_access("/home/user/.ssh/id_rsa")
        results = guards.check_all(action, context)
        # With fail_fast, should stop at first failure
        blocked = [r for r in results if not r.allowed]
        assert len(blocked) >= 1


class TestRuleSet:
    def test_default(self):
        from hush.policy import RuleSet
        rs = RuleSet.default()
        assert rs.id == "default"

    def test_strict(self):
        from hush.policy import RuleSet
        rs = RuleSet.strict()
        assert rs.id == "strict"
        assert rs.policy.settings.fail_fast is True

    def test_permissive(self):
        from hush.policy import RuleSet
        rs = RuleSet.permissive()
        assert rs.id == "permissive"

    def test_by_name(self):
        from hush.policy import RuleSet
        assert RuleSet.by_name("default") is not None
        assert RuleSet.by_name("strict") is not None
        assert RuleSet.by_name("unknown") is None
```

**Step 2: Run test to verify it fails**

```bash
cd packages/hush-py && python -m pytest tests/test_policy.py -v
```
Expected: FAIL

**Step 3: Write minimal implementation**

```python
# packages/hush-py/src/hush/policy.py
"""Policy configuration and rulesets."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from hush.guards.base import Guard, GuardAction, GuardContext, GuardResult
from hush.guards.forbidden_path import ForbiddenPathConfig, ForbiddenPathGuard
from hush.guards.egress import EgressConfig, EgressGuard
from hush.guards.secret_leak import SecretLeakGuard
from hush.guards.mcp_tool import McpToolConfig, McpToolGuard
from hush.guards.patch_integrity import PatchIntegrityConfig, PatchIntegrityGuard


@dataclass
class PolicySettings:
    """Global policy settings."""

    fail_fast: bool = False
    verbose_logging: bool = False
    session_timeout_secs: int = 3600


@dataclass
class GuardConfigs:
    """Configuration for all guards."""

    forbidden_path: Optional[ForbiddenPathConfig] = None
    egress: Optional[EgressConfig] = None
    secret_values: list[str] = field(default_factory=list)
    mcp_tool: Optional[McpToolConfig] = None
    patch_integrity: Optional[PatchIntegrityConfig] = None


@dataclass
class Policy:
    """Complete policy configuration."""

    version: str = "1.0.0"
    name: str = ""
    description: str = ""
    guards: GuardConfigs = field(default_factory=GuardConfigs)
    settings: PolicySettings = field(default_factory=PolicySettings)

    @classmethod
    def from_yaml(cls, yaml_content: str) -> "Policy":
        """Parse from YAML string."""
        data = yaml.safe_load(yaml_content)
        return cls._from_dict(data)

    @classmethod
    def from_yaml_file(cls, path: str | Path) -> "Policy":
        """Load from YAML file."""
        with open(path, encoding="utf-8") as f:
            return cls.from_yaml(f.read())

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> "Policy":
        """Create from dictionary."""
        guards_data = data.get("guards", {})
        settings_data = data.get("settings", {})

        guards = GuardConfigs(
            forbidden_path=ForbiddenPathConfig(**guards_data["forbidden_path"])
            if guards_data.get("forbidden_path")
            else None,
            egress=EgressConfig(**guards_data["egress_allowlist"])
            if guards_data.get("egress_allowlist")
            else None,
            secret_values=guards_data.get("secret_values", []),
            mcp_tool=McpToolConfig(**guards_data["mcp_tool"])
            if guards_data.get("mcp_tool")
            else None,
            patch_integrity=PatchIntegrityConfig(**guards_data["patch_integrity"])
            if guards_data.get("patch_integrity")
            else None,
        )

        settings = PolicySettings(
            fail_fast=settings_data.get("fail_fast", False),
            verbose_logging=settings_data.get("verbose_logging", False),
            session_timeout_secs=settings_data.get("session_timeout_secs", 3600),
        )

        return cls(
            version=data.get("version", "1.0.0"),
            name=data.get("name", ""),
            description=data.get("description", ""),
            guards=guards,
            settings=settings,
        )

    def to_yaml(self) -> str:
        """Export to YAML string."""
        data: dict[str, Any] = {
            "version": self.version,
            "name": self.name,
            "description": self.description,
            "guards": {},
            "settings": {
                "fail_fast": self.settings.fail_fast,
                "verbose_logging": self.settings.verbose_logging,
                "session_timeout_secs": self.settings.session_timeout_secs,
            },
        }
        return yaml.dump(data, default_flow_style=False)

    def create_guards(self) -> "PolicyGuards":
        """Create guards from this policy."""
        return PolicyGuards(
            forbidden_path=ForbiddenPathGuard(self.guards.forbidden_path)
            if self.guards.forbidden_path
            else ForbiddenPathGuard(),
            egress=EgressGuard(self.guards.egress)
            if self.guards.egress
            else EgressGuard(),
            secret_leak=SecretLeakGuard(self.guards.secret_values),
            mcp_tool=McpToolGuard(self.guards.mcp_tool)
            if self.guards.mcp_tool
            else McpToolGuard(),
            patch_integrity=PatchIntegrityGuard(self.guards.patch_integrity)
            if self.guards.patch_integrity
            else PatchIntegrityGuard(),
            fail_fast=self.settings.fail_fast,
        )


@dataclass
class PolicyGuards:
    """Guards instantiated from a policy."""

    forbidden_path: ForbiddenPathGuard
    egress: EgressGuard
    secret_leak: SecretLeakGuard
    mcp_tool: McpToolGuard
    patch_integrity: PatchIntegrityGuard
    fail_fast: bool = False

    def all_guards(self) -> list[Guard]:
        """Get all guards as a list."""
        return [
            self.forbidden_path,
            self.egress,
            self.secret_leak,
            self.mcp_tool,
            self.patch_integrity,
        ]

    def check_all(self, action: GuardAction, context: GuardContext) -> list[GuardResult]:
        """Check action against all applicable guards."""
        results: list[GuardResult] = []

        for guard in self.all_guards():
            if guard.handles(action):
                result = guard.check(action, context)
                results.append(result)
                if self.fail_fast and not result.allowed:
                    break

        return results


@dataclass
class RuleSet:
    """Named ruleset with pre-configured policies."""

    id: str
    name: str
    description: str
    policy: Policy

    @classmethod
    def default(cls) -> "RuleSet":
        """Load the default ruleset."""
        return cls(
            id="default",
            name="Default",
            description="Default security rules for AI agent execution",
            policy=Policy(),
        )

    @classmethod
    def strict(cls) -> "RuleSet":
        """Load the strict ruleset."""
        policy = Policy(
            name="Strict",
            description="Strict security rules with minimal permissions",
            guards=GuardConfigs(
                egress=EgressConfig(
                    allow=[],
                    block=[],
                    default_action="block",
                ),
                mcp_tool=McpToolConfig(
                    allow=["read_file", "list_directory", "search"],
                    block=[],
                    default_action="block",
                ),
                patch_integrity=PatchIntegrityConfig(
                    max_additions=500,
                    max_deletions=200,
                    require_balance=True,
                    max_imbalance_ratio=5.0,
                ),
            ),
            settings=PolicySettings(fail_fast=True),
        )
        return cls(
            id="strict",
            name="Strict",
            description="Strict security rules with minimal permissions",
            policy=policy,
        )

    @classmethod
    def permissive(cls) -> "RuleSet":
        """Load the permissive ruleset."""
        policy = Policy(
            name="Permissive",
            description="Permissive rules for development (use with caution)",
            guards=GuardConfigs(
                egress=EgressConfig(
                    allow=["*"],
                    default_action="allow",
                ),
                patch_integrity=PatchIntegrityConfig(
                    max_additions=10000,
                    max_deletions=5000,
                    require_balance=False,
                ),
            ),
            settings=PolicySettings(verbose_logging=True),
        )
        return cls(
            id="permissive",
            name="Permissive",
            description="Permissive rules for development (use with caution)",
            policy=policy,
        )

    @classmethod
    def by_name(cls, name: str) -> Optional["RuleSet"]:
        """Load a ruleset by name."""
        if name == "default":
            return cls.default()
        elif name == "strict":
            return cls.strict()
        elif name == "permissive":
            return cls.permissive()
        return None


__all__ = [
    "Policy",
    "PolicySettings",
    "GuardConfigs",
    "PolicyGuards",
    "RuleSet",
]
```

**Step 4: Run test to verify it passes**

```bash
cd packages/hush-py && python -m pytest tests/test_policy.py -v
```
Expected: PASS

**Step 5: Commit**

```bash
git add packages/hush-py/src/hush/policy.py
git add packages/hush-py/tests/test_policy.py
git commit -m "feat(hush-py): add policy engine"
```

---

## Task 12: Update Guards __init__.py

**Files:**
- Modify: `packages/hush-py/src/hush/guards/__init__.py`

**Step 1: Update exports**

```python
# packages/hush-py/src/hush/guards/__init__.py
"""Security guards for AI agent execution."""

from hush.guards.base import (
    Severity,
    GuardResult,
    GuardContext,
    GuardAction,
    Guard,
)
from hush.guards.forbidden_path import ForbiddenPathConfig, ForbiddenPathGuard
from hush.guards.egress import EgressConfig, EgressGuard
from hush.guards.secret_leak import SecretLeakGuard
from hush.guards.mcp_tool import McpToolConfig, McpToolGuard
from hush.guards.patch_integrity import PatchIntegrityConfig, PatchIntegrityGuard

__all__ = [
    # Base
    "Severity",
    "GuardResult",
    "GuardContext",
    "GuardAction",
    "Guard",
    # Guards
    "ForbiddenPathConfig",
    "ForbiddenPathGuard",
    "EgressConfig",
    "EgressGuard",
    "SecretLeakGuard",
    "McpToolConfig",
    "McpToolGuard",
    "PatchIntegrityConfig",
    "PatchIntegrityGuard",
]
```

**Step 2: Commit**

```bash
git add packages/hush-py/src/hush/guards/__init__.py
git commit -m "feat(hush-py): update guards exports"
```

---

## Task 13: Update Main __init__.py

**Files:**
- Modify: `packages/hush-py/src/hush/__init__.py`

**Step 1: Update exports**

```python
# packages/hush-py/src/hush/__init__.py
"""Hush Python SDK for clawdstrike security verification."""

from hush.core import sha256, keccak256, verify_signature, Hash
from hush.canonical import canonicalize, CanonicalJsonError
from hush.receipt import (
    Verdict,
    ViolationRef,
    Provenance,
    Receipt,
    SignedReceipt,
    VerificationResult,
)
from hush.policy import Policy, PolicyGuards, RuleSet
from hush.guards import (
    Severity,
    GuardResult,
    GuardContext,
    GuardAction,
    Guard,
    ForbiddenPathGuard,
    EgressGuard,
    SecretLeakGuard,
    McpToolGuard,
    PatchIntegrityGuard,
)

__version__ = "0.1.0"

__all__ = [
    # Version
    "__version__",
    # Core
    "sha256",
    "keccak256",
    "verify_signature",
    "Hash",
    # Canonical
    "canonicalize",
    "CanonicalJsonError",
    # Receipt
    "Verdict",
    "ViolationRef",
    "Provenance",
    "Receipt",
    "SignedReceipt",
    "VerificationResult",
    # Policy
    "Policy",
    "PolicyGuards",
    "RuleSet",
    # Guards
    "Severity",
    "GuardResult",
    "GuardContext",
    "GuardAction",
    "Guard",
    "ForbiddenPathGuard",
    "EgressGuard",
    "SecretLeakGuard",
    "McpToolGuard",
    "PatchIntegrityGuard",
]
```

**Step 2: Commit**

```bash
git add packages/hush-py/src/hush/__init__.py
git commit -m "feat(hush-py): update main package exports"
```

---

## Task 14: Run All Tests and Verify

**Step 1: Install package in development mode**

```bash
cd packages/hush-py
pip install -e ".[dev]"
```

**Step 2: Run all tests**

```bash
cd packages/hush-py && python -m pytest tests/ -v --cov=hush --cov-report=term-missing
```
Expected: All tests pass with 80%+ coverage

**Step 3: Run type checking**

```bash
cd packages/hush-py && mypy src/hush
```
Expected: No errors

**Step 4: Run linting**

```bash
cd packages/hush-py && ruff check src/hush tests/
```
Expected: No errors

**Step 5: Commit test config**

```bash
git add packages/hush-py/
git commit -m "chore(hush-py): add test configuration"
```

---

## Task 15: Create README

**Files:**
- Create: `packages/hush-py/README.md`

**Step 1: Write README**

```markdown
# hush-py

Python SDK for clawdstrike security verification.

## Installation

```bash
pip install hush
```

## Quick Start

```python
from hush import Policy, RuleSet
from hush.guards import GuardAction, GuardContext

# Load default policy
policy = Policy()
guards = policy.create_guards()

# Create context
context = GuardContext().with_cwd("/app")

# Check a file access
action = GuardAction.file_access("/app/main.py")
results = guards.check_all(action, context)

for result in results:
    print(f"{result.guard}: {'allowed' if result.allowed else 'blocked'}")
```

## Guards

- **ForbiddenPathGuard**: Blocks access to sensitive paths (SSH keys, AWS creds, etc.)
- **EgressGuard**: Controls network egress with allow/block lists
- **SecretLeakGuard**: Detects secret values in outputs
- **McpToolGuard**: Controls MCP tool invocations
- **PatchIntegrityGuard**: Validates patch size and balance

## Policy Configuration

```yaml
version: "1.0.0"
name: "my-policy"
guards:
  forbidden_path:
    patterns:
      - "**/.env"
      - "**/.ssh/**"
  egress_allowlist:
    allow:
      - "api.example.com"
    default_action: "block"
settings:
  fail_fast: true
```

## Receipts

```python
from hush import Receipt, SignedReceipt, Verdict
from hush.core import Hash
from nacl.signing import SigningKey

# Create a receipt
receipt = Receipt(
    content_hash=Hash.from_data(b"verified content"),
    verdict=Verdict.passing(gate_id="my-gate"),
)

# Sign it
key = SigningKey.generate()
signed = SignedReceipt.sign(receipt, key)

# Verify
result = signed.verify(bytes(key.verify_key))
assert result.valid
```

## License

MIT
```

**Step 2: Commit**

```bash
git add packages/hush-py/README.md
git commit -m "docs(hush-py): add README"
```

---

## Summary

This plan creates the hush-py Python SDK with:

1. **Core primitives**: SHA-256, Keccak-256, Ed25519 signatures, Hash type
2. **Canonical JSON**: RFC 8785 JCS implementation for cross-language compatibility
3. **Receipt types**: Verdict, Receipt, SignedReceipt with signing/verification
4. **5 Security Guards**:
   - ForbiddenPathGuard
   - EgressGuard
   - SecretLeakGuard
   - McpToolGuard
   - PatchIntegrityGuard
5. **Policy Engine**: YAML-based policy loading and guard instantiation
6. **RuleSets**: Predefined default, strict, and permissive policies

All implementations are pure Python with pynacl for cryptography. PyO3 native bindings are optional (Task 16+) and can be added later for performance.
