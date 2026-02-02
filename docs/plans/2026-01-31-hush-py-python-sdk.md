# hush-py Python SDK Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Create a pure Python SDK for clawdstrike with optional PyO3 native bindings for performance-critical operations.

**Architecture:** The SDK mirrors the Rust clawdstrike crate structure with pure Python implementations of all 5 guards (ForbiddenPath, EgressAllowlist, SecretLeak, PatchIntegrity, McpTool), a policy engine for YAML configuration, receipt types for verification, and optional PyO3 bindings that wrap hush-core for faster cryptographic operations.

**Tech Stack:** Python 3.10+, pynacl (Ed25519), pyyaml, httpx (attestation), pytest, maturin (PyO3 builds)

---

## Task 1: Package Structure Setup

**Files:**
- Create: `packages/hush-py/pyproject.toml`
- Create: `packages/hush-py/src/hush/__init__.py`
- Create: `packages/hush-py/src/hush/py.typed`
- Create: `packages/hush-py/tests/__init__.py`
- Create: `packages/hush-py/tests/conftest.py`

**Step 1: Create pyproject.toml**

```toml
[project]
name = "hush"
version = "0.1.0"
description = "Python SDK for clawdstrike security verification"
readme = "README.md"
license = { text = "MIT" }
requires-python = ">=3.10"
authors = [
    { name = "Clawdstrike Contributors" }
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
    "Typing :: Typed",
]
dependencies = [
    "pynacl>=1.5.0",
    "pyyaml>=6.0",
]

[project.optional-dependencies]
native = []
attestation = ["httpx>=0.25"]
dev = [
    "pytest>=7.0",
    "pytest-asyncio>=0.21",
    "pytest-cov>=4.0",
    "mypy>=1.0",
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
strict = true
warn_return_any = true
warn_unused_configs = true

[tool.ruff]
line-length = 100
target-version = "py310"

[tool.ruff.lint]
select = ["E", "F", "I", "N", "W", "UP", "B", "C4", "SIM"]
```

**Step 2: Create src/hush/__init__.py**

```python
"""Hush - Python SDK for clawdstrike security verification."""

from hush.core import sha256, keccak256, verify_signature
from hush.receipt import Receipt, SignedReceipt
from hush.policy import Policy, PolicyEngine

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "sha256",
    "keccak256",
    "verify_signature",
    "Receipt",
    "SignedReceipt",
    "Policy",
    "PolicyEngine",
]
```

**Step 3: Create src/hush/py.typed (empty marker file)**

```
```

**Step 4: Create tests/__init__.py (empty)**

```python
"""Hush test suite."""
```

**Step 5: Create tests/conftest.py**

```python
"""Pytest configuration and fixtures."""

import pytest


@pytest.fixture
def sample_policy_yaml() -> str:
    """Sample policy YAML for testing."""
    return """
version: "1.0.0"
name: test-policy
guards:
  forbidden_path:
    patterns:
      - "**/.ssh/**"
      - "**/.env"
    exceptions: []
  egress_allowlist:
    allow:
      - "api.example.com"
      - "*.github.com"
    block: []
    default_action: block
  secret_leak:
    enabled: true
  mcp_tool:
    allow:
      - "read_file"
      - "search"
    block: []
    default_action: block
settings:
  fail_fast: false
  verbose_logging: false
"""


@pytest.fixture
def sample_secrets() -> list[str]:
    """Sample secret values for testing."""
    return [
        "sk-abc123secretkey",
        "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    ]
```

**Step 6: Verify package structure**

Run: `ls -la packages/hush-py/`
Expected: Directory exists with pyproject.toml

**Step 7: Commit**

```bash
git add packages/hush-py/
git commit -m "feat(hush-py): initialize package structure with pyproject.toml"
```

---

## Task 2: Core Cryptographic Module

**Files:**
- Create: `packages/hush-py/src/hush/core.py`
- Create: `packages/hush-py/tests/test_core.py`

**Step 1: Write failing tests for core module**

```python
"""Tests for hush.core cryptographic primitives."""

import pytest
from hush.core import sha256, keccak256, verify_signature, sign_message, generate_keypair


class TestSha256:
    def test_sha256_bytes(self) -> None:
        result = sha256(b"hello")
        assert isinstance(result, bytes)
        assert len(result) == 32
        # Known SHA-256 hash of "hello"
        expected = bytes.fromhex(
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        )
        assert result == expected

    def test_sha256_string(self) -> None:
        result = sha256("hello")
        expected = bytes.fromhex(
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        )
        assert result == expected

    def test_sha256_empty(self) -> None:
        result = sha256(b"")
        expected = bytes.fromhex(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        assert result == expected


class TestKeccak256:
    def test_keccak256_bytes(self) -> None:
        result = keccak256(b"hello")
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_keccak256_string(self) -> None:
        result = keccak256("hello")
        assert isinstance(result, bytes)
        assert len(result) == 32


class TestSignature:
    def test_generate_keypair(self) -> None:
        private_key, public_key = generate_keypair()
        assert isinstance(private_key, bytes)
        assert isinstance(public_key, bytes)
        assert len(private_key) == 32
        assert len(public_key) == 32

    def test_sign_and_verify(self) -> None:
        private_key, public_key = generate_keypair()
        message = b"test message"

        signature = sign_message(message, private_key)
        assert isinstance(signature, bytes)
        assert len(signature) == 64

        assert verify_signature(message, signature, public_key) is True

    def test_verify_wrong_message(self) -> None:
        private_key, public_key = generate_keypair()
        message = b"test message"

        signature = sign_message(message, private_key)

        assert verify_signature(b"wrong message", signature, public_key) is False

    def test_verify_wrong_key(self) -> None:
        private_key, public_key = generate_keypair()
        _, other_public_key = generate_keypair()
        message = b"test message"

        signature = sign_message(message, private_key)

        assert verify_signature(message, signature, other_public_key) is False

    def test_verify_invalid_signature(self) -> None:
        _, public_key = generate_keypair()
        message = b"test message"
        invalid_signature = b"\x00" * 64

        assert verify_signature(message, invalid_signature, public_key) is False
```

**Step 2: Run tests to verify they fail**

Run: `cd /Users/connor/Medica/clawdstrike-ws9-python/packages/hush-py && python -m pytest tests/test_core.py -v`
Expected: FAIL with ImportError

**Step 3: Implement core.py**

```python
"""Pure Python cryptographic primitives.

Provides SHA-256, Keccak-256 hashing and Ed25519 signature verification.
Uses PyNaCl for cryptographic operations.
"""

from __future__ import annotations

import hashlib
from typing import Union

from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError


def sha256(data: Union[bytes, str]) -> bytes:
    """Compute SHA-256 hash.

    Args:
        data: Input bytes or string to hash

    Returns:
        32-byte SHA-256 digest
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).digest()


def keccak256(data: Union[bytes, str]) -> bytes:
    """Compute Keccak-256 hash.

    Note: This uses SHA3-256 which is the standardized version.
    For Ethereum-compatible Keccak, use a specialized library.

    Args:
        data: Input bytes or string to hash

    Returns:
        32-byte Keccak-256 digest
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha3_256(data).digest()


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate an Ed25519 keypair.

    Returns:
        Tuple of (private_key, public_key) as 32-byte values
    """
    signing_key = SigningKey.generate()
    return bytes(signing_key), bytes(signing_key.verify_key)


def sign_message(message: bytes, private_key: bytes) -> bytes:
    """Sign a message with Ed25519.

    Args:
        message: Message bytes to sign
        private_key: 32-byte Ed25519 private key

    Returns:
        64-byte signature
    """
    signing_key = SigningKey(private_key)
    signed = signing_key.sign(message)
    return signed.signature


def verify_signature(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify an Ed25519 signature.

    Args:
        message: Original message bytes
        signature: 64-byte signature
        public_key: 32-byte Ed25519 public key

    Returns:
        True if signature is valid, False otherwise
    """
    try:
        verify_key = VerifyKey(public_key)
        verify_key.verify(message, signature)
        return True
    except (BadSignatureError, Exception):
        return False


__all__ = [
    "sha256",
    "keccak256",
    "generate_keypair",
    "sign_message",
    "verify_signature",
]
```

**Step 4: Run tests to verify they pass**

Run: `cd /Users/connor/Medica/clawdstrike-ws9-python/packages/hush-py && python -m pytest tests/test_core.py -v`
Expected: All tests PASS

**Step 5: Commit**

```bash
git add packages/hush-py/src/hush/core.py packages/hush-py/tests/test_core.py
git commit -m "feat(hush-py): add core cryptographic primitives"
```

---

## Task 3: Receipt Types

**Files:**
- Create: `packages/hush-py/src/hush/receipt.py`
- Create: `packages/hush-py/tests/test_receipt.py`

**Step 1: Write failing tests for receipt module**

```python
"""Tests for hush.receipt types."""

import json
import pytest
from hush.receipt import Receipt, SignedReceipt
from hush.core import generate_keypair, sign_message


class TestReceipt:
    def test_create_receipt(self) -> None:
        receipt = Receipt(
            id="run-123",
            artifact_root="0x" + "ab" * 32,
            event_count=42,
            metadata={"task": "test"},
        )
        assert receipt.id == "run-123"
        assert receipt.event_count == 42

    def test_receipt_to_json(self) -> None:
        receipt = Receipt(
            id="run-123",
            artifact_root="0x" + "ab" * 32,
            event_count=42,
            metadata={},
        )
        json_str = receipt.to_json()
        data = json.loads(json_str)
        assert data["id"] == "run-123"
        assert data["event_count"] == 42

    def test_receipt_from_json(self) -> None:
        json_str = json.dumps({
            "id": "run-456",
            "artifact_root": "0x" + "cd" * 32,
            "event_count": 100,
            "metadata": {"key": "value"},
        })
        receipt = Receipt.from_json(json_str)
        assert receipt.id == "run-456"
        assert receipt.event_count == 100
        assert receipt.metadata["key"] == "value"

    def test_receipt_hash(self) -> None:
        receipt = Receipt(
            id="run-123",
            artifact_root="0x" + "ab" * 32,
            event_count=42,
            metadata={},
        )
        hash1 = receipt.hash()
        hash2 = receipt.hash()
        assert hash1 == hash2
        assert len(hash1) == 32


class TestSignedReceipt:
    def test_sign_and_verify(self) -> None:
        receipt = Receipt(
            id="run-123",
            artifact_root="0x" + "ab" * 32,
            event_count=42,
            metadata={},
        )
        private_key, public_key = generate_keypair()

        signed = SignedReceipt.sign(receipt, private_key, public_key)

        assert signed.receipt == receipt
        assert len(signed.signature) == 64
        assert signed.public_key == public_key
        assert signed.verify() is True

    def test_verify_tampered_receipt(self) -> None:
        receipt = Receipt(
            id="run-123",
            artifact_root="0x" + "ab" * 32,
            event_count=42,
            metadata={},
        )
        private_key, public_key = generate_keypair()

        signed = SignedReceipt.sign(receipt, private_key, public_key)

        # Tamper with the receipt
        signed.receipt.event_count = 999

        assert signed.verify() is False

    def test_signed_receipt_serialization(self) -> None:
        receipt = Receipt(
            id="run-123",
            artifact_root="0x" + "ab" * 32,
            event_count=42,
            metadata={},
        )
        private_key, public_key = generate_keypair()

        signed = SignedReceipt.sign(receipt, private_key, public_key)
        json_str = signed.to_json()

        restored = SignedReceipt.from_json(json_str)
        assert restored.receipt.id == "run-123"
        assert restored.verify() is True
```

**Step 2: Run tests to verify they fail**

Run: `cd /Users/connor/Medica/clawdstrike-ws9-python/packages/hush-py && python -m pytest tests/test_receipt.py -v`
Expected: FAIL with ImportError

**Step 3: Implement receipt.py**

```python
"""Receipt types and verification.

Provides Receipt and SignedReceipt types for verification artifacts.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from hush.core import sha256, sign_message, verify_signature


@dataclass
class Receipt:
    """Verification receipt for a run or task."""

    id: str
    artifact_root: str
    event_count: int
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "artifact_root": self.artifact_root,
            "event_count": self.event_count,
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        """Convert to canonical JSON string (sorted keys, no spaces)."""
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Receipt:
        """Create from dictionary."""
        return cls(
            id=data["id"],
            artifact_root=data["artifact_root"],
            event_count=data["event_count"],
            metadata=data.get("metadata", {}),
        )

    @classmethod
    def from_json(cls, json_str: str) -> Receipt:
        """Create from JSON string."""
        return cls.from_dict(json.loads(json_str))

    def hash(self) -> bytes:
        """Compute SHA-256 hash of canonical JSON."""
        return sha256(self.to_json())

    def hash_hex(self) -> str:
        """Compute SHA-256 hash as hex string."""
        return "0x" + self.hash().hex()


@dataclass
class SignedReceipt:
    """Receipt with Ed25519 signature."""

    receipt: Receipt
    signature: bytes
    public_key: bytes

    @classmethod
    def sign(cls, receipt: Receipt, private_key: bytes, public_key: bytes) -> SignedReceipt:
        """Sign a receipt.

        Args:
            receipt: Receipt to sign
            private_key: 32-byte Ed25519 private key
            public_key: 32-byte Ed25519 public key

        Returns:
            SignedReceipt with signature
        """
        message = receipt.to_json().encode("utf-8")
        signature = sign_message(message, private_key)
        return cls(receipt=receipt, signature=signature, public_key=public_key)

    def verify(self) -> bool:
        """Verify the signature.

        Returns:
            True if signature is valid, False otherwise
        """
        message = self.receipt.to_json().encode("utf-8")
        return verify_signature(message, self.signature, self.public_key)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "receipt": self.receipt.to_dict(),
            "signature": base64.b64encode(self.signature).decode("ascii"),
            "public_key": base64.b64encode(self.public_key).decode("ascii"),
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SignedReceipt:
        """Create from dictionary."""
        return cls(
            receipt=Receipt.from_dict(data["receipt"]),
            signature=base64.b64decode(data["signature"]),
            public_key=base64.b64decode(data["public_key"]),
        )

    @classmethod
    def from_json(cls, json_str: str) -> SignedReceipt:
        """Create from JSON string."""
        return cls.from_dict(json.loads(json_str))


__all__ = ["Receipt", "SignedReceipt"]
```

**Step 4: Run tests to verify they pass**

Run: `cd /Users/connor/Medica/clawdstrike-ws9-python/packages/hush-py && python -m pytest tests/test_receipt.py -v`
Expected: All tests PASS

**Step 5: Commit**

```bash
git add packages/hush-py/src/hush/receipt.py packages/hush-py/tests/test_receipt.py
git commit -m "feat(hush-py): add Receipt and SignedReceipt types"
```

---

## Task 4: Guard Base Classes and Types

**Files:**
- Create: `packages/hush-py/src/hush/guards/__init__.py`
- Create: `packages/hush-py/src/hush/guards/base.py`
- Create: `packages/hush-py/tests/test_guards_base.py`

**Step 1: Write failing tests for guard base types**

```python
"""Tests for hush.guards base types."""

import pytest
from hush.guards.base import (
    Guard,
    GuardResult,
    GuardContext,
    GuardAction,
    Severity,
)


class TestSeverity:
    def test_severity_ordering(self) -> None:
        assert Severity.INFO.value == "info"
        assert Severity.WARNING.value == "warning"
        assert Severity.ERROR.value == "error"
        assert Severity.CRITICAL.value == "critical"


class TestGuardResult:
    def test_allow_result(self) -> None:
        result = GuardResult.allow("test_guard")
        assert result.allowed is True
        assert result.guard == "test_guard"
        assert result.severity == Severity.INFO

    def test_block_result(self) -> None:
        result = GuardResult.block("test_guard", Severity.ERROR, "blocked")
        assert result.allowed is False
        assert result.guard == "test_guard"
        assert result.severity == Severity.ERROR
        assert result.message == "blocked"

    def test_warn_result(self) -> None:
        result = GuardResult.warn("test_guard", "warning message")
        assert result.allowed is True
        assert result.severity == Severity.WARNING

    def test_with_details(self) -> None:
        result = GuardResult.block("test_guard", Severity.ERROR, "blocked")
        result = result.with_details({"path": "/secret"})
        assert result.details == {"path": "/secret"}


class TestGuardContext:
    def test_default_context(self) -> None:
        ctx = GuardContext()
        assert ctx.cwd is None
        assert ctx.session_id is None

    def test_context_with_values(self) -> None:
        ctx = GuardContext(
            cwd="/app",
            session_id="sess-123",
            agent_id="agent-456",
        )
        assert ctx.cwd == "/app"
        assert ctx.session_id == "sess-123"
        assert ctx.agent_id == "agent-456"


class TestGuardAction:
    def test_file_access_action(self) -> None:
        action = GuardAction.file_access("/path/to/file")
        assert action.action_type == "file_access"
        assert action.path == "/path/to/file"

    def test_file_write_action(self) -> None:
        action = GuardAction.file_write("/path/to/file", b"content")
        assert action.action_type == "file_write"
        assert action.path == "/path/to/file"
        assert action.content == b"content"

    def test_network_egress_action(self) -> None:
        action = GuardAction.network_egress("api.example.com", 443)
        assert action.action_type == "network_egress"
        assert action.host == "api.example.com"
        assert action.port == 443

    def test_mcp_tool_action(self) -> None:
        action = GuardAction.mcp_tool("read_file", {"path": "/test"})
        assert action.action_type == "mcp_tool"
        assert action.tool == "read_file"
        assert action.args == {"path": "/test"}
```

**Step 2: Run tests to verify they fail**

Run: `cd /Users/connor/Medica/clawdstrike-ws9-python/packages/hush-py && python -m pytest tests/test_guards_base.py -v`
Expected: FAIL with ImportError

**Step 3: Implement guards/base.py**

```python
"""Base guard types and interfaces.

Provides the Guard abstract base class and supporting types.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class Severity(str, Enum):
    """Severity level for guard violations."""

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
    details: Optional[Dict[str, Any]] = None

    @classmethod
    def allow(cls, guard: str) -> GuardResult:
        """Create an allow result."""
        return cls(
            allowed=True,
            guard=guard,
            severity=Severity.INFO,
            message="Allowed",
        )

    @classmethod
    def block(cls, guard: str, severity: Severity, message: str) -> GuardResult:
        """Create a block result."""
        return cls(
            allowed=False,
            guard=guard,
            severity=severity,
            message=message,
        )

    @classmethod
    def warn(cls, guard: str, message: str) -> GuardResult:
        """Create a warning result (allowed but logged)."""
        return cls(
            allowed=True,
            guard=guard,
            severity=Severity.WARNING,
            message=message,
        )

    def with_details(self, details: Dict[str, Any]) -> GuardResult:
        """Add details to the result."""
        self.details = details
        return self


@dataclass
class GuardContext:
    """Context passed to guards for evaluation."""

    cwd: Optional[str] = None
    session_id: Optional[str] = None
    agent_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class GuardAction:
    """Action to be checked by guards."""

    action_type: str
    path: Optional[str] = None
    content: Optional[bytes] = None
    host: Optional[str] = None
    port: Optional[int] = None
    tool: Optional[str] = None
    args: Optional[Dict[str, Any]] = None
    command: Optional[str] = None
    diff: Optional[str] = None
    custom_type: Optional[str] = None
    custom_data: Optional[Dict[str, Any]] = None

    @classmethod
    def file_access(cls, path: str) -> GuardAction:
        """Create a file access action."""
        return cls(action_type="file_access", path=path)

    @classmethod
    def file_write(cls, path: str, content: bytes) -> GuardAction:
        """Create a file write action."""
        return cls(action_type="file_write", path=path, content=content)

    @classmethod
    def network_egress(cls, host: str, port: int) -> GuardAction:
        """Create a network egress action."""
        return cls(action_type="network_egress", host=host, port=port)

    @classmethod
    def shell_command(cls, command: str) -> GuardAction:
        """Create a shell command action."""
        return cls(action_type="shell_command", command=command)

    @classmethod
    def mcp_tool(cls, tool: str, args: Dict[str, Any]) -> GuardAction:
        """Create an MCP tool action."""
        return cls(action_type="mcp_tool", tool=tool, args=args)

    @classmethod
    def patch(cls, path: str, diff: str) -> GuardAction:
        """Create a patch action."""
        return cls(action_type="patch", path=path, diff=diff)

    @classmethod
    def custom(cls, custom_type: str, data: Dict[str, Any]) -> GuardAction:
        """Create a custom action."""
        return cls(action_type="custom", custom_type=custom_type, custom_data=data)


class Guard(ABC):
    """Abstract base class for security guards."""

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
        """Evaluate the action.

        Args:
            action: The action to check
            context: Execution context

        Returns:
            GuardResult indicating whether action is allowed
        """
        ...


__all__ = [
    "Severity",
    "GuardResult",
    "GuardContext",
    "GuardAction",
    "Guard",
]
```

**Step 4: Create guards/__init__.py**

```python
"""Security guards for clawdstrike.

Guards implement checks that can allow, block, or log actions.
"""

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

**Step 5: Run tests to verify they pass**

Run: `cd /Users/connor/Medica/clawdstrike-ws9-python/packages/hush-py && python -m pytest tests/test_guards_base.py -v`
Expected: All tests PASS

**Step 6: Commit**

```bash
git add packages/hush-py/src/hush/guards/
git add packages/hush-py/tests/test_guards_base.py
git commit -m "feat(hush-py): add guard base types and interfaces"
```

---

## Task 5: ForbiddenPath Guard

**Files:**
- Create: `packages/hush-py/src/hush/guards/forbidden_path.py`
- Create: `packages/hush-py/tests/test_forbidden_path.py`

**Step 1: Write failing tests**

```python
"""Tests for ForbiddenPathGuard."""

import pytest
from hush.guards.forbidden_path import ForbiddenPathGuard, ForbiddenPathConfig
from hush.guards.base import GuardAction, GuardContext, Severity


class TestForbiddenPathConfig:
    def test_default_patterns(self) -> None:
        config = ForbiddenPathConfig()
        assert "**/.ssh/**" in config.patterns
        assert "**/.env" in config.patterns
        assert "**/.aws/**" in config.patterns

    def test_custom_patterns(self) -> None:
        config = ForbiddenPathConfig(
            patterns=["**/secret/**"],
            exceptions=["**/secret/public/**"],
        )
        assert config.patterns == ["**/secret/**"]
        assert config.exceptions == ["**/secret/public/**"]


class TestForbiddenPathGuard:
    def test_default_forbidden_paths(self) -> None:
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
        assert guard.is_forbidden("/app/src/main.py") is False
        assert guard.is_forbidden("/home/user/project/README.md") is False

    def test_exceptions(self) -> None:
        config = ForbiddenPathConfig(
            patterns=["**/.env"],
            exceptions=["**/project/.env"],
        )
        guard = ForbiddenPathGuard(config)

        assert guard.is_forbidden("/app/.env") is True
        assert guard.is_forbidden("/app/project/.env") is False

    def test_windows_path_normalization(self) -> None:
        guard = ForbiddenPathGuard()

        # Windows paths should be normalized
        assert guard.is_forbidden("C:\\Users\\user\\.ssh\\id_rsa") is True
        assert guard.is_forbidden("C:\\app\\.env") is True

    def test_handles_file_actions(self) -> None:
        guard = ForbiddenPathGuard()

        assert guard.handles(GuardAction.file_access("/test")) is True
        assert guard.handles(GuardAction.file_write("/test", b"")) is True
        assert guard.handles(GuardAction.patch("/test", "")) is True
        assert guard.handles(GuardAction.network_egress("host", 80)) is False

    def test_check_forbidden_path(self) -> None:
        guard = ForbiddenPathGuard()
        context = GuardContext()

        result = guard.check(
            GuardAction.file_access("/home/user/.ssh/id_rsa"),
            context,
        )
        assert result.allowed is False
        assert result.severity == Severity.CRITICAL
        assert "forbidden" in result.message.lower()

    def test_check_allowed_path(self) -> None:
        guard = ForbiddenPathGuard()
        context = GuardContext()

        result = guard.check(
            GuardAction.file_access("/app/src/main.py"),
            context,
        )
        assert result.allowed is True

    def test_guard_name(self) -> None:
        guard = ForbiddenPathGuard()
        assert guard.name == "forbidden_path"
```

**Step 2: Run tests to verify they fail**

Run: `cd /Users/connor/Medica/clawdstrike-ws9-python/packages/hush-py && python -m pytest tests/test_forbidden_path.py -v`
Expected: FAIL with ImportError

**Step 3: Implement forbidden_path.py**

```python
"""Forbidden path guard - blocks access to sensitive paths."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import List, Optional

from hush.guards.base import Guard, GuardAction, GuardContext, GuardResult, Severity


def default_forbidden_patterns() -> List[str]:
    """Default patterns for forbidden paths."""
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

    patterns: List[str] = field(default_factory=default_forbidden_patterns)
    exceptions: List[str] = field(default_factory=list)


class ForbiddenPathGuard(Guard):
    """Guard that blocks access to sensitive paths."""

    def __init__(self, config: Optional[ForbiddenPathConfig] = None) -> None:
        self._config = config or ForbiddenPathConfig()

    @property
    def name(self) -> str:
        return "forbidden_path"

    def handles(self, action: GuardAction) -> bool:
        return action.action_type in ("file_access", "file_write", "patch")

    def is_forbidden(self, path: str) -> bool:
        """Check if a path is forbidden.

        Args:
            path: Path to check

        Returns:
            True if path is forbidden, False otherwise
        """
        # Normalize path (handle Windows paths)
        normalized = path.replace("\\", "/")

        # Check exceptions first
        for exception in self._config.exceptions:
            if fnmatch.fnmatch(normalized, exception):
                return False

        # Check forbidden patterns
        for pattern in self._config.patterns:
            if fnmatch.fnmatch(normalized, pattern):
                return True

        return False

    def check(self, action: GuardAction, context: GuardContext) -> GuardResult:
        """Check if file access is allowed.

        Args:
            action: The action to check
            context: Execution context

        Returns:
            GuardResult
        """
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


__all__ = ["ForbiddenPathGuard", "ForbiddenPathConfig"]
```

**Step 4: Update guards/__init__.py**

```python
"""Security guards for clawdstrike.

Guards implement checks that can allow, block, or log actions.
"""

from hush.guards.base import (
    Severity,
    GuardResult,
    GuardContext,
    GuardAction,
    Guard,
)
from hush.guards.forbidden_path import ForbiddenPathGuard, ForbiddenPathConfig

__all__ = [
    "Severity",
    "GuardResult",
    "GuardContext",
    "GuardAction",
    "Guard",
    "ForbiddenPathGuard",
    "ForbiddenPathConfig",
]
```

**Step 5: Run tests to verify they pass**

Run: `cd /Users/connor/Medica/clawdstrike-ws9-python/packages/hush-py && python -m pytest tests/test_forbidden_path.py -v`
Expected: All tests PASS

**Step 6: Commit**

```bash
git add packages/hush-py/src/hush/guards/
git add packages/hush-py/tests/test_forbidden_path.py
git commit -m "feat(hush-py): add ForbiddenPathGuard"
```

---

## Task 6: EgressAllowlist Guard

**Files:**
- Create: `packages/hush-py/src/hush/guards/egress_allowlist.py`
- Create: `packages/hush-py/tests/test_egress_allowlist.py`

**Step 1: Write failing tests**

```python
"""Tests for EgressAllowlistGuard."""

import pytest
from hush.guards.egress_allowlist import EgressAllowlistGuard, EgressAllowlistConfig
from hush.guards.base import GuardAction, GuardContext, Severity


class TestEgressAllowlistConfig:
    def test_default_config(self) -> None:
        config = EgressAllowlistConfig()
        assert config.allow == []
        assert config.block == []
        assert config.default_action == "block"

    def test_custom_config(self) -> None:
        config = EgressAllowlistConfig(
            allow=["*.github.com", "api.example.com"],
            block=["malicious.com"],
            default_action="allow",
        )
        assert "*.github.com" in config.allow
        assert "malicious.com" in config.block


class TestEgressAllowlistGuard:
    def test_allow_matching_domain(self) -> None:
        config = EgressAllowlistConfig(
            allow=["api.example.com", "*.github.com"],
            default_action="block",
        )
        guard = EgressAllowlistGuard(config)
        context = GuardContext()

        result = guard.check(
            GuardAction.network_egress("api.example.com", 443),
            context,
        )
        assert result.allowed is True

    def test_allow_wildcard_subdomain(self) -> None:
        config = EgressAllowlistConfig(
            allow=["*.github.com"],
            default_action="block",
        )
        guard = EgressAllowlistGuard(config)
        context = GuardContext()

        result = guard.check(
            GuardAction.network_egress("api.github.com", 443),
            context,
        )
        assert result.allowed is True

        result = guard.check(
            GuardAction.network_egress("raw.githubusercontent.com", 443),
            context,
        )
        assert result.allowed is False  # Different domain

    def test_block_explicit_domain(self) -> None:
        config = EgressAllowlistConfig(
            allow=["*"],
            block=["malicious.com"],
            default_action="allow",
        )
        guard = EgressAllowlistGuard(config)
        context = GuardContext()

        result = guard.check(
            GuardAction.network_egress("malicious.com", 80),
            context,
        )
        assert result.allowed is False
        assert result.severity == Severity.ERROR

    def test_default_block(self) -> None:
        config = EgressAllowlistConfig(
            allow=["allowed.com"],
            default_action="block",
        )
        guard = EgressAllowlistGuard(config)
        context = GuardContext()

        result = guard.check(
            GuardAction.network_egress("unknown.com", 443),
            context,
        )
        assert result.allowed is False

    def test_default_allow(self) -> None:
        config = EgressAllowlistConfig(
            block=["blocked.com"],
            default_action="allow",
        )
        guard = EgressAllowlistGuard(config)
        context = GuardContext()

        result = guard.check(
            GuardAction.network_egress("unknown.com", 443),
            context,
        )
        assert result.allowed is True

    def test_handles_network_actions(self) -> None:
        guard = EgressAllowlistGuard()

        assert guard.handles(GuardAction.network_egress("host", 80)) is True
        assert guard.handles(GuardAction.file_access("/test")) is False

    def test_guard_name(self) -> None:
        guard = EgressAllowlistGuard()
        assert guard.name == "egress_allowlist"

    def test_subdomain_matching(self) -> None:
        config = EgressAllowlistConfig(
            allow=["github.com"],
            default_action="block",
        )
        guard = EgressAllowlistGuard(config)
        context = GuardContext()

        # Exact match
        result = guard.check(
            GuardAction.network_egress("github.com", 443),
            context,
        )
        assert result.allowed is True

        # Subdomain should also match
        result = guard.check(
            GuardAction.network_egress("api.github.com", 443),
            context,
        )
        assert result.allowed is True
```

**Step 2: Run tests to verify they fail**

Run: `cd /Users/connor/Medica/clawdstrike-ws9-python/packages/hush-py && python -m pytest tests/test_egress_allowlist.py -v`
Expected: FAIL with ImportError

**Step 3: Implement egress_allowlist.py**

```python
"""Egress allowlist guard - controls outbound network access."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import List, Optional

from hush.guards.base import Guard, GuardAction, GuardContext, GuardResult, Severity


@dataclass
class EgressAllowlistConfig:
    """Configuration for EgressAllowlistGuard."""

    allow: List[str] = field(default_factory=list)
    block: List[str] = field(default_factory=list)
    default_action: str = "block"  # "block" or "allow"


class EgressAllowlistGuard(Guard):
    """Guard that controls outbound network access."""

    def __init__(self, config: Optional[EgressAllowlistConfig] = None) -> None:
        self._config = config or EgressAllowlistConfig()

    @property
    def name(self) -> str:
        return "egress_allowlist"

    def handles(self, action: GuardAction) -> bool:
        return action.action_type == "network_egress"

    def _matches_pattern(self, host: str, pattern: str) -> bool:
        """Check if host matches a pattern.

        Supports:
        - Exact match: "api.example.com"
        - Wildcard subdomain: "*.example.com"
        - Subdomain matching: "example.com" matches "api.example.com"
        """
        if not pattern:
            return False

        # Exact match
        if host == pattern:
            return True

        # Wildcard pattern
        if pattern.startswith("*."):
            suffix = pattern[1:]  # ".example.com"
            return host.endswith(suffix)

        # Subdomain matching (host ends with .pattern)
        if host.endswith("." + pattern):
            return True

        # fnmatch for other patterns
        return fnmatch.fnmatch(host, pattern)

    def _matches_any(self, host: str, patterns: List[str]) -> bool:
        """Check if host matches any pattern in the list."""
        return any(self._matches_pattern(host, p) for p in patterns)

    def check(self, action: GuardAction, context: GuardContext) -> GuardResult:
        """Check if network egress is allowed.

        Args:
            action: The action to check
            context: Execution context

        Returns:
            GuardResult
        """
        if not self.handles(action):
            return GuardResult.allow(self.name)

        host = action.host
        if host is None:
            return GuardResult.allow(self.name)

        # Check block list first (takes precedence)
        if self._matches_any(host, self._config.block):
            return GuardResult.block(
                self.name,
                Severity.ERROR,
                f"Egress to blocked destination: {host}",
            ).with_details({
                "host": host,
                "port": action.port,
                "reason": "explicitly_blocked",
            })

        # Check allow list
        if self._matches_any(host, self._config.allow):
            return GuardResult.allow(self.name)

        # Apply default action
        if self._config.default_action == "allow":
            return GuardResult.allow(self.name)

        return GuardResult.block(
            self.name,
            Severity.ERROR,
            f"Egress to unlisted destination: {host}",
        ).with_details({
            "host": host,
            "port": action.port,
            "reason": "not_in_allowlist",
        })


__all__ = ["EgressAllowlistGuard", "EgressAllowlistConfig"]
```

**Step 4: Update guards/__init__.py**

```python
"""Security guards for clawdstrike.

Guards implement checks that can allow, block, or log actions.
"""

from hush.guards.base import (
    Severity,
    GuardResult,
    GuardContext,
    GuardAction,
    Guard,
)
from hush.guards.forbidden_path import ForbiddenPathGuard, ForbiddenPathConfig
from hush.guards.egress_allowlist import EgressAllowlistGuard, EgressAllowlistConfig

__all__ = [
    "Severity",
    "GuardResult",
    "GuardContext",
    "GuardAction",
    "Guard",
    "ForbiddenPathGuard",
    "ForbiddenPathConfig",
    "EgressAllowlistGuard",
    "EgressAllowlistConfig",
]
```

**Step 5: Run tests to verify they pass**

Run: `cd /Users/connor/Medica/clawdstrike-ws9-python/packages/hush-py && python -m pytest tests/test_egress_allowlist.py -v`
Expected: All tests PASS

**Step 6: Commit**

```bash
git add packages/hush-py/src/hush/guards/
git add packages/hush-py/tests/test_egress_allowlist.py
git commit -m "feat(hush-py): add EgressAllowlistGuard"
```

---

## Task 7: SecretLeak Guard

**Files:**
- Create: `packages/hush-py/src/hush/guards/secret_leak.py`
- Create: `packages/hush-py/tests/test_secret_leak.py`

**Step 1: Write failing tests**

```python
"""Tests for SecretLeakGuard."""

import pytest
from hush.guards.secret_leak import SecretLeakGuard, SecretLeakConfig
from hush.guards.base import GuardAction, GuardContext, Severity


class TestSecretLeakConfig:
    def test_default_config(self) -> None:
        config = SecretLeakConfig()
        assert config.secrets == []
        assert config.enabled is True

    def test_with_secrets(self) -> None:
        config = SecretLeakConfig(secrets=["secret1", "secret2"])
        assert len(config.secrets) == 2


class TestSecretLeakGuard:
    def test_detect_secret_in_output(self) -> None:
        config = SecretLeakConfig(secrets=["sk-abc123secretkey"])
        guard = SecretLeakGuard(config)
        context = GuardContext()

        # Create action with output containing secret
        action = GuardAction.custom("output", {
            "content": "The API key is sk-abc123secretkey",
        })

        result = guard.check(action, context)
        assert result.allowed is False
        assert result.severity == Severity.CRITICAL

    def test_no_secret_in_output(self) -> None:
        config = SecretLeakConfig(secrets=["sk-abc123secretkey"])
        guard = SecretLeakGuard(config)
        context = GuardContext()

        action = GuardAction.custom("output", {
            "content": "This is safe output with no secrets",
        })

        result = guard.check(action, context)
        assert result.allowed is True

    def test_empty_secrets_list(self) -> None:
        config = SecretLeakConfig(secrets=[])
        guard = SecretLeakGuard(config)
        context = GuardContext()

        action = GuardAction.custom("output", {
            "content": "Any output is allowed",
        })

        result = guard.check(action, context)
        assert result.allowed is True

    def test_disabled_guard(self) -> None:
        config = SecretLeakConfig(
            secrets=["secret123"],
            enabled=False,
        )
        guard = SecretLeakGuard(config)
        context = GuardContext()

        action = GuardAction.custom("output", {
            "content": "Contains secret123 but guard is disabled",
        })

        result = guard.check(action, context)
        assert result.allowed is True

    def test_secret_hint_in_details(self) -> None:
        config = SecretLeakConfig(secrets=["verylongsecretvalue"])
        guard = SecretLeakGuard(config)
        context = GuardContext()

        action = GuardAction.custom("output", {
            "content": "Leaked: verylongsecretvalue",
        })

        result = guard.check(action, context)
        assert result.details is not None
        assert "secret_hint" in result.details
        # Should only show first 4 chars
        assert result.details["secret_hint"] == "very..."

    def test_handles_output_actions(self) -> None:
        guard = SecretLeakGuard()

        assert guard.handles(GuardAction.custom("output", {})) is True
        assert guard.handles(GuardAction.custom("bash_output", {})) is True
        assert guard.handles(GuardAction.custom("tool_result", {})) is True
        assert guard.handles(GuardAction.file_access("/test")) is False

    def test_guard_name(self) -> None:
        guard = SecretLeakGuard()
        assert guard.name == "secret_leak"

    def test_filters_empty_secrets(self) -> None:
        config = SecretLeakConfig(secrets=["", "  ", "valid"])
        guard = SecretLeakGuard(config)
        context = GuardContext()

        # Only "valid" should be checked
        action = GuardAction.custom("output", {"content": "valid secret"})
        result = guard.check(action, context)
        assert result.allowed is False

    def test_multiple_content_fields(self) -> None:
        config = SecretLeakConfig(secrets=["secret123"])
        guard = SecretLeakGuard(config)
        context = GuardContext()

        # Test with "output" field
        action = GuardAction.custom("output", {"output": "secret123 leaked"})
        result = guard.check(action, context)
        assert result.allowed is False

        # Test with "result" field
        action = GuardAction.custom("tool_result", {"result": "secret123 leaked"})
        result = guard.check(action, context)
        assert result.allowed is False
```

**Step 2: Run tests to verify they fail**

Run: `cd /Users/connor/Medica/clawdstrike-ws9-python/packages/hush-py && python -m pytest tests/test_secret_leak.py -v`
Expected: FAIL with ImportError

**Step 3: Implement secret_leak.py**

```python
"""Secret leak guard - detects secrets in output."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from hush.guards.base import Guard, GuardAction, GuardContext, GuardResult, Severity


@dataclass
class SecretLeakConfig:
    """Configuration for SecretLeakGuard."""

    secrets: List[str] = field(default_factory=list)
    enabled: bool = True


class SecretLeakGuard(Guard):
    """Guard that detects secret values in output."""

    # Action types that may contain output
    OUTPUT_ACTIONS = {"output", "bash_output", "tool_result", "response"}

    def __init__(self, config: Optional[SecretLeakConfig] = None) -> None:
        self._config = config or SecretLeakConfig()
        # Filter out empty/whitespace-only secrets
        self._secrets = [s for s in self._config.secrets if s and s.strip()]

    @property
    def name(self) -> str:
        return "secret_leak"

    def handles(self, action: GuardAction) -> bool:
        if action.action_type == "custom" and action.custom_type:
            return action.custom_type in self.OUTPUT_ACTIONS
        return False

    def _extract_text(self, data: Optional[Dict[str, Any]]) -> str:
        """Extract text content from action data."""
        if data is None:
            return ""

        # Check common content field names
        for key in ("content", "output", "result", "error", "text"):
            value = data.get(key)
            if isinstance(value, str) and value:
                return value

        return ""

    def check(self, action: GuardAction, context: GuardContext) -> GuardResult:
        """Check if output contains secrets.

        Args:
            action: The action to check
            context: Execution context

        Returns:
            GuardResult
        """
        # Skip if disabled or no secrets configured
        if not self._config.enabled or not self._secrets:
            return GuardResult.allow(self.name)

        if not self.handles(action):
            return GuardResult.allow(self.name)

        text = self._extract_text(action.custom_data)
        if not text:
            return GuardResult.allow(self.name)

        # Check for any secret in the output
        for secret in self._secrets:
            if secret in text:
                # Create hint (first 4 chars + "...")
                hint = secret[:4] + "..." if len(secret) > 4 else secret[:2] + "..."

                return GuardResult.block(
                    self.name,
                    Severity.CRITICAL,
                    "Secret value exposed in output",
                ).with_details({
                    "secret_hint": hint,
                    "action_type": action.custom_type,
                })

        return GuardResult.allow(self.name)


__all__ = ["SecretLeakGuard", "SecretLeakConfig"]
```

**Step 4: Update guards/__init__.py**

```python
"""Security guards for clawdstrike.

Guards implement checks that can allow, block, or log actions.
"""

from hush.guards.base import (
    Severity,
    GuardResult,
    GuardContext,
    GuardAction,
    Guard,
)
from hush.guards.forbidden_path import ForbiddenPathGuard, ForbiddenPathConfig
from hush.guards.egress_allowlist import EgressAllowlistGuard, EgressAllowlistConfig
from hush.guards.secret_leak import SecretLeakGuard, SecretLeakConfig

__all__ = [
    "Severity",
    "GuardResult",
    "GuardContext",
    "GuardAction",
    "Guard",
    "ForbiddenPathGuard",
    "ForbiddenPathConfig",
    "EgressAllowlistGuard",
    "EgressAllowlistConfig",
    "SecretLeakGuard",
    "SecretLeakConfig",
]
```

**Step 5: Run tests to verify they pass**

Run: `cd /Users/connor/Medica/clawdstrike-ws9-python/packages/hush-py && python -m pytest tests/test_secret_leak.py -v`
Expected: All tests PASS

**Step 6: Commit**

```bash
git add packages/hush-py/src/hush/guards/
git add packages/hush-py/tests/test_secret_leak.py
git commit -m "feat(hush-py): add SecretLeakGuard"
```

---

## Task 8: PatchIntegrity Guard

**Files:**
- Create: `packages/hush-py/src/hush/guards/patch_integrity.py`
- Create: `packages/hush-py/tests/test_patch_integrity.py`

**Step 1: Write failing tests**

```python
"""Tests for PatchIntegrityGuard."""

import pytest
from hush.guards.patch_integrity import PatchIntegrityGuard, PatchIntegrityConfig
from hush.guards.base import GuardAction, GuardContext, Severity


class TestPatchIntegrityConfig:
    def test_default_config(self) -> None:
        config = PatchIntegrityConfig()
        assert config.max_additions == 1000
        assert config.max_deletions == 500
        assert config.require_balance is False


class TestPatchIntegrityGuard:
    def test_within_limits(self) -> None:
        config = PatchIntegrityConfig(
            max_additions=100,
            max_deletions=50,
        )
        guard = PatchIntegrityGuard(config)
        context = GuardContext()

        # Small patch well within limits
        diff = """
+line 1
+line 2
-old line
"""
        result = guard.check(GuardAction.patch("/file.py", diff), context)
        assert result.allowed is True

    def test_exceeds_additions(self) -> None:
        config = PatchIntegrityConfig(max_additions=5)
        guard = PatchIntegrityGuard(config)
        context = GuardContext()

        # Patch with 10 additions
        diff = "\n".join([f"+line {i}" for i in range(10)])

        result = guard.check(GuardAction.patch("/file.py", diff), context)
        assert result.allowed is False
        assert "additions" in result.message.lower()

    def test_exceeds_deletions(self) -> None:
        config = PatchIntegrityConfig(max_deletions=3)
        guard = PatchIntegrityGuard(config)
        context = GuardContext()

        # Patch with 5 deletions
        diff = "\n".join([f"-line {i}" for i in range(5)])

        result = guard.check(GuardAction.patch("/file.py", diff), context)
        assert result.allowed is False
        assert "deletions" in result.message.lower()

    def test_balance_required_balanced(self) -> None:
        config = PatchIntegrityConfig(
            max_additions=100,
            max_deletions=100,
            require_balance=True,
            max_imbalance_ratio=2.0,
        )
        guard = PatchIntegrityGuard(config)
        context = GuardContext()

        # Balanced patch (10 additions, 8 deletions)
        diff = "\n".join([f"+line {i}" for i in range(10)])
        diff += "\n" + "\n".join([f"-line {i}" for i in range(8)])

        result = guard.check(GuardAction.patch("/file.py", diff), context)
        assert result.allowed is True

    def test_balance_required_imbalanced(self) -> None:
        config = PatchIntegrityConfig(
            max_additions=100,
            max_deletions=100,
            require_balance=True,
            max_imbalance_ratio=2.0,
        )
        guard = PatchIntegrityGuard(config)
        context = GuardContext()

        # Very imbalanced patch (20 additions, 2 deletions)
        diff = "\n".join([f"+line {i}" for i in range(20)])
        diff += "\n-line 1\n-line 2"

        result = guard.check(GuardAction.patch("/file.py", diff), context)
        assert result.allowed is False
        assert "imbalance" in result.message.lower()

    def test_handles_patch_actions(self) -> None:
        guard = PatchIntegrityGuard()

        assert guard.handles(GuardAction.patch("/file", "diff")) is True
        assert guard.handles(GuardAction.file_access("/test")) is False

    def test_guard_name(self) -> None:
        guard = PatchIntegrityGuard()
        assert guard.name == "patch_integrity"

    def test_counts_only_actual_changes(self) -> None:
        guard = PatchIntegrityGuard()
        context = GuardContext()

        # Diff with context lines (no + or - prefix)
        diff = """
@@ -1,5 +1,6 @@
 context line
+added line
 more context
-removed line
 final context
"""
        result = guard.check(GuardAction.patch("/file.py", diff), context)
        assert result.allowed is True
        assert result.details is not None
        assert result.details.get("additions") == 1
        assert result.details.get("deletions") == 1
```

**Step 2: Run tests to verify they fail**

Run: `cd /Users/connor/Medica/clawdstrike-ws9-python/packages/hush-py && python -m pytest tests/test_patch_integrity.py -v`
Expected: FAIL with ImportError

**Step 3: Implement patch_integrity.py**

```python
"""Patch integrity guard - validates code patches."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

from hush.guards.base import Guard, GuardAction, GuardContext, GuardResult, Severity


@dataclass
class PatchIntegrityConfig:
    """Configuration for PatchIntegrityGuard."""

    max_additions: int = 1000
    max_deletions: int = 500
    require_balance: bool = False
    max_imbalance_ratio: float = 5.0


class PatchIntegrityGuard(Guard):
    """Guard that validates patch size and balance."""

    def __init__(self, config: Optional[PatchIntegrityConfig] = None) -> None:
        self._config = config or PatchIntegrityConfig()

    @property
    def name(self) -> str:
        return "patch_integrity"

    def handles(self, action: GuardAction) -> bool:
        return action.action_type == "patch"

    def _count_changes(self, diff: str) -> Tuple[int, int]:
        """Count additions and deletions in a diff.

        Returns:
            Tuple of (additions, deletions)
        """
        additions = 0
        deletions = 0

        for line in diff.split("\n"):
            # Skip diff headers
            if line.startswith("@@") or line.startswith("---") or line.startswith("+++"):
                continue
            if line.startswith("+") and not line.startswith("+++"):
                additions += 1
            elif line.startswith("-") and not line.startswith("---"):
                deletions += 1

        return additions, deletions

    def check(self, action: GuardAction, context: GuardContext) -> GuardResult:
        """Check if patch is within allowed limits.

        Args:
            action: The action to check
            context: Execution context

        Returns:
            GuardResult
        """
        if not self.handles(action):
            return GuardResult.allow(self.name)

        diff = action.diff
        if diff is None:
            return GuardResult.allow(self.name)

        additions, deletions = self._count_changes(diff)

        # Check additions limit
        if additions > self._config.max_additions:
            return GuardResult.block(
                self.name,
                Severity.ERROR,
                f"Patch exceeds max additions: {additions} > {self._config.max_additions}",
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
                f"Patch exceeds max deletions: {deletions} > {self._config.max_deletions}",
            ).with_details({
                "additions": additions,
                "deletions": deletions,
                "max_deletions": self._config.max_deletions,
            })

        # Check balance if required
        if self._config.require_balance and deletions > 0:
            ratio = additions / deletions
            if ratio > self._config.max_imbalance_ratio:
                return GuardResult.block(
                    self.name,
                    Severity.WARNING,
                    f"Patch imbalance ratio too high: {ratio:.1f} > {self._config.max_imbalance_ratio}",
                ).with_details({
                    "additions": additions,
                    "deletions": deletions,
                    "ratio": ratio,
                    "max_ratio": self._config.max_imbalance_ratio,
                })

        return GuardResult.allow(self.name).with_details({
            "additions": additions,
            "deletions": deletions,
        })


__all__ = ["PatchIntegrityGuard", "PatchIntegrityConfig"]
```

**Step 4: Update guards/__init__.py**

```python
"""Security guards for clawdstrike.

Guards implement checks that can allow, block, or log actions.
"""

from hush.guards.base import (
    Severity,
    GuardResult,
    GuardContext,
    GuardAction,
    Guard,
)
from hush.guards.forbidden_path import ForbiddenPathGuard, ForbiddenPathConfig
from hush.guards.egress_allowlist import EgressAllowlistGuard, EgressAllowlistConfig
from hush.guards.secret_leak import SecretLeakGuard, SecretLeakConfig
from hush.guards.patch_integrity import PatchIntegrityGuard, PatchIntegrityConfig

__all__ = [
    "Severity",
    "GuardResult",
    "GuardContext",
    "GuardAction",
    "Guard",
    "ForbiddenPathGuard",
    "ForbiddenPathConfig",
    "EgressAllowlistGuard",
    "EgressAllowlistConfig",
    "SecretLeakGuard",
    "SecretLeakConfig",
    "PatchIntegrityGuard",
    "PatchIntegrityConfig",
]
```

**Step 5: Run tests to verify they pass**

Run: `cd /Users/connor/Medica/clawdstrike-ws9-python/packages/hush-py && python -m pytest tests/test_patch_integrity.py -v`
Expected: All tests PASS

**Step 6: Commit**

```bash
git add packages/hush-py/src/hush/guards/
git add packages/hush-py/tests/test_patch_integrity.py
git commit -m "feat(hush-py): add PatchIntegrityGuard"
```

---

## Task 9: McpTool Guard

**Files:**
- Create: `packages/hush-py/src/hush/guards/mcp_tool.py`
- Create: `packages/hush-py/tests/test_mcp_tool.py`

**Step 1: Write failing tests**

```python
"""Tests for McpToolGuard."""

import pytest
from hush.guards.mcp_tool import McpToolGuard, McpToolConfig
from hush.guards.base import GuardAction, GuardContext, Severity


class TestMcpToolConfig:
    def test_default_config(self) -> None:
        config = McpToolConfig()
        assert config.allow == []
        assert config.block == []
        assert config.default_action == "block"


class TestMcpToolGuard:
    def test_allow_listed_tool(self) -> None:
        config = McpToolConfig(
            allow=["read_file", "search", "list_*"],
            default_action="block",
        )
        guard = McpToolGuard(config)
        context = GuardContext()

        result = guard.check(
            GuardAction.mcp_tool("read_file", {"path": "/test"}),
            context,
        )
        assert result.allowed is True

    def test_allow_wildcard_pattern(self) -> None:
        config = McpToolConfig(
            allow=["list_*"],
            default_action="block",
        )
        guard = McpToolGuard(config)
        context = GuardContext()

        result = guard.check(
            GuardAction.mcp_tool("list_directory", {}),
            context,
        )
        assert result.allowed is True

        result = guard.check(
            GuardAction.mcp_tool("list_files", {}),
            context,
        )
        assert result.allowed is True

    def test_block_explicit_tool(self) -> None:
        config = McpToolConfig(
            allow=["*"],
            block=["execute_command"],
            default_action="allow",
        )
        guard = McpToolGuard(config)
        context = GuardContext()

        result = guard.check(
            GuardAction.mcp_tool("execute_command", {"cmd": "rm -rf /"}),
            context,
        )
        assert result.allowed is False
        assert result.severity == Severity.ERROR

    def test_default_block(self) -> None:
        config = McpToolConfig(
            allow=["safe_tool"],
            default_action="block",
        )
        guard = McpToolGuard(config)
        context = GuardContext()

        result = guard.check(
            GuardAction.mcp_tool("unknown_tool", {}),
            context,
        )
        assert result.allowed is False

    def test_default_allow(self) -> None:
        config = McpToolConfig(
            block=["dangerous_tool"],
            default_action="allow",
        )
        guard = McpToolGuard(config)
        context = GuardContext()

        result = guard.check(
            GuardAction.mcp_tool("unknown_tool", {}),
            context,
        )
        assert result.allowed is True

    def test_handles_mcp_tool_actions(self) -> None:
        guard = McpToolGuard()

        assert guard.handles(GuardAction.mcp_tool("tool", {})) is True
        assert guard.handles(GuardAction.file_access("/test")) is False

    def test_guard_name(self) -> None:
        guard = McpToolGuard()
        assert guard.name == "mcp_tool"

    def test_empty_allow_list_blocks_all(self) -> None:
        config = McpToolConfig(
            allow=[],
            default_action="block",
        )
        guard = McpToolGuard(config)
        context = GuardContext()

        result = guard.check(
            GuardAction.mcp_tool("any_tool", {}),
            context,
        )
        assert result.allowed is False
```

**Step 2: Run tests to verify they fail**

Run: `cd /Users/connor/Medica/clawdstrike-ws9-python/packages/hush-py && python -m pytest tests/test_mcp_tool.py -v`
Expected: FAIL with ImportError

**Step 3: Implement mcp_tool.py**

```python
"""MCP tool guard - controls which MCP tools can be invoked."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import List, Optional

from hush.guards.base import Guard, GuardAction, GuardContext, GuardResult, Severity


@dataclass
class McpToolConfig:
    """Configuration for McpToolGuard."""

    allow: List[str] = field(default_factory=list)
    block: List[str] = field(default_factory=list)
    default_action: str = "block"  # "block" or "allow"


class McpToolGuard(Guard):
    """Guard that controls MCP tool invocation."""

    def __init__(self, config: Optional[McpToolConfig] = None) -> None:
        self._config = config or McpToolConfig()

    @property
    def name(self) -> str:
        return "mcp_tool"

    def handles(self, action: GuardAction) -> bool:
        return action.action_type == "mcp_tool"

    def _matches_any(self, tool: str, patterns: List[str]) -> bool:
        """Check if tool name matches any pattern."""
        return any(fnmatch.fnmatch(tool, pattern) for pattern in patterns)

    def check(self, action: GuardAction, context: GuardContext) -> GuardResult:
        """Check if MCP tool invocation is allowed.

        Args:
            action: The action to check
            context: Execution context

        Returns:
            GuardResult
        """
        if not self.handles(action):
            return GuardResult.allow(self.name)

        tool = action.tool
        if tool is None:
            return GuardResult.allow(self.name)

        # Check block list first (takes precedence)
        if self._matches_any(tool, self._config.block):
            return GuardResult.block(
                self.name,
                Severity.ERROR,
                f"MCP tool explicitly blocked: {tool}",
            ).with_details({
                "tool": tool,
                "reason": "explicitly_blocked",
            })

        # Check allow list
        if self._matches_any(tool, self._config.allow):
            return GuardResult.allow(self.name)

        # Apply default action
        if self._config.default_action == "allow":
            return GuardResult.allow(self.name)

        return GuardResult.block(
            self.name,
            Severity.ERROR,
            f"MCP tool not in allowlist: {tool}",
        ).with_details({
            "tool": tool,
            "reason": "not_in_allowlist",
        })


__all__ = ["McpToolGuard", "McpToolConfig"]
```

**Step 4: Update guards/__init__.py (final version)**

```python
"""Security guards for clawdstrike.

Guards implement checks that can allow, block, or log actions.
"""

from hush.guards.base import (
    Severity,
    GuardResult,
    GuardContext,
    GuardAction,
    Guard,
)
from hush.guards.forbidden_path import ForbiddenPathGuard, ForbiddenPathConfig
from hush.guards.egress_allowlist import EgressAllowlistGuard, EgressAllowlistConfig
from hush.guards.secret_leak import SecretLeakGuard, SecretLeakConfig
from hush.guards.patch_integrity import PatchIntegrityGuard, PatchIntegrityConfig
from hush.guards.mcp_tool import McpToolGuard, McpToolConfig

__all__ = [
    # Base types
    "Severity",
    "GuardResult",
    "GuardContext",
    "GuardAction",
    "Guard",
    # Guards
    "ForbiddenPathGuard",
    "ForbiddenPathConfig",
    "EgressAllowlistGuard",
    "EgressAllowlistConfig",
    "SecretLeakGuard",
    "SecretLeakConfig",
    "PatchIntegrityGuard",
    "PatchIntegrityConfig",
    "McpToolGuard",
    "McpToolConfig",
]
```

**Step 5: Run tests to verify they pass**

Run: `cd /Users/connor/Medica/clawdstrike-ws9-python/packages/hush-py && python -m pytest tests/test_mcp_tool.py -v`
Expected: All tests PASS

**Step 6: Commit**

```bash
git add packages/hush-py/src/hush/guards/
git add packages/hush-py/tests/test_mcp_tool.py
git commit -m "feat(hush-py): add McpToolGuard"
```

---

## Task 10: Policy Engine

**Files:**
- Create: `packages/hush-py/src/hush/policy.py`
- Create: `packages/hush-py/tests/test_policy.py`

**Step 1: Write failing tests**

```python
"""Tests for hush.policy module."""

import pytest
from hush.policy import Policy, PolicyEngine, PolicySettings, GuardConfigs


class TestPolicy:
    def test_default_policy(self) -> None:
        policy = Policy()
        assert policy.version == "1.0.0"
        assert policy.name == ""

    def test_policy_from_yaml(self, sample_policy_yaml: str) -> None:
        policy = Policy.from_yaml(sample_policy_yaml)
        assert policy.version == "1.0.0"
        assert policy.name == "test-policy"
        assert policy.guards.forbidden_path is not None
        assert "**/.ssh/**" in policy.guards.forbidden_path.patterns

    def test_policy_to_yaml(self) -> None:
        policy = Policy(
            version="1.0.0",
            name="test",
            description="Test policy",
        )
        yaml_str = policy.to_yaml()
        assert "version:" in yaml_str
        assert "name:" in yaml_str

    def test_policy_roundtrip(self) -> None:
        original = Policy(
            version="2.0.0",
            name="roundtrip-test",
            description="Testing roundtrip",
        )
        yaml_str = original.to_yaml()
        restored = Policy.from_yaml(yaml_str)
        assert restored.version == original.version
        assert restored.name == original.name


class TestGuardConfigs:
    def test_default_configs(self) -> None:
        configs = GuardConfigs()
        assert configs.forbidden_path is None
        assert configs.egress_allowlist is None

    def test_from_dict(self) -> None:
        configs = GuardConfigs.from_dict({
            "forbidden_path": {
                "patterns": ["**/.secret/**"],
            },
            "egress_allowlist": {
                "allow": ["api.example.com"],
            },
        })
        assert configs.forbidden_path is not None
        assert configs.egress_allowlist is not None


class TestPolicySettings:
    def test_default_settings(self) -> None:
        settings = PolicySettings()
        assert settings.fail_fast is False
        assert settings.verbose_logging is False


class TestPolicyEngine:
    def test_create_from_policy(self, sample_policy_yaml: str) -> None:
        policy = Policy.from_yaml(sample_policy_yaml)
        engine = PolicyEngine(policy)

        assert len(engine.guards) == 5  # All 5 guards

    def test_check_allowed_action(self, sample_policy_yaml: str) -> None:
        from hush.guards.base import GuardAction, GuardContext

        policy = Policy.from_yaml(sample_policy_yaml)
        engine = PolicyEngine(policy)
        context = GuardContext()

        results = engine.check(
            GuardAction.file_access("/app/src/main.py"),
            context,
        )

        # All guards should allow this
        assert all(r.allowed for r in results)

    def test_check_forbidden_action(self, sample_policy_yaml: str) -> None:
        from hush.guards.base import GuardAction, GuardContext

        policy = Policy.from_yaml(sample_policy_yaml)
        engine = PolicyEngine(policy)
        context = GuardContext()

        results = engine.check(
            GuardAction.file_access("/home/user/.ssh/id_rsa"),
            context,
        )

        # At least one guard should block
        assert any(not r.allowed for r in results)

    def test_fail_fast_mode(self, sample_policy_yaml: str) -> None:
        from hush.guards.base import GuardAction, GuardContext

        policy = Policy.from_yaml(sample_policy_yaml)
        policy.settings.fail_fast = True
        engine = PolicyEngine(policy)
        context = GuardContext()

        # With fail_fast, should stop at first violation
        results = engine.check(
            GuardAction.file_access("/home/user/.ssh/id_rsa"),
            context,
        )

        # Should have exactly one blocking result
        blocked = [r for r in results if not r.allowed]
        assert len(blocked) >= 1
```

**Step 2: Run tests to verify they fail**

Run: `cd /Users/connor/Medica/clawdstrike-ws9-python/packages/hush-py && python -m pytest tests/test_policy.py -v`
Expected: FAIL with ImportError

**Step 3: Implement policy.py**

```python
"""Policy loading and evaluation.

Provides Policy loading from YAML and PolicyEngine for running guards.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import yaml

from hush.guards.base import Guard, GuardAction, GuardContext, GuardResult
from hush.guards.forbidden_path import ForbiddenPathGuard, ForbiddenPathConfig
from hush.guards.egress_allowlist import EgressAllowlistGuard, EgressAllowlistConfig
from hush.guards.secret_leak import SecretLeakGuard, SecretLeakConfig
from hush.guards.patch_integrity import PatchIntegrityGuard, PatchIntegrityConfig
from hush.guards.mcp_tool import McpToolGuard, McpToolConfig


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
    egress_allowlist: Optional[EgressAllowlistConfig] = None
    secret_leak: Optional[SecretLeakConfig] = None
    patch_integrity: Optional[PatchIntegrityConfig] = None
    mcp_tool: Optional[McpToolConfig] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> GuardConfigs:
        """Create from dictionary."""
        return cls(
            forbidden_path=ForbiddenPathConfig(**data["forbidden_path"])
                if "forbidden_path" in data else None,
            egress_allowlist=EgressAllowlistConfig(**data["egress_allowlist"])
                if "egress_allowlist" in data else None,
            secret_leak=SecretLeakConfig(**data["secret_leak"])
                if "secret_leak" in data else None,
            patch_integrity=PatchIntegrityConfig(**data["patch_integrity"])
                if "patch_integrity" in data else None,
            mcp_tool=McpToolConfig(**data["mcp_tool"])
                if "mcp_tool" in data else None,
        )


@dataclass
class Policy:
    """Complete policy configuration."""

    version: str = "1.0.0"
    name: str = ""
    description: str = ""
    guards: GuardConfigs = field(default_factory=GuardConfigs)
    settings: PolicySettings = field(default_factory=PolicySettings)

    @classmethod
    def from_yaml(cls, yaml_str: str) -> Policy:
        """Parse from YAML string."""
        data = yaml.safe_load(yaml_str) or {}

        guards_data = data.get("guards", {})
        settings_data = data.get("settings", {})

        return cls(
            version=data.get("version", "1.0.0"),
            name=data.get("name", ""),
            description=data.get("description", ""),
            guards=GuardConfigs.from_dict(guards_data) if guards_data else GuardConfigs(),
            settings=PolicySettings(**settings_data) if settings_data else PolicySettings(),
        )

    @classmethod
    def from_yaml_file(cls, path: str) -> Policy:
        """Load from YAML file."""
        with open(path, "r") as f:
            return cls.from_yaml(f.read())

    def to_yaml(self) -> str:
        """Export to YAML string."""
        data: Dict[str, Any] = {
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

        # Only include configured guards
        if self.guards.forbidden_path:
            data["guards"]["forbidden_path"] = {
                "patterns": self.guards.forbidden_path.patterns,
                "exceptions": self.guards.forbidden_path.exceptions,
            }
        if self.guards.egress_allowlist:
            data["guards"]["egress_allowlist"] = {
                "allow": self.guards.egress_allowlist.allow,
                "block": self.guards.egress_allowlist.block,
                "default_action": self.guards.egress_allowlist.default_action,
            }
        if self.guards.secret_leak:
            data["guards"]["secret_leak"] = {
                "secrets": self.guards.secret_leak.secrets,
                "enabled": self.guards.secret_leak.enabled,
            }
        if self.guards.patch_integrity:
            data["guards"]["patch_integrity"] = {
                "max_additions": self.guards.patch_integrity.max_additions,
                "max_deletions": self.guards.patch_integrity.max_deletions,
                "require_balance": self.guards.patch_integrity.require_balance,
                "max_imbalance_ratio": self.guards.patch_integrity.max_imbalance_ratio,
            }
        if self.guards.mcp_tool:
            data["guards"]["mcp_tool"] = {
                "allow": self.guards.mcp_tool.allow,
                "block": self.guards.mcp_tool.block,
                "default_action": self.guards.mcp_tool.default_action,
            }

        return yaml.dump(data, default_flow_style=False, sort_keys=False)


class PolicyEngine:
    """Engine for evaluating actions against a policy."""

    def __init__(self, policy: Policy) -> None:
        self.policy = policy
        self.guards = self._create_guards()

    def _create_guards(self) -> List[Guard]:
        """Create guard instances from policy configuration."""
        guards: List[Guard] = []

        # Create guards with config if provided, otherwise use defaults
        guards.append(
            ForbiddenPathGuard(self.policy.guards.forbidden_path)
            if self.policy.guards.forbidden_path
            else ForbiddenPathGuard()
        )
        guards.append(
            EgressAllowlistGuard(self.policy.guards.egress_allowlist)
            if self.policy.guards.egress_allowlist
            else EgressAllowlistGuard()
        )
        guards.append(
            SecretLeakGuard(self.policy.guards.secret_leak)
            if self.policy.guards.secret_leak
            else SecretLeakGuard()
        )
        guards.append(
            PatchIntegrityGuard(self.policy.guards.patch_integrity)
            if self.policy.guards.patch_integrity
            else PatchIntegrityGuard()
        )
        guards.append(
            McpToolGuard(self.policy.guards.mcp_tool)
            if self.policy.guards.mcp_tool
            else McpToolGuard()
        )

        return guards

    def check(self, action: GuardAction, context: GuardContext) -> List[GuardResult]:
        """Check an action against all guards.

        Args:
            action: The action to check
            context: Execution context

        Returns:
            List of GuardResults from all applicable guards
        """
        results: List[GuardResult] = []

        for guard in self.guards:
            if guard.handles(action):
                result = guard.check(action, context)
                results.append(result)

                # Stop early if fail_fast and action is blocked
                if self.policy.settings.fail_fast and not result.allowed:
                    break

        return results

    def is_allowed(self, action: GuardAction, context: GuardContext) -> bool:
        """Check if an action is allowed (convenience method).

        Args:
            action: The action to check
            context: Execution context

        Returns:
            True if all guards allow the action
        """
        results = self.check(action, context)
        return all(r.allowed for r in results)


__all__ = [
    "Policy",
    "PolicyEngine",
    "PolicySettings",
    "GuardConfigs",
]
```

**Step 4: Run tests to verify they pass**

Run: `cd /Users/connor/Medica/clawdstrike-ws9-python/packages/hush-py && python -m pytest tests/test_policy.py -v`
Expected: All tests PASS

**Step 5: Commit**

```bash
git add packages/hush-py/src/hush/policy.py
git add packages/hush-py/tests/test_policy.py
git commit -m "feat(hush-py): add Policy and PolicyEngine"
```

---

## Task 11: Update Main Package Exports and Final Tests

**Files:**
- Modify: `packages/hush-py/src/hush/__init__.py`
- Create: `packages/hush-py/tests/test_integration.py`

**Step 1: Update __init__.py with all exports**

```python
"""Hush - Python SDK for clawdstrike security verification."""

from hush.core import sha256, keccak256, verify_signature, sign_message, generate_keypair
from hush.receipt import Receipt, SignedReceipt
from hush.policy import Policy, PolicyEngine, PolicySettings, GuardConfigs
from hush.guards import (
    Severity,
    GuardResult,
    GuardContext,
    GuardAction,
    Guard,
    ForbiddenPathGuard,
    ForbiddenPathConfig,
    EgressAllowlistGuard,
    EgressAllowlistConfig,
    SecretLeakGuard,
    SecretLeakConfig,
    PatchIntegrityGuard,
    PatchIntegrityConfig,
    McpToolGuard,
    McpToolConfig,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # Core crypto
    "sha256",
    "keccak256",
    "verify_signature",
    "sign_message",
    "generate_keypair",
    # Receipt
    "Receipt",
    "SignedReceipt",
    # Policy
    "Policy",
    "PolicyEngine",
    "PolicySettings",
    "GuardConfigs",
    # Guards base
    "Severity",
    "GuardResult",
    "GuardContext",
    "GuardAction",
    "Guard",
    # Guards
    "ForbiddenPathGuard",
    "ForbiddenPathConfig",
    "EgressAllowlistGuard",
    "EgressAllowlistConfig",
    "SecretLeakGuard",
    "SecretLeakConfig",
    "PatchIntegrityGuard",
    "PatchIntegrityConfig",
    "McpToolGuard",
    "McpToolConfig",
]
```

**Step 2: Create integration tests**

```python
"""Integration tests for hush SDK."""

import pytest
from hush import (
    Policy,
    PolicyEngine,
    Receipt,
    SignedReceipt,
    GuardAction,
    GuardContext,
    generate_keypair,
    sha256,
)


class TestFullWorkflow:
    def test_policy_guard_workflow(self, sample_policy_yaml: str) -> None:
        """Test complete policy loading and guard evaluation workflow."""
        # Load policy
        policy = Policy.from_yaml(sample_policy_yaml)
        engine = PolicyEngine(policy)
        context = GuardContext(cwd="/app", session_id="test-session")

        # Test various actions
        assert engine.is_allowed(
            GuardAction.file_access("/app/src/main.py"),
            context,
        )

        assert not engine.is_allowed(
            GuardAction.file_access("/home/user/.ssh/id_rsa"),
            context,
        )

        assert engine.is_allowed(
            GuardAction.network_egress("api.example.com", 443),
            context,
        )

        assert not engine.is_allowed(
            GuardAction.network_egress("unknown.com", 443),
            context,
        )

    def test_receipt_signing_workflow(self) -> None:
        """Test complete receipt creation and verification workflow."""
        # Create a receipt
        receipt = Receipt(
            id="run-integration-test",
            artifact_root="0x" + "ab" * 32,
            event_count=100,
            metadata={
                "task": "integration-test",
                "passed": True,
            },
        )

        # Sign it
        private_key, public_key = generate_keypair()
        signed = SignedReceipt.sign(receipt, private_key, public_key)

        # Verify
        assert signed.verify() is True

        # Serialize and restore
        json_str = signed.to_json()
        restored = SignedReceipt.from_json(json_str)

        # Verify restored receipt
        assert restored.verify() is True
        assert restored.receipt.id == "run-integration-test"
        assert restored.receipt.metadata["passed"] is True

    def test_hash_consistency(self) -> None:
        """Test that hashing is consistent."""
        data = b"test data for hashing"

        hash1 = sha256(data)
        hash2 = sha256(data)

        assert hash1 == hash2

        # Receipt hashing should be deterministic
        receipt = Receipt(
            id="test",
            artifact_root="0x00",
            event_count=1,
            metadata={},
        )

        hash1 = receipt.hash()
        hash2 = receipt.hash()

        assert hash1 == hash2


class TestVersionInfo:
    def test_version_available(self) -> None:
        import hush
        assert hush.__version__ == "0.1.0"
```

**Step 3: Run all tests**

Run: `cd /Users/connor/Medica/clawdstrike-ws9-python/packages/hush-py && python -m pytest tests/ -v --tb=short`
Expected: All tests PASS

**Step 4: Run type checking**

Run: `cd /Users/connor/Medica/clawdstrike-ws9-python/packages/hush-py && pip install mypy && python -m mypy src/hush --ignore-missing-imports`
Expected: No errors

**Step 5: Commit**

```bash
git add packages/hush-py/
git commit -m "feat(hush-py): complete Python SDK with all guards and policy engine"
```

---

## Task 12: Optional PyO3 Native Bindings (Stretch Goal)

**Files:**
- Create: `packages/hush-py/hush-native/Cargo.toml`
- Create: `packages/hush-py/hush-native/src/lib.rs`
- Create: `packages/hush-py/hush-native/pyproject.toml`

**Step 1: Create Cargo.toml**

```toml
[package]
name = "hush-native"
version = "0.1.0"
edition = "2021"

[lib]
name = "hush_native"
crate-type = ["cdylib"]

[dependencies]
pyo3 = { version = "0.20", features = ["extension-module"] }
hush-core = { path = "../../../crates/hush-core" }

[build-dependencies]
pyo3-build-config = "0.20"
```

**Step 2: Create src/lib.rs**

```rust
use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;

/// Verify a signed receipt using native Rust implementation.
#[pyfunction]
fn verify_receipt_native(receipt_json: &str, signature_hex: &str, public_key_hex: &str) -> PyResult<bool> {
    use hush_core::signing::verify_ed25519;

    let signature = hex::decode(signature_hex.trim_start_matches("0x"))
        .map_err(|e| PyValueError::new_err(format!("Invalid signature hex: {}", e)))?;

    let public_key = hex::decode(public_key_hex.trim_start_matches("0x"))
        .map_err(|e| PyValueError::new_err(format!("Invalid public key hex: {}", e)))?;

    let message = receipt_json.as_bytes();

    match verify_ed25519(message, &signature, &public_key) {
        Ok(valid) => Ok(valid),
        Err(_) => Ok(false),
    }
}

/// Compute SHA-256 hash using native implementation.
#[pyfunction]
fn sha256_native(data: &[u8]) -> PyResult<Vec<u8>> {
    use hush_core::hashing::sha256;
    Ok(sha256(data).to_vec())
}

/// Compute Merkle root from leaf hashes.
#[pyfunction]
fn merkle_root_native(leaves: Vec<Vec<u8>>) -> PyResult<Vec<u8>> {
    use hush_core::merkle::MerkleTree;

    let tree = MerkleTree::from_leaves(&leaves);
    Ok(tree.root().to_vec())
}

/// Python module definition.
#[pymodule]
fn hush_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(verify_receipt_native, m)?)?;
    m.add_function(wrap_pyfunction!(sha256_native, m)?)?;
    m.add_function(wrap_pyfunction!(merkle_root_native, m)?)?;
    Ok(())
}
```

**Step 3: Create pyproject.toml for maturin**

```toml
[build-system]
requires = ["maturin>=1.4,<2.0"]
build-backend = "maturin"

[project]
name = "hush-native"
version = "0.1.0"
description = "Native Rust bindings for hush SDK"
requires-python = ">=3.10"

[tool.maturin]
features = ["pyo3/extension-module"]
```

**Step 4: Build with maturin (if available)**

Run: `cd /Users/connor/Medica/clawdstrike-ws9-python/packages/hush-py/hush-native && maturin develop`
Expected: Build succeeds (optional, depends on Rust toolchain)

**Step 5: Commit**

```bash
git add packages/hush-py/hush-native/
git commit -m "feat(hush-py): add optional PyO3 native bindings scaffold"
```

---

## Final Verification

**Step 1: Run full test suite**

Run: `cd /Users/connor/Medica/clawdstrike-ws9-python/packages/hush-py && python -m pytest tests/ -v --cov=hush --cov-report=term-missing`
Expected: All tests pass, 80%+ coverage

**Step 2: Test pip install**

Run: `cd /Users/connor/Medica/clawdstrike-ws9-python/packages/hush-py && pip install -e .`
Expected: Install succeeds

**Step 3: Test import**

Run: `python -c "import hush; print(hush.__version__)"`
Expected: Prints "0.1.0"

**Step 4: Final commit**

```bash
git add .
git commit -m "chore(hush-py): finalize SDK with tests and documentation"
```

---

## Summary

This plan implements the hush-py Python SDK with:

1. **Core crypto module** - SHA-256, Keccak-256, Ed25519 signatures using PyNaCl
2. **Receipt types** - Receipt and SignedReceipt for verification artifacts
3. **5 Security guards** - ForbiddenPath, EgressAllowlist, SecretLeak, PatchIntegrity, McpTool
4. **Policy engine** - YAML-based policy loading and guard orchestration
5. **Optional PyO3 bindings** - Native Rust acceleration for crypto operations

All implementations follow TDD with comprehensive test coverage.
