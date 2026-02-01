"""Receipt types and verification.

Provides Receipt and SignedReceipt types for verification artifacts.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Any, Dict

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
