"""Receipt types and signing for attestation.

This module implements the Rust `hush-core` receipt schema and signing contract:
- RFC 8785 (JCS) canonical JSON for signing/hashing
- Strict `version` validation (schema boundary)
- Deny-unknown-fields parsing to prevent silent drift
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from hush.canonical import canonicalize
from hush.core import keccak256, sha256, sign_message, verify_signature

RECEIPT_SCHEMA_VERSION = "1.0.0"


def _parse_semver_strict(version: str) -> Optional[tuple[int, int, int]]:
    parts = version.split(".")
    if len(parts) != 3:
        return None

    out: list[int] = []
    for part in parts:
        if not part:
            return None
        if len(part) > 1 and part.startswith("0"):
            return None
        if not part.isdigit():
            return None
        out.append(int(part))

    return out[0], out[1], out[2]


def validate_receipt_version(version: str) -> None:
    if _parse_semver_strict(version) is None:
        raise ValueError(f"Invalid receipt version: {version}")
    if version != RECEIPT_SCHEMA_VERSION:
        raise ValueError(
            f"Unsupported receipt version: {version} (supported: {RECEIPT_SCHEMA_VERSION})"
        )


def _normalize_hex(s: str, bytes_len: int, prefix: str, label: str) -> str:
    raw = s[2:] if s.startswith("0x") else s
    if len(raw) != bytes_len * 2:
        raise ValueError(f"{label} must be {bytes_len} bytes")
    try:
        bytes.fromhex(raw)
    except ValueError as e:
        raise ValueError(f"{label} must be hex") from e
    raw = raw.lower()
    return f"0x{raw}" if prefix == "0x" else raw


def normalize_hash(s: str) -> str:
    return _normalize_hex(s, 32, "0x", "hash")


def normalize_public_key(s: str) -> str:
    return _normalize_hex(s, 32, "none", "public key")


def normalize_signature(s: str) -> str:
    return _normalize_hex(s, 64, "none", "signature")


def _deny_unknown_fields(data: Dict[str, Any], allowed: set[str], label: str) -> None:
    unknown = set(data.keys()) - allowed
    if unknown:
        key = sorted(unknown)[0]
        raise ValueError(f"Unknown {label} field: {key}")


@dataclass(frozen=True)
class Verdict:
    passed: bool
    gate_id: Optional[str] = None
    scores: Optional[Any] = None
    threshold: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"passed": self.passed}
        if self.gate_id is not None:
            out["gate_id"] = self.gate_id
        if self.scores is not None:
            out["scores"] = self.scores
        if self.threshold is not None:
            out["threshold"] = self.threshold
        return out

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Verdict:
        _deny_unknown_fields(data, {"passed", "gate_id", "scores", "threshold"}, "verdict")
        passed = data.get("passed")
        if not isinstance(passed, bool):
            raise ValueError("verdict.passed must be a boolean")
        gate_id = data.get("gate_id")
        if gate_id is not None and not isinstance(gate_id, str):
            raise ValueError("verdict.gate_id must be a string")
        threshold = data.get("threshold")
        if threshold is not None:
            if not isinstance(threshold, (int, float)) or threshold != threshold:
                raise ValueError("verdict.threshold must be a finite number")
            threshold = float(threshold)
        return cls(passed=passed, gate_id=gate_id, scores=data.get("scores"), threshold=threshold)


@dataclass(frozen=True)
class ViolationRef:
    guard: str
    severity: str
    message: str
    action: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "guard": self.guard,
            "severity": self.severity,
            "message": self.message,
        }
        if self.action is not None:
            out["action"] = self.action
        return out

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ViolationRef:
        _deny_unknown_fields(data, {"guard", "severity", "message", "action"}, "violation")
        guard = data.get("guard")
        severity = data.get("severity")
        message = data.get("message")
        if not isinstance(guard, str):
            raise ValueError("violation.guard must be a string")
        if not isinstance(severity, str):
            raise ValueError("violation.severity must be a string")
        if not isinstance(message, str):
            raise ValueError("violation.message must be a string")
        action = data.get("action")
        if action is not None and not isinstance(action, str):
            raise ValueError("violation.action must be a string")
        return cls(guard=guard, severity=severity, message=message, action=action)


@dataclass(frozen=True)
class Provenance:
    clawdstrike_version: Optional[str] = None
    provider: Optional[str] = None
    policy_hash: Optional[str] = None
    ruleset: Optional[str] = None
    violations: List[ViolationRef] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        if self.clawdstrike_version is not None:
            out["clawdstrike_version"] = self.clawdstrike_version
        if self.provider is not None:
            out["provider"] = self.provider
        if self.policy_hash is not None:
            out["policy_hash"] = normalize_hash(self.policy_hash)
        if self.ruleset is not None:
            out["ruleset"] = self.ruleset
        if self.violations:
            out["violations"] = [v.to_dict() for v in self.violations]
        return out

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Provenance:
        _deny_unknown_fields(
            data,
            {"clawdstrike_version", "provider", "policy_hash", "ruleset", "violations"},
            "provenance",
        )
        clawdstrike_version = data.get("clawdstrike_version")
        provider = data.get("provider")
        policy_hash = data.get("policy_hash")
        ruleset = data.get("ruleset")
        violations_raw = data.get("violations", [])

        if clawdstrike_version is not None and not isinstance(clawdstrike_version, str):
            raise ValueError("provenance.clawdstrike_version must be a string")
        if provider is not None and not isinstance(provider, str):
            raise ValueError("provenance.provider must be a string")
        if policy_hash is not None:
            if not isinstance(policy_hash, str):
                raise ValueError("provenance.policy_hash must be a string")
            policy_hash = normalize_hash(policy_hash)
        if ruleset is not None and not isinstance(ruleset, str):
            raise ValueError("provenance.ruleset must be a string")
        if not isinstance(violations_raw, list):
            raise ValueError("provenance.violations must be a list")
        violations = [ViolationRef.from_dict(v) for v in violations_raw]
        return cls(
            clawdstrike_version=clawdstrike_version,
            provider=provider,
            policy_hash=policy_hash,
            ruleset=ruleset,
            violations=violations,
        )


@dataclass(frozen=True)
class Receipt:
    version: str
    timestamp: str
    content_hash: str
    verdict: Verdict
    receipt_id: Optional[str] = None
    provenance: Optional[Provenance] = None
    metadata: Optional[Any] = None

    @classmethod
    def new(cls, content_hash: str, verdict: Verdict) -> Receipt:
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        return cls(
            version=RECEIPT_SCHEMA_VERSION,
            receipt_id=None,
            timestamp=now,
            content_hash=normalize_hash(content_hash),
            verdict=verdict,
            provenance=None,
            metadata=None,
        )

    def validate_version(self) -> None:
        validate_receipt_version(self.version)

    def to_dict(self) -> Dict[str, Any]:
        self.validate_version()
        out: Dict[str, Any] = {
            "version": self.version,
            "timestamp": self.timestamp,
            "content_hash": normalize_hash(self.content_hash),
            "verdict": self.verdict.to_dict(),
        }
        if self.receipt_id is not None:
            out["receipt_id"] = self.receipt_id
        if self.provenance is not None:
            out["provenance"] = self.provenance.to_dict()
        if self.metadata is not None:
            out["metadata"] = self.metadata
        return out

    def to_canonical_json(self) -> str:
        return canonicalize(self.to_dict())

    def to_json(self) -> str:
        return self.to_canonical_json()

    def hash_sha256(self) -> str:
        digest = sha256(self.to_canonical_json())
        return "0x" + digest.hex()

    def hash_keccak256(self) -> str:
        digest = keccak256(self.to_canonical_json())
        return "0x" + digest.hex()

    @classmethod
    def from_json(cls, json_str: str) -> Receipt:
        data = json.loads(json_str)
        if not isinstance(data, dict):
            raise ValueError("receipt JSON must be an object")
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Receipt:
        _deny_unknown_fields(
            data,
            {
                "version",
                "receipt_id",
                "timestamp",
                "content_hash",
                "verdict",
                "provenance",
                "metadata",
            },
            "receipt",
        )
        version = data.get("version")
        if not isinstance(version, str):
            raise ValueError("receipt.version must be a string")
        validate_receipt_version(version)

        timestamp = data.get("timestamp")
        if not isinstance(timestamp, str):
            raise ValueError("receipt.timestamp must be a string")

        content_hash = data.get("content_hash")
        if not isinstance(content_hash, str):
            raise ValueError("receipt.content_hash must be a string")

        verdict_raw = data.get("verdict")
        if not isinstance(verdict_raw, dict):
            raise ValueError("receipt.verdict must be an object")

        provenance_raw = data.get("provenance")
        provenance = None
        if provenance_raw is not None:
            if not isinstance(provenance_raw, dict):
                raise ValueError("receipt.provenance must be an object")
            provenance = Provenance.from_dict(provenance_raw)

        receipt_id = data.get("receipt_id")
        if receipt_id is not None and not isinstance(receipt_id, str):
            raise ValueError("receipt.receipt_id must be a string")

        return cls(
            version=version,
            receipt_id=receipt_id,
            timestamp=timestamp,
            content_hash=normalize_hash(content_hash),
            verdict=Verdict.from_dict(verdict_raw),
            provenance=provenance,
            metadata=data.get("metadata"),
        )


@dataclass(frozen=True)
class Signatures:
    signer: str
    cosigner: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"signer": normalize_signature(self.signer)}
        if self.cosigner is not None:
            out["cosigner"] = normalize_signature(self.cosigner)
        return out

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Signatures:
        _deny_unknown_fields(data, {"signer", "cosigner"}, "signatures")
        signer = data.get("signer")
        if not isinstance(signer, str):
            raise ValueError("signatures.signer must be a string")
        cosigner = data.get("cosigner")
        if cosigner is not None and not isinstance(cosigner, str):
            raise ValueError("signatures.cosigner must be a string")
        return cls(signer=normalize_signature(signer), cosigner=None if cosigner is None else normalize_signature(cosigner))


@dataclass(frozen=True)
class SignedReceipt:
    receipt: Receipt
    signatures: Signatures

    @classmethod
    def sign(cls, receipt: Receipt, private_key: bytes) -> SignedReceipt:
        receipt.validate_version()
        message = receipt.to_canonical_json().encode("utf-8")
        sig = sign_message(message, private_key).hex()
        return cls(receipt=receipt, signatures=Signatures(signer=sig))

    def add_cosigner(self, private_key: bytes) -> SignedReceipt:
        self.receipt.validate_version()
        message = self.receipt.to_canonical_json().encode("utf-8")
        sig = sign_message(message, private_key).hex()
        return SignedReceipt(receipt=self.receipt, signatures=Signatures(signer=self.signatures.signer, cosigner=sig))

    def to_dict(self) -> Dict[str, Any]:
        return {"receipt": self.receipt.to_dict(), "signatures": self.signatures.to_dict()}

    def to_canonical_json(self) -> str:
        return canonicalize(self.to_dict())

    def to_json(self) -> str:
        return self.to_canonical_json()

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SignedReceipt:
        _deny_unknown_fields(data, {"receipt", "signatures"}, "signed receipt")
        receipt_raw = data.get("receipt")
        sig_raw = data.get("signatures")
        if not isinstance(receipt_raw, dict):
            raise ValueError("signed_receipt.receipt must be an object")
        if not isinstance(sig_raw, dict):
            raise ValueError("signed_receipt.signatures must be an object")
        return cls(receipt=Receipt.from_dict(receipt_raw), signatures=Signatures.from_dict(sig_raw))

    @classmethod
    def from_json(cls, json_str: str) -> SignedReceipt:
        data = json.loads(json_str)
        if not isinstance(data, dict):
            raise ValueError("signed receipt JSON must be an object")
        return cls.from_dict(data)

    def verify(self, public_keys: PublicKeySet) -> VerificationResult:
        try:
            self.receipt.validate_version()
        except Exception as e:  # noqa: BLE001 - surface schema errors as verification failure
            return VerificationResult(
                valid=False,
                signer_valid=False,
                cosigner_valid=None,
                errors=[str(e)],
            )

        message = self.receipt.to_canonical_json().encode("utf-8")

        signer_sig = bytes.fromhex(normalize_signature(self.signatures.signer))
        signer_pk = bytes.fromhex(normalize_public_key(public_keys.signer))
        signer_valid = verify_signature(message, signer_sig, signer_pk)

        errors: List[str] = []
        if not signer_valid:
            errors.append("Invalid signer signature")

        cosigner_valid: Optional[bool] = None
        valid = signer_valid
        if self.signatures.cosigner is not None and public_keys.cosigner is not None:
            cosigner_sig = bytes.fromhex(normalize_signature(self.signatures.cosigner))
            cosigner_pk = bytes.fromhex(normalize_public_key(public_keys.cosigner))
            cosigner_valid = verify_signature(message, cosigner_sig, cosigner_pk)
            if not cosigner_valid:
                valid = False
                errors.append("Invalid cosigner signature")

        return VerificationResult(
            valid=valid,
            signer_valid=signer_valid,
            cosigner_valid=cosigner_valid,
            errors=errors,
        )


@dataclass(frozen=True)
class PublicKeySet:
    signer: str
    cosigner: Optional[str] = None


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    signer_valid: bool
    cosigner_valid: Optional[bool]
    errors: List[str]


__all__ = [
    "RECEIPT_SCHEMA_VERSION",
    "validate_receipt_version",
    "Receipt",
    "SignedReceipt",
    "Verdict",
    "Provenance",
    "ViolationRef",
    "Signatures",
    "PublicKeySet",
    "VerificationResult",
]
