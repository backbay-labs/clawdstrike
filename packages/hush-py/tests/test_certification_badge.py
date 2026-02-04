from __future__ import annotations

import base64

from clawdstrike.canonical import canonicalize
from clawdstrike.core import generate_keypair, sign_message
from clawdstrike.certification_badge import verify_certification_badge


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def test_verify_certification_badge_roundtrip() -> None:
    private_key, public_key = generate_keypair()

    badge = {
        "certificationId": "cert_test_1",
        "version": "1.0.0",
        "subject": {"type": "agent", "id": "agent_1", "name": "test-agent"},
        "certification": {
            "tier": "silver",
            "issueDate": "2026-02-04T00:00:00Z",
            "expiryDate": "2026-03-06T00:00:00Z",
            "frameworks": ["soc2"],
        },
        "policy": {"hash": "sha256:deadbeef", "version": "1.0.0", "ruleset": "clawdstrike:strict"},
        "evidence": {"receiptCount": 0},
        "issuer": {
            "id": "iss_clawdstrike",
            "name": "Clawdstrike Certification Authority",
            "publicKey": _b64url_encode(public_key),
            "signature": "",
            "signedAt": "2026-02-04T00:00:00Z",
        },
    }

    issuer = badge["issuer"]
    unsigned = {
        "certificationId": badge["certificationId"],
        "version": badge["version"],
        "subject": badge["subject"],
        "certification": badge["certification"],
        "policy": badge["policy"],
        "evidence": badge["evidence"],
        "issuer": {
            "id": issuer["id"],
            "name": issuer["name"],
            "publicKey": issuer["publicKey"],
            "signedAt": issuer["signedAt"],
        },
    }
    msg = canonicalize(unsigned).encode("utf-8")
    sig = sign_message(msg, private_key)
    badge["issuer"]["signature"] = _b64url_encode(sig)

    assert verify_certification_badge(badge) is True

    badge_bad = {**badge, "subject": {**badge["subject"], "name": "tampered"}}
    assert verify_certification_badge(badge_bad) is False

