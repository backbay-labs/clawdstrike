from __future__ import annotations

import base64
from typing import Any

from clawdstrike.canonical import canonicalize
from clawdstrike.core import verify_signature


def _b64url_decode(s: str) -> bytes:
    s = s.strip()
    padding = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode(s + padding)


def verify_certification_badge(badge: dict[str, Any]) -> bool:
    """Verify a Clawdstrike/OpenClaw certification badge signature.

    The signature is Ed25519 over RFC 8785 canonical JSON of the badge payload,
    excluding `issuer.signature`.
    """
    try:
        issuer = badge.get("issuer") or {}
        unsigned_issuer = {
            "id": issuer.get("id"),
            "name": issuer.get("name"),
            "publicKey": issuer.get("publicKey"),
            "signedAt": issuer.get("signedAt"),
        }

        unsigned = {
            "certificationId": badge.get("certificationId"),
            "version": badge.get("version"),
            "subject": badge.get("subject"),
            "certification": badge.get("certification"),
            "policy": badge.get("policy"),
            "evidence": badge.get("evidence"),
            "issuer": unsigned_issuer,
        }

        canonical = canonicalize(unsigned)
        message = canonical.encode("utf-8")

        public_key = _b64url_decode(str(issuer.get("publicKey") or ""))
        signature = _b64url_decode(str(issuer.get("signature") or ""))
        if len(public_key) != 32 or len(signature) != 64:
            return False

        return verify_signature(message, signature, public_key)
    except Exception:
        return False


__all__ = ["verify_certification_badge"]

