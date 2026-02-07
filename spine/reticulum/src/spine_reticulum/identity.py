"""Reticulum destination hash binding to Aegis Ed25519 identity.

Uses Model A (separate keys): the Aegis Ed25519 signing key is distinct from
the Reticulum Curve25519 identity key.  Binding is established through a
signed ``node_attestation`` fact carried in a Spine envelope.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

from nacl.signing import SigningKey


def create_identity_binding(
    aegis_signing_key: SigningKey,
    reticulum_destination_hash: str,
    capabilities: Optional[list[str]] = None,
    announce_period_secs: int = 300,
) -> dict[str, Any]:
    """Create a ``node_attestation`` fact binding an Aegis identity to a
    Reticulum destination hash.

    Parameters
    ----------
    aegis_signing_key:
        The Ed25519 signing key for this node's Aegis identity.
    reticulum_destination_hash:
        Hex string of the Reticulum destination hash (without ``0x`` prefix).
    capabilities:
        Supported capabilities, defaults to ``["envelopes", "heads", "sync", "proofs"]``.
    announce_period_secs:
        How often this node announces on Reticulum, in seconds.
    """
    if capabilities is None:
        capabilities = ["envelopes", "heads", "sync", "proofs"]

    pubkey_hex = aegis_signing_key.verify_key.encode().hex()
    dest_hash = reticulum_destination_hash.removeprefix("0x")

    return {
        "schema": "clawdstrike.spine.fact.node_attestation.v1",
        "fact_id": f"na_{uuid4()}",
        "node_id": f"aegis:ed25519:{pubkey_hex}",
        "transports": {
            "reticulum": {
                "profile": "aegis.spine.reticulum.v1",
                "destination_hash": f"0x{dest_hash}",
                "announce_period_secs": announce_period_secs,
                "supports": capabilities,
            },
        },
        "issued_at": datetime.now(timezone.utc).isoformat(),
    }


def verify_identity_binding(
    envelope: dict[str, Any],
    expected_destination_hash: str,
) -> bool:
    """Check that a ``node_attestation`` envelope binds the envelope's issuer
    to the given Reticulum destination hash.

    This does **not** verify the envelope signature -- call ``verify_envelope``
    first.
    """
    fact = envelope.get("fact", {})
    if fact.get("schema") != "clawdstrike.spine.fact.node_attestation.v1":
        return False

    reticulum_transport = fact.get("transports", {}).get("reticulum", {})
    bound_hash = reticulum_transport.get("destination_hash", "")
    expected = expected_destination_hash.removeprefix("0x").lower()
    actual = bound_hash.removeprefix("0x").lower()
    return actual == expected
