"""Tests for NATS bridge disclosure policy and dedup ring."""

from __future__ import annotations

from spine_reticulum.gateway import DisclosurePolicy, _DeduplicatorRing


class TestDisclosurePolicy:
    def _policy(self) -> DisclosurePolicy:
        return DisclosurePolicy({
            "nats_to_reticulum": {
                "allowed": [
                    "clawdstrike.spine.fact.revocation.v1",
                    "clawdstrike.spine.fact.log_checkpoint.v1",
                    "clawdstrike.spine.fact.policy_delta.v1",
                    "clawdstrike.spine.fact.incident.v1",
                ],
                "blocked": [
                    "clawdstrike.spine.envelope.tetragon.*",
                    "aegisnet.hubble.*",
                ],
            },
            "reticulum_to_nats": {
                "allowed": [
                    "clawdstrike.spine.fact.revocation.v1",
                    "clawdstrike.spine.fact.incident.v1",
                    "clawdstrike.spine.fact.log_checkpoint.v1",
                    "clawdstrike.spine.fact.node_attestation.v1",
                ],
                "blocked": [
                    "clawdstrike.spine.fact.heartbeat.v1",
                ],
            },
        })

    def test_outbound_allows_revocation(self) -> None:
        p = self._policy()
        assert p.allows_outbound("clawdstrike.spine.fact.revocation.v1") is True

    def test_outbound_blocks_tetragon(self) -> None:
        p = self._policy()
        assert p.allows_outbound("clawdstrike.spine.envelope.tetragon.event") is False

    def test_outbound_blocks_hubble(self) -> None:
        p = self._policy()
        assert p.allows_outbound("aegisnet.hubble.flow") is False

    def test_outbound_blocks_unknown(self) -> None:
        """If allowed list is present, unknown schemas are blocked."""
        p = self._policy()
        assert p.allows_outbound("some.random.schema") is False

    def test_inbound_allows_incident(self) -> None:
        p = self._policy()
        assert p.allows_inbound("clawdstrike.spine.fact.incident.v1") is True

    def test_inbound_blocks_heartbeat(self) -> None:
        p = self._policy()
        assert p.allows_inbound("clawdstrike.spine.fact.heartbeat.v1") is False

    def test_inbound_blocks_unknown(self) -> None:
        p = self._policy()
        assert p.allows_inbound("some.unknown.schema") is False

    def test_empty_policy_allows_all(self) -> None:
        p = DisclosurePolicy({})
        assert p.allows_outbound("anything") is True
        assert p.allows_inbound("anything") is True

    def test_wildcard_block(self) -> None:
        p = DisclosurePolicy({
            "nats_to_reticulum": {
                "blocked": ["aegisnet.hubble.*"],
            },
        })
        assert p.allows_outbound("aegisnet.hubble.flow") is False
        assert p.allows_outbound("aegisnet.hubble.dns") is False
        assert p.allows_outbound("aegisnet.other.thing") is True


class TestDeduplicatorRing:
    def test_add_and_contains(self) -> None:
        ring = _DeduplicatorRing(maxsize=10)
        ring.add("hash1")
        assert "hash1" in ring
        assert "hash2" not in ring

    def test_evicts_oldest(self) -> None:
        ring = _DeduplicatorRing(maxsize=3)
        ring.add("a")
        ring.add("b")
        ring.add("c")
        assert "a" in ring
        ring.add("d")  # evicts "a"
        assert "a" not in ring
        assert "b" in ring
        assert "d" in ring

    def test_duplicate_add_moves_to_end(self) -> None:
        ring = _DeduplicatorRing(maxsize=3)
        ring.add("a")
        ring.add("b")
        ring.add("c")
        ring.add("a")  # refresh "a", so "b" is now oldest
        ring.add("d")  # evicts "b"
        assert "a" in ring
        assert "b" not in ring
