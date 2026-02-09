"""Tests for the 7-tier priority queue and bandwidth budget scheduler."""

from __future__ import annotations

import time

from spine_reticulum.priority import (
    BandwidthBudgetScheduler,
    Priority,
    priority_for_envelope,
)


def _envelope(fact_schema: str) -> dict:
    return {
        "schema": "aegis.spine.envelope.v1",
        "issuer": "aegis:ed25519:" + "aa" * 32,
        "seq": 1,
        "issued_at": "2026-01-01T00:00:00Z",
        "fact": {"schema": fact_schema},
        "envelope_hash": "0x" + "bb" * 32,
    }


class TestPriorityMapping:
    def test_revocation_is_highest(self) -> None:
        env = _envelope("clawdstrike.spine.fact.revocation.v1")
        assert priority_for_envelope(env) == Priority.REVOCATION

    def test_heartbeat_is_lowest(self) -> None:
        env = _envelope("clawdstrike.spine.fact.heartbeat.v1")
        assert priority_for_envelope(env) == Priority.HEARTBEAT

    def test_unknown_defaults_to_heartbeat(self) -> None:
        env = _envelope("some.unknown.schema")
        assert priority_for_envelope(env) == Priority.HEARTBEAT

    def test_all_seven_tiers(self) -> None:
        schemas = [
            ("clawdstrike.spine.fact.revocation.v1", Priority.REVOCATION),
            ("clawdstrike.spine.fact.log_checkpoint.v1", Priority.CHECKPOINT),
            ("clawdstrike.spine.fact.incident.v1", Priority.INCIDENT),
            ("clawdstrike.spine.fact.policy_delta.v1", Priority.POLICY_DELTA),
            ("clawdstrike.spine.fact.run.v1", Priority.RUN),
            ("clawdstrike.spine.fact.node_attestation.v1", Priority.NODE_ATTESTATION),
            ("clawdstrike.spine.fact.heartbeat.v1", Priority.HEARTBEAT),
        ]
        for schema, expected in schemas:
            assert priority_for_envelope(_envelope(schema)) == expected


class TestSchedulerOrdering:
    def test_revocation_before_heartbeat(self) -> None:
        sched = BandwidthBudgetScheduler(link_bps=10000)
        hb = _envelope("clawdstrike.spine.fact.heartbeat.v1")
        rev = _envelope("clawdstrike.spine.fact.revocation.v1")
        sched.enqueue(hb, 100)
        sched.enqueue(rev, 100)
        # Revocation should come out first regardless of insertion order
        first = sched.dequeue()
        assert first is not None
        assert first["fact"]["schema"] == "clawdstrike.spine.fact.revocation.v1"

    def test_full_priority_ordering(self) -> None:
        sched = BandwidthBudgetScheduler(link_bps=10000)
        schemas = [
            "clawdstrike.spine.fact.heartbeat.v1",
            "clawdstrike.spine.fact.incident.v1",
            "clawdstrike.spine.fact.revocation.v1",
            "clawdstrike.spine.fact.policy_delta.v1",
        ]
        for s in schemas:
            sched.enqueue(_envelope(s), 100)

        order = []
        while True:
            env = sched.dequeue()
            if env is None:
                break
            order.append(env["fact"]["schema"])

        assert order == [
            "clawdstrike.spine.fact.revocation.v1",
            "clawdstrike.spine.fact.incident.v1",
            "clawdstrike.spine.fact.policy_delta.v1",
            "clawdstrike.spine.fact.heartbeat.v1",
        ]


class TestDropThresholds:
    def test_heartbeat_dropped_on_slow_link(self) -> None:
        sched = BandwidthBudgetScheduler(link_bps=50)
        hb = _envelope("clawdstrike.spine.fact.heartbeat.v1")
        assert sched.enqueue(hb, 100) is False
        assert sched.pending_count == 0

    def test_revocation_never_dropped(self) -> None:
        sched = BandwidthBudgetScheduler(link_bps=5)
        rev = _envelope("clawdstrike.spine.fact.revocation.v1")
        assert sched.enqueue(rev, 100) is True
        assert sched.pending_count == 1

    def test_run_dropped_below_threshold(self) -> None:
        sched = BandwidthBudgetScheduler(link_bps=10)
        run_env = _envelope("clawdstrike.spine.fact.run.v1")
        assert sched.enqueue(run_env, 100) is False

    def test_run_accepted_above_threshold(self) -> None:
        sched = BandwidthBudgetScheduler(link_bps=100)
        run_env = _envelope("clawdstrike.spine.fact.run.v1")
        assert sched.enqueue(run_env, 100) is True


class TestRevocationRateLimit:
    def test_rate_limit_skips_excess(self) -> None:
        sched = BandwidthBudgetScheduler(link_bps=10000, revocation_rate_limit=2)
        rev = _envelope("clawdstrike.spine.fact.revocation.v1")
        hb = _envelope("clawdstrike.spine.fact.heartbeat.v1")
        # Enqueue 3 revocations + 1 heartbeat
        for _ in range(3):
            sched.enqueue(rev, 100)
        sched.enqueue(hb, 100)

        results = []
        while True:
            env = sched.dequeue()
            if env is None:
                break
            results.append(env["fact"]["schema"])

        # Only 2 revocations should pass, plus the heartbeat
        revs = [r for r in results if r == "clawdstrike.spine.fact.revocation.v1"]
        assert len(revs) == 2
        assert "clawdstrike.spine.fact.heartbeat.v1" in results
