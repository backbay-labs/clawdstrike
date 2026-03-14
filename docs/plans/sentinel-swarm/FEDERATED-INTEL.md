# Federated Intel Exchange Plan

> Concrete plan for portable, signed, reputation-aware intel sharing across
> trusted and federated swarms.

**Status:** Planned after missions and evidence ingestion
**Date:** 2026-03-12
**Branch:** `feat/sentinel-swarm`

---

## Goal

Make intel a portable artifact with enough provenance that another swarm can
ingest it without trusting the sender blindly.

## Core Requirements

### Signed intel envelope

Each published intel artifact needs:

- stable intel ID
- author sentinel identity
- source findings and evidence references
- content hash
- shareability scope
- reputation metadata
- optional witness/notary proof references

### Reputation-aware ingestion

Peers should not ingest shared intel equally. The receiving swarm should weigh:

- sender reputation
- prior confirmations or false-positive history
- trust relationship
- witness/notary verification state

### Selective disclosure

Raw evidence stays local by default. Shared intel should carry:

- normalized summaries
- redacted indicators
- hash or receipt references
- explicit attachment opt-in for sensitive evidence

## Proposed Flow

1. A finding is promoted to intel locally.
2. The intel artifact is signed by the sentinel or operator identity.
3. The artifact is published to a trusted swarm or federated topic.
4. Receiving swarms verify signature, reputation, and optional witness/notary proof.
5. The artifact is either:
   - ignored
   - stored as untrusted
   - promoted into local memory/pattern stores

## Data Shape

```ts
interface FederatedIntelEnvelope {
  intelId: string;
  authorFingerprint: string;
  swarmId: string | null;
  contentHash: string;
  reputationScore: number;
  trustClass: "private" | "trusted" | "federated";
  findingRefs: string[];
  witnessRefs: string[];
  notaryRefs: string[];
  createdAt: number;
  signature: string;
}
```

## Integration Points

| Surface | Role |
|---------|------|
| `reputation-tracker.ts` | local peer scoring and ingestion thresholds |
| Speakeasy bridge | trusted swarm transport and private exchange |
| Backbay witness/notary packages | artifact verification and provenance |
| signal/finding/intel stores | promotion, ingest, suppression, and traceability |

## Rollout

### Phase 1

- local envelope generation and verification
- reputation scoring hooks on ingest decisions

### Phase 2

- trusted swarm publication and subscription
- opt-in artifact promotion into sentinel memory

### Phase 3

- witness/notary proof attachment and verification
- federated cross-org sharing with explicit policies

## Definition of Done

- Intel can be exported as a signed envelope.
- Receiving swarms can verify and score that envelope.
- Promotion decisions are reputation-aware and auditable.
- Provenance is preserved without forcing raw evidence disclosure.
