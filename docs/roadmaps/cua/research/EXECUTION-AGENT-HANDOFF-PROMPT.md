# Execution Agent Handoff Prompt (Pass #6)

## Context

You are executing inside this repository:

- Root: `/Users/connor/Medica/backbay/standalone/clawdstrike-cua`
- Research index: `docs/roadmaps/cua/INDEX.md`
- Review log: `docs/roadmaps/cua/research/REVIEW-LOG.md`
- Prioritized backlog: `docs/roadmaps/cua/research/EXECUTION-BACKLOG.md`

Current review state:

- Passes 1-5 completed for roadmap docs.
- Pass #5 produced a prioritized execution backlog.
- The next step is implementation-ready artifact creation for Workstream A (`P0`).

## Mission

Execute **Workstream A: Trust and verifier foundation (`P0`)** from `EXECUTION-BACKLOG.md`.

Focus only on:

1. `A1` Reference verifier flow specification
2. `A2` Attestation verifier policy
3. `A3` Schema package + migration fixtures
4. `A4` Signer migration + rollback plan

Do not expand into `P1`/`P2` workstreams yet unless explicitly required to complete `P0`.

## Hard constraints

- Preserve baseline trust root and compatibility with existing `SignedReceipt` verification paths.
- Fail closed on unknown schema/action/version conditions.
- Keep changes scoped; do not refactor unrelated systems.
- If a claim is uncertain, encode it as an explicit assumption and TODO (do not present as fact).
- Prefer machine-checkable outputs (schemas, fixtures, policy files) over prose-only guidance.

## Required deliverables

Create or update the following artifacts:

- `docs/roadmaps/cua/research/verifier-flow-spec.md`
- `docs/roadmaps/cua/research/attestation_verifier_policy.yaml`
- Versioned CUA metadata schema artifacts (path you choose; document it)
- Migration fixture corpus for:
  - `v1 baseline`
  - `v1 + cua`
  - malformed variants
- `docs/roadmaps/cua/research/signer-migration-plan.md`

Also update:

- `docs/roadmaps/cua/research/REVIEW-LOG.md` (new pass entry)
- `docs/roadmaps/cua/INDEX.md` status row(s) as needed

## Acceptance checks (must pass)

- Verifier flow defines mandatory check order and stable error taxonomy.
- Attestation policy is explicit for issuer allowlist, nonce freshness, claim requirements, and clock skew.
- Schema compatibility behavior is testable via fixtures.
- Dual-sign migration plan includes compatibility window and rollback triggers.
- Artifacts are cross-linked from index/log so future agents can continue without ambiguity.

## Execution guidance

- Start by extracting exact `P0` acceptance criteria from `EXECUTION-BACKLOG.md`.
- Implement artifacts first, then update status/tracking files.
- Keep naming and directory structure consistent with existing CUA research docs.
- If tests/validation scripts are added, keep them minimal and local to the new artifacts.

## Final response format

Return:

1. Files created/updated
2. What acceptance checks are satisfied
3. Any remaining open risks/questions
4. Exact next step recommendation for the following execution pass
