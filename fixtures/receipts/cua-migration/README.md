# CUA Migration Fixtures

Fixture corpus for roadmap workstream A (`P0`) verifier, policy, and migration checks.

## Files

- `v1-baseline-valid.json`: baseline `SignedReceipt` (no CUA profile).
- `v1-cua-valid.json`: CUA-extended receipt (`receipt_profile = cua.v1`).
- `malformed-*.json`: fail-closed vectors for schema/profile/policy checks.
- `dual-sign-*.json`: dual-sign compatibility vectors for migration windows.
- `cases.json`: machine-checkable expected outcomes and verifier context.

## Deterministic inputs

- Public keys used for verification are declared in `cases.json`.
- Verification timestamp for freshness vectors is fixed at
  `2026-02-18T00:10:00Z` in `cases.json.evaluation_context.verified_at`.

## Intended verifier behavior

- Unknown profile/version/action values fail closed.
- Attestation policy denials include policy subcodes.
- Baseline and CUA-valid vectors return pass without rewriting `receipt.verdict`.
