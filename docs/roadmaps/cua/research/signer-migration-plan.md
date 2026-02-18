# Signer Migration and Rollback Plan (A4)

Date: 2026-02-18  
Scope: migrate from baseline signer-only path to dual-sign CUA-compatible path without changing
`SignedReceipt` trust root.

## 1. Goals and constraints

- Keep envelope compatibility: `SignedReceipt` remains the verifier trust root.
- Keep `receipt.version = 1.0.0` during migration window.
- Introduce CUA profile through metadata only.
- Ensure rollback can return to baseline signer-only receipts without format breakage.

## 2. Assumptions and explicit TODOs

- Assumption: existing `Signatures` object (`signer`, optional `cosigner`) is the only
  signature container available in all SDKs.
- TODO: if key identity (`kid`) is required by runtime verifiers, encode it in
  `receipt.metadata.cua.gateway.key_id` until envelope-level `kid` is standardized.
- Assumption: verifier deployments can roll policy/config independently from signer runtime.

## 3. Phased migration

### Phase 0: Baseline lock (2026-02-18 to 2026-02-24)

- Keep signer-only receipts (`signatures.signer` only).
- Deploy verifier support for CUA profile parsing/schema checks in dark mode
  (decision logs only, no enforcement change).

Exit criteria:
- `baseline_v1_valid` fixture continues to pass.
- No increase in `VFY_SIGNATURE_INVALID` for baseline traffic.

### Phase 1: Dual-sign compatibility window (2026-02-25 to 2026-04-07)

- Sign receipts with both signer and cosigner when CUA profile is enabled.
- Verifier acceptance rules:
  - Legacy verifier: validates `signer` only, ignores `cosigner`.
  - Updated verifier: validates `signer`; validates `cosigner` when present.
- Enforce attestation policy only for `receipt_profile = cua.v1`.

Exit criteria:
- dual-sign receipts verify on both legacy and updated verifier paths.
- malformed CUA fixtures fail with deterministic taxonomy/subcodes.

### Phase 2: Post-window enforcement (starting 2026-04-08)

- For CUA profile receipts, require dual-sign in policy/runtime configuration.
- Continue allowing signer-only baseline receipts for non-CUA flows.

Exit criteria:
- CUA production traffic has >= 99.9% valid cosigner coverage over 7 days.

## 4. Compatibility matrix

| Receipt class | Legacy verifier | Updated verifier |
|---|---|---|
| baseline v1 (signer only) | pass | pass |
| CUA v1 (signer only, during Phase 1) | pass | pass (with warning) |
| CUA v1 (dual-sign) | pass | pass |
| CUA v1 (invalid cosigner, Phase 1) | pass | fail (`VFY_COSIGNATURE_INVALID`) |
| CUA v1 (invalid cosigner, Phase 2) | pass | fail (`VFY_COSIGNATURE_INVALID`) |

## 5. Rollback triggers

Rollback to Phase 0 signer-only mode immediately if any trigger occurs:

1. `VFY_SIGNATURE_INVALID` or `VFY_COSIGNATURE_INVALID` combined rate > 0.5% for 15 minutes.
2. attestation policy denials caused by trusted-issuer misconfiguration (`AVP_UNKNOWN_ISSUER`) > 0.1% for 15 minutes.
3. key-management incident: signer or cosigner private key compromise suspected.
4. verifier crash/regression linked to CUA profile parsing or schema checks.

## 6. Rollback procedure

1. Disable cosigner emission in signer runtime config.
2. Keep CUA metadata emission enabled (do not mutate envelope shape).
3. Set verifier policy to treat cosigner as optional for all profiles.
4. Freeze policy changes; rotate affected keys if trigger was key-compromise related.
5. Re-run migration fixtures and verify:
- baseline and CUA signer-only fixtures pass,
- malformed fixtures still fail closed,
- receipt format remains `SignedReceipt` with unchanged field names.
6. Publish rollback incident note with trigger, timestamp, and restoration criteria.

## 7. Re-entry after rollback

- Require two consecutive 24h windows with signature error rate < 0.05%.
- Re-enable Phase 1 dual-sign in canary first (5% traffic), then 25%, then 100%.
- Reconfirm fixture corpus parity before each step.
