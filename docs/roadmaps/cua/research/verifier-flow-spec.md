# Reference Verifier Flow Specification (A1)

Date: 2026-02-18  
Scope: baseline `SignedReceipt` compatibility + CUA metadata/profile verification.

## 1. Inputs and linked artifacts

- Baseline envelope: `SignedReceipt` from `crates/libs/hush-core/src/receipt.rs`
- CUA schema package: `docs/roadmaps/cua/research/schemas/cua-metadata/schema-package.json`
- CUA schema v1.0.0: `docs/roadmaps/cua/research/schemas/cua-metadata/v1.0.0/cua-metadata.schema.json`
- Attestation policy: `docs/roadmaps/cua/research/attestation_verifier_policy.yaml`
- Migration fixture cases: `fixtures/receipts/cua-migration/cases.json`

## 2. Normative check order (MUST)

Checks are strict and stop-on-first-failure. This ordering is normative for deterministic
error outcomes.

1. Parse JSON as object.
2. Parse as `SignedReceipt` with unknown-field rejection.
3. Validate `receipt.version` with baseline version gate (`1.0.0` only).
4. Determine profile:
- If `receipt.metadata.receipt_profile` is absent: baseline flow.
- If present and equals `cua.v1`: CUA flow.
- Any other value: fail closed.
5. For CUA flow only, resolve schema package entry by (`receipt_profile`, `cua_schema_version`).
6. For CUA flow only, validate `receipt.metadata` against resolved JSON Schema.
7. Canonicalize `receipt` and verify primary signature.
8. If cosigner is present, verify cosigner signature.
9. For CUA flow only, evaluate attestation policy (`attestation_verifier_policy.yaml`).
10. For CUA flow only, validate chain summary consistency:
- `cua.session.event_count == cua.chain.total_events`
- all `action_summary[*].kind` values in supported enum (schema-backed)
11. Emit success with unchanged verdict semantics (`receipt.verdict` is not rewritten).

## 3. Stable error taxonomy

| Code | Stage | Condition | Fail closed |
|---|---|---|---|
| `VFY_PARSE_INVALID_JSON` | 1 | JSON parse failed or top-level not object | yes |
| `VFY_SIGNED_RECEIPT_SHAPE_INVALID` | 2 | `SignedReceipt` parse/shape/unknown-field failure | yes |
| `VFY_RECEIPT_VERSION_INVALID` | 3 | non-semver receipt version | yes |
| `VFY_RECEIPT_VERSION_UNSUPPORTED` | 3 | semver but not supported (`!= 1.0.0`) | yes |
| `VFY_PROFILE_UNKNOWN` | 4 | unknown `receipt_profile` | yes |
| `VFY_CUA_SCHEMA_VERSION_UNSUPPORTED` | 5 | no package match for version/profile pair | yes |
| `VFY_CUA_SCHEMA_INVALID` | 6 | JSON Schema validation failed | yes |
| `VFY_SIGNATURE_INVALID` | 7 | signer signature failed verification | yes |
| `VFY_COSIGNATURE_INVALID` | 8 | cosigner signature present but invalid | yes |
| `VFY_ATTESTATION_POLICY_DENY` | 9 | policy decision is deny | yes |
| `VFY_CHAIN_SUMMARY_MISMATCH` | 10 | event-count or chain summary mismatch | yes |
| `VFY_INTERNAL_UNEXPECTED` | any | verifier internal error | yes |

For `VFY_ATTESTATION_POLICY_DENY`, include a policy subcode from
`attestation_verifier_policy.yaml#error_codes` (for example `AVP_UNKNOWN_ISSUER`,
`AVP_NONCE_STALE`) so failures are deterministic and machine-checkable.

## 4. Baseline compatibility requirements

- Receipts without `receipt_profile` continue through existing baseline path.
- Trust root remains baseline `SignedReceipt` signature verification.
- CUA metadata is an extension under `receipt.metadata`; it does not replace the envelope.
- Unknown profile/version/action conditions fail closed before policy acceptance.

## 5. Fixture expectations (deterministic)

Expected outcomes are declared in `fixtures/receipts/cua-migration/cases.json`.

| Case ID | Fixture | Expected |
|---|---|---|
| `baseline_v1_valid` | `v1-baseline-valid.json` | pass |
| `cua_v1_valid` | `v1-cua-valid.json` | pass |
| `malformed_unknown_profile` | `malformed-unknown-profile.json` | `VFY_PROFILE_UNKNOWN` |
| `malformed_unknown_cua_schema_version` | `malformed-unknown-cua-schema-version.json` | `VFY_CUA_SCHEMA_VERSION_UNSUPPORTED` |
| `malformed_unknown_action_kind` | `malformed-unknown-action-kind.json` | `VFY_CUA_SCHEMA_INVALID` |
| `malformed_missing_attestation_claim` | `malformed-missing-attestation-claim.json` | `VFY_CUA_SCHEMA_INVALID` |
| `malformed_wrong_attestation_issuer` | `malformed-wrong-attestation-issuer.json` | `VFY_ATTESTATION_POLICY_DENY` + `AVP_UNKNOWN_ISSUER` |
| `malformed_stale_nonce` | `malformed-stale-nonce.json` | `VFY_ATTESTATION_POLICY_DENY` + `AVP_NONCE_STALE` |

## 6. Reference pseudocode

```text
verify(receipt_json, keyset, now_utc):
  obj = parse_json(receipt_json)                    or VFY_PARSE_INVALID_JSON
  sr  = parse_signed_receipt(obj)                   or VFY_SIGNED_RECEIPT_SHAPE_INVALID
  validate_receipt_version(sr.receipt.version)      or VFY_RECEIPT_VERSION_INVALID/UNSUPPORTED

  profile = sr.receipt.metadata.receipt_profile?
  if profile is absent: mode = baseline
  else if profile == "cua.v1": mode = cua
  else fail VFY_PROFILE_UNKNOWN

  if mode == cua:
    schema = resolve_schema(profile, metadata.cua_schema_version)
    if none: fail VFY_CUA_SCHEMA_VERSION_UNSUPPORTED
    validate_json_schema(sr.receipt.metadata, schema) or VFY_CUA_SCHEMA_INVALID

  verify_signer(sr, keyset.signer)                  or VFY_SIGNATURE_INVALID
  if sr.signatures.cosigner present:
    verify_cosigner(sr, keyset.cosigner)            or VFY_COSIGNATURE_INVALID

  if mode == cua:
    decision, subcode = eval_attestation_policy(sr, now_utc)
    if decision != allow: fail VFY_ATTESTATION_POLICY_DENY(subcode)
    check_chain_summary(sr)                         or VFY_CHAIN_SUMMARY_MISMATCH

  return pass_with_verdict(sr.receipt.verdict)
```
