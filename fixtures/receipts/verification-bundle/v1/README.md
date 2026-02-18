# Verification Bundle Fixtures

Fixture corpus for pass #12 (D2) end-to-end verification bundle format validation.

## Purpose

Verifies that verification bundles -- self-contained packages of receipt,
attestation evidence, and verification transcript -- can be validated by a
third-party verifier without hidden context. The validator ensures that:

- Receipts are present with all required fields
- Attestation types are recognized (fail-closed on unknown types)
- Verification transcripts contain all required checkpoint types
- Policy references are present in transcripts
- Any checkpoint failure propagates to bundle-level failure

## Files

- `cases.json`: Machine-checkable test cases with bundles and expected outcomes.

## Suite Definition

The suite YAML is at:
`docs/roadmaps/cua/research/verification_bundle_format.yaml`

## Test Cases

| Case ID | Attestation Type | Outcome | Error Code |
|---------|-----------------|---------|------------|
| `complete_bundle_software_only` | none | pass | - |
| `complete_bundle_tpm2` | tpm2_quote | pass | - |
| `complete_bundle_nitro` | nitro_enclave | pass | - |
| `transcript_all_checkpoints_pass` | sev_snp | pass | - |
| `missing_receipt_fails_closed` | none | fail | BDL_RECEIPT_MISSING |
| `incomplete_transcript_fails_closed` | none | fail | BDL_TRANSCRIPT_INCOMPLETE |
| `unknown_attestation_type_fails_closed` | quantum_proof | fail | BDL_ATTESTATION_TYPE_UNKNOWN |
| `checkpoint_failure_propagates` | tpm2_quote | fail | BDL_CHECKPOINT_FAILED |
| `missing_policy_ref_fails_closed` | none | fail | BDL_POLICY_REF_MISSING |

## Fail-Closed Error Codes

- `BDL_RECEIPT_MISSING` - Bundle has no receipt (null or absent)
- `BDL_TRANSCRIPT_INCOMPLETE` - Verification transcript missing required checkpoint types
- `BDL_ATTESTATION_TYPE_UNKNOWN` - Attestation type not in the supported types list
- `BDL_CHECKPOINT_FAILED` - One or more checkpoints have status "fail"
- `BDL_POLICY_REF_MISSING` - Verification transcript has no policy_ref field

## Running the Validator

```bash
python docs/roadmaps/cua/research/verify_verification_bundle.py \
  --cases fixtures/receipts/verification-bundle/v1/cases.json \
  --report docs/roadmaps/cua/research/pass12-verification-bundle-report.json
```
