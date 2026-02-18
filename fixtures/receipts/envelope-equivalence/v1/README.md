# Envelope Semantic Equivalence Fixtures

Fixture corpus for pass #11 (C3) envelope semantic equivalence validation.

## Purpose

Verifies that a canonical receipt payload maintains semantic identity when
wrapped in any supported envelope format (bare, COSE Sign1, JWS compact,
JWS JSON). The validator ensures that the five canonical payload fields
(`receipt_id`, `timestamp`, `content_hash`, `verdict`, `provenance`) are
preserved exactly across all wrapper types.

## Files

- `cases.json`: Machine-checkable test cases with payloads, envelopes,
  and expected outcomes.

## Suite Definition

The suite YAML is at:
`docs/roadmaps/cua/research/envelope_semantic_equivalence_suite.yaml`

## Test Cases

| Case ID | Wrapper | Outcome | Error Code |
|---------|---------|---------|------------|
| `bare_payload_verifies` | bare | pass | - |
| `cose_sign1_wraps_identical_payload` | cose_sign1 | pass | - |
| `jws_compact_wraps_identical_payload` | jws_compact | pass | - |
| `jws_json_wraps_identical_payload` | jws_json | pass | - |
| `cross_wrapper_verdict_parity` | cose_sign1 | pass | - |
| `unknown_wrapper_fails_closed` | protobuf_experimental | fail | ENV_WRAPPER_UNKNOWN |
| `version_mismatch_fails_closed` | bare | fail | ENV_VERSION_MISMATCH |
| `payload_divergence_detected` | jws_compact | fail | ENV_PAYLOAD_DIVERGENCE |
| `invalid_signature_fails` | cose_sign1 | fail | ENV_SIGNATURE_INVALID |

## Fail-Closed Error Codes

- `ENV_WRAPPER_UNKNOWN` - Unrecognized envelope wrapper type
- `ENV_VERSION_MISMATCH` - Receipt version not supported
- `ENV_PAYLOAD_DIVERGENCE` - Canonical payload fields differ between declared payload and envelope contents
- `ENV_SIGNATURE_INVALID` - Envelope signature verification failed

## Running the Validator

```bash
python docs/roadmaps/cua/research/verify_envelope_semantic_equivalence.py \
  --cases fixtures/receipts/envelope-equivalence/v1/cases.json \
  --report docs/roadmaps/cua/research/pass11-envelope-equivalence-report.json
```
