# Adapter Contract Fixtures (v1)

Fixture corpus for pass #13 canonical adapter-core CUA contract validation.

Files:

- `cases.json`: deterministic flow -> outcome -> reason code -> policy event -> guard result expectations.

Suite definition:

- `docs/roadmaps/cua/research/canonical_adapter_cua_contract.yaml`

Validator:

- `docs/roadmaps/cua/research/verify_canonical_adapter_contract.py`

Coverage:

- flow surfaces: `connect`, `input`, `clipboard_write`, `file_transfer_download`, `reconnect`, `disconnect`,
- canonical outcomes: `accepted`, `applied`, `verified`, `denied`, `unknown`,
- reason codes: `ADC_POLICY_ALLOW`, `ADC_POLICY_DENY`, `ADC_GUARD_ERROR`, `ADC_PROBE_VERIFIED`, `ADC_PROBE_FAILED`, `ADC_UNKNOWN_FLOW`,
- adapter output fields: `flow`, `outcome`, `reason_code`, `policy_event_ref`, `guard_results`, `audit_ref`,
- fail-closed on unknown flows, invalid outcomes, missing policy refs, malformed guard results, unknown reason codes.

Fail-closed codes under test:

- `ADC_FLOW_UNKNOWN`
- `ADC_OUTCOME_INVALID`
- `ADC_MISSING_POLICY_REF`
- `ADC_GUARD_RESULT_MALFORMED`
- `ADC_REASON_CODE_UNKNOWN`
