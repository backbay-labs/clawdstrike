# Policy Evaluation Fixtures (v1)

Fixture corpus for pass #12 CUA policy evaluation validation.

Files:

- `cases.json`: deterministic CUA action -> evaluation stage -> guard result set expectations.

Suite definition:

- `docs/roadmaps/cua/research/cua_policy_evaluation_suite.yaml`

Validator:

- `docs/roadmaps/cua/research/verify_cua_policy_evaluation.py`

Coverage:

- action path resolution: `connect`, `input`, `clipboard_write`, `file_transfer_upload`, `disconnect`,
- evaluation stages: `fast_path`, `std_path`, `deep_path`,
- approval token binding: evidence digest, policy hash, action intent, expiry window, approver identity,
- enforcement modes: `observe`, `guardrail`, `fail_closed`,
- fail-closed on unknown actions, missing context, expired approvals, digest mismatches, unresolved stages.

Fail-closed codes under test:

- `POL_ACTION_UNKNOWN`
- `POL_CONTEXT_MISSING`
- `POL_APPROVAL_EXPIRED`
- `POL_APPROVAL_DIGEST_MISMATCH`
- `POL_STAGE_UNRESOLVED`
- `POL_PARITY_VIOLATION`
