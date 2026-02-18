# Session Recording Evidence Fixtures (v1)

Fixture corpus for pass #12 session recording evidence pipeline validation.

Files:

- `cases.json`: artifact evidence queries and expected validation outcomes.

Suite:

- `docs/roadmaps/cua/research/session_recording_evidence_suite.yaml`

Validator:

- `docs/roadmaps/cua/research/verify_session_recording_evidence.py`

Coverage:

- artifact types: `raw_frame`, `redacted_frame`, `video_segment`, `protocol_log`, `capture_manifest`,
- capture modes: `pre_post_action`, `continuous`, `on_demand`,
- redaction provenance chain: `rule_id`, `method`, `pre_hash`, `post_hash`,
- manifest digest end-to-end replay verification,
- fail-closed behavior for unknown types, missing hashes, incomplete configs, missing provenance, digest mismatches.

Fail-closed codes under test:

- `REC_ARTIFACT_TYPE_UNKNOWN`
- `REC_HASH_MISSING`
- `REC_CAPTURE_CONFIG_INCOMPLETE`
- `REC_REDACTION_PROVENANCE_MISSING`
- `REC_MANIFEST_DIGEST_MISMATCH`
- `REC_LOSSY_BEFORE_HASH`
