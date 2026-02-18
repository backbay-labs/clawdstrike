# Remote Session Continuity Fixtures (v1)

Fixture corpus for pass #10 `C2` remote session continuity validation.

Files:

- `cases.json`: deterministic reconnect/packet-loss/gateway-restart continuity transcripts.

Validator:

- `docs/roadmaps/cua/research/verify_remote_session_continuity.py`

Coverage:

- reconnect, packet-loss recovery, and gateway-restart recovery continuity chains,
- hash-link continuity across session transitions,
- orphan action detection,
- required policy/audit event coverage.

Fail-closed codes under test:

- `CONT_SUITE_INVALID`
- `CONT_SCENARIO_UNKNOWN`
- `CONT_CHAIN_BREAK`
- `CONT_ORPHAN_ACTION_DETECTED`
- `CONT_AUDIT_INCOMPLETE`
