# Orchestration Isolation Fixtures (v1)

Fixture corpus for pass #12 orchestration/containerization isolation validation.

Files:

- `cases.json`: orchestration isolation queries and expected outcomes.

Validator:

- `docs/roadmaps/cua/research/verify_orchestration_isolation.py`

Coverage:

- isolation tiers: `process`, `container_runc`, `sandboxed_container_gvisor`, `microvm_firecracker`, `full_vm_qemu`,
- session lifecycle: `pending_launch`, `validating`, `running`, `teardown`, `disposed`,
- launch validation: runtime policy digest, image digest, network profile checks,
- side-effect channel enforcement: broker path allowed, direct filesystem/network/process denied,
- teardown verification: workspace disposal marker, data wipe hash, cleanup timestamp,
- breakout detection: process namespace escape attempts.

Fail-closed codes under test:

- `ORC_SUITE_INVALID`
- `ORC_TIER_UNKNOWN`
- `ORC_LAUNCH_VALIDATION_FAILED`
- `ORC_DIRECT_IO_DENIED`
- `ORC_TEARDOWN_INCOMPLETE`
- `ORC_BREAKOUT_DETECTED`
- `ORC_IMAGE_DIGEST_MISMATCH`
- `ORC_SCENARIO_UNKNOWN`
