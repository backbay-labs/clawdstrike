# Post-Condition Probe Fixtures (v1)

Fixture corpus for pass #10 `C1` deterministic post-condition probe validation.

Files:

- `cases.json`: probe suite queries and expected outcome classifications.

Validator:

- `docs/roadmaps/cua/research/verify_postcondition_probes.py`

Coverage:

- action kinds: `click`, `type`, `scroll`, `key_chord`,
- success state differentiation: `accepted` vs `applied` vs `verified`,
- explicit negative outcomes: ambiguous target, focus steal, permission revocation, timeout,
- fail-closed behavior for unknown action/scenario.

Fail-closed codes under test:

- `PRB_SUITE_INVALID`
- `PRB_ACTION_UNKNOWN`
- `PRB_SCENARIO_UNKNOWN`
- `PRB_INVALID_OUTCOME`
- `PRB_OUTCOME_NOT_SUCCESS`
