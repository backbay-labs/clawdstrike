# Policy Event Mapping Fixtures (v1)

Fixture corpus for pass #9 `B3` mapping validation.

Files:

- `cases.json`: deterministic flow->policy->guard->audit expectations.

Validator:

- `docs/roadmaps/cua/research/verify_policy_event_mapping.py`

Fail-closed error codes under test:

- `PEMAP_FLOW_UNKNOWN`
- `PEMAP_SIDE_EFFECT_UNKNOWN`
- `PEMAP_FLOW_SIDE_EFFECT_MISMATCH`
- `PEMAP_MAPPING_INVALID`
- `PEMAP_MAPPING_INCOMPLETE`
