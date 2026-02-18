# Input Injection Capability Fixtures (v1)

Fixture-driven validation vectors for pass #9 B2 artifacts:

- `docs/roadmaps/cua/research/injection_outcome_schema.json`
- `docs/roadmaps/cua/research/injection_backend_capabilities.yaml`

`cases.json` covers:

- success classes (`accepted` / `applied` / `verified`),
- denial classes with standardized `reason_code`,
- fail-closed behavior for unknown backends/actions/target modes,
- fail-closed behavior for unsupported backend capability combinations.

Validator:

- `docs/roadmaps/cua/research/verify_injection_capabilities.py`
