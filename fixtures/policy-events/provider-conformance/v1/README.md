# Provider Conformance Fixtures (v1)

Fixture corpus for pass #13 E2 provider translator conformance validation.

Files:

- `cases.json`: deterministic provider-specific input -> canonical policy event parity expectations.

Suite definition:

- `docs/roadmaps/cua/research/provider_conformance_suite.yaml`

Validator:

- `docs/roadmaps/cua/research/verify_provider_conformance.py`

Coverage:

- single-provider translation: OpenAI click, OpenAI type, Claude click, Claude navigate,
- cross-provider parity: identical canonical fields for same intent across OpenAI and Claude,
- fail-closed on unknown provider, unknown intent, parity violation, missing required field.

Fail-closed codes under test:

- `PRV_PROVIDER_UNKNOWN`
- `PRV_INTENT_UNKNOWN`
- `PRV_PARITY_VIOLATION`
- `PRV_TRANSLATION_ERROR`
- `PRV_MISSING_REQUIRED_FIELD`
