# 0005 — Custom guards: policy-driven registry (phase 1)

## Status
Accepted

## Context
Custom guards exist today only as programmatic `with_extra_guard(...)`.
We want policy-driven configuration without silently ignoring guard requirements.

## Decision
Introduce `custom_guards` at the policy top-level (schema bump required in Rust policy schema):

```yaml
version: "1.1.0"
custom_guards:
  - id: "acme.always_warn"
    enabled: true
    config: { "foo": "bar" }
```

Rules:
- When `custom_guards` is present, the engine must **fail closed** if a registry is not provided.
- When a registry is provided, missing ids are a **policy load error**.
- Custom guards run **after** built-in guards.

Future phases (planned):
- WASM plugins (portable marketplace)
- Native plugins (perf/power users)

