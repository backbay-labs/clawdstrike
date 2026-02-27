# Policy Torture Suites

Stress suites for policy authoring edge-cases and security invariants.

## What is covered

- Deep-merge inheritance with additive/removal semantics
- Replace-merge behavior (intentional non-inheritance)
- Posture transitions (budget exhaustion, any-violation, capability precheck)
- Full built-in guard gauntlet with hard 100% guard coverage
- Extends resolver stress checks:
  - Circular loop detection
  - Depth-limit enforcement
- IRM mixed-token extraction precedence:
  - Path-like string token must not override object `{ "path": ... }` extraction

## Run

```bash
bash rulesets/tests/policy-torture/run.sh
```

Artifacts are written to `rulesets/tests/policy-torture/reports/`:

- `*.txt`: human-readable reports
- `*.json`: stable CI artifact payloads for audit traceability
