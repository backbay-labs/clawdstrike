# Formal Verification

ClawdStrike provides formally verified policy enforcement -- mathematical proof that security policies behave correctly for *all possible* inputs, not just tested ones.

## Guarantees

- **Deny always wins.** If any guard blocks an action, the final verdict is always "deny" -- no combination of other guards can override it.
- **Inheritance never weakens security.** When a child policy extends a parent, the child cannot silently remove prohibitions.
- **Circular extends chains are always caught.** Policy resolution will never loop forever or silently ignore cycles.
- **Errors fail closed.** A misconfigured policy (unsupported version, invalid config) always results in denial, never silent approval.

## Quick start

### Verify a policy

```bash
hush policy verify my-policy.yaml
```

This compiles your policy into normative logic formulas and checks three properties:

1. **Consistency** -- No action is simultaneously permitted and forbidden
2. **Completeness** -- All action types (file, network, shell, MCP) are covered by at least one guard
3. **Inheritance soundness** -- If your policy extends a parent, it does not weaken any of the parent's prohibitions

Example output:

```text
Policy: my-policy.yaml (resolved)

  Consistency ............ PASS  (0 conflicts)
  Completeness ........... PASS  (5/5 action types covered)
  Inheritance soundness .. PASS  (0 weakened prohibitions)

All checks passed.
```

### Verify with JSON output

```bash
hush policy verify --json my-policy.yaml
```

Returns structured output suitable for CI pipelines and automated processing.

### Verify a built-in ruleset

```bash
hush policy verify clawdstrike:strict
hush policy verify clawdstrike:ai-agent
```

## Attestation levels

Every receipt includes a verification attestation level:

| Level | Name | What it means | How to achieve |
|-------|------|---------------|----------------|
| 0 | Heuristic | Guards ran, no formal checks | Default behavior |
| 1 | Z3-Verified | Policy is mathematically consistent | `hush policy verify` passes |
| 2 | Lean-Proved | Core properties proved about the spec | Lean 4 spec builds cleanly |
| 3 | Impl-Verified | Properties proved about the actual Rust code | Aeneas proofs complete |

Most users operate at Level 1. Levels 2 and 3 provide assurance about the engine itself, not your specific policy.

## Verification in CI

### GitHub Actions

```yaml
name: Policy verification

on:
  pull_request:
    paths:
      - ".hush/**/*.yaml"
      - ".hush/**/*.yml"

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable

      - name: Install ClawdStrike CLI
        run: cargo install --path crates/services/hush-cli

      - name: Verify policy
        run: hush policy verify --resolve .hush/policy.yaml

      - name: Verify policy (JSON for artifacts)
        run: |
          hush policy verify --json --resolve .hush/policy.yaml \
            > policy-verification.json

      - uses: actions/upload-artifact@v4
        with:
          name: policy-verification
          path: policy-verification.json
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | All checks passed |
| 1 | One or more checks failed |
| 2 | Policy could not be loaded (parse error, missing file, etc.) |

## What we prove

### Core properties (Lean 4 specification)

Machine-checked proofs in `formal/lean4/ClawdStrike/`. Lean's type checker guarantees validity.

**P1: Deny monotonicity.** If any guard has `allowed = false`, the aggregate verdict has `allowed = false`.

**P2: Allow requires unanimity.** The contrapositive of P1 -- if the aggregate allows, then *every* guard allowed. No guard's denial was dropped.

**P3: Severity total order.** The severity levels (Info < Warning < Error < Critical) form a well-defined total order. This ensures the aggregation comparison logic is deterministic.

**P4: Forbidden path soundness.** If a policy has an enabled forbidden path guard, and a file path matches a forbidden pattern without matching any exception, the guard produces a denial.

**P5: Inheritance restrictiveness.** Deep-merging a child policy with a base produces a policy that is at least as restrictive as the base. Prohibitions from the base are preserved unless explicitly removed.

**P9: Fail-closed on config error.** If the policy has an unsupported schema version, evaluation returns an error. The engine never silently proceeds with a misconfigured policy.

**P10: Cycle detection.** If a policy key appears in the visited set during extends resolution, the cycle is detected and an error is returned. Extends chains deeper than 32 levels are also rejected.

**P11: Empty results safety.** When no guards match an action, the engine returns an explicit allow verdict (not undefined behavior or an error).

**P12: Disabled guard transparency.** A disabled guard always produces an allow verdict, ensuring it has no effect on the aggregate.

**P13: Action irrelevance.** Guards only affect actions in their domain. A ForbiddenPathGuard has no effect on shell commands; an EgressAllowlistGuard has no effect on file access.

### Properties checked by `hush policy verify` (Z3/Logos)

These are checked at the policy level (your specific YAML), not the engine level:

- **Consistency**: No action atom is simultaneously permitted and prohibited for the same agent.
- **Completeness**: All expected action types (file access, file write, network egress, shell command, MCP tool) have at least one covering formula.
- **Inheritance soundness**: No prohibition from a parent policy is weakened (removed) in the child.

### What we do not prove

- **Guard heuristic accuracy.** Pattern matching quality (regex, glob) is axiomatized -- we prove the logic around matching is correct, not that any specific pattern catches every threat.
- **External crypto implementations.** Ed25519 signature internals (provided by the `ed25519-dalek` crate) are trusted, not verified.
- **Async guard timeout behavior.** The formal spec models guards as pure synchronous functions. Timeout, cancellation, and concurrency behavior in async guards are tested, not proved.
- **Content-dependent guard analysis.** Guards like JailbreakGuard and PromptInjectionGuard use ML models and heuristics for detection. The formal spec models them as opaque functions and proves properties about how their verdicts are aggregated, not about detection accuracy.
- **Serde deserialization.** YAML parsing and deserialization are outside the verified core. Invalid YAML is handled by fail-closed load-time validation.

## How it works

### 1. Z3/Logos policy verification (Level 1)

`hush policy verify` compiles your policy YAML into normative logic formulas via the Logos framework:

```text
ForbiddenPathConfig  -->  Prohibition(access("/etc/shadow"))
EgressAllowlistConfig --> Permission(egress("api.github.com"))
                          Prohibition(egress("*"))  (default deny)
McpToolConfig        -->  Prohibition(tool("shell_exec"))
```

These formulas are checked for consistency (no conflicts), completeness (all action types covered), and inheritance soundness (child does not weaken parent).

### 2. Lean 4 specification (Level 2)

`formal/lean4/ClawdStrike/` models the policy engine as pure functions in Lean 4, mirroring the Rust implementation:

| Lean module | Rust source | What it models |
|-------------|-------------|----------------|
| `Core/Verdict.lean` | `core/verdict.rs` | Severity, GuardResult, Action, Policy types |
| `Core/Aggregate.lean` | `core/aggregate.rs` | The `aggregate_overall` verdict selection |
| `Core/Merge.lean` | `policy.rs` | Policy inheritance merge logic |
| `Core/Cycle.lean` | `core/cycle.rs` | Extends chain cycle detection |
| `Core/Eval.lean` | `engine.rs`, `guards/*.rs` | Per-guard evaluation and full policy evaluation |
| `Spec/Properties.lean` | -- | Theorem statements and proofs |

To build the specification and check all proofs:

```bash
cd formal/lean4/ClawdStrike && lake build
```

### 3. Aeneas implementation verification (Level 3)

[Aeneas](https://github.com/AeneasVerif/aeneas) translates the actual Rust source code into Lean 4, producing a faithful model of the implementation (not a hand-written approximation). The generated code in `formal/lean4/ClawdStrike/ClawdStrike/Impl/` is auto-generated -- do not edit by hand.

### 4. Differential testing

`formal-diff-tests` uses proptest to compare the Lean spec against the Rust implementation on randomly generated inputs.

```bash
cargo test -p formal-diff-tests
```

The differential tests cover:

- **Aggregate logic**: Random verdict lists are aggregated by both the spec and the implementation; results must match.
- **Cycle detection**: Random policy graphs are checked for cycles by both implementations.
- **Merge logic**: Random policy configurations are merged by both implementations; results must match.

## For power users

### Building the Lean specification

```bash
# Install Lean 4 (if not already installed)
curl https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh -sSf | sh

# Build and check all proofs
cd formal/lean4/ClawdStrike && lake build
```

A successful build means every theorem in `Spec/Properties.lean` has been verified by Lean's kernel.

### Full verification suite

```bash
hush policy verify my-policy.yaml         # Z3 policy verification
cargo test -p formal-diff-tests            # Differential tests
cd formal/lean4/ClawdStrike && lake build  # Lean proofs
```

### Regenerating Aeneas output

When you change any file in `crates/libs/clawdstrike/src/core/`, the Aeneas-generated Lean code must be regenerated so the Lean proofs continue to reflect the actual Rust implementation.

**When to regenerate:**

- After modifying `verdict.rs`, `aggregate.rs`, `merge.rs`, `cycle.rs`, or `mod.rs` in the `core/` module
- After adding new types or functions to the core module
- CI will flag drift automatically on a weekly schedule

**How to regenerate:**

```bash
# Regenerate and overwrite the committed Impl/ files
mise run regenerate-aeneas

# Or run the script directly
./formal/scripts/regenerate-aeneas.sh
```

**How to check without overwriting (CI mode):**

```bash
# Compare freshly generated output against committed files
mise run check-aeneas

# Or directly
./formal/scripts/regenerate-aeneas.sh --check
```

**Prerequisites:** The script requires [Charon](https://github.com/AeneasVerif/charon) and [Aeneas](https://github.com/AeneasVerif/aeneas) to be installed. See the script header for installation instructions.

**What to do if proofs break after regeneration:**

1. Run `./formal/scripts/regenerate-aeneas.sh` to update the Impl/ files
2. Run `cd formal/lean4/ClawdStrike && lake build` to see which proofs fail
3. Update the affected theorems in `Spec/Properties.lean` (or the relevant `Core/*.lean` files) to match the new implementation shape
4. Re-run `lake build` until all proofs pass
5. Commit both the updated `Impl/` files and the proof fixes together

The auto-generated files are `Types.lean`, `Funs.lean`, and `*_Template.lean` in the `Impl/` directory. Files named `*External.lean` (without the `_Template` suffix) are hand-written glue and are not overwritten by regeneration.

**CI behavior:** The `aeneas-check` job in the Formal Verification workflow runs on a weekly schedule and can be triggered manually via `workflow_dispatch`. It does not block PRs (the OCaml toolchain install takes ~15 minutes), but will alert the team when Impl/ files have drifted.

## Further reading

- [Design Philosophy](concepts/design-philosophy.md) -- Fail-closed principles that formal verification enforces
- [Policy Inheritance](guides/policy-inheritance.md) -- How `extends` chains work (and why inheritance soundness matters)
- [GitHub Actions recipe](recipes/github-actions.md) -- General CI integration patterns
