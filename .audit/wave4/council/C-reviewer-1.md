# Wave C Council — Reviewer 1 (schema + examples)

**HEAD:** 7f97033caeb77cf0b123da9a4805fc73c58ab57f
**Verdict:** CONCUR

## Check 1: Source-of-truth
**POLICY_SCHEMA_VERSION:** `"1.5.0"` — `crates/libs/clawdstrike/src/policy.rs:29`
> `pub const POLICY_SCHEMA_VERSION: &str = "1.5.0";`

**Supported versions:** `["1.1.0", "1.2.0", "1.3.0", "1.4.0", "1.5.0"]` — `crates/libs/clawdstrike/src/policy.rs:30-31`
> `pub const POLICY_SUPPORTED_SCHEMA_VERSIONS: &[&str] = &["1.1.0", "1.2.0", "1.3.0", "1.4.0", "1.5.0"];`

Matches the spec's expectation exactly.

## Check 2: Doc consistency
**Files with stale versions:** none in the main user-facing docs surface. The spec's regex `version[:"]\s*"?1\.[0-5]\.0"?` returns 0 matches in `*.md` (regex requires a `:` or `"` immediately followed by `\s` which doesn't match the typical YAML/quoted form). A wider regex (`"1\.[0-5]\.0"`) on `*.md` shows all citations are within the supported range `1.1.0`-`1.5.0`. No `"1.0.0"` policy-version mentions outside historical audit and legacy plan/RFC contexts (see DISSENT log for full list, none considered a regression). README.md line 628 still shows `version: "1.3.0"` in the Spider-Sense quickstart block — this is supported but stale; per the prompt the README rewrite is explicitly deferred to user.

**clawdstrike-v\* mentions (all-tree):** 41 total. Within `*.md`: 13 matches, but ALL of them are intentional references in:
- `docs/audits/2026-02-26-package-ecosystem-audit.md:39` — audit finding documenting the legacy schema
- `docs/plans/agent-frameworks/{autogpt,crewai,langchain,overview,vercel-ai}.md` — 9 mentions describing the legacy OpenClaw schema in plan docs
- `docs/plans/decisions/0002-policy-schema-convergence.md:11` — ADR documenting the schema convergence
- `docs/plans/implementation-pad.md:64` — implementation notes describing the legacy form
- `docs/src/concepts/schema-governance.md:14` — governance table documenting "legacy"
- `docs/src/guides/openclaw-integration.md:65` — explicitly states "Legacy OpenClaw schema"

None of these are stale-in-the-wild; they are descriptive references to the legacy schema for documentation/migration purposes. The actual code paths in `packages/adapters/clawdstrike-openclaw/` still implement the `clawdstrike-v1.0` legacy translation as intended.

**schema_version key in docs (all-tree):** 24 matches. In `docs/src/` only 3, all in `docs/src/rfcs/0001-package-manager.md:78,199,569` — these refer to a hypothetical PACKAGE-MANAGER schema (not the policy schema) and use `schema_version` as a different field name in that RFC. Other matches are in `docs/plans/**` (custom-guards/policy-as-code/origin-enclaves) describing future/proposed schemas (e.g., `2.0.0` migration plan), `docs/roadmaps/cua/**` for the CUA-receipt schema, `docs/specs/11-open-source-governance.md:303` (governance template).

The CRITICAL invariant — that NO `schema_version:` key appears as the YAML top-level form of the policy schema — is upheld. The 24 matches are either (a) policy-schema docs talking ABOUT `schema_version` as a renamed key (e.g., the 6 in `policy-as-code/versioning.md`), or (b) unrelated schemas (CUA, package-manager, receipt).

Plugin docs (`clawdstrike-plugin/commands/selftest.md:46`, `cursor-plugin/commands/selftest.md:46`) reference `schema_version` as a field returned by a health-check endpoint, not as a policy YAML key. This is not the policy schema's `version:` field.

**Per-file status:**
- `README.md:628` — has `version: "1.3.0"` in Spider-Sense quickstart YAML. Supported. README rewrite explicitly deferred — PASS (within scope).
- `CONTRIBUTING.md:153` — `version: "1.5.0"` in Level 1 ruleset example. PASS.
- `CLAUDE.md` root — `CLAUDE.md:91,113` cite "schema v1.5.0 (backward-compatible with v1.1.0)". PASS.
- `docs/src/reference/policy-schema.md:11-17` — supported versions list `1.1.0`-`1.5.0`; `21` cites `1.5.0` as current with reference to `policy.rs:29`. Example at `:55` uses `1.3.0` (supported, but mildly inconsistent with `1.5.0` current). PASS with minor note.
- `docs/src/concepts/policies.md:10,32` — example uses `1.5.0`; note states "Supported schema versions are `1.1.0` through `1.5.0`". PASS.
- `docs/src/getting-started/quick-start.md:54` — `version: "1.5.0"`. PASS.
- `docs/src/getting-started/first-policy.md:5,10` — explicit "schema `1.5.0` is current; versions `1.1.0`-`1.5.0` are supported"; example uses `1.5.0`. PASS.

## Check 3: Example YAML loadability
**validate-example-policies.sh result:** `validated 27, skipped 6, failed 0`. All 27 example policies load successfully against the canonical Rust engine (`hush policy validate`).
```
ok   examples/openclaw-plugin/policy.yaml
ok   examples/spider-sense-threat-intel/policy.hardened.yaml
ok   examples/spider-sense-threat-intel/policy.baseline.yaml
ok   examples/hybrid-swarm/policy-coder.yaml
ok   examples/hybrid-swarm/policy-planner.yaml
ok   examples/hybrid-swarm/policy-reviewer.yaml
ok   examples/bb-edr/policy.yaml
ok   examples/enterprise-deployment/policy-next.yaml
ok   examples/secure-coding-assistant/policy.yaml
ok   examples/red-blue-swarm/policy.yaml
ok   examples/hello-secure-agent-py/policy.yaml
ok   examples/policies/project-dev.yaml
ok   examples/policies/threat-intel-virustotal-url.yaml
ok   examples/policies/minimal-posture.yaml
ok   examples/policies/extend-strict.yaml
ok   examples/policies/threat-intel-snyk-background.yaml
ok   examples/policies/project-base.yaml
ok   examples/policies/synthesized-example.yaml
ok   examples/policies/enterprise-posture.yaml
ok   examples/policies/threat-intel-safe-browsing.yaml
ok   examples/hello-secure-agent-ts/policy.yaml
ok   examples/secure-agent-swarm/policy-coder.yaml
ok   examples/secure-agent-swarm/policy-planner.yaml
ok   examples/secure-agent-swarm/policy-reviewer.yaml
ok   examples/hello-secure-agent-vercel/policy.yaml
ok   examples/edr-pipeline/policy.yaml
ok   examples/docker-compose/policy.yaml
```

**find examples count:** 27 (matches `validated 27` from script)

**stale `schema_version:` key (`grep -rE '^schema_version:' examples/`):** 0

**stale `1.0.0` version (`grep -rE '^version: "?1\.0\.0"?' examples/`):** 0

**clawdstrike-v\* version (`grep -rE '^version: "?clawdstrike' examples/`):** 0

**Spot-check 3 files:**
- `examples/hybrid-swarm/policy-coder.yaml:1` → `version: "1.1.0"` (supported). PASS.
- `examples/red-blue-swarm/policy.yaml:1` → `version: "1.1.0"` (supported). PASS.
- `examples/secure-agent-swarm/policy-coder.yaml:1` → `version: "1.1.0"` (supported). PASS.

All use the `version:` key (not `schema_version:`) with a supported value. **All 3 PASS.**

## Check 4: Validation script quality
**Script exists:** Y — `scripts/validate-example-policies.sh` (66 lines).

**Invokes verifier:** Y — `scripts/validate-example-policies.sh:51`
> `if "$HUSH_BIN" policy validate "$file" >/dev/null 2>&1; then`

It builds `hush-cli` first (`scripts/validate-example-policies.sh:20` — `cargo build -q -p hush-cli --bin hush`) and invokes the resulting `hush policy validate` binary, which is the canonical Rust engine path.

**Non-zero on fail:** Y — `scripts/validate-example-policies.sh:63-65`:
> `if [[ "$failures" -gt 0 ]]; then`
> `  exit 1`
> `fi`

Plus `set -euo pipefail` on line 9 guarantees abort on unhandled error.

**Recursive over `examples/`:** Y — `scripts/validate-example-policies.sh:58`:
> `done < <(find examples -type f \( -name '*.yaml' -o -name '*.yml' \) -print0)`

**Intentional skips:**
- `*/docker-compose.yml|*/docker-compose.yaml` (line 35) — compose files, not policies.
- `*/config.yaml|*/config.yml` (line 38) — hushd/agent config files shipped next to policies.
- Files without a top-level `version:` or `hushspec:` line (line 45) — not a policy shape (e.g., MCP manifests).

All skips are explicit, documented in the script header (lines 5-8), and produce a reported skip count (`skipped=$((skipped + 1))`). The final output line `validated 27, skipped 6, failed 0` makes intentional skips auditable.

## DISSENT log
Minor inconsistencies, none rising to dissent:

1. `README.md:628` still has `version: "1.3.0"` (supported but stale). Spec acknowledges README rewrite deferred to user — **NOT a blocker**.

2. `docs/src/reference/policy-schema.md:55` "Full Example" still uses `version: "1.3.0"`. This contradicts line 21 declaring `1.5.0` is current. Cosmetic; would-be-nice to bump in a follow-up. Functionally fine because the doc explicitly lists supported versions at lines 13-17.

3. `docs/audits/2026-02-26-core-docs-audit.md` and related audit files contain old references to `1.2.0`/`1.1.0` as the "current" version. These are time-stamped audit reports; not load-bearing for current behavior.

4. `docs/plans/agent-frameworks/*.md` and `docs/src/concepts/schema-governance.md` continue to reference `clawdstrike-v1.0` legacy schema by name. Verified intentional — the OpenClaw adapter (`packages/adapters/clawdstrike-openclaw/`) still translates this legacy format. Documenting it is correct.

5. `docs/plans/policy-as-code/versioning.md` uses `schema_version` as a key name in a proposed 2.0.0 migration spec. Future proposal, not current behavior.

6. The `*-plugin/commands/selftest.md` files describe a runtime healthcheck `schema_version` field returned by an endpoint — that's an API response field unrelated to the policy YAML top-level key. Acceptable.

None of these undermine the Wave C deliverable (schema unification + example loadability).

## Final verdict
**CONCUR.**

Source-of-truth constants are correctly unified to `1.5.0` with the full supported list `[1.1.0..1.5.0]`. All 27 example YAML policies validate cleanly against the canonical Rust engine via the new `scripts/validate-example-policies.sh`, which is well-formed, CI-ready, and produces auditable output. No examples use the stale `schema_version:` key, no examples use `1.0.0`, and no examples use the `clawdstrike-v*` legacy form. User-facing docs (README, CONTRIBUTING, CLAUDE.md, the 4 docs/src/ pages in the spec) all cite the canonical `1.5.0` version or the explicit supported-versions list, except for the README's deferred Spider-Sense quickstart block and one cosmetic `1.3.0` example in `policy-schema.md:55` — neither is load-bearing.
