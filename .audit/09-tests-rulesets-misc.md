# Tests / Rulesets / Dev Hygiene Audit

**Repository:** `/Users/connor/Medica/backbay/standalone/clawdstrike/`
**Scope:** `crates/tests/`, `rulesets/`, `packages/sdk/hush-py/`, `fuzz/`, `tests/` (top-level), `fixtures/`, `vendor/`, cross-cutting test hygiene
**Out of scope:** `crates/libs/`, `crates/services/`, `crates/bridges/`, `apps/`, `infra/vendor/`

---

## Executive Summary

This is a serious-looking testbed with some genuinely impressive bones — particularly the `formal-diff-tests` crate (spec vs implementation property tests with thoughtful proptest tuning) and the `policy-torture` runner (deep-merge, replace, posture, gauntlet coverage at 100%). The fuzz harness covers nine attack surfaces and runs nightly.

That said, the surface presentation does not yet say "elite principal engineer." The cracks:

- **The rulesets pretend to use inheritance, but mostly don't.** `default.yaml`, `strict.yaml`, `ai-agent.yaml`, `cicd.yaml` each redeclare the same Windows-credential and SSH path blocks verbatim instead of `extends: default` / `extends: strict`. Only the remote-desktop and origin example policies actually `extends`. This is the single most visible thing a code-tour engineer will notice.
- **Six of thirteen built-in guards never appear in any of the four core rulesets.** `path_allowlist`, `shell_command`, `prompt_injection` (missing from default/permissive/cicd), `jailbreak`, `computer_use`, `spider_sense` — these are either remote-desktop-only or strict-only. New users loading `default.yaml` get a surprisingly partial defense.
- **The compliance fixtures (`fixtures/certification/policies/{hipaa,pci-dss,soc2}-policy.yaml`) are broken.** They use `additional_patterns:` without `merge_strategy: deep_merge`, declare `default_action: deny` instead of `block`, use `deny:` instead of `block:`, use unsupported severity values like `medium`/`low`/`high`, and reference fields like `severity_threshold` and `redact` that the engine does not recognize. These are aspirational placeholders shipped as if they worked.
- **Python packaging has two coexisting `pyproject.toml` files** (`hush-py/pyproject.toml` hatchling + `hush-py/hush-native/pyproject.toml` maturin), both claiming to ship a package named `clawdstrike` v0.2.7, with the hatchling one referencing a nonexistent `src/hush/` source root and the maturin one referencing a nonexistent `hush-native/python/` source root.
- **mypy strict is misleading.** `pyproject.toml` sets `strict = true` but `moon.yml` runs `mypy src/` only — never against `tests/`. Half the test files have no return annotations and would fail strict checking; the policy obscures that.
- **The `RecordingBackend` test double allows everything.** Tests that wrap their facade in it (`test_facade.py`, `test_typed_actions.py` adjacents) verify routing but never verify a single negative verdict against the real backend.
- **Integration tests for `k8s_audit_bridge_reliability.rs` silently pass when Docker/NATS are unavailable** via `eprintln!("skipping integration test"); return;` instead of `#[ignore]` or a proper test skip. CI will report green even when nothing ran.
- **One built `tests/registry-smoke.sh` script lives at the top level** and is the only top-level test entrypoint. It does not match the otherwise-consistent `mise` / `cargo test` / `pytest` conventions.

The bones are there. The shellac is uneven.

---

## Inventory

### Test crate inventory (`crates/tests/`)

| Crate | Files | LOC | Test quality | Gaps |
|---|---|---|---|---|
| `formal-diff-tests` | 4 src + 3 tests | ~900 (tests) | Excellent. Proptest with env-driven `PROPTEST_CASES`, 11 algebraic properties on aggregate, 11 on merge, 8 on cycle. Spec is a real independent reimplementation. | One untranslatable function (`merge_keyed_vec`) per existing notes; otherwise clean. |
| `sdr-integration-tests` | 1 lib stub + 3 tests | 1,662 | Mixed. `e2e_pipeline.rs` is a thorough self-contained pipeline test. `k8s_audit_bridge_reliability.rs` is a real-bridge integration test but silently no-ops when Docker/NATS missing. `bridge_roundtrip_test.rs` good. | Silent-skip pattern hides absence of execution in CI. Hand-rolled `simulate_ingest_contract` may drift from real `clawdstrike-spine` ingest path. |
| `e2e-posture-cmd` | 1 src | 154 | This is a **CLI binary**, not a test. Belongs under `crates/services/` or `tools/`, not under `crates/tests/`. | Misclassified. The crate description claims "E2E test binary" but `cargo test` finds nothing here. |

### Ruleset inventory (`rulesets/`)

| Ruleset | LOC | `extends`? | Guards configured | Overlap | Clarity |
|---|---|---|---|---|---|
| `permissive.yaml` | 24 | No | egress_allowlist, patch_integrity | — | Clean. |
| `default.yaml` | 119 | **No** | forbidden_path, egress_allowlist, secret_leak, patch_integrity, mcp_tool | Duplicates ~30 Windows/SSH patterns with `strict.yaml`, `ai-agent.yaml`, `cicd.yaml` | Decent but should extend nothing or be the root others extend. |
| `strict.yaml` | 130 | **No** | + prompt_injection, jailbreak | Massive overlap with default | Should be `extends: default` with additions. |
| `ai-agent.yaml` | 139 | **No** | Like default + prompt_injection, jailbreak, more egress entries | Massive overlap with default | Should be `extends: default`. |
| `cicd.yaml` | 116 | **No** | Like default minus prompt/jailbreak, different egress | Heavy overlap | Should be `extends: default`. |
| `ai-agent-posture.yaml` | 52 | `clawdstrike:ai-agent` | (inherited) + posture states | — | Good example of inheritance. |
| `remote-desktop.yaml` | 44 | `ai-agent` | + computer_use, side_channel, input_injection | — | Good. |
| `remote-desktop-strict.yaml` | 33 | `remote-desktop` | overrides | — | Good. |
| `remote-desktop-permissive.yaml` | 31 | `remote-desktop` | overrides | — | Good. |
| `spider-sense.yaml` | 19 | **No** | spider_sense only | — | Requires external env vars — not self-contained. |
| `origin-enclaves-example.yaml` | 160 | `"default"` | + origins + posture | — | Marked `-example`, which is honest. |

**Pattern DB:** `rulesets/patterns/s2bench-v1.json` — 38 entries, 3-dim demo embeddings. Comment in source says it's a demo. OK if labeled as such — but it's loaded by default when policy says `builtin:s2bench-v1` and tests use it for conformance assertions, so it's effectively a production pattern set in disguise.

**Policy-torture suite:** `rulesets/tests/policy-torture/` — base-core policy + four suites + a bash runner that writes report artifacts. Good idea. Uses the `hush policy test` CLI with `--min-coverage 100` for the gauntlet, which is genuinely strong.

### Python SDK (`packages/sdk/hush-py/`)

| Dimension | Status |
|---|---|
| Test files | 57 files, ~13K LOC of tests |
| Test naming | Mostly good (`test_check_shell_blocks_rm_rf`). One file uses `test1` as a string value (test_testing_module.py:181). One test uses `test_tmp_file_allowed` (acceptable). |
| Type hints in tests | Inconsistent. `test_decision.py`, `test_native_engine.py`, `test_typed_actions.py` use `-> None`. `test_native.py`, `test_canonical.py` do not. Mypy strict is set in pyproject but moon runs mypy on `src/` only — tests are unchecked. |
| `__init__.py` | Present in `tests/`. No package `__init__.py` issues found in `src/clawdstrike/`. |
| Skipped tests | 18+ `pytest.mark.skipif` instances, all justified by `NATIVE_AVAILABLE`, missing optional deps, or missing fixtures. Acceptable; "fixture not found" silent-skip in `test_policy_lab.py` lines 228/240 is a smell. |
| Live API tests | `test_openai_agents_dogfood.py` (736 LOC) and `test_detection_layers_dogfood.py` (962 LOC) gated by `OPENAI_API_KEY`. Dogfood-only files are fine but they fall through to "no tests collected" in CI without explicit opt-in. |
| `pyproject.toml` issues | (a) declares `packages = ["src/clawdstrike", "src/hush"]` but `src/hush/` does not exist; (b) coexists with a second `hush-native/pyproject.toml` that also names itself `clawdstrike` 0.2.7 with maturin backend and references a nonexistent `python/` source dir. |
| Setup.py | None present — good. |
| `dist/` | Two stale wheels (`clawdstrike-0.1.0`, `clawdstrike-0.2.4`) sit on disk but are not git-committed. Cleanup target. |
| `_recording_backend.py` | Always returns allow; lies-on-purpose mock. Documented as a fake but the routing tests built on it never exercise a real deny path. |

### Fuzz (`fuzz/`)

| Target | Corpus on disk | In gitignore | CI |
|---|---|---|---|
| `fuzz_sha256` | none | yes | nightly 120s |
| `fuzz_merkle` | none | yes | nightly 120s |
| `fuzz_policy_parse` | 3,218 local | yes (not committed) | nightly 120s |
| `fuzz_secret_leak` | none | yes | nightly 120s |
| `fuzz_dns_parse` | none | yes | nightly 120s |
| `fuzz_sni_parse` | none | yes | nightly 120s |
| `fuzz_irm_fs_parse` | 2 local | yes | nightly 120s |
| `fuzz_irm_net_parse` | 247 local | yes | nightly 120s |
| `fuzz_remote_extends_parse` | 1,601 local | yes | nightly 120s |

Corpora are **not committed** (good — keeps repo small). Trade-off: seed corpora aren't reproducible across CI hosts, so each nightly run discovers from scratch. For deterministic regressions, a `seeds/` dir of curated inputs per target would be the principal-engineer move.

### Fixtures (`fixtures/`)

| Group | Files | Notes |
|---|---|---|
| `canonical/` | 1 (`jcs_vectors.json`) | Golden RFC 8785 vectors. Clean. |
| `receipts/` | 11 (incl. `cua-migration/` subset, `envelope-equivalence/v1/`, `verification-bundle/v1/`) | Signed vectors. Largest is 17 KB — well under "huge snapshot" territory. |
| `policy/conformance_vectors.json` | 1 | Multi-parent DAG, deep merge, replace merge fixtures. Good. |
| `policy-events/` | ~30 case files across 18 subdirs, all `v1/cases.json` style | Versioned subdirs (`v1/`) is good. Some are 7-15 KB. |
| `policy-lab/` | 3 files | `expected_ocsf.jsonl` 10 KB — fine. |
| `hushspec/rulesets/` | 7 yaml files | **Duplicates the same files under `vendor/hushspec/rulesets/` with diffs.** Likely an out-of-date copy. |
| `certification/policies/` | 3 yaml (hipaa, pci-dss, soc2) | **Broken — see Findings.** |
| `threat-intel/` | 2 (`policy.yaml` + `events.jsonl`) | Looks fine, small. |
| `spider-sense/` | 2 conformance JSON | Cross-SDK conformance vectors. Good. |
| `ocsf/` | 5 JSON | OCSF samples. |
| `macos/` | dir present | Not inspected in depth. |
| `benchmarks/remote-latency/v1/cases.json` | 1 | 10 KB. Latency vectors. |

No fixture is over 17 KB. No snapshot has ballooned. **No PII spotted** — sample SSNs, MRNs in fixtures are documented test patterns.

### Top-level `tests/`

| File | Notes |
|---|---|
| `tests/registry-smoke.sh` | One-off bash smoke for the registry service. 8.9 KB. The only thing at this level. Should live under `crates/services/clawdstrike-registry/scripts/smoke.sh` or `mise.toml` task, not in a top-level `tests/` that implies broader purpose. |

### `vendor/`

| Path | Notes |
|---|---|
| `vendor/hushspec/` | Local path dep of `clawdstrike` lib (Cargo.toml line 33). Legitimate, but vendoring an external spec that you also depend on as `version = "0.1.1"` is unusual — typically this would be either fully external or fully merged. |

---

## Scores

| Dimension | Score | Notes |
|---|---|---|
| Test discipline (naming, structure) | **7/10** | Good Rust naming; Python tests cluster nicely; `e2e-posture-cmd` misclassified as a test crate; some construction-only tests. |
| Test depth (real vs trivial) | **6/10** | Formal-diff-tests and sdr-integration-tests are genuinely deep. `test_typed_actions.py`, several `test_native_engine.py` cases ("`assert engine is not None`") are constructor sanity only. |
| Ruleset quality / cohesion | **4/10** | Massive duplication across `default/strict/ai-agent/cicd`. `extends` exists but is barely used. Half the built-in guards never appear in core rulesets. |
| Python package quality | **5/10** | Two pyprojects with the same name, ghost source dirs, mypy strict that doesn't actually check tests, stale `dist/` artifacts. Good underlying type discipline in `src/`. |
| Fixture / test-data hygiene | **6/10** | Small, versioned, well-organized — but compliance fixtures are broken-as-shipped and hushspec fixtures duplicate `vendor/`. |
| CI integration of these tests | **6/10** | Fuzz has scheduled CI. Formal-diff-tests have proptest case knobs for PR/nightly. Policy-torture has its own runner. But k8s integration tests silent-skip; live OpenAI dogfood tests have no CI lane. |

---

## Strengths

These genuinely look professional and should be preserved or showcased:

1. **`formal-diff-tests`** is exemplary. Independent spec, proptest with shrink and env-driven case counts, named algebraic properties (P1–P11), regression files persisted. (`crates/tests/formal-diff-tests/proptest.toml`, `tests/aggregate_diff.rs`, `tests/merge_diff.rs`, `tests/cycle_diff.rs`)
2. **Policy-torture suite** with `--min-coverage 100` gauntlet and explicit depth/loop stress for the extends resolver. (`rulesets/tests/policy-torture/run.sh`)
3. **`e2e_pipeline.rs`** simulates the full bridge → envelope → checkpoint → witness → inclusion proof chain in-process with no external dependencies. Tampering checks for wrong-leaf and wrong-root. (`crates/tests/sdr-integration-tests/tests/e2e_pipeline.rs`)
4. **Fixture versioning** under `policy-events/<category>/v1/cases.json` — disciplined and makes schema evolution tractable.
5. **Python `conftest.py`** is short, fixtures are typed, sample policies are inline strings (not external files that drift).
6. **Fuzz coverage** of nine attack surfaces with a deterministic-looking `Arbitrary` derive for the structured `remote_extends_parse` target.
7. **`.gitignore` for `fuzz/`** correctly excludes `corpus/` and `artifacts/` so we don't bloat the repo with churn from libfuzzer.

---

## Findings

### [HIGH] [Rulesets] `default.yaml`, `strict.yaml`, `ai-agent.yaml`, `cicd.yaml` do not use `extends`

- **Where:** `rulesets/default.yaml`, `rulesets/strict.yaml`, `rulesets/ai-agent.yaml`, `rulesets/cicd.yaml`
- **What:** Each redeclares the same SSH/AWS/.env/Windows-credential blocks verbatim. `strict.yaml` line 11 even has the comment `# All default patterns plus more` — which is a textual admission that this should be `extends: default`. The four files together repeat ~30 patterns each. `grep -c "AppData\|NTUSER\|System32"` returns 7 hits in default.yaml, 9 in strict.yaml, 7 in ai-agent.yaml, 7 in cicd.yaml.
- **Why it matters:** This is the first thing a new contributor looks at. The repo ships a working `extends` mechanism, uses it correctly in the remote-desktop family, and then doesn't use it in the core four. It makes the rulesets look amateur even though the engine is sophisticated.
- **Recommended action:** RESTRUCTURE. Make `default.yaml` the root. `strict.yaml` extends default and *adds* (or use `merge_strategy: deep_merge` with `additional_patterns:`). `ai-agent.yaml` extends default with widened egress. `cicd.yaml` extends default with build-time deltas. `permissive.yaml` becomes `extends: default` with `remove_*` overrides instead of a separate world.
- **Effort:** Medium. The deep-merge / replace logic is tested; this is mostly authoring + a CI check that the resolved policies still match a golden.

### [HIGH] [Rulesets] Core rulesets do not enable six of thirteen built-in guards

- **Where:** `rulesets/default.yaml`, `rulesets/permissive.yaml`, `rulesets/cicd.yaml`
- **What:** Of the 13 built-in guards listed in `CLAUDE.md` (forbidden_path, path_allowlist, egress_allowlist, secret_leak, patch_integrity, shell_command, mcp_tool, prompt_injection, jailbreak, computer_use, remote_desktop_side_channel, input_injection_capability, spider_sense), `default.yaml` configures only 5 (forbidden_path, egress, secret_leak, patch_integrity, mcp_tool). `permissive.yaml` configures 2. `cicd.yaml` configures 5. `prompt_injection` and `jailbreak` are strict-only or ai-agent-only. `shell_command` and `path_allowlist` never appear in any built-in ruleset.
- **Why it matters:** `clawdstrike check --ruleset default ...` provides a notably thinner defense than the README's "13 built-in guards" suggests. The framing in CLAUDE.md ("Default — Balanced security for AI agent execution") does not match the contents.
- **Recommended action:** RESTRUCTURE. Either enable shell_command + prompt_injection + jailbreak in default (with sensible thresholds and `enabled: true`), or rename `default` to `default-minimal` and provide a `default-balanced` that activates the full set.
- **Effort:** Small.

### [HIGH] [Fixtures] Compliance policy fixtures are broken

- **Where:** `fixtures/certification/policies/hipaa-policy.yaml` lines 45–48, 53, 67, 82–84, 150, 157; `fixtures/certification/policies/pci-dss-policy.yaml` (similar pattern from line 50)
- **What:** Uses fields the engine does not recognize:
  - `default_action: deny` — engine expects `block`. Other rulesets in this repo use `default_action: block`.
  - `deny:` — engine expects `block:`. (PCI-DSS and HIPAA both.)
  - `additional_patterns:` without `merge_strategy: deep_merge` — only valid under deep merge.
  - `severity_threshold: warning`, `redact: true` on `secret_leak` — neither is a documented field.
  - Severity values `medium`, `high`, `low` — the canonical four are `info`/`warning`/`error`/`critical`.
- **Why it matters:** Anyone clicking "HIPAA policy template" gets a file that fails to load, or worse, silently fails open if `deny_unknown_fields` is not aggressive at every level. These are presented as "Compliance templates" in the README and CLAUDE.md — they should at least parse.
- **Recommended action:** REWRITE the three compliance fixtures so they parse against the current `Policy::from_yaml_with_extends`, OR delete them and replace with a single tested "compliance example" that uses real engine fields. Add a `cargo test` case that loads every YAML under `fixtures/certification/policies/`.
- **Effort:** Small to medium.

### [HIGH] [Python] Two `pyproject.toml` files claim the same package name

- **Where:** `packages/sdk/hush-py/pyproject.toml` (hatchling), `packages/sdk/hush-py/hush-native/pyproject.toml` (maturin)
- **What:** Both declare `name = "clawdstrike"`, `version = "0.2.7"`. The outer one uses `[build-system] requires = ["hatchling"]` and `force-include`s `../../../rulesets` into the wheel. The inner uses maturin to build a PyO3 extension named `clawdstrike._native`. They cannot both publish.
- **Why it matters:** Confusing build story. Whichever one publishes wins; the other is dead config. CI release scripts have to pick one and most reviewers won't know which. The inner one also references `python-source = "python"` and there is no `hush-native/python/` directory.
- **Recommended action:** RESTRUCTURE. Either:
  - (a) Keep maturin as primary, have it build the pure-Python wheel with the native extension bundled (`[tool.maturin] python-source = "../src"`); delete outer pyproject + hatchling config.
  - (b) Keep hatchling as primary, have the native extension build separately as a build-step (`hatch_build.py` hook) and bundle as a `.so` artifact.
- **Effort:** Medium.

### [HIGH] [Python] mypy `strict = true` is misleading

- **Where:** `packages/sdk/hush-py/pyproject.toml` line 58–62; `packages/sdk/hush-py/moon.yml` typecheck task
- **What:** `pyproject.toml` declares `[tool.mypy]\nstrict = true`. `moon.yml` runs `.venv/bin/mypy src/` — never `tests/`. `test_native.py` and `test_canonical.py` have zero `-> None` return annotations and would fail strict.
- **Why it matters:** "Typing :: Typed" classifier + strict mypy looks rigorous; not actually running it against tests means half the Python code in the repo is unchecked. Tests are the place users copy from.
- **Recommended action:** Either (a) extend the moon task to `mypy src/ tests/` and fix the annotations, or (b) add an explicit `[[tool.mypy.overrides]] module = "tests.*"` block that disables strict, so the README/classifier and the actual contract agree.
- **Effort:** Trivial (decision) + small (fixing annotations).

### [HIGH] [Python] `pyproject.toml` references nonexistent `src/hush` package

- **Where:** `packages/sdk/hush-py/pyproject.toml` line 48: `packages = ["src/clawdstrike", "src/hush"]`
- **What:** `src/hush` does not exist on disk (`find src -type d` returns only `clawdstrike` subtree).
- **Why it matters:** Build will either fail or quietly skip. Indicates either dead config (legacy `hush` namespace that got renamed to `clawdstrike`) or unfinished work.
- **Recommended action:** WIPE the `src/hush` entry. Or, if it's truly intended as a stub for the future `import hush` -> `clawdstrike` shim, scaffold it with a `__init__.py` re-export.
- **Effort:** Trivial.

### [MEDIUM] [Tests/Integration] k8s_audit_bridge_reliability tests silently no-op

- **Where:** `crates/tests/sdr-integration-tests/tests/k8s_audit_bridge_reliability.rs` lines 313, 337, 384
- **What:** Three `#[tokio::test]` functions each begin with:
  ```rust
  let harness = match NatsHarness::start().await {
      Ok(h) => h,
      Err(err) => {
          eprintln!("skipping integration test: {err}");
          return;
      }
  };
  ```
  When Docker is unavailable and `nats-server` is not on PATH, the test prints to stderr and returns Ok. To `cargo test` it looks identical to a passing test.
- **Why it matters:** CI shows green; nothing ran. A future change that breaks the bridge ingestion will pass CI until someone notices the eprintln.
- **Recommended action:** REWRITE the gate. Use `#[ignore]` with a documented `cargo test -- --ignored --include-ignored` lane, OR fail the test when Docker/NATS missing with an explicit env opt-out (`CLAWDSTRIKE_SKIP_NATS_IT=1`). Also publish a CI job that brings up NATS and asserts the tests ran.
- **Effort:** Small.

### [MEDIUM] [Tests] `e2e-posture-cmd` is not a test crate

- **Where:** `crates/tests/e2e-posture-cmd/Cargo.toml`, `crates/tests/e2e-posture-cmd/src/main.rs`
- **What:** This is a `[[bin]]`-only crate that publishes a CLI to send signed posture commands to NATS. It has no `tests/` directory and no `#[test]` functions. It lives under `crates/tests/` purely by convention.
- **Why it matters:** Mixed taxonomy. New contributors look at `crates/tests/` and expect tests. A CLI tool for ops/CI belongs under `crates/tools/`, `crates/services/`, or `tools/`.
- **Recommended action:** RESTRUCTURE — move to `tools/e2e-posture-cmd/` or `crates/tools/e2e-posture-cmd/`.
- **Effort:** Trivial.

### [MEDIUM] [Tests] Recording backend lies (always allows)

- **Where:** `packages/sdk/hush-py/tests/_recording_backend.py` lines 16–25
- **What:** Every `check_*` method returns `{"overall": {"allowed": True, ...}, "per_guard": []}`. It records arguments but never reproduces a real deny verdict.
- **Why it matters:** Tests built on it (`test_facade.py` line 84+, and the test_session/test_origin tests) prove routing — "the facade called the right backend method with the right args" — but never prove "and the deny verdict propagates correctly." If `Decision.from_backend_dict` ever miscomputes status the recording-backend tests would not catch it.
- **Recommended action:** REWRITE. Either add a `RecordingBackend.with_verdict(decision)` constructor so tests can also exercise deny paths, or split into two doubles: `AllowingRecordingBackend` and `DenyingRecordingBackend`.
- **Effort:** Small.

### [MEDIUM] [Rulesets] `permissive.yaml` is dangerously thin

- **Where:** `rulesets/permissive.yaml` (24 lines)
- **What:** Configures only `egress_allowlist` (with `allow: ["*"]`) and `patch_integrity`. No `forbidden_path`, no `secret_leak`, no `mcp_tool`. A developer who picks "permissive for local dev" has zero secret-leak detection and zero shell-command gating — defeating the point of the framework.
- **Why it matters:** Permissive should mean "broader allowlist," not "no defenses." This sets a poor mental model of what the system does at minimum.
- **Recommended action:** REWRITE. `permissive.yaml` should `extends: default` and only relax the egress block list. Keep secret_leak and forbidden_path on.
- **Effort:** Trivial.

### [MEDIUM] [Rulesets] `spider-sense.yaml` requires unset env vars to even parse-and-resolve

- **Where:** `rulesets/spider-sense.yaml` lines 11–12
- **What:** `embedding_api_url: "${SPIDER_SENSE_EMBEDDING_URL}"` and `embedding_api_key: "${SPIDER_SENSE_EMBEDDING_KEY}"`. If the engine doesn't expand env vars, this is a literal string. If it does, an unset env var produces empty strings.
- **Why it matters:** Shipped ruleset cannot be loaded out of the box. The other rulesets are runnable without env config.
- **Recommended action:** DOCUMENT. Add a comment header stating "this policy is a stencil — requires env vars set." Or REWRITE to use the embedded `builtin:s2bench-v1` pattern DB only (no remote embedding API) so it works standalone.
- **Effort:** Trivial.

### [MEDIUM] [Fixtures] `fixtures/hushspec/rulesets/` duplicates `vendor/hushspec/rulesets/` with diffs

- **Where:** `fixtures/hushspec/rulesets/{cicd,permissive,remote-desktop,ai-agent,strict,default}.yaml` vs `vendor/hushspec/rulesets/{...}.yaml`
- **What:** Both directories have the same set of YAML files, but `diff` shows real differences (newer comments, reorganized blocks). The fixtures copy lags the vendor copy.
- **Why it matters:** Test fixtures should not silently drift from the spec they assert against. If the intent is "fixture = pinned version of what hushspec used to look like," that needs a `README.md` saying so.
- **Recommended action:** RESTRUCTURE. Either (a) delete `fixtures/hushspec/rulesets/` and have tests point at `vendor/hushspec/rulesets/`, or (b) add a CI step that `diff`s the two and fails when they drift unintentionally, with a `pin: 2026-MM-DD` header.
- **Effort:** Trivial.

### [MEDIUM] [Python] Stale wheels in `dist/`

- **Where:** `packages/sdk/hush-py/dist/{clawdstrike-0.1.0,clawdstrike-0.2.4}-py3-none-any.whl` + tarballs
- **What:** Two old built wheels present (current version is 0.2.7). Not git-tracked but they're present in a working tree referenced by the moon task.
- **Why it matters:** Clutter; possible accidental re-publish of an old artifact; people doing `ls dist/` get confused about what's current.
- **Recommended action:** WIPE locally + add a `clean` task that nukes `dist/` before `build`. Already gitignored, so no upstream change needed.
- **Effort:** Trivial.

### [MEDIUM] [Python] `_native` import-path drift between maturin and hatchling configs

- **Where:** `packages/sdk/hush-py/hush-native/pyproject.toml` line 27 (`module-name = "clawdstrike._native"`), but the outer pyproject builds `src/clawdstrike` via hatchling which has no `_native` to bundle.
- **What:** The native module would have to be built and installed into `src/clawdstrike/` for either build to ship a working wheel with the native acceleration. There's no glue in the moon task or pyproject that does this.
- **Why it matters:** `clawdstrike.native.NATIVE_AVAILABLE` will always be False from a hatchling build; the 18+ `skipif(not NATIVE_AVAILABLE)` tests skip silently. So the native fast path is largely untested through the SDK test surface.
- **Recommended action:** REWRITE. Pick one build backend, document `maturin develop` as the test invocation, gate CI on a job that builds native then runs the skipif'd suites with native enabled.
- **Effort:** Medium.

### [MEDIUM] [Tests] `test_typed_actions.py` and many `test_native_engine.py` cases are constructor-only

- **Where:** `packages/sdk/hush-py/tests/test_typed_actions.py` lines 16–47; `packages/sdk/hush-py/tests/test_native_engine.py` lines 29–51
- **What:** Tests like `test_file_access_action` do `a = FileAccessAction(path="/test"); assert a.path == "/test"; assert a.action_type == "file_access"`. These assert that a dataclass works — they don't test any behavior. Same with `engine = native_mod.NativeEngine.from_ruleset("strict"); assert engine is not None` four times.
- **Why it matters:** Low-signal tests inflate the test-count metric while providing no regression value.
- **Recommended action:** REWRITE. Replace the constructor sanity tests with parameterized table-tests that exercise real behavior. Keep one "all action subclasses are frozen" + one "all action subclasses have correct action_type" test.
- **Effort:** Small.

### [MEDIUM] [Fuzz] No seed corpora committed

- **Where:** `fuzz/.gitignore` line 1–3 (`corpus/`, `artifacts/`)
- **What:** Every fuzz run starts from an empty corpus. The nightly CI gets 120s per target, which is too little to rediscover non-trivial inputs from scratch.
- **Why it matters:** Real crashes get discovered, fixed, and then their inputs are lost — no regression seeds. The structured `RemoteExtendsInput` `Arbitrary` derive will be fine; the unstructured `policy_parse` will not.
- **Recommended action:** RESTRUCTURE. Add `fuzz/seeds/<target>/` committed minimal corpora (5-20 inputs per target) and configure the CI invocation to use them: `cargo +nightly fuzz run <target> seeds/<target> -- -max_total_time=120`.
- **Effort:** Small.

### [MEDIUM] [Tests] Top-level `tests/registry-smoke.sh` is the only thing at that level

- **Where:** `tests/registry-smoke.sh`
- **What:** 9 KB bash smoke test for the registry service. Top-level `tests/` directory has no README, no consistent layout, and only this one script.
- **Why it matters:** Top-level `tests/` implies "this is where I find tests for the whole project," but the actual test corpus lives in `crates/`, `packages/`, `rulesets/tests/`. A new contributor looks here and finds one bash script and is confused.
- **Recommended action:** RESTRUCTURE — move to `crates/services/clawdstrike-registry/scripts/smoke.sh` (where the rest of registry code lives) or to `scripts/smoke/registry.sh` alongside the existing `scripts/` directory.
- **Effort:** Trivial.

### [LOW] [Rulesets] `remote-desktop-strict.yaml` describes overrides not deltas, but loses observability options

- **Where:** `rulesets/remote-desktop-strict.yaml` lines 12–15
- **What:** Strict extends remote-desktop but redeclares `allowed_actions:` for `computer_use`, going from 10 actions to 3. There's no `disallowed:` semantics so this is fine, but a reader has to know that the redeclaration replaces.
- **Why it matters:** Minor readability concern; trips up reviewers who'd expect deltas.
- **Recommended action:** DOCUMENT — add an inline comment `# replaces inherited allowed_actions:` so the intent is explicit.
- **Effort:** Trivial.

### [LOW] [Tests] `e2e_pipeline.rs` hand-rolls `simulate_ingest_contract` and may drift

- **Where:** `crates/tests/sdr-integration-tests/tests/e2e_pipeline.rs` lines 38–98, 568–638
- **What:** Defines a `SimulatedCheckpointerState` and `simulate_ingest_contract` function that asserts envelope_kv → log → fact_index → issuer_heads ordering. This is intended to mirror the real `spine-checkpointer` ingest path.
- **Why it matters:** If the production ingest changes order or adds a step (TTL, signature check), the simulation won't and the test will pass but won't reflect production.
- **Recommended action:** DOCUMENT — add a comment with a link to the file where the real ingest contract lives, plus a doc-test or compile-time assertion (`const _: () = { let _ = real_ingest_contract; };`) that fails when the real contract evolves.
- **Effort:** Trivial.

### [LOW] [Tests] Several `#[allow(clippy::expect_used, clippy::unwrap_used)]` at file scope

- **Where:** `crates/tests/sdr-integration-tests/tests/e2e_pipeline.rs:16`, `tests/bridge_roundtrip_test.rs:6`, `tests/k8s_audit_bridge_reliability.rs:1`
- **What:** The workspace deny lints for `expect_used` and `unwrap_used` are globally allowed in all three integration test files.
- **Why it matters:** Workspace `clippy.toml` and `Cargo.toml` enforce no `unwrap`/`expect` in production code. Tests get a blanket pass, which is reasonable, but the `#![allow(...)]` at the top of the file means a test author would never see a lint nudge them toward better failure messages.
- **Recommended action:** DOCUMENT — add a comment explaining why tests opt out, or LEAVE. Consider switching to `assert!(...)` with named messages for clearer test output.
- **Effort:** Trivial.

### [LOW] [Tests] Some tests in `policy-torture` workspace are textual hints, not real fixtures

- **Where:** `rulesets/tests/policy-torture/workspace/allowed.txt` (`policy-torture workspace fixture`); `workspace/company-secrets/token.txt` (`fake-secret-token`)
- **What:** The fixture path `**/company-secrets/**` is matched by the deep-merge-overlay policy's `forbidden_path.additional_patterns`, and the token content is just `fake-secret-token`. Real assertions don't depend on the file contents — only on the path.
- **Why it matters:** No actual PII concern. The note is that the file content suggests it might contain a real-looking secret (it doesn't), which is good. Worth keeping as-is.
- **Recommended action:** LEAVE.

### [LOW] [Fixtures] `s2bench-v1.json` is described as "demo embeddings" but is loaded as production

- **Where:** `rulesets/patterns/s2bench-v1.json` (38 entries, 3-dim embeddings)
- **What:** Embeddings are 3-dimensional (e.g. `[0.95, 0.05, 0.0]`). Real `text-embedding-3-small` produces 1536-dim vectors. So similarity computed against this DB is geometrically nonsense once the live embedding API is hooked up.
- **Why it matters:** A user who configures `embedding_api_url` and `pattern_db_path: "builtin:s2bench-v1"` will get cosine similarities that are mathematically incoherent.
- **Recommended action:** DOCUMENT — rename file to `s2bench-v1-demo.json` and add a header comment saying "do not use with real embedding APIs; ship a real-dim pattern DB out-of-band." OR ship a real-dim DB.
- **Effort:** Small (rename + comment) to large (build real DB).

### [LOW] [Tests] `proptest.toml` has no companion `regressions/` directory committed

- **Where:** `crates/tests/formal-diff-tests/proptest.toml` line 19
- **What:** `failure_persistence = "file"` means proptest writes `.txt` regression files next to the test files when shrinking finds a counterexample. The git tree currently has none — either because no counterexample has ever been found, or because they've been gitignored.
- **Why it matters:** "We hit a property failure and now it's lost" is a worse outcome than "we hit a property failure and the regression seed is in git."
- **Recommended action:** DOCUMENT — add a `crates/tests/formal-diff-tests/proptest-regressions/.gitkeep` and explicitly do NOT gitignore `proptest-regressions/*.txt`. Mention in README that committed regressions are intentional.
- **Effort:** Trivial.

### [LOW] [Rulesets] No `path_allowlist` example anywhere in `rulesets/`

- **Where:** all of `rulesets/*.yaml`
- **What:** `path_allowlist` is one of the 13 built-in guards. It appears only in `rulesets/tests/policy-torture/policies/base-core.yaml` and `replace-overlay.yaml` — as test fixtures, not in any ruleset a user would adopt.
- **Why it matters:** Users have to discover by reading source that `path_allowlist` exists. No production ruleset demonstrates how to use it.
- **Recommended action:** DOCUMENT — add a `path_allowlist:` block to `default.yaml` (with a permissive default) so the feature is discoverable.
- **Effort:** Trivial.

### [LOW] [Tests] `test_testing_module.py` line 181 has a fixture-name `test1`

- **Where:** `packages/sdk/hush-py/tests/test_testing_module.py:181` — `{"name": "test1", "action": "file_access", "target": "/tmp/x"}`
- **What:** A scenario name "test1" inside a fixture. Not a `def test_test1` — but the value is uninformative.
- **Why it matters:** Real grep audits for "test1" / "test_foo" patterns flag this. A scenario name like `read_tmp_x` would be self-documenting.
- **Recommended action:** REWRITE — rename to something descriptive.
- **Effort:** Trivial.

### [LOW] [Tests] Live OpenAI dogfood tests have no CI lane visible in workflows

- **Where:** `packages/sdk/hush-py/tests/test_openai_agents_dogfood.py:48`, `tests/test_detection_layers_dogfood.py:42`
- **What:** Two 700–960 LOC files gated on `OPENAI_API_KEY`. `.github/workflows/` does not appear to have a job that sets `OPENAI_API_KEY` and runs only these.
- **Why it matters:** Big tests sit in tree, never run, slowly bitrot. If they're aspirational, that should be explicit.
- **Recommended action:** RESTRUCTURE — either move to `packages/sdk/hush-py/tests/dogfood/` with a separate pytest config + a dedicated `workflow_dispatch` GH workflow, or DOCUMENT in the test docstring why they aren't on CI.
- **Effort:** Small.

### [LOW] [Crates/tests] `crates/tests/README.md` is one line

- **Where:** `crates/tests/README.md`
- **What:** Contents: "Cross-component and integration test crates live here."
- **Why it matters:** First impression. A reader expects a table of crates + what each tests + how to run them.
- **Recommended action:** REWRITE — add a one-paragraph-per-crate index, the cargo invocation, and the PROPTEST_CASES knob.
- **Effort:** Trivial.

### [LOW] [Tests] `policy-torture/run.sh` `cat > "${REPORTS_DIR}/05-extends-depth-loop-stress.json" <<EOF` hand-builds JSON

- **Where:** `rulesets/tests/policy-torture/run.sh` lines 119–141 and similar
- **What:** Builds canned PASS JSON reports via heredoc after running the actual check. So if `run_expected_policy_load_failure` passes its grep but actually didn't fail correctly for the right reason, the report still shows PASS because the script wrote the literal PASS json.
- **Why it matters:** Reports decouple from real test status. A subtle change in error messages could pass the grep but the JSON would be definitionally PASS regardless.
- **Recommended action:** REWRITE — have `run_expected_policy_load_failure` emit its own status string and templatize the JSON. Or, even better, port the depth/loop stress cases into the `hush policy test` framework directly so the same report writer is used for all suites.
- **Effort:** Small.

### [LOW] [Vendor] `vendor/hushspec/` is both vendored and `version = "0.1.1"` declared

- **Where:** `crates/libs/clawdstrike/Cargo.toml:33` — `hushspec = { version = "0.1.1", path = "../../../vendor/hushspec", optional = true }`
- **What:** Cargo path deps shadow the crates.io version. Specifying both means cargo uses the path locally and the version for publication metadata. Fine in principle, but it implies `hushspec 0.1.1` is published on crates.io and the vendored copy may or may not match.
- **Why it matters:** Vendoring a thing you also depend on as a version is unusual. Either pull it in as a real workspace member (since it has its own `src/`, `tests/`, `Cargo.toml`) or remove the path dep and consume from crates.io.
- **Recommended action:** RESTRUCTURE — either promote `vendor/hushspec/` to `crates/libs/hushspec/` and remove the version pin, or unvendor and pin to a specific crates.io version. Either way, eliminate the double-source-of-truth.
- **Effort:** Medium.

### [LOW] [Tests] Pyproject `tests/` directory is implicit, no `__init__.py` per subdir

- **Where:** `packages/sdk/hush-py/tests/`
- **What:** Single `__init__.py` at the top. Tests reference `from tests._recording_backend import RecordingBackend` (e.g. `test_facade.py:15`), which works only because pytest adds the parent.
- **Why it matters:** Modern pytest convention is `rootdir/tests/conftest.py` discovery without packaged tests. Using `from tests...` couples to layout.
- **Recommended action:** LEAVE — works fine. Could simplify by moving `_recording_backend.py` to `conftest.py` as a fixture, but optional.
- **Effort:** Trivial.

### [LOW] [Fixtures] No fixture-loading helper or schema validation

- **Where:** `fixtures/`
- **What:** Tests load fixtures via raw `json.loads(Path(...).read_text())`. There's no central `load_fixture(name)` helper that validates schema versions.
- **Why it matters:** Schema evolution is painful. A breaking change to a `v1/cases.json` will surface as JSON-key errors in random tests rather than one validator error.
- **Recommended action:** RESTRUCTURE — add a `fixtures/_loader.py` (Python) and `fixtures::Loader` (Rust) that validates against a JSON Schema per fixture group. Versioned subdirs make this clean.
- **Effort:** Medium.

### [LOW] [Tests] `bridge_roundtrip_test.rs` includes `make_*` helpers that duplicate `e2e_pipeline.rs`

- **Where:** `crates/tests/sdr-integration-tests/tests/bridge_roundtrip_test.rs:19–100` vs `e2e_pipeline.rs:110–138`
- **What:** Both files define `make_process`, `make_tetragon_process`, hubble endpoint/flow helpers. Same structure, slight differences. The `sdr-integration-tests/src/lib.rs` is empty save a comment.
- **Why it matters:** Drift risk when one helper is updated and the other isn't.
- **Recommended action:** REWRITE — move helpers into `crates/tests/sdr-integration-tests/src/lib.rs` (or a `src/helpers.rs`) and have both test files import them.
- **Effort:** Trivial.

### [LOW] [Tests] `sdr-integration-tests` uses tokio + async-nats but no test gate for missing async-nats version

- **Where:** `crates/tests/sdr-integration-tests/Cargo.toml:18` — `async-nats = "0.40"`
- **What:** `async-nats` 0.40 is unpinned to a specific minor; integration tests will silently rebuild against semver-compatible upgrades.
- **Why it matters:** Test reproducibility. A new minor of async-nats subtly changing semantics could break tests in CI without a clear "we bumped the dep" commit.
- **Recommended action:** DOCUMENT — pin to `= "0.40.0"` or use `Cargo.lock` discipline (which exists for binaries but not always honored for test crates).
- **Effort:** Trivial.

---

## Action Plan

### Phase 1: Quick wipe (1 day)

1. Delete `dist/` artifacts (`packages/sdk/hush-py/dist/clawdstrike-0.1.0*` and `0.2.4*`).
2. Remove `src/hush` from `pyproject.toml:48`.
3. Rename `s2bench-v1.json` to `s2bench-v1-demo.json` and add header comment.
4. Move `tests/registry-smoke.sh` to `scripts/smoke/registry.sh`.
5. Move `crates/tests/e2e-posture-cmd/` to `tools/e2e-posture-cmd/`.
6. Write `crates/tests/README.md` with a real index.
7. Rename `"test1"` literal in `test_testing_module.py:181`.

### Phase 2: Restructure rulesets (2-3 days)

1. Rewrite `default.yaml` as the canonical root with all 13 guards enabled where sensible.
2. Convert `strict.yaml`, `ai-agent.yaml`, `cicd.yaml`, `permissive.yaml` to `extends: default` with deep-merge / replace deltas.
3. Add CI test that loads each ruleset, resolves extends, and golden-compares the fully resolved policy.
4. Add a `path_allowlist:` block to `default.yaml`.
5. Make `spider-sense.yaml` work out-of-the-box using `builtin:s2bench-v1` only.

### Phase 3: Fix compliance fixtures (1-2 days)

1. Rewrite `hipaa-policy.yaml`, `pci-dss-policy.yaml`, `soc2-policy.yaml` to use real engine field names + valid severity values.
2. Add `cargo test` case that loads every YAML under `fixtures/certification/policies/`.
3. Or: delete and replace with a single tested `fixtures/certification/policies/example.yaml`.

### Phase 4: Python packaging unification (2-3 days)

1. Pick a single build backend (maturin recommended — already builds the native ext).
2. Delete the redundant pyproject.
3. Make `mypy` actually check `tests/` (and fix annotations) OR explicitly carve tests out in pyproject.
4. Document the build in `packages/sdk/hush-py/README.md`.

### Phase 5: Test depth (1-2 weeks)

1. Replace `RecordingBackend` always-allow with parameterizable decision.
2. Wipe constructor-only tests in `test_typed_actions.py`, `test_native_engine.py`; replace with behavior tests.
3. Convert `k8s_audit_bridge_reliability.rs` silent skips to `#[ignore]` + dedicated CI job.
4. Add committed seed corpora under `fuzz/seeds/<target>/`.
5. Hoist `make_*` helpers from sdr integration tests into the crate `lib.rs`.

### Phase 6: Polish (ongoing)

1. Document live-dogfood test running model + add `workflow_dispatch` GH workflow.
2. Add fixture-schema validator helper.
3. Pin async-nats version exactly.
4. Consolidate `vendor/hushspec/` into workspace.
5. Make `policy-torture/run.sh` report JSON from real run state, not heredoc canned PASS.

---

## Top 10 Quick Wins

In order of effort-to-impact:

1. **Delete `packages/sdk/hush-py/dist/clawdstrike-0.1.0*` and `0.2.4*`** — 30 seconds, removes confusing stale artifacts.
2. **Remove `"src/hush"` from `pyproject.toml`** — 30 seconds, removes ghost package reference.
3. **Make `permissive.yaml` `extends: default`** — 5 minutes, removes the "permissive means defenseless" trap.
4. **Add `path_allowlist:` block to `default.yaml`** — 10 minutes, makes a guard discoverable.
5. **Rename `s2bench-v1.json` → `s2bench-v1-demo.json` with a comment** — 5 minutes, signals it's not production-ready.
6. **Move `crates/tests/e2e-posture-cmd/` to `tools/`** — 15 minutes, fixes taxonomy.
7. **Move `tests/registry-smoke.sh` under `scripts/`** — 5 minutes, removes lonely top-level dir.
8. **Write a real `crates/tests/README.md`** — 30 minutes, professionalism signal at a glance.
9. **Convert `strict.yaml`, `ai-agent.yaml`, `cicd.yaml` to use `extends: default`** — 1-2 hours, the highest-visibility "this team knows what they're doing" change.
10. **Fix or delete the broken compliance fixtures (`hipaa-policy.yaml`, `pci-dss-policy.yaml`, `soc2-policy.yaml`)** — 2-4 hours, removes the most embarrassing aspirational shipping.

---

## Things to Leave Alone

These are doing fine. Don't touch:

- **`crates/tests/formal-diff-tests/`** — the proptest setup, env-driven case counts, and named algebraic properties are exactly what you want a code-tour reviewer to see. Keep it.
- **`crates/tests/sdr-integration-tests/tests/e2e_pipeline.rs`** — self-contained pipeline test with tamper checks. Strong.
- **`rulesets/tests/policy-torture/suites/04-guard-gauntlet.policy-test.yaml`** — exercises every built-in guard. Don't simplify.
- **`fixtures/canonical/jcs_vectors.json`** and the `receipts/cua-migration/` collection — well-structured golden vectors.
- **`packages/sdk/hush-py/src/clawdstrike/_version.py`** — careful semver parser with leading-zero rejection. Good.
- **`fuzz/.gitignore` excluding corpus/artifacts** — correct for a healthy fuzz setup (just add committed seeds).
- **`crates/tests/formal-diff-tests/proptest.toml`** — thoughtful defaults and clear CI-override comments.
- **The fixture versioning convention `<category>/v1/cases.json`** — keep extending this pattern.

---

*Audit date: 2026-05-23. Source: `clawdstrike` repo @ `fix/macos-es-ne-hardening` branch.*
