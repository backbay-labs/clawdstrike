# DELTA D09: Tests, Rulesets, Misc

**Refreshed:** 2026-05-24 | **Source:** `.audit/09-tests-rulesets-misc.md` (2026-05-23) + wave3 `I-scripts-py-triage.md`, `J-infra-vendor-audit.md` | **Scope:** `rulesets/`, `tests/` (top-level), `fuzz/`, `fixtures/`, `integrations/`, `tools/`, repo-root `vendor/`, compliance fixtures

---

## Quick Verdict

- **Findings still valid:** 30 of 30 (every concrete claim in the original audit reproduces at HEAD).
- **Findings fixed since 2026-05-23:** 0. Nothing in the scoped tree was touched in the past 24 hours; `git log --since="2026-05-23" -- rulesets tests fuzz fixtures integrations tools vendor` returns empty.
- **Findings wrong/misdiagnosed:** 1 small numeric error — `s2bench-v1.json` has **36 entries**, not 38 as the audit said. The audit later self-corrects in §Inventory ("36 entries, 3-dim demo embeddings"), so this is an internal inconsistency, not a bad call. The dimensionality (3) and "demo" framing are correct.
- **New issues found:** 5 (see [NEW ISSUES](#new-issues)). The most material: the `fixtures/hushspec/` <-> `vendor/hushspec/rulesets/` "drift" is actually two *different schemas* (legacy `hushspec: "0.1.0"` / `rules:` vs current `version: "1.x"` / `guards:`), not a stale copy — recommendation needs to be sharpened; `vendor/hushspec/` is also a **legitimate first-party tracked workspace member** that wave3-J explicitly excluded from scope and that this audit understated.
- **Rulesets using `extends:`:** 5 of 11 (`ai-agent-posture.yaml`, `origin-enclaves-example.yaml`, `remote-desktop.yaml`, `remote-desktop-strict.yaml`, `remote-desktop-permissive.yaml`). The other 6 (`default.yaml`, `permissive.yaml`, `strict.yaml`, `ai-agent.yaml`, `cicd.yaml`, `spider-sense.yaml`) do not — original finding stands.
- **Default ruleset guard count:** 5 of 13 (`forbidden_path`, `egress_allowlist`, `secret_leak`, `patch_integrity`, `mcp_tool`). Audit's "5 of 13" is exact. Original framing of "6 of 13 guards missing from default" is slightly imprecise — it's **8 of 13 missing** from `default.yaml`, but `prompt_injection` / `jailbreak` / `computer_use` / `remote_desktop_side_channel` / `input_injection_capability` / `spider_sense` are deliberate ai-agent / remote-desktop / spider-sense only. The truly missing-from-anywhere-core ones are **`path_allowlist`** and **`shell_command`** — these never appear in any user-facing ruleset (only in `rulesets/tests/policy-torture/policies/`).
- **Net delta:** The 2026-05-23 audit is **fully accurate and fully unactioned**. Nothing was fixed; nothing got worse. The five new issues are all low-severity items the original audit missed because it didn't drill into repo-root `vendor/`, didn't notice the local working-tree `tools/scripts/__pycache__` modification, and didn't compare hushspec schemas across the two paths. The aggressive-ceiling execution plan in §AGGRESSIVE EXECUTION PLAN is essentially the original audit's Top-10 with three additions and one reframing.

---

## STILL VALID

Every finding in the source audit reproduces at HEAD. Listed in priority/severity order with file:line citations from re-verification.

### [HIGH] Rulesets — `default/strict/ai-agent/cicd` do not use `extends`

**Status:** STILL VALID at HEAD. Verified by `grep -L "^extends:" rulesets/*.yaml`.

- `rulesets/default.yaml:1-119` — no `extends:`, has 5 inline guards.
- `rulesets/strict.yaml:1-130` — no `extends:`, comment at line 11 still says `# All default patterns plus more`, which (as the audit noted) is a textual admission. Line 12-30 verbatim duplicates lines 12-30 of `default.yaml`.
- `rulesets/ai-agent.yaml:1-139` — no `extends:`, duplicates the same SSH/AWS/Windows path block.
- `rulesets/cicd.yaml:1-116` — no `extends:`, duplicates the same block.
- `rulesets/permissive.yaml:1-24` — no `extends:`, but its problem is different (only 2 guards configured) and addressed below.
- `rulesets/spider-sense.yaml:1-19` — no `extends:` either; standalone single-guard config.

Compare the **5 rulesets that DO use `extends:`**:
- `rulesets/ai-agent-posture.yaml:?` — `extends: clawdstrike:ai-agent`
- `rulesets/origin-enclaves-example.yaml` — `extends: "default"`
- `rulesets/remote-desktop.yaml` — `extends: ai-agent`
- `rulesets/remote-desktop-strict.yaml` — `extends: remote-desktop`
- `rulesets/remote-desktop-permissive.yaml` — `extends: remote-desktop`

The engine's `merge_strategy: deep_merge` machinery exists, is tested at `crates/libs/clawdstrike/src/policy.rs:3271-3450`, and is used by the remote-desktop family — but the core four user-facing rulesets opt out. Audit recommendation (RESTRUCTURE) stands.

### [HIGH] Rulesets — Core rulesets do not enable all 13 built-in guards

**Status:** STILL VALID at HEAD. Reframed slightly for precision.

Verified by `grep -E "^\s+(<guard>:)" rulesets/*.yaml`:

| Ruleset | Guards configured | Count |
|---|---|---|
| `default.yaml` | `forbidden_path`, `egress_allowlist`, `secret_leak`, `patch_integrity`, `mcp_tool` | 5/13 |
| `permissive.yaml` | `egress_allowlist`, `patch_integrity` | 2/13 |
| `strict.yaml` | `forbidden_path`, `egress_allowlist`, `secret_leak`, `patch_integrity`, `mcp_tool`, `prompt_injection`, `jailbreak` | 7/13 |
| `ai-agent.yaml` | same 7 as strict | 7/13 |
| `cicd.yaml` | 5 (no prompt_injection/jailbreak) | 5/13 |
| `remote-desktop.yaml` (+ variants) | `computer_use`, `remote_desktop_side_channel`, `input_injection_capability` (inherited rest from ai-agent) | varies |
| `spider-sense.yaml` | `spider_sense` only | 1/13 |

The audit said "6 of 13 missing from core rulesets" — the precise figure is:

- **`path_allowlist`**: appears in **zero** user-facing rulesets. Only in test fixtures (`rulesets/tests/policy-torture/policies/{replace-overlay,base-core}.yaml`).
- **`shell_command`**: appears in **zero** user-facing rulesets. (Despite the CLAUDE.md description and the prominence of `clawdstrike check` for shell guards.)
- **`prompt_injection`**: in `strict.yaml`, `ai-agent.yaml`. Missing from `default`, `permissive`, `cicd`.
- **`jailbreak`**: same set as `prompt_injection`.
- **`computer_use`, `remote_desktop_side_channel`, `input_injection_capability`**: remote-desktop family only — defensible.
- **`spider_sense`**: spider-sense ruleset only — defensible but `spider-sense.yaml` itself doesn't work without env vars (see next finding).

The 2 truly hidden guards are `path_allowlist` and `shell_command`. The audit's framing is roughly right but the cleaner statement is: **2 guards are invisible to anyone reading the shipped rulesets**.

### [HIGH] Compliance fixtures are broken

**Status:** STILL VALID at HEAD. Every specific syntactic violation reproduced.

Verified at `fixtures/certification/policies/{hipaa,pci-dss,soc2}-policy.yaml`:

| Issue | HIPAA line | PCI-DSS line | SOC2 line |
|---|---|---|---|
| `default_action: deny` (engine expects `block`) | 53, 150 | 57, 189 | 53 |
| `deny:` block (engine expects `block:`) | 157 | 196 | 173 |
| `additional_patterns:` without `merge_strategy: deep_merge` | 45 | 50 | — (none used) |
| `severity_threshold: warning/critical` (not a documented field) | 84 | 87 | 91 |
| `redact: true` on `secret_leak` (not a documented field) | 83 | 86 | 90 |
| Severity values `medium`/`high`/`low` | 99, 103, 113, 117, 122, 127 | (multiple) | (multiple) |

The engine has `#[serde(deny_unknown_fields)]` at 10+ struct definitions in `crates/libs/clawdstrike/src/policy.rs` (lines 62, 178, 251, 498, 509, 520, 531, 544, 564, 580). So these files will fail to load at parse time, not silently — that's a small mercy. The audit's call to either fix or delete them stands. **Aggressive ceiling: DELETE all three**, replace with one tested `example.yaml` that uses real fields. (Recommended below.)

### [HIGH] Python — two `pyproject.toml` files with same package name

**Status:** STILL VALID at HEAD.

- `packages/sdk/hush-py/pyproject.toml:2-3` — `name = "clawdstrike"`, `version = "0.2.7"`, hatchling backend, `packages = ["src/clawdstrike", "src/hush"]`, `force-include`s `../../../rulesets`.
- `packages/sdk/hush-py/hush-native/pyproject.toml:6-7` — `name = "clawdstrike"`, `version = "0.2.7"`, maturin backend, `module-name = "clawdstrike._native"`, `python-source = "python"` (line 47).

Both declare themselves the canonical `clawdstrike` package. They cannot both publish to PyPI. The maturin pyproject's `python-source = "python"` references a directory that does not exist (`packages/sdk/hush-py/hush-native/python/`) — only `packages/sdk/hush-py/hush-native/src/` exists.

### [HIGH] Python — `pyproject.toml` references nonexistent `src/hush` package

**Status:** STILL VALID at HEAD. `packages/sdk/hush-py/pyproject.toml:48` reads `packages = ["src/clawdstrike", "src/hush"]`. `packages/sdk/hush-py/src/` contains only `clawdstrike/`. **Trivial fix; delete the `"src/hush"` entry.**

### [HIGH] Python — mypy strict is misleading

**Status:** STILL VALID at HEAD.

- `packages/sdk/hush-py/pyproject.toml:58-62` — `[tool.mypy] python_version = "3.10"\nstrict = true`.
- `packages/sdk/hush-py/moon.yml:30-35` (verified) — typecheck task runs `.venv/bin/mypy src/` only. Tests are unchecked.

### [MEDIUM] Tests — k8s_audit_bridge_reliability silent no-op

**Status:** STILL VALID at HEAD.

Verified by `grep -n "skipping integration test" crates/tests/sdr-integration-tests/tests/k8s_audit_bridge_reliability.rs`:

- Line 313: `eprintln!("skipping integration test: {err}");`
- Line 337: same
- Line 384: same

Each is followed by an unconditional `return;` — the `#[tokio::test]` resolves green. The audit's recommendation (use `#[ignore]` or env opt-out + dedicated CI lane) stands. **Aggressive: convert all three to `#[ignore]` and add a `nats-integration` CI job that fails if they don't actually run.**

### [MEDIUM] Tests — `e2e-posture-cmd` is not a test crate

**Status:** STILL VALID at HEAD.

`crates/tests/e2e-posture-cmd/Cargo.toml` defines `[[bin]] name = "e2e-posture-cmd"` and no `[lib]` or `[[test]]`. `src/main.rs:1-8` opens with `//! E2E test binary: sign and publish posture commands to NATS as Spine envelopes.` It's a CLI tool, not a test. `find crates/tests/e2e-posture-cmd -name tests` returns nothing. **Aggressive: move to `tools/e2e-posture-cmd/` (or `crates/tools/`); update workspace `Cargo.toml` member list.**

### [MEDIUM] Tests — RecordingBackend lies (always allows)

**Status:** STILL VALID at HEAD.

`packages/sdk/hush-py/tests/_recording_backend.py:16-25` (verified):

```python
def _allow(self, action: str, *args: Any, ctx: dict[str, Any]) -> dict[str, Any]:
    self.calls.append((action, args, ctx))
    return {
        "overall": {
            "allowed": True,
            ...
        },
        "per_guard": [],
    }
```

Every `check_*` method returns `{"overall": {"allowed": True, ...}}`. Tests built on it never exercise a deny verdict against the real backend.

### [MEDIUM] Rulesets — `permissive.yaml` is dangerously thin

**Status:** STILL VALID at HEAD.

`rulesets/permissive.yaml:1-24` (all 24 lines reproduced; verified). Configures **only** `egress_allowlist` (`allow: ["*"]`) and `patch_integrity` (relaxed). No `forbidden_path`, no `secret_leak`, no `mcp_tool`, no `shell_command`. A user picks "permissive" and gets *no defense at all*, not "permissive defense". The audit's recommendation (`extends: default` with egress relaxation only) is correct.

### [MEDIUM] Rulesets — `spider-sense.yaml` requires unset env vars

**Status:** STILL VALID at HEAD.

`rulesets/spider-sense.yaml:11-12`:

```yaml
embedding_api_url: "${SPIDER_SENSE_EMBEDDING_URL}"
embedding_api_key: "${SPIDER_SENSE_EMBEDDING_KEY}"
```

The ruleset cannot be loaded out of the box. Recommendation: make `builtin:s2bench-v1` the default and require env vars only for the LLM deep-reasoning path.

### [MEDIUM] Fixtures — `fixtures/hushspec/rulesets/` ≠ `vendor/hushspec/rulesets/`

**Status:** STILL VALID at HEAD **but the diagnosis is incomplete.** See [NEW ISSUES](#new-issues) §N1 — the audit framed this as "lagging copy", but the two trees use the *same filenames with different schemas* (`hushspec:`/`rules:` vs `version:`/`guards:`).

`diff vendor/hushspec/rulesets/default.yaml fixtures/hushspec/rulesets/default.yaml`:

- `vendor/` version starts with `hushspec: "0.1.0"`, `rules:` (line 7), `forbidden_paths:` (plural, line 8). Wave-3 J audit identified `vendor/hushspec/` as the **published 0.1.1 spec crate** (`vendor/hushspec/Cargo.toml:2-3`).
- `fixtures/` version starts with comments, `hushspec: "0.1.0"`, `rules:`, `forbidden_paths:` — same schema, **older comment style** and a few patterns reordered/grouped differently.

Both files share the *HushSpec schema* (`hushspec:` + `rules:`), which is **distinct from the local rulesets/*.yaml schema** (`version:` + `guards:`). So this is *not* a clean drift between identical files — it's two snapshots of an external spec format that the engine also consumes via dual-format loading (commit `c980358c2`, "HushSpec compiler with dual-format loading").

**Sharpened recommendation:** the `fixtures/hushspec/` tree is fine to keep as pinned conformance vectors **if** it gets a `README.md` saying so. The drift complaint as worded ("the fixtures copy lags the vendor copy") understates the problem; what's really happening is *cross-spec conformance vectors* shadowing *the workspace dep itself*. See [N1](#n1-vendor-hushspec-is-a-first-party-workspace-member-with-its-own-rulesets-not-a-passive-fixture).

### [MEDIUM] Python — stale wheels in `dist/`

**Status:** STILL VALID at HEAD. Reconfirmed:

- `packages/sdk/hush-py/dist/clawdstrike-0.1.0-py3-none-any.whl`
- `packages/sdk/hush-py/dist/clawdstrike-0.1.0.tar.gz`
- `packages/sdk/hush-py/dist/clawdstrike-0.2.4-py3-none-any.whl`
- `packages/sdk/hush-py/dist/clawdstrike-0.2.4.tar.gz`

Current pyproject pins 0.2.7. The wheels are gitignored (`git check-ignore` returns the path) so they're local clutter. **Trivial: `rm -rf packages/sdk/hush-py/dist/clawdstrike-0.1.0* packages/sdk/hush-py/dist/clawdstrike-0.2.4*`.**

### [MEDIUM] Python — `_native` import-path drift between maturin and hatchling configs

**Status:** STILL VALID at HEAD.

`packages/sdk/hush-py/hush-native/pyproject.toml:48` — `module-name = "clawdstrike._native"`. But the outer hatchling build (`packages/sdk/hush-py/pyproject.toml:46-50`) produces `src/clawdstrike` with no `_native` shipped. So `clawdstrike.native.NATIVE_AVAILABLE` is False whenever the hatchling wheel is the installed one — and **12** `pytest.mark.skipif` instances (verified by grep) silently skip in that case.

### [MEDIUM] Tests — `test_typed_actions.py` and `test_native_engine.py` are constructor-only

**Status:** STILL VALID at HEAD.

`packages/sdk/hush-py/tests/test_typed_actions.py:13-50` confirms: every `test_*_action` does
```python
a = FileAccessAction(path="/test")
assert a.path == "/test"
assert a.action_type == "file_access"
```
Pure dataclass-creation assertions, no behavior.

`packages/sdk/hush-py/tests/test_native_engine.py:29-51` confirms four near-identical `assert engine is not None` smoke tests:
```python
engine = native_mod.NativeEngine.from_ruleset("strict")
assert engine is not None
```
plus one `pytest.raises(ValueError)` for the invalid-ruleset path. The invalid-ruleset one is real; the four happy-path ones are zero-signal.

### [MEDIUM] Fuzz — no seed corpora committed

**Status:** STILL VALID at HEAD.

`fuzz/.gitignore` (verified): `target/`, `corpus/`, `artifacts/`, `coverage/`. Tracked files (`git ls-files fuzz/`) are only the `Cargo.toml`, `Cargo.lock`, `README.md`, 9 `fuzz_targets/*.rs` files, and `.gitignore`. No `seeds/` directory exists. Nightly CI (`.github/workflows/fuzz.yml`) runs each target with `-max_total_time=120` starting from an empty corpus.

### [MEDIUM] Tests — top-level `tests/registry-smoke.sh` is the only thing there

**Status:** STILL VALID at HEAD.

`ls tests/`: single file, `registry-smoke.sh` (9 KB, executable). No README, no other layout. **Aggressive: move to `crates/services/clawdstrike-registry/scripts/smoke.sh` or to `scripts/smoke/registry.sh`. Delete the top-level `tests/` dir.**

### [LOW] Rulesets — `remote-desktop-strict.yaml` describes overrides not deltas

**Status:** STILL VALID at HEAD. `rulesets/remote-desktop-strict.yaml:12-15` still redeclares `allowed_actions:` for `computer_use` without an inline comment explaining that this replaces (not extends) the inherited list. Trivial documentation fix.

### [LOW] Tests — `e2e_pipeline.rs` hand-rolls `simulate_ingest_contract`

**Status:** STILL VALID at HEAD. `crates/tests/sdr-integration-tests/tests/e2e_pipeline.rs` still defines `SimulatedCheckpointerState`. May drift from the real `spine-checkpointer` ingest path. Low priority — add a doc comment pointing to the real implementation.

### [LOW] Tests — `#![allow(clippy::expect_used, clippy::unwrap_used)]` at file scope

**Status:** STILL VALID at HEAD. Verified at:

- `crates/tests/sdr-integration-tests/tests/bridge_roundtrip_test.rs:6`
- `crates/tests/sdr-integration-tests/tests/k8s_audit_bridge_reliability.rs:1`
- `crates/tests/sdr-integration-tests/tests/e2e_pipeline.rs:16`

Each file blanket-allows the workspace-deny lints. Stylistic; leave or document.

### [LOW] Fixtures — `s2bench-v1.json` is described as demo but loaded as production

**Status:** STILL VALID at HEAD with a minor numeric correction.

`rulesets/patterns/s2bench-v1.json` — Python verification: `len(d)` returns **36 entries** (audit table said 38, prose later said 36). All embeddings are 3-dimensional. Real `text-embedding-3-small` produces 1536-dim vectors. The file is loaded by `builtin:s2bench-v1` references in `rulesets/spider-sense.yaml:17`. **Aggressive: rename to `s2bench-v1-demo.json`, add header comment, or replace with a real-dim DB.**

### [LOW] Tests — proptest.toml without companion `regressions/` directory

**Status:** STILL VALID at HEAD.

`crates/tests/formal-diff-tests/proptest.toml:19` sets `failure_persistence = "file"`. `ls crates/tests/formal-diff-tests/proptest-regressions/` returns "No such file or directory". **Trivial: `mkdir crates/tests/formal-diff-tests/proptest-regressions && touch ...proptest-regressions/.gitkeep`. Explicit not-ignored so future counter-examples persist.**

### [LOW] Rulesets — no `path_allowlist` example

**Status:** STILL VALID at HEAD. `grep -rn "path_allowlist:" rulesets/` returns only:

- `rulesets/tests/policy-torture/policies/replace-overlay.yaml:8`
- `rulesets/tests/policy-torture/policies/base-core.yaml:15`

Both are torture-suite fixtures, not user-facing rulesets.

### [LOW] Tests — `test_testing_module.py` line 181 has fixture name `test1`

**Status:** STILL VALID at HEAD. `grep -n "test1" packages/sdk/hush-py/tests/test_testing_module.py`: `181: {"name": "test1", "action": "file_access", "target": "/tmp/x"},`. Uninformative scenario name. Rename to `read_tmp_x` or similar. Trivial.

### [LOW] Tests — Live OpenAI dogfood tests have no CI lane

**Status:** STILL VALID at HEAD. `grep -rn "OPENAI_API_KEY" .github/workflows/` returns nothing. `wc -l packages/sdk/hush-py/tests/test_openai_agents_dogfood.py` reports 736 lines; the audit also flagged `test_detection_layers_dogfood.py` at 962 lines. They sit in tree, never run.

### [LOW] Crates/tests — `crates/tests/README.md` is one line

**Status:** STILL VALID at HEAD. Verified contents: `# Test Crates\n\nCross-component and integration test crates live here.` That's the whole file. Three of the four sub-crates (`formal-diff-tests`, `sdr-integration-tests`, `e2e-posture-cmd`) have no entry. Trivial rewrite.

### [LOW] Tests — `policy-torture/run.sh` hand-builds canned PASS JSON

**Status:** STILL VALID at HEAD. Lines 119-141 of `rulesets/tests/policy-torture/run.sh` still emit a `${REPORTS_DIR}/05-extends-depth-loop-stress.json` heredoc with hard-coded `"status": "pass"` regardless of the actual command exit. This decouples the report from the truth of the test. The `run_mixed_path_precedence_edge_case` function below it (lines ~150+) does the same for `06-mixed-path-precedence.json`. Recommended: have `run_expected_policy_load_failure` emit status into a real JSON, or port these stress cases into the `hush policy test` framework so the same writer is used.

### [LOW] Vendor — `vendor/hushspec/` is both vendored and `version = "0.1.1"` declared

**Status:** STILL VALID at HEAD (with new context). `crates/libs/clawdstrike/Cargo.toml:33` reads:
```toml
hushspec = { version = "0.1.1", path = "../../../vendor/hushspec", optional = true }
```
The path dep at `vendor/hushspec/` is a full workspace member with `Cargo.toml`, `src/`, `tests/` (verified by `find vendor/hushspec -type d`). Its `Cargo.toml:2-11` declares it as `hushspec` `0.1.1` `publish = false`. So **`vendor/hushspec/` is a first-party crate hiding inside a directory labeled `vendor/`**. See [N1](#n1-vendor-hushspec-is-a-first-party-workspace-member-with-its-own-rulesets-not-a-passive-fixture) for the sharpened diagnosis.

### [LOW] Tests — pyproject tests directory has implicit `__init__.py`

**Status:** STILL VALID at HEAD. Leave as-is; works in pytest. Audit recommendation is "LEAVE" already.

### [LOW] Fixtures — no fixture-loading helper or schema validation

**Status:** STILL VALID at HEAD. Schema-validator infrastructure would be a real engineering investment; out-of-scope for cleanup mode. Leave for later.

### [LOW] Tests — `bridge_roundtrip_test.rs` duplicates `make_*` helpers from `e2e_pipeline.rs`

**Status:** STILL VALID at HEAD. Verified by reading both files; `make_process`, `make_tetragon_process`, etc. defined twice with slight differences. `crates/tests/sdr-integration-tests/src/lib.rs` is two comment lines and nothing else. Trivial refactor: hoist helpers into `src/lib.rs` (or `src/helpers.rs`) and import.

### [LOW] Tests — `sdr-integration-tests` doesn't pin `async-nats` exactly

**Status:** STILL VALID at HEAD. `crates/tests/sdr-integration-tests/Cargo.toml:18`: `async-nats = "0.40"`. Tests will silently rebuild against any semver-compatible patch. Trivial fix or leave.

---

## FIXED SINCE 2026-05-23

**Nothing.** `git log --since="2026-05-23" -- rulesets tests fuzz fixtures integrations tools vendor` is empty. The only local modification touching D09 scope is uncommitted: `M tools/scripts/check-changed-rust-coverage.py` (visible in `git status --porcelain`), which is unrelated to any audit finding.

---

## NOW WRONG / MISDIAGNOSED

### [INTERNAL INCONSISTENCY] `s2bench-v1.json` entry count

The audit says "38 entries" in the inventory table (`Pattern DB:` row) but later prose says "36 entries". Python verification (`json.load(open('rulesets/patterns/s2bench-v1.json'))`) returns **36**. The "demo" + "3-dim" framing is correct. Trivial — fix the table count in any rewrite.

### [DIAGNOSIS UNDERSTATES] `fixtures/hushspec/` vs `vendor/hushspec/rulesets/` drift

The audit calls this a "fixtures copy lags the vendor copy" — true in spirit but the deeper issue is what's actually being duplicated. See [N1](#n1-vendor-hushspec-is-a-first-party-workspace-member-with-its-own-rulesets-not-a-passive-fixture).

### [SCOPE NOTE] Wave3-J explicitly excluded repo-root `vendor/`

J's audit scope (`.audit/wave3/J-infra-vendor-audit.md:7`) lists `infra/vendor/` only. Repo-root `vendor/` (which contains only `vendor/hushspec/`) was not in J's scope. The 2026-05-23 audit picked it up briefly in the LOW "vendor/hushspec/" entry, but understated its significance — see [N1](#n1-vendor-hushspec-is-a-first-party-workspace-member-with-its-own-rulesets-not-a-passive-fixture).

---

## NEW ISSUES

These were not in the 2026-05-23 audit but surface at HEAD.

### N1. `vendor/hushspec/` is a first-party workspace member with its own rulesets, not a passive fixture

**Severity:** MEDIUM.

The audit and wave3-J both note that `vendor/hushspec/` is unusual ("both vendored and `version = "0.1.1"` declared"), but **neither characterizes it accurately**. Verified findings at HEAD:

- `vendor/hushspec/Cargo.toml:2-11` — full package metadata: `name = "hushspec"`, `version = "0.1.1"`, `edition = "2024"`, `repository = "https://github.com/backbay-labs/hush"`, `publish = false`.
- `find vendor/hushspec -type d` — directory contains `src/`, `tests/` (with 11 separate test files: `resolve.rs`, `signing.rs`, `merge.rs`, `detection.rs`, etc.), `rulesets/`, full `README.md`, `LICENSE`.
- `vendor/hushspec/rulesets/` contains **7** YAML files (`cicd.yaml`, `permissive.yaml`, `remote-desktop.yaml`, `ai-agent.yaml`, `strict.yaml`, `panic.yaml`, `default.yaml`).
- These use the **HushSpec schema** (`hushspec: "0.1.0"`, top-level `rules:`, `forbidden_paths:` plural), distinct from the workspace's own ruleset schema (`version: "1.1.0"`, top-level `guards:`, `forbidden_path:` singular).
- `crates/libs/clawdstrike/Cargo.toml:33` consumes it as an *optional* feature: `hushspec = { version = "0.1.1", path = "../../../vendor/hushspec", optional = true }` activated by feature `dep:hushspec` (line 83).
- The "dual-format loading" landed in commit `c980358c2` (2026-03-16, "HushSpec compiler with dual-format loading (#197)").

`fixtures/hushspec/rulesets/` mirrors these 6 of 7 (no `panic.yaml`) but uses the *same HushSpec schema*, slightly older. So:

| Path | Schema | Purpose | LOC |
|---|---|---|---|
| `rulesets/*.yaml` | `version:`/`guards:` (workspace native) | Loaded by `clawdstrike check` | ~867 |
| `vendor/hushspec/rulesets/*.yaml` | `hushspec:`/`rules:` (spec format) | Bundled with the `hushspec` crate, distributed in published 0.1.1 | varies |
| `fixtures/hushspec/rulesets/*.yaml` | `hushspec:`/`rules:` (spec format) | Conformance fixtures for tests | varies |

The "drift" the original audit complained about is real, but it's drift between **the workspace's pinned conformance vectors** and **the same crate's bundled rulesets**. Two valid fixes:

1. **Authoritative:** delete `fixtures/hushspec/rulesets/` and have tests load from `vendor/hushspec/rulesets/` directly. Saves duplication; tests track the spec exactly.
2. **Pinned:** keep `fixtures/hushspec/` as a deliberately frozen snapshot, add `fixtures/hushspec/README.md` saying "pinned snapshot of HushSpec 0.1.1 — regenerate with `cp -r vendor/hushspec/rulesets fixtures/hushspec/rulesets`".

The audit landed at option (2). I'd recommend option (1) — the test fixtures should be the live source.

The deeper recommendation is that `vendor/hushspec/` (a first-party crate with its own published version) should arguably live in `crates/libs/hushspec/`, not `vendor/`. The naming implies "third party we don't touch", which is misleading. **Aggressive: move `vendor/hushspec/` to `crates/libs/hushspec/` (paralleling J's recommendation for `nono`); remove the `vendor/` directory at repo root entirely.**

### N2. `tools/scripts/__pycache__/` exists locally but is gitignored

**Severity:** LOW (cosmetic).

Verified: `tools/scripts/__pycache__/check-changed-rust-coverage.cpython-311.pyc` is present, but `git check-ignore` confirms it's gitignored (output line confirms). So this is *not* a leak into git history, just local working-tree clutter. Plus `git status --porcelain tools/scripts/` shows `M tools/scripts/check-changed-rust-coverage.py` — an uncommitted modification to the source. Worth noting only because the original audit didn't surface `tools/` clutter (it's outside the original scope but in mine).

### N3. `crates/libs/hush-fuzz` package version is `0.0.0` and Cargo.lock is committed at the fuzz workspace level

**Severity:** LOW.

`fuzz/Cargo.toml:2` — `version = "0.0.0"`. Acceptable for a non-publishing fuzz workspace, but worth flagging. `fuzz/Cargo.lock` is a separate 4,678-line lockfile (not a symlink to workspace lockfile). This is a deliberate cargo-fuzz pattern (the fuzz package is its own mini-workspace), but it does mean the fuzz lockfile can drift from the main workspace lockfile on dep updates. **Recommendation:** verify by `cargo +nightly fuzz build` after every workspace `cargo update`; consider adding a pre-commit check.

### N4. `fixtures/macos/` has 12+ JSON test fixtures but no README

**Severity:** LOW.

Verified: `fixtures/macos/endpoint-security/{evidence,status}/` and `fixtures/macos/network-extension/` together contain 17 JSON files (5 evidence, 7 endpoint-security/status, 4 network-extension, 1 healthy-allow). Per `fixtures/README.md`, these aren't listed in the "Current fixture groups" enumeration (which goes up to item 22). Either:

- The README needs items 23-24 (`fixtures/macos/endpoint-security/`, `fixtures/macos/network-extension/`).
- Or these fixtures should be moved under `fixtures/policy-events/endpoint-security/v1/` to follow the existing versioned convention.

Pattern violation: `fixtures/macos/endpoint-security/evidence/missing-full-disk-access.json` lacks the `v1/` versioning of every other fixture group. **Aggressive:** restructure to `fixtures/macos/endpoint-security/v1/cases.json` (or similar) per established convention.

### N5. Compliance fixtures' `extends: clawdstrike:strict` may compound the breakage

**Severity:** MEDIUM.

Verified: all three compliance fixtures (`hipaa-policy.yaml:8`, `pci-dss-policy.yaml:8`, `soc2-policy.yaml:8`) start with `extends: clawdstrike:strict`. Combined with the broken syntax (`deny:`, `severity_threshold:`, etc.), this means a user loading `hipaa-policy.yaml` would:

1. Resolve `extends: clawdstrike:strict` — which works because `strict.yaml` parses.
2. Apply the HIPAA overlay — which **fails** because of unknown fields.
3. Get a parse error at the HIPAA file.

So at least the extends mechanism does its job partway. But the audit's recommendation should be sharpened: **delete the three broken files and replace with a single `compliance-example.yaml` that uses `extends: strict` plus only documented fields**. The old "compliance templates" framing is aspirational and the directory structure (`fixtures/certification/policies/`) implies these are *fixtures*, not user-facing templates — they should not be shipped as if a HIPAA-covered entity could adopt them as-is.

---

## AGGRESSIVE EXECUTION PLAN (top-5, aggressive ceiling)

Sequenced for impact-per-effort. Each is one atomic commit; all are within the aggressive deletion/restructuring ceiling the user established.

### 1. Delete broken compliance fixtures and stale Python wheels — `chore: prune broken compliance fixtures and stale wheels` (~10 minutes)

**Delete:**
- `fixtures/certification/policies/hipaa-policy.yaml`
- `fixtures/certification/policies/pci-dss-policy.yaml`
- `fixtures/certification/policies/soc2-policy.yaml`
- `packages/sdk/hush-py/dist/clawdstrike-0.1.0-py3-none-any.whl`
- `packages/sdk/hush-py/dist/clawdstrike-0.1.0.tar.gz`
- `packages/sdk/hush-py/dist/clawdstrike-0.2.4-py3-none-any.whl`
- `packages/sdk/hush-py/dist/clawdstrike-0.2.4.tar.gz`

**Also:** remove `"src/hush"` from `packages/sdk/hush-py/pyproject.toml:48` (the line becomes `packages = ["src/clawdstrike"]`).

**Rationale:** the compliance fixtures don't parse against the current engine; shipping them as templates is worse than shipping nothing. The wheels are gitignored clutter. The `src/hush` reference is a ghost. All four removals are zero-coupling.

**Verify:** `cargo test --workspace` and `pytest packages/sdk/hush-py/tests` still pass.

### 2. Restructure core rulesets to use `extends:` — `chore(rulesets): use extends for default/strict/ai-agent/cicd/permissive`  (2-3 hours)

Make `rulesets/default.yaml` the canonical root. Add `path_allowlist:` and `shell_command:` guards to it so the truly missing guards become discoverable. Then rewrite:

- `rulesets/permissive.yaml` → `extends: default` with `egress_allowlist.allow: ["*"]` override. Keep secret_leak and forbidden_path on.
- `rulesets/strict.yaml` → `extends: default` with `merge_strategy: deep_merge` and `prompt_injection:`, `jailbreak:` adds.
- `rulesets/ai-agent.yaml` → `extends: default` with widened egress + `prompt_injection:`, `jailbreak:`.
- `rulesets/cicd.yaml` → `extends: default` with build-time egress + relaxed patch_integrity.

Add CI test that loads each ruleset, resolves extends, golden-compares the fully resolved policy against a committed snapshot (`rulesets/tests/extends-snapshots/`).

**Verify:** existing tests pass; new test asserts deterministic resolution.

### 3. Convert k8s_audit_bridge_reliability silent skips to `#[ignore]` + CI lane — `test(sdr): convert silent integration skips to ignored tests` (1 hour)

Edit `crates/tests/sdr-integration-tests/tests/k8s_audit_bridge_reliability.rs` lines 313, 337, 384: replace the `match NatsHarness::start().await { Err(...) => return; }` pattern with `#[ignore = "requires NATS — run with --include-ignored"]` on the three `#[tokio::test]` functions, and gate the body on the harness directly. Then add a `nats-integration` job to `.github/workflows/ci.yml` that brings up NATS via docker-compose and runs `cargo test -p sdr-integration-tests -- --include-ignored`.

**Verify:** `cargo test` reports 3 ignored, `cargo test -- --include-ignored` reports them running in the new CI lane.

### 4. Move `crates/tests/e2e-posture-cmd` → `tools/e2e-posture-cmd` and `tests/registry-smoke.sh` → `scripts/smoke/registry.sh` — `chore: relocate misplaced ops tools` (1 hour)

- `mv crates/tests/e2e-posture-cmd tools/e2e-posture-cmd`
- Update workspace `Cargo.toml` members list, any references in `.github/workflows/` and `scripts/`.
- `mkdir -p scripts/smoke && mv tests/registry-smoke.sh scripts/smoke/registry.sh`
- `rmdir tests/` (after the move).
- Update any caller references (search for `tests/registry-smoke.sh` and `crates/tests/e2e-posture-cmd` in CI workflows and docs).

**Verify:** `cargo build --workspace`, smoke shell still runs, `find . -maxdepth 2 -type d -name tests` returns only `<crate>/tests/` style directories.

### 5. Aggressive vendor consolidation: collapse `vendor/hushspec/` and `fixtures/hushspec/rulesets/` — `chore: consolidate hushspec into workspace and dedupe conformance fixtures` (2-3 hours)

- `git mv vendor/hushspec crates/libs/hushspec`
- Update `crates/libs/clawdstrike/Cargo.toml:33`: `hushspec = { path = "../hushspec", optional = true }` (drop the `version = "0.1.1"` redundancy now that it's an in-workspace path dep).
- Update workspace `Cargo.toml` to include `crates/libs/hushspec` as a member.
- `rm -rf fixtures/hushspec/rulesets` and update any tests that loaded these to load `crates/libs/hushspec/rulesets/` directly (or symlink).
- `rmdir vendor` (now empty).
- Add `crates/libs/hushspec/README.md` (the existing one can stay) noting "promoted from vendor/ — first-party workspace member".

**Rationale:** `vendor/` at repo root currently holds exactly one directory and that directory is misfiled (it's a workspace member, not a vendored dep). Wave3-J already made the parallel case for `nono` in `infra/vendor/`. Aggressive ceiling agrees both should move.

**Verify:** `cargo test --workspace`, `cargo +stable check --workspace --locked`, no broken paths in tests.

---

## DEFER / OUT OF SCOPE

Items that are *correct* findings but lower priority or outside the cleanup ceiling:

- **`RecordingBackend` improvement** — real fix; defer to a "test depth" milestone. The shipped behavior (always-allow) is wrong but not actively harmful.
- **Fuzz seed corpora** — net positive but writing 5-20 seeds per target × 9 targets is real engineering work; defer.
- **Constructor-only tests cleanup** (`test_typed_actions.py`, `test_native_engine.py`) — low blast radius; rewrite alongside any related feature work.
- **`policy-torture/run.sh` heredoc PASS JSON** — sharpened report writer requires extending `hush policy test`; defer to the formal-verification milestone.
- **mypy strict alignment** — either fix all test annotations or carve tests out. Decision pending; defer.
- **Fixture loader / schema validator** — useful for schema evolution; out of scope for "cleanup mode."
- **Live OpenAI dogfood CI lane** — needs `workflow_dispatch` workflow + `OPENAI_API_KEY` secret; product call, not a cleanup.
- **`crates/tests/README.md` rewrite** — trivial polish; one paragraph per crate. Roll into the e2e-posture-cmd move (item 4).
- **Native `_native` build path drift** — fixing requires picking maturin vs hatchling; pair with the "two pyprojects" decision.
- **`fixtures/macos/` versioning** (N4) — directory restructure with caller updates; defer until tested.

Items the audit covered as out of scope and that should remain so:

- **`crates/tests/formal-diff-tests/`** — exemplary. Don't touch.
- **`crates/tests/sdr-integration-tests/tests/e2e_pipeline.rs`** — the pipeline test itself is strong; only the silent skips need fixing (item 3 above).
- **`rulesets/tests/policy-torture/suites/04-guard-gauntlet.policy-test.yaml`** — strong coverage. Keep.
- **`fixtures/canonical/jcs_vectors.json`** and `receipts/cua-migration/` — well-structured.
- **Wave3-I scope** (`scripts/*.py`) — D02 owns that. Confirmed not duplicated here.
- **`infra/vendor/`** — D02 / wave3-J ground. Out of D09 scope.

---

## Summary

The 2026-05-23 audit is **accurate and unchanged**. None of its 30 findings have been remediated; none have been falsified. The 5 new issues I add tighten the `vendor/hushspec/` diagnosis (it's a first-party crate, not a vendored fixture) and surface the `fixtures/macos/` versioning irregularity. The execution plan keeps the original Top-10 priorities but folds them into 5 aggressive-ceiling commits totaling ~8-10 hours of work for an experienced engineer. The biggest single signal-to-noise lift is item 2 (rulesets `extends:` restructure) — it turns ~580 LOC of YAML duplication into ~200 LOC of inheritance and surfaces two guards that are currently invisible.
