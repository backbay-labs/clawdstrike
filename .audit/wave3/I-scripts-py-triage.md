# `scripts/*.py` Triage

Audit target: `standalone/clawdstrike/scripts/*.py` plus any nested `scripts/**/*.py`.
Audit date: 2026-05-23. Branch: `fix/macos-es-ne-hardening`.

## Summary

**File count:** 16 Python files (15 in `scripts/`, 1 in `scripts/codex-swarm/`).
Wave-1's count of "18" appears to have included the README and source-of-truth docs.

**Total LOC:** 16,968 lines (15,887 in the EDR proof-bundle set; 81 in `codex-swarm/notify.py`; the EDR set alone is 14,167 LOC if you exclude the four "verify"/"gate"/"manifest"/"deployment-evidence" scripts that have direct shell-script callers).

**All 15 EDR scripts landed in a single commit on 2026-05-19** (`chore(scripts): add EDR qualification, dogfood, and proof bundles`). None have been touched since. The commit is four days old as of audit date and represents one mass dump from an evidence-bundle generation exercise.

**Headline disposition:**
- **0 of 15** scripts are referenced by any `.github/workflows/*.yml` workflow (direct or transitive).
- **All 15** scripts ARE wired in `scripts/test-macos-provider-dogfood-contract.sh` and `scripts/ci-changed.sh` as a developer-local `mise run ci:changed` selector — but `ci-changed.sh` itself is **never invoked from CI**. Its discovery path is local-only via `mise.toml [tasks."ci:changed"]`.
- **6 of 15** scripts are runtime dependencies of operator-facing shell scripts (`endpoint-decision-engine-live-qualification.sh`, `macos-provider-live-dogfood.sh`, `endpoint-security-live-dogfood.sh`, `network-extension-live-dogfood.sh`). Those shell scripts are themselves not in CI but are real operator commands documented in `scripts/README.md`.
- **9 of 15** scripts are "supplemental proof bridges" — they only get called when a future operator runs the EDR live qualification end-to-end. They generate JSON proof artifacts from operator-supplied coverage inputs. They are evidence-generators, not test runners.
- **0** dangerous patterns (no `rm -rf` of fixed paths, no network calls, no secret reads, no destructive ops outside `--out-dir` plus a `--replace-output` gate and a protected-dirs deny list).
- **`scripts/codex-swarm/notify.py`** is a separate 81-line Codex-swarm helper unrelated to the EDR bundle.

**Bottom line:** This is not "13 of 18 should be deleted." Six scripts are genuine operator tooling and should stay (with documentation cleanup). Nine "supplemental proof bridges" are useful as evidence generators but are over-scaled relative to their actual user (zero CI consumers, one operator workflow). They form a coherent, dependency-linked subsystem and should be relocated as a group to `tools/edr-proof-bundle/`, not split or deleted. The contract test that exercises all their `--self-test` paths should be promoted to CI to give the subsystem real protection.

## Per-File Disposition

| File | LOC | Last touched | CI ref? | What it does (1 line) | Class | Recommended action |
| --- | ---: | --- | --- | --- | --- | --- |
| `macos-provider-deployment-evidence.py` | 1,035 | 2026-05-19 | No (called by `macos-provider-live-dogfood.sh`, `test-macos-provider-dogfood-contract.sh`) | Collects & verifies signed/notarized macOS app bundle deployment evidence (codesign, plist, systemextensionsctl). | STILL-USEFUL-MOVE | Keep as operator tool; move to `tools/macos-provider-dogfood/`. |
| `macos-provider-dogfood-gate.py` | 819 | 2026-05-19 | No (called by `macos-provider-live-dogfood.sh`, `test-macos-provider-dogfood-contract.sh`) | Combines verified deployment + ES + NE summaries into one go/no-go gate. | STILL-USEFUL-MOVE | Keep; move to `tools/macos-provider-dogfood/`. |
| `macos-provider-dogfood-manifest.py` | 1,789 | 2026-05-19 | No (called by `macos-provider-live-dogfood.sh`, `test-macos-provider-dogfood-contract.sh`) | Writes & verifies SHA-256 manifest over the combined macOS provider evidence bundle; reruns the gate during verify. | STILL-USEFUL-MOVE | Keep; move to `tools/macos-provider-dogfood/`. |
| `endpoint-security-live-dogfood-verify.py` | 828 | 2026-05-19 | No (called by `endpoint-security-live-dogfood.sh`, `test-macos-provider-dogfood-contract.sh`) | Validates an `EndpointSecurity` dogfood `summary.json` against strict rules. | STILL-USEFUL-MOVE | Keep; move to `tools/macos-provider-dogfood/`. |
| `network-extension-live-dogfood-verify.py` | 963 | 2026-05-19 | No (called by `network-extension-live-dogfood.sh`, `test-macos-provider-dogfood-contract.sh`) | Validates a `NetworkExtension` containment `summary.json`. | STILL-USEFUL-MOVE | Keep; move to `tools/macos-provider-dogfood/`. |
| `endpoint-decision-engine-readiness-audit.py` | 3,814 | 2026-05-19 | No (called by `test-macos-provider-dogfood-contract.sh`; loaded as module by every proof script) | Machine-readable completion audit mapping north-star EDR requirements to evidence artifacts; central module used by all other proof scripts. | STILL-USEFUL-MOVE | Keep; move to `tools/edr-proof-bundle/`. This is the spine of the bundle — do not delete. |
| `endpoint-decision-engine-qualification-bundle.py` | 2,538 | 2026-05-19 | No (called by `endpoint-decision-engine-live-qualification.sh`, `test-macos-provider-dogfood-contract.sh`) | Verifies a complete EDR qualification evidence bundle: discovers manifest + all proof JSONs, runs readiness audit, persists self-hashed audit. | STILL-USEFUL-MOVE | Keep; move to `tools/edr-proof-bundle/`. |
| `endpoint-decision-engine-supplemental-proof-bundle.py` | 733 | 2026-05-19 | No (called by `endpoint-decision-engine-live-qualification.sh`, `test-macos-provider-dogfood-contract.sh`) | Builds staged supplemental proof root: runs every proof bridge, copies sources, writes manifest with policy hash binding. | STILL-USEFUL-MOVE | Keep; move to `tools/edr-proof-bundle/`. |
| `policy-simulation-impact-proof.py` | 641 | 2026-05-19 | No (called transitively by supplemental-proof-bundle and contract test) | Generates a strict policy-simulation supplemental proof JSON from operator policy-impact output. | STILL-USEFUL-MOVE | Keep; move to `tools/edr-proof-bundle/proofs/`. |
| `ai-agent-developer-workstation-proof.py` | 582 | 2026-05-19 | No (same) | Generates the AI-agent / developer-workstation supplemental proof JSON. | STILL-USEFUL-MOVE | Keep; move to `tools/edr-proof-bundle/proofs/`. |
| `endpoint-deception-proof.py` | 480 | 2026-05-19 | No (same) | Generates the endpoint-deception (honey artifact) supplemental proof JSON. | STILL-USEFUL-MOVE | Keep; move to `tools/edr-proof-bundle/proofs/`. |
| `supply-chain-runtime-guard-proof.py` | 730 | 2026-05-19 | No (same) | Generates the supply-chain runtime-guard supplemental proof JSON. | STILL-USEFUL-MOVE | Keep; move to `tools/edr-proof-bundle/proofs/`. (Contains `/Users/alice/...` synthetic fixture paths — see Dangerous Patterns.) |
| `privacy-preserving-telemetry-proof.py` | 680 | 2026-05-19 | No (same) | Generates the privacy-preserving telemetry supplemental proof JSON. | STILL-USEFUL-MOVE | Keep; move to `tools/edr-proof-bundle/proofs/`. |
| `operator-workflows-proof.py` | 665 | 2026-05-19 | No (same) | Generates the operator-workflows supplemental proof JSON. | STILL-USEFUL-MOVE | Keep; move to `tools/edr-proof-bundle/proofs/`. |
| `cross-platform-sensor-breadth-proof.py` | 590 | 2026-05-19 | No (same) | Generates the cross-platform sensor-breadth supplemental proof JSON. | STILL-USEFUL-MOVE | Keep; move to `tools/edr-proof-bundle/proofs/`. |
| `codex-swarm/notify.py` | 81 | 2025-05-14 | No (presumably called by `scripts/codex-swarm/*.sh`) | Codex-swarm notify helper; out of scope for the EDR bundle. | OUT-OF-SCOPE | Leave in place; not part of this audit. |

## CI-Referenced Scripts (KEEP)

**None.** No script in `scripts/*.py` is invoked by a GitHub Actions workflow under `.github/workflows/`.

What looks like CI coverage is actually local-developer coverage:
- `mise.toml` defines `[tasks."ci:changed"] run = "bash scripts/ci-changed.sh"`.
- `scripts/ci-changed.sh` lines 77–82 contain the dispatch rule that runs `bash scripts/test-macos-provider-dogfood-contract.sh` when any of these Python scripts change.
- `scripts/test-macos-provider-dogfood-contract.sh` runs `--self-test` on all 15 scripts (lines 78–94).
- But `grep -r "ci:changed\|ci-changed\|test-macos-provider" .github/` returns **nothing**.

This is a real gap: the only CI execution of these scripts depends on a developer running `mise run ci:changed` locally before pushing. The contract test should be promoted to a real workflow job (see Cleanup Plan §5).

## One-Shot Evidence Bundles (MOVE TO `docs/evidence/`)

**None.** None of these are "produce-an-artifact-and-walk-away" scripts. Every one of them either:
1. Re-runs on demand to verify operator-supplied evidence (the four `*-verify.py` / gate / manifest scripts), or
2. Loads other scripts as Python modules via `importlib.util.spec_from_file_location` (every proof script imports `endpoint-decision-engine-readiness-audit.py`; `macos-provider-dogfood-manifest.py` imports `macos-provider-dogfood-gate.py`).

They form a tightly-coupled validator/generator/manifest pipeline. Treating any individual file as "one-shot evidence" would break the others. The whole bundle is either alive together or dead together. This audit's recommendation is the former (relocate as a unit).

## Still-Useful Tools (RELOCATE)

All 15 EDR scripts. Proposed layout:

```
tools/edr-proof-bundle/
├── README.md                                          # NEW — describes the bundle, who runs it, when
├── readiness_audit.py                                 # was endpoint-decision-engine-readiness-audit.py
├── qualification_bundle.py                            # was endpoint-decision-engine-qualification-bundle.py
├── supplemental_proof_bundle.py                       # was endpoint-decision-engine-supplemental-proof-bundle.py
└── proofs/
    ├── policy_simulation_impact.py
    ├── ai_agent_developer_workstation.py
    ├── endpoint_deception.py
    ├── supply_chain_runtime_guard.py
    ├── privacy_preserving_telemetry.py
    ├── operator_workflows.py
    └── cross_platform_sensor_breadth.py

tools/macos-provider-dogfood/
├── README.md                                          # NEW
├── deployment_evidence.py                             # was macos-provider-deployment-evidence.py
├── dogfood_gate.py                                    # was macos-provider-dogfood-gate.py
├── dogfood_manifest.py                                # was macos-provider-dogfood-manifest.py
├── endpoint_security_verify.py                        # was endpoint-security-live-dogfood-verify.py
└── network_extension_verify.py                        # was network-extension-live-dogfood-verify.py
```

Required documentation in each `README.md`:
1. **Audience:** operator running pre-release macOS provider qualification, not CI.
2. **Entry point:** `scripts/macos-provider-live-dogfood.sh` and `scripts/endpoint-decision-engine-live-qualification.sh` (these orchestrators stay in `scripts/` because they ARE the documented operator commands).
3. **Required external inputs:** signed/notarized `.app` bundle path, target host:port, coverage artifacts under `CLAWDSTRIKE_EDE_*` env vars (the live-qualification shell script lists them).
4. **Outputs:** `qualification-summary.json`, `manifest.json`, `gate-result.json`, `supplemental-proof-source-manifest.json`.
5. **Self-test command:** `python3 <script> --self-test` for each.
6. **Module-import contract:** the proofs and verify/gate/manifest scripts import each other as modules using `importlib.util.spec_from_file_location`. Renaming files breaks this — the rename to snake_case is mandatory if relocating, and every cross-reference must be updated together. See `endpoint-decision-engine-readiness-audit.py:36-44` (`EXPECTED_BRIDGE_SCRIPTS`), `endpoint-decision-engine-supplemental-proof-bundle.py:25-33`, `endpoint-decision-engine-qualification-bundle.py:65-73`, `macos-provider-dogfood-manifest.py:23-31`. These hard-coded filename maps must all change in lockstep.

Caller updates required:
- `scripts/macos-provider-live-dogfood.sh:334-434` — 5 path references.
- `scripts/endpoint-decision-engine-live-qualification.sh:190-603` — 6 path references.
- `scripts/endpoint-security-live-dogfood.sh:771` — 1 path reference.
- `scripts/network-extension-live-dogfood.sh:679` — 1 path reference.
- `scripts/test-macos-provider-dogfood-contract.sh:18-94` — full path list (18 references).
- `scripts/ci-changed.sh:79` — the dispatch regex.
- `scripts/README.md:21-28` — items 21–28 list these scripts by old name.
- `docs/plans/clawdstrike/endpoint-decision-engine/current-state.md` and `roadmap.md` — multiple references.

## Dead (DELETE)

**None.** No `scripts/*.py` qualifies as dead under the wave-3 criteria: every Python file in `scripts/` is either (a) directly invoked by a shell script in the same directory, (b) imported as a module by another Python file in the same directory, or (c) covered by the documented `--self-test` contract surface in `test-macos-provider-dogfood-contract.sh`.

Wave-1's narrative ("18 scripts, ~14k LOC, none referenced by CI") is technically true about CI but misleading about callers. The scripts have callers; the callers just aren't in CI.

## Dangerous Patterns (REDESIGN BEFORE KEEPING)

**No critical issues.** Three minor items worth noting:

### 1. `shutil.rmtree` calls — gated and safe

Three call sites mutate the filesystem outside tempfiles:

- `scripts/endpoint-decision-engine-supplemental-proof-bundle.py:152`:
  ```
  shutil.rmtree(child)
  ```
  Context (lines 140–155): only executes when `replace_output=True` is passed, and only against `out_dir` children, and only after `protected_dirs` rejects sensitive paths:
  ```
  if resolved in protected_dirs:
      raise ValueError(f"--out-dir refuses protected directory: {resolved}")
  ```

- `scripts/endpoint-decision-engine-qualification-bundle.py:2309`: `shutil.rmtree(internal_proof.parent)` — inside a `with tempfile.TemporaryDirectory()` block (self-test only).

- `scripts/macos-provider-dogfood-manifest.py:1632`: `shutil.rmtree(relocated_root)` — inside a `tempfile.TemporaryDirectory()` block (self-test only).

All three are acceptable as-is. No hardcoded destructive paths. Confirm `protected_dirs` actually covers `/`, `$HOME`, repo root, and common system paths when relocating; spot-check before merging the move.

### 2. Hardcoded `/Users/alice/...` paths in synthetic fixtures

`scripts/supply-chain-runtime-guard-proof.py` lines 590, 593, 596:

```
"unsignedBinaryPath": "/Users/alice/Downloads/build-helper",
...
"dylibPath": "/Users/alice/Library/Caches/libspy.dylib",
...
"path": "/Users/alice/Library/LaunchAgents/com.example.updater.plist",
```

These are **not** real paths — they're inside a `_synthetic_*` self-test fixture function and represent example attacker artifacts that the proof schema needs to encode. The placeholder username `alice` is unambiguous (not a real developer's home dir). **Action:** harmless; optionally change to `/Users/example/...` or `/var/folders/synthetic/...` during the relocation pass for clarity.

### 3. Subprocess calls without timeout in proof bridges

Files: `ai-agent-developer-workstation-proof.py`, `cross-platform-sensor-breadth-proof.py`, `endpoint-deception-proof.py`, `operator-workflows-proof.py`, `policy-simulation-impact-proof.py`, `privacy-preserving-telemetry-proof.py`, `supply-chain-runtime-guard-proof.py`, `endpoint-decision-engine-supplemental-proof-bundle.py` all `import subprocess`. They invoke `python3 endpoint-decision-engine-readiness-audit.py` as a child to validate written proofs. The invocations do not always pass `timeout=`. By contrast, `macos-provider-deployment-evidence.py:_run_command` correctly sets `timeout_seconds=30`.

**Risk:** a corrupt audit script could hang an operator proof run indefinitely. Low severity (operator can ctrl-C) but cheap to fix during the move. Add `timeout=120` to the child invocations during the relocation refactor.

## Cleanup Plan

Sequenced to keep the bundle internally consistent at every step. Each numbered item is one commit.

1. **Promote `test-macos-provider-dogfood-contract.sh` to CI** *(do this first, before any move)*. Add a job to `.github/workflows/ci.yml` (mirroring the existing `bash scripts/path-lint.sh` pattern around line 102) that runs `bash scripts/test-macos-provider-dogfood-contract.sh`. This gives the bundle real regression protection before the move and lets you catch import-path breakage in the relocation commits.

2. **Add `scripts/README.md` redirect block.** Add a "EDR proof bundle scripts" subsection explaining that the macOS provider and EDR qualification scripts will be relocated to `tools/macos-provider-dogfood/` and `tools/edr-proof-bundle/`. Link to the destination READMEs once they exist.

3. **Create `tools/macos-provider-dogfood/` and move the 5 macOS provider scripts** in a single commit:
   - Rename files to snake_case.
   - Update `_load_gate_module` lookup in `dogfood_manifest.py`.
   - Update `scripts/macos-provider-live-dogfood.sh`, `scripts/endpoint-security-live-dogfood.sh`, `scripts/network-extension-live-dogfood.sh`, `scripts/test-macos-provider-dogfood-contract.sh`, `scripts/ci-changed.sh` path regexes.
   - Add `tools/macos-provider-dogfood/README.md`.
   - Verify CI job from step 1 still passes.

4. **Create `tools/edr-proof-bundle/` and move the 10 EDR scripts** in a single commit:
   - Rename files to snake_case.
   - Update every `EXPECTED_BRIDGE_SCRIPTS` / `EXPECTED_PROOFS` / `READINESS_AUDIT` constant block in `readiness_audit.py:36-44`, `supplemental_proof_bundle.py:25-33`, `qualification_bundle.py:65-73`, and at the top of each `proofs/*.py` (each one has `READINESS_AUDIT = SCRIPT_DIR / "endpoint-decision-engine-readiness-audit.py"`).
   - Update `scripts/endpoint-decision-engine-live-qualification.sh` callsites and `scripts/test-macos-provider-dogfood-contract.sh` callsites.
   - Update `scripts/ci-changed.sh:79` dispatch regex.
   - Add `tools/edr-proof-bundle/README.md`.
   - Verify CI job still passes (this is the move that exercises the most cross-references).

5. **Add subprocess timeouts.** Add `timeout=120` to every `subprocess.run(...)` invocation in the proof bridges that doesn't already have one. Small commit, easy review.

6. **Update doc cross-references.** Sweep `docs/plans/clawdstrike/endpoint-decision-engine/current-state.md` and `roadmap.md` for the old `scripts/<name>.py` paths and update them. Update `scripts/README.md` items 21–28 to point to the new locations. Optionally delete those numbered items entirely and link out to `tools/*/README.md`.

7. **Decide whether `scripts/README.md` belongs here at all.** It is currently the only authoritative inventory of what each shell and Python script does. Several entries duplicate the script's own module docstring. Either keep it as the index of operator entry points and stop documenting per-module internals here, or move the index into a top-level `docs/operator/scripts.md`. Out of scope for this audit; flagged for follow-up.

### What this plan does NOT recommend

- **No deletes.** Every script has a real caller and a `--self-test` contract. Mass deletion would silently break operator workflows that are the documented gate for macOS provider releases (see `scripts/README.md` items 19–20).
- **No moves to `docs/evidence/`.** These scripts are validators and generators, not artifacts. They have no "produced artifact" that lives elsewhere — they produce JSON on demand from operator input.
- **No standalone redesign.** The subprocess-timeout gap is the only behavior change recommended, and it is additive.
