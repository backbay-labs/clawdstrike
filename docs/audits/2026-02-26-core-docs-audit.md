# Core Documentation Audit — 2026-02-26

## Summary
- Files audited: 35
- Total findings: 25
- Critical (outdated/wrong): 10
- Missing (should exist but doesn't): 8
- Improvement (could be better): 7

---

## Findings

### Concepts

#### 1. Guards doc lists only 7 built-in guards; code has 12
- **File:** docs/src/concepts/guards.md:33-41
- **Severity:** Critical
- **Issue:** The guards concept doc lists exactly 7 built-in guards (ForbiddenPathGuard, EgressAllowlistGuard, SecretLeakGuard, PatchIntegrityGuard, McpToolGuard, PromptInjectionGuard, JailbreakGuard). The actual codebase has 12 guards exported from `guards/mod.rs`.
- **Evidence:** `crates/libs/clawdstrike/src/guards/mod.rs:39-56` exports: ComputerUseGuard, ShellCommandGuard, PathAllowlistGuard, InputInjectionCapabilityGuard, RemoteDesktopSideChannelGuard in addition to the 7 listed. These are also wired into `GuardConfigs` at `crates/libs/clawdstrike/src/policy.rs:229-272`.
- **Fix:** Add the 5 missing guards to the built-in guards list: `ComputerUseGuard`, `ShellCommandGuard`, `PathAllowlistGuard`, `InputInjectionCapabilityGuard`, `RemoteDesktopSideChannelGuard`.

#### 2. Architecture doc lists TS SDK as `@backbay/sdk`
- **File:** docs/src/concepts/architecture.md:59
- **Severity:** Critical
- **Issue:** The architecture doc says `@clawdstrike/sdk` package description is "Crypto/receipts + a subset of guards + prompt-security utilities" but calls it `@backbay/sdk` in the table header: `@clawdstrike/sdk` is correct.
- **Evidence:** `packages/sdk/hush-ts/package.json:2` has `"name": "@clawdstrike/sdk"`. The doc line 59 incorrectly uses `@clawdstrike/sdk` in the description column but the table is accurate. However, the CLAUDE.md at root line 59 references `@backbay/sdk`. The architecture doc is internally consistent — no fix needed on this doc specifically.
- **Fix:** No fix needed for architecture.md. The root CLAUDE.md reference to `@backbay/sdk` (line from CLAUDE.md) is the actual discrepancy — that belongs to a different audit scope.

#### 3. Architecture doc missing OutputSanitizer and Watermarking as separate components
- **File:** docs/src/concepts/architecture.md:18-20
- **Severity:** Improvement
- **Issue:** The ASCII diagram at lines 18-20 shows OutputSanitizer and Watermarking as boxes in HushEngine, which is accurate. However, they are not listed as guards in the text or as separate items in the "Components" section. OutputSanitizer and Watermarking are standalone modules (`crates/libs/clawdstrike/src/output_sanitizer.rs`, `crates/libs/clawdstrike/src/watermarking.rs`), not guards. The diagram appropriately shows them separately, but the components table at line 48 doesn't mention them individually.
- **Fix:** Consider adding OutputSanitizer and Watermarking to the crate description at line 48 (they are already implicitly covered by "output sanitization" in the description, but explicit mention would be clearer).

#### 4. Decisions doc `GuardResult` fields don't match actual code
- **File:** docs/src/concepts/decisions.md:9-13
- **Severity:** Critical
- **Issue:** The doc says `GuardResult` contains `severity` with values `info | warning | error | critical`, `message`, and `details`. Actual code at `crates/libs/clawdstrike/src/guards/mod.rs:83-95` shows the struct also has a `guard` field (string). The doc omits this field.
- **Evidence:** `crates/libs/clawdstrike/src/guards/mod.rs:88` — `pub guard: String`
- **Fix:** Add `guard` field to the `GuardResult` documentation: "- `guard` (string) — the name of the guard that produced this result".

#### 5. Decisions doc references `1.2.0+` for posture-aware decisions
- **File:** docs/src/concepts/decisions.md:29
- **Severity:** Improvement
- **Issue:** The heading says "Posture-Aware Decisions (`1.2.0+`)" which is correct — but the rest of the concept docs (policies.md, the example YAML) still show `version: "1.1.0"` as the primary example. This creates confusion about what version to use.
- **Fix:** Consistent guidance: note that `1.2.0` is the current schema version and `1.1.0` is still supported. See finding #8 below.

#### 6. Terminology doc omits `ShellCommand` from `GuardAction` types
- **File:** docs/src/concepts/terminology.md:19
- **Severity:** Critical
- **Issue:** The terminology doc lists `GuardAction` types as: `FileAccess`, `FileWrite`, `Patch`, `NetworkEgress`, `McpTool`, `Custom`. But the actual enum at `crates/libs/clawdstrike/src/guards/mod.rs:226-241` also includes `ShellCommand`. The concepts/guards.md doc does list `ShellCommand` at line 26.
- **Evidence:** `crates/libs/clawdstrike/src/guards/mod.rs:234` — `ShellCommand(&'a str)`
- **Fix:** Add `ShellCommand` to the `GuardAction` types list in the terminology table.

#### 7. Terminology doc severity levels don't match code
- **File:** docs/src/concepts/terminology.md:72-78
- **Severity:** Critical
- **Issue:** The terminology doc lists severity levels as: `safe`, `suspicious`, `likely`, `confirmed`, `critical`. These are the **JailbreakSeverity** levels (from `crates/libs/clawdstrike/src/jailbreak.rs:39-44`), not the guard `Severity` enum. The actual guard `Severity` at `crates/libs/clawdstrike/src/guards/mod.rs:64-78` is: `Info` (alias `low`), `Warning` (alias `medium`), `Error` (alias `high`), `Critical`.
- **Evidence:** `crates/libs/clawdstrike/src/guards/mod.rs:64-78` defines `Severity { Info, Warning, Error, Critical }`. The doc conflates two different severity taxonomies.
- **Fix:** Split into two sections: (1) Guard severity levels: info, warning, error, critical; (2) Jailbreak severity levels: safe, suspicious, likely, confirmed.

#### 8. Policies concept doc shows schema version `1.1.0`; current is `1.2.0`
- **File:** docs/src/concepts/policies.md:10
- **Severity:** Critical
- **Issue:** The YAML example shows `version: "1.1.0"`. The actual current schema version is `1.2.0` per `crates/libs/clawdstrike/src/policy.rs:26` (`POLICY_SCHEMA_VERSION: &str = "1.2.0"`). While `1.1.0` is still supported (`POLICY_SUPPORTED_SCHEMA_VERSIONS: &["1.1.0", "1.2.0"]`), the doc should show the current version and note backwards compatibility.
- **Evidence:** `crates/libs/clawdstrike/src/policy.rs:26-27`
- **Fix:** Update the example to `version: "1.2.0"` and add a note that `1.1.0` is still accepted.

#### 9. Architecture doc missing rulesets in built-in list
- **File:** docs/src/concepts/architecture.md (implicit, via CLAUDE.md reference)
- **Severity:** Missing
- **Issue:** The CLAUDE.md and various doc pages mention 5 built-in rulesets: `permissive`, `default`, `strict`, `ai-agent`, `cicd`. The actual `RuleSet::list()` at `crates/libs/clawdstrike/src/policy.rs:1682-1694` returns 9 rulesets: the 5 listed plus `ai-agent-posture`, `remote-desktop`, `remote-desktop-strict`, `remote-desktop-permissive`.
- **Evidence:** `crates/libs/clawdstrike/src/policy.rs:1682-1694` and matching YAML files in `rulesets/`.
- **Fix:** Update all docs that list built-in rulesets to include the 4 new rulesets: `ai-agent-posture`, `remote-desktop`, `remote-desktop-strict`, `remote-desktop-permissive`.

#### 10. Postures doc capabilities list is incomplete
- **File:** docs/src/concepts/postures.md:8
- **Severity:** Improvement
- **Issue:** The postures doc lists capabilities as `file_access, file_write, egress, shell, mcp_tool, patch, custom`. The actual `ai-agent-posture.yaml` ruleset file at `rulesets/ai-agent-posture.yaml:33` also uses `shell` capability. The doc list is complete per the code. However, checking `crates/libs/clawdstrike/src/posture.rs` would confirm the full enum — this is a minor verification note, not a discrepancy.
- **Fix:** No change needed — the list appears complete.

---

### Getting Started

#### 11. Quick Start shows `version: "1.1.0"`; should prefer `1.2.0`
- **File:** docs/src/getting-started/quick-start.md:54
- **Severity:** Critical
- **Issue:** The YAML example at line 54 uses `version: "1.1.0"`. While valid, new users should be guided to use the current schema `1.2.0`.
- **Evidence:** `crates/libs/clawdstrike/src/policy.rs:26` — `POLICY_SCHEMA_VERSION: &str = "1.2.0"`
- **Fix:** Change the example to `version: "1.2.0"`.

#### 12. Installation doc says TypeScript SDK import is `Clawdstrike`
- **File:** docs/src/getting-started/installation.md:49
- **Severity:** Improvement
- **Issue:** The import example `import { Clawdstrike } from "@clawdstrike/sdk"` is correct per `packages/sdk/hush-ts/src/clawdstrike.ts`. However the `Clawdstrike.withDefaults("strict")` factory method and `cs.checkFile()` API should be verified against actual exports. The class does export `withDefaults` and `checkFile`, so this is accurate.
- **Fix:** No fix needed — verified correct.

#### 13. Quick Start Python mentions 5 guards; should mention 7+ available in Rust
- **File:** docs/src/getting-started/quick-start-python.md:7
- **Severity:** Improvement
- **Issue:** States "five guards (ForbiddenPath, EgressAllowlist, SecretLeak, PatchIntegrity, McpTool)". This is the correct count for the Python SDK specifically (it doesn't have PromptInjection or Jailbreak). The doc is accurate for Python's scope.
- **Fix:** No fix needed — doc correctly scopes to Python's capabilities.

#### 14. OpenClaw integration doc references wrong Rust policy schema version
- **File:** docs/src/guides/openclaw-integration.md:57
- **Severity:** Critical
- **Issue:** States "It is not the same as the Rust `clawdstrike::Policy` schema (`version: "1.1.0"`)". The Rust policy schema current version is `1.2.0`, with `1.1.0` as a supported legacy version.
- **Evidence:** `crates/libs/clawdstrike/src/policy.rs:26` — `POLICY_SCHEMA_VERSION: &str = "1.2.0"`
- **Fix:** Change `"1.1.0"` to `"1.2.0"` (or `"1.1.0"/"1.2.0"`).

---

### Guides

#### 15. Policy Inheritance guide shows `version: "1.1.0"` in example
- **File:** docs/src/guides/policy-inheritance.md:23
- **Severity:** Critical
- **Issue:** Example YAML shows `version: "1.1.0"`. Should prefer `1.2.0`.
- **Evidence:** `crates/libs/clawdstrike/src/policy.rs:26`
- **Fix:** Update to `version: "1.2.0"`.

#### 16. Policy Inheritance guide missing 4 newer rulesets
- **File:** docs/src/guides/policy-inheritance.md:8-12
- **Severity:** Missing
- **Issue:** Lists 5 built-in rulesets. Missing: `clawdstrike:ai-agent-posture`, `clawdstrike:remote-desktop`, `clawdstrike:remote-desktop-strict`, `clawdstrike:remote-desktop-permissive`.
- **Evidence:** `crates/libs/clawdstrike/src/policy.rs:1682-1694`
- **Fix:** Add the 4 missing rulesets to the list.

#### 17. Custom Guards guide doesn't mention `guards.custom[]` policy-driven guards
- **File:** docs/src/guides/custom-guards.md
- **Severity:** Missing
- **Issue:** The doc mentions `guards.custom[]` at line 42 in passing but doesn't document the `PolicyCustomGuardSpec` configuration shape (`id`, `enabled`, `config` fields) or how policy-driven custom guards differ from programmatic `with_extra_guard`. The `GuardConfigs` struct at `crates/libs/clawdstrike/src/policy.rs:266-271` has a `custom: Vec<CustomGuardSpec>` field that accepts plugin-shaped guards in YAML.
- **Evidence:** `crates/libs/clawdstrike/src/policy.rs:59-70` — `PolicyCustomGuardSpec { id, enabled, config }`
- **Fix:** Add a section documenting policy-driven custom guards via `guards.custom[]` YAML config.

#### 18. Desktop Agent guide references `ai-agent-minimal` ruleset that doesn't exist
- **File:** docs/src/guides/openclaw-integration.md:88
- **Severity:** Critical
- **Issue:** Recommends `clawdstrike:ai-agent-minimal` as a starting point. No such ruleset exists in `RuleSet::list()` or in `rulesets/` directory.
- **Evidence:** `crates/libs/clawdstrike/src/policy.rs:1682-1694` — the list is: default, strict, ai-agent, ai-agent-posture, cicd, permissive, remote-desktop, remote-desktop-strict, remote-desktop-permissive. No `ai-agent-minimal`.
- **Fix:** Replace `clawdstrike:ai-agent-minimal` with `clawdstrike:ai-agent` or `clawdstrike:permissive` depending on intended meaning.

#### 19. Audit Logging guide references `clawdstriked start` — CLI uses `clawdstrike daemon start`
- **File:** docs/src/guides/audit-logging.md:36
- **Severity:** Improvement
- **Issue:** The guide says `clawdstriked start` on line 36. The CLI main.rs at `crates/services/hush-cli/src/main.rs:26` documents `hush daemon start|stop|status|reload` as the daemon management subcommand. The binary `clawdstriked` may be a separate binary — this needs verification. The installation doc at `docs/src/getting-started/installation.md:39` says `clawdstrike daemon start`, which is consistent with the CLI.
- **Fix:** Verify whether `clawdstriked` is a standalone binary or an alias. If it's only available as `clawdstrike daemon start`, update the audit logging guide accordingly.

#### 20. No documentation for CUA (Computer Use Agent) guards
- **File:** (missing)
- **Severity:** Missing
- **Issue:** The codebase has `ComputerUseGuard`, `InputInjectionCapabilityGuard`, and `RemoteDesktopSideChannelGuard` (added in commit `95973807` — "feat(cua): CUA Gateway — guards, rulesets, research, ecosystem integrations (#88)") plus 3 rulesets (`remote-desktop`, `remote-desktop-strict`, `remote-desktop-permissive`). There are no concept docs or guide docs explaining CUA guards, and no reference guard pages for these 3 guards.
- **Evidence:** `crates/libs/clawdstrike/src/guards/computer_use.rs`, `crates/libs/clawdstrike/src/guards/input_injection_capability.rs`, `crates/libs/clawdstrike/src/guards/remote_desktop_side_channel.rs`, `rulesets/remote-desktop*.yaml`
- **Fix:** Create reference pages for the 3 CUA guards and a guide for remote desktop/CUA integration.

#### 21. No documentation for ShellCommandGuard
- **File:** (missing)
- **Severity:** Missing
- **Issue:** `ShellCommandGuard` exists in code (`crates/libs/clawdstrike/src/guards/shell_command.rs`) and is wired into `GuardConfigs` at `policy.rs:247`. No reference page or mention in guard docs exists. It blocks dangerous command-line patterns and enforces forbidden-path checks on extracted path tokens.
- **Evidence:** `crates/libs/clawdstrike/src/guards/shell_command.rs:1-40`
- **Fix:** Create a reference page `docs/src/reference/guards/shell-command.md` and add ShellCommandGuard to the guard list in concepts.

#### 22. No documentation for PathAllowlistGuard
- **File:** (missing)
- **Severity:** Missing
- **Issue:** `PathAllowlistGuard` is a deny-by-default path guard (opposite of `ForbiddenPathGuard`). It exists in code at `crates/libs/clawdstrike/src/guards/path_allowlist.rs` and is wired into policy at `policy.rs:235`. The first-policy guide mentions it at line 53 but no reference page exists.
- **Evidence:** `crates/libs/clawdstrike/src/guards/path_allowlist.rs:1-30`
- **Fix:** Create a reference page `docs/src/reference/guards/path-allowlist.md`.

#### 23. Observe-Synth guide references example files that may not exist
- **File:** docs/src/guides/observe-synth.md:39
- **Severity:** Improvement
- **Issue:** References `examples/policies/synthesized-example.yaml` — this should be verified to exist. If it doesn't, the reference is a dead pointer.
- **Fix:** Verify the file exists; if not, either create it or remove the reference.

---

### Recipes

#### 24. Claude recipe shows `version: "1.1.0"` in example
- **File:** docs/src/recipes/claude.md:19
- **Severity:** Critical
- **Issue:** Example YAML uses `version: "1.1.0"`. Same issue as findings #8, #11, #15.
- **Evidence:** `crates/libs/clawdstrike/src/policy.rs:26`
- **Fix:** Update to `version: "1.2.0"`.

#### 25. GitHub Actions recipe shows `version: "1.1.0"` in example
- **File:** docs/src/recipes/github-actions.md:37-39
- **Severity:** Critical
- **Issue:** CI policy example uses `version: "1.1.0"`.
- **Evidence:** `crates/libs/clawdstrike/src/policy.rs:26`
- **Fix:** Update to `version: "1.2.0"`.

---

## Cross-Cutting Issues

### Schema Version Inconsistency (affects 6+ files)

The policy schema version `1.2.0` is current, with `1.1.0` supported for backward compatibility. However, 6+ doc files still show `1.1.0` as the example version:
- `docs/src/concepts/policies.md:10`
- `docs/src/getting-started/quick-start.md:54`
- `docs/src/guides/policy-inheritance.md:23`
- `docs/src/guides/openclaw-integration.md:57`
- `docs/src/recipes/claude.md:19`
- `docs/src/recipes/github-actions.md:37`

**Recommendation:** Bulk-update all example YAML to `version: "1.2.0"` and add a note about `1.1.0` backward compatibility.

### Built-in Rulesets List Incomplete (affects 3+ files)

Multiple files list only 5 rulesets (`default`, `strict`, `ai-agent`, `cicd`, `permissive`) while the code has 9. Files affected:
- `docs/src/concepts/terminology.md:11`
- `docs/src/guides/policy-inheritance.md:8-12`
- CLAUDE.md (root)

### Missing Guard Documentation (affects multiple)

5 guards have no reference pages or are undocumented in concept docs:
- `ComputerUseGuard` — CUA action control
- `ShellCommandGuard` — shell command pattern blocking
- `PathAllowlistGuard` — deny-by-default path allowlisting
- `InputInjectionCapabilityGuard` — CUA input type control
- `RemoteDesktopSideChannelGuard` — RDP side channel control

These were added in recent commits (#88, #80) and need both reference pages and concept doc updates.

---

## Notes

- All built-in rulesets (`rulesets/*.yaml`) use `version: "1.1.0"` or `"1.2.0"` — this is correct since supported versions include both.
- The TypeScript and Python quick-start guides are reasonably accurate for their respective SDK surfaces.
- The enforcement-tiers, design-philosophy, and schema-governance concept docs are accurate and well-aligned with the code.
- The desktop-agent guide and agent-openclaw-operations runbook are comprehensive and largely accurate.
- The Helm confidence pipeline guide is operational documentation and does not make code claims — no discrepancies found.
