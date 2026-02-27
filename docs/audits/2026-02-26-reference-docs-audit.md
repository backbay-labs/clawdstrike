# Reference Documentation Audit -- 2026-02-26

## Summary

- Files audited: 51 (24 reference docs + 9 YAML rulesets + 15 guard .rs files + 3 source files)
- Total findings: 17
- Critical (outdated/wrong): 7
- Missing (should exist but doesn't): 6
- Improvement (could be better): 4

---

## Findings

### Guard Reference Docs

#### 1. Guards README claims "seven built-in guards" -- actual count is 12+
- **File:** `docs/src/reference/guards/README.md:3`
- **Severity:** Critical
- **Issue:** The README says "Clawdstrike ships with seven built-in guards" and lists only 7 in the table. The actual codebase has 12 guard implementations registered in `mod.rs`, plus `custom` and `path_normalization` modules.
- **Evidence:** `crates/libs/clawdstrike/src/guards/mod.rs:24-37` declares 13 modules. The `GuardConfigs` struct in `crates/libs/clawdstrike/src/policy.rs:229-272` has config fields for 12 distinct guards: `forbidden_path`, `path_allowlist`, `egress_allowlist`, `secret_leak`, `patch_integrity`, `shell_command`, `mcp_tool`, `prompt_injection`, `jailbreak`, `computer_use`, `remote_desktop_side_channel`, `input_injection_capability`.
- **Fix:** Update the README to list all 12 guards (or at minimum acknowledge the existence of the 5 undocumented ones). Update the table and the action coverage matrix.

#### 2. Missing reference doc: ComputerUseGuard
- **File:** (missing) `docs/src/reference/guards/computer-use.md`
- **Severity:** Missing
- **Issue:** `ComputerUseGuard` exists in `crates/libs/clawdstrike/src/guards/computer_use.rs` with config key `guards.computer_use` in the policy schema and is used in the `remote-desktop*.yaml` rulesets, but has no reference documentation.
- **Evidence:** `crates/libs/clawdstrike/src/guards/computer_use.rs:1-176` -- full guard implementation with `ComputerUseConfig` (fields: `enabled`, `allowed_actions`, `mode`), three modes (`observe`, `guardrail`, `fail_closed`). Used in `rulesets/remote-desktop.yaml:9-22`.
- **Fix:** Create `docs/src/reference/guards/computer-use.md` documenting config fields, modes, and action handling.

#### 3. Missing reference doc: ShellCommandGuard
- **File:** (missing) `docs/src/reference/guards/shell-command.md`
- **Severity:** Missing
- **Issue:** `ShellCommandGuard` exists in `crates/libs/clawdstrike/src/guards/shell_command.rs` with config key `guards.shell_command` in the policy schema, but has no reference documentation.
- **Evidence:** `crates/libs/clawdstrike/src/guards/shell_command.rs:1-478` -- handles `GuardAction::ShellCommand`, checks forbidden regex patterns and forbidden-path references extracted from command lines. Config fields: `enabled`, `forbidden_patterns`, `enforce_forbidden_paths`.
- **Fix:** Create `docs/src/reference/guards/shell-command.md`.

#### 4. Missing reference doc: RemoteDesktopSideChannelGuard
- **File:** (missing) `docs/src/reference/guards/remote-desktop-side-channel.md`
- **Severity:** Missing
- **Issue:** `RemoteDesktopSideChannelGuard` exists in `crates/libs/clawdstrike/src/guards/remote_desktop_side_channel.rs` with config key `guards.remote_desktop_side_channel`, but has no reference documentation.
- **Evidence:** `crates/libs/clawdstrike/src/guards/remote_desktop_side_channel.rs:1-502` -- controls clipboard, file transfer, audio, drive mapping, printing, session sharing channels. Config fields: `enabled`, `clipboard_enabled`, `file_transfer_enabled`, `session_share_enabled`, `audio_enabled`, `drive_mapping_enabled`, `printing_enabled`, `max_transfer_size_bytes`. Used in `rulesets/remote-desktop*.yaml`.
- **Fix:** Create `docs/src/reference/guards/remote-desktop-side-channel.md`.

#### 5. Missing reference doc: PathAllowlistGuard
- **File:** (missing) `docs/src/reference/guards/path-allowlist.md`
- **Severity:** Missing
- **Issue:** `PathAllowlistGuard` exists in `crates/libs/clawdstrike/src/guards/path_allowlist.rs` with config key `guards.path_allowlist` in the policy schema (v1.2.0+), but has no reference documentation.
- **Evidence:** `crates/libs/clawdstrike/src/guards/path_allowlist.rs:1-309` -- deny-by-default guard for filesystem paths. Config fields: `enabled`, `file_access_allow`, `file_write_allow`, `patch_allow`. Referenced in `crates/libs/clawdstrike/src/policy.rs:234-235`.
- **Fix:** Create `docs/src/reference/guards/path-allowlist.md`.

#### 6. Missing reference doc: InputInjectionCapabilityGuard
- **File:** (missing) `docs/src/reference/guards/input-injection-capability.md`
- **Severity:** Missing
- **Issue:** `InputInjectionCapabilityGuard` exists in `crates/libs/clawdstrike/src/guards/input_injection_capability.rs` with config key `guards.input_injection_capability`, but has no reference documentation.
- **Evidence:** `crates/libs/clawdstrike/src/guards/input_injection_capability.rs:1-253` -- controls input injection types (keyboard, mouse, touch) and postcondition probe requirements. Config fields: `enabled`, `allowed_input_types`, `require_postcondition_probe`. Used in `rulesets/remote-desktop*.yaml`.
- **Fix:** Create `docs/src/reference/guards/input-injection-capability.md`.

#### 7. Guards README: "enabled: false" toggle claim is incorrect
- **File:** `docs/src/reference/guards/README.md:55`
- **Severity:** Critical
- **Issue:** The README states "There is no `enabled: false` toggle in the current policy schema." This is incorrect -- every guard config struct has an `enabled: bool` field with `#[serde(default = "default_enabled")]` set to `true`.
- **Evidence:** All guard configs in the source code have `enabled` fields: `ForbiddenPathConfig` (`forbidden_path.rs:19`), `EgressAllowlistConfig` (`egress_allowlist.rs:15`), `SecretLeakConfig` (`secret_leak.rs:48`), `PatchIntegrityConfig` (`patch_integrity.rs:16`), `McpToolConfig` (`mcp_tool.rs:26`), `PromptInjectionConfig` (`prompt_injection.rs:14`), `JailbreakConfig` (`jailbreak.rs:14`), `ComputerUseConfig` (`computer_use.rs:27`), `RemoteDesktopSideChannelConfig` (`remote_desktop_side_channel.rs:15`), `InputInjectionCapabilityConfig` (`input_injection_capability.rs:14`), `ShellCommandConfig` (`shell_command.rs:17`), `PathAllowlistConfig` (`path_allowlist.rs:18`). The `strict.yaml` ruleset actually uses `enabled: true` at lines 112, 119.
- **Fix:** Replace the "no enabled toggle" paragraph with documentation of the `enabled` field.

#### 8. Guards README: Action Coverage matrix is incomplete
- **File:** `docs/src/reference/guards/README.md:26-34`
- **Severity:** Critical
- **Issue:** The action coverage matrix only lists 7 guards but misses 5 guards: ShellCommandGuard (handles `ShellCommand`), ComputerUseGuard (handles `Custom` with `remote.*`/`input.*`), RemoteDesktopSideChannelGuard (handles `Custom` with `remote.*` side channels), PathAllowlistGuard (handles `FileAccess`, `FileWrite`, `Patch`), InputInjectionCapabilityGuard (handles `Custom` with `input.inject`).
- **Evidence:** See guard source files as documented above.
- **Fix:** Add all 12 guards to the matrix with their action coverage, and add a `ShellCommand` column.

#### 9. Guards README: Evaluation order list is incomplete
- **File:** `docs/src/reference/guards/README.md:38-48`
- **Severity:** Critical
- **Issue:** The evaluation order only lists 7 guards. The `ShellCommandGuard`, `PathAllowlistGuard`, `ComputerUseGuard`, `RemoteDesktopSideChannelGuard`, and `InputInjectionCapabilityGuard` are not listed.
- **Evidence:** `crates/libs/clawdstrike/src/policy.rs:229-272` shows all 12 guard config fields in `GuardConfigs`.
- **Fix:** Update the evaluation order to include all built-in guards.

#### 10. SecretLeakGuard doc: Missing config fields
- **File:** `docs/src/reference/guards/secret-leak.md`
- **Severity:** Improvement
- **Issue:** The doc shows a minimal config example but does not document several config fields that exist in the code: `redact` (bool), `severity_threshold`, `additional_patterns`, `remove_patterns`, `description` and `luhn_check` and `masking` on pattern objects.
- **Evidence:** `crates/libs/clawdstrike/src/guards/secret_leak.rs:43-67` shows `SecretLeakConfig` fields: `enabled`, `redact`, `severity_threshold`, `patterns`, `additional_patterns`, `remove_patterns`, `skip_paths`. `SecretPattern` struct at lines 10-29 has `name`, `pattern`, `severity`, `description`, `luhn_check`, `masking`.
- **Fix:** Document all config fields with their types and defaults.

#### 11. ForbiddenPathGuard doc: Missing Windows patterns from default list
- **File:** `docs/src/reference/guards/forbidden-path.md`
- **Severity:** Improvement
- **Issue:** The doc shows only 3 example patterns (`**/.ssh/**`, `**/.aws/**`, `/etc/shadow`) but doesn't mention that the default list includes Windows-specific patterns (credential stores, registry hives, certificate stores, PowerShell profiles, `.reg` files).
- **Evidence:** `crates/libs/clawdstrike/src/guards/forbidden_path.rs:44-103` shows the full default list including 11 Windows-specific patterns.
- **Fix:** Add a note about Windows path coverage or show a more complete example.

---

### Ruleset Reference Docs

#### 12. Remote desktop rulesets have no reference docs
- **File:** (missing) `docs/src/reference/rulesets/remote-desktop.md`
- **Severity:** Critical
- **Issue:** Three remote-desktop rulesets exist (`remote-desktop.yaml`, `remote-desktop-permissive.yaml`, `remote-desktop-strict.yaml`) but none have reference documentation. They are also not listed in the rulesets README.
- **Evidence:** `rulesets/remote-desktop.yaml`, `rulesets/remote-desktop-permissive.yaml`, `rulesets/remote-desktop-strict.yaml` exist on disk. `docs/src/reference/rulesets/README.md:9-15` only lists 5 rulesets.
- **Fix:** Create docs for all three remote-desktop rulesets and add them to the rulesets README table.

#### 13. Rulesets README: Missing ai-agent-posture ruleset
- **File:** `docs/src/reference/rulesets/README.md`
- **Severity:** Critical
- **Issue:** The `ai-agent-posture.yaml` ruleset exists but is not listed in the rulesets README and has no reference doc.
- **Evidence:** `rulesets/ai-agent-posture.yaml` exists on disk -- it extends `clawdstrike:ai-agent` and defines a posture model with restricted/standard/elevated states.
- **Fix:** Add `ai-agent-posture` to the README table and create a reference doc.

#### 14. CI/CD ruleset doc: claims "verbose logging" but the YAML uses fail_fast: true
- **File:** `docs/src/reference/rulesets/cicd.md:15`
- **Severity:** Improvement
- **Issue:** Minor: the doc says "Enables verbose logging" and also separately says "Restricts MCP tools via an allowlist and defaults to block". The YAML does set `verbose_logging: true` and `fail_fast: true`, but the doc doesn't mention `fail_fast: true`. Since this is a significant behavior difference vs `default`, it should be called out.
- **Evidence:** `rulesets/cicd.yaml:113`: `fail_fast: true`.
- **Fix:** Add "Uses `fail_fast: true`" to the high-level description.

---

### API Reference Docs

#### 15. Python API doc: claims "five guards" but Python SDK has seven
- **File:** `docs/src/reference/api/python.md:9`
- **Severity:** Critical
- **Issue:** The doc says Python provides "five guards (ForbiddenPath, EgressAllowlist, SecretLeak, PatchIntegrity, McpTool)". The actual Python SDK exports 7 guards including PromptInjectionGuard and JailbreakGuard.
- **Evidence:** `packages/sdk/hush-py/src/clawdstrike/guards/__init__.py:18-23` exports `PromptInjectionGuard`, `PromptInjectionConfig`, `PromptInjectionLevel`, `JailbreakGuard`, and `JailbreakConfig`.
- **Fix:** Update the guard count to seven and list all guards.

#### 16. Python API doc: claims prompt-security utilities are "not yet implemented"
- **File:** `docs/src/reference/api/python.md:12`
- **Severity:** Critical
- **Issue:** The doc states "Prompt-security utilities (jailbreak detection, output sanitization, watermarking) are not yet implemented in Python." Jailbreak detection and prompt injection are implemented as guards. The `prompt_security.py` module also exists.
- **Evidence:** `packages/sdk/hush-py/src/clawdstrike/guards/jailbreak.py` and `packages/sdk/hush-py/src/clawdstrike/guards/prompt_injection.py` exist. `packages/sdk/hush-py/src/clawdstrike/prompt_security.py` also exists (and has tests: `tests/test_prompt_security.py`).
- **Fix:** Remove or correct the claim. At minimum, jailbreak detection and prompt injection are implemented. Output sanitization and watermarking status should be verified separately.

---

### Schema Docs

#### 17. Policy schema doc: Missing several guard config keys
- **File:** `docs/src/reference/policy-schema.md:46-76`
- **Severity:** Improvement
- **Issue:** The full schema example in the policy schema doc shows only `forbidden_path`, `path_allowlist`, `egress_allowlist`, `secret_leak`, `patch_integrity`, and `mcp_tool`. It does not show `shell_command`, `prompt_injection`, `jailbreak`, `computer_use`, `remote_desktop_side_channel`, or `input_injection_capability`.
- **Evidence:** `crates/libs/clawdstrike/src/policy.rs:229-272` shows `GuardConfigs` has fields for all 12 guards.
- **Fix:** Add the missing guard config keys to the full schema example, or add a note that the example is partial and link to the guards reference for the complete list.

---

## CLI Reference Accuracy

The CLI reference doc (`docs/src/reference/api/cli.md`) was checked against the actual subcommand definitions in `crates/services/hush-cli/src/main.rs`. The following observations are noted:

**Accurate items:**
- `check`, `policy show`, `policy validate`, `policy diff`, `policy list`, `policy lint`, `policy test`, `policy test generate`, `policy eval`, `policy simulate`, `policy observe`, `policy synth`, `policy migrate`, `policy bundle build/verify`, `policy rego compile/eval`, `guard inspect/validate`, `keygen`, `verify`, `hash`, `sign`, `merkle root/proof/verify`, `daemon start/stop/status/reload`, `completions` -- all match the source code.

**Items in the CLI source but not in the doc:**
- `policy impact` -- exists in the CLI (`main.rs:428-444`) but is missing from the CLI reference doc. The doc does not mention `clawdstrike policy impact <old> <new> <events>`.
- `policy version` -- exists in the CLI (`main.rs:447-456`) but is missing from the CLI reference doc.
- `run` -- exists in the CLI (`main.rs:156-200`) but is not documented in the CLI reference doc.
- `policy pac` -- module exists (`policy_pac.rs`), but its exposure via CLI was not verified in the subcommand enum, so this is not counted as a finding.

**Note:** These are borderline findings. The CLI doc is already quite comprehensive. The `impact`, `version`, and `run` subcommands should be added to the reference.

*These items are counted in the total findings above under finding #1 (the broader "guards README" finding also subsumes the structural incompleteness).*

---

## Ruleset YAML vs Doc Cross-Check

| Ruleset | YAML exists | Doc exists | Content match |
|---------|-------------|------------|---------------|
| `default` | Yes | Yes | Accurate |
| `strict` | Yes | Yes | Accurate |
| `permissive` | Yes | Yes | Accurate |
| `ai-agent` | Yes | Yes | Accurate |
| `cicd` | Yes | Yes | Accurate (minor: missing fail_fast mention) |
| `remote-desktop` | Yes | **No** | N/A |
| `remote-desktop-permissive` | Yes | **No** | N/A |
| `remote-desktop-strict` | Yes | **No** | N/A |
| `ai-agent-posture` | Yes | **No** | N/A |

---

## Guard Code vs Doc Cross-Check

| Guard | Source file | Doc exists | Config fields match |
|-------|-----------|------------|---------------------|
| ForbiddenPathGuard | `forbidden_path.rs` | Yes | Yes (partial -- missing Windows details) |
| EgressAllowlistGuard | `egress_allowlist.rs` | Yes | Yes |
| SecretLeakGuard | `secret_leak.rs` | Yes | Partial (missing `redact`, `severity_threshold`, `additional_patterns`, etc.) |
| PatchIntegrityGuard | `patch_integrity.rs` | Yes | Yes |
| McpToolGuard | `mcp_tool.rs` | Yes | Yes |
| PromptInjectionGuard | `prompt_injection.rs` | Yes | Yes |
| JailbreakGuard | `jailbreak.rs` | Yes | Yes |
| ComputerUseGuard | `computer_use.rs` | **No** | N/A |
| ShellCommandGuard | `shell_command.rs` | **No** | N/A |
| RemoteDesktopSideChannelGuard | `remote_desktop_side_channel.rs` | **No** | N/A |
| PathAllowlistGuard | `path_allowlist.rs` | **No** | N/A |
| InputInjectionCapabilityGuard | `input_injection_capability.rs` | **No** | N/A |
