# HushSpec Carve-Out Plan

## 1. Executive Summary

HushSpec is a proposed open, portable specification for declaring security rules at the tool boundary of AI agent runtimes. Today, all of this lives inside Clawdstrike's `Policy` struct — a single YAML schema that mixes portable security intent with engine-specific guard config, runtime knobs, stateful automation, and provider infrastructure. This plan carves the portable core out into a standalone spec owned by `../hush`, while Clawdstrike becomes an engine that compiles, extends, and enforces HushSpec documents.

**The split in one sentence:** HushSpec defines *what* security rules an agent operates under; Clawdstrike defines *how* those rules are compiled, evaluated, attested, and enforced at runtime.

**Key outcomes:**
- A neutral spec that third-party runtimes (OpenAI, LangChain, custom) can adopt without importing Clawdstrike
- Clean separation of concerns: spec versioning decoupled from engine versioning
- Clawdstrike gains a compiler layer (`hushspec → clawdstrike native policy`) that enables backward compatibility and progressive adoption
- Existing users experience zero breakage — current policy YAML remains valid via the compiler

**Recommended timeline:** 6-8 weeks from kickoff to first tagged HushSpec v0.1.0 and Clawdstrike release with compiler.

---

## 2. Current State in Clawdstrike

### 2.1 Policy Schema (v1.5.0)

The canonical policy type lives in `crates/libs/clawdstrike/src/policy.rs`. Top-level:

```
Policy {
  version: String,                    // "1.1.0" through "1.5.0"
  name: String,
  description: String,
  extends: Option<String>,            // inheritance chain (max depth 32)
  merge_strategy: MergeStrategy,      // Replace | Merge | DeepMerge
  guards: GuardConfigs,               // 13 built-in + custom plugin array
  custom_guards: Vec<...>,            // deprecated path
  settings: PolicySettings,           // fail_fast, verbose_logging, session_timeout
  posture: Option<PostureConfig>,     // v1.2.0+ state machine
  origins: Option<OriginsConfig>,     // v1.4.0+ origin-aware profiles
  broker: Option<BrokerConfig>,       // v1.5.0+ secret broker
}
```

### 2.2 Guard Configs

`GuardConfigs` holds `Option<T>` for each of 13 built-in guards plus `Vec<CustomGuardSpec>`:

| # | Guard | Config Location | Portability |
|---|-------|----------------|-------------|
| 1 | ForbiddenPath | `guards/forbidden_path.rs` | Portable — glob patterns + exceptions |
| 2 | PathAllowlist | `guards/path_allowlist.rs` | Portable — glob allowlists (read/write/patch) |
| 3 | EgressAllowlist | `guards/egress_allowlist.rs` | Portable — domain patterns + default action |
| 4 | SecretLeak | `guards/secret_leak.rs` | Portable — named regex patterns + severity |
| 5 | PatchIntegrity | `guards/patch_integrity.rs` | Portable — limits + forbidden patterns |
| 6 | ShellCommand | `guards/shell_command.rs` | Portable — forbidden regex patterns |
| 7 | McpTool | `guards/mcp_tool.rs` | Portable — tool allow/block/confirm lists |
| 8 | PromptInjection | `guards/prompt_injection.rs` | Hybrid — thresholds portable, detection engine-specific |
| 9 | Jailbreak | `guards/jailbreak.rs` | Hybrid — thresholds portable, 4-layer detector engine-specific |
| 10 | ComputerUse | `guards/computer_use.rs` | Portable — action allowlist + mode |
| 11 | RemoteDesktopSideChannel | `guards/remote_desktop_side_channel.rs` | Portable — boolean channel toggles |
| 12 | InputInjectionCapability | `guards/input_injection_capability.rs` | Portable — input type list + probe flag |
| 13 | SpiderSense | `spider_sense.rs` + `async_guards/threat_intel.rs` | Hybrid — pattern DB path portable, embedding/LLM engine-specific |

### 2.3 Posture System (v1.2.0+)

Source: `crates/libs/clawdstrike/src/posture.rs`

Declarative state machine: states with capabilities and budgets, transitions with triggers. The *config* is stateless YAML; the *runtime* (`PostureRuntimeState`) is ephemeral in-memory session state.

- 7 transition triggers: `UserApproval`, `UserDenial`, `CriticalViolation`, `AnyViolation`, `Timeout`, `BudgetExhausted`, `PatternMatch`
- 7 capability types: `file_access`, `file_write`, `egress`, `shell`, `mcp_tool`, `patch`, `custom`
- 6 budget keys: `file_writes`, `egress_calls`, `shell_commands`, `mcp_tool_calls`, `patches`, `custom_calls`

### 2.4 Origins/Enclaves (v1.4.0+)

Source: `origin.rs`, `enclave.rs`, `origin_runtime.rs`

Origin-aware policy projection. Profiles match on provider/space/visibility/tags and project narrowed MCP/egress/data/budget constraints. Bridge policies govern cross-origin transitions.

- 8 providers: Slack, Teams, GitHub, Jira, Email, Discord, Webhook, Custom
- 8 space types: Channel, Group, Dm, Thread, Issue, Ticket, PullRequest, EmailThread, Custom
- Deterministic match priority: space_id → field specificity → provider → default → fallback

### 2.5 Broker System (v1.5.0+)

Source: `policy.rs` (BrokerConfig struct)

Per-provider credential brokering: path-scoped, method-scoped, with intent preview and approval gates. Capabilities are time-bounded, Ed25519-signed.

### 2.6 SDK/CLI Surfaces

| Surface | Schema Version | Key Files |
|---------|---------------|-----------|
| Rust core | 1.1.0–1.5.0 | `crates/libs/clawdstrike/src/policy.rs` |
| TypeScript policy engine | 1.1.0–1.3.0 | `packages/policy/clawdstrike-policy/src/policy/schema.ts` |
| Python SDK | 1.1.0–1.3.0 | `packages/sdk/hush-py/src/clawdstrike/policy.py` |
| CLI (`hush policy`) | 1.1.0–1.5.0 | `crates/services/hush-cli/src/policy_*.rs` |
| Daemon (`hushd`) | 1.1.0–1.5.0 | `crates/services/hushd/src/api/policy.rs` |

CLI commands: `validate`, `lint`, `diff`, `synth`, `simulate`, `test`, `migrate`, `eval`, `observe`, `impact`, `show`.

### 2.7 Rulesets

11 built-in YAML files in `rulesets/`:

| Ruleset | Version | Uses Extends | Uses Posture | Uses Origins | Uses Broker |
|---------|---------|-------------|-------------|-------------|------------|
| default | 1.1.0 | — | — | — | — |
| permissive | 1.1.0 | — | — | — | — |
| strict | 1.1.0 | — | — | — | — |
| ai-agent | 1.1.0 | — | — | — | — |
| ai-agent-posture | 1.2.0 | ai-agent | Yes | — | — |
| cicd | 1.1.0 | — | — | — | — |
| remote-desktop | 1.2.0 | ai-agent | — | — | — |
| remote-desktop-permissive | 1.2.0 | remote-desktop | — | — | — |
| remote-desktop-strict | 1.2.0 | remote-desktop | — | — | — |
| spider-sense | 1.2.0 | — | — | — | — |
| origin-enclaves-example | 1.4.0 | default | Yes | Yes | — |

### 2.8 Test Infrastructure

- Rust: `crates/libs/clawdstrike/tests/policy_extends.rs` (extends, merge, cycle detection)
- Policy torture: `rulesets/tests/policy-torture/` (4 suites: deep-merge, replace, posture-escalation, guard-gauntlet)
- Python: `packages/sdk/hush-py/tests/test_policy.py` (20K+ lines), `test_origin.py`
- TS: `packages/policy/clawdstrike-policy/` tests
- Pattern DB schema: `rulesets/spider-sense-patterns.schema.json`

---

## 3. Proposed Architectural Split

```
┌──────────────────────────────────────────────────┐
│                    HushSpec                       │
│  (portable, stateless, engine-neutral)            │
│                                                   │
│  • Guard rule schemas (10 portable guards)        │
│  • Action type taxonomy                           │
│  • Merge/inheritance semantics                    │
│  • Conformance test vectors                       │
│  • Reference rulesets                             │
│  • JSON Schema for validation                     │
└──────────────┬───────────────────────────────────┘
               │ compiles to
┌──────────────▼───────────────────────────────────┐
│              Clawdstrike Engine                    │
│  (runtime, stateful, implementation)              │
│                                                   │
│  • HushSpec compiler/loader                       │
│  • Engine-native Policy representation            │
│  • Detection guards (prompt injection, jailbreak, │
│    spider sense)                                  │
│  • Posture state machine runtime                  │
│  • Origin enclave resolver + runtime state        │
│  • Broker capability authority                    │
│  • Receipt signing + audit                        │
│  • Async guard infrastructure (timeout, cache,    │
│    circuit breaker, retry)                        │
│  • Custom guard plugin system                     │
│  • CLI, daemon, SDKs                              │
└──────────────────────────────────────────────────┘
```

### 3.1 Three Layers

**Layer 1: HushSpec Core** — The portable rule language. A HushSpec document declares security intent: what paths are forbidden, what domains are allowed, what tools are blocked, what patterns leak secrets. No runtime state, no detection algorithms, no cryptographic attestation. Any engine can read and enforce these rules.

**Layer 2: HushSpec Extensions** — Optional spec modules that extend the core with richer (but still declarative) capabilities. Posture state machines, origin profiles, detection thresholds. These are spec-level but not required for a minimal conformant implementation.

**Layer 3: Clawdstrike Engine Profiles** — Everything that requires the Clawdstrike runtime: async guard infrastructure, 4-layer jailbreak detection, Spider Sense embedding search, receipt signing, broker capabilities, daemon API, session management.

---

## 4. What Becomes HushSpec Core

### 4.1 Scope

HushSpec Core v0.1.0 covers the **stateless, declarative guard rules** that any engine can evaluate without proprietary detection logic.

### 4.2 Top-Level Schema

```yaml
hushspec: "0.1.0"          # HushSpec version (not Clawdstrike version)
name: "my-policy"
description: "..."
extends: "hushspec:default" # spec-level inheritance
merge_strategy: deep_merge  # replace | merge | deep_merge

rules:
  forbidden_paths:
    enabled: true
    patterns: ["**/.ssh/**", "**/.aws/**"]
    exceptions: [".env.example"]

  path_allowlist:
    enabled: true
    read: ["./src/**", "./docs/**"]
    write: ["./src/**"]
    patch: ["./src/**"]

  egress:
    enabled: true
    allow: ["api.openai.com", "api.anthropic.com"]
    block: ["*.internal.corp"]
    default: block

  secret_patterns:
    enabled: true
    patterns:
      - name: aws_access_key
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
    skip_paths: ["**/test/**", "**/fixtures/**"]

  patch_integrity:
    enabled: true
    max_additions: 1000
    max_deletions: 500
    forbidden_patterns: ["rm -rf /", "chmod 777"]

  shell_commands:
    enabled: true
    forbidden_patterns: ["rm -rf /", "curl.*\\|.*bash"]

  tool_access:
    enabled: true
    allow: ["read_file", "list_directory"]
    block: ["shell_exec", "run_command"]
    require_confirmation: ["file_write", "git_push"]
    default: allow

  computer_use:
    enabled: true
    mode: guardrail
    allowed_actions: ["remote.session.connect", "input.inject"]

  remote_desktop_channels:
    enabled: true
    clipboard: false
    file_transfer: false
    audio: true
    drive_mapping: false

  input_injection:
    enabled: true
    allowed_types: ["keyboard", "mouse"]
    require_postcondition_probe: false
```

### 4.3 What Is In

| Area | HushSpec Field | Notes |
|------|---------------|-------|
| Metadata | `hushspec`, `name`, `description` | Spec version, not engine version |
| Inheritance | `extends`, `merge_strategy` | Spec-level; resolution is engine concern |
| Forbidden paths | `rules.forbidden_paths` | Glob patterns + exceptions |
| Path allowlist | `rules.path_allowlist` | Read/write/patch globs |
| Egress control | `rules.egress` | Domain allow/block + default action |
| Secret detection | `rules.secret_patterns` | Named regex patterns + severity + masking |
| Patch integrity | `rules.patch_integrity` | Size limits + forbidden patterns |
| Shell commands | `rules.shell_commands` | Forbidden regex patterns |
| Tool access | `rules.tool_access` | Allow/block/confirm lists + default action |
| Computer use | `rules.computer_use` | Action allowlist + mode |
| Remote desktop | `rules.remote_desktop_channels` | Boolean channel toggles |
| Input injection | `rules.input_injection` | Type allowlist + probe flag |

### 4.4 What Is Explicitly Deferred from Core

| Area | Reason |
|------|--------|
| Prompt injection detection | Requires detection engine (WASM module) — goes to extension |
| Jailbreak detection | Requires 4-layer detector — goes to extension |
| Spider Sense | Requires embedding model + pattern DB — goes to extension |
| Posture state machines | Stateful automation — goes to extension |
| Origin enclaves | Origin-aware projection — goes to extension |
| Broker config | Credential infrastructure — stays engine-only |
| Custom guard plugins | Engine plugin system — stays engine-only |
| Async guard config | Runtime infrastructure — stays engine-only |
| Settings (fail_fast, verbose_logging, session_timeout) | Runtime behavior — stays engine-only |
| Receipt/attestation format | Cryptographic protocol — stays engine-only |

---

## 5. What Stays Clawdstrike-Native

### 5.1 Engine-Only Concerns

| Concern | Location | Rationale |
|---------|----------|-----------|
| `PolicySettings` | `policy.rs` | Runtime behavior (fail_fast, logging, timeouts) |
| `AsyncGuardPolicyConfig` | `policy.rs` | Timeout, cache, circuit breaker, retry, rate limit |
| `CustomGuardSpec` / `PolicyCustomGuardSpec` | `policy.rs` | Plugin registry, package resolution |
| `BrokerConfig` / `BrokerProviderPolicy` | `policy.rs` | Credential brokering infrastructure |
| `PostureRuntimeState` | `posture.rs` | Ephemeral session state |
| `OriginRuntimeState` | `origin_runtime.rs` | Ephemeral session state |
| Receipt signing | `hush-core/`, `spine/` | Ed25519 attestation protocol |
| Guard trait + evaluation pipeline | `engine.rs`, `guards/mod.rs` | Engine internals |
| Detection modules | `hygiene.rs`, `jailbreak.rs`, `spider_sense.rs` | Proprietary detection logic |
| Policy resolution (URL, Git, integrity) | `policy.rs` (extends resolver) | Engine-specific fetch + verification |

### 5.2 Extensions (Spec-Level but Optional)

These are declared in HushSpec extension modules but compiled/enforced by the engine:

| Extension | HushSpec Declaration | Clawdstrike Enforcement |
|-----------|---------------------|------------------------|
| Posture | State names, capabilities, budgets, transition triggers | `PostureProgram` runtime, budget counters, session tracking |
| Origins | Match rules, profiles, bridge targets | `EnclaveResolver`, `intersect_with()`, runtime isolation |
| Detection thresholds | `prompt_injection.block_at: high`, `jailbreak.block_threshold: 40` | WASM detector, 4-layer pipeline, LLM judge |
| Spider Sense | `pattern_db: "builtin:s2bench-v1"`, `similarity_threshold: 0.85` | `SpiderSenseDetector`, embedding inference |

---

## 6. Proposed `../hush` Repo Structure

```
hush/
├── README.md
├── LICENSE                          # Apache-2.0 (or dual Apache/MIT)
├── CLAUDE.md
├── Cargo.toml                       # Workspace root
├── package.json                     # TS workspace root
│
├── spec/                            # The specification itself
│   ├── hushspec-core.md             # Core spec document (normative)
│   ├── hushspec-posture.md          # Extension: posture state machines
│   ├── hushspec-origins.md          # Extension: origin-aware profiles
│   ├── hushspec-detection.md        # Extension: detection thresholds
│   ├── versioning.md                # Spec versioning policy
│   └── changelog.md
│
├── schemas/                         # JSON Schema (machine-readable)
│   ├── hushspec-core.v0.schema.json
│   ├── hushspec-posture.v0.schema.json
│   ├── hushspec-origins.v0.schema.json
│   └── hushspec-detection.v0.schema.json
│
├── rulesets/                        # Reference rulesets (valid HushSpec YAML)
│   ├── default.yaml
│   ├── strict.yaml
│   ├── permissive.yaml
│   ├── ai-agent.yaml
│   ├── cicd.yaml
│   └── remote-desktop.yaml
│
├── fixtures/                        # Test vectors for conformance
│   ├── core/
│   │   ├── valid/                   # Valid HushSpec docs
│   │   ├── invalid/                 # Must-reject docs
│   │   └── merge/                   # Inheritance/merge test pairs
│   ├── posture/
│   ├── origins/
│   └── detection/
│
├── crates/                          # Rust reference implementation
│   ├── hushspec/                    # Core types + validation (no_std compatible)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── schema.rs            # HushSpec struct definitions
│   │       ├── rules.rs             # Per-rule config types
│   │       ├── merge.rs             # Merge/inheritance semantics
│   │       ├── validate.rs          # Schema validation
│   │       └── version.rs           # Version negotiation
│   └── hushspec-testkit/            # Conformance test runner
│       ├── Cargo.toml
│       └── src/
│
├── packages/                        # TS/JS reference implementation
│   └── hushspec/
│       ├── package.json             # @hushspec/core
│       ├── src/
│       │   ├── index.ts
│       │   ├── schema.ts            # TypeScript types
│       │   ├── validate.ts          # Validation
│       │   └── merge.ts             # Merge semantics
│       └── tests/
│
├── bindings/                        # Language bindings (future)
│   ├── python/
│   └── go/
│
└── docs/                            # Spec documentation site (mdBook)
    ├── book.toml
    └── src/
        ├── SUMMARY.md
        ├── introduction.md
        ├── core-spec.md
        ├── extensions/
        └── conformance.md
```

### 6.1 Package Names

| Package | Registry | Name |
|---------|----------|------|
| Rust crate | crates.io | `hushspec` |
| Rust test crate | crates.io | `hushspec-testkit` |
| TypeScript | npm | `@hushspec/core` |
| Python | PyPI | `hushspec` |
| Go | Go modules | `github.com/<org>/hush/bindings/go` |

---

## 7. Compatibility and Migration Strategy

### 7.1 Compiler Layer in Clawdstrike

Clawdstrike gains a new module: `crates/libs/clawdstrike/src/hushspec_compiler.rs`

```
HushSpec YAML ──parse──▶ hushspec::HushSpec ──compile──▶ clawdstrike::Policy
```

The compiler:
1. Parses HushSpec YAML into `hushspec::HushSpec` (from the `hushspec` crate dependency)
2. Maps `rules.*` fields to `GuardConfigs` fields
3. Maps extensions (posture, origins, detection) to their Clawdstrike counterparts
4. Injects engine defaults for fields not present in HushSpec (e.g., `settings`, async config)
5. Returns a fully-formed `clawdstrike::Policy` that the engine processes as before

### 7.2 Dual-Format Support

The engine detects format by checking for `hushspec:` (HushSpec) vs `version:` (legacy Clawdstrike) at the top level.

```rust
pub fn load_policy(yaml: &str) -> Result<Policy> {
    if is_hushspec(yaml) {
        let spec = hushspec::parse(yaml)?;
        compile_hushspec_to_policy(spec)
    } else {
        parse_clawdstrike_policy(yaml)
    }
}
```

### 7.3 Backward Compatibility Guarantees

- **Existing Clawdstrike policies remain valid indefinitely.** No deprecation in v0/v1.
- **HushSpec is additive.** Users can adopt it incrementally.
- **`extends` across formats**: A HushSpec doc can `extends: clawdstrike:strict` and vice versa (via the compiler).
- **CLI commands**: `hush policy validate` accepts both formats. `hush policy migrate --to hushspec` converts legacy → HushSpec.

### 7.4 Field Mapping Table

| Current Clawdstrike Field | HushSpec Core Field | Migration Notes |
|---------------------------|--------------------|-----------------|
| `version: "1.5.0"` | `hushspec: "0.1.0"` | New version namespace |
| `name` | `name` | Direct mapping |
| `description` | `description` | Direct mapping |
| `extends` | `extends` | Prefix changes: `clawdstrike:X` → `hushspec:X` for reference rulesets |
| `merge_strategy` | `merge_strategy` | Same enum values |
| `guards.forbidden_path` | `rules.forbidden_paths` | Rename `patterns` stays, add/remove helpers become engine concern |
| `guards.path_allowlist` | `rules.path_allowlist` | Rename `file_access_allow` → `read`, `file_write_allow` → `write` |
| `guards.egress_allowlist` | `rules.egress` | Rename `default_action` → `default` |
| `guards.secret_leak` | `rules.secret_patterns` | Drop `redact` (engine concern), keep patterns |
| `guards.patch_integrity` | `rules.patch_integrity` | Direct mapping |
| `guards.shell_command` | `rules.shell_commands` | Direct mapping |
| `guards.mcp_tool` | `rules.tool_access` | Rename for neutrality |
| `guards.computer_use` | `rules.computer_use` | Direct mapping |
| `guards.remote_desktop_side_channel` | `rules.remote_desktop_channels` | Flatten `*_enabled` → boolean keys |
| `guards.input_injection_capability` | `rules.input_injection` | Rename `allowed_input_types` → `allowed_types` |
| `guards.prompt_injection` | Extension: `detection.prompt_injection` | Not in core |
| `guards.jailbreak` | Extension: `detection.jailbreak` | Not in core |
| `guards.spider_sense` | Extension: `detection.spider_sense` | Not in core |
| `posture` | Extension: `posture` | Not in core |
| `origins` | Extension: `origins` | Not in core |
| `broker` | **Stays engine-only** | No HushSpec equivalent |
| `custom_guards` | **Stays engine-only** | Plugin system is engine-specific |
| `settings` | **Stays engine-only** | Runtime behavior |
| `guards.*.additional_*` | **Stays engine-only** | Merge helpers are compiler concern |
| `guards.*.remove_*` | **Stays engine-only** | Merge helpers are compiler concern |

### 7.5 Core vs Extension vs Engine Profile

| Schema Area | Layer | Rationale |
|-------------|-------|-----------|
| Forbidden paths | **Core** | Universal filesystem safety |
| Path allowlist | **Core** | Universal filesystem scoping |
| Egress control | **Core** | Universal network policy |
| Secret patterns | **Core** | Universal secret detection |
| Patch integrity | **Core** | Universal diff safety |
| Shell commands | **Core** | Universal command safety |
| Tool access (MCP) | **Core** | Universal tool boundary |
| Computer use | **Core** | CUA is becoming standard |
| Remote desktop channels | **Core** | Side-channel control is portable |
| Input injection | **Core** | Input type control is portable |
| Posture state machines | **Extension** | Stateful automation, not all engines support it |
| Origin profiles | **Extension** | Origin-aware projection, advanced feature |
| Detection thresholds | **Extension** | Requires detection backend |
| Merge helpers (additional_*, remove_*) | **Engine** | Implementation of extends resolution |
| Async guard config | **Engine** | Runtime infrastructure |
| Broker config | **Engine** | Credential infrastructure |
| Custom guard plugins | **Engine** | Plugin registry |
| Settings | **Engine** | Runtime behavior |
| Receipt format | **Engine** | Cryptographic protocol |

---

## 8. Test and Conformance Strategy

### 8.1 Conformance Levels

| Level | Name | Requirements |
|-------|------|-------------|
| Level 0 | **Parser** | Can parse valid HushSpec YAML, reject invalid |
| Level 1 | **Validator** | Validates all field types, versions, constraints |
| Level 2 | **Merger** | Correctly implements extends + merge strategies |
| Level 3 | **Evaluator** | Produces correct allow/warn/deny decisions for test vectors |

### 8.2 Test Vector Format

```yaml
# fixtures/core/valid/egress-basic.test.yaml
hushspec_test: "0.1.0"
description: "Basic egress allow/deny"
policy:
  hushspec: "0.1.0"
  rules:
    egress:
      enabled: true
      allow: ["api.openai.com"]
      default: block
cases:
  - description: "Allowed domain passes"
    action: { type: egress, target: "api.openai.com" }
    expect: allow
  - description: "Unlisted domain blocked"
    action: { type: egress, target: "evil.com" }
    expect: deny
```

### 8.3 Migration from Existing Tests

| Current Test | Target |
|-------------|--------|
| `rulesets/tests/policy-torture/01-deep-merge.policy-test.yaml` | `fixtures/core/merge/deep-merge.test.yaml` |
| `rulesets/tests/policy-torture/02-replace.policy-test.yaml` | `fixtures/core/merge/replace.test.yaml` |
| `rulesets/tests/policy-torture/04-guard-gauntlet.policy-test.yaml` | Split into per-rule fixture files |
| `rulesets/tests/policy-torture/03-posture-escalation.policy-test.yaml` | `fixtures/posture/escalation.test.yaml` |
| `crates/libs/clawdstrike/tests/policy_extends.rs` | Rust conformance tests in `hushspec-testkit` |

### 8.4 Conformance Runner

`hushspec-testkit` provides a `run_conformance(engine: &dyn HushSpecEngine, fixtures_dir: &Path)` function. Any engine (Clawdstrike, third-party) can plug in and validate conformance.

---

## 9. Phase-by-Phase Execution Plan

### Phase 0: Analysis and Boundary Freeze (Week 1)

**Goal:** Lock down the exact schema boundary. No code changes except this plan.

- [ ] Review this plan with stakeholders
- [ ] Finalize the core vs. extension vs. engine split (the table in §7.5)
- [ ] Decide on field renaming (§7.4) — accept or modify the proposed names
- [ ] Decide on `hushspec:` version numbering (proposed: start at `0.1.0`, independent of Clawdstrike)
- [ ] Decide on license (proposed: Apache-2.0)
- [ ] Decide on org/namespace (proposed: `hushspec` on crates.io/npm, `hush` repo name)

**Deliverable:** Approved plan document with locked schema decisions.

### Phase 1: Create `../hush` Repo Skeleton (Week 2)

**Goal:** Standing repo with spec docs, JSON Schema, and empty reference implementations.

- [ ] `git init ../hush` with standard boilerplate (LICENSE, README, CLAUDE.md, .gitignore)
- [ ] Write `spec/hushspec-core.md` — normative spec for core rules
- [ ] Write `schemas/hushspec-core.v0.schema.json` — JSON Schema for validation
- [ ] Create `crates/hushspec/` with `HushSpec` struct, `Rules` struct, per-rule config types
- [ ] Create `packages/hushspec/` with TypeScript types mirroring Rust
- [ ] Create `rulesets/` with `default.yaml`, `strict.yaml`, `permissive.yaml` (adapted from Clawdstrike)
- [ ] Create `fixtures/core/valid/` and `fixtures/core/invalid/` with initial test vectors
- [ ] Set up CI (cargo test, cargo clippy, cargo fmt, npm test)
- [ ] Tag `v0.1.0-alpha.1`

**Deliverable:** `../hush` repo with compilable crates and passing CI.

### Phase 2: Move or Copy Spec Material (Weeks 3–4)

**Goal:** Populate HushSpec with real content extracted from Clawdstrike.

- [ ] Extract guard config types from `policy.rs` → `hushspec/src/rules.rs`
  - Strip `additional_*`/`remove_*` merge helpers (engine concern)
  - Strip `redact` from secret leak (engine concern)
  - Apply field renames per §7.4
- [ ] Extract merge semantics from `policy.rs` → `hushspec/src/merge.rs`
  - Core merge only (deep_merge, replace, merge)
  - No remote URL resolution, no integrity pinning
- [ ] Write `hushspec/src/validate.rs` — pure schema validation (no filesystem, no network)
- [ ] Port 6 rulesets to HushSpec format → `rulesets/`
- [ ] Create conformance fixtures from Clawdstrike torture tests
- [ ] Write `spec/hushspec-posture.md` and `schemas/hushspec-posture.v0.schema.json`
- [ ] Write `spec/hushspec-origins.md` and `schemas/hushspec-origins.v0.schema.json`
- [ ] Write `spec/hushspec-detection.md` and `schemas/hushspec-detection.v0.schema.json`
- [ ] Mirror types in TypeScript package
- [ ] Run conformance tests against both Rust and TS implementations
- [ ] Tag `v0.1.0-alpha.2`

**Deliverable:** Complete spec + reference types + test vectors for core and all three extensions.

### Phase 3: Add Compiler/Adapter in Clawdstrike (Weeks 4–5)

**Goal:** Clawdstrike can load HushSpec documents natively.

- [ ] Add `hushspec` crate as dependency to `clawdstrike` Cargo.toml (path or git dep initially)
- [ ] Implement `crates/libs/clawdstrike/src/hushspec_compiler.rs`:
  - `compile(spec: &hushspec::HushSpec) -> Result<Policy>`
  - Map `rules.*` → `GuardConfigs` fields
  - Map extensions → posture/origins/detection configs
  - Inject engine defaults for missing engine-only fields
- [ ] Update `policy.rs` loader to detect `hushspec:` prefix and route through compiler
- [ ] Update CLI `hush policy validate` to accept HushSpec format
- [ ] Add `hush policy migrate --to hushspec` command (Clawdstrike → HushSpec converter)
- [ ] Add `hush policy migrate --to clawdstrike` command (HushSpec → Clawdstrike converter)
- [ ] Integration tests: load HushSpec YAML → compile → evaluate → same decisions as equivalent Clawdstrike policy
- [ ] Update TS policy engine to accept HushSpec format (import `@hushspec/core` types)

**Deliverable:** Clawdstrike release that can load both formats, with `migrate` commands.

### Phase 4: Migrate Built-in Rulesets and Docs (Weeks 5–6)

**Goal:** Official rulesets available in both formats; docs updated.

- [ ] Add HushSpec-format copies of all 6 portable rulesets to `../hush/rulesets/`
- [ ] Keep Clawdstrike-format originals in `clawdstrike/rulesets/` (not removed)
- [ ] Update `clawdstrike/rulesets/` to include a comment header: `# Clawdstrike-native format. See also: HushSpec equivalent at github.com/<org>/hush/rulesets/`
- [ ] Update Clawdstrike docs to reference HushSpec for the portable policy language
- [ ] Write migration guide: "Adopting HushSpec in your project"
- [ ] Update SDK README files to show both HushSpec and Clawdstrike-native examples

**Deliverable:** Dual-format documentation, reference rulesets in both repos.

### Phase 5: Stabilize and Deprecate (Weeks 7–8)

**Goal:** HushSpec v0.1.0 tagged; Clawdstrike encourages HushSpec for new users.

- [ ] Run full conformance suite against Clawdstrike compiler
- [ ] Run full conformance suite against TS reference implementation
- [ ] Tag `hush v0.1.0`
- [ ] Publish `hushspec` to crates.io
- [ ] Publish `@hushspec/core` to npm
- [ ] Update Clawdstrike docs: "For new projects, we recommend writing policies in HushSpec format"
- [ ] **Do not** deprecate Clawdstrike-native format — it remains supported indefinitely
- [ ] Blog post / announcement

**Deliverable:** Stable HushSpec v0.1.0, published packages, Clawdstrike with compiler.

---

## 10. Risks / Open Questions / Recommended Decisions

### 10.1 Risks

| Risk | Impact | Mitigation |
|------|--------|-----------|
| **SDK version divergence** — TS/Python are at schema 1.3.0, Rust at 1.5.0 | HushSpec adoption blocked in TS/Python until they catch up | HushSpec v0.1.0 targets only features available in 1.2.0 (core guards + posture); origins/broker are extensions |
| **Schema confusion** — users unsure which format to use | Support burden, docs sprawl | Clear recommendation: HushSpec for new, Clawdstrike-native for existing. Single `validate` command handles both. |
| **Merge helper loss** — `additional_*`/`remove_*` fields don't exist in HushSpec | Users who rely on fine-grained inheritance lose expressiveness | Compiler synthesizes these from HushSpec extends chain. Document the semantic difference. |
| **Duplicated validation** — same rules validated in two crates | Drift risk | `hushspec` crate is the source of truth for spec validation. Clawdstrike delegates spec-level validation to it. |
| **Field rename churn** — renaming `mcp_tool` → `tool_access` etc. | User confusion | Compiler accepts both old and new names. Old names are aliases. |
| **Premature standardization** — locking spec before feature set is stable | Spec debt | v0.x explicitly unstable. Semver: breaking changes allowed before v1.0. |

### 10.2 Open Questions

1. **Should `extends` resolution be spec-level or engine-level?**
   - **Recommendation:** Spec defines the `extends` field and merge semantics. Engine implements resolution (fetching remote refs, resolving builtins). The spec says "an extends reference is an opaque string resolved by the engine." This keeps the spec portable while allowing engines to support different resolution strategies.

2. **Should merge helpers (`additional_patterns`, `remove_patterns`) exist in HushSpec?**
   - **Recommendation:** No. HushSpec uses simple override semantics. If you extend a policy and provide `rules.forbidden_paths.patterns`, your patterns fully replace the base. This is simpler and more predictable. Engines that want additive merge can offer it as an engine-level feature on top.

3. **Should HushSpec mandate `deny_unknown_fields`?**
   - **Recommendation:** Yes. Conformant parsers MUST reject unknown fields. This prevents silent misconfiguration and is consistent with Clawdstrike's fail-closed philosophy.

4. **Should detection thresholds be in core or extension?**
   - **Recommendation:** Extension. Detection requires backend infrastructure. A HushSpec document saying `prompt_injection.block_at: high` is meaningless without a detector.

5. **Where does the `action_type` taxonomy live?**
   - **Recommendation:** HushSpec core defines a standard action type enum: `file_read`, `file_write`, `egress`, `shell_command`, `tool_call`, `patch_apply`, `computer_use`, `custom`. Engines can extend this with custom action types.

### 10.3 Recommended Decisions

| Decision | Recommendation | Rationale |
|----------|---------------|-----------|
| Spec versioning | `0.x.y` semver, independent of Clawdstrike | Decouple cadences; v0 signals instability |
| License | Apache-2.0 | Standard for open specs; compatible with Clawdstrike |
| Repo name | `hush` | Short, matches existing `hush-*` naming |
| Crate name | `hushspec` | Clear, available on crates.io |
| npm package | `@hushspec/core` | Scoped, unambiguous |
| Top-level key | `hushspec: "0.1.0"` | Distinguishes from `version: "1.5.0"` |
| Rules key | `rules` (not `guards`) | Engine-neutral language |
| Merge helpers | Not in spec (engine feature) | Simplicity; avoid spec bloat |
| Unknown fields | Reject (fail-closed) | Consistency with Clawdstrike |
| `no_std` support | Yes for Rust crate | Enables WASM and embedded use |

---

## 11. Non-Goals

- **HushSpec is not a runtime.** It does not define how to evaluate rules, only what rules to evaluate. Evaluation semantics (guard order, short-circuit, async) are engine concerns.
- **HushSpec is not a receipt format.** Cryptographic attestation of decisions is engine-specific.
- **HushSpec does not replace Clawdstrike policy format.** Both formats coexist indefinitely.
- **HushSpec does not define detection algorithms.** Prompt injection scoring, jailbreak detection layers, and embedding search are engine implementations.
- **HushSpec does not define a transport protocol.** How policies are fetched, cached, or distributed is engine-specific.
- **HushSpec does not define a plugin system.** Custom guards are engine-specific.
- **HushSpec v0 does not aim for formal standardization.** It's an open spec, not an RFC/IETF submission.

---

## 12. Recommended MVP Schema Sketch — HushSpec v0.1.0

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://hushspec.dev/schemas/hushspec-core.v0.schema.json",
  "title": "HushSpec Core v0",
  "type": "object",
  "required": ["hushspec"],
  "additionalProperties": false,
  "properties": {
    "hushspec": {
      "type": "string",
      "pattern": "^0\\."
    },
    "name": { "type": "string" },
    "description": { "type": "string" },
    "extends": { "type": "string" },
    "merge_strategy": {
      "type": "string",
      "enum": ["replace", "merge", "deep_merge"],
      "default": "deep_merge"
    },
    "rules": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "forbidden_paths": { "$ref": "#/$defs/ForbiddenPathsRule" },
        "path_allowlist": { "$ref": "#/$defs/PathAllowlistRule" },
        "egress": { "$ref": "#/$defs/EgressRule" },
        "secret_patterns": { "$ref": "#/$defs/SecretPatternsRule" },
        "patch_integrity": { "$ref": "#/$defs/PatchIntegrityRule" },
        "shell_commands": { "$ref": "#/$defs/ShellCommandsRule" },
        "tool_access": { "$ref": "#/$defs/ToolAccessRule" },
        "computer_use": { "$ref": "#/$defs/ComputerUseRule" },
        "remote_desktop_channels": { "$ref": "#/$defs/RemoteDesktopChannelsRule" },
        "input_injection": { "$ref": "#/$defs/InputInjectionRule" }
      }
    },
    "extensions": {
      "type": "object",
      "description": "Optional extension modules (posture, origins, detection)"
    }
  },
  "$defs": {
    "ForbiddenPathsRule": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "enabled": { "type": "boolean" },
        "patterns": { "type": "array", "items": { "type": "string" } },
        "exceptions": { "type": "array", "items": { "type": "string" } }
      }
    },
    "EgressRule": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "enabled": { "type": "boolean" },
        "allow": { "type": "array", "items": { "type": "string" } },
        "block": { "type": "array", "items": { "type": "string" } },
        "default": { "type": "string", "enum": ["allow", "block"] }
      }
    },
    "ToolAccessRule": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "enabled": { "type": "boolean" },
        "allow": { "type": "array", "items": { "type": "string" } },
        "block": { "type": "array", "items": { "type": "string" } },
        "require_confirmation": { "type": "array", "items": { "type": "string" } },
        "default": { "type": "string", "enum": ["allow", "block"] },
        "max_args_size": { "type": "integer" }
      }
    }
  }
}
```

*(Full schema omitted for brevity — the JSON Schema above shows the pattern; all 10 rule types follow the same structure.)*

---

## 13. Versioning Strategy

### HushSpec Versioning

| Version | Stability | Breaking Changes |
|---------|-----------|-----------------|
| `0.x.y` | Unstable | Allowed between minor versions |
| `1.0.0` | Stable | Only in major versions |

- HushSpec versions are independent of Clawdstrike versions
- Spec version appears in `hushspec:` field
- Extension versions tracked separately (e.g., `extensions.posture.version: "0.1.0"`)

### Clawdstrike Compatibility Mapping

| HushSpec Version | Minimum Clawdstrike Version | Notes |
|-----------------|---------------------------|-------|
| 0.1.0 | 0.2.x (next release) | Initial compiler support |
| 0.2.0 | 0.3.x | Posture + Origins extensions |
| 1.0.0 | 1.0.x | Stable spec = stable engine |

Clawdstrike policy schema versions (1.1.0–1.5.0) continue independently. The compiler bridges both.

---

## 14. First PR Checklist for Clawdstrike

**PR title:** `feat(policy): add HushSpec compiler and dual-format loading`

- [ ] Add `hushspec` as a path dependency in `Cargo.toml` (initially `path = "../../hush/crates/hushspec"`)
- [ ] Create `crates/libs/clawdstrike/src/hushspec_compiler.rs`:
  - `pub fn compile(spec: &hushspec::HushSpec) -> Result<Policy, CompileError>`
  - `pub fn decompile(policy: &Policy) -> Result<hushspec::HushSpec, DecompileError>`
  - Unit tests for each rule mapping
- [ ] Update `policy.rs`:
  - `pub fn is_hushspec(yaml: &str) -> bool` (checks for `hushspec:` key)
  - Update `load_policy_from_str()` to route through compiler for HushSpec docs
- [ ] Update CLI:
  - `hush policy validate` accepts HushSpec format
  - `hush policy migrate --to hushspec <input>` — converts Clawdstrike → HushSpec
  - `hush policy migrate --to clawdstrike <input>` — converts HushSpec → Clawdstrike
- [ ] Add integration tests:
  - Load each reference HushSpec ruleset → compile → evaluate known actions → assert same decisions as equivalent Clawdstrike ruleset
- [ ] Update docs: add "HushSpec Compatibility" section to policy-schema.md
- [ ] Do NOT change any existing policy loading, validation, or guard behavior

---

## 15. First PR Checklist for `../hush`

**PR title:** `feat: initial HushSpec v0.1.0-alpha.1 with core spec, schema, and reference types`

- [ ] Repo boilerplate: LICENSE (Apache-2.0), README.md, CLAUDE.md, .gitignore, .github/workflows/ci.yml
- [ ] `spec/hushspec-core.md` — normative spec document covering:
  - Top-level fields (`hushspec`, `name`, `description`, `extends`, `merge_strategy`, `rules`)
  - All 10 core rule definitions with field types and semantics
  - Action type taxonomy
  - Merge semantics (deep_merge, replace, merge)
  - Validation requirements (deny_unknown_fields, version checking)
  - Conformance levels (parser, validator, merger, evaluator)
- [ ] `schemas/hushspec-core.v0.schema.json` — JSON Schema for core
- [ ] `crates/hushspec/` — Rust crate:
  - `HushSpec` struct with all core types
  - `validate()` function
  - `merge()` function
  - `parse()` function (YAML → HushSpec)
  - `#![no_std]` compatible (with `alloc`)
  - Unit tests for parsing, validation, merge
- [ ] `packages/hushspec/` — TypeScript package:
  - Matching types
  - `validate()` and `parse()` functions
  - Unit tests
- [ ] `rulesets/default.yaml`, `strict.yaml`, `permissive.yaml` — reference rulesets in HushSpec format
- [ ] `fixtures/core/valid/` — 10+ valid HushSpec documents
- [ ] `fixtures/core/invalid/` — 10+ documents that must be rejected (unknown fields, bad types, invalid versions)
- [ ] `fixtures/core/merge/` — inheritance test pairs with expected merged output
- [ ] CI: cargo test + cargo clippy + cargo fmt + npm test
- [ ] Tag `v0.1.0-alpha.1`
