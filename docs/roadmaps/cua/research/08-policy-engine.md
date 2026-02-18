# 08 Policy Engine & Enforcement

## Scope

Policy language and enforcement workflow for CUA actions, including approvals, redaction, and fail-closed behavior.

## What is already solid

- "Observe -> Guardrail -> Fail-closed" progression is the right rollout pattern.
- Emphasis on deterministic denial reasons and pre-action checks aligns with production safety needs.
- Framing policy as the control boundary (not model trust) is correct.

## Corrections and caveats (2026-02-18)

- Avoid creating a parallel CUA policy universe too early; map into existing guard semantics first.
- Approval workflows must bind to immutable evidence digests to avoid TOCTOU approvals.
- Policy must explicitly cover remote-desktop side channels (clipboard, transfer, session-share), not only click/type actions.

## Clawdstrike-specific integration suggestions

- Extend canonical `PolicyEvent` shape with CUA action metadata instead of inventing an incompatible pipeline.
- Reuse existing guard evaluation and severity aggregation semantics for CUA where possible.
- Add a dedicated CUA guard for UI-specific invariants: target ambiguity, frame-hash preconditions, redaction completeness.

## Gaps for agent team to fill

- Policy grammar proposal with examples for browser and full desktop modes.
- Enforcement proofs: exact point where a decision is checked relative to side effect execution.
- Unit/integration test plan for denies, constrained allows, approval-required actions, and evidence failures.

## Suggested experiments

- Build a minimal adapter converting `computer.use` to canonical policy events and evaluate with existing engine.
- Add regression tests for policy ambiguity handling and fail-closed defaults.
- Simulate adversarial prompts attempting tool bypass and verify guard coverage.

## Repo anchors

- `docs/src/concepts/enforcement-tiers.md`
- `docs/src/reference/guards/README.md`
- `packages/policy/clawdstrike-policy/src/policy/validator.ts`

## Primary references

- https://www.w3.org/TR/webdriver2/
- https://w3c.github.io/webdriver-bidi/
- https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.RemoteDesktop.html

## Pass #3 reviewer notes (2026-02-18)

- REVIEW-P3-CORRECTION: Code/version excerpts in this document should be treated as snapshot claims; bind them to commit hashes in implementation planning.
- REVIEW-P3-GAP-FILL: Add a normative mapping table from each `computer.use` action to existing `GuardAction`/`PolicyEvent` forms and expected guard coverage.
- REVIEW-P3-CORRECTION: Approval flow security depends on evidence-binding and expiry semantics; "approved" without digest/TTL binding is insufficient.

## Pass #3 execution criteria

- Every CUA action path resolves to a deterministic policy evaluation stage and guard result set.
- Approval tokens bind to immutable evidence digest, policy hash, action intent, and expiry window.
- Unknown action types, unknown fields, or missing policy context fail closed with stable error codes.
- Policy evaluation output is reproducible across Rust/TS integration boundaries for the same canonical input.

## Pass #11 reviewer notes (2026-02-18)

- REVIEW-P11-CORRECTION: Provider ecosystems (OpenAI/Claude/OpenClaw/third-party runtimes) must integrate as adapter translators into canonical `PolicyEvent` semantics, not as independent policy contracts.
- REVIEW-P11-GAP-FILL: Add adapter conformance fixtures proving equivalent computer-use intents produce equivalent canonical policy events and decision classes across providers.
- REVIEW-P11-CORRECTION: Unknown provider action variants must fail closed with deterministic adapter error families before guard evaluation proceeds.

## Pass #11 integration TODO block

- [x] Define canonical CUA event/outcome adapter contract in `packages/adapters/clawdstrike-adapter-core/src/`. *(Pass #13 — E1)*
- [x] Add OpenAI and Claude CUA translator layers that normalize provider payloads into canonical events. *(Pass #15 — runtime translators; Pass #17 — parity hardening)*
- [x] Align `@clawdstrike/openclaw` hook path to emit canonical CUA events where supported. *(Pass #14 — E3; Pass #15 — runtime enforcement closure)*
- [x] Add cross-provider conformance fixtures and fail-closed drift tests. *(Pass #13 baseline; Pass #17 full canonical flow surface)*
- [x] Track external runtime connector evaluation (`trycua/cua`) against canonical contract constraints (`./09-ecosystem-integrations.md`). *(Pass #14 — E4)*

---

# Deep Research: Policy Engine & Enforcement Mechanics

> Comprehensive analysis of the Clawdstrike policy engine, CUA-specific policy extensions, enforcement workflows, approval hooks, rate limiting, response modes, TOCTOU prevention, and comparisons with OPA/Rego, Cedar, Casbin, and Sentinel.

---

## 1. Existing Clawdstrike Policy System

### 1.1 Policy Schema (v1.1.0 / v1.2.0)

The existing policy system is defined in `crates/libs/clawdstrike/src/policy.rs`. Policies are YAML documents with a strict schema version boundary:

```rust
// policy.rs:22-24
pub const POLICY_SCHEMA_VERSION: &str = "1.2.0";
pub const POLICY_SUPPORTED_SCHEMA_VERSIONS: &[&str] = &["1.1.0", "1.2.0"];
const MAX_POLICY_EXTENDS_DEPTH: usize = 32;
```

The `Policy` struct is the root configuration object:

```rust
pub struct Policy {
    pub version: String,           // Schema version (must be in supported set)
    pub name: String,
    pub description: String,
    pub extends: Option<String>,   // Base policy (ruleset name, file, URL, git ref)
    pub merge_strategy: MergeStrategy, // Replace | Merge | DeepMerge (default)
    pub guards: GuardConfigs,      // 9 built-in guard configurations
    pub custom_guards: Vec<PolicyCustomGuardSpec>,
    pub settings: PolicySettings,  // fail_fast, verbose_logging, session_timeout_secs
    pub posture: Option<PostureConfig>, // v1.2.0+: dynamic state machine
}
```

Key design decisions in the current system:

1. **Fail-closed on version mismatch**: If the policy version is not in `POLICY_SUPPORTED_SCHEMA_VERSIONS`, parsing returns `Error::UnsupportedPolicyVersion`. This is a security boundary.
2. **`deny_unknown_fields` everywhere**: Serde rejects unknown YAML keys, preventing policy drift or injection of unvalidated configuration.
3. **Validation at load time**: `Policy::validate()` runs regex compilation, glob validation, placeholder resolution, and structural checks. Invalid policies never reach the guard evaluation stage.

### 1.2 Guard Configuration (9 Built-in Guards)

The `GuardConfigs` struct holds optional configuration for each guard. The 9 guards are evaluated in a fixed order defined by `PolicyGuards::builtin_guards_in_order()`:

| Order | Guard                   | Config Field           | Action Types Handled |
|-------|-------------------------|------------------------|---------------------|
| 1     | `ForbiddenPathGuard`    | `forbidden_path`       | FileAccess, FileWrite |
| 2     | `PathAllowlistGuard`    | `path_allowlist`       | FileAccess, FileWrite, Patch (v1.2.0) |
| 3     | `EgressAllowlistGuard`  | `egress_allowlist`     | NetworkEgress |
| 4     | `SecretLeakGuard`       | `secret_leak`          | FileWrite, Patch |
| 5     | `PatchIntegrityGuard`   | `patch_integrity`      | Patch |
| 6     | `ShellCommandGuard`     | `shell_command`        | ShellCommand |
| 7     | `McpToolGuard`          | `mcp_tool`             | McpTool |
| 8     | `PromptInjectionGuard`  | `prompt_injection`     | Custom("untrusted_text") |
| 9     | `JailbreakGuard`        | `jailbreak`            | Custom("untrusted_text") |

Guards implement the `Guard` trait:

```rust
#[async_trait]
pub trait Guard: Send + Sync {
    fn name(&self) -> &str;
    fn handles(&self, action: &GuardAction<'_>) -> bool;
    async fn check(&self, action: &GuardAction<'_>, context: &GuardContext) -> GuardResult;
}
```

Actions are dispatched via the `GuardAction` enum:

```rust
pub enum GuardAction<'a> {
    FileAccess(&'a str),
    FileWrite(&'a str, &'a [u8]),
    NetworkEgress(&'a str, u16),
    ShellCommand(&'a str),
    McpTool(&'a str, &'a serde_json::Value),
    Patch(&'a str, &'a str),
    Custom(&'a str, &'a serde_json::Value),
}
```

The `Custom(&str, &Value)` variant is the extensibility point. The first argument is a type tag (e.g., `"untrusted_text"`), and the second is arbitrary JSON metadata. This variant is how CUA actions will be threaded through the existing guard pipeline.

### 1.3 Policy Inheritance (`extends`)

Policies support single-parent inheritance via the `extends` field. Resolution order:

1. Built-in rulesets (`"default"`, `"strict"`, `"ai-agent"`, etc.)
2. `"clawdstrike:"` prefixed names (strip prefix, look up built-in)
3. Local filesystem paths (relative to parent policy location)
4. Custom resolvers (for remote URLs, git refs)

The `PolicyResolver` trait abstracts resolution:

```rust
pub trait PolicyResolver {
    fn resolve(&self, reference: &str, from: &PolicyLocation) -> Result<ResolvedPolicySource>;
}
```

Cycle detection uses a `HashSet<String>` of canonical keys, with a hard depth limit of 32 levels.

Three merge strategies govern how child overrides base:

| Strategy | Behavior |
|----------|----------|
| `Replace` | Child fully replaces base |
| `Merge` | Child top-level fields override base, but non-default base fields survive |
| `DeepMerge` (default) | Recursive merge: guard configs merged per-field, settings use `child.or(base)` |

For guard configs, `DeepMerge` uses additive/subtractive patterns:
- `additional_patterns` / `additional_allow` / `additional_block` add to base lists
- `remove_patterns` / `remove_allow` / `remove_block` subtract from base lists
- Direct field assignment replaces

### 1.4 Posture Model (v1.2.0)

The posture system (`crates/libs/clawdstrike/src/posture.rs`) adds a state machine to policies:

```yaml
posture:
  initial: restricted
  states:
    restricted:
      capabilities: [file_access]
      budgets: {}
    standard:
      capabilities: [file_access, file_write, egress]
      budgets:
        file_writes: 50
        egress_calls: 20
    elevated:
      capabilities: [file_access, file_write, egress, mcp_tool, patch, shell]
      budgets:
        file_writes: 200
  transitions:
    - from: restricted
      to: standard
      on: user_approval
    - from: "*"
      to: restricted
      on: critical_violation
```

Known capabilities: `file_access`, `file_write`, `egress`, `shell`, `mcp_tool`, `patch`, `custom`.

Known budgets: `file_writes`, `egress_calls`, `shell_commands`, `mcp_tool_calls`, `patches`, `custom_calls`.

Transition triggers: `user_approval`, `user_denial`, `critical_violation`, `any_violation`, `timeout`, `budget_exhausted`, `pattern_match`.

### 1.5 Evaluation Flow (Engine)

The `HushEngine` (`crates/libs/clawdstrike/src/engine.rs`) orchestrates guard evaluation:

```
check_action_report(action, context)
  ├── Validate engine config (fail-closed on config errors)
  ├── Split guards into stages:
  │   ├── FastPath: ForbiddenPath, PathAllowlist, Egress, SecretLeak
  │   ├── StdPath: PatchIntegrity, ShellCommand, McpTool
  │   └── DeepPath: PromptInjection, Jailbreak
  ├── Evaluate FastPath guards (short-circuit on fail_fast + deny)
  ├── Evaluate StdPath guards + custom + extra guards
  ├── Evaluate async guards (VirusTotal, SafeBrowsing, Snyk)
  └── Aggregate: GuardReport { overall, per_guard[] }
```

The engine exposes typed convenience methods:
- `check_file_access(path, ctx)`
- `check_file_write(path, content, ctx)`
- `check_egress(host, port, ctx)`
- `check_shell(command, ctx)`
- `check_mcp_tool(tool, args, ctx)`
- `check_patch(path, diff, ctx)`
- `check_untrusted_text(source, text, ctx)` -- uses `Custom("untrusted_text", ...)`
- `check_action(action, ctx)` -- generic dispatch

### 1.6 Built-in Rulesets

Six rulesets ship in `rulesets/`:

| Ruleset | Key Characteristics |
|---------|-------------------|
| `default` | Balanced: SSH/AWS/env blocking, common egress, basic secret detection |
| `strict` | Maximum: no egress, fail_fast, 30-min timeout, PI + jailbreak guards |
| `ai-agent` | AI assistants: extended egress, relaxed patch limits, PI + jailbreak |
| `ai-agent-posture` | Extends `ai-agent` with restricted/standard/elevated state machine |
| `cicd` | CI/CD pipelines: specific egress for registries, no shell blocking |
| `permissive` | Development: all egress, relaxed limits, verbose logging |

---

## 2. CUA-Specific Policy Extensions

### 2.1 Design Principle: Map Into Existing Semantics First

Per the linter's correction: avoid creating a parallel CUA policy universe. The CUA gateway should map `computer.use` actions into the existing `GuardAction` enum and guard pipeline before introducing new guard types.

The mapping strategy:

| CUA Action | Primary Guard Mapping | Secondary Checks |
|------------|----------------------|-----------------|
| `navigate(url)` | `NetworkEgress(host, 443)` via `EgressAllowlistGuard` | URL allowlist (surface guard) |
| `click(x, y)` | `Custom("cua_click", {...})` via CUA guard | Surface allowlist, frame-hash precondition |
| `type(text)` | `Custom("cua_type", {...})` via CUA guard | Secret leak (for typed content), redaction |
| `screenshot()` | `Custom("cua_screenshot", {...})` via CUA guard | Redaction rules (before capture) |
| `scroll(dx, dy)` | `Custom("cua_scroll", {...})` via CUA guard | Rate limiting |
| `key(combo)` | `Custom("cua_key", {...})` via CUA guard | Forbidden key combos |
| `drag(...)` | `Custom("cua_drag", {...})` via CUA guard | Surface allowlist |
| `select(text)` / `copy()` | `Custom("cua_clipboard", {...})` via CUA guard | Data-flow control, redaction |
| `file_upload(path)` | `FileAccess(path)` + `Custom("cua_upload", {...})` | ForbiddenPath, data-flow |
| `file_download(url, path)` | `NetworkEgress(host, port)` + `FileWrite(path, content)` | Egress + secret leak |

### 2.2 CUA Guard Configuration (Proposed YAML)

A new `computer_use` section within `guards` extends the existing `GuardConfigs`:

```yaml
version: "1.3.0"
name: CUA Browser Policy
extends: ai-agent
description: Policy for browser-mode computer-use agent

guards:
  # Existing guards still apply (inherited from ai-agent)

  computer_use:
    enabled: true
    mode: guardrail  # observe | guardrail | fail_closed

    surfaces:
      browser:
        enabled: true
        url_allowlist:
          - "*.example.com"
          - "*.internal.corp"
        url_blocklist:
          - "*.darkweb.onion"
          - "chrome://settings/*"
          - "about:config"
        allowed_protocols:
          - https
          - http
        navigation_depth: 10  # max pages from start URL
      desktop:
        enabled: false
        app_allowlist: []
        app_blocklist: []
        window_title_patterns: []

    data_flow:
      upload:
        enabled: false
        max_file_size_bytes: 10485760  # 10MB
        allowed_extensions: [".csv", ".json", ".txt"]
        forbidden_paths:
          - "**/.ssh/**"
          - "**/.env*"
      download:
        enabled: true
        max_file_size_bytes: 52428800  # 50MB
        quarantine_path: "/tmp/cua-downloads"
      clipboard:
        read: true
        write: true
        max_content_bytes: 65536  # 64KB
        redact_before_paste: true

    redaction:
      always_redact:
        - pattern: "\\b\\d{3}-\\d{2}-\\d{4}\\b"  # SSN
          replacement: "[SSN-REDACTED]"
          label: ssn
        - pattern: "\\b\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}\\b"
          replacement: "[CARD-REDACTED]"
          label: credit_card
        - pattern: "(?i)password\\s*[:=]\\s*\\S+"
          replacement: "[PASSWORD-REDACTED]"
          label: password_field
      content_triggers:
        - selector: "input[type=password]"
          action: redact_region
        - selector: ".sensitive-data"
          action: redact_region
      timing: before_capture  # before_capture | post_capture

    approval:
      require_human_approval:
        - action: file_upload
          evidence_binding: true
        - action: navigate
          condition: "url_not_in_allowlist"
          evidence_binding: true
        - action: type
          condition: "target_is_password_field"
          evidence_binding: true
      timeout_seconds: 300
      timeout_action: deny  # deny | escalate | allow_with_flag
      max_pending: 5

    rate_limits:
      global:
        actions_per_minute: 120
        actions_per_hour: 3000
      per_action:
        click:
          max_per_minute: 60
          burst: 10
        type:
          max_per_minute: 30
          burst: 5
        navigate:
          max_per_minute: 20
          burst: 3
        screenshot:
          max_per_minute: 30
          burst: 10

    safety:
      max_session_duration_secs: 3600
      max_consecutive_errors: 10
      error_cooldown_secs: 30
      forbidden_key_combos:
        - "Ctrl+Alt+Delete"
        - "Ctrl+Shift+Esc"
        - "Alt+F4"  # conditionally: only on system windows
      forbidden_ui_targets:
        - window_class: "SecurityCenter"
        - window_class: "TaskManager"
        - aria_role: "dialog"
          aria_label_pattern: "(?i)admin|security|firewall"
```

### 2.3 Schema Version Bump

Adding `computer_use` to `GuardConfigs` requires a schema version bump to `1.3.0`. Following existing patterns:

```rust
pub const POLICY_SUPPORTED_SCHEMA_VERSIONS: &[&str] = &["1.1.0", "1.2.0", "1.3.0"];

fn policy_version_supports_cua(version: &str) -> bool {
    semver_at_least(version, (1, 3, 0))
}
```

Validation must reject `computer_use` config on v1.1.0 or v1.2.0 policies, exactly as `posture` is rejected on v1.1.0.

---

## 3. Surface Allowlists

### 3.1 Browser Surface

The browser surface restricts where the agent can navigate and interact:

**URL Allowlisting**: Glob-based matching reuses the existing `EgressAllowlistGuard` pattern (domain globs via `globset`). URLs are decomposed:

```
https://app.example.com:8443/dashboard?tab=settings#main
   │         │           │      │           │         │
scheme    domain       port   path        query    fragment
```

Matching stages:
1. **Protocol check**: Is `https` in `allowed_protocols`?
2. **Domain check**: Does `app.example.com` match any `url_allowlist` glob?
3. **Blocklist check**: Does the full URL match any `url_blocklist` glob? (blocklist wins over allowlist)
4. **Navigation depth**: Has the agent navigated more than `navigation_depth` pages from the start URL?

```rust
/// Browser surface policy evaluation
pub struct BrowserSurfaceGuard {
    url_allowlist: Vec<GlobMatcher>,
    url_blocklist: Vec<GlobMatcher>,
    allowed_protocols: HashSet<String>,
    navigation_depth: u32,
}

impl BrowserSurfaceGuard {
    pub fn check_navigation(&self, url: &Url, depth: u32) -> SurfaceDecision {
        // Protocol check
        if !self.allowed_protocols.contains(url.scheme()) {
            return SurfaceDecision::Deny(format!(
                "protocol '{}' not in allowed set", url.scheme()
            ));
        }

        // Blocklist (checked first -- blocklist wins)
        let url_str = url.as_str();
        for glob in &self.url_blocklist {
            if glob.is_match(url_str) {
                return SurfaceDecision::Deny(format!(
                    "URL matches blocklist pattern"
                ));
            }
        }

        // Allowlist
        let domain = url.host_str().unwrap_or("");
        let allowed = self.url_allowlist.iter().any(|g| g.is_match(domain));
        if !allowed {
            return SurfaceDecision::Deny(format!(
                "domain '{}' not in URL allowlist", domain
            ));
        }

        // Navigation depth
        if depth > self.navigation_depth {
            return SurfaceDecision::Deny(format!(
                "navigation depth {} exceeds limit {}", depth, self.navigation_depth
            ));
        }

        SurfaceDecision::Allow
    }
}
```

### 3.2 Desktop Surface

Desktop surface control is more complex because there is no URL-based addressing. Instead, identification relies on:

| Property | Source (Linux) | Source (Windows) | Source (macOS) |
|----------|---------------|-----------------|---------------|
| Window title | `_NET_WM_NAME` / Wayland `xdg_toplevel` | `GetWindowText` | `kCGWindowName` |
| App name / Process | `/proc/{pid}/exe` | `GetModuleFileName` | `NSRunningApplication` |
| Window class | `WM_CLASS` | `GetClassName` | Bundle ID |
| PID | `_NET_WM_PID` | `GetWindowThreadProcessId` | `kCGWindowOwnerPID` |

The desktop surface guard matches against:
- **`app_allowlist`**: Glob patterns on process name / bundle ID
- **`app_blocklist`**: Glob patterns that deny interaction regardless
- **`window_title_patterns`**: Regex patterns on window title
- **`forbidden_ui_targets`**: Structural matches (window class, ARIA role, accessibility labels)

```yaml
surfaces:
  desktop:
    enabled: true
    app_allowlist:
      - "com.microsoft.VSCode"
      - "org.mozilla.firefox"
      - "com.google.Chrome"
    app_blocklist:
      - "com.apple.systempreferences"
      - "com.microsoft.SecurityCenter"
    window_title_patterns:
      - "(?i)terminal|console"  # Allow terminals
    forbidden_ui_targets:
      - window_class: "CredentialDialog"
      - aria_role: "dialog"
        aria_label_pattern: "(?i)password|credential|admin"
```

### 3.3 Protocol Restrictions

For remote-desktop-mediated sessions, surfaces also include protocol-level controls:

```yaml
surfaces:
  remote_desktop:
    enabled: true
    protocol: rdp  # rdp | vnc | webrtc
    clipboard_redirect: false      # block clipboard via protocol
    drive_redirect: false          # block file transfer
    printer_redirect: false        # block printer access
    usb_redirect: false            # block USB passthrough
    audio_redirect: read_only      # allow audio out, block audio in
```

These protocol-level controls are enforced at the gateway's remote desktop proxy layer, not at the policy engine level. The policy engine declares intent; the transport layer enforces it.

---

## 4. Data-Flow Control

### 4.1 Upload Policy

File uploads are a high-risk CUA action. The policy controls:

1. **Enablement**: `upload.enabled: false` blocks all uploads (fail-closed default)
2. **Path restrictions**: Reuse `ForbiddenPathGuard` patterns -- `upload.forbidden_paths` is additive
3. **Extension allowlist**: Only permit specific file types
4. **Size limits**: `max_file_size_bytes` prevents exfiltration of large archives

Enforcement flow:

```
Agent requests: upload("/home/user/report.csv")
  ├── ForbiddenPathGuard.check(FileAccess("/home/user/report.csv"))
  │   └── Is path in forbidden patterns? (inherited from base policy)
  ├── CuaDataFlowGuard.check_upload(path, metadata)
  │   ├── Is upload enabled?
  │   ├── Is extension in allowed_extensions?
  │   ├── Is file_size <= max_file_size_bytes?
  │   └── Is path in upload.forbidden_paths?
  └── Aggregate: Allow | Deny | RequireApproval
```

### 4.2 Download Policy

Downloads are controlled similarly but with a quarantine stage:

```rust
pub struct DownloadPolicy {
    pub enabled: bool,
    pub max_file_size_bytes: u64,
    pub quarantine_path: PathBuf,
    pub scan_before_access: bool,  // run async guards (VirusTotal, etc.)
}
```

Downloaded files land in `quarantine_path` first. If `scan_before_access` is true, the async guard pipeline (VirusTotal, SafeBrowsing, Snyk) runs before the file is made available. This reuses the existing `AsyncGuardRuntime` infrastructure.

### 4.3 Clipboard Policy

Clipboard is a bidirectional data-flow channel that must be controlled in both directions:

| Direction | Risk | Control |
|-----------|------|---------|
| Read (copy from app) | Data exfiltration | `clipboard.read: true/false`, size limits |
| Write (paste to app) | Injection (paste malicious content) | `clipboard.write: true/false`, `redact_before_paste` |

When `redact_before_paste` is true, clipboard content passes through the redaction pipeline (Section 5) before being pasted. This prevents the agent from pasting sensitive data it obtained from one application into another.

### 4.4 Network Egress Integration

CUA navigation actions naturally map to network egress. The existing `EgressAllowlistGuard` handles domain-level control. The CUA layer adds:

- **URL-level granularity**: The egress guard checks domains; the CUA surface guard checks full URLs
- **Protocol restrictions**: The egress guard does not distinguish HTTP from HTTPS; the surface guard does
- **Request context**: CUA navigation includes referrer, method, and target frame -- this metadata flows into receipt evidence but does not affect the egress decision (to avoid fragile policies)

---

## 5. Redaction Rules

### 5.1 Pattern-Based Redaction

Redaction removes sensitive content from screenshots and captured evidence. Two timing modes:

**`before_capture` (recommended for production)**:
- Redaction runs before the screenshot is captured
- Uses DOM manipulation (inject CSS `filter: blur()` on sensitive elements) or overlay painting
- Captured frame never contains sensitive pixels
- Receipt evidence includes redaction manifest (what was redacted, which rule, element selector)

**`post_capture`**:
- Screenshot captured first, then pixel regions are blurred/masked
- Higher fidelity for non-sensitive areas
- Requires storing unredacted frame temporarily (even if briefly)
- Redaction manifest records the regions (x, y, w, h) and the rule

### 5.2 Redaction Rule Types

```yaml
redaction:
  always_redact:
    # Regex patterns applied to visible text content
    - pattern: "\\b\\d{3}-\\d{2}-\\d{4}\\b"
      replacement: "[SSN-REDACTED]"
      label: ssn
    - pattern: "(?i)sk-[a-z0-9]{48}"
      replacement: "[API-KEY-REDACTED]"
      label: api_key

  content_triggers:
    # DOM/accessibility selectors that trigger region redaction
    - selector: "input[type=password]"
      action: redact_region
      label: password_input
    - selector: "[data-sensitive=true]"
      action: redact_region
      label: app_marked_sensitive
    - aria_role: "textbox"
      aria_label_pattern: "(?i)ssn|social.security"
      action: redact_region
      label: aria_sensitive

  timing: before_capture
```

### 5.3 Redaction Provenance in Receipts

Per the 07 document's corrections, redaction metadata must include provenance to prove what was removed. The receipt includes:

```json
{
  "redactions": [
    {
      "rule_label": "ssn",
      "rule_hash": "sha256:abc123...",
      "target_selector": "#ssn-field",
      "region": {"x": 120, "y": 340, "w": 200, "h": 30},
      "content_hash_before": "sha256:def456...",
      "content_hash_after": "sha256:789abc...",
      "timing": "before_capture"
    }
  ]
}
```

The `rule_hash` is the SHA-256 of the canonical JSON serialization of the redaction rule, allowing verifiers to confirm which rule version was applied. The `content_hash_before` and `content_hash_after` allow verification that only the redacted regions changed.

---

## 6. Human Approval Hooks

### 6.1 Two-Person Rule

Certain CUA actions require human approval before execution. This implements a "two-person rule" where the agent proposes an action and a human approves or denies it.

Approval-required actions are declared in policy:

```yaml
approval:
  require_human_approval:
    - action: file_upload
      evidence_binding: true
    - action: navigate
      condition: "url_not_in_allowlist"
      evidence_binding: true
    - action: type
      condition: "target_is_password_field"
      evidence_binding: true
    - action: click
      condition: "target_matches_forbidden_ui"
      evidence_binding: true
```

### 6.2 Evidence-Bound Approval

Per the linter's correction, approval workflows must bind to immutable evidence digests to avoid TOCTOU attacks. When the agent requests approval:

```
1. Agent proposes: click(x=340, y=120)
2. Gateway captures pre-action state:
   - frame_hash: sha256(current_screenshot)
   - dom_hash: sha256(canonical_dom_snapshot)
   - url: "https://app.example.com/settings"
   - target_element: {tag: "button", text: "Delete Account", aria_role: "button"}
3. Gateway creates ApprovalRequest with evidence digest:
   - evidence_digest = sha256(frame_hash || dom_hash || url || target_element_hash)
4. Human reviews evidence and approves/denies
5. On approval, gateway verifies current state still matches evidence_digest
   - If state changed (different URL, different frame), approval is VOID
   - Agent must re-request approval with new evidence
6. If evidence matches, execute action
```

```rust
pub struct ApprovalRequest {
    pub request_id: String,
    pub session_id: String,
    pub action: CuaAction,
    pub evidence: ApprovalEvidence,
    pub evidence_digest: Hash,  // SHA-256 of canonical evidence
    pub requested_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

pub struct ApprovalEvidence {
    pub frame_hash: Hash,
    pub dom_hash: Option<Hash>,
    pub url: Option<String>,
    pub target_element: Option<ElementDescriptor>,
    pub accessibility_context: Option<A11ySnapshot>,
}

pub enum ApprovalDecision {
    Approved {
        approver_id: String,
        approved_at: DateTime<Utc>,
        evidence_digest: Hash,   // Must match request's evidence_digest
    },
    Denied {
        approver_id: String,
        denied_at: DateTime<Utc>,
        reason: String,
    },
    Expired,
}
```

### 6.3 Approval UI Patterns

The gateway exposes an approval API that frontends consume:

```
POST /api/v1/sessions/{session_id}/approvals
GET  /api/v1/sessions/{session_id}/approvals/{request_id}
POST /api/v1/sessions/{session_id}/approvals/{request_id}/decide
```

The approval UI must show:
- Screenshot of current state (with redactions applied)
- Description of proposed action ("Click 'Delete Account' button at (340, 120)")
- Accessibility context (what the target element is, its role, its label)
- Risk assessment (which policy rules triggered the approval requirement)
- Approve / Deny buttons with mandatory reason for denial

### 6.4 Timeout and Fallback

```yaml
approval:
  timeout_seconds: 300          # 5 minutes
  timeout_action: deny          # deny | escalate | allow_with_flag
  max_pending: 5                # max concurrent approval requests per session
```

| `timeout_action` | Behavior |
|------------------|----------|
| `deny` | Action is denied after timeout. Agent receives denial reason. Default. |
| `escalate` | Notification sent to escalation channel. Action remains blocked. |
| `allow_with_flag` | Action proceeds but receipt is flagged as "unreviewed". Auditable. |

---

## 7. Rate Limits & Safety

### 7.1 Token Bucket Algorithm

Rate limiting uses a token bucket model consistent with the existing `AsyncRateLimitPolicyConfig`:

```rust
pub struct TokenBucket {
    capacity: u32,         // Maximum burst
    tokens: AtomicU32,     // Current tokens
    refill_rate: f64,      // Tokens per second
    last_refill: AtomicU64, // Timestamp (nanos)
}

impl TokenBucket {
    pub fn try_consume(&self, count: u32) -> bool {
        self.refill();
        let current = self.tokens.load(Ordering::Acquire);
        if current >= count {
            self.tokens.fetch_sub(count, Ordering::Release);
            true
        } else {
            false
        }
    }
}
```

### 7.2 Hierarchical Rate Limits

CUA rate limits operate at three levels:

```
Session-level (global):
  └── actions_per_minute: 120, actions_per_hour: 3000
      │
      ├── Action-type level (per_action):
      │   ├── click:     max_per_minute: 60,  burst: 10
      │   ├── type:      max_per_minute: 30,  burst: 5
      │   ├── navigate:  max_per_minute: 20,  burst: 3
      │   └── screenshot: max_per_minute: 30, burst: 10
      │
      └── Target-level (optional, per surface):
          ├── Per-domain navigation limits
          └── Per-element interaction limits
```

When any level's budget is exhausted, the action is denied with a specific reason (`"rate_limit_exceeded:click:per_minute"`). The agent can use this information to back off.

### 7.3 Sliding Window for Hourly Limits

For longer time windows (per-hour), a sliding window is more appropriate than a fixed window to avoid burst-at-boundary attacks:

```rust
pub struct SlidingWindowCounter {
    window_size: Duration,    // e.g., 1 hour
    slots: Vec<AtomicU32>,    // Sub-windows (e.g., 60 one-minute slots)
    slot_duration: Duration,  // window_size / slots.len()
}

impl SlidingWindowCounter {
    pub fn count(&self) -> u32 {
        let now = Instant::now();
        let current_slot = self.slot_index(now);
        let partial = self.partial_weight(now);

        // Sum all slots except current, plus weighted current
        let mut total = 0u32;
        for i in 0..self.slots.len() {
            if i == current_slot {
                total += (self.slots[i].load(Ordering::Relaxed) as f64 * partial) as u32;
            } else {
                total += self.slots[i].load(Ordering::Relaxed);
            }
        }
        total
    }
}
```

### 7.4 Safety Invariants

Beyond rate limits, the safety section enforces session-level invariants:

| Safety Check | Purpose |
|-------------|---------|
| `max_session_duration_secs` | Hard session timeout -- prevents runaway agents |
| `max_consecutive_errors` | Circuit breaker -- too many failures trigger pause |
| `error_cooldown_secs` | After hitting error limit, wait before resuming |
| `forbidden_key_combos` | Block dangerous keyboard shortcuts |
| `forbidden_ui_targets` | Block interaction with security-sensitive UI elements |

```rust
pub struct SessionSafetyState {
    session_start: Instant,
    consecutive_errors: AtomicU32,
    last_error_at: Option<Instant>,
    total_actions: AtomicU64,
    cooldown_until: Option<Instant>,
}

impl SessionSafetyState {
    pub fn check_safety(&self, config: &SafetyConfig) -> SafetyDecision {
        // Session duration
        if self.session_start.elapsed() > Duration::from_secs(config.max_session_duration_secs) {
            return SafetyDecision::SessionExpired;
        }

        // Error cooldown
        if let Some(cooldown) = self.cooldown_until {
            if Instant::now() < cooldown {
                return SafetyDecision::InCooldown {
                    remaining: cooldown - Instant::now(),
                };
            }
        }

        // Consecutive error circuit breaker
        if self.consecutive_errors.load(Ordering::Relaxed) >= config.max_consecutive_errors {
            return SafetyDecision::CircuitOpen;
        }

        SafetyDecision::Ok
    }
}
```

---

## 8. Three Response Modes

### 8.1 Mode Definitions

The `mode` field on the `computer_use` guard controls how policy decisions affect execution:

| Mode | Behavior | Receipt Impact | Use Case |
|------|----------|----------------|----------|
| `observe` | Log decisions but never block actions | `verdict: allow` with `shadow_verdict` in metadata | Initial deployment, shadow testing |
| `guardrail` | Block high-risk actions, allow low/medium risk | Risk-scored verdicts | Production with graduated enforcement |
| `fail_closed` | Block any action not explicitly allowed | Default deny | High-security environments |

### 8.2 Observe Mode (Shadow)

In observe mode, every CUA action passes through the full guard pipeline, but denials are converted to allows with a `shadow_verdict` annotation:

```rust
pub fn apply_mode(result: GuardResult, mode: CuaMode) -> GuardResult {
    match mode {
        CuaMode::Observe => {
            if result.action == GuardDecision::Deny {
                GuardResult {
                    action: GuardDecision::Allow,
                    metadata: Some(json!({
                        "shadow_verdict": "deny",
                        "shadow_reasons": result.violations,
                        "mode": "observe"
                    })),
                    ..result
                }
            } else {
                result
            }
        }
        CuaMode::Guardrail => apply_risk_scoring(result),
        CuaMode::FailClosed => result, // No transformation
    }
}
```

Receipts in observe mode record both the actual and shadow verdicts, enabling operators to measure what would be blocked before enabling enforcement.

### 8.3 Guardrail Mode (Risk-Scored)

Guardrail mode introduces a risk scoring layer that maps guard violations to risk levels:

```rust
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    None = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

pub struct RiskScorer {
    thresholds: RiskThresholds,
}

pub struct RiskThresholds {
    pub block_at: RiskLevel,        // Default: High
    pub approve_at: RiskLevel,      // Default: Medium
    pub flag_at: RiskLevel,         // Default: Low
}
```

Risk scoring considers:
- **Violation severity**: Each guard violation has a severity (info, warning, error, critical)
- **Action type weight**: Some actions are inherently riskier (file_upload > click)
- **Surface context**: Actions on unknown/untrusted surfaces score higher
- **Session history**: Repeated similar violations increase risk
- **Posture state**: Actions in `restricted` posture score higher than in `elevated`

```rust
fn score_action(
    violations: &[Violation],
    action: &CuaAction,
    surface: &SurfaceContext,
    session: &SessionHistory,
    posture: &str,
) -> RiskLevel {
    let mut score = 0u32;

    // Violation severity
    for v in violations {
        score += match v.severity {
            Severity::Info => 0,
            Severity::Warning => 1,
            Severity::Error => 5,
            Severity::Critical => 20,
        };
    }

    // Action type weight
    score += match action.action_type() {
        "navigate" => 2,
        "click" => 1,
        "type" => 3,
        "file_upload" => 10,
        "file_download" => 5,
        _ => 1,
    };

    // Surface context
    if !surface.is_allowlisted {
        score += 5;
    }

    // Posture adjustment
    if posture == "restricted" {
        score *= 2;
    }

    match score {
        0 => RiskLevel::None,
        1..=3 => RiskLevel::Low,
        4..=10 => RiskLevel::Medium,
        11..=25 => RiskLevel::High,
        _ => RiskLevel::Critical,
    }
}
```

### 8.4 Fail-Closed Mode

In fail-closed mode, the policy engine requires explicit allowance for every action. The evaluation is:

1. If no guard handles the action type: **deny** (unknown action type)
2. If any guard denies: **deny** (with specific violation)
3. If all handling guards allow: **allow**
4. If guard errors: **deny** (fail-closed on guard errors)

This matches the existing Clawdstrike philosophy: "Fail-closed. Invalid policies reject at load time; errors during evaluation deny access."

### 8.5 Mode Transitions

Modes can transition based on operational experience. The posture system can model this:

```yaml
posture:
  initial: observe
  states:
    observe:
      description: Shadow mode - log but don't block
      capabilities: [file_access, file_write, egress, mcp_tool, patch, shell, custom]
    guardrail:
      description: Risk-scored blocking
      capabilities: [file_access, file_write, egress, mcp_tool, patch, custom]
    fail_closed:
      description: Default deny
      capabilities: [file_access, egress]
  transitions:
    - from: observe
      to: guardrail
      on: user_approval
    - from: guardrail
      to: fail_closed
      on: user_approval
    - from: "*"
      to: fail_closed
      on: critical_violation
```

---

## 9. Integration with Existing Guards

### 9.1 Guard Dispatch for CUA Actions

CUA actions flow through the existing `check_action()` pipeline. The key design is that CUA-specific logic lives in a new `ComputerUseGuard` that handles `Custom("cua_*", ...)` action types, while existing guards handle their traditional action types.

For a `navigate(url)` action, the flow is:

```
Agent: computer.use({ action: "navigate", url: "https://example.com/page" })
  │
  ├── CUA Gateway maps to two actions:
  │   ├── GuardAction::NetworkEgress("example.com", 443)
  │   └── GuardAction::Custom("cua_navigate", {"url": "https://example.com/page"})
  │
  ├── Engine evaluates NetworkEgress:
  │   └── EgressAllowlistGuard: is example.com in allow list?
  │
  ├── Engine evaluates Custom("cua_navigate"):
  │   ├── ComputerUseGuard: surface allowlist check
  │   ├── ComputerUseGuard: navigation depth check
  │   └── ComputerUseGuard: rate limit check
  │
  └── Aggregate results → Allow / Deny / RequireApproval
```

### 9.2 Mapping CUA Actions to Existing Guards

| CUA Action | Existing Guard Coverage | Gap (CUA Guard fills) |
|-----------|------------------------|----------------------|
| `navigate(url)` | `EgressAllowlistGuard` (domain) | URL-level allowlist, protocol, depth |
| `type(text)` | `SecretLeakGuard` (for typed content as "written" data) | Password field detection, redaction |
| `click(x, y)` | None | Surface/target validation, frame-hash precondition |
| `screenshot()` | None | Redaction timing, evidence binding |
| `file_upload(path)` | `ForbiddenPathGuard` (path check) | Upload enable/disable, extension/size |
| `file_download(url, path)` | `EgressAllowlistGuard` + `ForbiddenPathGuard` | Download quarantine, scanning |
| `key(combo)` | None | Forbidden key combos |
| `clipboard_read/write` | None | Clipboard data-flow, redaction |
| `scroll/drag/select` | None | Rate limiting, target validation |

### 9.3 ComputerUseGuard Implementation

```rust
pub struct ComputerUseGuard {
    config: ComputerUseConfig,
    surface_guards: SurfaceGuards,
    rate_limiter: CuaRateLimiter,
    session_safety: Arc<SessionSafetyState>,
    redaction_engine: RedactionEngine,
    approval_manager: ApprovalManager,
}

#[async_trait]
impl Guard for ComputerUseGuard {
    fn name(&self) -> &str {
        "computer_use"
    }

    fn handles(&self, action: &GuardAction<'_>) -> bool {
        matches!(action, GuardAction::Custom(tag, _) if tag.starts_with("cua_"))
    }

    async fn check(&self, action: &GuardAction<'_>, context: &GuardContext) -> GuardResult {
        let GuardAction::Custom(tag, payload) = action else {
            return GuardResult::skip();
        };

        // Safety check first
        if let SafetyDecision::Err(reason) = self.session_safety.check_safety(&self.config.safety) {
            return GuardResult::deny(reason);
        }

        // Rate limit check
        if !self.rate_limiter.try_consume(tag) {
            return GuardResult::deny(format!("rate_limit_exceeded:{}", tag));
        }

        // Dispatch to action-specific checks
        match *tag {
            "cua_navigate" => self.check_navigate(payload, context).await,
            "cua_click" => self.check_click(payload, context).await,
            "cua_type" => self.check_type(payload, context).await,
            "cua_screenshot" => self.check_screenshot(payload, context).await,
            "cua_key" => self.check_key(payload, context).await,
            "cua_upload" => self.check_upload(payload, context).await,
            "cua_download" => self.check_download(payload, context).await,
            "cua_clipboard" => self.check_clipboard(payload, context).await,
            "cua_scroll" | "cua_drag" | "cua_select" => {
                self.check_basic_interaction(payload, context).await
            }
            _ => {
                // Unknown CUA action type -- fail closed
                GuardResult::deny(format!("unknown CUA action type: {}", tag))
            }
        }
    }
}
```

### 9.4 Guard Evaluation Order with CUA

The CUA guard should be evaluated in the `StdPath` stage, after fast-path guards (ForbiddenPath, Egress) have already checked filesystem and network constraints. Proposed order:

| Stage | Guards |
|-------|--------|
| FastPath | ForbiddenPath, PathAllowlist, Egress, SecretLeak |
| StdPath | PatchIntegrity, ShellCommand, McpTool, **ComputerUse** |
| DeepPath | PromptInjection, Jailbreak |
| AsyncPath | VirusTotal, SafeBrowsing, Snyk |

This means a CUA `navigate` action first hits `EgressAllowlistGuard` (fast path), then `ComputerUseGuard` (std path) for surface-level checks. Both must allow for the action to proceed.

---

## 10. TOCTOU Prevention

### 10.1 The Problem

Time-of-check-to-time-of-use (TOCTOU) is the primary enforcement gap in CUA systems. The agent's view of the screen when it decides to act may differ from the actual state when the action executes. This creates two attack vectors:

1. **UI Race**: A popup appears between policy check and click execution, causing the click to hit a different target
2. **Approval Staleness**: A human approves an action based on a screenshot, but the page changes before execution

### 10.2 Pre-Action Assertions

The gateway enforces pre-action assertions immediately before execution (after policy approval but before side effect):

```rust
pub struct PreActionAssertions {
    /// Hash of the current frame (must match what was policy-checked)
    pub expected_frame_hash: Option<Hash>,
    /// URL must still match
    pub expected_url: Option<String>,
    /// DOM element at target coordinates must match
    pub expected_target: Option<ElementAssertion>,
    /// Accessibility node at target must match
    pub expected_a11y_node: Option<A11yAssertion>,
}

pub struct ElementAssertion {
    pub tag: String,
    pub text_content: Option<String>,
    pub aria_role: Option<String>,
    pub aria_label: Option<String>,
    pub bounding_box: Option<BoundingBox>,
}

impl Gateway {
    pub async fn execute_with_assertions(
        &self,
        action: &CuaAction,
        assertions: &PreActionAssertions,
    ) -> Result<ActionResult> {
        // 1. Capture current state
        let current_frame = self.capture_frame().await?;
        let current_frame_hash = sha256(&current_frame);

        // 2. Verify frame hash
        if let Some(expected) = &assertions.expected_frame_hash {
            if current_frame_hash != *expected {
                return Err(CuaError::AssertionFailed {
                    assertion: "frame_hash",
                    expected: expected.to_hex(),
                    actual: current_frame_hash.to_hex(),
                });
            }
        }

        // 3. Verify URL
        if let Some(expected_url) = &assertions.expected_url {
            let current_url = self.get_current_url().await?;
            if current_url != *expected_url {
                return Err(CuaError::AssertionFailed {
                    assertion: "url",
                    expected: expected_url.clone(),
                    actual: current_url,
                });
            }
        }

        // 4. Verify target element
        if let Some(expected) = &assertions.expected_target {
            let actual = self.element_at(action.coordinates()).await?;
            if !expected.matches(&actual) {
                return Err(CuaError::AssertionFailed {
                    assertion: "target_element",
                    expected: format!("{:?}", expected),
                    actual: format!("{:?}", actual),
                });
            }
        }

        // 5. All assertions pass -- execute action atomically
        self.execute_action(action).await
    }
}
```

### 10.3 Frame Hash Pinning

Frame hash pinning is the strongest TOCTOU prevention mechanism. The flow:

```
1. Agent receives screenshot (frame N)
2. Agent decides: click(340, 120)
3. Gateway computes frame_hash_N = sha256(frame_N)
4. Policy check runs with frame_hash_N as context
5. Policy approves action
6. Pre-execution: gateway captures frame_N+1, computes frame_hash_N+1
7. If frame_hash_N != frame_hash_N+1:
   - Action REJECTED (state changed since policy check)
   - Agent receives new screenshot (frame N+1)
   - Agent must re-decide and re-request
8. If hashes match: execute action
```

This creates a strict constraint: the screen must not change between when the agent sees it and when the action executes. For dynamic pages, this is overly strict. Relaxation strategies:

| Strategy | Trade-off |
|----------|-----------|
| **Exact frame match** | Most secure but rejects on any pixel change (cursor blink, animation) |
| **Perceptual hash match** | Allows minor visual changes; configurable threshold (dHash hamming distance < 5) |
| **Target element match** | Only checks that the element at (x,y) matches; allows rest of page to change |
| **DOM subtree match** | Checks that the DOM subtree around the target element is unchanged |
| **URL + element match** | Checks URL hasn't changed and target element exists; most permissive |

The policy controls which strategy is used:

```yaml
safety:
  toctou_strategy: target_element  # exact_frame | perceptual | target_element | dom_subtree | url_element
  perceptual_threshold: 5          # hamming distance for dHash (only if strategy=perceptual)
```

### 10.4 Approval TOCTOU

For human-approved actions, the evidence-binding mechanism (Section 6.2) is the TOCTOU defense. The `evidence_digest` in the `ApprovalRequest` is recomputed before execution and compared to the approved digest. This is non-negotiable per the linter's correction.

---

## 11. Policy Inheritance for CUA

### 11.1 CUA Rulesets

Two new built-in rulesets for CUA extend the existing `ai-agent` base:

**`cua-browser` (Browser-mode CUA)**:

```yaml
version: "1.3.0"
name: CUA Browser
description: Policy for browser-mode computer-use agents
extends: ai-agent

guards:
  computer_use:
    enabled: true
    mode: guardrail
    surfaces:
      browser:
        enabled: true
        url_allowlist: ["*"]  # Override per deployment
        url_blocklist:
          - "chrome://*"
          - "about:*"
          - "file://*"
        allowed_protocols: [https, http]
        navigation_depth: 50
      desktop:
        enabled: false
    data_flow:
      upload:
        enabled: false
      download:
        enabled: true
        max_file_size_bytes: 52428800
        quarantine_path: "/tmp/cua-downloads"
      clipboard:
        read: true
        write: true
        max_content_bytes: 65536
        redact_before_paste: true
    redaction:
      always_redact:
        - pattern: "\\b\\d{3}-\\d{2}-\\d{4}\\b"
          replacement: "[SSN-REDACTED]"
          label: ssn
        - pattern: "\\b\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}\\b"
          replacement: "[CARD-REDACTED]"
          label: credit_card
      content_triggers:
        - selector: "input[type=password]"
          action: redact_region
      timing: before_capture
    approval:
      require_human_approval:
        - action: file_upload
          evidence_binding: true
      timeout_seconds: 300
      timeout_action: deny
    rate_limits:
      global:
        actions_per_minute: 120
        actions_per_hour: 3000
    safety:
      max_session_duration_secs: 7200
      max_consecutive_errors: 10
      error_cooldown_secs: 30
      forbidden_key_combos: []
      toctou_strategy: target_element

settings:
  fail_fast: false
  verbose_logging: false
  session_timeout_secs: 7200
```

**`cua-strict` (Maximum-security CUA)**:

```yaml
version: "1.3.0"
name: CUA Strict
description: Maximum security policy for computer-use agents
extends: strict

guards:
  computer_use:
    enabled: true
    mode: fail_closed
    surfaces:
      browser:
        enabled: true
        url_allowlist: []  # Must be explicitly configured
        url_blocklist:
          - "chrome://*"
          - "about:*"
          - "file://*"
          - "javascript:*"
          - "data:*"
        allowed_protocols: [https]
        navigation_depth: 10
      desktop:
        enabled: false
    data_flow:
      upload:
        enabled: false
      download:
        enabled: false
      clipboard:
        read: false
        write: false
    redaction:
      always_redact:
        - pattern: "\\b\\d{3}-\\d{2}-\\d{4}\\b"
          replacement: "[SSN-REDACTED]"
          label: ssn
        - pattern: "\\b\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}\\b"
          replacement: "[CARD-REDACTED]"
          label: credit_card
        - pattern: "(?i)(password|secret|token|api.?key)\\s*[:=]\\s*\\S+"
          replacement: "[CREDENTIAL-REDACTED]"
          label: credential
      content_triggers:
        - selector: "input[type=password]"
          action: redact_region
        - selector: "input[type=hidden]"
          action: redact_region
      timing: before_capture
    approval:
      require_human_approval:
        - action: file_upload
          evidence_binding: true
        - action: navigate
          condition: "url_not_in_allowlist"
          evidence_binding: true
        - action: type
          condition: "target_is_password_field"
          evidence_binding: true
        - action: click
          condition: "target_matches_forbidden_ui"
          evidence_binding: true
      timeout_seconds: 120
      timeout_action: deny
      max_pending: 3
    rate_limits:
      global:
        actions_per_minute: 60
        actions_per_hour: 1000
      per_action:
        click:
          max_per_minute: 30
          burst: 5
        type:
          max_per_minute: 15
          burst: 3
        navigate:
          max_per_minute: 10
          burst: 2
    safety:
      max_session_duration_secs: 1800
      max_consecutive_errors: 5
      error_cooldown_secs: 60
      forbidden_key_combos:
        - "Ctrl+Alt+Delete"
        - "Ctrl+Shift+Esc"
        - "Alt+F4"
      toctou_strategy: dom_subtree

settings:
  fail_fast: true
  verbose_logging: false
  session_timeout_secs: 1800
```

### 11.2 Inheritance Chain

```
permissive
  └── (no CUA -- development only)

default
  └── cua-browser (extends ai-agent which uses default patterns)

strict
  └── cua-strict (extends strict directly)

ai-agent
  └── cua-browser (extends ai-agent)

ai-agent-posture
  └── cua-browser-posture (extends ai-agent-posture + cua-browser surfaces)
```

### 11.3 Per-Deployment Overrides

Production deployments override the built-in rulesets:

```yaml
version: "1.3.0"
name: Acme Corp CUA
extends: cua-browser

guards:
  computer_use:
    surfaces:
      browser:
        url_allowlist:
          - "*.acme-corp.com"
          - "*.salesforce.com"
          - "*.slack.com"
        url_blocklist:
          - "*.acme-corp.com/admin/*"
    approval:
      require_human_approval:
        - action: navigate
          condition: "url_not_in_allowlist"
          evidence_binding: true
    rate_limits:
      global:
        actions_per_minute: 60

  # Existing guards also overridden
  egress_allowlist:
    additional_allow:
      - "*.acme-corp.com"
      - "*.salesforce.com"
```

---

## 12. Refined computer.use API Schema

### 12.1 Request Schema

The `computer.use` tool call schema, refined for policy integration:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "ComputerUseRequest",
  "type": "object",
  "required": ["action"],
  "properties": {
    "action": {
      "type": "string",
      "enum": [
        "navigate", "click", "double_click", "right_click",
        "type", "key", "screenshot", "scroll",
        "drag", "select", "copy", "paste",
        "file_upload", "file_download",
        "wait", "get_element", "get_accessibility_tree"
      ]
    },
    "parameters": {
      "type": "object",
      "description": "Action-specific parameters",
      "properties": {
        "url": { "type": "string", "format": "uri" },
        "x": { "type": "integer", "minimum": 0 },
        "y": { "type": "integer", "minimum": 0 },
        "text": { "type": "string" },
        "key": { "type": "string" },
        "modifiers": {
          "type": "array",
          "items": { "enum": ["ctrl", "alt", "shift", "meta"] }
        },
        "selector": { "type": "string" },
        "path": { "type": "string" },
        "dx": { "type": "integer" },
        "dy": { "type": "integer" },
        "duration_ms": { "type": "integer", "minimum": 0 }
      }
    },
    "assertions": {
      "type": "object",
      "description": "Pre-action assertions for TOCTOU prevention",
      "properties": {
        "expected_url": { "type": "string" },
        "expected_frame_hash": { "type": "string" },
        "expected_target": {
          "type": "object",
          "properties": {
            "tag": { "type": "string" },
            "text": { "type": "string" },
            "aria_role": { "type": "string" },
            "aria_label": { "type": "string" }
          }
        }
      }
    },
    "session_id": { "type": "string" },
    "request_id": { "type": "string", "format": "uuid" }
  }
}
```

### 12.2 Response Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "ComputerUseResponse",
  "type": "object",
  "required": ["status", "request_id"],
  "properties": {
    "status": {
      "type": "string",
      "enum": ["success", "denied", "approval_required", "assertion_failed", "error", "rate_limited"]
    },
    "request_id": { "type": "string" },
    "receipt_id": { "type": "string" },
    "result": {
      "type": "object",
      "description": "Action-specific results",
      "properties": {
        "screenshot": {
          "type": "object",
          "properties": {
            "data": { "type": "string", "contentEncoding": "base64" },
            "format": { "enum": ["png", "webp", "jpeg"] },
            "width": { "type": "integer" },
            "height": { "type": "integer" },
            "frame_hash": { "type": "string" },
            "redactions_applied": { "type": "integer" }
          }
        },
        "element": {
          "type": "object",
          "properties": {
            "tag": { "type": "string" },
            "text": { "type": "string" },
            "aria_role": { "type": "string" },
            "bounding_box": {
              "type": "object",
              "properties": {
                "x": { "type": "integer" },
                "y": { "type": "integer" },
                "width": { "type": "integer" },
                "height": { "type": "integer" }
              }
            }
          }
        },
        "accessibility_tree": { "type": "object" },
        "url": { "type": "string" }
      }
    },
    "denial": {
      "type": "object",
      "description": "Present when status=denied",
      "properties": {
        "reasons": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "guard": { "type": "string" },
              "rule": { "type": "string" },
              "message": { "type": "string" },
              "severity": { "enum": ["info", "warning", "error", "critical"] }
            }
          }
        },
        "mode": { "enum": ["guardrail", "fail_closed"] }
      }
    },
    "approval": {
      "type": "object",
      "description": "Present when status=approval_required",
      "properties": {
        "approval_id": { "type": "string" },
        "expires_at": { "type": "string", "format": "date-time" },
        "evidence_digest": { "type": "string" },
        "reason": { "type": "string" }
      }
    },
    "rate_limit": {
      "type": "object",
      "description": "Present when status=rate_limited",
      "properties": {
        "retry_after_ms": { "type": "integer" },
        "limit_type": { "type": "string" },
        "remaining": { "type": "integer" }
      }
    }
  }
}
```

---

## 13. Comparison with External Policy Engines

### 13.1 OPA / Rego

**Open Policy Agent** (OPA) uses the Rego language (a Datalog variant) for policy evaluation.

| Dimension | OPA/Rego | Clawdstrike |
|-----------|---------|-------------|
| **Language** | Rego (Datalog-inspired, declarative) | YAML config + Rust guards (imperative) |
| **Evaluation** | Query-based: `allow { ... }` rules | Guard pipeline: sequential check with fail-fast |
| **Data model** | JSON documents (input + data) | Typed `GuardAction` enum + `GuardContext` |
| **Extensibility** | Built-in functions + Wasm plugins | Custom guards (Rust trait) + plugin packages |
| **Merge/inheritance** | Bundle system + package imports | `extends` with DeepMerge/Merge/Replace |
| **Performance** | Compiled Rego → partial evaluation; ~1-5ms typical | Rust-native; guard checks ~0.1-1ms each |
| **Audit** | Decision logs (JSON) | Signed receipts (Ed25519) |
| **CUA suitability** | Good for data-plane policy; no built-in UI awareness | Built-in guard pipeline designed for tool-boundary enforcement |

**Key insight**: Rego excels at expressing complex boolean conditions over structured data, but lacks UI-specific primitives (frame hashes, element assertions, redaction). Clawdstrike's typed guard pipeline is better suited for CUA because guards can encapsulate platform-specific logic (CDP queries, accessibility tree traversal).

**Potential integration**: Use OPA as an optional "custom guard" for complex authorization rules that exceed what YAML config can express:

```yaml
guards:
  custom:
    - package: clawdstrike-opa
      config:
        bundle_url: "https://policy.example.com/cua/bundle.tar.gz"
        query: "data.cua.allow"
```

### 13.2 Cedar

**Cedar** (AWS) is a formally verified policy language designed for authorization.

| Dimension | Cedar | Clawdstrike |
|-----------|-------|-------------|
| **Language** | Cedar (custom, formally verified in Lean 4) | YAML config + Rust guards |
| **Model** | Principals, Actions, Resources, Context | GuardAction + GuardContext |
| **Decisions** | Permit / Forbid (Forbid always wins) | Allow / Deny / RequireConfirmation |
| **Verification** | Formal proofs (soundness, termination) | Property tests (proptest) |
| **Schema** | Entity type schemas | `deny_unknown_fields` + validation at load |
| **Performance** | ~0.01ms per decision (simple policies) | ~0.1-1ms per guard |

**Key insight**: Cedar's "Forbid always wins" semantics align with Clawdstrike's fail-closed philosophy. Cedar's formal verification guarantees are attractive for high-assurance CUA deployments.

**Practical consideration**: Cedar requires mapping CUA actions to the Principal-Action-Resource model:

```cedar
// Cedar policy for CUA
permit (
    principal == Agent::"agent-123",
    action == Action::"navigate",
    resource
) when {
    resource.url.host in AllowedDomains &&
    resource.url.scheme == "https" &&
    context.session.posture == "elevated"
};

forbid (
    principal,
    action == Action::"file_upload",
    resource
) unless {
    context.approval.status == "approved" &&
    context.approval.evidence_digest == context.current_evidence_digest
};
```

### 13.3 Casbin

**Casbin** is a multi-model authorization library supporting ACL, RBAC, ABAC, and custom models.

| Dimension | Casbin | Clawdstrike |
|-----------|--------|-------------|
| **Language** | Model config (PERM) + policies (CSV/DB) | YAML config + Rust guards |
| **Models** | ACL, RBAC, ABAC, custom | Guard pipeline (closest to ABAC) |
| **Runtime** | Go/Java/Python/Rust/etc. | Rust-first + TypeScript + Python + Wasm |
| **Performance** | Varies by model; RBAC ~0.1ms | ~0.1-1ms per guard |
| **Extensibility** | Custom model definitions | Custom guard trait |

**Key insight**: Casbin's model flexibility is powerful but adds complexity. For CUA, the ABAC model (attribute-based) is most relevant, but Casbin's generic model language lacks CUA-specific primitives.

### 13.4 HashiCorp Sentinel

**Sentinel** is HashiCorp's policy-as-code framework, used in Terraform, Vault, and Consul.

| Dimension | Sentinel | Clawdstrike |
|-----------|----------|-------------|
| **Language** | Sentinel (custom, Python-like) | YAML config + Rust guards |
| **Enforcement** | Hard-mandatory / Soft-mandatory / Advisory | Deny / RequireConfirmation / Allow |
| **Scope** | Infrastructure and access policy | AI agent tool-boundary enforcement |
| **Testing** | Sentinel CLI test framework | Rust unit/integration tests |

**Key insight**: Sentinel's three enforcement levels (hard-mandatory, soft-mandatory, advisory) map closely to Clawdstrike's three CUA modes (fail_closed, guardrail, observe). The pattern is validated by production use in infrastructure.

### 13.5 Comparison Summary

| Feature | OPA | Cedar | Casbin | Sentinel | Clawdstrike CUA |
|---------|-----|-------|--------|----------|-----------------|
| UI-aware guards | No | No | No | No | Yes (proposed) |
| Signed receipts | No | No | No | No | Yes (existing) |
| TOCTOU prevention | No | No | No | No | Yes (proposed) |
| Redaction pipeline | No | No | No | No | Yes (proposed) |
| Approval workflows | No | No | No | Soft-mandatory | Yes (proposed) |
| Formal verification | No | Yes | No | No | No (property tests) |
| Wasm portability | Yes | Yes | Yes | No | Yes (hush-wasm) |
| Multi-language SDK | Yes | Yes | Yes | Sentinel-only | Yes (Rust/TS/Python/Wasm/FFI) |

The key differentiator for Clawdstrike CUA is that it combines policy evaluation with UI-specific primitives (frame hashing, element assertions, redaction, evidence-bound approvals) that external engines cannot provide without significant custom integration.

---

## 14. Implementation Priorities

### Phase A: Foundation (Weeks 1-4)

1. **Add `computer_use` to `GuardConfigs`** with schema v1.3.0 gating
2. **Implement `ComputerUseGuard`** handling `Custom("cua_*", ...)` actions
3. **Surface allowlists** (browser URL allowlist/blocklist, protocol check)
4. **Basic rate limiting** (global actions_per_minute, per-action limits)
5. **Three response modes** (observe, guardrail, fail_closed) with mode field
6. **CUA action mapping** in gateway adapter (navigate -> NetworkEgress + Custom)
7. **Property tests** for mode behavior, allowlist matching, rate limit correctness

### Phase B: Safety & Redaction (Weeks 5-8)

8. **Pattern-based redaction** (always_redact regex patterns)
9. **Content-trigger redaction** (DOM selector-based, accessibility-based)
10. **Data-flow controls** (upload/download/clipboard policy)
11. **TOCTOU: target element assertions** (element at coordinates must match)
12. **Session safety** (max duration, consecutive error circuit breaker)
13. **Forbidden key combos and UI targets**
14. **Built-in `cua-browser` and `cua-strict` rulesets**

### Phase C: Approval & Advanced (Weeks 9-12)

15. **Human approval workflows** with evidence-bound digests
16. **Approval API** (REST endpoints for approval UI)
17. **Approval TOCTOU** (evidence digest recomputation before execution)
18. **Desktop surface guard** (app allowlist, window title matching)
19. **Risk scoring** for guardrail mode
20. **Posture-mode integration** (CUA mode transitions via posture state machine)
21. **OPA integration** as optional custom guard for complex authorization rules

---

## 15. Conclusion

The Clawdstrike policy engine provides a strong foundation for CUA enforcement. The existing guard pipeline, typed action dispatch, inheritance system, posture model, and fail-closed philosophy are directly applicable. CUA-specific extensions should be introduced as a new `ComputerUseGuard` that handles `Custom("cua_*")` actions, keeping the existing guard evaluation flow intact.

The three response modes (observe/guardrail/fail_closed) enable graduated rollout. Evidence-bound human approval workflows and TOCTOU prevention via pre-action assertions address the unique challenges of UI automation. Redaction and data-flow controls protect sensitive information throughout the CUA session lifecycle.

By mapping CUA actions into existing guard semantics first and introducing CUA-specific logic through the established extensibility points (`Custom` action variant, custom guards, policy inheritance), the CUA gateway avoids creating a parallel policy universe while gaining the UI-specific safety properties that external policy engines cannot provide.
