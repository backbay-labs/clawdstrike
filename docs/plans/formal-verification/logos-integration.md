# Logos Integration: Modal-Temporal Logic for Policy Verification

**Status:** Design
**Authors:** Security Engineering
**Last updated:** 2026-03-16
**Depends on:** `crates/libs/logos-ffi`, `crates/libs/logos-z3`, `crates/libs/clawdstrike`

---

## 1. Overview

This document designs the integration between the Logos formal reasoning stack (`crates/libs/logos-*`) and ClawdStrike's policy engine. The goal: static, pre-deployment verification of security policies by translating them into normative formulas and checking properties via Z3 SMT solving.

### 1.1 What This Enables

With Logos integration, policy authors can prove (over all possible inputs, not just tested ones):

- **Consistency**: No action is simultaneously permitted and forbidden.
- **Completeness**: Every action type is handled by at least one guard.
- **Monotonicity**: Extending a parent policy never weakens its denials.
- **Fail-closed**: Config errors always produce denial.

### 1.2 The Logos Stack

See [Landscape Survey, Section 3.3](./landscape-survey.md) for full details. Key points for this integration:

- **logos-ffi**: Layer 3 normative operators (Obligation, Permission, Prohibition) with `AgentId`. `RoutingSpec` already has `verify_completeness()` and `verify_consistency()` as precedent.
- **logos-z3**: Layer 0 SMT checking is implemented and the ClawdStrike policy verifier now calls the Z3-backed checker. Broader Layer 3 normative semantics still need hardening beyond the current policy-focused checks.

### 1.3 Policy Engine Types (Quick Reference)

Key types for the translation (see [Verification Targets](./verification-targets.md) for details):

- **`Policy`**: `version`, `extends`, `merge_strategy`, `guards: GuardConfigs`, `settings`, `posture`, `origins`, `broker`
- **`GuardConfigs`**: 13 optional guard configs + `custom: Vec<CustomGuardSpec>`
- **`GuardAction<'a>`**: FileAccess, FileWrite, NetworkEgress, ShellCommand, McpTool, Patch, Custom
- **`GuardResult`**: `allowed: bool`, `guard`, `severity: Severity`, `message`, `details`
- **`aggregate_overall()`**: Deny-wins left-to-right scan (blocked > allowed > severity > sanitize tiebreaker)
- **`GuardConfigs::merge_with()`**: Deep-merge (additive/subtractive) for 4 guards, child-overrides-base for 7 guards

---

## 2. Policy-to-Formula Translation

The core of the integration is a deterministic translation function:

```
translate : Policy -> AgentId -> Vec<Formula>
```

This produces a set of Logos Layer 3 normative formulas that encode the policy's security semantics. Each guard configuration maps to one or more formulas.

### 2.1 Action Atom Encoding

Every `GuardAction` variant maps to a family of atoms:

```
Action atoms (parameterized):
  access(path)       -- file access to `path`
  write(path)        -- file write to `path`
  egress(domain)     -- network egress to `domain`
  exec(cmd)          -- shell command execution of `cmd`
  mcp(tool)          -- MCP tool invocation of `tool`
  patch(path)        -- patch application to `path`
  custom(type)       -- custom action of `type`
```

In the Logos AST, these are represented as `Formula::Atom(String)` with a structured naming convention:

```rust
fn action_atom(action_type: &str, param: &str) -> Formula {
    Formula::atom(format!("{}({})", action_type, param))
}
// e.g., action_atom("access", "/etc/shadow") -> Formula::Atom("access(/etc/shadow)")
```

### 2.2 Per-Guard Translation Rules

#### 2.2.1 ForbiddenPathGuard

**Rust type:** `ForbiddenPathConfig` with fields `enabled: bool`, `patterns: Option<Vec<String>>`, `exceptions: Vec<String>`, `additional_patterns: Vec<String>`, `remove_patterns: Vec<String>`.

**Effective patterns** are computed by `effective_patterns()`: start with `patterns` (or defaults), add `additional_patterns`, remove `remove_patterns`.

**Translation:** For each effective pattern `p` that is not excepted:

```
F_agent(access(p))          -- Prohibition on accessing path matching p
```

For each exception `e`:

```
P_agent(access(e))          -- Permission to access excepted path e
```

```rust
fn translate_forbidden_path(cfg: &ForbiddenPathConfig, agent: &AgentId) -> Vec<Formula> {
    if !cfg.enabled { return vec![]; }
    let effective = cfg.effective_patterns();
    effective.iter()
        .filter(|pattern| !cfg.exceptions.iter().any(|e| pattern_subsumes(e, pattern)))
        .map(|pattern| {
            Formula::prohibition(agent.clone(), action_atom("access", pattern))
        })
        .chain(cfg.exceptions.iter().map(|e| {
            Formula::permission(agent.clone(), action_atom("access", e))
        }))
        .collect()
}
```

#### 2.2.2 PathAllowlistGuard

**Rust type:** `PathAllowlistConfig` with `paths: Vec<String>`.

**Translation:** The allowlist defines the complete set of permitted paths. Anything outside is implicitly forbidden:

```
P_agent(access(path))   iff   path in allowlist
```

#### 2.2.3 EgressAllowlistGuard

**Rust type:** `EgressAllowlistConfig` with `enabled: bool`, `allow: Vec<String>`, `block: Vec<String>`, `default_action: Option<PolicyAction>`, `additional_allow: Vec<String>`, `remove_allow: Vec<String>`, `additional_block: Vec<String>`, `remove_block: Vec<String>`.

**Translation:**

```
-- Explicit allows
forall d in allow:  P_agent(egress(d))

-- Explicit blocks (takes precedence over allow)
forall d in block:  F_agent(egress(d))

-- Default action (applied to unmatched domains)
if default_action == Block:
    forall d not in allow and not in block:  F_agent(egress(d))
if default_action == Allow (or None):
    forall d not in allow and not in block:  P_agent(egress(d))
```

Note: The `block` list takes precedence over `allow` in the Rust implementation. A domain in both lists is blocked. The precedence order is: block > allow > default.

#### 2.2.4 ShellCommandGuard

**Rust type:** `ShellCommandConfig` with `enabled: bool`, `forbidden_patterns: Vec<String>`, `enforce_forbidden_paths: bool`.

Note: `forbidden_patterns` are _regex_ patterns, not exact command strings. The translation is necessarily an over-approximation since Z3 cannot directly reason about regex matching.

**Translation:**

```
forall pat in forbidden_patterns:  F_agent(exec(pat))
```

#### 2.2.5 McpToolGuard

**Rust type:** `McpToolConfig` with `enabled: bool`, `allow: Vec<String>`, `block: Vec<String>`, `require_confirmation: Vec<String>`, `default_action: Option<McpDefaultAction>`, `max_args_size: Option<usize>`, plus additive/subtractive merge fields.

Same precedence structure as egress:

```
forall t in block:  F_agent(mcp(t))
forall t in allow:  P_agent(mcp(t))

-- default
if default_action == block:
    forall t not in allow and not in block:  F_agent(mcp(t))
```

#### 2.2.6 SecretLeakGuard

**Rust type:** `SecretLeakConfig` with `enabled: bool`, `patterns: Vec<SecretPattern>`, `additional_patterns: Vec<SecretPattern>`, `remove_patterns: Vec<String>`, `skip_paths: Vec<String>`, and more.

```
-- For each secret pattern, writing content matching it is forbidden
forall sp in effective_patterns, forall path not in skip_paths:
    O_agent(scan_before_write(path))  -- obligation to scan
    F_agent(write_secret(sp.name, path))  -- prohibition on writing detected secrets
```

The obligation operator captures the guard's nature as a mandatory check, not just a prohibition.

#### 2.2.7 PatchIntegrityGuard

**Config fields:** `max_additions`, `max_deletions`, `forbidden_patterns: Vec<String>`, `require_balance`, `max_imbalance_ratio`

```
-- Forbidden patch patterns
forall pat in forbidden_patterns:  F_agent(patch_containing(pat))

-- Size bounds (as bounded quantification)
O_agent(patch_additions <= max_additions)
O_agent(patch_deletions <= max_deletions)
```

#### 2.2.8 Content-Inspection Guards

PromptInjectionGuard, JailbreakGuard, SpiderSenseGuard, ComputerUseGuard, RemoteDesktopSideChannelGuard, and InputInjectionCapabilityGuard are _content-dependent_ guards. Their verdicts depend on runtime analysis of actual content (embedding similarity, regex matching, heuristic scoring), not on structural properties of the policy.

**Translation strategy:** These guards are modeled as obligations rather than permissions/prohibitions:

```
-- Prompt injection scanning is obligatory when enabled
if prompt_injection.enabled:
    O_agent(scan_injection_before_processing)

-- Jailbreak detection is obligatory when enabled
if jailbreak.enabled:
    O_agent(scan_jailbreak_before_processing)
```

We verify the _structural_ property (the guard is enabled and configured) rather than the _runtime_ property (what the guard detects). Runtime detection correctness is a separate verification target (see the [Policy Specification](./policy-specification.md) document for differential testing).

### 2.3 Guard Aggregation Formula

Deny-wins aggregation as a universal formula:

```
-- Deny monotonicity: if any guard forbids, the overall verdict forbids
Box(exists g in guards: deny(g, action)) -> deny(overall, action)
```

In Logos AST:

```rust
fn aggregation_monotonicity(agent: &AgentId) -> Formula {
    let guard_denies = Formula::atom("guard_denies_action");
    let overall_denies = Formula::atom("overall_denies_action");
    Formula::necessity(Formula::implies(guard_denies, overall_denies))
}
```

The `Necessity` (Box) operator makes this hold across all possible worlds.

**Caveat:** The aggregation is NOT fully commutative -- ties are broken by position and sanitize status. The `allowed` boolean is order-independent (the security-relevant property); the specific `GuardResult` selected may vary by order.

### 2.4 Posture State Formulas

The posture subsystem (`posture.rs`) is the one stateful component. It defines a finite state machine with:
- States (e.g., `restricted`, `standard`, `elevated`)
- Capabilities per state (e.g., `file_access`, `shell`, `egress`)
- Budgets per state (e.g., `shell_commands: 10`)
- Transitions triggered by events (violation, approval, timeout)

**Translation:** States and transitions map to temporal formulas:

```
-- If in state s, only capabilities in s.capabilities are permitted
G(in_state(s) -> (P_agent(cap) <-> cap in s.capabilities))

-- Budget enforcement: after N uses of capability c, transition or deny
G(in_state(s) AND budget(c) = 0 -> F_agent(c))

-- Transition: trigger t in state s causes move to state s'
G(in_state(s) AND trigger(t) -> F(in_state(s')))
```

The temporal operator `G` (AlwaysFuture) captures the invariant nature of these constraints. Budget counters require bounded temporal reasoning. Since budgets are finite integers, the temporal horizon is bounded by the maximum budget value, keeping the Z3 encoding decidable.

---

## 3. Z3 Verification Properties

Given a translated policy (a set of normative formulas), we verify the following properties.

### 3.1 Consistency

**Property:** No policy produces both permit and forbid for the same action.

**Formal statement:**

```
not exists action a, agent ag:
    P_ag(a) AND F_ag(a)
```

**Z3 encoding:** Assert the negation (i.e., assert that such an action exists) and check for unsatisfiability. If UNSAT, the policy is consistent. If SAT, the satisfying assignment is a counterexample showing the conflicting action.

**Note:** Deny-wins resolves conflicts at runtime, so consistency violations are not security failures -- but they signal policy authoring errors.

### 3.2 Completeness

**Property:** Every action type is handled by at least one guard.

**Formal statement:**

```
forall action_type t:
    exists guard g in policy.guards:
        g.handles(t)
```

**Z3 encoding:** For each `GuardAction` variant (FileAccess, FileWrite, NetworkEgress, ShellCommand, McpTool, Patch, Custom), verify that at least one configured guard's `handles()` method returns true.

This is a structural check on the policy configuration, not a formula validity check. We enumerate the 7 action types and check guard coverage.

### 3.3 Deny Monotonicity

**Property:** Adding guards to a policy never turns a denial into an allow.

**Formal statement:**

```
forall policy P, guard g, action a, context c:
    evalPolicy(P, a, c) = deny ->
    evalPolicy(P + {g}, a, c) = deny
```

This follows from the structure of `aggregate_overall()`: the function scans for the worst result. Adding a guard can only add results to the list, never remove them. If any existing result is a denial, that denial remains, and `aggregate_overall` always selects a denial over any allow.

### 3.4 Inheritance Soundness

**Property:** Merging a parent policy with a child policy preserves the child's explicit denials.

**Formal statement:**

```
forall parent P, child C, merged M = merge(P, C), action a, context ctx:
    evalPolicy(C, a, ctx) = deny ->
    evalPolicy(M, a, ctx) = deny
```

This is subtle because `GuardConfigs::merge_with()` uses different strategies per guard:

- **Deep-merge guards** (forbidden_path, egress_allowlist, mcp_tool, secret_leak): The child can add patterns (`additional_patterns`) and remove patterns (`remove_patterns`) relative to the base. The merged effective pattern set is: base effective patterns + child additions - child removals. If the child explicitly specifies a full `patterns` list, that replaces the base entirely.
- **Child-overrides-base guards** (patch_integrity, shell_command, prompt_injection, jailbreak, computer_use, remote_desktop_side_channel, input_injection_capability): `child.or_else(|| base)`. Child config replaces base entirely when present.

**Z3 encoding:** For each deep-merge guard, verify that any pattern responsible for a denial in the child's config also appears in the merged config. For child-overrides guards, the property holds trivially since the child config is preserved verbatim when present.

A child that omits a guard inherits the parent's config; a child that includes a guard replaces the parent's. This is by design.

### 3.5 Fail-Closed on Config Error

**Property:** If the policy has a configuration error, every action check returns an error (which the caller must treat as deny).

This is verified by examining the `check_action_report()` method in `engine.rs`, which begins with an unconditional early return on `config_error`. This is a syntactic property -- the Z3 encoding asserts that `config_error.is_some()` implies the function returns `Err`, which is trivially valid from the control flow.

### 3.6 Schema Version Rejection

**Property:** Unsupported schema versions are rejected at parse time.

---

## 4. Z3 Layer 3 Encoding Design

The existing `logos-z3` Z3Checker returns `ProofResult::Unknown` for Layer 3 normative formulas (see `check_normative()` at `lib.rs:220`). This section specifies how to implement a normative checker.

### 4.1 Deontic Semantics for ClawdStrike

Standard Deontic Logic (SDL) assumes permission and prohibition are duals: `P(a) <-> not F(a)`. **ClawdStrike does not follow this convention.** In ClawdStrike, an action can be explicitly permitted by one guard (e.g., path_allowlist) and explicitly forbidden by another (e.g., forbidden_path), with the deny-wins aggregation resolving the conflict. Permission and Prohibition are independent assertions that may coexist, with Prohibition taking priority.

We therefore use a **deny-overrides deontic logic** rather than standard SDL:

**Axiom D1 (Deny overrides Permit):**
```
F_a(phi) -> not effective_P_a(phi)
```
If any guard forbids an action, the effective verdict is denial, regardless of other guards' permissions.

**Axiom D2 (Obligation implies effective Permission when not Forbidden):**
```
O_a(phi) AND not F_a(phi) -> effective_P_a(phi)
```

**Axiom D3 (No effective permission under prohibition):**
```
F_a(phi) -> not effective_P_a(phi)
```

```
(declare-fun F (String String) Bool)    ; F(agent, action) = some guard forbids
(declare-fun P (String String) Bool)    ; P(agent, action) = some guard permits
(declare-fun O (String String) Bool)    ; O(agent, action) = some guard obligates
(declare-fun eff_P (String String) Bool) ; effective permission (after deny-wins)

; Deny-overrides: effective permission requires no prohibition
(assert (forall ((a String) (phi String))
    (= (eff_P a phi) (and (P a phi) (not (F a phi))))))
```

### 4.2 Policy-Specific Constraints

For each translated formula from section 2, we add a Z3 assertion. For example, given the strict ruleset:

```yaml
guards:
  egress_allowlist:
    allow: []
    default_action: block
```

We generate:
```
; Universal egress prohibition (strict ruleset, default=block, empty allow)
(assert (forall ((d String))
    (F "agent" (concat "egress(" d ")"))))
```

### 4.3 Conflict Detection Query

To find actions where both P and F hold (consistency check from section 3.1):

```
; Check: is there an action that has both a permission and a prohibition?
(declare-const conflict_action String)
(assert (P "agent" conflict_action))
(assert (F "agent" conflict_action))
(check-sat)
; Expected: unsat (no conflict)
; If sat: (get-value (conflict_action)) yields the conflicting action
```

Note: SAT here means the policy has a _structural_ conflict. ClawdStrike still behaves correctly (deny wins), but the policy author likely made a mistake.

### 4.4 Policy Composition Encoding

When verifying merged policies (parent extends child), we encode the actual merge semantics:

**For deep-merge guards (forbidden_path, egress, mcp, secret_leak):**

The merged effective patterns are NOT a simple union. The merge computes:
```
merged_patterns = (base_effective OR child_additions) AND NOT child_removals
```

If the child provides an explicit full `patterns` list, that replaces the base entirely:
```
merged_patterns = child_explicit_patterns + child_additions - child_removals
```

**For child-overrides guards:**
```
merged_config = child_config OR base_config  (child takes priority)
```

**Merge monotonicity verification (restricted to deep-merge guards without removals):**

When the child does not use `remove_patterns`, the merge is monotonically non-weakening:
```
(assert (=> (F_child conflict_action) (F_merged conflict_action)))
(check-sat)
; Expected: unsat (child denials preserved in merge)
```

When the child _does_ use `remove_patterns`, the merge can intentionally weaken the base. This is by design -- a child extending a `strict` parent may need to relax specific restrictions. The verification reports this as an intentional weakening, not an error.

### 4.5 Finite-Domain Optimization

ClawdStrike policies operate over finite domains -- the patterns, paths, domains, tools, and commands listed in the YAML. Rather than universal quantification over strings (which Z3 handles poorly), we enumerate the finite domain:

```rust
fn finite_domain(policy: &Policy) -> Vec<String> {
    let mut atoms = Vec::new();
    if let Some(fp) = &policy.guards.forbidden_path {
        for p in &fp.effective_patterns() {
            atoms.push(format!("access({})", p));
        }
        for e in &fp.exceptions { atoms.push(format!("access({})", e)); }
    }
    if let Some(eg) = &policy.guards.egress_allowlist {
        for d in &eg.allow { atoms.push(format!("egress({})", d)); }
        for d in &eg.block { atoms.push(format!("egress({})", d)); }
    }
    // ... similar for all guards
    atoms.sort();
    atoms.dedup();
    atoms
}
```

For a typical policy with ~50 patterns across all guards, this gives a finite domain of ~50 atoms. The `Z3Checker`'s existing exhaustive enumeration (up to 10 atoms) is insufficient, but Z3's native SMT encoding handles 50 boolean variables efficiently via DPLL(T).

### 4.6 Bounded Temporal Encoding for Posture

The posture state machine is encoded using bounded model checking. Given `max_times` time steps (default 8 from `Z3Config`):

```
; State variable at each time step
(declare-fun state (Int) String)

; Initial state
(assert (= (state 0) "restricted"))

; Transition function
(assert (forall ((t Int))
    (=> (and (>= t 0) (< t 7))
        (= (state (+ t 1))
            (ite (and (= (state t) "restricted") (trigger t "user_approval"))
                "standard"
            (ite (and (= (state t) "standard") (trigger t "critical_violation"))
                "restricted"
                (state t)))))))

; Capability invariant at each time step
(assert (forall ((t Int))
    (=> (= (state t) "restricted")
        (and (not (P "agent" "shell"))
             (not (P "agent" "egress"))))))
```

Budget counters are modeled as integer-valued functions of time:

```
(declare-fun budget (Int String) Int)

; Initial budget
(assert (= (budget 0 "shell_commands") 10))

; Decrement on use
(assert (forall ((t Int))
    (=> (and (>= t 0) (< t 7) (used t "shell"))
        (= (budget (+ t 1) "shell_commands")
            (- (budget t "shell_commands") 1)))))

; Budget exhaustion -> prohibition
(assert (forall ((t Int))
    (=> (<= (budget t "shell_commands") 0)
        (F "agent" "exec(shell)"))))
```

---

## 5. Proof Receipt Integration

### 5.1 Enriched ClawdStrike Receipts

When a policy passes Z3 verification, the signed receipt is enriched with verification metadata. The existing `Receipt::merge_metadata()` method supports this without schema changes:

```rust
fn enrich_receipt_with_verification(
    receipt: Receipt,
    proof_result: &logos_ffi::ProofResult,
    properties_checked: &[&str],
) -> Receipt {
    let verification_metadata = serde_json::json!({
        "formal_verification": {
            "z3_verified": proof_result.is_valid(),
            "z3_proof_hash": proof_result.receipt()
                .map(|r| r.formula_hash.clone()),
            "properties_checked": properties_checked,
            "verification_timestamp": chrono::Utc::now().to_rfc3339(),
        }
    });
    receipt.merge_metadata(verification_metadata)
}
```

### 5.2 Receipt Field Semantics

| Field | Type | Meaning |
|-------|------|---------|
| `formal_verification.z3_verified` | `bool` | All checked properties passed Z3 verification |
| `formal_verification.z3_proof_hash` | `Option<String>` | SHA-256 hash of the verified formula set |
| `formal_verification.properties_checked` | `Vec<String>` | List of property names that were verified |
| `formal_verification.verification_timestamp` | `String` | ISO-8601 timestamp of verification |
| `formal_verification.counterexamples` | `Option<Vec<Object>>` | Counterexample(s) if any property failed |

### 5.3 Verification Tiers

Not all policies need the same level of verification:

| Tier | Properties Checked | Z3 Time Budget | Receipt Annotation |
|------|-------------------|----------------|-------------------|
| **Quick** | Consistency only | 1s | `z3_tier: "quick"` |
| **Standard** | Consistency + Completeness + Deny monotonicity | 5s | `z3_tier: "standard"` |
| **Full** | All properties + Posture BMC | 30s | `z3_tier: "full"` |

---

## 6. Architecture

### 6.1 Data Flow

```
Policy YAML
    |
    v
Policy::from_yaml() ───────────────────> Policy struct
    |                                         |
    v                                         v
PolicyTranslator::translate()           HushEngine::with_policy()
    |                                         |
    v                                         v
Vec<Formula>  (Logos Layer 3)           Guard evaluation (runtime)
    |                                         |
    v                                         v
Z3Checker                              GuardResult / Receipt
    |                                         |
    v                                         v
ProofResult / VerificationReport    Receipt::merge_metadata()
    |                                         |
    v                                         v
enriched Receipt metadata              Enriched SignedReceipt
```

### 6.2 Crate Structure

New crate: `clawdstrike-logos` (in `crates/libs/clawdstrike-logos/`)

```
clawdstrike-logos/
  Cargo.toml
  src/
    lib.rs              -- public API: verify_policy(), VerificationReport
    translator.rs       -- Policy -> Vec<Formula> translation (section 2)
    properties.rs       -- Property definitions (section 3)
    z3_encoding.rs      -- Z3 constraint generation (section 4)
    receipt_enrichment.rs -- Receipt metadata attachment (section 5)
```

**Dependency graph:**

```
clawdstrike-logos
    ├── clawdstrike          (policy types, GuardConfigs, merge_with)
    ├── hush-core            (Receipt, SignedReceipt, merge_metadata)
    ├── logos-ffi            (Formula, AgentId, ProofReceipt, ProofResult)
    └── logos-z3             (Z3Checker, Z3Config)
```

**Dependency direction:** `clawdstrike-logos` depends on both `clawdstrike` (for policy types) and `logos-ffi`/`logos-z3` (for formula types and the checker). Neither `clawdstrike` nor `logos-*` depends on `clawdstrike-logos`. This keeps the integration optional.

### 6.3 Feature Gating

The Z3 dependency is heavy (native C++ library). We gate it behind a feature:

```toml
[features]
default = []
z3-verify = ["logos-z3"]
lean-verify = ["logos-ffi/lean-runtime"]
full = ["z3-verify"]
```

Without the feature, `verify_policy()` returns a no-op `VerificationReport` with all properties marked `Unknown`.

### 6.4 Performance Constraints

**Z3 checking happens at policy load time, not per-action.** Policy load is an infrequent operation. Per-action evaluation must remain sub-millisecond. The verification cost is amortized over the policy's lifetime.

**Cache verification results keyed by policy content hash:**

```rust
struct VerificationCache {
    cache: HashMap<String, VerificationReport>,
}

impl VerificationCache {
    fn get_or_verify(&mut self, policy: &Policy) -> Result<VerificationReport> {
        let yaml = policy.to_yaml()?;
        let hash = hex::encode(sha256(yaml.as_bytes()));
        if let Some(report) = self.cache.get(&hash) {
            return Ok(report.clone());
        }
        let report = verify_policy(policy)?;
        self.cache.insert(hash, report.clone());
        Ok(report)
    }
}
```

---

## 7. Public API

```rust
/// Verification report for a single policy.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerificationReport {
    pub policy_hash: String,
    pub properties: Vec<PropertyResult>,
    pub all_passed: bool,
    pub verification_time_ms: u64,
    pub proof_receipt: Option<logos_ffi::ProofReceipt>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PropertyResult {
    pub name: String,
    pub status: PropertyStatus,
    pub counterexample: Option<String>,
    pub check_time_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PropertyStatus {
    Valid,
    Invalid,
    Unknown,
    Timeout,
}

/// Verify a policy against formal properties.
pub fn verify_policy(policy: &Policy) -> Result<VerificationReport> {
    verify_policy_with_config(policy, &VerificationConfig::default())
}

pub fn verify_policy_with_config(
    policy: &Policy,
    config: &VerificationConfig,
) -> Result<VerificationReport> {
    todo!()
}

#[derive(Clone, Debug)]
pub struct VerificationConfig {
    pub tier: VerificationTier,
    pub z3_config: logos_z3::Z3Config,
    pub agent_id: logos_ffi::AgentId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerificationTier {
    Quick,
    Standard,
    Full,
}
```

---

## 8. CLI Integration

The `hush-cli` binary exposes verification via the `clawdstrike verify` subcommand:

```bash
# Verify default policy
clawdstrike verify

# Verify a specific policy file
clawdstrike verify --policy my-policy.yaml

# Full verification tier
clawdstrike verify --policy strict.yaml --tier full

# JSON output for CI integration
clawdstrike verify --policy strict.yaml --output json
```

Example output:

```
Verifying policy: strict.yaml (hash: a1b2c3...)

  [PASS] Consistency          0.3ms   No action is both permitted and forbidden
  [PASS] Completeness         0.1ms   All 7 action types covered by guards
  [PASS] Deny monotonicity    0.2ms   Adding guards preserves denials
  [PASS] Inheritance sound.   0.8ms   Merge preserves child denials
  [PASS] Fail-closed          0.0ms   Config errors produce Err
  [PASS] Schema version       0.0ms   Unsupported versions rejected

All 6 properties verified in 1.4ms
Proof receipt: proof_a1b2c3d4e5f6
```

---

## 9. Integration with Existing Logos Patterns

### 9.1 Reusing RoutingSpec's Verification Pattern

The `RoutingSpec` in `logos-ffi` already implements `verify_completeness()` and `verify_consistency()` for routing rules. Our policy verification follows the same pattern:

1. Translate domain concepts to formulas
2. Check structural properties (completeness, consistency)
3. Return `ProofReceipt` on success or structured errors on failure

The key difference is that routing rules use Layer 0 (propositional) formulas, while policy verification uses Layer 3 (normative) formulas. This motivates implementing normative checking in `logos-z3`.

### 9.2 GOAP Integration (Future)

`logos-goap` could combine verified policies with verified plans for compositional proofs (plan achieves goal AND every action is policy-compliant). Future work.

---

## 10. Implementation Roadmap

| Phase | Scope | Estimated Effort |
|-------|-------|-----------------|
| **Phase 1** | `PolicyTranslator` for ForbiddenPath, EgressAllowlist, McpTool (the three allow/block guards) | 1 week |
| **Phase 2** | Deny-overrides deontic encoding in logos-z3 | 1 week |
| **Phase 3** | Consistency and completeness verification | 3 days |
| **Phase 4** | Merge monotonicity verification | 3 days |
| **Phase 5** | Receipt enrichment and CLI integration | 3 days |
| **Phase 6** | Posture BMC encoding | 1 week |
| **Phase 7** | Lean 4 backend (when `lean-runtime` is available) | TBD |

Phases 1--5 are the minimal viable integration. Phase 6 adds stateful verification. Phase 7 upgrades from SMT checking (sound but incomplete for some properties) to full theorem proving.

---

## 11. Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|-----------|
| Z3 timeout on complex policies | Verification returns Unknown | Finite-domain optimization (section 4.5), configurable timeout, tier system |
| Z3 native dependency is large | Increases build time | Feature-gate behind `z3-verify`, optional at runtime |
| Translation bugs (policy semantics != formula semantics) | False confidence | Differential testing: generate random policies, evaluate via both Rust engine and Z3, assert agreement (see [Policy Specification](./policy-specification.md) section 6) |
| Deontic encoding is unsound | Incorrect verification results | Use deny-overrides axioms matching ClawdStrike's actual semantics, not standard SDL |
| Glob patterns are not first-class in Z3 | Path matching is approximate | Over-approximate: if Z3 says "consistent", it is; if "inconsistent", manual review needed for glob-related false positives |
| Merge semantics are complex (add/remove, not simple union) | Translation may miss edge cases | Test against actual `merge_with` output for all built-in rulesets |

---

## 12. References

- Standard Deontic Logic: von Wright, G.H. "Deontic Logic." _Mind_, 1951.
- Z3 SMT Solver: de Moura, L. and Bjorner, N. "Z3: An Efficient SMT Solver." _TACAS_, 2008.
- Logos Stack: `crates/libs/logos-ffi`, `crates/libs/logos-z3`
- ClawdStrike Policy Engine: `crates/libs/clawdstrike/src/policy.rs`, `crates/libs/clawdstrike/src/engine.rs`
- Amazon Cedar formal verification: Cutler et al. "Cedar: A New Language for Expressive, Fast, Safe, and Analyzable Authorization." _OOPSLA_, 2024.
- Bounded Model Checking: Biere et al. "Bounded Model Checking." _Advances in Computers_, 2003.
