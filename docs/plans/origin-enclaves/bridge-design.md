# Origin Enclaves — Bridge Model Design

> Phase 0.0 design sketch
> Status: Draft
> Branch: feat/enclaves
> Date: 2026-03-07

This document defines the type shapes and semantics for the bridge model before
`OriginProfile` is finalized. It is a design note, not a spec. Implementation
happens in Phase 4.3 (`crates/libs/clawdstrike/src/bridge.rs`).

---

## 1. BridgePolicy Type Shape

A `BridgePolicy` lives inside each `OriginProfile` (the `bridge` field from
INDEX.md section 2.1). It governs whether an agent operating under one enclave
may cross into a different origin.

```rust
/// Controls cross-origin transitions from the enclave that owns this policy.
/// Attached to OriginProfile as `bridge: Option<BridgePolicy>`.
/// When None, cross-origin is implicitly denied (fail-closed).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgePolicy {
    /// Master switch. When false, all cross-origin attempts from this
    /// enclave are denied regardless of other fields.
    #[serde(default)]
    pub allow_cross_origin: bool,

    /// Which target origins this enclave may bridge to.
    /// Empty vec + allow_cross_origin=true means "any target" (use with caution).
    #[serde(default)]
    pub allowed_targets: Vec<BridgeTarget>,

    /// Whether crossing requires human approval before proceeding.
    /// When true, the bridge emits a RequireApproval decision that feeds
    /// into the existing approval queue (control-api).
    #[serde(default)]
    pub require_approval: bool,

    /// How much capability transfers from source enclave to target enclave.
    #[serde(default)]
    pub max_capability_transfer: CapabilityTransferLevel,
}

/// A filter describing a permitted target origin.
/// All present fields must match (logical AND). Absent fields are wildcards.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeTarget {
    /// Target provider, e.g. "github", "slack", "jira".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,

    /// Target space type, e.g. "issue", "channel", "ticket".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_type: Option<String>,

    /// Required tags on the target origin. All listed tags must be present
    /// on the target (subset match).
    #[serde(default)]
    pub tags: Vec<String>,

    /// Required visibility on the target origin.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visibility: Option<String>,
}

/// Controls how much of the source enclave's capability set transfers
/// to the target enclave on a bridge crossing.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub enum CapabilityTransferLevel {
    /// Target gets its own enclave profile resolved independently.
    /// No capabilities inherited from source. Safest default.
    #[default]
    None,

    /// Read-oriented capabilities transfer (list, get, search).
    /// Write capabilities are not inherited.
    ReadOnly,

    /// An explicit subset of source capabilities transfers.
    /// The subset is defined by intersecting source enclave MCP config
    /// with a transfer allowlist on the bridge policy (future extension).
    Restricted,

    /// Full source capabilities transfer to target. The target enclave
    /// operates with the union of its own resolved profile and the source
    /// enclave's profile. Dangerous -- requires require_approval: true
    /// in any reasonable deployment.
    Full,
}
```

### YAML Example

```yaml
schema_version: "1.4.0"
origins:
  default_behavior: deny
  profiles:
    - id: incident-room
      match:
        provider: slack
        tags: [incident]
        visibility: internal
      bridge:
        allow_cross_origin: true
        require_approval: false
        max_capability_transfer: read_only
        allowed_targets:
          - provider: github
            space_type: issue
            tags: [incident]
          - provider: jira
            space_type: ticket
            tags: [sev1, sev2]

    - id: public-channel
      match:
        provider: slack
        visibility: public
      bridge:
        allow_cross_origin: false  # no cross-origin from public channels
```

---

## 2. BridgeRequest Type Shape

A `BridgeRequest` is constructed by the engine when it detects a cross-origin
transition within a session (Phase 1b cross-origin isolation check in
`engine.rs`). The `BridgeResolver` evaluates it against the source enclave's
`BridgePolicy`.

```rust
/// A request to cross from one origin to another.
/// Built by the engine when guard_context.origin differs from session_origin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeRequest {
    /// The origin the agent is currently operating in.
    pub source_origin: OriginContext,

    /// The origin the agent wants to transition to.
    pub target_origin: OriginContext,

    /// What the agent wants to do in the target origin, expressed as
    /// a tool name or capability identifier (e.g. "mcp:github:create_issue").
    pub requested_capability: String,

    /// Session ID for correlation. Same session implies same agent run.
    pub session_id: String,

    /// Agent identity (maps to IdentityPrincipal.agent_id).
    pub agent_id: String,

    /// ISO 8601 timestamp of the bridge request.
    pub timestamp: String,
}

/// The resolver's decision on a bridge request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BridgeDecision {
    /// Bridge allowed. The agent proceeds in the target enclave.
    Allow {
        /// ID of the resolved target enclave profile.
        target_enclave_id: String,

        /// Effective capability transfer level applied.
        capability_transfer: CapabilityTransferLevel,
    },

    /// Bridge denied. The agent stays in the source enclave.
    Deny {
        /// Human-readable reason for denial.
        reason: String,
    },

    /// Bridge requires human approval before proceeding.
    /// The engine emits this to the approval queue (control-api).
    RequireApproval {
        /// Pre-built approval request for the approval broker.
        approval_request: ApprovalRequest,
    },
}
```

### Resolver Logic

```rust
impl BridgeResolver {
    /// Evaluate a bridge request against the source enclave's bridge policy.
    pub fn check(
        request: &BridgeRequest,
        source_policy: &BridgePolicy,
        target_enclave: &ResolvedEnclave,
    ) -> BridgeDecision {
        // 1. Master switch
        if !source_policy.allow_cross_origin {
            return BridgeDecision::Deny {
                reason: "cross-origin disabled on source enclave".into(),
            };
        }

        // 2. Target matching -- at least one BridgeTarget must match
        if !source_policy.allowed_targets.is_empty() {
            let matched = source_policy.allowed_targets.iter().any(|t| {
                t.matches(&request.target_origin)
            });
            if !matched {
                return BridgeDecision::Deny {
                    reason: "target origin does not match any allowed bridge target".into(),
                };
            }
        }

        // 3. Approval gate
        if source_policy.require_approval {
            return BridgeDecision::RequireApproval {
                approval_request: build_bridge_approval(request, source_policy),
            };
        }

        // 4. Allow
        BridgeDecision::Allow {
            target_enclave_id: target_enclave.profile_id.clone(),
            capability_transfer: source_policy.max_capability_transfer.clone(),
        }
    }
}
```

---

## 3. DM Default Behavior

**Decision:** Hybrid approach.

| DM Type | Default Behavior | Rationale |
|---------|-----------------|-----------|
| Internal DM (all participants are known org members) | **Minimal read-only profile** | Low risk. Blocking internal DMs entirely creates friction without meaningful security gain. Agents can read context but cannot write, execute tools, or make external calls. |
| External DM (any participant outside the organization) | **Deny** | High risk. External participants mean data exfiltration surface. The agent should not operate in a DM with external users unless an explicit profile matches. |

This maps to `OriginsConfig.default_behavior` from INDEX.md section 2.1.
The minimal read-only profile is a synthetic enclave, not a user-authored
profile. It is equivalent to:

```yaml
# Synthetic profile applied when default_behavior is MinimalProfile
# and the origin is an internal DM with no matching profile.
id: "__internal_dm_fallback"
posture: restricted
mcp:
  enabled: true
  allow: []
  block: []
  default_action: deny    # deny all tool calls
egress:
  enabled: true
  allow: []               # no egress allowed
data:
  allow_external_sharing: false
  redact_before_send: true
  block_sensitive_outputs: true
bridge:
  allow_cross_origin: false
```

The `default_behavior` enum:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum OriginDefaultBehavior {
    /// Deny all unmatched origins. Fail-closed.
    #[default]
    Deny,

    /// Apply a minimal read-only profile to unmatched internal origins.
    /// External origins (external_participants = true) are still denied.
    MinimalProfile,
}
```

The enclave resolver applies this logic at the bottom of the match cascade
(priority level 5 in INDEX.md section 2.3):

1. If `default_behavior` is `Deny` -- return error, fail-closed.
2. If `default_behavior` is `MinimalProfile`:
   a. If `origin.external_participants` is true or `origin.visibility` is
      `Public` or `ExternalShared` -- deny.
   b. Otherwise -- return the synthetic `__internal_dm_fallback` profile.

---

## 4. McpToolConfig Composition Semantics

Enclave resolution produces an `McpToolConfig` (the enclave's tool surface).
The engine must compose this with the base policy's `McpToolConfig` before
guard evaluation. These are two different composition operations.

### 4.1 `merge_with()` -- Inheritance Composition (Existing)

Used by `Policy.extends` to merge parent and child policies. Semantics
(from `guards/mcp_tool.rs:120-151`):

- Child's `additional_allow` appends to parent's `allow`.
- Child's `additional_block` appends to parent's `block`.
- Child's `remove_allow` / `remove_block` prunes parent lists.
- If child has non-empty `allow` / `block` / `require_confirmation`, it
  **replaces** the parent list entirely.

This is an **override** model: children can expand or contract the parent's
tool surface in any direction.

### 4.2 `intersect_with()` -- Enclave Projection (New)

Used by the engine to combine enclave MCP config with policy MCP config.
Semantics: **most restrictive wins**.

```rust
impl McpToolConfig {
    /// Compute the intersection of two tool configs.
    /// Result only allows tools that both configs allow,
    /// blocks tools that either config blocks, and requires
    /// confirmation if either config requires it.
    ///
    /// This is NOT merge_with(). merge_with() is for policy inheritance
    /// (child overrides base). intersect_with() is for enclave projection
    /// (enclave narrows policy, policy narrows enclave).
    pub fn intersect_with(&self, other: &Self) -> Self {
        // Disabled in either → disabled
        if !self.enabled || !other.enabled {
            return Self { enabled: false, ..Self::default() };
        }

        // --- Allow list ---
        // If both have explicit allow lists: intersection.
        // If only one has an allow list: use it (it's more restrictive).
        // If neither has one: empty (meaning "all allowed except blocked").
        let allow = match (self.allow.is_empty(), other.allow.is_empty()) {
            (false, false) => self.allow.iter()
                .filter(|t| other.allow.contains(t))
                .cloned()
                .collect(),
            (false, true) => self.allow.clone(),
            (true, false) => other.allow.clone(),
            (true, true) => vec![],
        };

        // --- Block list ---
        // Union of both block lists.
        let mut block = self.block.clone();
        for t in &other.block {
            if !block.contains(t) {
                block.push(t.clone());
            }
        }

        // --- Require confirmation ---
        // Union: if either requires confirmation, require it.
        let mut require_confirmation = self.require_confirmation.clone();
        for t in &other.require_confirmation {
            if !require_confirmation.contains(t) {
                require_confirmation.push(t.clone());
            }
        }

        // --- Default action ---
        // Most restrictive: if either is Deny, result is Deny.
        let default_action = match (&self.default_action, &other.default_action) {
            (Some(McpDefaultAction::Deny), _) | (_, Some(McpDefaultAction::Deny)) => {
                Some(McpDefaultAction::Deny)
            }
            (Some(McpDefaultAction::RequireConfirmation), _)
            | (_, Some(McpDefaultAction::RequireConfirmation)) => {
                Some(McpDefaultAction::RequireConfirmation)
            }
            _ => self.default_action.clone().or_else(|| other.default_action.clone()),
        };

        // --- Max args size ---
        // Smaller of the two (more restrictive).
        let max_args_size = match (self.max_args_size, other.max_args_size) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };

        Self {
            enabled: true,
            allow,
            block,
            require_confirmation,
            default_action,
            max_args_size,
            // Inheritance fields are not relevant for intersection.
            additional_allow: vec![],
            remove_allow: vec![],
            additional_block: vec![],
            remove_block: vec![],
        }
    }
}
```

### 4.3 Truth Table

| Enclave | Policy | Result | Reason |
|---------|--------|--------|--------|
| allow: [A, B] | allow: [B, C] | allow: [B] | Intersection of allow lists |
| block: [X] | block: [Y] | block: [X, Y] | Union of block lists |
| allow: [A] | block: [A] | block: [A] | Block takes precedence over allow |
| require_confirmation: [A] | allow: [A] | require_confirmation: [A] | Confirmation required if either says so |
| default_action: allow | default_action: deny | default_action: deny | Most restrictive wins |
| enabled: false | enabled: true | enabled: false | Disabled in either disables both |

### 4.4 Where Intersection Runs

In `engine.rs`, after enclave resolution and before guard categorization
(lines ~363-364 of `check_action_report()`):

```
policy.guards.mcp_tool  (base policy MCP config)
        |
        v
  intersect_with(enclave.mcp)  -->  effective_mcp_config
        |
        v
  McpToolGuard::new(effective_mcp_config)
        |
        v
  [existing guard pipeline]
```

The `additional_*` / `remove_*` fields on `McpToolConfig` are irrelevant
for `intersect_with()` because those are inheritance operators, not
projection operators. They are zeroed out in the intersection result.

---

## 5. Receipt Chain for Bridges

When a bridge crossing occurs, the engine emits a **bridge receipt** that
links the source context to the target context. This receipt sits between
the last receipt in the source enclave and the first receipt in the target
enclave.

### 5.1 Bridge Receipt Metadata

Bridge receipts use the existing `Receipt` struct with `merge_metadata()`.
No structural changes to `hush-core/src/receipt.rs`.

```json
{
  "version": "1.0.0",
  "receipt_id": "br-<uuid>",
  "timestamp": "2026-03-07T14:30:00Z",
  "content_hash": "<hash of BridgeRequest canonical JSON>",
  "verdict": { "pass": true },
  "metadata": {
    "clawdstrike": {
      "receipt_type": "bridge",
      "bridge": {
        "source_origin": {
          "provider": "slack",
          "space_id": "C123",
          "visibility": "internal"
        },
        "target_origin": {
          "provider": "github",
          "space_type": "issue",
          "space_id": "ISSUE#456"
        },
        "requested_capability": "mcp:github:create_comment",
        "decision": "allow",
        "capability_transfer": "read_only",
        "bridge_policy_id": "incident-room",
        "source_receipt_id": "r-<uuid-of-last-source-receipt>",
        "session_id": "ses-<uuid>"
      }
    }
  }
}
```

### 5.2 Receipt Chain Structure

```
[source enclave receipt N]
    content_hash: <action hash>
    metadata.clawdstrike.origin: { provider: "slack", ... }
    metadata.clawdstrike.enclave: { id: "incident-room" }
         |
         v
[bridge receipt]
    content_hash: <bridge request hash>
    metadata.clawdstrike.bridge.source_receipt_id: "r-<N>"
    metadata.clawdstrike.bridge.decision: "allow"
         |
         v
[target enclave receipt N+1]
    content_hash: <action hash>
    metadata.clawdstrike.origin: { provider: "github", ... }
    metadata.clawdstrike.enclave: { id: "code-review" }
    metadata.clawdstrike.bridge_receipt_id: "br-<uuid>"
```

The chain is linked by receipt IDs, not by cryptographic hash chaining.
Receipt IDs are sufficient because each receipt is independently signed
with the same Ed25519 keypair. Spine checkpoints provide tamper-evidence
for the sequence.

### 5.3 Delegation Graph Integration

Bridge crossings are recorded in the delegation graph (Phase 4.5) as:

- **Node kind:** `Bridge` (new variant in `DelegationGraphNodeKind`)
- **Edge kind:** `BridgedTo` (new variant in `DelegationGraphEdgeKind`)
- **Grant type:** `"bridge"` (added to `validate_grant_type()` at line 1785)
- **Grant context JSON:** contains `source_origin`, `target_origin`,
  `capability_transfer`, `bridge_policy_id`

This allows lineage queries to trace cross-origin paths:
"Show me every origin this agent touched, and through which bridges."

---

## 6. Open Questions

### 6.1 Should bridge policies be bidirectional or unidirectional?

**Current design: unidirectional.** The `BridgePolicy` on enclave A controls
whether A can bridge *to* other origins. It says nothing about whether other
origins can bridge *to* A.

Bidirectional would require a second field (`inbound_bridge_policy`) on each
enclave. This adds complexity. The unidirectional model is simpler and covers
the primary use case: "this incident room can reach out to GitHub issues."

If bidirectional is needed later, it can be added as an `inbound` field on
`BridgePolicy` without breaking the existing `allowed_targets` (outbound)
semantics.

**Recommendation:** Ship unidirectional in Phase 4.3. Revisit if customer
feedback demands inbound controls.

### 6.2 How do transitive bridges work (A -> B -> C)?

The current design evaluates each hop independently:

1. Agent in enclave A requests bridge to B. A's `BridgePolicy` is checked.
2. Agent in enclave B requests bridge to C. B's `BridgePolicy` is checked.

There is no global "path policy" that governs A -> B -> C as a unit. Each
hop stands alone.

**Risk:** An agent could chain through permissive enclaves to reach a
target that the original enclave would not allow directly (A blocks C,
but A allows B, and B allows C).

**Mitigations (not in Phase 4.3, candidates for Phase 7):**

- **Max bridge depth per session.** Add `max_bridge_hops: Option<u32>` to
  `BridgePolicy`. Default: 1 (no transitive bridges). The engine tracks
  hop count in `EngineState`.
- **Origin chain in bridge request.** Extend `BridgeRequest` with
  `origin_chain: Vec<OriginContext>` so each hop can inspect the full path.
- **Transitive deny rules.** A new policy field that says "if the agent
  originally came from provider X, deny bridge regardless of intermediate
  hops."

**Recommendation:** Ship with `max_bridge_hops` defaulting to 1, which
effectively disables transitive bridges. This is fail-closed. Operators
who want A -> B -> C explicitly set `max_bridge_hops: 2` on A's policy.

### 6.3 Should bridges have TTL?

**Yes, but via the existing grant system, not a new mechanism.**

When `require_approval: true`, the bridge approval creates an `origin_grant`
(INDEX.md section 4) with `ttl_seconds`. The grant expires, and subsequent
bridge attempts require re-approval.

When `require_approval: false` (unconditional bridge), the bridge is valid
for the session lifetime. There is no separate bridge TTL because the
session itself is the scope boundary. If the session ends, the bridge is
implicitly revoked.

If finer-grained TTL is needed for unconditional bridges, add
`bridge_ttl_seconds: Option<u32>` to `BridgePolicy` in a later phase.
The engine would track bridge grant time in `EngineState` and deny if
elapsed time exceeds TTL.

**Recommendation:** No separate bridge TTL in Phase 4.3. Session scope
and approval grants cover the primary cases.

---

## Summary of Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| DM default (internal) | Minimal read-only profile | Low risk, good UX |
| DM default (external) | Deny | High risk, fail-closed |
| MCP composition | `intersect_with()` (new method) | Most restrictive wins; distinct from `merge_with()` |
| Bridge direction | Unidirectional (outbound only) | Simpler, covers primary use case |
| Transitive bridges | Disabled by default (`max_bridge_hops: 1`) | Fail-closed; opt-in for multi-hop |
| Bridge TTL | Session-scoped; approval grants use existing TTL | No new mechanism needed |
| Bridge receipts | Existing `Receipt` + metadata convention | No struct changes to hush-core |
| Delegation graph | New `Bridge` node kind + `BridgedTo` edge kind | Traceable cross-origin lineage |

These decisions feed directly into Phase 0.2 (`OriginProfile.bridge` field shape)
and Phase 4.3 (`bridge.rs` implementation).
