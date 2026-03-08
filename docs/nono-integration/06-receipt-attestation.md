# 06 - Receipt Attestation

Extend ClawdStrike's receipt system to attest to kernel-level enforcement, not just advisory observations.

## Current Receipt System

**File**: `clawdstrike/crates/libs/hush-core/src/receipt.rs`

### Receipt Structure

```rust
// receipt.rs:157-175
struct Receipt {
    version: String,            // "1.0.0"
    receipt_id: Option<String>,
    timestamp: String,          // ISO-8601
    content_hash: Hash,         // SHA-256 of what was verified
    verdict: Verdict,           // pass/fail
    provenance: Option<Provenance>,
    metadata: Option<JsonValue>,
}

// receipt.rs:62-73
struct Verdict {
    passed: bool,
    gate_id: Option<String>,
    scores: Option<JsonValue>,
    threshold: Option<f64>,
}

// receipt.rs:136-152
struct Provenance {
    clawdstrike_version: Option<String>,
    provider: Option<String>,
    policy_hash: Option<Hash>,
    ruleset: Option<String>,
    violations: Vec<ViolationRef>,
}

// receipt.rs:121-131
struct ViolationRef {
    guard: String,
    severity: String,
    message: String,
    action: Option<String>,
}
```

### Current Semantics

Today, a receipt attests: "We **observed** these violations during execution."

The verdict reflects what guards detected, but violations were not prevented. A receipt with `passed: false` means "the agent did something bad and we noticed" — not "the agent was prevented from doing something bad."

### Signing

**File**: `receipt.rs:289-406`

```rust
struct SignedReceipt {
    receipt: Receipt,
    signatures: Signatures,  // Ed25519 primary + optional cosigner
}
```

Receipts are signed with Ed25519 keypairs. Verification checks all signatures and returns `VerificationResult` with error codes.

## Enhanced Receipt with Sandbox Attestation

### New Metadata Schema

Add a `sandbox` field to receipt metadata that describes the kernel enforcement applied:

```json
{
  "version": "1.0.0",
  "receipt_id": "receipt-uuid",
  "timestamp": "2026-03-07T12:00:00Z",
  "content_hash": "sha256:abc123...",
  "verdict": {
    "passed": true,
    "gate_id": "hush-run-session-xyz"
  },
  "provenance": {
    "clawdstrike_version": "0.2.5",
    "policy_hash": "sha256:def456...",
    "ruleset": "default",
    "violations": []
  },
  "metadata": {
    "sandbox": {
      "enforced": false,
      "enforcement_level": "degraded",
      "platform": {
        "name": "macos",
        "mechanisms": ["seatbelt", "endpoint_security"],
        "abi_version": null,
        "details": "Seatbelt base sandbox with EndpointSecurity provider installed but degraded"
      },
      "capabilities": {
        "fs": [
          {
            "original": "/home/user/project",
            "resolved": "/home/user/project",
            "access": "ReadWrite",
            "is_file": false
          },
          {
            "original": "/usr",
            "resolved": "/usr",
            "access": "Read",
            "is_file": false
          }
        ],
        "net_blocked": false,
        "network_mode": "MediatedEgress",
        "proxy_port": null,
        "signal_mode": "Isolated",
        "blocked_commands": ["rm", "sudo", "dd"],
        "extensions_enabled": true
      },
      "provider_states": [
        {
          "provider": "seatbelt",
          "installed": true,
          "active": true,
          "healthy": true,
          "degraded_reason": null
        },
        {
          "provider": "endpoint_security",
          "installed": true,
          "active": true,
          "healthy": false,
          "degraded_reason": "full-disk-access-missing"
        },
        {
          "provider": "network_extension",
          "installed": true,
          "active": true,
          "healthy": true,
          "degraded_reason": null
        }
      ],
      "supervisor": {
        "enabled": true,
        "backend": "clawdstrike-guard-supervisor",
        "requests_total": 47,
        "requests_granted": 42,
        "requests_denied": 5,
        "never_grant_blocks": 2,
        "rate_limit_blocks": 0
      },
      "denials": [
        {
          "path": "/home/user/.ssh/id_rsa",
          "access": "Read",
          "reason": "PolicyBlocked",
          "timestamp": "2026-03-07T12:01:23Z"
        }
      ],
      "audit": [
        {
          "timestamp": "2026-03-07T12:00:05Z",
          "path": "/home/user/project/src/main.rs",
          "access": "Read",
          "decision": "Granted",
          "backend": "clawdstrike-guard-supervisor",
          "duration_ms": 2
        }
      ]
    }
  }
}
```

### Implementation

#### SandboxAttestation Type

New type in ClawdStrike with **custom serialization**. We cannot directly wrap nono's
`SandboxState` because it only contains `fs: Vec<FsCapState>` and `net_blocked: bool` —
it lacks `network_mode`, `proxy_port`, `signal_mode`, `blocked_commands`, and
`extensions_enabled`. Similarly, nono's `DenialRecord` does not derive `Serialize`/
`Deserialize` and has no `timestamp` field. `CapabilitySet` itself does not implement serde.

Therefore, `SandboxAttestation` must define its own serializable types:

```rust
// NOTE: These are ClawdStrike-owned types, NOT re-exports from nono.
// They are built by reading nono's CapabilitySet accessors, not by
// wrapping SandboxState.

#[derive(Serialize, Deserialize)]
pub struct SandboxAttestation {
    /// Whether kernel enforcement was active
    pub enforced: bool,
    /// Enforcement level after provider health is evaluated
    pub enforcement_level: EnforcementLevel,
    /// Platform details
    pub platform: PlatformInfo,
    /// Serialized capability details (custom, NOT nono::SandboxState)
    pub capabilities: CapabilitySnapshot,
    /// Per-provider install, health, and degraded-state snapshot
    pub provider_states: Vec<ProviderState>,
    /// Supervisor statistics (if Phase 4)
    pub supervisor: Option<SupervisorStats>,
    /// Denied operations (with timestamps, unlike nono's DenialRecord)
    pub denials: Vec<TimestampedDenial>,
    /// Audit trail of supervisor decisions
    pub audit: Vec<AuditEntry>,
}

/// Built from CapabilitySet accessors, not from SandboxState.
#[derive(Serialize, Deserialize)]
pub struct CapabilitySnapshot {
    pub fs: Vec<FsCapSnapshot>,
    pub network_mode: String,         // "Blocked" | "AllowAll" | "MediatedEgress" | "ProxyOnly" (legacy runtime only)
    pub proxy_port: Option<u16>,
    pub signal_mode: String,          // "Isolated" | "AllowAll"
    pub blocked_commands: Vec<String>,
    pub extensions_enabled: bool,
}

#[derive(Serialize, Deserialize)]
pub struct FsCapSnapshot {
    pub original: String,
    pub resolved: String,
    pub access: String,
    pub is_file: bool,
}

#[derive(Serialize, Deserialize)]
pub struct TimestampedDenial {
    pub path: String,
    pub access: String,
    pub reason: String,
    pub timestamp: String,  // ISO-8601, added by ClawdStrike
}

#[derive(Serialize, Deserialize)]
pub struct ProviderState {
    pub provider: String,         // "seatbelt" | "endpoint_security" | "network_extension"
    pub installed: bool,
    pub active: bool,
    pub healthy: bool,
    pub degraded_reason: Option<String>,
}

pub enum EnforcementLevel {
    /// No kernel enforcement (legacy mode)
    None,
    /// Static sandbox (Phase 1-2)
    Kernel,
    /// Dynamic supervisor enforcement (Phase 3)
    KernelSupervised,
    /// Kernel surfaces existed but one or more required providers were unavailable or unhealthy
    Degraded,
}

pub struct PlatformInfo {
    pub name: String,        // "linux" | "macos" (from Sandbox::support_info().platform)
    pub mechanisms: Vec<String>,  // derived from active platform providers, not a single hard-coded string
    pub abi_version: Option<u32>,
    pub details: String,
}

pub struct SupervisorStats {
    pub enabled: bool,
    pub backend: String,
    pub requests_total: u64,
    pub requests_granted: u64,
    pub requests_denied: u64,
    pub never_grant_blocks: u64,
    pub rate_limit_blocks: u64,
}
```

#### Building the Attestation

In `cmd_run()` after child exits:

```rust
// After child exit, build sandbox attestation
// Build CapabilitySnapshot from CapabilitySet accessors (not SandboxState)
let cap_snapshot = CapabilitySnapshot {
    fs: caps.fs_capabilities().iter().map(|c| FsCapSnapshot {
        original: c.original.to_string_lossy().into_owned(),
        resolved: c.resolved.to_string_lossy().into_owned(),
        access: format!("{:?}", c.access),
        is_file: c.is_file,
    }).collect(),
    network_mode: derive_network_mode_for_attestation(&caps, &provider_states),
    proxy_port: match caps.network_mode() {
        NetworkMode::ProxyOnly { port, .. } => Some(*port),
        _ => None,
    },
    signal_mode: format!("{:?}", caps.signal_mode()),
    blocked_commands: caps.blocked_commands().to_vec(),
    extensions_enabled: caps.extensions_enabled(),
};

let support = Sandbox::support_info();
let providers_healthy = provider_states.iter().all(|p| p.active && p.healthy);
let sandbox_attestation = SandboxAttestation {
    enforced: support.is_supported && providers_healthy,
    enforcement_level: if !providers_healthy {
        EnforcementLevel::Degraded
    } else if supervisor_enabled {
        EnforcementLevel::KernelSupervised
    } else {
        EnforcementLevel::Kernel
    },
    platform: PlatformInfo {
        name: support.platform.to_string(),
        mechanisms: derive_platform_mechanisms(&provider_states),
        abi_version: None, // filled per-platform
        details: support.details,
    },
    capabilities: cap_snapshot,
    provider_states,
    supervisor: supervisor_stats,
    denials: denial_records,  // Vec<TimestampedDenial>, built during execution
    audit: audit_entries,
};

// Merge into receipt metadata
let sandbox_json = serde_json::to_value(&sandbox_attestation)?;
receipt.merge_metadata(json!({ "sandbox": sandbox_json }));
```

**Code ref for merge_metadata**: `receipt.rs:213-220`

### Verdict Semantics Change

With kernel enforcement, the verdict semantics change:

| Scenario | Before (Advisory) | After (Enforced) |
|----------|-------------------|------------------|
| Agent tried to read ~/.ssh/id_rsa | `passed: false` (violation observed) | `passed: true` (violation prevented, noted in denials) |
| Agent wrote to allowed path | `passed: true` | `passed: true` |
| Agent tried unknown egress | `passed: false` (proxy logged violation) | `passed: true` only if mediated egress was active and the provider actually blocked it |
| ES provider missed a deadline | `passed: false` or not represented | never claim fully enforced success; receipt must record degraded or unavailable enforcement |

The key insight: **enforcement changes verdicts from "we saw bad things happen" to "bad things were prevented," but only while the required providers were actually healthy.** A receipt with `enforced: true` and `passed: true` means the agent operated within its sandbox successfully, and any attempted violations were structurally prevented. If a required provider was inactive, unhealthy, or degraded, the receipt must say so instead of silently claiming success.

A degraded receipt is intentionally different from an enforced receipt. It can still contain useful audit evidence, but it must not be treated as proof that the platform actually enforced the intended policy end to end.

Violations in `provenance.violations` now mean "the agent attempted these operations, and they were blocked":

```json
{
  "verdict": { "passed": true },
  "provenance": {
    "violations": [
      {
        "guard": "ForbiddenPathGuard",
        "severity": "Error",
        "message": "Attempted access to ~/.ssh/id_rsa (blocked by kernel sandbox)",
        "action": "FileAccess"
      }
    ]
  },
  "metadata": {
    "sandbox": {
      "enforced": true,
      "denials": [
        { "path": "~/.ssh/id_rsa", "reason": "PolicyBlocked" }
      ]
    }
  }
}
```

### Receipt Verification Enhancement

Verifiers can now check enforcement claims:

```rust
impl SignedReceipt {
    /// Check if this receipt attests to kernel-level enforcement
    pub fn is_kernel_enforced(&self) -> bool {
        self.receipt.metadata
            .as_ref()
            .and_then(|m| m.get("sandbox"))
            .and_then(|s| s.get("enforced"))
            .and_then(|e| e.as_bool())
            .unwrap_or(false)
    }

    /// Get the enforcement level
    pub fn enforcement_level(&self) -> EnforcementLevel {
        self.receipt.metadata
            .as_ref()
            .and_then(|m| m.get("sandbox"))
            .and_then(|s| s.get("enforcement_level"))
            .and_then(|l| l.as_str())
            .map(EnforcementLevel::from_str)
            .unwrap_or(EnforcementLevel::None)
    }
}
```

### Integration with Posture System

Sandbox enforcement state can feed into posture transitions:

```yaml
# Policy with posture + sandbox awareness
posture:
  initial: "standard"
  states:
    standard:
      capabilities: [file_read, file_write, egress]
      budgets:
        file_writes: 100
    restricted:
      capabilities: [file_read]
      budgets:
        file_writes: 0
  transitions:
    - from: standard
      to: restricted
      trigger: critical_violation
```

When the supervisor denies a never_grant path access, this can trigger a `CriticalViolation` posture transition, tightening both the guard policy and (potentially) the sandbox.

### Spine Integration

For distributed attestation, the sandbox state is included in Spine signed envelopes:

```rust
// Checkpoint includes sandbox attestation hash
let checkpoint = Checkpoint {
    receipt_hash: receipt.hash_sha256(),
    sandbox_state_hash: sandbox_attestation.hash(),
    timestamp: now(),
};

let envelope = SignedEnvelope::sign(checkpoint, &keypair);
spine_client.publish(envelope).await?;
```

This allows downstream SIEM/SOAR systems to verify that enforcement was active when the receipt was generated.

## Code References

| File | Lines | Content |
|------|-------|---------|
| `hush-core/src/receipt.rs` | 157-175 | Receipt struct definition |
| `hush-core/src/receipt.rs` | 62-73 | Verdict struct |
| `hush-core/src/receipt.rs` | 136-152 | Provenance struct |
| `hush-core/src/receipt.rs` | 213-220 | `merge_metadata()` |
| `hush-core/src/receipt.rs` | 289-406 | SignedReceipt, signing, verification |
| `hush_run.rs` | 498-515 | Current receipt creation |
| `nono/src/state.rs` | 34-48 | `SandboxState::from_caps()` |
| `nono/src/state.rs` | 87-91 | `SandboxState::to_json()` |
| `nono/src/sandbox/mod.rs` | 124-143 | `Sandbox::support_info()` |
| `nono/src/diagnostic.rs` | 34-42 | `DenialRecord` struct |
