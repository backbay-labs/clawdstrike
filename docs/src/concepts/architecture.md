# Architecture

Hushclaw is a guard suite and attestation primitives for agent runtimes.
It is **not** an operating system sandbox: it will not automatically intercept syscalls or “wrap” a process.

The intended integration is at the **tool boundary** (your agent runtime calls Hushclaw before performing actions).

## Components

- `hushclaw` (Rust): policy type, built-in guards, `HushEngine`
- `hush-core` (Rust): hashing/signing, Merkle trees, `SignedReceipt`
- `hush-proxy` (Rust): DNS/SNI parsing utilities and domain matching
- `hush-cli` (Rust): `hush` CLI for ad-hoc checks and verification
- `hushd` (Rust, optional): HTTP daemon for centralized checks (WIP)

## Data flow (typical integration)

1. Your agent runtime wants to do an action (read a file, call a tool, make a network request).
2. Your runtime constructs a `GuardAction` (e.g. `FileAccess`, `NetworkEgress`, `McpTool`) and a `GuardContext`.
3. Your runtime calls `HushEngine::check_*` (or `check_action_report` for per-guard evidence).
4. Your runtime uses the returned `GuardResult` to allow, warn, or block the action.
5. Optionally, your runtime creates a signed receipt (`create_signed_receipt`) for a content hash that represents the run output/artifacts.

## What Hushclaw can and cannot enforce

Hushclaw can enforce only what your runtime routes through it. If an agent has direct access to the filesystem/network without going through your tool layer, Hushclaw cannot stop it.

## Threat model (explicit)

### Attacker

- Untrusted agent output (LLM-generated tool calls, patches, commands).
- Prompt-injection content that tries to influence tool usage.
- Accidental operator error (overly broad allowlists, unsafe tools enabled).

### Assets to protect

- Local secrets and credentials (SSH keys, `.env`, cloud creds).
- Network egress destinations (exfil to arbitrary hosts).
- Repository integrity (unsafe patches, disabling checks).
- Auditability (what happened, under which policy, with what evidence).

### Enforcement points

- **Tool boundary**: your runtime must call `HushEngine::check_*` before performing an action.
- **Policy validation**: malformed patterns are rejected at policy load time (fail-closed).
- **Receipts**: cryptographically signed artifacts that record results + provenance for later verification.

### Non-goals / limitations

- No syscall interception, sandbox escape prevention, or kernel-level isolation.
- Cannot stop actions that bypass the runtime/tool layer (direct FS/net access).
- Does not guarantee secrecy against a fully compromised host or OS-level attacker.

## Enforced vs attested (don’t conflate these)

- **Enforced**: the action your runtime *chose not to perform* because a guard returned `allowed=false` (or required confirmation).
- **Attested**: what Hushclaw recorded in a `Receipt`/`SignedReceipt` (policy hash, verdict, violations, timestamps).

Receipts are only as strong as the integration: they prove what Hushclaw *observed/decided* under a specific policy, not that the underlying OS prevented all side effects.
