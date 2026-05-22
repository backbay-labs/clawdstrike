# 01 - Requirements

## Goals

### G1: Kernel-Enforced Sandbox for `hush run`
Replace the ad-hoc `sandbox-exec`/`bwrap` wrappers with nono's cross-platform `CapabilitySet` + `Sandbox::apply()` API. Child processes spawned by `hush run` must be structurally constrained by the OS kernel.

### G2: Policy-Driven Capability Construction
Derive nono `CapabilitySet` from ClawdStrike policy YAML. Guard configurations (forbidden paths, egress allowlists, command restrictions) should inform what capabilities are granted to the sandbox. A strict policy should produce a tighter sandbox.

### G3: Attestation of Enforcement
Include nono sandbox state in signed receipts. Receipts must attest not just to what violations were *observed* but what restrictions were *enforced* at the kernel level.

### G4: Dynamic Enforcement via Supervisor (Stretch)
Use nono's supervisor IPC (seccomp-notify on Linux, Seatbelt extensions on macOS) to route runtime capability requests through ClawdStrike guards. Every file access intercepted by the kernel triggers guard evaluation before the fd is injected.

## Non-Goals

### NG1: Replace Guards with Kernel Enforcement
Guards provide semantic, context-aware policy decisions (prompt injection, secret leak detection, jailbreak detection, MCP tool filtering). These cannot be expressed at the kernel level. Guards remain the primary policy engine; nono adds structural enforcement for what the kernel *can* express.

### NG2: Full Glob Pattern Translation
ClawdStrike uses glob patterns like `**/.env*` that match anywhere in the filesystem tree. Nono requires fixed, canonical paths. Exhaustive enumeration of all possible glob matches is not feasible. Accept that kernel enforcement is coarser than guard-level enforcement.

### NG3: Domain-Level Network Filtering in Kernel
Nono/Landlock filters by TCP port, not by hostname. Domain-level filtering continues to be handled by the HTTP CONNECT proxy. The kernel enforces `NetworkMode::ProxyOnly` to ensure traffic routes through the proxy.

### NG4: Content Inspection in Kernel
Guards that inspect file content (SecretLeakGuard), command arguments (ShellCommandGuard regex patterns), or user input (JailbreakGuard, PromptInjectionGuard) remain application-level. The kernel sandbox does not inspect payloads.

## Success Criteria

| ID | Criterion | Measurement |
|----|-----------|-------------|
| SC1 | `hush run` on macOS uses Seatbelt via nono instead of `sandbox-exec` | Integration test: sandbox blocks access to `~/.ssh/id_rsa` |
| SC2 | `hush run` on Linux uses Landlock via nono instead of `bwrap` | Integration test: sandbox blocks access to `/etc/shadow` |
| SC3 | Policy YAML with `forbidden_path` patterns produces a `CapabilitySet` that excludes those paths | Unit test: capability set does not cover forbidden paths |
| SC4 | Policy YAML with `egress_allowlist` produces `NetworkMode::ProxyOnly` when proxy is enabled | Unit test: network mode matches policy |
| SC5 | Receipts include `sandbox` metadata with enforced capabilities | Receipt JSON contains `sandbox.capabilities` field |
| SC6 | `QueryContext` validates policy-derived capabilities match guard expectations | Pre-flight check: no false denials for allowed paths |
| SC7 | (Stretch) Supervisor intercepts unauthorized file access and routes through guard evaluation | Integration test: seccomp-notify triggers guard check |

## Constraints

### C1: nono Library Applies to Current Process
`Sandbox::apply()` restricts the *calling* process. For child process sandboxing, the sandbox must be applied after `fork()` but before `exec()`. This matches nono-cli's `Supervised` execution strategy.

**Code ref**: `nono/crates/nono/src/sandbox/mod.rs:77-101`

### C2: Landlock Is Strictly Allow-List
Linux Landlock has no deny semantics. You cannot express "allow everything except `/etc/shadow`". The sandbox starts with zero access and you grant paths explicitly. ClawdStrike's deny-oriented policies (ForbiddenPathGuard) must be inverted: start from allowed paths, omit forbidden ones.

**Code ref**: `nono/crates/nono/src/sandbox/linux.rs:88-253`

### C3: Seatbelt Supports Deny Rules (macOS Only)
macOS Seatbelt can express both allow and deny rules. Nono already translates deny groups to Seatbelt platform rules: `(deny file-read-data (subpath "PATH"))`. This is a macOS-specific advantage.

**Code ref**: `nono/crates/nono-cli/src/policy.rs:437-475`

### C4: Path Must Exist for Canonicalization
`FsCapability::new_dir()` and `new_file()` call `canonicalize()`, which requires the path to exist. Paths that don't exist at sandbox creation time cannot be granted. This affects dynamic working directories.

**Code ref**: `nono/crates/nono/src/capability.rs:89-117`

### C5: Irrevocable Once Applied
Once `Sandbox::apply()` succeeds, there is no API to expand permissions (except via supervisor extensions). The capability set must be complete before application.

**Code ref**: `nono/crates/nono/src/sandbox/mod.rs:77-101`

### C6: hush run Process Model
ClawdStrike's `hush run` currently uses `Command::new().spawn()` (not fork+exec). Integrating nono's supervised execution requires switching to fork+exec with sandbox application in the child before exec.

**Code ref**: `clawdstrike/crates/services/hush-cli/src/hush_run.rs:787-833`

## Dependencies

| Dependency | Version | Purpose |
|------------|---------|---------|
| `nono` (library crate) | 0.11.x | `CapabilitySet`, `Sandbox`, `QueryContext`, `SandboxState` |
| `landlock` | 0.4 | Linux kernel sandbox (transitive via nono) |
| `nix` | 0.31 | Unix syscalls for fork/exec (transitive via nono) |
| `libc` | latest | Raw FFI for Seatbelt, seccomp-notify (transitive via nono) |

## Platform Matrix

| Feature | Linux (Landlock) | macOS (Seatbelt) |
|---------|-----------------|------------------|
| Filesystem allow-list | ABI v1+ | Always |
| Filesystem deny rules | Not supported | Seatbelt platform rules |
| Network port filtering | ABI v4+ | Always |
| Network domain filtering | Via proxy only | Via proxy only |
| Signal isolation | Not supported | `(deny signal (target others))` |
| File deletion prevention | `AccessFs::RemoveFile` | `(deny file-write-unlink)` |
| Command blocking | Via blocked_commands list | Via blocked_commands list |
| Sandbox extensions | seccomp-notify + fd inject | `sandbox_extension_issue/consume` |
| Supervisor IPC | Unix socket + SCM_RIGHTS | Unix socket + extension tokens |
