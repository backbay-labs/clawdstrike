# 02 - Architecture

## Current State: Advisory Only

```
hush run policy.yaml -- agent-command
  |
  +-- Load policy, create HushEngine
  +-- Start HTTP CONNECT proxy (optional)
  +-- Prepare sandbox wrapper (optional, basic)
  |     macOS: sandbox-exec -f profile (hardcoded denies)
  |     Linux: bwrap with bind mounts
  +-- Command::new().spawn() child
  |     Child runs with UNRESTRICTED access
  |     Proxy observes CONNECT requests
  +-- Wait for child exit
  +-- Guards evaluate observed traffic (after the fact)
  +-- Generate receipt (advisory verdict)
  +-- Exit with policy-determined code
```

**Key problem**: Guards produce verdicts but don't prevent operations. The child has full OS permissions. The optional sandbox wrapper is not integrated with policy.

### Current Integration Points

| Component | File | Line | Current Behavior |
|-----------|------|------|-----------------|
| Sandbox creation | `hush_run.rs` | 690 | `maybe_prepare_sandbox()` — hardcoded deny paths |
| macOS profile gen | `hush_run.rs` | 746 | `generate_macos_sandbox_profile()` — static Seatbelt |
| Child spawn | `hush_run.rs` | 787 | `spawn_and_wait_child()` — `Command::new().spawn()` |
| Proxy start | `hush_run.rs` | 836 | `start_connect_proxy()` — CONNECT tunnel |
| Guard evaluation | `engine.rs` | 352 | `check_action_report()` — advisory pipeline |
| Receipt creation | `hush_run.rs` | 498 | `Receipt::new()` — no sandbox attestation |

## Target State: Kernel-Enforced

```
hush run policy.yaml -- agent-command
  |
  +-- Load policy, create HushEngine
  +-- Translate policy -> CapabilitySet (NEW)
  |     ForbiddenPathGuard patterns -> omit from cap set
  |     PathAllowlistGuard -> direct cap set mapping
  |     EgressAllowlistGuard -> NetworkMode::ProxyOnly
  |     ShellCommandGuard -> blocked_commands
  +-- Pre-flight: QueryContext validates cap set (NEW)
  +-- Start HTTP CONNECT proxy (if egress policy exists)
  +-- fork() (CHANGED from Command::spawn)
  |
  +-- CHILD (sandboxed):
  |     Apply Sandbox::apply(&caps)  (kernel enforcement)
  |     [Linux] Install seccomp-notify filter (optional)
  |     exec(agent-command)
  |     ALL operations constrained by kernel
  |
  +-- PARENT (unsandboxed):
  |     [Optional] Run supervisor loop
  |       Receive seccomp notifications
  |       Route through HushEngine guards
  |       Inject fd or deny
  |     Forward signals to child
  |     Wait for child exit
  |     Guards evaluate proxy traffic (network)
  |
  +-- Generate receipt with sandbox state (CHANGED)
  |     Includes enforced CapabilitySet
  |     Includes SandboxState JSON
  +-- Exit with policy-determined code
```

## Component Architecture

### New Components

```
clawdstrike/crates/libs/clawdstrike/src/
  sandbox/                      # NEW module
    mod.rs                      # SandboxPolicy facade
    capability_builder.rs       # Policy -> CapabilitySet translation
    preflight.rs                # QueryContext validation

clawdstrike/crates/services/hush-cli/src/
  sandbox_nono.rs               # NEW: replaces maybe_prepare_sandbox()
  supervised_exec.rs            # NEW: fork+exec with nono sandbox
```

### Data Flow

```
                    Policy YAML
                        |
                        v
              +-------------------+
              |   HushEngine      |
              |   (guard config)  |
              +-------------------+
                   |          |
           guard   |          |  sandbox
           eval    |          |  construction
                   v          v
              +---------+  +--------------------+
              | Guards  |  | CapabilityBuilder   |
              | (13+)   |  | policy_to_caps()    |
              +---------+  +--------------------+
                   |              |
                   |              v
                   |       +-------------+
                   |       | QueryContext |
                   |       | (pre-flight) |
                   |       +-------------+
                   |              |
                   v              v
              +--------+   +------------+
              |Receipts|   | Sandbox    |
              |+sandbox|   | ::apply()  |
              | state  |   +------------+
              +--------+         |
                                 v
                          +-------------+
                          | Kernel      |
                          | Enforcement |
                          +-------------+
```

### Integration with Existing Systems

#### IRM → Sandbox Validation

The IRM monitors (FilesystemIrm, NetworkIrm, ExecutionIrm) currently produce advisory `Decision` values. With nono integration:

1. **FilesystemIrm** forbidden paths → paths omitted from `CapabilitySet`
2. **NetworkIrm** allowed hosts → `NetworkMode::ProxyOnly` forces traffic through proxy where hosts are checked
3. **ExecutionIrm** blocked commands → `CapabilitySet::block_command()`

The IRM continues to run at the proxy/application level for traffic that passes kernel checks.

**Code refs**:
- `clawdstrike/crates/libs/clawdstrike/src/irm/fs.rs:26-61` — forbidden path patterns
- `clawdstrike/crates/libs/clawdstrike/src/irm/net.rs:122-188` — host allowlist
- `clawdstrike/crates/libs/clawdstrike/src/irm/exec.rs:75-99` — dangerous command patterns

#### Guard → CapabilityBuilder

Each guard type maps to a specific aspect of the `CapabilitySet`:

| Guard | CapabilitySet Effect | Enforcement Level |
|-------|---------------------|-------------------|
| ForbiddenPathGuard | Omit forbidden paths from grants | Kernel (allow-list) |
| PathAllowlistGuard | Direct mapping to `allow_path()` calls | Kernel (allow-list) |
| EgressAllowlistGuard | `NetworkMode::ProxyOnly` + proxy port | Kernel (port) + App (domain) |
| ShellCommandGuard | `block_command()` for known-dangerous | App (name check pre-exec) + App (regex) |
| SecretLeakGuard | No kernel equivalent | App only |
| PatchIntegrityGuard | No kernel equivalent | App only |
| McpToolGuard | No kernel equivalent | App only |
| PromptInjectionGuard | No kernel equivalent | App only |
| JailbreakGuard | No kernel equivalent | App only |
| ComputerUseGuard | No kernel equivalent | App only |

#### Proxy → Network Enforcement

The existing CONNECT proxy provides domain-level filtering. With nono:

1. Nono enforces `NetworkMode::ProxyOnly { port }` at kernel level
2. All outbound traffic must go through the proxy
3. Proxy performs domain allowlist checks via guards
4. Direct connections bypass is **structurally impossible** (kernel blocks non-proxy ports)

**Code refs**:
- `clawdstrike/crates/services/hush-cli/src/hush_run.rs:836-898` — proxy start
- `nono/crates/nono/src/capability.rs:514-520` — `proxy_only()` builder

#### Receipts → Sandbox Attestation

Current receipt structure (advisory):
```json
{
  "verdict": { "passed": false },
  "provenance": { "violations": [...] }
}
```

With nono (enforced). Note: the `capabilities` field is a custom `CapabilitySnapshot`
built from `CapabilitySet` accessors, NOT nono's `SandboxState` (which only has `fs` and
`net_blocked`). See [06-receipt-attestation.md](06-receipt-attestation.md) for full schema.

```json
{
  "verdict": { "passed": true },
  "provenance": { "violations": [...] },
  "metadata": {
    "sandbox": {
      "enforced": true,
      "platform": { "name": "linux", "mechanism": "landlock", "abi_version": 5 },
      "capabilities": {
        "fs": [
          { "resolved": "/usr", "access": "Read", "is_file": false },
          { "resolved": "/project", "access": "ReadWrite", "is_file": false }
        ],
        "network_mode": "ProxyOnly",
        "proxy_port": 8080,
        "signal_mode": "Isolated",
        "blocked_commands": ["rm", "sudo", "dd"]
      }
    }
  }
}
```

**Code refs**:
- `clawdstrike/crates/libs/hush-core/src/receipt.rs:157-245` — Receipt struct
- `nono/crates/nono/src/capability.rs:721-789` — CapabilitySet accessors (fs_capabilities, network_mode, etc.)

## Execution Strategies

### Strategy 1: Static Sandbox (Phase 1-2)

```
Parent: build CapabilitySet from policy
        fork()
Child:  Sandbox::apply(&caps)
        exec(command)
Parent: wait + generate receipt
```

- Simple, no IPC
- All capabilities determined before execution
- Cannot handle dynamic path requests

### Strategy 2: Supervised Sandbox (Phase 4)

```
Parent: build CapabilitySet from policy
        create supervisor socket pair
        fork()
Child:  Sandbox::apply(&caps)
        install seccomp-notify (Linux) / enable extensions (macOS)
        exec(command)
Parent: supervisor loop:
          receive seccomp notification / extension request
          read path from child /proc/PID/mem
          check never_grant list
          route through HushEngine guards
          if approved: inject fd / issue extension token
          if denied: send EPERM / deny
          log to receipt
        wait + generate receipt
```

- Full dynamic enforcement
- Every file access is guard-evaluated AND kernel-enforced
- Requires fork+exec (not `Command::spawn()`)
- Higher latency per file operation

## Threading Considerations

ClawdStrike's `hush run` uses Tokio async runtime. Nono's supervised execution requires `fork()`, which is unsafe in multi-threaded processes. Options:

1. **Fork before Tokio, start proxy after**: Fork first (single-threaded), then start the Tokio runtime in the parent. The proxy starts after fork, so the child must inherit the proxy port (e.g., via env var or pre-allocated port). The child cannot make network requests until the proxy is ready, but the kernel's `ProxyOnly` mode ensures it cannot bypass the proxy regardless.
2. **Pre-fork pattern**: Use `unsafe { fork() }` with careful thread management, similar to nono-cli's `ThreadingContext::Strict` check. Validate thread count before fork.
3. **Separate process**: Spawn nono-cli as a subprocess that manages the sandbox, communicate via pipe/socket.

Recommended: Option 1 (fork before Tokio) for simplest integration. The parent starts the async runtime after fork for proxy/event handling.

> **IMPORTANT**: The child MUST close inherited fds (proxy listening socket, log handles)
> via `close_inherited_fds()` before exec. Without this, the child could impersonate the
> proxy or leak sensitive resources. See nono-cli's `exec_strategy.rs:493` for reference.
>
> Also note that `Sandbox::apply()` in the child must NOT use Rust's `?` operator post-fork.
> Only async-signal-safe operations are permitted. Errors must use raw `libc::write` + `libc::_exit`.

**Code ref**: `nono/crates/nono-cli/src/exec_strategy.rs:329-365` — threading validation
