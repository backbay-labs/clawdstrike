# 07 - Implementation Plan

Phased rollout for integrating nono into ClawdStrike, from basic sandbox replacement to full dynamic enforcement.

## Phase Overview

```
Phase 1: Sandbox Replacement          (~2 weeks)
  Replace sandbox-exec/bwrap with nono library API

Phase 2: Policy Translation           (~3 weeks)
  Derive CapabilitySet from policy YAML

Phase 3: Receipt Attestation           (~1 week)
  Include sandbox state in signed receipts

Phase 4: Supervisor Enforcement        (~4 weeks)
  Dynamic enforcement via seccomp-notify/extensions
```

## Phase 1: Sandbox Replacement

**Goal**: Replace ad-hoc sandbox wrappers with nono's cross-platform API.

### Tasks

| # | Task | Effort | Dependency |
|---|------|--------|------------|
| 1.1 | Add `nono` as workspace dependency | S | - |
| 1.2 | Create `sandbox_nono.rs` module in hush-cli | M | 1.1 |
| 1.3 | Implement `build_capability_set()` with hardcoded system paths | M | 1.2 |
| 1.4 | Implement `spawn_sandboxed_child()` with fork+exec | L | 1.2 |
| 1.5 | Wire into `cmd_run()`, replace `maybe_prepare_sandbox()` | M | 1.3, 1.4 |
| 1.6 | Add `--sandbox=nono\|legacy\|none` flag | S | 1.5 |
| 1.7 | Delete `SandboxWrapper`, `generate_macos_sandbox_profile()` | S | 1.5 |
| 1.8 | Integration tests: forbidden paths blocked | M | 1.5 |
| 1.9 | Integration tests: working dir accessible | M | 1.5 |
| 1.10 | Integration tests: network modes | M | 1.5 |
| 1.11 | CI: test on both Linux and macOS | M | 1.8-1.10 |

### Key Files Modified

| File | Change |
|------|--------|
| `Cargo.toml` (workspace) | Add `nono` dependency |
| `crates/services/hush-cli/Cargo.toml` | Add `nono` dependency |
| `crates/services/hush-cli/src/sandbox_nono.rs` | **NEW**: capability builder + fork+exec |
| `crates/services/hush-cli/src/hush_run.rs` | Replace sandbox branches, change spawn model |
| `crates/services/hush-cli/src/cli.rs` | Add `--sandbox` flag |

### Key Code Changes

**hush_run.rs:690-743** (`maybe_prepare_sandbox()`):
- Delete entirely
- Replace call site (line ~380) with `sandbox_nono::build_capability_set()`

**hush_run.rs:746-785** (`generate_macos_sandbox_profile()`):
- Delete entirely
- nono generates platform-specific profiles internally

**hush_run.rs:787-833** (`spawn_and_wait_child()`):
- Replace `Command::new().spawn()` with `fork() + Sandbox::apply() + execve()`
- Environment variables set before fork (inherited by child)
- Signal forwarding: parent forwards SIGINT/SIGTERM to child PID

### Threading Concern

`hush run` uses Tokio for the CONNECT proxy. `fork()` in a multi-threaded process is unsafe. Resolution:

**Option A** (recommended): Fork before starting Tokio runtime.
```
1. Load policy
2. Build CapabilitySet
3. fork()
4. CHILD: apply sandbox, exec
5. PARENT: start Tokio runtime, run proxy, wait for child
```

**Option B** (NOT RECOMMENDED): Use `pre_exec` hook with `Command::new()`.

> **UNSAFE**: `pre_exec` runs after fork in the child. If the parent has multiple threads
> (e.g., Tokio runtime already running), `Sandbox::apply()` performs memory allocation
> (generating Seatbelt profile strings, opening Landlock PathFds) which is NOT
> async-signal-safe and can deadlock. nono-cli explicitly validates thread count before
> fork (`exec_strategy.rs:329-365`). This option bypasses that safety check.
> Additionally, it does not support seccomp-notify (Phase 4) or fd cleanup.

Use Option A.

### Acceptance Criteria

- [ ] `hush run default.yaml -- ls /` works on macOS and Linux
- [ ] `hush run default.yaml -- cat ~/.ssh/id_rsa` fails with EPERM
- [ ] `hush run default.yaml -- curl https://example.com` is blocked (network)
- [ ] `--sandbox=none` disables kernel enforcement
- [ ] `--sandbox=legacy` uses old sandbox-exec/bwrap (transition period)
- [ ] Clippy + fmt pass, no `unwrap()` usage
- [ ] Child closes inherited fds before exec
- [ ] Child error handling uses `libc::write`/`libc::_exit` (no `?` operator)
- [ ] SignalMode configured appropriately (agents spawning subprocesses may need `AllowAll`)

---

## Phase 2: Policy Translation

**Goal**: Guard configurations drive `CapabilitySet` construction.

### Tasks

| # | Task | Effort | Dependency |
|---|------|--------|------------|
| 2.1 | Create `CapabilityBuilder` struct | M | Phase 1 |
| 2.2 | Implement ForbiddenPathGuard → path omission | L | 2.1 |
| 2.3 | Implement PathAllowlistGuard → allow_path mapping | M | 2.1 |
| 2.4 | Implement EgressAllowlistGuard → NetworkMode | S | 2.1 |
| 2.5 | Implement ShellCommandGuard → blocked_commands | S | 2.1 |
| 2.6 | macOS: add deny platform rules for forbidden paths | M | 2.2 |
| 2.7 | Implement pre-flight validation via QueryContext | M | 2.1 |
| 2.8 | Unit tests: default.yaml produces expected caps | M | 2.2-2.5 |
| 2.9 | Unit tests: strict.yaml produces tighter caps | M | 2.2-2.5 |
| 2.10 | Unit tests: ai-agent.yaml produces wider caps | M | 2.2-2.5 |
| 2.11 | Integration tests: policy-driven sandbox blocks correctly | L | 2.8-2.10 |
| 2.12 | `build_with_diagnostics()` returns TranslationWarnings | M | 2.7 |

### Key Files

| File | Change |
|------|--------|
| `crates/libs/clawdstrike/src/sandbox/mod.rs` | **NEW**: module root |
| `crates/libs/clawdstrike/src/sandbox/capability_builder.rs` | **NEW**: policy → caps translation |
| `crates/libs/clawdstrike/src/sandbox/preflight.rs` | **NEW**: QueryContext validation |
| `crates/services/hush-cli/src/sandbox_nono.rs` | Use CapabilityBuilder instead of hardcoded paths |
| `crates/services/hush-cli/src/hush_run.rs` | Pass policy to CapabilityBuilder |

### Translation Matrix

| Ruleset | Forbidden Paths | Network | Commands | Expected CapabilitySet |
|---------|----------------|---------|----------|----------------------|
| default.yaml | .ssh, .aws, .gnupg, .kube, .env, etc. | ProxyOnly | rm, dd, chmod, sudo | Standard system + workdir, proxy networking |
| strict.yaml | Same + additional | ProxyOnly (empty allowlist) | Same + tighter | Minimal system + workdir, strict proxy |
| permissive.yaml | Minimal | AllowAll | Minimal | Wide system access |
| ai-agent.yaml | Same minus exceptions | ProxyOnly (wider allowlist) | rm, dd only | Standard + exception paths |

### Acceptance Criteria

- [ ] `CapabilityBuilder::new(policy).build()` returns valid `CapabilitySet`
- [ ] `default.yaml` sandbox blocks `~/.ssh`, `~/.aws`, `/etc/shadow`
- [ ] `strict.yaml` sandbox has fewer allowed paths than `default.yaml`
- [ ] `ai-agent.yaml` sandbox allows `.env.example` (exception)
- [ ] Pre-flight warns if working directory would be blocked
- [ ] TranslationWarnings emitted for untranslatable guard configs

---

## Phase 3: Receipt Attestation

**Goal**: Receipts attest to kernel enforcement.

### Tasks

| # | Task | Effort | Dependency |
|---|------|--------|------------|
| 3.1 | Define `SandboxAttestation` struct | S | Phase 2 |
| 3.2 | Implement serialization to JSON | S | 3.1 |
| 3.3 | Build attestation in `cmd_run()` after child exits | M | 3.1 |
| 3.4 | Merge into receipt metadata via `merge_metadata()` | S | 3.3 |
| 3.5 | Add `is_kernel_enforced()` to SignedReceipt | S | 3.4 |
| 3.6 | Update receipt verification to check sandbox claims | M | 3.5 |
| 3.7 | Tests: receipt contains sandbox metadata | M | 3.4 |
| 3.8 | Tests: signed receipt verifies with sandbox data | M | 3.6 |

### Key Files

| File | Change |
|------|--------|
| `crates/libs/clawdstrike/src/sandbox/attestation.rs` | **NEW**: SandboxAttestation types |
| `crates/libs/hush-core/src/receipt.rs` | Add helper methods |
| `crates/services/hush-cli/src/hush_run.rs` | Build attestation, merge into receipt |

### Acceptance Criteria

- [ ] `hush run` generates receipt with `metadata.sandbox.enforced: true`
- [ ] Receipt includes capability set serialization
- [ ] Receipt includes platform info (landlock/seatbelt, ABI version)
- [ ] Signed receipt verification succeeds with sandbox metadata
- [ ] `hush verify` displays sandbox enforcement status

---

## Phase 4: Supervisor Enforcement

**Goal**: Dynamic enforcement via supervisor IPC.

### Tasks

| # | Task | Effort | Dependency |
|---|------|--------|------------|
| 4.1 | Implement `GuardSupervisorBackend` (ApprovalBackend trait) | L | Phase 2 |
| 4.2 | Build never_grant list from policy | M | 4.1 |
| 4.3 | Implement Linux supervisor loop (seccomp-notify) | XL | 4.1, 4.2 |
| 4.4 | Implement macOS supervisor loop (extensions) | L | 4.1, 4.2 |
| 4.5 | Modify `spawn_sandboxed_child()` for supervisor mode | L | 4.3, 4.4 |
| 4.6 | Add `--supervised` flag to CLI | S | 4.5 |
| 4.7 | Include supervisor stats in receipt | M | 4.5 |
| 4.8 | Include denial records in receipt | M | 4.5 |
| 4.9 | Integration tests: supervisor approves allowed paths | L | 4.5 |
| 4.10 | Integration tests: supervisor denies forbidden paths | L | 4.5 |
| 4.11 | Integration tests: never_grant is absolute | M | 4.5 |
| 4.12 | Integration tests: rate limiting works | M | 4.5 |
| 4.13 | Performance benchmarks | M | 4.5 |

### Key Files

| File | Change |
|------|--------|
| `crates/libs/clawdstrike/src/sandbox/supervisor.rs` | **NEW**: GuardSupervisorBackend |
| `crates/libs/clawdstrike/src/sandbox/never_grant.rs` | **NEW**: policy → never_grant |
| `crates/services/hush-cli/src/supervised_exec.rs` | **NEW**: fork+exec with supervisor loop |
| `crates/services/hush-cli/src/hush_run.rs` | Wire supervised execution |
| `crates/services/hush-cli/src/cli.rs` | Add `--supervised` flag |

### Acceptance Criteria

- [ ] `hush run --supervised default.yaml -- cat /project/file.txt` succeeds (guard approves)
- [ ] `hush run --supervised default.yaml -- cat ~/.ssh/id_rsa` fails (never_grant)
- [ ] Supervisor loop handles child exit gracefully
- [ ] Rate limiting prevents fd-injection flooding
- [ ] Receipt includes supervisor request/denial counts
- [ ] macOS extension flow works end-to-end
- [ ] Linux seccomp-notify flow works end-to-end
- [ ] Performance: <5ms added latency per file operation

---

## Risk Mitigation

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Fork in multi-threaded Tokio process | HIGH | HIGH | Fork before Tokio runtime (pre_exec is unsafe — see Phase 1) |
| Path canonicalization failures (nonexistent paths) | MEDIUM | MEDIUM | Skip with warning, log to receipt |
| Landlock ABI not available (old kernel) | MEDIUM | MEDIUM | Graceful degradation, log warning |
| seccomp-notify kernel support (requires 5.9+) | LOW | HIGH | Feature-gate supervisor mode, fallback to static |
| Glob pattern → fixed path translation gaps | HIGH | MEDIUM | Accept coarser enforcement, document gaps |
| Performance regression from supervisor IPC | MEDIUM | LOW | Fast-path for initial capabilities, benchmark |
| Breaking change in nono API | LOW | MEDIUM | Pin version, integration tests |

## Rollback Strategy

Each phase has independent rollback:

- **Phase 1**: `--sandbox=legacy` flag falls back to old wrappers
- **Phase 2**: `--sandbox=static` uses hardcoded paths (Phase 1 behavior)
- **Phase 3**: Receipt metadata is additive; removal doesn't break verification
- **Phase 4**: `--supervised=false` disables supervisor loop, falls back to static sandbox

## Dependency Graph

```
Phase 1 ──> Phase 2 ──> Phase 3
                  |
                  └──> Phase 4
```

Phase 3 and Phase 4 can proceed in parallel after Phase 2, but Phase 3's `SandboxAttestation`
struct should be designed with optional Phase 4 fields (supervisor stats, denial records)
from the start, populated as `None`/empty until Phase 4 is complete.

## nono API Coverage by Phase

| API | Phase 1 | Phase 2 | Phase 3 | Phase 4 |
|-----|---------|---------|---------|---------|
| `CapabilitySet::new()` | x | x | x | x |
| `.allow_path()` | x | x | x | x |
| `.block_network()` / `.proxy_only()` | x | x | x | x |
| `.block_command()` | x | x | x | x |
| `.platform_rule()` | | x | | x |
| `.enable_extensions()` | | | | x |
| `Sandbox::apply()` | x | x | x | x |
| `Sandbox::is_supported()` | x | x | x | x |
| `Sandbox::support_info()` | x | | x | |
| `QueryContext::new()` | | x | | |
| `.query_path()` | | x | | |
| `SandboxState::from_caps()` | | | x | x |
| `.to_json()` | | | x | x |
| `SupervisorSocket::pair()` | | | | x |
| `NeverGrantChecker::new()` | | | | x |
| `linux::install_seccomp_notify()` | | | | x |
| `linux::recv_notif()` | | | | x |
| `linux::inject_fd()` / `deny_notif()` | | | | x |
| `macos::extension_issue_file()` | | | | x |
| `macos::extension_consume()` | | | | x |
| `DiagnosticFormatter` | | | | x |
| `DenialRecord` | | | x | x |
