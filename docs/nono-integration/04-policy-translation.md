# 04 - Policy Translation (Phase 2)

Translate ClawdStrike policy YAML guard configurations into nono `CapabilitySet` operations.

## The Fundamental Challenge

ClawdStrike policies are **deny-oriented**: "block these paths, block these hosts, block these commands." Nono/Landlock is **allow-oriented**: "only these paths, only these ports, only these commands are permitted." Translation requires **inversion**: start from a reasonable allow-set, then subtract what guards forbid.

macOS Seatbelt is the exception — it supports both allow and deny rules, so some deny-oriented patterns can be expressed directly.

## Guard-to-Capability Mapping

### ForbiddenPathGuard → Path Omission

**Guard source**: `clawdstrike/crates/libs/clawdstrike/src/guards/forbidden_path.rs:44-104`

**Strategy**: The `CapabilityBuilder` constructs an allow-set of system/working paths. Paths matching ForbiddenPathGuard patterns are **not granted**. On macOS, additional deny platform rules are generated.

#### Default Forbidden Paths (from guard)

```
**/.ssh/**              **/.aws/**           **/.gnupg/**
**/id_rsa*              **/.azure/**         **/.kube/**
**/id_ed25519*          **/.gcloud/**        **/.docker/**
**/id_ecdsa*            **/.npmrc            **/.password-store/**
/etc/shadow             **/.env              **/.1password/**
/etc/passwd             **/.env.*            **/.git-credentials
/etc/sudoers            **/.gitconfig
```

#### Nono Translation

**Linux (Landlock)**: These paths are simply never added to the `CapabilitySet`. Since Landlock is strictly allow-list, they are denied by default. The key requirement: ensure no broad grant (like granting `$HOME` read-write) accidentally covers a forbidden path.

```rust
// Build allow-set, skip forbidden
fn build_fs_caps(
    policy: &Policy,
    working_dir: &Path,
) -> Result<Vec<FsCapability>> {
    let forbidden = collect_forbidden_patterns(policy);
    let mut caps = vec![];

    // Working directory - always granted
    caps.push(FsCapability::new_dir(working_dir, AccessMode::ReadWrite)?);

    // System paths - granted if not forbidden
    for sys_path in system_read_paths() {
        if !is_forbidden(&sys_path, &forbidden) && sys_path.exists() {
            caps.push(FsCapability::new_dir(&sys_path, AccessMode::Read)?);
        }
    }

    Ok(caps)
}

fn is_forbidden(path: &Path, patterns: &[GlobPattern]) -> bool {
    patterns.iter().any(|p| p.matches_path(path))
}
```

**macOS (Seatbelt)**: In addition to omission, generate explicit deny rules for sensitive paths that might be inside a broad allow:

```rust
// macOS: add deny platform rules for forbidden paths inside granted directories
//
// IMPORTANT: Paths must be escaped before embedding in Seatbelt S-expressions.
// See nono's macos.rs:282-298 escape_path() for the reference implementation.
// Unescaped paths containing `"` or `\` would break the profile syntax and
// could be exploited as an injection vector.
fn add_deny_rules(
    caps: &mut CapabilitySet,
    forbidden_paths: &[PathBuf],
) -> Result<()> {
    for path in forbidden_paths {
        let path_str = escape_seatbelt_path(&path.to_string_lossy());
        // Deny content reads (allow metadata for stat)
        caps.add_platform_rule(
            format!("(deny file-read-data (subpath \"{}\"))", path_str)
        )?;
        caps.add_platform_rule(
            format!("(deny file-write* (subpath \"{}\"))", path_str)
        )?;
    }
    Ok(())
}

/// Escape a path for embedding in a Seatbelt S-expression string.
/// Matches nono's internal escape_path() at sandbox/macos.rs:282.
fn escape_seatbelt_path(path: &str) -> String {
    path.replace('\\', "\\\\").replace('"', "\\\"")
}
```

#### Translation Gaps

| Gap | Impact | Mitigation |
|-----|--------|------------|
| Glob `**/.env*` matches anywhere in tree | HIGH | Enumerate known locations; on macOS add deny rules for `$HOME/.env*` |
| Exception support | MEDIUM | Exceptions widen the allow-set; add those paths to caps |
| Dynamic paths (created after sandbox) | MEDIUM | Use supervisor extensions for runtime expansion |
| Symlink resolution differences | LOW | Nono already canonicalizes; both resolve symlinks |

### PathAllowlistGuard → Direct CapabilitySet Mapping

**Guard source**: `clawdstrike/crates/libs/clawdstrike/src/guards/path_allowlist.rs:20-28`

**Strategy**: This is the most natural mapping. The guard's allow-lists translate directly to `CapabilitySet` operations.

```rust
fn translate_path_allowlist(
    config: &PathAllowlistConfig,
    caps: &mut CapabilitySet,
) -> Result<()> {
    // Read-only paths
    for pattern in &config.file_access_allow {
        for path in expand_glob_to_existing_paths(pattern)? {
            caps.add_fs(FsCapability::new_dir(&path, AccessMode::Read)?);
        }
    }

    // Write paths
    for pattern in &config.file_write_allow {
        for path in expand_glob_to_existing_paths(pattern)? {
            caps.add_fs(FsCapability::new_dir(&path, AccessMode::ReadWrite)?);
        }
    }

    Ok(())
}
```

#### Translation Quality: HIGH

Both systems use allow-lists with per-path access modes. The only gap is glob expansion — ClawdStrike patterns like `**/repo/**` must be resolved to concrete existing paths.

### EgressAllowlistGuard → Current Runtime `NetworkMode` + Proxy

**Guard source**: `clawdstrike/crates/libs/clawdstrike/src/guards/egress_allowlist.rs:55-69`

> macOS note: this section describes the current nono + `hush_proxy` runtime collapse to `NetworkMode::ProxyOnly`.
> It is not the frozen macOS NetworkExtension architecture.
> The active macOS control docs now require a provider-agnostic mediation contract, a content-filter baseline, and a documented exception before transparent proxy can become the implementation target.

**Strategy**: Current runtime path: kernel enforces proxy-only networking; proxy enforces domain allowlist. macOS target path: freeze a provider-agnostic mediation contract first, then realize it with a content filter provider unless a reviewed exception proves transparent proxy is required.

```rust
fn translate_egress_policy(
    config: &EgressAllowlistConfig,
    proxy_port: u16,
    caps: &mut CapabilitySet,
) {
    if config.default_action == PolicyAction::Block {
        // All traffic must go through proxy for domain filtering
        caps.set_network_mode_mut(NetworkMode::ProxyOnly {
            port: proxy_port,
            bind_ports: vec![],
        });
    } else {
        // Permissive: allow all network, proxy optional
        caps.set_network_mode_mut(NetworkMode::AllowAll);
    }
}
```

The existing `start_connect_proxy()` continues to handle domain-level filtering using `hush_proxy::policy::DomainPolicy`.

**Code ref**: `clawdstrike/crates/libs/hush-proxy/src/policy.rs:82-112`

#### Defense in Depth

```
Agent tries to connect to evil.com:443
  |
  v
Kernel: NetworkMode::ProxyOnly(8080)
  → Blocks direct connection to evil.com:443
  → Only allows 127.0.0.1:8080
  |
  v
Agent connects through proxy: CONNECT evil.com:443
  |
  v
Proxy: EgressAllowlistGuard check
  → evil.com not in allowlist
  → Returns 403 Forbidden
  |
  v
Connection denied at BOTH layers
```

#### Translation Quality: MEDIUM for the current runtime only

Kernel enforces port-level restriction (no bypass possible). Domain filtering remains application-level via proxy. Direct IP connections to non-proxy ports are blocked by kernel. This should not be treated as the final macOS NetworkExtension decision.

### ShellCommandGuard → blocked_commands

**Guard source**: `clawdstrike/crates/libs/clawdstrike/src/guards/shell_command.rs:35-47`

**Strategy**: Map dangerous command names to `CapabilitySet::block_command()`. Regex pattern matching (pipe detection, argument inspection) remains guard-level only.

```rust
fn translate_shell_commands(
    config: &ShellCommandConfig,
    caps: &mut CapabilitySet,
) {
    // Nono's dangerous_commands equivalent
    let kernel_blocked = [
        "rm", "rmdir", "dd", "chmod", "chown",
        "sudo", "kill", "killall", "shutdown",
        "mkfs", "parted", "systemctl",
    ];

    for cmd in &kernel_blocked {
        caps.add_blocked_command(*cmd);
    }

    // Additional from policy
    for pattern in &config.blocked_patterns {
        // Extract command name from regex if possible
        if let Some(cmd_name) = extract_command_name(pattern) {
            caps.add_blocked_command(cmd_name);
        }
    }
}
```

#### What the Kernel CAN Block

| Pattern | Kernel Enforcement |
|---------|-------------------|
| `rm` | Blocked by command name |
| `sudo` | Blocked by command name |
| `curl \| bash` | `bash` blocked (interpreter) |
| `echo > ~/.ssh/id_rsa` | `~/.ssh` not in allow-set |
| `python -c "os.unlink(...)"` | `python` can be blocked |

#### What the Kernel CANNOT Block

| Pattern | Why | Guard Handles |
|---------|-----|--------------|
| `curl \| bash` composite | Kernel blocks `bash` not the pipe | ShellCommandGuard regex |
| `node -e "fs.writeFile(...)"` | Content inspection | ShellCommandGuard path extraction |
| Quoted arguments | Argument parsing | ShellCommandGuard normalization |

#### Translation Quality: LOW

Command name blocking is crude but useful as defense-in-depth. **Important caveat**: nono's
`blocked_commands` list is checked at the CLI/profile layer, not by the kernel itself.
If a blocked binary resides in an allowed directory (e.g., `/usr/bin/rm`), Landlock/Seatbelt
will still permit execution — the check happens before exec in userspace. The guard continues
to provide the primary enforcement via regex-based detection.

### SecretLeakGuard → No Kernel Equivalent

**Guard source**: `clawdstrike/crates/libs/clawdstrike/src/guards/secret_leak.rs`

Content inspection (regex matching on file writes for API keys, tokens, private keys) cannot be expressed at the kernel level. The guard continues to run at the application level.

The kernel sandbox helps indirectly: by restricting which files can be written, it reduces the attack surface for secret exfiltration.

### Other Guards → Application Level Only

| Guard | Why No Kernel Mapping |
|-------|----------------------|
| PatchIntegrityGuard | Inspects diff content (additions/deletions counts) |
| McpToolGuard | MCP protocol is application-level |
| PromptInjectionGuard | Semantic analysis of text |
| JailbreakGuard | ML-based classification |
| ComputerUseGuard | CUA action filtering |
| RemoteDesktopSideChannelGuard | Side-channel controls |
| InputInjectionCapabilityGuard | Input injection detection |
| SpiderSenseGuard | Embedding-based threat screening |

These guards run unchanged. The kernel sandbox provides structural defense beneath them.

## CapabilityBuilder Implementation

### Public API

```rust
pub struct CapabilityBuilder {
    policy: Policy,
    working_dir: PathBuf,
    proxy_port: Option<u16>,
}

impl CapabilityBuilder {
    pub fn new(policy: Policy, working_dir: PathBuf) -> Self;
    pub fn with_proxy_port(self, port: u16) -> Self;
    pub fn build(self) -> nono::Result<CapabilitySet>;
    pub fn build_with_diagnostics(self) -> nono::Result<(CapabilitySet, Vec<TranslationWarning>)>;
}

pub struct TranslationWarning {
    pub guard: String,
    pub message: String,
    pub severity: WarningSeverity,
}
```

### build() Algorithm

> **CRITICAL**: ForbiddenPathGuard MUST be collected BEFORE adding allow paths.
> On Linux (Landlock), once a path is granted, it cannot be revoked. The
> forbidden set must be known before any grants are issued.

```
1. Start with empty CapabilitySet
2. Collect forbidden path patterns from ForbiddenPathGuard config (FIRST)
3. Add system read paths — skip any that overlap a forbidden path
4. Add system write paths (tmp, dev) — skip any that overlap a forbidden path
5. Add working directory (ReadWrite)
6. Process PathAllowlistGuard config:
   - For each allowed path, check it doesn't cover a forbidden path
   - Add each allowed read/write path
7. On macOS: add deny platform rules for forbidden paths inside granted dirs
8. Process EgressAllowlistGuard config:
   - Set NetworkMode based on default_action
9. Process ShellCommandGuard config:
   - Add blocked commands
10. Deduplicate capabilities
11. Return CapabilitySet
```

### Mapping from Policy Rulesets

#### default.yaml

```
forbidden_path.patterns → omit from caps + macOS deny rules
egress_allowlist.allow → current nono runtime: ProxyOnly (default_action: block)
macOS target → provider-agnostic mediated egress contract resolved by the NetworkExtension control doc
shell_command.enabled → standard blocked commands
```

**Resulting CapabilitySet**:
- FS: working_dir (RW), system paths (R), tmp (RW)
- Forbidden: ~/.ssh, ~/.aws, ~/.gnupg, ~/.kube, etc. (omitted/denied)
- Network: current runtime `ProxyOnly(proxy_port)`; macOS target is a mediated egress provider contract
- Commands: rm, dd, chmod, sudo, etc. blocked

#### strict.yaml

```
egress_allowlist.allow: [] → current runtime ProxyOnly with empty allowlist
mcp_tool.default_action: block → no kernel equivalent
settings.fail_fast: true → no kernel equivalent
```

**Resulting CapabilitySet**: Same structure but the current proxy allowlist is empty (all domains blocked by proxy). The macOS target remains "mediated egress with no approved destinations," not "transparent proxy by default."

#### ai-agent.yaml

```
forbidden_path.exceptions: [**/.env.example] → add .env.example to caps
egress_allowlist.allow: expanded → current runtime ProxyOnly with wider allowlist
```

**Resulting CapabilitySet**: Slightly wider FS access, wider current-runtime proxy allowlist. The macOS control docs still decide the concrete provider separately.

## Pre-flight Validation

Before applying the sandbox, validate the capability set against expected operations:

```rust
pub fn preflight_check(
    caps: &CapabilitySet,
    command: &[String],
    working_dir: &Path,
    policy: &Policy,
) -> PreflightResult {
    let ctx = QueryContext::new(caps.clone());
    let mut errors = vec![];
    let mut warnings = vec![];

    // 1. Working directory must be accessible
    if let QueryResult::Denied(_) = ctx.query_path(working_dir, AccessMode::ReadWrite) {
        errors.push("Working directory not accessible in sandbox");
    }

    // 2. Command binary must be readable
    if let Ok(bin_path) = which::which(&command[0]) {
        if let QueryResult::Denied(_) = ctx.query_path(&bin_path, AccessMode::Read) {
            errors.push("Command binary not accessible in sandbox");
        }
    }

    // 3. Forbidden paths should NOT be accessible
    if let Some(fp) = &policy.guards.forbidden_path {
        for pattern in &fp.patterns {
            // Spot-check concrete paths derived from patterns
            for path in sample_forbidden_paths(pattern) {
                if let QueryResult::Allowed(_) = ctx.query_path(&path, AccessMode::Read) {
                    warnings.push(format!(
                        "Forbidden path {} is accessible in sandbox", path.display()
                    ));
                }
            }
        }
    }

    PreflightResult { errors, warnings }
}
```

## Code References

### ClawdStrike (read by guards)

| File | Lines | Content |
|------|-------|---------|
| `guards/forbidden_path.rs` | 44-104 | Default forbidden patterns |
| `guards/forbidden_path.rs` | 221-261 | Path normalization + exception logic |
| `guards/path_allowlist.rs` | 20-28 | Allow-list config fields |
| `guards/path_allowlist.rs` | 125-143 | Check logic |
| `guards/egress_allowlist.rs` | 55-69 | Default allow/block lists |
| `guards/egress_allowlist.rs` | 78-119 | Merge semantics |
| `guards/shell_command.rs` | 35-47 | Dangerous command patterns |
| `guards/shell_command.rs` | 99-149 | Path extraction from commands |
| `policy.rs` | 233-293 | GuardConfigs struct (all guard configs) |

### Nono (used for translation)

| File | Lines | Content |
|------|-------|---------|
| `capability.rs` | 477-491 | `allow_path()`, `allow_file()` |
| `capability.rs` | 497-520 | `block_network()`, `proxy_only()` |
| `capability.rs` | 621-633 | `allow_command()`, `block_command()` |
| `capability.rs` | 641-646 | `platform_rule()` (macOS deny rules) |
| `capability.rs` | 808-893 | `deduplicate()` |
| `query.rs` | 71-114 | `query_path()` |
| `policy.rs` | 437-475 | `add_deny_access_rules()` (reference implementation) |
| `policy.json` | full | Group definitions (reference for system paths) |
