//! CapabilityBuilder -- translates ClawdStrike guard policies to nono CapabilitySets.

use std::path::{Path, PathBuf};

use nono::{AccessMode, CapabilitySet, FsCapability, NetworkMode};

use crate::guards::{EgressAllowlistConfig, ForbiddenPathConfig};
use crate::policy::Policy;

/// Builds a nono `CapabilitySet` from a ClawdStrike `Policy`.
pub struct CapabilityBuilder {
    policy: Policy,
    working_dir: PathBuf,
    proxy_port: Option<u16>,
}

/// Warning emitted during policy translation.
#[derive(Debug, Clone)]
pub struct TranslationWarning {
    pub guard: String,
    pub message: String,
    pub severity: WarningSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarningSeverity {
    Info,
    Warning,
}

impl CapabilityBuilder {
    pub fn new(policy: Policy, working_dir: PathBuf) -> Self {
        Self {
            policy,
            working_dir,
            proxy_port: None,
        }
    }

    #[must_use]
    pub fn with_proxy_port(mut self, port: u16) -> Self {
        self.proxy_port = Some(port);
        self
    }

    /// Build a CapabilitySet from the policy.
    pub fn build(self) -> nono::Result<CapabilitySet> {
        let (caps, _warnings) = self.build_with_diagnostics()?;
        Ok(caps)
    }

    /// Build with diagnostic warnings about translation gaps.
    pub fn build_with_diagnostics(self) -> nono::Result<(CapabilitySet, Vec<TranslationWarning>)> {
        let mut caps = CapabilitySet::new();
        let mut warnings = Vec::new();

        // 1. Collect forbidden patterns FIRST (before any grants).
        //    On Linux (Landlock), once a path is granted it cannot be revoked.
        let forbidden_patterns = self.collect_forbidden_patterns();

        // 2. System read paths -- skip forbidden (including parent dirs of forbidden files)
        for path in system_read_paths() {
            if !path.exists() {
                continue;
            }
            if is_path_forbidden(&path, &forbidden_patterns) {
                warnings.push(TranslationWarning {
                    guard: "ForbiddenPathGuard".into(),
                    message: format!(
                        "Skipping system read path {} because it contains forbidden subpaths. \
                         Use --supervised mode or add specific paths to the allowlist.",
                        path.display()
                    ),
                    severity: WarningSeverity::Warning,
                });
                continue;
            }
            caps.add_fs(try_fs_capability(&path, AccessMode::Read)?);
        }

        // 3. System write paths -- skip forbidden (including parent dirs of forbidden files)
        for path in system_write_paths() {
            if !path.exists() {
                continue;
            }
            if is_path_forbidden(&path, &forbidden_patterns) {
                warnings.push(TranslationWarning {
                    guard: "ForbiddenPathGuard".into(),
                    message: format!(
                        "Skipping system write path {} because it contains forbidden subpaths. \
                         Use --supervised mode or add specific paths to the allowlist.",
                        path.display()
                    ),
                    severity: WarningSeverity::Warning,
                });
                continue;
            }
            caps.add_fs(try_fs_capability(&path, AccessMode::ReadWrite)?);
        }

        // 4. Working directory (ReadWrite) when it can be represented faithfully.
        //
        // Path-sensitive policies cannot be enforced by first granting the entire
        // working directory and hoping later guards claw access back. The static
        // sandbox has to fail closed instead of widening access beyond policy.
        let wd_has_forbidden = self.working_dir_contains_forbidden(&forbidden_patterns);
        let allowlist_enabled = self
            .policy
            .guards
            .path_allowlist
            .as_ref()
            .map(|cfg| cfg.enabled)
            .unwrap_or(false);

        if wd_has_forbidden {
            let is_home = dirs::home_dir()
                .map(|h| self.working_dir == h)
                .unwrap_or(false);
            if is_home && cfg!(target_os = "linux") {
                // Granting $HOME on Linux exposes all forbidden paths (.ssh, .aws, etc.)
                // with no way to revoke. Emit a hard warning — preflight should catch this.
                warnings.push(TranslationWarning {
                    guard: "ForbiddenPathGuard".into(),
                    message: format!(
                        "Working directory is $HOME ({}). On Linux, granting $HOME \
                         exposes forbidden subpaths (.ssh, .aws, etc.) irrevocably. \
                         Run from a project subdirectory or use --supervised mode.",
                        self.working_dir.display()
                    ),
                    severity: WarningSeverity::Warning,
                });
            } else {
                warnings.push(TranslationWarning {
                    guard: "ForbiddenPathGuard".into(),
                    message: format!(
                        "Working directory {} contains forbidden subpaths. \
                         On Linux (Landlock), the static sandbox cannot deny them once the parent is granted. \
                         Use --supervised mode for runtime enforcement of forbidden paths within the working directory.",
                        self.working_dir.display()
                    ),
                    severity: WarningSeverity::Warning,
                });
            }
        }

        let grant_working_dir =
            !allowlist_enabled && (!wd_has_forbidden || cfg!(target_os = "macos"));
        if grant_working_dir {
            caps = caps.allow_path(&self.working_dir, AccessMode::ReadWrite)?;
        } else {
            let reason = if allowlist_enabled {
                "PathAllowlistGuard is enabled; granting the full working directory would bypass deny-by-default path enforcement"
            } else {
                "Working directory contains forbidden subpaths that the static Linux sandbox cannot revoke once granted"
            };
            warnings.push(TranslationWarning {
                guard: "CapabilityBuilder".into(),
                message: format!(
                    "Not granting working directory {}. {}. Static translation will fail closed unless the command can run without cwd access or supervised mode is used.",
                    self.working_dir.display(),
                    reason
                ),
                severity: WarningSeverity::Warning,
            });
        }

        // 5. PathAllowlistGuard -> direct path grants
        if let Some(ref allowlist) = self.policy.guards.path_allowlist {
            if allowlist.enabled {
                for pattern in &allowlist.file_access_allow {
                    for path in expand_glob_to_existing(pattern) {
                        if !is_path_forbidden(&path, &forbidden_patterns) {
                            match try_fs_capability(&path, AccessMode::Read) {
                                Ok(cap) => caps.add_fs(cap),
                                Err(_) => {
                                    warnings.push(TranslationWarning {
                                        guard: "PathAllowlistGuard".into(),
                                        message: format!(
                                            "Could not grant read access to {}",
                                            path.display()
                                        ),
                                        severity: WarningSeverity::Warning,
                                    });
                                }
                            }
                        }
                    }
                }
                for pattern in &allowlist.file_write_allow {
                    for path in expand_glob_to_existing(pattern) {
                        if !is_path_forbidden(&path, &forbidden_patterns) {
                            match try_fs_capability(&path, AccessMode::ReadWrite) {
                                Ok(cap) => caps.add_fs(cap),
                                Err(_) => {
                                    warnings.push(TranslationWarning {
                                        guard: "PathAllowlistGuard".into(),
                                        message: format!(
                                            "Could not grant write access to {}",
                                            path.display()
                                        ),
                                        severity: WarningSeverity::Warning,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        // 6. macOS: add deny platform rules for forbidden paths
        #[cfg(target_os = "macos")]
        {
            let concrete_forbidden = self.resolve_forbidden_to_concrete_paths();
            for path in &concrete_forbidden {
                let escaped = escape_seatbelt_path(&path.to_string_lossy());
                // Deny content reads (allow metadata for stat)
                let _ = caps
                    .add_platform_rule(format!("(deny file-read-data (subpath \"{escaped}\"))"));
                let _ =
                    caps.add_platform_rule(format!("(deny file-write* (subpath \"{escaped}\"))"));
            }
        }

        // 7. EgressAllowlistGuard -> NetworkMode
        self.apply_network_mode(&mut caps);

        // 8. ShellCommandGuard -> blocked commands (defense in depth)
        self.apply_blocked_commands(&mut caps);

        // 9. Deduplicate
        caps.deduplicate();

        // Add informational warnings about untranslatable guards
        for guard_name in &[
            "SecretLeakGuard",
            "PatchIntegrityGuard",
            "PromptInjectionGuard",
            "JailbreakGuard",
        ] {
            warnings.push(TranslationWarning {
                guard: guard_name.to_string(),
                message:
                    "Content inspection guard -- no kernel equivalent, runs at application level only"
                        .into(),
                severity: WarningSeverity::Info,
            });
        }

        Ok((caps, warnings))
    }

    /// Collect all forbidden path patterns from the policy.
    fn collect_forbidden_patterns(&self) -> Vec<String> {
        if let Some(ref fp) = self.policy.guards.forbidden_path {
            if !fp.enabled {
                return vec![];
            }
            fp.effective_patterns()
        } else {
            ForbiddenPathConfig::default().effective_patterns()
        }
    }

    /// Check if any forbidden pattern resolves to a path under working_dir.
    fn working_dir_contains_forbidden(&self, patterns: &[String]) -> bool {
        let home = dirs::home_dir();
        for pattern in patterns {
            if let Some(rel) = pattern.strip_prefix("**/") {
                let rel = rel.trim_end_matches("/**").trim_end_matches("/*");
                if let Some(ref home) = home {
                    let concrete = home.join(rel);
                    if concrete.starts_with(&self.working_dir) {
                        return true;
                    }
                }
            } else if pattern.starts_with('/') {
                let p = std::path::Path::new(pattern);
                if p.starts_with(&self.working_dir) {
                    return true;
                }
            }
        }
        false
    }

    /// Resolve forbidden glob patterns to concrete existing paths for macOS deny rules.
    #[cfg(target_os = "macos")]
    fn resolve_forbidden_to_concrete_paths(&self) -> Vec<PathBuf> {
        let patterns = self.collect_forbidden_patterns();
        let mut paths = Vec::new();

        if let Some(home) = dirs::home_dir() {
            for pattern in &patterns {
                if let Some(rel) = pattern.strip_prefix("**/") {
                    // Strip trailing glob suffixes
                    let rel = rel.trim_end_matches("/**").trim_end_matches("/*");
                    let concrete = home.join(rel);
                    if concrete.exists() {
                        paths.push(concrete);
                    }
                } else if pattern.starts_with('/') {
                    let p = PathBuf::from(pattern);
                    if p.exists() {
                        paths.push(p);
                    }
                }
            }
        }

        paths
    }

    fn apply_network_mode(&self, caps: &mut CapabilitySet) {
        // When egress guard is present AND enabled, respect its policy.
        // Otherwise (absent OR disabled), default to blocking — a disabled
        // guard must not weaken security vs. an absent guard.
        if let Some(ref egress) = self.policy.guards.egress_allowlist {
            if egress.enabled && !is_egress_blocking(egress) {
                caps.set_network_mode_mut(NetworkMode::AllowAll);
                return;
            }
        }

        // Default: block network (or proxy-only if configured)
        if let Some(port) = self.proxy_port {
            *caps = std::mem::take(caps).proxy_only(port);
        } else {
            *caps = std::mem::take(caps).block_network();
        }
    }

    fn apply_blocked_commands(&self, caps: &mut CapabilitySet) {
        const KERNEL_BLOCKED: &[&str] = &[
            "rm",
            "rmdir",
            "dd",
            "chmod",
            "chown",
            "sudo",
            "kill",
            "killall",
            "shutdown",
            "mkfs",
            "parted",
            "systemctl",
        ];

        if let Some(ref shell) = self.policy.guards.shell_command {
            if shell.enabled {
                for cmd in KERNEL_BLOCKED {
                    caps.add_blocked_command(*cmd);
                }
            }
        }
    }
}

/// Check if egress policy defaults to blocking.
fn is_egress_blocking(egress: &EgressAllowlistConfig) -> bool {
    use hush_proxy::policy::PolicyAction;
    egress
        .default_action
        .as_ref()
        .map(|a| matches!(a, PolicyAction::Block))
        .unwrap_or(true)
}

/// Try to create an `FsCapability` for a path, choosing dir or file based on metadata.
fn try_fs_capability(path: &Path, mode: AccessMode) -> nono::Result<FsCapability> {
    if path.is_dir() {
        FsCapability::new_dir(path, mode)
    } else {
        FsCapability::new_file(path, mode)
    }
}

/// Check if a path matches any forbidden pattern.
///
/// Uses `Path::components()` for dotfile/dotdir matching to avoid
/// string `starts_with` vulnerabilities on path segments.
///
/// Also checks whether granting `path` would implicitly expose a forbidden
/// child path (e.g. granting `/etc` when `/etc/shadow` is forbidden).
/// On Linux Landlock, directory grants are irrevocable — once granted,
/// subdirectories cannot be denied.
fn is_path_forbidden(path: &Path, patterns: &[String]) -> bool {
    for pattern in patterns {
        let clean = pattern
            .trim_start_matches("**/")
            .trim_end_matches("/**")
            .trim_end_matches("/*");

        if clean.starts_with('/') {
            // Absolute path pattern -- use Path::starts_with for component-level comparison
            if path.starts_with(clean) {
                return true;
            }
            // Reverse check: granting `path` would expose forbidden child `clean`.
            // e.g. granting `/etc` when `/etc/shadow` is forbidden.
            let forbidden_path = Path::new(clean);
            if forbidden_path.starts_with(path) && forbidden_path != path {
                return true;
            }
        } else if clean.starts_with('.') {
            // Dotfile/dotdir pattern -- check each path component
            for component in path.components() {
                let comp_str = component.as_os_str().to_string_lossy();
                // Exact match on path component (e.g., ".ssh" matches component ".ssh")
                if comp_str == clean {
                    return true;
                }
                // Handle patterns like ".env.*" where clean is ".env." after glob stripping
                // Also handles ".env" matching a component that starts with ".env."
                // (e.g., ".env.local")
                if clean.ends_with('*') {
                    let prefix = clean.trim_end_matches('*');
                    if comp_str.starts_with(prefix) {
                        return true;
                    }
                }
            }
        } else {
            // Filename pattern (e.g., "id_rsa*") -- check final component
            if let Some(file_name) = path.file_name() {
                let name = file_name.to_string_lossy();
                if clean.ends_with('*') {
                    let prefix = clean.trim_end_matches('*');
                    if name.starts_with(prefix) {
                        return true;
                    }
                } else if name == clean {
                    return true;
                }
            }
        }
    }
    false
}

/// Expand a glob pattern to existing paths.
fn expand_glob_to_existing(pattern: &str) -> Vec<PathBuf> {
    match glob::glob(pattern) {
        Ok(paths) => paths.filter_map(|r| r.ok()).collect(),
        Err(_) => vec![],
    }
}

/// Escape a path for embedding in a Seatbelt S-expression string.
#[cfg(target_os = "macos")]
fn escape_seatbelt_path(path: &str) -> String {
    path.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Platform-specific system paths (read-only).
#[cfg(target_os = "macos")]
fn system_read_paths() -> Vec<PathBuf> {
    [
        "/bin",
        "/usr",
        "/sbin",
        "/System/Library",
        "/Library",
        "/private/etc",
        "/opt/homebrew",
    ]
    .iter()
    .map(PathBuf::from)
    .collect()
}

#[cfg(target_os = "linux")]
fn system_read_paths() -> Vec<PathBuf> {
    [
        "/bin",
        "/lib",
        "/lib64",
        "/usr",
        "/sbin",
        // Grant specific /etc paths needed for DNS and TLS rather than all
        // of /etc, which would conflict with forbidden files like /etc/shadow.
        "/etc/resolv.conf",
        "/etc/hosts",
        "/etc/nsswitch.conf",
        "/etc/ssl",
        "/etc/pki",
        "/etc/ca-certificates",
        "/etc/ld.so.cache",
        "/etc/ld.so.conf",
        "/etc/ld.so.conf.d",
        "/etc/alternatives",
        "/etc/localtime",
        "/proc",
        "/sys",
        "/run",
    ]
    .iter()
    .map(PathBuf::from)
    .collect()
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn system_read_paths() -> Vec<PathBuf> {
    vec![]
}

/// Platform-specific system paths (writable).
#[cfg(target_os = "macos")]
fn system_write_paths() -> Vec<PathBuf> {
    ["/tmp", "/private/tmp", "/dev"]
        .iter()
        .map(PathBuf::from)
        .collect()
}

#[cfg(target_os = "linux")]
fn system_write_paths() -> Vec<PathBuf> {
    ["/tmp", "/dev", "/dev/shm"]
        .iter()
        .map(PathBuf::from)
        .collect()
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn system_write_paths() -> Vec<PathBuf> {
    vec![]
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use crate::guards::{
        EgressAllowlistConfig, ForbiddenPathConfig, PathAllowlistConfig, ShellCommandConfig,
    };

    fn minimal_policy() -> Policy {
        Policy::default()
    }

    #[test]
    fn test_forbidden_patterns_collected() {
        let builder = CapabilityBuilder::new(minimal_policy(), PathBuf::from("/tmp"));
        let patterns = builder.collect_forbidden_patterns();
        assert!(patterns.iter().any(|p| p.contains(".ssh")));
        assert!(patterns.iter().any(|p| p.contains(".aws")));
    }

    #[test]
    fn test_forbidden_patterns_with_custom_config() {
        let mut policy = minimal_policy();
        policy.guards.forbidden_path = Some(ForbiddenPathConfig {
            enabled: true,
            patterns: Some(vec!["**/custom/**".into()]),
            exceptions: vec![],
            additional_patterns: vec![],
            remove_patterns: vec![],
        });
        let builder = CapabilityBuilder::new(policy, PathBuf::from("/tmp"));
        let patterns = builder.collect_forbidden_patterns();
        assert_eq!(patterns, vec!["**/custom/**"]);
    }

    #[test]
    fn test_forbidden_patterns_disabled_returns_empty() {
        let mut policy = minimal_policy();
        policy.guards.forbidden_path = Some(ForbiddenPathConfig {
            enabled: false,
            patterns: None,
            exceptions: vec![],
            additional_patterns: vec![],
            remove_patterns: vec![],
        });
        let builder = CapabilityBuilder::new(policy, PathBuf::from("/tmp"));
        let patterns = builder.collect_forbidden_patterns();
        assert!(patterns.is_empty());
    }

    #[test]
    fn test_is_path_forbidden_ssh() {
        let patterns = ForbiddenPathConfig::default().effective_patterns();
        assert!(is_path_forbidden(
            Path::new("/home/user/.ssh/id_rsa"),
            &patterns
        ));
        assert!(is_path_forbidden(
            Path::new("/home/user/.ssh/authorized_keys"),
            &patterns
        ));
    }

    #[test]
    fn test_is_path_forbidden_aws() {
        let patterns = ForbiddenPathConfig::default().effective_patterns();
        assert!(is_path_forbidden(
            Path::new("/home/user/.aws/credentials"),
            &patterns
        ));
    }

    #[test]
    fn test_is_path_forbidden_system() {
        let patterns = ForbiddenPathConfig::default().effective_patterns();
        assert!(is_path_forbidden(Path::new("/etc/shadow"), &patterns));
        assert!(is_path_forbidden(Path::new("/etc/passwd"), &patterns));
    }

    #[test]
    fn test_safe_paths_not_forbidden() {
        let patterns = ForbiddenPathConfig::default().effective_patterns();
        assert!(!is_path_forbidden(
            Path::new("/home/user/project/src/main.rs"),
            &patterns
        ));
        assert!(!is_path_forbidden(
            Path::new("/tmp/build/output.txt"),
            &patterns
        ));
    }

    #[test]
    fn test_is_path_forbidden_parent_of_forbidden_file() {
        // Granting /etc should be blocked when /etc/shadow is forbidden,
        // because on Linux Landlock the grant is irrevocable and would
        // expose the forbidden file.
        let patterns = vec!["/etc/shadow".to_string()];
        assert!(
            is_path_forbidden(Path::new("/etc"), &patterns),
            "parent directory of a forbidden file should be considered forbidden"
        );
    }

    #[test]
    fn test_is_path_forbidden_unrelated_path_not_blocked() {
        // /usr should NOT be blocked by /etc/shadow being forbidden
        let patterns = vec!["/etc/shadow".to_string()];
        assert!(
            !is_path_forbidden(Path::new("/usr"), &patterns),
            "unrelated directory should not be blocked"
        );
    }

    #[test]
    fn test_is_path_forbidden_no_false_prefix_match() {
        // Ensure "/etc/passwd" does not match "/etc/passwdevil" --
        // Path::starts_with does component-level comparison.
        let patterns = vec!["/etc/passwd".to_string()];
        assert!(!is_path_forbidden(Path::new("/etc/passwdevil"), &patterns));
    }

    #[test]
    fn test_build_with_defaults() {
        let tmp = tempfile::TempDir::new().unwrap();
        let builder = CapabilityBuilder::new(minimal_policy(), tmp.path().to_path_buf());
        let result = builder.build();
        assert!(result.is_ok(), "should build with default policy");
    }

    #[test]
    fn test_build_with_proxy_port() {
        let tmp = tempfile::TempDir::new().unwrap();
        let builder = CapabilityBuilder::new(minimal_policy(), tmp.path().to_path_buf())
            .with_proxy_port(8080);
        let (caps, _) = builder.build_with_diagnostics().unwrap();
        assert!(caps.is_network_blocked());
    }

    #[test]
    fn test_build_emits_info_warnings() {
        let tmp = tempfile::TempDir::new().unwrap();
        let builder = CapabilityBuilder::new(minimal_policy(), tmp.path().to_path_buf());
        let (_, warnings) = builder.build_with_diagnostics().unwrap();
        let info_guards: Vec<_> = warnings
            .iter()
            .filter(|w| w.severity == WarningSeverity::Info)
            .map(|w| w.guard.as_str())
            .collect();
        assert!(info_guards.contains(&"SecretLeakGuard"));
        assert!(info_guards.contains(&"PatchIntegrityGuard"));
    }

    #[test]
    fn test_blocked_commands_applied() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut policy = minimal_policy();
        policy.guards.shell_command = Some(ShellCommandConfig::default());
        let builder = CapabilityBuilder::new(policy, tmp.path().to_path_buf());
        let (caps, _) = builder.build_with_diagnostics().unwrap();
        let blocked = caps.blocked_commands();
        assert!(blocked.contains(&"rm".to_string()));
        assert!(blocked.contains(&"sudo".to_string()));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_escape_seatbelt_path() {
        assert_eq!(escape_seatbelt_path("/normal/path"), "/normal/path");
        assert_eq!(
            escape_seatbelt_path("/path/with\"quotes"),
            "/path/with\\\"quotes"
        );
        assert_eq!(
            escape_seatbelt_path("/path/with\\backslash"),
            "/path/with\\\\backslash"
        );
    }

    // --- Phase 2C: Comprehensive policy translation tests ---

    #[test]
    fn test_default_policy_ssh_denied() {
        let tmp = tempfile::TempDir::new().unwrap();
        let builder = CapabilityBuilder::new(minimal_policy(), tmp.path().to_path_buf());
        let (caps, _) = builder.build_with_diagnostics().unwrap();

        // .ssh paths must not appear in granted filesystem capabilities
        let has_ssh_grant = caps.fs_capabilities().iter().any(|cap| {
            let p = cap.resolved.to_string_lossy();
            p.contains(".ssh")
        });
        assert!(
            !has_ssh_grant,
            "default policy must not grant access to .ssh paths"
        );
    }

    #[test]
    fn test_default_policy_working_dir_granted() {
        let tmp = tempfile::TempDir::new().unwrap();
        let working_dir = tmp.path().canonicalize().unwrap();
        let builder = CapabilityBuilder::new(minimal_policy(), working_dir.clone());
        let (caps, _) = builder.build_with_diagnostics().unwrap();

        let ctx = nono::query::QueryContext::new(caps);
        assert!(
            matches!(
                ctx.query_path(&working_dir, AccessMode::ReadWrite),
                nono::query::QueryResult::Allowed(_)
            ),
            "working directory must be accessible in the capability set"
        );
    }

    #[test]
    fn test_default_policy_network_blocked_with_proxy() {
        let tmp = tempfile::TempDir::new().unwrap();
        let builder = CapabilityBuilder::new(minimal_policy(), tmp.path().to_path_buf())
            .with_proxy_port(9090);
        let (caps, _) = builder.build_with_diagnostics().unwrap();

        assert!(
            caps.is_network_blocked(),
            "default policy with proxy port should block direct network access"
        );
        assert!(
            matches!(
                caps.network_mode(),
                NetworkMode::ProxyOnly { port: 9090, .. }
            ),
            "network mode should be ProxyOnly with the specified port"
        );
    }

    #[test]
    fn test_default_policy_network_blocked_without_proxy() {
        let tmp = tempfile::TempDir::new().unwrap();
        let builder = CapabilityBuilder::new(minimal_policy(), tmp.path().to_path_buf());
        let (caps, _) = builder.build_with_diagnostics().unwrap();

        assert!(
            caps.is_network_blocked(),
            "default policy without proxy should block network access"
        );
        assert!(
            matches!(caps.network_mode(), NetworkMode::Blocked),
            "network mode should be Blocked when no proxy port and no egress config"
        );
    }

    #[test]
    fn test_strict_policy_no_extra_grants_over_default() {
        let tmp = tempfile::TempDir::new().unwrap();

        let default_caps = CapabilityBuilder::new(minimal_policy(), tmp.path().to_path_buf())
            .build()
            .unwrap();

        // Strict: more forbidden patterns, same system paths
        let mut strict_policy = minimal_policy();
        strict_policy.guards.forbidden_path = Some(ForbiddenPathConfig {
            enabled: true,
            patterns: Some(vec![
                "**/.ssh/**".into(),
                "**/.aws/**".into(),
                "**/.env".into(),
                "**/.env.*".into(),
                "**/.vault/**".into(),
                "**/.secrets/**".into(),
                "**/credentials/**".into(),
                "**/private/**".into(),
                "/etc/shadow".into(),
                "/etc/passwd".into(),
                "/etc/sudoers".into(),
            ]),
            exceptions: vec![],
            additional_patterns: vec![],
            remove_patterns: vec![],
        });

        let strict_caps = CapabilityBuilder::new(strict_policy, tmp.path().to_path_buf())
            .build()
            .unwrap();

        // Strict should grant no more filesystem capabilities than default
        assert!(
            strict_caps.fs_capabilities().len() <= default_caps.fs_capabilities().len(),
            "strict policy must not grant more fs capabilities than default (strict={}, default={})",
            strict_caps.fs_capabilities().len(),
            default_caps.fs_capabilities().len()
        );
    }

    #[test]
    fn test_forbidden_before_grants_ordering() {
        let tmp = tempfile::TempDir::new().unwrap();

        // Create a policy with a forbidden pattern that overlaps system paths
        let mut policy = minimal_policy();
        policy.guards.forbidden_path = Some(ForbiddenPathConfig {
            enabled: true,
            patterns: Some(vec!["/etc/shadow".into(), "/etc/passwd".into()]),
            exceptions: vec![],
            additional_patterns: vec![],
            remove_patterns: vec![],
        });

        let builder = CapabilityBuilder::new(policy, tmp.path().to_path_buf());
        let (caps, _) = builder.build_with_diagnostics().unwrap();

        // /etc/shadow must NOT have been granted even though /etc might be a system path
        let has_shadow = caps
            .fs_capabilities()
            .iter()
            .any(|cap| cap.resolved.to_string_lossy().contains("shadow"));
        assert!(
            !has_shadow,
            "forbidden paths must not be granted even if they overlap system paths"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_macos_deny_platform_rules_generated() {
        let tmp = tempfile::TempDir::new().unwrap();
        let builder = CapabilityBuilder::new(minimal_policy(), tmp.path().to_path_buf());
        let (caps, _) = builder.build_with_diagnostics().unwrap();

        let rules = caps.platform_rules();
        // On macOS, deny rules should be generated for forbidden paths that exist
        // At minimum, if $HOME/.ssh exists it should have deny rules
        if let Some(home) = dirs::home_dir() {
            let ssh_dir = home.join(".ssh");
            if ssh_dir.exists() {
                let ssh_str = ssh_dir.to_string_lossy().to_string();
                let has_deny = rules
                    .iter()
                    .any(|r| r.contains(&ssh_str) && r.contains("deny"));
                assert!(
                    has_deny,
                    "macOS should generate Seatbelt deny rules for existing forbidden paths like .ssh"
                );
            }
        }
    }

    #[test]
    fn test_build_with_diagnostics_emits_content_inspection_warnings() {
        let tmp = tempfile::TempDir::new().unwrap();
        let builder = CapabilityBuilder::new(minimal_policy(), tmp.path().to_path_buf());
        let (_, warnings) = builder.build_with_diagnostics().unwrap();

        let info_warnings: Vec<_> = warnings
            .iter()
            .filter(|w| w.severity == WarningSeverity::Info)
            .collect();

        let expected_guards = [
            "SecretLeakGuard",
            "PatchIntegrityGuard",
            "PromptInjectionGuard",
            "JailbreakGuard",
        ];
        for guard_name in &expected_guards {
            assert!(
                info_warnings.iter().any(|w| w.guard == *guard_name),
                "should emit info warning for content-inspection guard: {guard_name}"
            );
        }

        // All info warnings should mention "content inspection"
        for w in &info_warnings {
            assert!(
                w.message.contains("Content inspection")
                    || w.message.contains("content inspection"),
                "info warning for {} should mention content inspection, got: {}",
                w.guard,
                w.message
            );
        }
    }

    #[test]
    fn test_path_allowlist_guard_read_translation() {
        let tmp = tempfile::TempDir::new().unwrap();
        // Create a real file inside tmp so the glob can find it
        let test_file = tmp.path().join("allowed_read.txt");
        std::fs::write(&test_file, "test").unwrap();

        let mut policy = minimal_policy();
        policy.guards.path_allowlist = Some(PathAllowlistConfig {
            enabled: true,
            file_access_allow: vec![test_file.to_string_lossy().to_string()],
            file_write_allow: vec![],
            patch_allow: vec![],
        });

        let builder = CapabilityBuilder::new(policy, tmp.path().to_path_buf());
        let (caps, _) = builder.build_with_diagnostics().unwrap();

        let has_file = caps
            .fs_capabilities()
            .iter()
            .any(|cap| cap.resolved == test_file.canonicalize().unwrap());
        assert!(
            has_file,
            "PathAllowlistGuard file_access_allow should grant read access to specified paths"
        );
    }

    #[test]
    fn test_path_allowlist_guard_write_translation() {
        let tmp = tempfile::TempDir::new().unwrap();
        let test_file = tmp.path().join("allowed_write.txt");
        std::fs::write(&test_file, "test").unwrap();

        let mut policy = minimal_policy();
        policy.guards.path_allowlist = Some(PathAllowlistConfig {
            enabled: true,
            file_access_allow: vec![],
            file_write_allow: vec![test_file.to_string_lossy().to_string()],
            patch_allow: vec![],
        });

        let builder = CapabilityBuilder::new(policy, tmp.path().to_path_buf());
        let (caps, _) = builder.build_with_diagnostics().unwrap();

        let has_rw = caps.fs_capabilities().iter().any(|cap| {
            cap.resolved == test_file.canonicalize().unwrap() && cap.access == AccessMode::ReadWrite
        });
        assert!(
            has_rw,
            "PathAllowlistGuard file_write_allow should grant ReadWrite access"
        );
    }

    #[test]
    fn test_path_allowlist_guard_disabled() {
        let tmp = tempfile::TempDir::new().unwrap();
        let test_file = tmp.path().join("should_not_grant.txt");
        std::fs::write(&test_file, "test").unwrap();

        let mut policy = minimal_policy();
        policy.guards.path_allowlist = Some(PathAllowlistConfig {
            enabled: false,
            file_access_allow: vec![test_file.to_string_lossy().to_string()],
            file_write_allow: vec![],
            patch_allow: vec![],
        });

        let builder = CapabilityBuilder::new(policy, tmp.path().to_path_buf());
        let (caps, _) = builder.build_with_diagnostics().unwrap();

        let canon = test_file.canonicalize().unwrap();
        let has_file = caps
            .fs_capabilities()
            .iter()
            .any(|cap| cap.resolved == canon && cap.is_file);
        assert!(
            !has_file,
            "disabled PathAllowlistGuard should not contribute capabilities"
        );
    }

    #[test]
    fn test_path_allowlist_does_not_grant_entire_working_dir() {
        use nono::query::{QueryContext, QueryResult};

        let tmp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let test_file = tmp.path().join("allowed_read.txt");
        std::fs::write(&test_file, "test").unwrap();

        let mut policy = minimal_policy();
        policy.guards.path_allowlist = Some(PathAllowlistConfig {
            enabled: true,
            file_access_allow: vec![test_file.to_string_lossy().to_string()],
            file_write_allow: vec![],
            patch_allow: vec![],
        });

        let (caps, warnings) = CapabilityBuilder::new(policy, tmp.path().to_path_buf())
            .build_with_diagnostics()
            .unwrap();

        assert!(
            matches!(
                QueryContext::new(caps.clone()).query_path(&test_file, AccessMode::Read),
                QueryResult::Allowed(_)
            ),
            "explicit allowlisted file should remain accessible"
        );
        assert!(
            !caps.fs_capabilities().iter().any(|cap| {
                cap.resolved == tmp.path().canonicalize().unwrap()
                    && cap.access == AccessMode::ReadWrite
            }),
            "builder must not emit a direct ReadWrite grant for the working directory when deny-by-default allowlists are enabled"
        );
        assert!(
            !matches!(
                QueryContext::new(caps).query_path(tmp.path(), AccessMode::ReadWrite),
                QueryResult::Allowed(_)
            ),
            "builder must not grant the entire working directory when deny-by-default allowlists are enabled"
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.message.contains("Not granting working directory")),
            "builder should explain why cwd was not granted"
        );
    }

    #[test]
    fn test_egress_block_to_proxy_only() {
        use hush_proxy::policy::PolicyAction;

        let tmp = tempfile::TempDir::new().unwrap();
        let mut policy = minimal_policy();
        policy.guards.egress_allowlist = Some(EgressAllowlistConfig {
            enabled: true,
            allow: vec![],
            block: vec![],
            default_action: Some(PolicyAction::Block),
            additional_allow: vec![],
            remove_allow: vec![],
            additional_block: vec![],
            remove_block: vec![],
        });

        let builder =
            CapabilityBuilder::new(policy, tmp.path().to_path_buf()).with_proxy_port(8080);
        let (caps, _) = builder.build_with_diagnostics().unwrap();

        assert!(
            matches!(
                caps.network_mode(),
                NetworkMode::ProxyOnly { port: 8080, .. }
            ),
            "egress Block with proxy port should yield ProxyOnly mode"
        );
    }

    #[test]
    fn test_egress_block_without_proxy_blocks_network() {
        use hush_proxy::policy::PolicyAction;

        let tmp = tempfile::TempDir::new().unwrap();
        let mut policy = minimal_policy();
        policy.guards.egress_allowlist = Some(EgressAllowlistConfig {
            enabled: true,
            allow: vec![],
            block: vec![],
            default_action: Some(PolicyAction::Block),
            additional_allow: vec![],
            remove_allow: vec![],
            additional_block: vec![],
            remove_block: vec![],
        });

        let builder = CapabilityBuilder::new(policy, tmp.path().to_path_buf());
        let (caps, _) = builder.build_with_diagnostics().unwrap();

        assert!(
            matches!(caps.network_mode(), NetworkMode::Blocked),
            "egress Block without proxy should yield Blocked mode"
        );
    }

    #[test]
    fn test_egress_allow_to_allow_all() {
        use hush_proxy::policy::PolicyAction;

        let tmp = tempfile::TempDir::new().unwrap();
        let mut policy = minimal_policy();
        policy.guards.egress_allowlist = Some(EgressAllowlistConfig {
            enabled: true,
            allow: vec!["*".into()],
            block: vec![],
            default_action: Some(PolicyAction::Allow),
            additional_allow: vec![],
            remove_allow: vec![],
            additional_block: vec![],
            remove_block: vec![],
        });

        let builder = CapabilityBuilder::new(policy, tmp.path().to_path_buf());
        let (caps, _) = builder.build_with_diagnostics().unwrap();

        assert!(
            matches!(caps.network_mode(), NetworkMode::AllowAll),
            "egress Allow should yield AllowAll network mode"
        );
    }

    #[test]
    fn test_shell_command_guard_blocks_dangerous_commands() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut policy = minimal_policy();
        policy.guards.shell_command = Some(ShellCommandConfig::default());

        let builder = CapabilityBuilder::new(policy, tmp.path().to_path_buf());
        let (caps, _) = builder.build_with_diagnostics().unwrap();

        let blocked = caps.blocked_commands();
        let expected_blocked = [
            "rm",
            "rmdir",
            "dd",
            "chmod",
            "chown",
            "sudo",
            "kill",
            "killall",
            "shutdown",
            "mkfs",
            "parted",
            "systemctl",
        ];

        for cmd in &expected_blocked {
            assert!(
                blocked.contains(&cmd.to_string()),
                "ShellCommandGuard should block command: {cmd}"
            );
        }
    }

    #[test]
    fn test_shell_command_guard_disabled_no_blocked_commands() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut policy = minimal_policy();
        policy.guards.shell_command = Some(ShellCommandConfig {
            enabled: false,
            forbidden_patterns: vec![],
            enforce_forbidden_paths: false,
        });

        let builder = CapabilityBuilder::new(policy, tmp.path().to_path_buf());
        let (caps, _) = builder.build_with_diagnostics().unwrap();

        assert!(
            caps.blocked_commands().is_empty(),
            "disabled ShellCommandGuard should not add blocked commands"
        );
    }

    #[test]
    fn test_disabled_forbidden_path_guard_allows_all() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut policy = minimal_policy();
        policy.guards.forbidden_path = Some(ForbiddenPathConfig {
            enabled: false,
            patterns: None,
            exceptions: vec![],
            additional_patterns: vec![],
            remove_patterns: vec![],
        });

        let builder = CapabilityBuilder::new(policy, tmp.path().to_path_buf());
        let patterns = builder.collect_forbidden_patterns();
        assert!(
            patterns.is_empty(),
            "disabled forbidden_path guard should produce no forbidden patterns"
        );
    }

    #[test]
    fn test_disabled_egress_guard_defaults_to_blocked() {
        use hush_proxy::policy::PolicyAction;

        let tmp = tempfile::TempDir::new().unwrap();
        let mut policy = minimal_policy();
        policy.guards.egress_allowlist = Some(EgressAllowlistConfig {
            enabled: false,
            allow: vec![],
            block: vec![],
            default_action: Some(PolicyAction::Block),
            additional_allow: vec![],
            remove_allow: vec![],
            additional_block: vec![],
            remove_block: vec![],
        });

        // A disabled egress guard must not weaken security vs. an absent guard.
        // Both cases should default to blocking network access.
        let builder = CapabilityBuilder::new(policy, tmp.path().to_path_buf());
        let (caps, _) = builder.build_with_diagnostics().unwrap();

        assert!(
            matches!(caps.network_mode(), NetworkMode::Blocked),
            "disabled egress guard should default to Blocked (same as absent guard)"
        );
    }

    #[test]
    fn test_no_guards_configured_builds_successfully() {
        let tmp = tempfile::TempDir::new().unwrap();
        let policy = Policy {
            guards: crate::policy::GuardConfigs::default(),
            ..Policy::default()
        };

        let result = CapabilityBuilder::new(policy, tmp.path().to_path_buf()).build();
        assert!(
            result.is_ok(),
            "policy with no guards configured should build successfully"
        );
    }

    #[test]
    fn test_multiple_guards_combine() {
        let tmp = tempfile::TempDir::new().unwrap();
        let test_file = tmp.path().join("extra.txt");
        std::fs::write(&test_file, "data").unwrap();

        let mut policy = minimal_policy();
        policy.guards.shell_command = Some(ShellCommandConfig::default());
        policy.guards.path_allowlist = Some(PathAllowlistConfig {
            enabled: true,
            file_access_allow: vec![test_file.to_string_lossy().to_string()],
            file_write_allow: vec![],
            patch_allow: vec![],
        });

        let builder = CapabilityBuilder::new(policy, tmp.path().to_path_buf());
        let (caps, _) = builder.build_with_diagnostics().unwrap();

        // Both guards should contribute
        assert!(
            !caps.blocked_commands().is_empty(),
            "shell command guard should contribute blocked commands"
        );

        let canon = test_file.canonicalize().unwrap();
        let has_extra = caps
            .fs_capabilities()
            .iter()
            .any(|cap| cap.resolved == canon);
        assert!(
            has_extra,
            "path allowlist guard should contribute filesystem capabilities"
        );
    }
}
