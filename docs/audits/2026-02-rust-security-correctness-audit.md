# Rust Security + Correctness Audit (2026-02-10)

1) **Executive Summary**
- `High`: `hush-cli` remote-extends host allowlisting is bypassable for non-HTTP git remotes (SCP-style and `ssh://`/`git://`) in `crates/services/hush-cli/src/remote_extends.rs:333`.
- `High`: Path guards (`path_allowlist`, `forbidden_path`) evaluate only lexical-normalized paths, not resolved filesystem targets; symlink traversal can bypass intent in `crates/libs/clawdstrike/src/guards/path_allowlist.rs:98` and `crates/libs/clawdstrike/src/guards/forbidden_path.rs:191`.
- `Medium`: `allow_private_ips=false` is enforced for HTTP remote extends, but not for git remotes in server/CLI resolvers; policy intent is inconsistent (`crates/services/hushd/src/remote_extends.rs:152`, `crates/services/hushd/src/remote_extends.rs:303`).
- `Medium`: `hush run` uses `mpsc::unbounded_channel` for policy events plus per-connection task spawning, enabling unbounded memory growth under event flood (`crates/services/hush-cli/src/hush_run.rs:199`, `crates/services/hush-cli/src/hush_run.rs:695`).
- `Medium`: `hushd` session lock table (`DashMap<session_id, Arc<Mutex<()>>>`) has no lifecycle pruning; lock entries accumulate over long uptime (`crates/services/hushd/src/session/mod.rs:354`, `crates/services/hushd/src/session/mod.rs:405`).
- `Low`: `threat_intel_guards` tests panic on loopback bind denial due `unwrap()`; brittle in restricted runtime environments (`crates/libs/clawdstrike/tests/threat_intel_guards.rs:15`).
- No production `unsafe` blocks were found (only a test-only `unsafe` env var set in `crates/services/hushd/tests/common/mod.rs:68`), so direct UB risk surface is currently low.
- Local Rust gates are mostly healthy: `fmt` and `clippy` pass; test failures are isolated to the threat-intel test harness using localhost bind in this sandbox.

2) **Current Gates (what exists today)**
- Workspace/packages discovered (Rust): 16 workspace members from root `Cargo.toml`; primary libs include `clawdstrike`, `hush-core`, `hush-proxy`, `spine`, `hush-certification`, `hush-multi-agent`; primary binaries include `hush`, `hushd`, `clawdstriked`, `spine-*`, `tetragon-bridge`, `hubble-bridge`, `clawdstrike-cloud-api`, and `clawdstrike` utility bins.
- Public API/entrypoint modules are explicit in crate `lib.rs` exports, especially `clawdstrike` (`engine`, `guards`, `policy`, `plugins`, `irm`, `posture`, etc.) at `crates/libs/clawdstrike/src/lib.rs`.
- CI on PR/push (`.github/workflows/ci.yml`) includes: `cargo fmt --check`, `cargo clippy --all-targets --all-features -D warnings`, `cargo build --all-targets`, `cargo test --all --exclude sdr-integration-tests`, MSRV build, offline vendored tests, docs build, `cargo audit`, `cargo deny`, coverage (`cargo llvm-cov`), wasm build/size gate, proptests (`PROPTEST_CASES=500`), integration tests, TS/Python package jobs.
- Scheduled fuzz exists separately (`.github/workflows/fuzz.yml`): daily at `03:00 UTC`, six fuzz targets, 60s each.
- Path-aware CI (`ci-changed-paths.yml`) runs scoped checks by changed domains.
- Pre-commit hooks are default sample hooks only; no active custom pre-commit hook enforced in repo.
- Local commands executed for validation:
  - `cargo fmt --all -- --check` `OK`
  - `cargo clippy --all-targets --all-features -- -D warnings` `OK`
  - `cargo test --workspace` `FAIL` (3 failing threat-intel tests; localhost bind `PermissionDenied`)
  - `mise run ci` `FAIL` (same 3 failures)
  - `cargo test --all --exclude sdr-integration-tests` `FAIL` (same 3 failures)
  - `CARGO_NET_OFFLINE=true scripts/cargo-offline.sh test --workspace --all-targets` (started, then interrupted due long rebuild)
- Tooling attempts (Phase 4):
  - `cargo miri ...` / `cargo +nightly miri ...` `FAIL` `cargo-miri` missing.
  - `cargo +nightly` ASAN/LSAN targeted run `FAIL` noisy failures from build-script/system-runtime leaks on macOS toolchain, not directly app code.
  - `cargo fuzz ...` `FAIL` `cargo-fuzz` not installed.
  - `cargo audit` / `cargo deny check` `FAIL` advisory DB fetch/lock blocked by environment.

3) **Risk Map**
- `crates/services/hush-cli/src/remote_extends.rs` (`resolve_git_absolute`):
  - Invariant: remote extends must be constrained to explicit allowlisted hosts/schemes and transport safety policy.
- `crates/services/hushd/src/remote_extends.rs` (`validate_and_resolve_http_target`, `resolve_git_absolute`):
  - Invariant: `allow_private_ips=false` should prevent private/loopback resolution for all remote transport paths.
- `crates/libs/clawdstrike/src/guards/path_allowlist.rs`, `crates/libs/clawdstrike/src/guards/forbidden_path.rs`, `crates/libs/clawdstrike/src/guards/path_normalization.rs`:
  - Invariant: path policy decision should reflect resolved filesystem target, not only lexical path string.
- `crates/services/hush-cli/src/hush_run.rs` (`mpsc::unbounded_channel`, proxy connection task fanout):
  - Invariant: event/audit pipeline must be bounded under adversarial output/connection rates.
- `crates/services/hushd/src/session/mod.rs` (`session_locks`):
  - Invariant: session lock bookkeeping should not grow unbounded across terminated/expired session churn.
- `crates/libs/clawdstrike/tests/threat_intel_guards.rs` (test harness server binding):
  - Invariant: test harness should degrade gracefully when loopback bind is unavailable.

4) **Findings (detailed)**

**CS-AUDIT-001**  
Severity: High  
Location: `crates/services/hush-cli/src/remote_extends.rs:333` (`resolve_git_absolute`)  
Category: security invariant  
What’s happening: Git remote host validation in CLI resolver is only applied when `Url::parse(repo)` succeeds and scheme is `http|https`; SCP-style (`git@host:repo`) and `ssh://`/`git://` paths skip allowlist enforcement.  
Invariant violated: Remote extends host constraints should be enforced for all accepted git remote forms.  
How to trigger: Use a policy with `extends: git+git@127.0.0.1:org/repo.git@deadbeef:policy.yaml#sha256=...` while allowlisting only `github.com`; resolver proceeds to git fetch path instead of immediate host allowlist rejection.  
Evidence: Host check block is gated by `matches!(repo_url.scheme(), "http" | "https")` at `crates/services/hush-cli/src/remote_extends.rs:352`.  
Fix: Parse git host for URL + SCP-like remotes and always run `ensure_host_allowed`; reject unsupported schemes explicitly.  
Test: Add `remote_extends_git_scp_host_must_be_allowlisted` and `remote_extends_git_file_scheme_is_rejected` in CLI tests.

**CS-AUDIT-002**  
Severity: Medium  
Location: `crates/services/hushd/src/remote_extends.rs:152`, `crates/services/hushd/src/remote_extends.rs:303`, `crates/services/hush-cli/src/remote_extends.rs:231`, `crates/services/hush-cli/src/remote_extends.rs:333`  
Category: security invariant  
What’s happening: Private-IP filtering is implemented in HTTP resolution flow but not in git flow before invoking `git fetch`.  
Invariant violated: `allow_private_ips=false` should block private/loopback/link-local targets consistently for all remote-extends transports.  
How to trigger: Configure allowlisted host that resolves to private address and use git remote extends (`git+ssh://...` or SCP-style); resolver can attempt private network fetch even with `allow_private_ips=false`.  
Evidence: IP filter at HTTP path only (`...:152`/`...:231`), no equivalent check in `resolve_git_absolute` (`...:303`/`...:333`).  
Fix: Resolve git host addresses and enforce `is_public_ip` before git fetch, or disallow non-HTTPS git remotes when private IPs are blocked.  
Test: Add resolver test asserting git remote to private host is rejected with “non-public IPs” when `allow_private_ips=false`.

**CS-AUDIT-003**  
Severity: High  
Location: `crates/libs/clawdstrike/src/guards/path_allowlist.rs:98`, `crates/libs/clawdstrike/src/guards/forbidden_path.rs:191`, `crates/libs/clawdstrike/src/guards/path_normalization.rs:10`  
Category: security invariant / TOCTOU  
What’s happening: Guards normalize path strings lexically only; they do not resolve symlinks/canonical paths.  
Invariant violated: Guard decision for filesystem actions should correspond to actual file target, including symlink resolution.  
How to trigger: Create symlink inside allowlisted path that points outside allowlist (or into forbidden path), then request access via symlink path. Lexical checks pass while real target violates policy.  
Evidence: `normalize_path_for_policy` is purely lexical (`without filesystem access`) and is the sole normalization used by both guards.  
Fix: Prefer canonicalized path for existing paths (and canonical parent for write-target paths), fallback to lexical only when canonicalization is impossible.  
Test: Add Unix symlink regression tests proving allowlist denial/forbidden-path block on symlinked escape targets.

**CS-AUDIT-004**  
Severity: Medium  
Location: `crates/services/hush-cli/src/hush_run.rs:199`, `crates/services/hush-cli/src/hush_run.rs:695`  
Category: async leak / reliability  
What’s happening: Event pipeline uses `mpsc::unbounded_channel`; proxy path can spawn many connection tasks and enqueue events without backpressure.  
Invariant violated: Telemetry/event buffering should remain memory-bounded under high request rate or slow sink.  
How to trigger: Run `hush run` against workload generating many CONNECT attempts while disk/network writer is slow; queue grows until process memory pressure.  
Evidence: Unbounded channel creation at `...:199`; per-connection spawn at `...:695`; send path is best-effort and unconstrained.  
Fix: Replace with bounded `mpsc::channel(N)`; apply backpressure or explicit drop policy + dropped-event counter.  
Test: Add stress test that saturates queue and asserts bounded behavior (send blocks/fails predictably, no unbounded growth).

**CS-AUDIT-005**  
Severity: Medium  
Location: `crates/services/hushd/src/session/mod.rs:354`, `crates/services/hushd/src/session/mod.rs:405`, `crates/services/hushd/src/session/mod.rs:623`  
Category: leak  
What’s happening: `session_locks` map inserts one lock per session ID and is never pruned, including after termination.  
Invariant violated: Per-session lock table should track active sessions only; stale entries should be reclaimable.  
How to trigger: Long-lived daemon with repeated session churn (`create_session` / `terminate_session`); lock map cardinality grows monotonically.  
Evidence: Insert-only `lock_for_session_id` at `...:405`; no remove path; `terminate_session` only updates store at `...:623`.  
Fix: Remove idle lock on session termination/expiration and periodic prune entries with `Arc::strong_count==1`.  
Test: Add test that acquires lock for session, terminates session, and asserts lock entry is removed.

**CS-AUDIT-006**  
Severity: Low  
Location: `crates/libs/clawdstrike/tests/threat_intel_guards.rs:15`  
Category: reliability  
What’s happening: Threat-intel tests `unwrap()` loopback bind; in restricted environments they panic before guard logic executes.  
Invariant violated: Test harness should fail closed with clear skip/error semantics, not panic on environment capability mismatch.  
How to trigger: Current sandbox produced `PermissionDenied` bind failures consistently for all three tests.  
Evidence: Local test runs failed with panic at `threat_intel_guards.rs:15:59` (`TcpListener::bind("127.0.0.1:0").await.unwrap()`).  
Fix: Return `Result` from helper and skip test on `PermissionDenied` (or gate with env feature).  
Test: Add harness-level test asserting bind errors are handled without panic.

5) **Patch proposals (only for top 3)**

**Patch Proposal A (CS-AUDIT-001): enforce git host checks for all git remote forms**
```diff
diff --git a/crates/services/hush-cli/src/remote_extends.rs b/crates/services/hush-cli/src/remote_extends.rs
@@
-        if let Ok(repo_url) = Url::parse(repo) {
-            if matches!(repo_url.scheme(), "http" | "https") {
-                if self.cfg.https_only && repo_url.scheme() != "https" {
-                    return Err(Error::ConfigError(format!(
-                        "Remote extends require https:// URLs (got {}://)",
-                        repo_url.scheme()
-                    )));
-                }
-                let host = repo_url.host_str().ok_or_else(|| {
-                    Error::ConfigError(format!("Invalid URL host in remote extends: {}", repo))
-                })?;
-                self.ensure_host_allowed(host)?;
-            }
-        }
+        let repo_host = parse_git_remote_host(repo)?;
+        self.ensure_host_allowed(&repo_host)?;
+
+        if let Ok(repo_url) = Url::parse(repo) {
+            if self.cfg.https_only && repo_url.scheme() == "http" {
+                return Err(Error::ConfigError(format!(
+                    "Remote extends require https:// URLs (got {}://)",
+                    repo_url.scheme()
+                )));
+            }
+        }
 @@
+fn parse_git_remote_host(repo: &str) -> Result<String> {
+    if let Ok(repo_url) = Url::parse(repo) {
+        let scheme = repo_url.scheme();
+        if !matches!(scheme, "http" | "https" | "ssh" | "git") {
+            return Err(Error::ConfigError(format!(
+                "Unsupported git remote scheme for remote extends: {}",
+                scheme
+            )));
+        }
+        let host = repo_url.host_str().ok_or_else(|| {
+            Error::ConfigError(format!("Invalid URL host in remote extends: {}", repo))
+        })?;
+        return Ok(normalize_host(host));
+    }
+
+    parse_scp_like_git_host(repo).ok_or_else(|| {
+        Error::ConfigError(format!(
+            "Invalid git remote in remote extends (expected URL or scp-style host:path): {}",
+            repo
+        ))
+    })
+}
+
+fn parse_scp_like_git_host(repo: &str) -> Option<String> {
+    let (lhs, rhs) = repo.split_once(':')?;
+    if rhs.is_empty() || lhs.contains('/') || lhs.contains('\\') {
+        return None;
+    }
+    let host = lhs.rsplit_once('@').map(|(_, h)| h).unwrap_or(lhs);
+    let host = normalize_host(host);
+    if host.is_empty() { None } else { Some(host) }
+}
diff --git a/crates/services/hush-cli/src/tests.rs b/crates/services/hush-cli/src/tests.rs
@@ mod remote_extends_contract {
+    use clawdstrike::policy::{PolicyLocation, PolicyResolver as _};
@@
+    #[test]
+    fn remote_extends_git_scp_host_must_be_allowlisted() {
+        let cfg = RemoteExtendsConfig::new(["github.com".to_string()]);
+        let resolver = RemotePolicyResolver::new(cfg).expect("resolver");
+        let reference = format!(
+            "git+git@127.0.0.1:org/repo.git@deadbeef:policy.yaml#sha256={}",
+            "0".repeat(64)
+        );
+        let err = resolver
+            .resolve(&reference, &PolicyLocation::None)
+            .expect_err("scp-style git host should be rejected before fetch");
+        assert!(err.to_string().contains("allowlisted"), "unexpected error: {err}");
+    }
+
+    #[test]
+    fn remote_extends_git_file_scheme_is_rejected() {
+        let cfg = RemoteExtendsConfig::new(["github.com".to_string()]);
+        let resolver = RemotePolicyResolver::new(cfg).expect("resolver");
+        let reference = format!(
+            "git+file:///tmp/repo@deadbeef:policy.yaml#sha256={}",
+            "0".repeat(64)
+        );
+        let err = resolver
+            .resolve(&reference, &PolicyLocation::None)
+            .expect_err("file:// git remotes must be rejected");
+        assert!(err.to_string().contains("Unsupported git remote scheme"), "unexpected error: {err}");
+    }
 }
```

**Patch Proposal B (CS-AUDIT-003): resolve filesystem targets before path-policy matching**
```diff
diff --git a/crates/libs/clawdstrike/src/guards/path_normalization.rs b/crates/libs/clawdstrike/src/guards/path_normalization.rs
@@
+use std::path::Path;
+
 pub fn normalize_path_for_policy(path: &str) -> String {
@@
 }
+
+pub fn normalize_path_for_policy_with_fs(path: &str) -> String {
+    resolve_path_for_policy(path).unwrap_or_else(|| normalize_path_for_policy(path))
+}
+
+fn resolve_path_for_policy(path: &str) -> Option<String> {
+    let p = Path::new(path);
+    if let Ok(canon) = std::fs::canonicalize(p) {
+        return Some(normalize_path_for_policy(&canon.to_string_lossy()));
+    }
+    let parent = p.parent()?;
+    let file_name = p.file_name()?;
+    let canon_parent = std::fs::canonicalize(parent).ok()?;
+    let joined = canon_parent.join(file_name);
+    Some(normalize_path_for_policy(&joined.to_string_lossy()))
+}
diff --git a/crates/libs/clawdstrike/src/guards/path_allowlist.rs b/crates/libs/clawdstrike/src/guards/path_allowlist.rs
@@
-use super::path_normalization::normalize_path_for_policy;
+use super::path_normalization::normalize_path_for_policy_with_fs;
@@
-        let normalized = normalize_path_for_policy(path);
+        let normalized = normalize_path_for_policy_with_fs(path);
@@
-        let normalized = normalize_path_for_policy(path);
+        let normalized = normalize_path_for_policy_with_fs(path);
@@
-        let normalized = normalize_path_for_policy(path);
+        let normalized = normalize_path_for_policy_with_fs(path);
@@
+    #[cfg(unix)]
+    #[test]
+    fn denies_symlink_escape_outside_allowlist() {
+        use std::os::unix::fs::symlink;
+        let root = std::env::temp_dir().join(format!("path-allowlist-{}", uuid::Uuid::new_v4()));
+        let allowed = root.join("allowed");
+        let outside = root.join("outside");
+        std::fs::create_dir_all(&allowed).unwrap();
+        std::fs::create_dir_all(&outside).unwrap();
+        let target = outside.join("secret.txt");
+        std::fs::write(&target, "x").unwrap();
+        let link = allowed.join("link.txt");
+        symlink(&target, &link).unwrap();
+
+        let guard = PathAllowlistGuard::with_config(PathAllowlistConfig {
+            enabled: true,
+            file_access_allow: vec![format!("{}/allowed/**", root.display())],
+            file_write_allow: vec![format!("{}/allowed/**", root.display())],
+            patch_allow: vec![],
+        });
+        assert!(!guard.is_file_access_allowed(link.to_str().unwrap()));
+        let _ = std::fs::remove_dir_all(&root);
+    }
diff --git a/crates/libs/clawdstrike/src/guards/forbidden_path.rs b/crates/libs/clawdstrike/src/guards/forbidden_path.rs
@@
-use super::path_normalization::normalize_path_for_policy;
+use super::path_normalization::normalize_path_for_policy_with_fs;
@@
-        let path = normalize_path_for_policy(path);
+        let path = normalize_path_for_policy_with_fs(path);
@@
+    #[cfg(unix)]
+    #[test]
+    fn forbids_symlink_target_when_target_matches_forbidden_pattern() {
+        use std::os::unix::fs::symlink;
+        let root = std::env::temp_dir().join(format!("forbidden-path-{}", uuid::Uuid::new_v4()));
+        let safe = root.join("safe");
+        let forbidden = root.join("forbidden");
+        std::fs::create_dir_all(&safe).unwrap();
+        std::fs::create_dir_all(&forbidden).unwrap();
+        let target = forbidden.join("secret.txt");
+        std::fs::write(&target, "x").unwrap();
+        let link = safe.join("link.txt");
+        symlink(&target, &link).unwrap();
+
+        let guard = ForbiddenPathGuard::with_config(ForbiddenPathConfig {
+            enabled: true,
+            patterns: Some(vec![format!("{}/forbidden/**", root.display())]),
+            exceptions: vec![],
+            additional_patterns: vec![],
+            remove_patterns: vec![],
+        });
+        assert!(guard.is_forbidden(link.to_str().unwrap()));
+        let _ = std::fs::remove_dir_all(&root);
+    }
```

**Patch Proposal C (CS-AUDIT-005): prune stale per-session locks**
```diff
diff --git a/crates/services/hushd/src/session/mod.rs b/crates/services/hushd/src/session/mod.rs
@@
 impl SessionManager {
+    fn remove_session_lock_if_idle(&self, session_id: &str) {
+        if let Some(entry) = self.session_locks.get(session_id) {
+            if Arc::strong_count(entry.value()) == 1 {
+                drop(entry);
+                self.session_locks.remove(session_id);
+            }
+        }
+    }
+
     fn lock_for_session_id(&self, session_id: &str) -> Arc<tokio::sync::Mutex<()>> {
         self.session_locks
             .entry(session_id.to_string())
             .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
             .clone()
@@
     pub fn terminate_session(&self, session_id: &str, _reason: Option<&str>) -> Result<bool> {
         let now = Utc::now().to_rfc3339();
         let updated = self.store.update(
             session_id,
             SessionUpdates {
                 terminated_at: Some(now),
                 ..Default::default()
             },
         )?;
-        Ok(updated.is_some())
+        let terminated = updated.is_some();
+        if terminated {
+            self.remove_session_lock_if_idle(session_id);
+        }
+        Ok(terminated)
     }
@@
 #[cfg(test)]
 mod tests {
@@
+    #[tokio::test]
+    async fn terminate_session_releases_idle_lock_entry() {
+        let store = Arc::new(InMemorySessionStore::new());
+        let manager = SessionManager::new(
+            store,
+            60,
+            600,
+            None,
+            SessionHardeningConfig::default(),
+        );
+        let session = manager.create_session(test_identity(), None).unwrap();
+        let session_id = session.session_id.clone();
+
+        {
+            let _guard = manager.acquire_session_lock(&session_id).await;
+        }
+        assert!(manager.session_locks.contains_key(&session_id));
+
+        assert!(manager.terminate_session(&session_id, None).unwrap());
+        assert!(!manager.session_locks.contains_key(&session_id));
+    }
 }
```

6) **Improve Gates suggestions (only if justified)**

1. Scope: run a short fuzz execution on PR instead of only building fuzz targets. Cost: ~4-6 minutes. Expected signal: catches parser panic/regression classes currently missed by `fuzz-check` build-only job.  
CI snippet:
```yaml
- name: Install cargo-fuzz
  run: cargo install cargo-fuzz --locked --version 0.13.1
- name: PR fuzz smoke
  run: |
    cd fuzz
    cargo +nightly fuzz run fuzz_policy_parse -- -max_total_time=30
    cargo +nightly fuzz run fuzz_dns_parse -- -max_total_time=30
```

2. Scope: targeted sanitizer job on Linux for one or two critical crates/tests, with leak detection disabled for toolchain/build-script noise. Cost: medium (nightly + extra build time). Expected signal: memory/concurrency runtime issues in critical guards without macOS LSAN false positives seen locally.  
CI snippet:
```yaml
- name: ASAN smoke (targeted)
  env:
    RUSTFLAGS: "-Zsanitizer=address"
    ASAN_OPTIONS: "detect_leaks=0"
  run: cargo +nightly test -p clawdstrike --test async_guard_runtime
```

3. Scope: add CI test coverage for git remote-extends invariants (host allowlist on SCP/SSH + private-IP behavior parity). Cost: low. Expected signal: prevents recurrence of CS-AUDIT-001/002 class bugs early in PR.  
Command:
```bash
cargo test -p hush-cli remote_extends_contract::remote_extends_git_scp_host_must_be_allowlisted
cargo test -p hushd remote_extends::tests::scp_style_git_remote_must_be_allowlisted
```
