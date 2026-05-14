//! Backend-held authorization for sensitive IPC commands.
//!
//! The renderer must not hold reusable auth material for terminal/worktree
//! control. Instead, sensitive commands are gated by short-lived backend grants
//! that can only be established after native user approval.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use chrono::Utc;
use tauri::{Manager, Runtime};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
use tokio::sync::Mutex;

const TRUSTED_WINDOW_LABEL: &str = "main";
const TERMINAL_READ_TTL_SECS: i64 = 60;
const TERMINAL_READ_MAX_USES: u32 = 128;
const TERMINAL_LIFECYCLE_TTL_SECS: i64 = 30;
const TERMINAL_LIFECYCLE_MAX_USES: u32 = 8;
const TERMINAL_WRITE_TTL_SECS: i64 = 30;
const TERMINAL_WRITE_MAX_USES: u32 = 256;
const REPO_READ_TTL_SECS: i64 = 60;
const REPO_READ_MAX_USES: u32 = 128;
const WORKTREE_WRITE_TTL_SECS: i64 = 15;
const WORKTREE_WRITE_MAX_USES: u32 = 1;
const DENIAL_COOLDOWN_SECS: i64 = 5;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum AuthorizationScope {
    TerminalRead,
    TerminalLifecycle,
    TerminalWrite,
    RepoRead,
    WorktreeWrite,
}

struct ScopePolicy {
    scope: AuthorizationScope,
    ttl_secs: i64,
    max_uses: u32,
    title: &'static str,
    message: &'static str,
}

#[derive(Clone)]
struct AuthorizationGrant {
    expires_at_epoch: i64,
    remaining_uses: u32,
}

pub struct CommandCapabilityManager {
    grants: HashMap<(String, AuthorizationScope), AuthorizationGrant>,
    pending_prompts: HashSet<(String, AuthorizationScope)>,
    denial_cooldowns: HashMap<(String, AuthorizationScope), i64>,
}

pub type CommandCapabilityState = Arc<Mutex<CommandCapabilityManager>>;

impl CommandCapabilityManager {
    pub fn new() -> Self {
        Self {
            grants: HashMap::new(),
            pending_prompts: HashSet::new(),
            denial_cooldowns: HashMap::new(),
        }
    }

    fn prune_expired(&mut self, now_epoch: i64) {
        self.grants
            .retain(|_, grant| grant.expires_at_epoch > now_epoch && grant.remaining_uses > 0);
        self.denial_cooldowns
            .retain(|_, &mut expires_at| expires_at > now_epoch);
    }

    fn is_denial_cooled_down(
        &self,
        window_label: &str,
        scope: AuthorizationScope,
        now_epoch: i64,
    ) -> bool {
        let key = (window_label.to_string(), scope);
        match self.denial_cooldowns.get(&key) {
            Some(&expires_at) => now_epoch >= expires_at,
            None => true,
        }
    }

    fn record_denial(&mut self, window_label: &str, scope: AuthorizationScope, now_epoch: i64) {
        let key = (window_label.to_string(), scope);
        self.denial_cooldowns
            .insert(key, now_epoch.saturating_add(DENIAL_COOLDOWN_SECS));
    }

    fn consume_active_grant(
        &mut self,
        window_label: &str,
        scope: AuthorizationScope,
        now_epoch: i64,
    ) -> bool {
        self.prune_expired(now_epoch);
        let key = (window_label.to_string(), scope);
        let Some(grant) = self.grants.get_mut(&key) else {
            return false;
        };

        if grant.expires_at_epoch <= now_epoch || grant.remaining_uses == 0 {
            self.grants.remove(&key);
            return false;
        }

        grant.remaining_uses = grant.remaining_uses.saturating_sub(1);
        if grant.remaining_uses == 0 {
            self.grants.remove(&key);
        }
        true
    }

    fn issue_grant(
        &mut self,
        window_label: &str,
        scope: AuthorizationScope,
        now_epoch: i64,
        ttl_secs: i64,
        max_uses: u32,
    ) {
        let remaining_uses = max_uses.saturating_sub(1);
        if remaining_uses == 0 {
            self.grants.remove(&(window_label.to_string(), scope));
            return;
        }

        self.grants.insert(
            (window_label.to_string(), scope),
            AuthorizationGrant {
                expires_at_epoch: now_epoch.saturating_add(ttl_secs),
                remaining_uses,
            },
        );
    }
}

fn ensure_trusted_window<R: Runtime>(window: &tauri::Window<R>) -> Result<(), String> {
    if window.label() != TRUSTED_WINDOW_LABEL {
        return Err("Rejecting command from untrusted window".to_string());
    }
    Ok(())
}

fn policy_for_command(command: &str) -> Result<ScopePolicy, String> {
    match command.trim() {
        "terminal_list" | "terminal_preview" => Ok(ScopePolicy {
            scope: AuthorizationScope::TerminalRead,
            ttl_secs: TERMINAL_READ_TTL_SECS,
            max_uses: TERMINAL_READ_MAX_USES,
            title: "Approve Terminal Inspection",
            message:
                "Allow this window to list and preview terminal sessions for the next 60 seconds?",
        }),
        "terminal_create" | "terminal_kill" | "terminal_resize" => Ok(ScopePolicy {
            scope: AuthorizationScope::TerminalLifecycle,
            ttl_secs: TERMINAL_LIFECYCLE_TTL_SECS,
            max_uses: TERMINAL_LIFECYCLE_MAX_USES,
            title: "Approve Terminal Lifecycle",
            message:
                "Allow this window to create, resize, or kill terminal sessions for the next 30 seconds?",
        }),
        "terminal_write" => Ok(ScopePolicy {
            scope: AuthorizationScope::TerminalWrite,
            ttl_secs: TERMINAL_WRITE_TTL_SECS,
            max_uses: TERMINAL_WRITE_MAX_USES,
            title: "Approve Terminal Input",
            message:
                "Allow this window to send input to running terminal sessions for the next 30 seconds?",
        }),
        "get_cwd" | "worktree_list" | "worktree_status" => Ok(ScopePolicy {
            scope: AuthorizationScope::RepoRead,
            ttl_secs: REPO_READ_TTL_SECS,
            max_uses: REPO_READ_MAX_USES,
            title: "Approve Repository Inspection",
            message:
                "Allow this window to inspect local repository metadata for the next 60 seconds?",
        }),
        "worktree_create" | "worktree_remove" => Ok(ScopePolicy {
            scope: AuthorizationScope::WorktreeWrite,
            ttl_secs: WORKTREE_WRITE_TTL_SECS,
            max_uses: WORKTREE_WRITE_MAX_USES,
            title: "Approve Worktree Mutation",
            message:
                "Allow this window to create or remove a git worktree? This approval is single-use.",
        }),
        _ => Err("Unsupported sensitive command".to_string()),
    }
}

async fn prompt_for_native_approval<R: Runtime>(
    window: &tauri::Window<R>,
    policy: &ScopePolicy,
) -> Result<bool, String> {
    let app_handle = window.app_handle().clone();
    let title = policy.title.to_string();
    let message = policy.message.to_string();

    tauri::async_runtime::spawn_blocking(move || {
        Ok::<bool, String>(
            app_handle
                .dialog()
                .message(message)
                .title(title)
                .kind(MessageDialogKind::Warning)
                .buttons(MessageDialogButtons::OkCancelCustom(
                    "Allow".to_string(),
                    "Deny".to_string(),
                ))
                .blocking_show(),
        )
    })
    .await
    .map_err(|e| format!("Failed to wait for native approval dialog: {e}"))?
}

pub async fn authorize_sensitive_command<R: Runtime>(
    window: &tauri::Window<R>,
    state: &tauri::State<'_, CommandCapabilityState>,
    command: &str,
) -> Result<(), String> {
    ensure_trusted_window(window)?;
    let policy = policy_for_command(command)?;
    let now_epoch = Utc::now().timestamp();

    {
        let mut manager = state.lock().await;
        if manager.consume_active_grant(window.label(), policy.scope, now_epoch) {
            return Ok(());
        }
    }

    if !window
        .is_visible()
        .map_err(|e| format!("Failed to inspect window visibility: {e}"))?
    {
        return Err("Sensitive command requires a visible trusted window".to_string());
    }
    if !window
        .is_focused()
        .map_err(|e| format!("Failed to inspect window focus: {e}"))?
    {
        return Err("Sensitive command requires the trusted window to be focused".to_string());
    }

    {
        let mut manager = state.lock().await;
        let now = Utc::now().timestamp();
        let prompt_key = (window.label().to_string(), policy.scope);
        if manager.consume_active_grant(window.label(), policy.scope, now) {
            return Ok(());
        }
        if !manager.is_denial_cooled_down(window.label(), policy.scope, now) {
            return Err(
                "Sensitive command denied — approval cooldown active, try again shortly"
                    .to_string(),
            );
        }
        if manager.pending_prompts.contains(&prompt_key) {
            return Err("Sensitive command approval already pending".to_string());
        }
        manager.pending_prompts.insert(prompt_key);
    }

    // Guard ensures pending_prompts is cleaned up even if this future is
    // cancelled (e.g. by Tauri shutting down or the caller dropping the
    // future). Uses try_lock to avoid blocking in the Drop path.
    let prompt_key = (window.label().to_string(), policy.scope);
    struct PendingPromptGuard {
        state: CommandCapabilityState,
        key: Option<(String, AuthorizationScope)>,
    }
    impl Drop for PendingPromptGuard {
        fn drop(&mut self) {
            if let Some(key) = self.key.take() {
                if let Ok(mut manager) = self.state.try_lock() {
                    manager.pending_prompts.remove(&key);
                }
            }
        }
    }
    let mut guard = PendingPromptGuard {
        state: Arc::clone(state),
        key: Some(prompt_key.clone()),
    };

    let prompt_result = prompt_for_native_approval(window, &policy).await;
    let mut manager = state.lock().await;
    manager.pending_prompts.remove(&prompt_key);
    // Defuse the guard — explicit cleanup succeeded.
    guard.key = None;

    let approved = prompt_result?;
    if !approved {
        manager.record_denial(window.label(), policy.scope, Utc::now().timestamp());
        return Err("Sensitive command denied by native user approval".to_string());
    }

    let now_epoch = Utc::now().timestamp();
    manager.issue_grant(
        window.label(),
        policy.scope,
        now_epoch,
        policy.ttl_secs,
        policy.max_uses,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_permissions_are_split_by_scope() {
        let Ok(list) = policy_for_command("terminal_list") else {
            panic!("missing terminal_list policy");
        };
        let Ok(write) = policy_for_command("terminal_write") else {
            panic!("missing terminal_write policy");
        };
        let Ok(create) = policy_for_command("terminal_create") else {
            panic!("missing terminal_create policy");
        };

        assert_eq!(list.scope, AuthorizationScope::TerminalRead);
        assert_eq!(write.scope, AuthorizationScope::TerminalWrite);
        assert_eq!(create.scope, AuthorizationScope::TerminalLifecycle);
    }

    #[test]
    fn single_use_grant_does_not_authorize_a_second_call() {
        let mut manager = CommandCapabilityManager::new();
        let now = 1_700_000_000;

        manager.issue_grant("main", AuthorizationScope::WorktreeWrite, now, 15, 1);

        assert!(!manager.consume_active_grant("main", AuthorizationScope::WorktreeWrite, now));
    }

    #[test]
    fn multi_use_grant_reserves_one_use_for_the_approving_call() {
        let mut manager = CommandCapabilityManager::new();
        let now = 1_700_000_000;

        manager.issue_grant("main", AuthorizationScope::TerminalWrite, now, 30, 3);

        assert!(manager.consume_active_grant("main", AuthorizationScope::TerminalWrite, now));
        assert!(manager.consume_active_grant("main", AuthorizationScope::TerminalWrite, now));
        assert!(!manager.consume_active_grant("main", AuthorizationScope::TerminalWrite, now));
    }
}
