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
const WORKSPACE_CONTROL_TTL_SECS: i64 = 8 * 60 * 60;
const WORKSPACE_CONTROL_MAX_USES: u32 = 10_000;
const DENIAL_COOLDOWN_SECS: i64 = 5;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum AuthorizationScope {
    WorkspaceControl,
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

pub(crate) fn ensure_trusted_window<R: Runtime>(window: &tauri::Window<R>) -> Result<(), String> {
    if window.label() != TRUSTED_WINDOW_LABEL {
        return Err("Rejecting command from untrusted window".to_string());
    }
    Ok(())
}

fn policy_for_command(command: &str) -> Result<ScopePolicy, String> {
    match command.trim() {
        "worktree_list" | "worktree_status" | "worktree_create" | "worktree_remove" => Ok(ScopePolicy {
            scope: AuthorizationScope::WorkspaceControl,
            ttl_secs: WORKSPACE_CONTROL_TTL_SECS,
            max_uses: WORKSPACE_CONTROL_MAX_USES,
            title: "Approve Workspace Control",
            message:
                "Allow this window to inspect repositories and manage worktrees for the next 8 hours?",
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
    // Terminal control is a first-class local workbench feature; gate it on
    // the trusted main window only, not on per-command native approval.
    if command.trim().starts_with("terminal_") {
        return Ok(());
    }
    let policy = policy_for_command(command)?;
    let now_epoch = Utc::now().timestamp();

    {
        let mut manager = state.lock().await;
        if manager.consume_active_grant(window.label(), policy.scope, now_epoch) {
            return Ok(());
        }
    }

    // Visibility is a hard requirement — the window must be on-screen.
    if !window
        .is_visible()
        .map_err(|e| format!("Failed to inspect window visibility: {e}"))?
    {
        return Err("Sensitive command requires a visible trusted window".to_string());
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
    fn terminal_commands_bypass_native_capability_prompts() {
        assert!(policy_for_command("terminal_list").is_err());
        assert!(policy_for_command("terminal_write").is_err());
        assert!(policy_for_command("terminal_create").is_err());
    }

    #[test]
    fn one_use_grant_is_consumed_immediately() {
        let mut manager = CommandCapabilityManager::new();
        let now = 1_700_000_000;

        manager.issue_grant("main", AuthorizationScope::WorkspaceControl, now, 15, 1);

        assert!(!manager.consume_active_grant("main", AuthorizationScope::WorkspaceControl, now));
    }

    #[test]
    fn multi_use_grant_reserves_one_use_for_the_approving_call() {
        let mut manager = CommandCapabilityManager::new();
        let now = 1_700_000_000;

        manager.issue_grant("main", AuthorizationScope::WorkspaceControl, now, 30, 3);

        assert!(manager.consume_active_grant("main", AuthorizationScope::WorkspaceControl, now));
        assert!(manager.consume_active_grant("main", AuthorizationScope::WorkspaceControl, now));
        assert!(!manager.consume_active_grant("main", AuthorizationScope::WorkspaceControl, now));
    }
}
