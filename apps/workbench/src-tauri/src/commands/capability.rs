//! Backend-minted capability tokens for sensitive IPC commands.
//!
//! The trusted window label check alone is not sufficient for high-impact
//! command surfaces. This module adds a deny-by-default capability layer:
//! sensitive commands require a short-lived token minted by Rust and bound to
//! the trusted window label.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use tauri::Runtime;
use tokio::sync::Mutex;
use uuid::Uuid;

const TRUSTED_WINDOW_LABEL: &str = "main";
const CAPABILITY_TTL_SECS: i64 = 5 * 60;
const CAPABILITY_MAX_USES: u32 = 512;
const MAX_TRACKED_CAPABILITIES: usize = 64;
const ALLOWED_SENSITIVE_COMMANDS: &[&str] = &[
    "terminal_create",
    "terminal_write",
    "terminal_resize",
    "terminal_kill",
    "terminal_list",
    "terminal_preview",
    "get_cwd",
    "worktree_create",
    "worktree_remove",
    "worktree_list",
    "worktree_status",
];

#[derive(Clone)]
struct CapabilityRecord {
    window_label: String,
    command: String,
    issued_at_epoch: i64,
    last_used_epoch: i64,
    remaining_uses: u32,
}

pub struct CommandCapabilityManager {
    by_window_command: HashMap<(String, String), String>,
    records: HashMap<String, CapabilityRecord>,
}

pub type CommandCapabilityState = Arc<Mutex<CommandCapabilityManager>>;

impl CommandCapabilityManager {
    pub fn new() -> Self {
        Self {
            by_window_command: HashMap::new(),
            records: HashMap::new(),
        }
    }

    fn revoke_token(&mut self, token: &str) {
        self.records.remove(token);
        self.by_window_command
            .retain(|_, existing| existing != token);
    }

    fn prune_expired(&mut self, now_epoch: i64) {
        let expired: Vec<String> = self
            .records
            .iter()
            .filter_map(|(token, record)| {
                let age = now_epoch.saturating_sub(record.last_used_epoch);
                (age >= CAPABILITY_TTL_SECS).then_some(token.clone())
            })
            .collect();
        for token in expired {
            self.revoke_token(&token);
        }
    }

    fn enforce_capacity(&mut self) {
        while self.records.len() >= MAX_TRACKED_CAPABILITIES {
            let oldest = self
                .records
                .iter()
                .min_by_key(|(_, record)| (record.last_used_epoch, record.issued_at_epoch))
                .map(|(token, _)| token.clone());
            if let Some(token) = oldest {
                self.revoke_token(&token);
            } else {
                break;
            }
        }
    }

    fn issue_for_window(&mut self, window_label: &str, command: &str, now_epoch: i64) -> String {
        self.prune_expired(now_epoch);
        let scope_key = (window_label.to_string(), command.to_string());

        if let Some(existing_token) = self.by_window_command.get(&scope_key).cloned() {
            if let Some(record) = self.records.get_mut(&existing_token) {
                let age = now_epoch.saturating_sub(record.last_used_epoch);
                if age < CAPABILITY_TTL_SECS && record.remaining_uses > 0 {
                    record.last_used_epoch = now_epoch;
                    return existing_token;
                }
            }
            self.revoke_token(&existing_token);
        }

        self.enforce_capacity();

        let token = format!("cap_{}_{}", Uuid::new_v4(), Uuid::new_v4());
        self.by_window_command.insert(scope_key, token.clone());
        self.records.insert(
            token.clone(),
            CapabilityRecord {
                window_label: window_label.to_string(),
                command: command.to_string(),
                issued_at_epoch: now_epoch,
                last_used_epoch: now_epoch,
                remaining_uses: CAPABILITY_MAX_USES,
            },
        );
        token
    }

    fn validate_for_window(
        &mut self,
        window_label: &str,
        capability: &str,
        command: &str,
        now_epoch: i64,
    ) -> Result<(), String> {
        self.prune_expired(now_epoch);

        let Some(record) = self.records.get_mut(capability) else {
            return Err("Invalid or expired command capability".to_string());
        };
        if record.window_label != window_label {
            return Err("Command capability does not match active window context".to_string());
        }
        if record.command != command {
            return Err("Command capability does not match requested operation".to_string());
        }

        let age = now_epoch.saturating_sub(record.last_used_epoch);
        if age >= CAPABILITY_TTL_SECS {
            self.revoke_token(capability);
            return Err("Command capability expired".to_string());
        }
        if record.remaining_uses == 0 {
            self.revoke_token(capability);
            return Err("Command capability exhausted".to_string());
        }

        record.last_used_epoch = now_epoch;
        record.remaining_uses = record.remaining_uses.saturating_sub(1);
        let revoke_after_use = record.remaining_uses == 0;
        if revoke_after_use {
            self.revoke_token(capability);
        }
        Ok(())
    }
}

fn normalize_sensitive_command(command: &str) -> Result<String, String> {
    let command = command.trim();
    if command.is_empty() {
        return Err("Missing sensitive command name for capability issuance".to_string());
    }
    if !ALLOWED_SENSITIVE_COMMANDS.contains(&command) {
        return Err(format!(
            "Unsupported sensitive command for capability issuance: {command}"
        ));
    }
    Ok(command.to_string())
}

fn ensure_trusted_window<R: Runtime>(window: &tauri::Window<R>) -> Result<(), String> {
    if window.label() != TRUSTED_WINDOW_LABEL {
        return Err(format!(
            "Rejecting command from unexpected window label: {}",
            window.label()
        ));
    }
    Ok(())
}

#[tauri::command]
pub async fn acquire_command_capability<R: Runtime>(
    window: tauri::Window<R>,
    state: tauri::State<'_, CommandCapabilityState>,
    command: String,
) -> Result<String, String> {
    ensure_trusted_window(&window)?;
    let command = normalize_sensitive_command(&command)?;

    let now_epoch = Utc::now().timestamp();
    let mut manager = state.lock().await;
    Ok(manager.issue_for_window(window.label(), &command, now_epoch))
}

pub async fn validate_command_capability<R: Runtime>(
    window: &tauri::Window<R>,
    state: &tauri::State<'_, CommandCapabilityState>,
    capability: &str,
    command: &str,
) -> Result<(), String> {
    ensure_trusted_window(window)?;
    let command = normalize_sensitive_command(command)?;

    let capability = capability.trim();
    if capability.is_empty() {
        return Err("Missing command capability".to_string());
    }

    let now_epoch = Utc::now().timestamp();
    let mut manager = state.lock().await;
    manager.validate_for_window(window.label(), capability, &command, now_epoch)
}
