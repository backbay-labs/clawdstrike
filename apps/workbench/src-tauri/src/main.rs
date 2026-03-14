// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;

use commands::{
    capability, mcp_sidecar, repo_roots, stronghold as stronghold_cmds, terminal, workbench,
    worktree,
};
use capability::CommandCapabilityState;
use mcp_sidecar::McpState;
use stronghold_cmds::StrongholdState;
#[allow(unused_imports)]
use tauri::Manager;
use terminal::TerminalState;

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_window_state::Builder::new().build())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_http::init())
        .plugin({
            // Register tauri-plugin-stronghold for JS-side capabilities/permissions.
            // The actual Stronghold instance is managed by our StrongholdState below.
            // Use the same machine-derived password as our StrongholdState.
            let data_dir = dirs_next::data_dir()
                .unwrap_or_else(std::env::temp_dir)
                .join("com.clawdstrike.workbench");
            let _ = std::fs::create_dir_all(&data_dir);
            let password = stronghold_cmds::derive_machine_password(&data_dir);
            tauri_plugin_stronghold::Builder::new(move |_| password.to_vec()).build()
        })
        .manage(StrongholdState::new())
        .manage(McpState::new())
        .manage(
            std::sync::Arc::new(tokio::sync::Mutex::new(capability::CommandCapabilityManager::new()))
                as CommandCapabilityState,
        )
        .manage(
            std::sync::Arc::new(tokio::sync::Mutex::new(terminal::TerminalManager::new()))
                as TerminalState,
        )
        .setup(|app| {
            if let Some(window) = app.get_webview_window("main") {
                #[cfg(not(target_os = "macos"))]
                {
                    // On Windows/Linux, disable native decorations so the custom
                    // titlebar is the only window chrome.
                    let _ = window.set_decorations(false);
                }
                #[cfg(target_os = "macos")]
                {
                    // Ensure decorations stay enabled on macOS so the native
                    // traffic-light buttons (close/minimize/fullscreen) are visible.
                    // This is needed because tauri-plugin-window-state may restore
                    // a saved state that lost decorations.
                    let _ = window.set_decorations(true);
                }
            }

            // Spawn the embedded MCP server as a sidecar process.
            let mcp_state: McpState = (*app.state::<McpState>()).clone();
            let app_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                match mcp_sidecar::spawn_mcp_server(&app_handle, &mcp_state).await {
                    Ok(info) => {
                        eprintln!(
                            "[workbench] MCP sidecar started at {} (token: [redacted])",
                            info.url,
                        );
                    }
                    Err(e) => {
                        eprintln!("[workbench] ============================================");
                        eprintln!("[workbench] WARNING: MCP sidecar failed to start!");
                        eprintln!("[workbench] MCP features will be unavailable: {e}");
                        eprintln!("[workbench] ============================================");
                        // last_error is set internally by spawn_mcp_server
                    }
                }
            });

            if let Err(err) = repo_roots::init_approved_repo_roots(app.handle()) {
                eprintln!(
                    "[workbench] WARNING: failed to initialize approved repo roots registry: {}",
                    err
                );
            }

            Ok(())
        })
        // ------------------------------------------------------------------
        // Trust model
        // ------------------------------------------------------------------
        // All commands below are exposed via Tauri's IPC bridge, which is
        // restricted to the same-origin webview window (label "main").
        // External web pages, browser extensions, and other processes
        // cannot invoke these handlers.
        //
        // Additional defence-in-depth:
        //  - Sensitive terminal/worktree commands require a backend-held
        //    native approval grant; the renderer does not receive reusable
        //    auth material for these operations.
        //  - Terminal commands validate shell paths against an allowlist,
        //    sanitise environment variables via an allowlist, and
        //    canonicalise working directories.
        //  - Worktree commands validate branch names via `git check-ref-format`,
        //    reject path traversal, and verify paths are registered worktrees
        //    before removal.
        //
        // Renderer compromise is still an in-scope desktop risk; do not load
        // remote/untrusted content in this webview, and keep adding backend
        // guardrails for high-impact commands.
        // ------------------------------------------------------------------
        .invoke_handler(tauri::generate_handler![
            workbench::validate_policy,
            workbench::load_builtin_ruleset,
            workbench::list_builtin_rulesets,
            workbench::simulate_action,
            workbench::simulate_action_with_posture,
            workbench::sign_receipt,
            workbench::sign_receipt_persistent,
            workbench::verify_receipt_chain,
            workbench::export_policy_file,
            workbench::import_policy_file,
            stronghold_cmds::init_stronghold,
            stronghold_cmds::store_credential,
            stronghold_cmds::get_credential,
            stronghold_cmds::delete_credential,
            stronghold_cmds::has_credential,
            stronghold_cmds::generate_persistent_keypair,
            stronghold_cmds::get_signing_public_key,
            stronghold_cmds::sign_with_persistent_key,
            mcp_sidecar::get_mcp_status,
            mcp_sidecar::stop_mcp_server,
            mcp_sidecar::restart_mcp_server,
            terminal::terminal_create,
            terminal::terminal_write,
            terminal::terminal_resize,
            terminal::terminal_kill,
            terminal::terminal_list,
            terminal::terminal_preview,
            terminal::get_cwd,
            worktree::worktree_create,
            worktree::worktree_remove,
            worktree::worktree_list,
            worktree::worktree_status,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app, event| {
            if let tauri::RunEvent::Exit = event {
                // Clean up the MCP sidecar child process on exit.
                let mcp_state = app.state::<McpState>();
                mcp_sidecar::kill_mcp_server(&mcp_state);

                // Clean up all terminal sessions on exit.
                let terminal_state = app.state::<TerminalState>();
                // Use a blocking approach since we're in a sync callback.
                let state_clone = (*terminal_state).clone();
                tauri::async_runtime::block_on(async {
                    terminal::kill_all_sessions(&state_clone).await;
                });
            }
        });
}
