// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;

use commands::{mcp_sidecar, stronghold as stronghold_cmds, workbench};
use mcp_sidecar::McpState;
use stronghold_cmds::StrongholdState;
#[allow(unused_imports)]
use tauri::Manager;

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

            Ok(())
        })
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
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app, event| {
            if let tauri::RunEvent::Exit = event {
                // Clean up the MCP sidecar child process on exit.
                let state = app.state::<McpState>();
                mcp_sidecar::kill_mcp_server(&state);
            }
        });
}
