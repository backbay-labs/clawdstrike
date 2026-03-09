// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;

use commands::{stronghold as stronghold_cmds, workbench};
use stronghold_cmds::StrongholdState;
#[allow(unused_imports)]
use tauri::Manager;

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_window_state::Builder::new().build())
        .plugin(tauri_plugin_http::init())
        .plugin(tauri_plugin_fs::init())
        .plugin({
            // Register tauri-plugin-stronghold for JS-side capabilities/permissions.
            // The actual Stronghold instance is managed by our StrongholdState below.
            let hostname = hostname::get()
                .map(|h| h.to_string_lossy().into_owned())
                .unwrap_or_else(|_| "clawdstrike-default".to_string());
            let password = format!("clawdstrike-vault-{}", hostname);
            tauri_plugin_stronghold::Builder::new(move |_| password.as_bytes().to_vec()).build()
        })
        .manage(StrongholdState::new())
        .setup(|_app| {
            if let Some(window) = _app.get_webview_window("main") {
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
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
