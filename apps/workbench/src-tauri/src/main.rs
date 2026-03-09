// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;

use commands::workbench;

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_window_state::Builder::new().build())
        .plugin(tauri_plugin_http::init())
        .plugin(tauri_plugin_fs::init())
        .invoke_handler(tauri::generate_handler![
            workbench::validate_policy,
            workbench::load_builtin_ruleset,
            workbench::list_builtin_rulesets,
            workbench::simulate_action,
            workbench::simulate_action_with_posture,
            workbench::sign_receipt,
            workbench::verify_receipt_chain,
            workbench::export_policy_file,
            workbench::import_policy_file,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
