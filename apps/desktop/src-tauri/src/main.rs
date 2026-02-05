//! SDR Desktop - Tauri Application Entry Point

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod state;

use state::AppState;

fn main() {
    let app_state = AppState::new();

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            commands::hushd::test_connection,
            commands::hushd::get_daemon_status,
            commands::policy::policy_check,
            commands::receipts::verify_receipt,
            commands::workflows::list_workflows,
            commands::workflows::save_workflow,
            commands::workflows::delete_workflow,
            commands::workflows::test_workflow,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
