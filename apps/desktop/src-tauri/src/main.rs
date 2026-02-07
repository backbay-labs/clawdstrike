//! SDR Desktop - Tauri Application Entry Point

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod marketplace_discovery;
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
            commands::marketplace::marketplace_list_policies,
            commands::marketplace::marketplace_install_policy,
            commands::marketplace::marketplace_verify_attestation,
            commands::marketplace::marketplace_list_curators,
            commands::marketplace::marketplace_add_curator,
            commands::marketplace::marketplace_remove_curator,
            commands::marketplace::marketplace_verify_spine_proof,
            commands::marketplace_discovery::marketplace_discovery_start,
            commands::marketplace_discovery::marketplace_discovery_stop,
            commands::marketplace_discovery::marketplace_discovery_status,
            commands::marketplace_discovery::marketplace_discovery_announce,
            commands::spine::subscribe_spine_events,
            commands::spine::unsubscribe_spine_events,
            commands::spine::spine_status,
            commands::spine::get_spine_connection_status,
            commands::workflows::list_workflows,
            commands::workflows::save_workflow,
            commands::workflows::delete_workflow,
            commands::workflows::test_workflow,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
