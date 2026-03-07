//! SDR Desktop - Tauri Application Entry Point

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod marketplace_discovery;
mod state;

use std::path::PathBuf;

use state::AppState;

fn workspace_settings_path() -> PathBuf {
    let base = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."));
    base.join("huntronomer").join("workspace-settings.json")
}

fn main() {
    let app_state = AppState::new();
    let workspace_state =
        commands::workspace::WorkspaceCommandState::new(workspace_settings_path())
            .expect("workspace command state should initialize");

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(app_state)
        .manage(workspace_state)
        .invoke_handler(tauri::generate_handler![
            commands::hushd::test_connection,
            commands::hushd::get_daemon_status,
            commands::policy::policy_check,
            commands::policy::policy_load,
            commands::policy::policy_validate,
            commands::policy::policy_eval_event,
            commands::policy::policy_save,
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
            commands::openclaw::openclaw_gateway_discover,
            commands::openclaw::openclaw_gateway_probe,
            commands::openclaw::openclaw_agent_request,
            commands::spine::subscribe_spine_events,
            commands::spine::unsubscribe_spine_events,
            commands::spine::spine_status,
            commands::spine::get_spine_connection_status,
            commands::workflows::list_workflows,
            commands::workflows::save_workflow,
            commands::workflows::delete_workflow,
            commands::workflows::test_workflow,
            commands::workspace::workspace_register_root,
            commands::workspace::workspace_remove_root,
            commands::workspace::workspace_list_recent_roots,
            commands::workspace::workspace_list_dir,
            commands::workspace::workspace_stat_path,
            commands::workspace::workspace_read_file,
            commands::workspace::workspace_write_file,
            commands::workspace::workspace_create_path,
            commands::workspace::workspace_move_path,
            commands::workspace::workspace_delete_path,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
