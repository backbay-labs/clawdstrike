#![cfg(test)]

use super::paths::write_settings_file;
use super::store::{backfill_dashboard_url_if_missing, Settings};

#[test]
fn test_default_settings() {
    let settings = Settings::default();
    assert_eq!(settings.daemon_port, 9876);
    assert_eq!(settings.mcp_port, 9877);
    assert_eq!(settings.agent_api_port, 9878);
    assert!(settings.enabled);
    assert!(settings.notifications_enabled);
    assert!(!settings.debug_include_daemon_error_body);
    assert!(settings.ota_enabled);
    assert_eq!(settings.ota_mode, "auto");
    assert_eq!(settings.ota_channel, "stable");
    assert_eq!(settings.ota_check_interval_minutes, 360);
    assert_eq!(settings.integrations.siem.provider, "datadog");
    assert!(!settings.integrations.siem.enabled);
    assert!(!settings.integrations.webhooks.enabled);
    assert!(!settings.control_api.enabled);
    assert!(settings.control_api.url.is_none());
    assert!(settings.control_api.api_key.is_none());
}

#[test]
fn backfills_dashboard_url_from_loaded_agent_port_when_missing() {
    let mut settings = Settings {
        agent_api_port: 21111,
        dashboard_url: String::new(),
        ..Settings::default()
    };

    backfill_dashboard_url_if_missing(&mut settings, false);

    assert_eq!(settings.dashboard_url, "http://127.0.0.1:21111/ui");
}

#[test]
fn preserves_dashboard_url_when_explicitly_present() {
    let mut settings = Settings {
        agent_api_port: 21111,
        dashboard_url: "http://localhost:3100".to_string(),
        ..Settings::default()
    };

    backfill_dashboard_url_if_missing(&mut settings, true);

    assert_eq!(settings.dashboard_url, "http://localhost:3100");
}

#[test]
fn test_daemon_url() {
    let settings = Settings::default();
    assert_eq!(settings.daemon_url(), "http://127.0.0.1:9876");
    assert_eq!(settings.agent_api_port, 9878);
}

#[cfg(unix)]
#[test]
fn write_settings_file_uses_private_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let unique = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => duration.as_nanos(),
        Err(_) => 0,
    };
    let dir = std::env::temp_dir().join(format!("clawdstrike-settings-perms-{unique}"));
    if let Err(err) = std::fs::create_dir_all(&dir) {
        panic!("failed to create temp dir for settings permissions test: {err}");
    }
    let path = dir.join("agent.json");

    if let Err(err) = write_settings_file(&path, "{\"nats\":{\"token\":\"secret\"}}") {
        panic!("failed to write settings file: {err}");
    }

    let metadata = match std::fs::metadata(&path) {
        Ok(metadata) => metadata,
        Err(err) => panic!("failed to read settings metadata: {err}"),
    };
    let mode = metadata.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(unix)]
#[test]
fn write_settings_file_hardens_existing_file_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let unique = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => duration.as_nanos(),
        Err(_) => 0,
    };
    let dir = std::env::temp_dir().join(format!("clawdstrike-settings-perms-existing-{unique}"));
    if let Err(err) = std::fs::create_dir_all(&dir) {
        panic!("failed to create temp dir for settings permissions test: {err}");
    }
    let path = dir.join("agent.json");
    if let Err(err) = std::fs::write(&path, "{}") {
        panic!("failed to seed settings file: {err}");
    }
    if let Err(err) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)) {
        panic!("failed to seed settings file mode: {err}");
    }

    if let Err(err) = write_settings_file(&path, "{\"nats\":{\"token\":\"secret\"}}") {
        panic!("failed to write settings file: {err}");
    }

    let metadata = match std::fs::metadata(&path) {
        Ok(metadata) => metadata,
        Err(err) => panic!("failed to read settings metadata: {err}"),
    };
    let mode = metadata.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir(&dir);
}
