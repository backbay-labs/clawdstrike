use anyhow::Result;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

const KEYRING_SERVICE: &str = "clawdstrike-agent-key-store";
const ENROLLMENT_USER: &str = "enrollment-agent-key";

fn fallback_map() -> &'static Mutex<HashMap<String, String>> {
    static FALLBACK: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    FALLBACK.get_or_init(|| Mutex::new(HashMap::new()))
}

fn openclaw_user(device_id: &str) -> String {
    format!("openclaw-device:{device_id}")
}

fn fallback_insert(user: &str, value: &str) {
    match fallback_map().lock() {
        Ok(mut guard) => {
            guard.insert(user.to_string(), value.to_string());
        }
        Err(err) => {
            tracing::error!(error = %err, user, "Failed to lock fallback key store for insert");
        }
    }
}

fn fallback_remove(user: &str) {
    match fallback_map().lock() {
        Ok(mut guard) => {
            guard.remove(user);
        }
        Err(err) => {
            tracing::error!(error = %err, user, "Failed to lock fallback key store for remove");
        }
    }
}

fn fallback_get(user: &str) -> Option<String> {
    match fallback_map().lock() {
        Ok(guard) => guard.get(user).cloned(),
        Err(err) => {
            tracing::error!(error = %err, user, "Failed to lock fallback key store for read");
            None
        }
    }
}

fn set_secret(user: &str, value: &str) -> Result<()> {
    match keyring::Entry::new(KEYRING_SERVICE, user) {
        Ok(entry) => {
            if let Err(err) = entry.set_password(value) {
                tracing::warn!(error = %err, user, "Keyring write failed; using memory fallback");
                fallback_insert(user, value);
            } else {
                fallback_remove(user);
            }
        }
        Err(err) => {
            tracing::warn!(error = %err, user, "Keyring unavailable; using memory fallback");
            fallback_insert(user, value);
        }
    }

    Ok(())
}

fn get_secret(user: &str) -> Result<Option<String>> {
    if let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, user) {
        match entry.get_password() {
            Ok(value) => return Ok(Some(value)),
            Err(keyring::Error::NoEntry) => {}
            Err(err) => {
                tracing::warn!(error = %err, user, "Keyring read failed; using memory fallback");
            }
        }
    }

    Ok(fallback_get(user))
}

pub fn store_enrollment_key_hex(key_hex: &str) -> Result<()> {
    set_secret(ENROLLMENT_USER, key_hex)
}

pub fn load_enrollment_key_hex() -> Result<Option<String>> {
    get_secret(ENROLLMENT_USER)
}

pub fn store_openclaw_private_key(device_id: &str, private_key_pem: &str) -> Result<()> {
    set_secret(&openclaw_user(device_id), private_key_pem)
}

pub fn load_openclaw_private_key(device_id: &str) -> Result<Option<String>> {
    get_secret(&openclaw_user(device_id))
}
