use anyhow::{anyhow, Result};

const KEYRING_SERVICE: &str = "clawdstrike-agent-key-store";
const ENROLLMENT_USER: &str = "enrollment-agent-key";

fn openclaw_user(device_id: &str) -> String {
    format!("openclaw-device:{device_id}")
}

fn set_secret(user: &str, value: &str) -> Result<()> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, user).map_err(|err| {
        anyhow!(
            "failed to initialize keyring entry for user {}: {}",
            user,
            err
        )
    })?;

    entry.set_password(value).map_err(|err| {
        anyhow!(
            "failed to persist secret in keyring for user {}: {}",
            user,
            err
        )
    })?;

    Ok(())
}

fn get_secret(user: &str) -> Result<Option<String>> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, user).map_err(|err| {
        anyhow!(
            "failed to initialize keyring entry for user {}: {}",
            user,
            err
        )
    })?;

    match entry.get_password() {
        Ok(value) => Ok(Some(value)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(err) => Err(anyhow!(
            "failed to load secret from keyring for user {}: {}",
            user,
            err
        )),
    }
}

fn delete_secret(user: &str) -> Result<()> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, user).map_err(|err| {
        anyhow!(
            "failed to initialize keyring entry for deletion for user {}: {}",
            user,
            err
        )
    })?;

    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(err) => Err(anyhow!(
            "failed to delete keyring secret for user {}: {}",
            user,
            err
        )),
    }
}

pub fn store_enrollment_key_hex(key_hex: &str) -> Result<()> {
    set_secret(ENROLLMENT_USER, key_hex)
}

pub fn load_enrollment_key_hex() -> Result<Option<String>> {
    get_secret(ENROLLMENT_USER)
}

pub fn delete_enrollment_key_hex() -> Result<()> {
    delete_secret(ENROLLMENT_USER)
}

pub fn store_openclaw_private_key(device_id: &str, private_key_pem: &str) -> Result<()> {
    set_secret(&openclaw_user(device_id), private_key_pem)
}

pub fn load_openclaw_private_key(device_id: &str) -> Result<Option<String>> {
    get_secret(&openclaw_user(device_id))
}
