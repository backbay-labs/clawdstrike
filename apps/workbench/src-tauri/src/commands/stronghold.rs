//! Stronghold-backed secure storage and persistent signing key commands.
//!
//! Uses `iota_stronghold` for encrypted-at-rest credential storage
//! and Ed25519 keypair persistence. The vault is initialised with a
//! machine-derived key so no user password is required.

use std::convert::TryFrom;
use std::sync::Mutex;

use iota_stronghold::{KeyProvider, SnapshotPath, Stronghold};
use serde::Serialize;
use tauri::{AppHandle, Manager, Runtime};
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Managed state
// ---------------------------------------------------------------------------

/// Application state wrapping the Stronghold instance.
/// Lazily initialised on the first `init_stronghold` call.
pub struct StrongholdState {
    inner: Mutex<Option<StrongholdInner>>,
}

struct StrongholdInner {
    stronghold: Stronghold,
    snapshot_path: SnapshotPath,
    keyprovider: KeyProvider,
}

impl StrongholdState {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(None),
        }
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Client name inside the Stronghold snapshot.
const CLIENT_NAME: &[u8] = b"clawdstrike-workbench";

/// Store key prefix for credentials.
const CRED_PREFIX: &str = "credentials:";

/// Store key for the persistent Ed25519 signing seed (32 bytes).
const SIGNING_KEY_RECORD: &[u8] = b"signing_key_seed";

/// Store key for the cached persistent Ed25519 public key (32 bytes).
const SIGNING_PUBKEY_RECORD: &[u8] = b"signing_public_key";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Derive a deterministic password from the machine hostname + a fixed salt.
///
/// This avoids requiring the user to enter a password while still encrypting
/// the Stronghold snapshot at rest. A production build would use a more
/// robust machine-bound key (Secure Enclave / TPM).
fn derive_machine_password() -> Vec<u8> {
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "clawdstrike-default".to_string());
    format!("clawdstrike-vault-{}", hostname).into_bytes()
}

/// Access the initialised Stronghold, returning an error if not yet initialised.
fn with_stronghold<T, F>(state: &StrongholdState, f: F) -> Result<T, String>
where
    F: FnOnce(&StrongholdInner) -> Result<T, String>,
{
    let guard = state
        .inner
        .lock()
        .map_err(|e| format!("Lock poisoned: {}", e))?;
    match guard.as_ref() {
        Some(inner) => f(inner),
        None => Err("Stronghold not initialised. Call init_stronghold first.".into()),
    }
}

/// Save the current Stronghold state to its snapshot file.
fn save_snapshot(inner: &StrongholdInner) -> Result<(), String> {
    inner
        .stronghold
        .commit_with_keyprovider(&inner.snapshot_path, &inner.keyprovider)
        .map_err(|e| format!("Failed to save Stronghold snapshot: {}", e))
}

// ---------------------------------------------------------------------------
// P4-1: Stronghold initialisation
// ---------------------------------------------------------------------------

/// Initialise the Stronghold vault. Called once at app startup from the
/// frontend. Subsequent calls are no-ops returning `true`.
///
/// The snapshot file is stored in the Tauri app data directory.
#[tauri::command]
pub async fn init_stronghold<R: Runtime>(app: AppHandle<R>) -> Result<bool, String> {
    let state = app.state::<StrongholdState>();
    let mut guard = state
        .inner
        .lock()
        .map_err(|e| format!("Lock poisoned: {}", e))?;

    if guard.is_some() {
        return Ok(true);
    }

    // Resolve snapshot path inside the Tauri app data directory.
    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("Cannot resolve app data dir: {}", e))?;
    std::fs::create_dir_all(&data_dir).map_err(|e| format!("Cannot create app data dir: {}", e))?;
    let snapshot_file = data_dir.join("clawdstrike.stronghold");

    let password = derive_machine_password();
    let keyprovider = KeyProvider::try_from(Zeroizing::new(password))
        .map_err(|e| format!("KeyProvider error: {}", e))?;
    let snapshot_path = SnapshotPath::from_path(&snapshot_file);

    let stronghold = Stronghold::default();

    // Load existing snapshot if it exists.
    if snapshot_file.exists() {
        stronghold
            .load_snapshot(&keyprovider, &snapshot_path)
            .map_err(|e| format!("Failed to load Stronghold snapshot: {}", e))?;
    }

    // Ensure the default client exists.
    let _ = stronghold
        .create_client(CLIENT_NAME)
        .or_else(|_| stronghold.load_client(CLIENT_NAME));

    // Persist immediately.
    stronghold
        .commit_with_keyprovider(&snapshot_path, &keyprovider)
        .map_err(|e| format!("Failed to save Stronghold snapshot: {}", e))?;

    *guard = Some(StrongholdInner {
        stronghold,
        snapshot_path,
        keyprovider,
    });

    Ok(true)
}

// ---------------------------------------------------------------------------
// P4-2: Credential storage
// ---------------------------------------------------------------------------

/// Store a credential value in the Stronghold vault.
#[tauri::command]
pub async fn store_credential<R: Runtime>(
    app: AppHandle<R>,
    key: String,
    value: String,
) -> Result<bool, String> {
    if key.is_empty() {
        return Err("Credential key must not be empty".into());
    }
    if value.len() > 1_048_576 {
        return Err("Credential value too large (max 1 MiB)".into());
    }

    let state = app.state::<StrongholdState>();
    with_stronghold(&state, |inner| {
        let client = inner
            .stronghold
            .load_client(CLIENT_NAME)
            .map_err(|e| format!("Client load error: {}", e))?;
        let store = client.store();
        let store_key = format!("{}{}", CRED_PREFIX, key).into_bytes();
        store
            .insert(store_key, value.into_bytes(), None)
            .map_err(|e| format!("Store insert error: {}", e))?;
        save_snapshot(inner)?;
        Ok(true)
    })
}

/// Retrieve a credential value from the Stronghold vault.
/// Returns `null` if the key does not exist.
#[tauri::command]
pub async fn get_credential<R: Runtime>(
    app: AppHandle<R>,
    key: String,
) -> Result<Option<String>, String> {
    let state = app.state::<StrongholdState>();
    with_stronghold(&state, |inner| {
        let client = inner
            .stronghold
            .load_client(CLIENT_NAME)
            .map_err(|e| format!("Client load error: {}", e))?;
        let store = client.store();
        let store_key = format!("{}{}", CRED_PREFIX, key).into_bytes();
        match store.get(&store_key) {
            Ok(Some(bytes)) => {
                if bytes.is_empty() {
                    return Ok(None);
                }
                let s = String::from_utf8(bytes)
                    .map_err(|e| format!("Credential is not valid UTF-8: {}", e))?;
                Ok(Some(s))
            }
            Ok(None) | Err(_) => Ok(None),
        }
    })
}

/// Delete a credential from the Stronghold vault.
#[tauri::command]
pub async fn delete_credential<R: Runtime>(app: AppHandle<R>, key: String) -> Result<bool, String> {
    let state = app.state::<StrongholdState>();
    with_stronghold(&state, |inner| {
        let client = inner
            .stronghold
            .load_client(CLIENT_NAME)
            .map_err(|e| format!("Client load error: {}", e))?;
        let store = client.store();
        let store_key = format!("{}{}", CRED_PREFIX, key).into_bytes();
        let _ = store.delete(&store_key);
        save_snapshot(inner)?;
        Ok(true)
    })
}

/// Check whether a credential exists in the Stronghold vault.
#[tauri::command]
pub async fn has_credential<R: Runtime>(app: AppHandle<R>, key: String) -> Result<bool, String> {
    let state = app.state::<StrongholdState>();
    with_stronghold(&state, |inner| {
        let client = inner
            .stronghold
            .load_client(CLIENT_NAME)
            .map_err(|e| format!("Client load error: {}", e))?;
        let store = client.store();
        let store_key = format!("{}{}", CRED_PREFIX, key).into_bytes();
        store
            .contains_key(&store_key)
            .map_err(|e| format!("Store error: {}", e))
    })
}

// ---------------------------------------------------------------------------
// P4-3: Persistent signing keys
// ---------------------------------------------------------------------------

/// Response type for the generate_persistent_keypair command.
#[derive(Debug, Clone, Serialize)]
pub struct GenerateKeypairResponse {
    /// Hex-encoded Ed25519 public key (64 hex chars = 32 bytes).
    pub public_key: String,
    /// Whether a new keypair was generated (false = existing key was found).
    pub newly_generated: bool,
}

/// Generate or retrieve a persistent Ed25519 keypair.
///
/// The private key seed is stored in the Stronghold vault; only the public
/// key is returned to the frontend. If a keypair already exists it is
/// returned without generating a new one.
#[tauri::command]
pub async fn generate_persistent_keypair<R: Runtime>(
    app: AppHandle<R>,
) -> Result<GenerateKeypairResponse, String> {
    let state = app.state::<StrongholdState>();
    with_stronghold(&state, |inner| {
        let client = inner
            .stronghold
            .load_client(CLIENT_NAME)
            .map_err(|e| format!("Client load error: {}", e))?;
        let store = client.store();

        // Check if we already have a cached public key.
        if let Ok(Some(existing_pub)) = store.get(SIGNING_PUBKEY_RECORD) {
            if existing_pub.len() == 32 {
                return Ok(GenerateKeypairResponse {
                    public_key: hex::encode(&existing_pub),
                    newly_generated: false,
                });
            }
        }

        // Generate a new Ed25519 keypair using hush-core.
        let keypair = hush_core::Keypair::generate();
        let seed_hex = keypair.to_hex();
        let seed_bytes = hex::decode(&seed_hex).map_err(|e| format!("Hex decode error: {}", e))?;
        let pub_bytes = keypair.public_key().as_bytes().to_vec();
        let pub_hex = keypair.public_key().to_hex();

        // Store seed in the Stronghold store.
        store
            .insert(SIGNING_KEY_RECORD.to_vec(), seed_bytes, None)
            .map_err(|e| format!("Failed to store signing key seed: {}", e))?;

        // Cache the public key for quick retrieval.
        store
            .insert(SIGNING_PUBKEY_RECORD.to_vec(), pub_bytes, None)
            .map_err(|e| format!("Failed to store public key: {}", e))?;

        save_snapshot(inner)?;

        Ok(GenerateKeypairResponse {
            public_key: pub_hex,
            newly_generated: true,
        })
    })
}

/// Retrieve the public key of the persistent signing keypair.
/// Returns `null` if no keypair has been generated yet.
#[tauri::command]
pub async fn get_signing_public_key<R: Runtime>(
    app: AppHandle<R>,
) -> Result<Option<String>, String> {
    let state = app.state::<StrongholdState>();
    with_stronghold(&state, |inner| {
        let client = inner
            .stronghold
            .load_client(CLIENT_NAME)
            .map_err(|e| format!("Client load error: {}", e))?;
        let store = client.store();
        match store.get(SIGNING_PUBKEY_RECORD) {
            Ok(Some(bytes)) if bytes.len() == 32 => Ok(Some(hex::encode(&bytes))),
            _ => Ok(None),
        }
    })
}

/// Sign arbitrary data with the persistent Ed25519 key.
///
/// `data_hex` is a hex-encoded byte string to sign.
/// Returns the hex-encoded Ed25519 signature (128 hex chars = 64 bytes).
#[tauri::command]
pub async fn sign_with_persistent_key<R: Runtime>(
    app: AppHandle<R>,
    data_hex: String,
) -> Result<String, String> {
    let data = hex::decode(data_hex.strip_prefix("0x").unwrap_or(&data_hex))
        .map_err(|e| format!("Invalid hex data: {}", e))?;

    let state = app.state::<StrongholdState>();
    with_stronghold(&state, |inner| {
        let client = inner
            .stronghold
            .load_client(CLIENT_NAME)
            .map_err(|e| format!("Client load error: {}", e))?;
        let store = client.store();

        let seed_bytes = store
            .get(SIGNING_KEY_RECORD)
            .map_err(|e| format!("Store read error: {}", e))?
            .ok_or_else(|| {
                "No persistent signing key found. Call generate_persistent_keypair first."
                    .to_string()
            })?;

        if seed_bytes.len() != 32 {
            return Err("Stored signing key seed has invalid length".into());
        }

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_bytes);
        let keypair = hush_core::Keypair::from_seed(&seed);

        // Zeroize seed from stack.
        seed.iter_mut().for_each(|b| *b = 0);

        let signature = keypair.sign(&data);
        Ok(signature.to_hex())
    })
}

// ---------------------------------------------------------------------------
// Public helper for workbench commands (P4-3: persistent key signing)
// ---------------------------------------------------------------------------

/// Attempt to load the persistent Ed25519 keypair from Stronghold state.
/// Returns `None` if Stronghold is not initialised or no key exists.
///
/// Used by `sign_receipt_persistent` in `workbench.rs`.
pub fn load_persistent_keypair_from_state(state: &StrongholdState) -> Option<hush_core::Keypair> {
    let guard = state.inner.lock().ok()?;
    let inner = guard.as_ref()?;
    let client = inner.stronghold.load_client(CLIENT_NAME).ok()?;
    let store = client.store();
    let seed_bytes = store.get(SIGNING_KEY_RECORD).ok()??;

    if seed_bytes.len() != 32 {
        return None;
    }

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);
    let kp = hush_core::Keypair::from_seed(&seed);
    seed.iter_mut().for_each(|b| *b = 0);
    Some(kp)
}
