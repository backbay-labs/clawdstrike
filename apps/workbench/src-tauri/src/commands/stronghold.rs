//! Stronghold-backed secure storage and persistent signing key commands.
//!
//! Uses `iota_stronghold` for encrypted-at-rest credential storage
//! and Ed25519 keypair persistence. The vault is initialised with a
//! machine-derived key so no user password is required.

use std::convert::TryFrom;
use std::path::Path;
use std::sync::Mutex;

use iota_stronghold::{KeyProvider, SnapshotPath, Stronghold};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Manager, Runtime};
use zeroize::{Zeroize, Zeroizing};

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

/// Derive a machine-bound password that combines real entropy with hostname binding.
///
/// The function reads (or generates) a random 32-byte machine secret from
/// `{data_dir}/vault-machine-key`, then derives the final key as:
///
///   `SHA-256(machine_secret || hostname || "clawdstrike-vault-v2")`
///
/// This avoids the previous predictable hostname-only derivation while still
/// binding the key to the machine. A production build would use a more
/// robust machine-bound key (Secure Enclave / TPM).
pub fn derive_machine_password(data_dir: &Path) -> Zeroizing<Vec<u8>> {
    let key_file = data_dir.join("vault-machine-key");
    let mut machine_secret = Zeroizing::new([0u8; 32]);

    if key_file.exists() {
        if let Ok(bytes) = std::fs::read(&key_file) {
            if bytes.len() == 32 {
                machine_secret.copy_from_slice(&bytes);
            } else {
                // Corrupted file — regenerate.
                generate_and_write_machine_secret(&key_file, &mut machine_secret);
            }
        } else {
            // Cannot read — regenerate.
            generate_and_write_machine_secret(&key_file, &mut machine_secret);
        }
    } else {
        generate_and_write_machine_secret(&key_file, &mut machine_secret);
    }

    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "clawdstrike-default".to_string());

    let mut hasher = Sha256::new();
    hasher.update(machine_secret.as_ref());
    hasher.update(hostname.as_bytes());
    hasher.update(b"clawdstrike-vault-v2");
    Zeroizing::new(hasher.finalize().to_vec())
}

/// Generate 32 random bytes using the OS CSPRNG and write them to the key file.
fn generate_and_write_machine_secret(key_file: &Path, out: &mut [u8; 32]) {
    getrandom::getrandom(out).unwrap_or_else(|_| {
        // Absolute last resort — should never happen on supported platforms.
        eprintln!("[stronghold] WARNING: getrandom failed, using fallback");
    });
    // Best-effort write; if it fails the key will be regenerated next time.
    let _ = std::fs::write(key_file, &out[..]);
    // Restrict file permissions to owner-only on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(key_file, std::fs::Permissions::from_mode(0o600));
    }
}


/// Access the initialised Stronghold, returning an error if not yet initialised.
fn with_stronghold<T, F>(state: &StrongholdState, f: F) -> Result<T, String>
where
    F: FnOnce(&StrongholdInner) -> Result<T, String>,
{
    let guard = state.inner.lock().unwrap_or_else(|e| e.into_inner());
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
        .map_err(|e| {
            eprintln!("[stronghold] snapshot save error: {e}");
            "Failed to save vault snapshot".to_string()
        })
}

fn init_stronghold_state(
    state: &StrongholdState,
    snapshot_file: &Path,
    data_dir: &Path,
) -> Result<bool, String> {
    let mut guard = state.inner.lock().unwrap_or_else(|e| e.into_inner());

    if guard.is_some() {
        return Ok(true);
    }

    let password = derive_machine_password(data_dir);
    let keyprovider = KeyProvider::try_from(password).map_err(|e| {
        eprintln!("[stronghold] keyprovider error: {e}");
        "Failed to initialize vault key".to_string()
    })?;
    let snapshot_path = SnapshotPath::from_path(snapshot_file);

    let stronghold = Stronghold::default();

    if snapshot_file.exists() {
        stronghold
            .load_snapshot(&keyprovider, &snapshot_path)
            .map_err(|e| {
                eprintln!("[stronghold] snapshot load error: {e}");
                "Failed to load vault snapshot".to_string()
            })?;
    }

    let _ = stronghold
        .create_client(CLIENT_NAME)
        .or_else(|_| stronghold.load_client(CLIENT_NAME));

    stronghold
        .commit_with_keyprovider(&snapshot_path, &keyprovider)
        .map_err(|e| {
            eprintln!("[stronghold] snapshot save error: {e}");
            "Failed to save vault snapshot".to_string()
        })?;

    *guard = Some(StrongholdInner {
        stronghold,
        snapshot_path,
        keyprovider,
    });

    Ok(true)
}

fn store_credential_in_state(
    state: &StrongholdState,
    key: String,
    value: String,
) -> Result<bool, String> {
    if key.is_empty() {
        return Err("Credential key must not be empty".into());
    }
    if value.len() > 1_048_576 {
        return Err("Credential value too large (max 1 MiB)".into());
    }

    with_stronghold(state, |inner| {
        let client = inner
            .stronghold
            .get_client(CLIENT_NAME)
            .map_err(|e| {
                eprintln!("[stronghold] client load error: {e}");
                "Failed to access vault client".to_string()
            })?;
        let store = client.store();
        let store_key = format!("{}{}", CRED_PREFIX, key).into_bytes();
        store
            .insert(store_key, value.into_bytes(), None)
            .map_err(|e| {
                eprintln!("[stronghold] store insert error: {e}");
                "Failed to store credential".to_string()
            })?;
        save_snapshot(inner)?;
        Ok(true)
    })
}

fn get_credential_from_state(
    state: &StrongholdState,
    key: String,
) -> Result<Option<String>, String> {
    with_stronghold(state, |inner| {
        let client = inner
            .stronghold
            .get_client(CLIENT_NAME)
            .map_err(|e| {
                eprintln!("[stronghold] client load error: {e}");
                "Failed to access vault client".to_string()
            })?;
        let store = client.store();
        let store_key = format!("{}{}", CRED_PREFIX, key).into_bytes();
        match store.get(&store_key) {
            Ok(Some(bytes)) => {
                if bytes.is_empty() {
                    return Ok(None);
                }
                let s = String::from_utf8(bytes).map_err(|e| {
                    eprintln!("[stronghold] credential UTF-8 error: {e}");
                    "Credential is not valid UTF-8".to_string()
                })?;
                Ok(Some(s))
            }
            Ok(None) | Err(_) => Ok(None),
        }
    })
}

fn delete_credential_from_state(state: &StrongholdState, key: String) -> Result<bool, String> {
    with_stronghold(state, |inner| {
        let client = inner
            .stronghold
            .get_client(CLIENT_NAME)
            .map_err(|e| {
                eprintln!("[stronghold] client load error: {e}");
                "Failed to access vault client".to_string()
            })?;
        let store = client.store();
        let store_key = format!("{}{}", CRED_PREFIX, key).into_bytes();
        let _ = store.delete(&store_key);
        save_snapshot(inner)?;
        Ok(true)
    })
}

fn has_credential_in_state(state: &StrongholdState, key: String) -> Result<bool, String> {
    with_stronghold(state, |inner| {
        let client = inner
            .stronghold
            .get_client(CLIENT_NAME)
            .map_err(|e| {
                eprintln!("[stronghold] client load error: {e}");
                "Failed to access vault client".to_string()
            })?;
        let store = client.store();
        let store_key = format!("{}{}", CRED_PREFIX, key).into_bytes();
        store
            .contains_key(&store_key)
            .map_err(|e| {
                eprintln!("[stronghold] store error: {e}");
                "Failed to check credential".to_string()
            })
    })
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
    // Resolve snapshot path inside the Tauri app data directory.
    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| {
            eprintln!("[stronghold] cannot resolve app data dir: {e}");
            "Cannot resolve app data directory".to_string()
        })?;
    std::fs::create_dir_all(&data_dir).map_err(|e| {
        eprintln!("[stronghold] cannot create app data dir: {e}");
        "Cannot create app data directory".to_string()
    })?;
    let snapshot_file = data_dir.join("clawdstrike.stronghold");
    let state = app.state::<StrongholdState>();
    init_stronghold_state(&state, &snapshot_file, &data_dir)
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
    let state = app.state::<StrongholdState>();
    store_credential_in_state(&state, key, value)
}

/// Retrieve a credential value from the Stronghold vault.
/// Returns `null` if the key does not exist.
#[tauri::command]
pub async fn get_credential<R: Runtime>(
    app: AppHandle<R>,
    key: String,
) -> Result<Option<String>, String> {
    let state = app.state::<StrongholdState>();
    get_credential_from_state(&state, key)
}

/// Delete a credential from the Stronghold vault.
#[tauri::command]
pub async fn delete_credential<R: Runtime>(app: AppHandle<R>, key: String) -> Result<bool, String> {
    let state = app.state::<StrongholdState>();
    delete_credential_from_state(&state, key)
}

/// Check whether a credential exists in the Stronghold vault.
#[tauri::command]
pub async fn has_credential<R: Runtime>(app: AppHandle<R>, key: String) -> Result<bool, String> {
    let state = app.state::<StrongholdState>();
    has_credential_in_state(&state, key)
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
    generate_persistent_keypair_in_state(&state)
}

/// Retrieve the public key of the persistent signing keypair.
/// Returns `null` if no keypair has been generated yet.
#[tauri::command]
pub async fn get_signing_public_key<R: Runtime>(
    app: AppHandle<R>,
) -> Result<Option<String>, String> {
    let state = app.state::<StrongholdState>();
    get_signing_public_key_from_state(&state)
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
    let state = app.state::<StrongholdState>();
    sign_with_persistent_key_in_state(&state, data_hex)
}

// ---------------------------------------------------------------------------
// Public helper for workbench commands (P4-3: persistent key signing)
// ---------------------------------------------------------------------------

/// Attempt to load the persistent Ed25519 keypair from Stronghold state.
/// Returns `None` if Stronghold is not initialised or no key exists.
///
/// Used by `sign_receipt_persistent` in `workbench.rs`.
pub fn load_persistent_keypair_from_state(state: &StrongholdState) -> Option<hush_core::Keypair> {
    let guard = state.inner.lock().unwrap_or_else(|e| e.into_inner());
    let inner = guard.as_ref()?;
    let client = inner.stronghold.get_client(CLIENT_NAME).ok()?;
    let store = client.store();
    let seed_bytes = Zeroizing::new(store.get(SIGNING_KEY_RECORD).ok()??);

    if seed_bytes.len() != 32 {
        return None;
    }

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);
    let kp = hush_core::Keypair::from_seed(&seed);
    seed.zeroize();
    Some(kp)
}

fn generate_persistent_keypair_in_state(
    state: &StrongholdState,
) -> Result<GenerateKeypairResponse, String> {
    with_stronghold(state, |inner| {
        let client = inner
            .stronghold
            .get_client(CLIENT_NAME)
            .map_err(|e| {
                eprintln!("[stronghold] client load error: {e}");
                "Failed to access vault client".to_string()
            })?;
        let store = client.store();

        if let Ok(Some(existing_pub)) = store.get(SIGNING_PUBKEY_RECORD) {
            if existing_pub.len() == 32 {
                return Ok(GenerateKeypairResponse {
                    public_key: hex::encode(&existing_pub),
                    newly_generated: false,
                });
            }
        }

        let keypair = hush_core::Keypair::generate();
        let seed_hex = keypair.to_hex();
        let seed_bytes = Zeroizing::new(hex::decode(&seed_hex).map_err(|e| {
            eprintln!("[stronghold] hex decode error: {e}");
            "Failed to encode signing key".to_string()
        })?);
        let pub_bytes = keypair.public_key().as_bytes().to_vec();
        let pub_hex = keypair.public_key().to_hex();

        store
            .insert(SIGNING_KEY_RECORD.to_vec(), seed_bytes.to_vec(), None)
            .map_err(|e| {
                eprintln!("[stronghold] store signing key error: {e}");
                "Failed to store signing key".to_string()
            })?;
        store
            .insert(SIGNING_PUBKEY_RECORD.to_vec(), pub_bytes, None)
            .map_err(|e| {
                eprintln!("[stronghold] store public key error: {e}");
                "Failed to store public key".to_string()
            })?;

        save_snapshot(inner)?;

        Ok(GenerateKeypairResponse {
            public_key: pub_hex,
            newly_generated: true,
        })
    })
}

fn get_signing_public_key_from_state(state: &StrongholdState) -> Result<Option<String>, String> {
    with_stronghold(state, |inner| {
        let client = inner
            .stronghold
            .get_client(CLIENT_NAME)
            .map_err(|e| {
                eprintln!("[stronghold] client load error: {e}");
                "Failed to access vault client".to_string()
            })?;
        let store = client.store();
        match store.get(SIGNING_PUBKEY_RECORD) {
            Ok(Some(bytes)) if bytes.len() == 32 => Ok(Some(hex::encode(&bytes))),
            _ => Ok(None),
        }
    })
}

fn sign_with_persistent_key_in_state(
    state: &StrongholdState,
    data_hex: String,
) -> Result<String, String> {
    let data = hex::decode(data_hex.strip_prefix("0x").unwrap_or(&data_hex))
        .map_err(|_| "Invalid hex data".to_string())?;

    with_stronghold(state, |inner| {
        let client = inner
            .stronghold
            .get_client(CLIENT_NAME)
            .map_err(|e| {
                eprintln!("[stronghold] client load error: {e}");
                "Failed to access vault client".to_string()
            })?;
        let store = client.store();

        let seed_bytes = Zeroizing::new(
            store
                .get(SIGNING_KEY_RECORD)
                .map_err(|e| {
                    eprintln!("[stronghold] store read error: {e}");
                    "Failed to read signing key".to_string()
                })?
                .ok_or_else(|| {
                    "No persistent signing key found. Call generate_persistent_keypair first."
                        .to_string()
                })?,
        );

        if seed_bytes.len() != 32 {
            return Err("Stored signing key seed has invalid length".into());
        }

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_bytes);
        let keypair = hush_core::Keypair::from_seed(&seed);
        seed.zeroize();

        let signature = keypair.sign(&data);
        Ok(signature.to_hex())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn init_state() -> (StrongholdState, TempDir) {
        let temp_dir = TempDir::new().expect("temp dir");
        let snapshot = temp_dir.path().join("clawdstrike.stronghold");
        let keyprovider =
            KeyProvider::try_from(Zeroizing::new(vec![7u8; 32])).expect("test keyprovider");
        let snapshot_path = SnapshotPath::from_path(&snapshot);
        let stronghold = Stronghold::default();
        let _ = stronghold
            .create_client(CLIENT_NAME)
            .or_else(|_| stronghold.load_client(CLIENT_NAME));
        stronghold
            .commit_with_keyprovider(&snapshot_path, &keyprovider)
            .expect("commit snapshot");

        let state = StrongholdState {
            inner: Mutex::new(Some(StrongholdInner {
                stronghold,
                snapshot_path,
                keyprovider,
            })),
        };
        (state, temp_dir)
    }

    fn insert_raw_record(state: &StrongholdState, record: &[u8], value: Vec<u8>) {
        with_stronghold(state, |inner| {
            let client = inner
                .stronghold
                .get_client(CLIENT_NAME)
                .map_err(|e| format!("Client load error: {}", e))?;
            client
                .store()
                .insert(record.to_vec(), value, None)
                .map_err(|e| format!("Store insert error: {}", e))?;
            save_snapshot(inner)?;
            Ok(())
        })
        .expect("insert raw record");
    }

    #[test]
    fn derive_machine_password_is_stable_fixed_length_material() {
        let temp_dir = TempDir::new().expect("temp dir");
        let first = derive_machine_password(temp_dir.path());
        let second = derive_machine_password(temp_dir.path());

        assert_eq!(*first, *second);
        assert_eq!(first.len(), 32);

        // Verify the machine key file was created.
        assert!(temp_dir.path().join("vault-machine-key").exists());
    }

    #[test]
    fn initialized_test_state_persists_snapshot() {
        let (state, temp_dir) = init_state();
        let snapshot = temp_dir.path().join("clawdstrike.stronghold");

        assert!(snapshot.exists());
        assert!(
            store_credential_in_state(&state, "fleet".into(), "token".into())
                .expect("store credential")
        );
        assert!(snapshot.exists());
    }

    #[test]
    fn credential_helpers_require_initialized_state() {
        let state = StrongholdState::new();
        let err = store_credential_in_state(&state, "fleet".into(), "token".into())
            .expect_err("uninitialized state should fail");
        assert!(err.contains("Stronghold not initialised"));
    }

    #[test]
    fn credential_round_trip_validates_inputs() {
        let (state, _temp_dir) = init_state();

        let empty_key_err = store_credential_in_state(&state, String::new(), "token".into())
            .expect_err("empty key should fail");
        assert!(empty_key_err.contains("must not be empty"));

        let oversized_err =
            store_credential_in_state(&state, "fleet".into(), "x".repeat(1_048_577))
                .expect_err("oversized value should fail");
        assert!(oversized_err.contains("too large"));

        assert!(
            store_credential_in_state(&state, "fleet".into(), "token".into())
                .expect("store credential")
        );
        assert!(has_credential_in_state(&state, "fleet".into()).expect("has credential"));
        assert_eq!(
            get_credential_from_state(&state, "fleet".into()).expect("get credential"),
            Some("token".to_string())
        );
        assert!(delete_credential_from_state(&state, "fleet".into()).expect("delete credential"));
        assert!(!has_credential_in_state(&state, "fleet".into()).expect("missing credential"));
        assert_eq!(
            get_credential_from_state(&state, "fleet".into()).expect("get deleted credential"),
            None
        );
    }

    #[test]
    fn persistent_keypair_round_trip_signs_data() {
        let (state, _temp_dir) = init_state();

        assert_eq!(
            get_signing_public_key_from_state(&state).expect("empty public key"),
            None
        );

        let generated =
            generate_persistent_keypair_in_state(&state).expect("generate persistent keypair");
        assert!(generated.newly_generated);
        assert_eq!(generated.public_key.len(), 64);

        let cached =
            generate_persistent_keypair_in_state(&state).expect("reuse persistent keypair");
        assert!(!cached.newly_generated);
        assert_eq!(cached.public_key, generated.public_key);
        assert_eq!(
            get_signing_public_key_from_state(&state).expect("get public key"),
            Some(generated.public_key.clone())
        );

        let keypair = load_persistent_keypair_from_state(&state).expect("load keypair");
        assert_eq!(keypair.public_key().to_hex(), generated.public_key);

        let signature =
            sign_with_persistent_key_in_state(&state, "0x68656c6c6f".into()).expect("sign data");
        assert_eq!(signature.len(), 128);
    }

    #[test]
    fn persistent_key_helpers_cover_error_paths() {
        let (state, _temp_dir) = init_state();

        let missing_key_err = sign_with_persistent_key_in_state(&state, "6869".into())
            .expect_err("missing keypair should fail");
        assert!(missing_key_err.contains("Call generate_persistent_keypair first"));

        let invalid_hex_err = sign_with_persistent_key_in_state(&state, "not-hex".into())
            .expect_err("invalid hex should fail");
        assert!(invalid_hex_err.contains("Invalid hex data"));

        insert_raw_record(&state, SIGNING_PUBKEY_RECORD, vec![7u8; 31]);
        assert_eq!(
            get_signing_public_key_from_state(&state).expect("invalid public key cache"),
            None
        );

        insert_raw_record(&state, SIGNING_KEY_RECORD, vec![9u8; 31]);
        assert!(
            load_persistent_keypair_from_state(&state).is_none(),
            "invalid stored seed length should be rejected"
        );
        let invalid_seed_err = sign_with_persistent_key_in_state(&state, "6869".into())
            .expect_err("invalid seed should fail");
        assert!(invalid_seed_err.contains("invalid length"));
    }
}
