use std::ffi::OsStr;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use tauri::{AppHandle, Manager, Runtime};

use sha2::{Digest, Sha256};

use super::file_watcher::{mark_self_writes, record_content_hash_value, SwarmFileWatcherState};

const PERSISTENCE_DIR: &str = "state";
const MAX_FILENAME_LEN: usize = 128;
const MAX_CONTENT_BYTES: usize = 16 * 1024 * 1024;

pub(crate) fn validate_filename(filename: &str) -> Result<(), String> {
    if filename.is_empty() {
        return Err("Persistence filename must not be empty".to_string());
    }
    if filename.len() > MAX_FILENAME_LEN {
        return Err("Persistence filename is too long".to_string());
    }
    if !filename.ends_with(".json") {
        return Err("Persistence filename must end with .json".to_string());
    }
    if filename.contains('/') || filename.contains('\\') {
        return Err(
            "Persistence filename must be a single file name without path separators".to_string(),
        );
    }

    let path = Path::new(filename);
    let mut components = path.components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(name)), None) if name == OsStr::new(filename) => {}
        _ => {
            return Err(
                "Persistence filename must be a single file name without path separators"
                    .to_string(),
            )
        }
    }

    if filename.starts_with('.') {
        return Err("Persistence filename must not start with '.'".to_string());
    }

    Ok(())
}

pub(crate) fn persistence_root<R: Runtime>(app: &AppHandle<R>) -> Result<PathBuf, String> {
    let root = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("Failed to resolve app data dir: {e}"))?
        .join(PERSISTENCE_DIR);

    std::fs::create_dir_all(&root)
        .map_err(|e| format!("Failed to create persistence dir {}: {e}", root.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700));
    }

    Ok(root)
}

fn resolve_paths(root: &Path, filename: &str) -> Result<(PathBuf, PathBuf, PathBuf), String> {
    validate_filename(filename)?;

    let target = root.join(filename);
    let temp = root.join(format!(".{filename}.tmp"));
    let backup = root.join(format!("{filename}.bak"));
    Ok((target, temp, backup))
}

fn ensure_not_symlink(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }

    let metadata = std::fs::symlink_metadata(path)
        .map_err(|e| format!("Failed to inspect {}: {e}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "Refusing to access symlinked persistence path {}",
            path.display()
        ));
    }

    Ok(())
}

fn cleanup_stale_temp(path: &Path) {
    if path.exists() {
        let _ = std::fs::remove_file(path);
    }
}

fn read_persistence_file(root: &Path, filename: &str) -> Result<Option<String>, String> {
    let (target, temp, backup) = resolve_paths(root, filename)?;
    cleanup_stale_temp(&temp);

    ensure_not_symlink(&target)?;
    ensure_not_symlink(&backup)?;

    let source = if target.exists() {
        target
    } else if backup.exists() {
        backup
    } else {
        return Ok(None);
    };

    std::fs::read_to_string(&source)
        .map(Some)
        .map_err(|e| format!("Failed to read persistence file {}: {e}", source.display()))
}

fn write_persistence_file(root: &Path, filename: &str, content: String) -> Result<(), String> {
    if content.len() > MAX_CONTENT_BYTES {
        return Err(format!(
            "Persistence payload exceeds max size ({} bytes > {} bytes)",
            content.len(),
            MAX_CONTENT_BYTES
        ));
    }

    let (target, temp, backup) = resolve_paths(root, filename)?;
    cleanup_stale_temp(&temp);

    ensure_not_symlink(&target)?;
    ensure_not_symlink(&backup)?;

    {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temp)
            .map_err(|e| {
                format!(
                    "Failed to open temp persistence file {}: {e}",
                    temp.display()
                )
            })?;

        file.write_all(content.as_bytes()).map_err(|e| {
            format!(
                "Failed to write temp persistence file {}: {e}",
                temp.display()
            )
        })?;
        file.sync_all().map_err(|e| {
            format!(
                "Failed to sync temp persistence file {}: {e}",
                temp.display()
            )
        })?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o600));
    }

    let had_existing_target = target.exists();
    if had_existing_target {
        if backup.exists() {
            std::fs::remove_file(&backup).map_err(|e| {
                format!(
                    "Failed to remove stale persistence backup {}: {e}",
                    backup.display()
                )
            })?;
        }

        std::fs::rename(&target, &backup).map_err(|e| {
            format!(
                "Failed to move previous persistence file {} to backup {}: {e}",
                target.display(),
                backup.display()
            )
        })?;
    }

    if let Err(error) = std::fs::rename(&temp, &target) {
        cleanup_stale_temp(&temp);
        if had_existing_target {
            let _ = std::fs::rename(&backup, &target);
        }
        return Err(format!(
            "Failed to finalize persistence file {}: {error}",
            target.display()
        ));
    }

    Ok(())
}

#[tauri::command]
pub async fn read_app_persistence_file<R: Runtime>(
    app: AppHandle<R>,
    filename: String,
) -> Result<Option<String>, String> {
    let root = persistence_root(&app)?;
    tauri::async_runtime::spawn_blocking(move || read_persistence_file(&root, &filename))
        .await
        .map_err(|e| format!("Persistence read task failed: {e}"))?
}

#[tauri::command]
pub async fn write_app_persistence_file<R: Runtime>(
    app: AppHandle<R>,
    watcher_state: tauri::State<'_, SwarmFileWatcherState>,
    filename: String,
    content: String,
) -> Result<(), String> {
    let root = persistence_root(&app)?;
    let (target, temp, backup) = resolve_paths(&root, &filename)?;

    // Pre-compute the content hash before moving `content` into the blocking task.
    let content_hash: [u8; 32] = Sha256::digest(content.as_bytes()).into();

    // Record self-write suppression and content hash BEFORE the blocking write
    // to close a TOCTOU race: the file watcher debouncer could fire between
    // the atomic rename inside write_persistence_file and the hash recording.
    // The hash is computed from the in-memory content that will be written, so
    // recording it early is correct.
    mark_self_writes(&watcher_state, &[target.clone(), temp, backup]);
    record_content_hash_value(&watcher_state, &target, content_hash);

    tauri::async_runtime::spawn_blocking(move || write_persistence_file(&root, &filename, content))
        .await
        .map_err(|e| format!("Persistence write task failed: {e}"))??;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{read_persistence_file, validate_filename, write_persistence_file};

    #[test]
    fn validate_filename_rejects_paths() {
        assert!(validate_filename("../evil.json").is_err());
        assert!(validate_filename("nested/evil.json").is_err());
        assert!(validate_filename("nested\\\\evil.json").is_err());
        assert!(validate_filename(".hidden.json").is_err());
    }

    #[test]
    fn validate_filename_accepts_simple_json_files() {
        assert!(validate_filename("swarm-board-state.v1.json").is_ok());
    }

    #[test]
    fn read_write_round_trip_uses_backup_when_primary_missing() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let root = tempdir.path();

        write_persistence_file(root, "state.json", "{\"v\":1}".to_string()).expect("write 1");
        write_persistence_file(root, "state.json", "{\"v\":2}".to_string()).expect("write 2");

        let target = root.join("state.json");
        let backup = root.join("state.json.bak");
        assert!(target.exists());
        assert!(backup.exists());

        std::fs::remove_file(&target).expect("remove target");

        let recovered = read_persistence_file(root, "state.json")
            .expect("read")
            .expect("backup read");
        assert_eq!(recovered, "{\"v\":1}");
    }
}
