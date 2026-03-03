use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::{fs, io::Write};

/// Atomically write a file with private permissions (0600 on Unix).
pub fn write_private_atomic(path: &Path, bytes: &[u8], target: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create {target} parent dir {:?}", parent))?;
    }

    let tmp = temp_path(path);

    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("Failed to open temporary {target} file {:?}", tmp))?;
        file.write_all(bytes)
            .with_context(|| format!("Failed to write temporary {target} file {:?}", tmp))?;
        file.sync_all()
            .with_context(|| format!("Failed to sync temporary {target} file {:?}", tmp))?;
    }

    #[cfg(not(unix))]
    {
        fs::write(&tmp, bytes)
            .with_context(|| format!("Failed to write temporary {target} file {:?}", tmp))?;
    }

    replace_file(&tmp, path, target)?;

    #[cfg(unix)]
    {
        ensure_mode_0600(path, target)?;
    }

    Ok(())
}

fn temp_path(path: &Path) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let base = path
        .file_name()
        .map(|value| value.to_string_lossy().to_string())
        .unwrap_or_else(|| "clawdstrike".to_string());
    let unique = uuid::Uuid::new_v4().simple().to_string();
    parent.join(format!(".{base}.{unique}.tmp"))
}

#[cfg(windows)]
fn backup_path(path: &Path) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let base = path
        .file_name()
        .map(|value| value.to_string_lossy().to_string())
        .unwrap_or_else(|| "clawdstrike".to_string());
    let unique = uuid::Uuid::new_v4().simple().to_string();
    parent.join(format!(".{base}.{unique}.bak"))
}

#[cfg(not(windows))]
fn replace_file(tmp: &Path, path: &Path, target: &str) -> Result<()> {
    fs::rename(tmp, path)
        .with_context(|| format!("Failed to atomically replace {target} at {:?}", path))
}

#[cfg(windows)]
fn replace_file(tmp: &Path, path: &Path, target: &str) -> Result<()> {
    if !path.exists() {
        return fs::rename(tmp, path)
            .with_context(|| format!("Failed to atomically replace {target} at {:?}", path));
    }

    let backup = backup_path(path);
    fs::rename(path, &backup)
        .with_context(|| format!("Failed to stage existing {target} file for replacement"))?;

    if let Err(rename_err) = fs::rename(tmp, path) {
        if let Err(rollback_err) = fs::rename(&backup, path) {
            anyhow::bail!(
                "Failed to replace {target} at {:?}: {}; rollback also failed: {}",
                path,
                rename_err,
                rollback_err
            );
        }
        return Err(rename_err)
            .with_context(|| format!("Failed to atomically replace {target} at {:?}", path));
    }

    if backup.exists() {
        fs::remove_file(&backup)
            .with_context(|| format!("Failed to clean up staged {target} backup"))?;
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_mode_0600(path: &Path, target: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = fs::metadata(path)
        .with_context(|| format!("Failed to read {target} metadata {:?}", path))?
        .permissions()
        .mode()
        & 0o777;

    if mode != 0o600 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("Failed to set {target} permissions on {:?}", path))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temp_path_is_unique_per_call() {
        let path = PathBuf::from("/tmp/clawdstrike-test.yaml");
        let a = temp_path(&path);
        let b = temp_path(&path);
        assert_ne!(a, b);
    }

    #[test]
    fn write_private_atomic_overwrites_existing_file() {
        let unique = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(duration) => duration.as_nanos(),
            Err(_) => 0,
        };
        let dir = std::env::temp_dir().join(format!("clawdstrike-fs-write-private-{unique}"));
        if let Err(err) = fs::create_dir_all(&dir) {
            panic!("failed to create temp dir: {err}");
        }
        let path = dir.join("target.yaml");

        if let Err(err) = write_private_atomic(&path, b"one", "test file") {
            panic!("first private write failed: {err}");
        }
        if let Err(err) = write_private_atomic(&path, b"two", "test file") {
            panic!("second private write failed: {err}");
        }

        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) => panic!("failed to read rewritten file: {err}"),
        };
        assert_eq!(bytes, b"two");

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }
}
