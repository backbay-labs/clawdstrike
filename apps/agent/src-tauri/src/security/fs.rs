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

    fs::rename(&tmp, path)
        .with_context(|| format!("Failed to atomically replace {target} at {:?}", path))?;

    #[cfg(unix)]
    {
        ensure_mode_0600(path, target)?;
    }

    Ok(())
}

fn temp_path(path: &Path) -> PathBuf {
    let mut ext = path
        .extension()
        .map(|value| value.to_string_lossy().to_string())
        .unwrap_or_else(|| "tmp".to_string());
    ext.push_str(".tmp");
    path.with_extension(ext)
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
