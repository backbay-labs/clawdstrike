//! Roll back the `quarantine_file` response action.

use super::super::*;

pub(crate) fn execute_quarantine_file_rollback(
    state: &AgentApiState,
    execution: &EndpointResponseExecutionReport,
    reason: &str,
) -> Result<EndpointResponseRollbackReport, (StatusCode, String)> {
    let effect = quarantine_file_effect(execution).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid quarantine execution effect: {err}"),
        )
    })?;
    let target_path = PathBuf::from(effect.target.as_str());
    validate_quarantine_restore_target_path(&target_path).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("unsafe rollback target: {err}"),
        )
    })?;
    if target_path.exists() {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "rollback target already exists, refusing overwrite: {}",
                target_path.display()
            ),
        ));
    }
    let artifact_path = effect
        .artifact
        .as_deref()
        .map(PathBuf::from)
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "quarantine effect is missing artifact path".to_string(),
            )
        })?;
    validate_quarantine_artifact_path(state.edr_quarantine_root.as_ref(), &artifact_path)?;
    let artifact_bytes = fs::read(&artifact_path)
        .with_context(|| format!("read quarantine artifact {}", artifact_path.display()))
        .map_err(internal_error)?;
    let artifact_hash = sha256(&artifact_bytes).to_hex_prefixed();
    let expected_hash = effect.content_hash.as_deref().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "quarantine effect is missing content hash".to_string(),
        )
    })?;
    if artifact_hash != expected_hash {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "quarantine artifact hash mismatch: expected {expected_hash}, got {artifact_hash}"
            ),
        ));
    }
    if let Some(expected_bytes) = effect.byte_count {
        if artifact_bytes.len() as u64 != expected_bytes {
            return Err((
                StatusCode::CONFLICT,
                format!(
                    "quarantine artifact byte count mismatch: expected {expected_bytes}, got {}",
                    artifact_bytes.len()
                ),
            ));
        }
    }
    if let Some(parent) = target_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create rollback target directory {}", parent.display()))
            .map_err(internal_error)?;
    }
    let rollback =
        EndpointResponseRollbackReport::quarantine_file(execution, reason, chrono::Utc::now())
            .map_err(internal_error)?;
    fs::rename(&artifact_path, &target_path)
        .with_context(|| {
            format!(
                "restore quarantine artifact {} to {}",
                artifact_path.display(),
                target_path.display()
            )
        })
        .map_err(internal_error)?;
    Ok(rollback)
}

pub(crate) fn validate_quarantine_restore_target_path(path: &FsPath) -> Result<()> {
    if !path.is_absolute() {
        return Err(anyhow::anyhow!(
            "rollback target path must be absolute: {}",
            path.display()
        ));
    }
    if !path_is_bounded_quarantine_source(path) {
        return Err(anyhow::anyhow!(
            "rollback target must be in a temp, download, cache, node_modules, or build-output path: {}",
            path.display()
        ));
    }
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            return Err(anyhow::anyhow!(
                "rollback target must not be a symlink: {}",
                path.display()
            ));
        }
    }
    Ok(())
}
