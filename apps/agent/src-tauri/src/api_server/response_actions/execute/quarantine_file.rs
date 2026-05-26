//! Execute the `quarantine_file` response action.

use super::super::*;

pub(crate) async fn execute_quarantine_file_response(
    state: &AgentApiState,
    plan: &EndpointResponsePlan,
    graph: &CausalGraph,
    actor: EndpointDecisionActor,
) -> Result<
    (
        EndpointResponseExecutionReport,
        StoredEndpointEvidenceBundle,
        SignedReceipt,
        SignedReceipt,
    ),
    (StatusCode, String),
> {
    let source_path = quarantine_file_target_path(plan, graph).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid quarantine target: {err}"),
        )
    })?;
    validate_quarantine_source_path(&source_path).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("unsafe quarantine target: {err}"),
        )
    })?;
    let bytes = fs::read(&source_path)
        .with_context(|| format!("read quarantine target {}", source_path.display()))
        .map_err(internal_error)?;
    let byte_count = bytes.len() as u64;
    let content_hash = sha256(&bytes).to_hex_prefixed();
    let quarantine_root = state.edr_quarantine_root.as_ref();
    fs::create_dir_all(quarantine_root)
        .with_context(|| format!("create quarantine directory {}", quarantine_root.display()))
        .map_err(internal_error)?;
    let quarantine_path =
        quarantine_destination_path(quarantine_root, plan, &source_path, &content_hash);
    if quarantine_path.exists() {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "quarantine artifact already exists: {}",
                quarantine_path.display()
            ),
        ));
    }
    let mut execution = EndpointResponseExecutionReport::quarantine_file(
        plan,
        graph,
        source_path.display().to_string(),
        quarantine_path.display().to_string(),
        &content_hash,
        byte_count,
    )
    .map_err(internal_error)?;
    execution.actor = Some(actor.clone());
    let stored_bundle = state
        .edr_evidence_bundle_store
        .lock()
        .await
        .store(&execution.evidence_bundle, graph)
        .map_err(internal_error)?;
    emit_pre_effect_response_execution_receipt(
        state,
        &execution,
        graph,
        actor.clone(),
        "pre_effect_quarantine_file",
    )
    .await?;
    fs::rename(&source_path, &quarantine_path)
        .with_context(|| {
            format!(
                "move quarantine target {} to {}",
                source_path.display(),
                quarantine_path.display()
            )
        })
        .map_err(internal_error)?;
    let (execution_receipt, evidence_bundle_receipt) =
        append_and_receipt_edr_response_execution(state, &execution, graph, Some(actor), &[])
            .await?;
    Ok((
        execution,
        stored_bundle,
        execution_receipt,
        evidence_bundle_receipt,
    ))
}

pub(super) fn validate_quarantine_source_path(path: &FsPath) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("stat quarantine target {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(anyhow::anyhow!(
            "quarantine target must not be a symlink: {}",
            path.display()
        ));
    }
    if !metadata.is_file() {
        return Err(anyhow::anyhow!(
            "quarantine target must be a regular file: {}",
            path.display()
        ));
    }
    if !path_is_bounded_quarantine_source(path) {
        return Err(anyhow::anyhow!(
            "quarantine target must be in a temp, download, cache, node_modules, or build-output path: {}",
            path.display()
        ));
    }
    Ok(())
}

pub(in crate::api_server::response_actions) fn path_is_bounded_quarantine_source(
    path: &FsPath,
) -> bool {
    let normalized = path.display().to_string().replace('\\', "/");
    let temp_dir = std::env::temp_dir()
        .display()
        .to_string()
        .replace('\\', "/");
    normalized.starts_with(temp_dir.as_str())
        || normalized.starts_with("/tmp/")
        || normalized.starts_with("/private/tmp/")
        || normalized.starts_with("/var/folders/")
        || normalized.contains("/Downloads/")
        || normalized.contains("/Library/Caches/")
        || normalized.contains("/.cache/")
        || normalized.contains("/node_modules/")
        || normalized.contains("/target/debug/")
        || normalized.contains("/target/release/")
}

pub(in crate::api_server::response_actions) fn validate_quarantine_artifact_path(
    quarantine_root: &FsPath,
    artifact_path: &FsPath,
) -> Result<(), (StatusCode, String)> {
    let root = fs::canonicalize(quarantine_root)
        .with_context(|| format!("canonicalize quarantine root {}", quarantine_root.display()))
        .map_err(internal_error)?;
    let artifact = fs::canonicalize(artifact_path)
        .with_context(|| {
            format!(
                "canonicalize quarantine artifact {}",
                artifact_path.display()
            )
        })
        .map_err(internal_error)?;
    if !artifact.starts_with(root.as_path()) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "quarantine artifact is outside quarantine root: {}",
                artifact_path.display()
            ),
        ));
    }
    let metadata = fs::symlink_metadata(artifact_path)
        .with_context(|| format!("stat quarantine artifact {}", artifact_path.display()))
        .map_err(internal_error)?;
    if metadata.file_type().is_symlink() {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "quarantine artifact must not be a symlink: {}",
                artifact_path.display()
            ),
        ));
    }
    if !metadata.is_file() {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "quarantine artifact must be a regular file: {}",
                artifact_path.display()
            ),
        ));
    }
    Ok(())
}
