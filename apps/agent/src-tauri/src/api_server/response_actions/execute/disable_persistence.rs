//! Execute the `disable_persistence` response action.

use super::super::*;

pub(crate) async fn execute_disable_persistence_response(
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
    let source_path = disable_persistence_target_path(plan, graph).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid persistence target: {err}"),
        )
    })?;
    validate_disable_persistence_source_path(&source_path).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("unsafe persistence target: {err}"),
        )
    })?;
    let bytes = fs::read(&source_path)
        .with_context(|| format!("read persistence target {}", source_path.display()))
        .map_err(internal_error)?;
    let byte_count = bytes.len() as u64;
    let content_hash = sha256(&bytes).to_hex_prefixed();
    let quarantine_root = state.edr_quarantine_root.as_ref();
    fs::create_dir_all(quarantine_root)
        .with_context(|| {
            format!(
                "create persistence disable directory {}",
                quarantine_root.display()
            )
        })
        .map_err(internal_error)?;
    let disabled_path =
        persistence_disable_destination_path(quarantine_root, plan, &source_path, &content_hash);
    if disabled_path.exists() {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "disabled persistence artifact already exists: {}",
                disabled_path.display()
            ),
        ));
    }
    let mut execution = EndpointResponseExecutionReport::disable_persistence(
        plan,
        graph,
        source_path.display().to_string(),
        disabled_path.display().to_string(),
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
        "pre_effect_disable_persistence",
    )
    .await?;
    fs::rename(&source_path, &disabled_path)
        .with_context(|| {
            format!(
                "move persistence target {} to {}",
                source_path.display(),
                disabled_path.display()
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

pub(crate) fn disable_persistence_target_path(
    plan: &EndpointResponsePlan,
    graph: &CausalGraph,
) -> Result<PathBuf> {
    let node = graph
        .nodes
        .get(&plan.root_node_id)
        .ok_or_else(|| anyhow::anyhow!("root node not found: {}", plan.root_node_id))?;
    let path = match node.kind {
        CausalNodeKind::File => PathBuf::from(node.label.trim()),
        CausalNodeKind::BrowserExtension => {
            browser_extension_manifest_target_path(PathBuf::from(node.label.trim()))
        }
        _ => {
            return Err(anyhow::anyhow!(
                "root node must be a file or browser_extension node for disable_persistence, got {:?}",
                node.kind
            ));
        }
    };
    if !path.is_absolute() {
        return Err(anyhow::anyhow!(
            "persistence target path must be absolute: {}",
            node.label
        ));
    }
    if !path_is_bounded_persistence_target(&path) {
        return Err(anyhow::anyhow!(
            "persistence target must be a bounded LaunchAgent/LaunchDaemon plist, systemd user/system unit or drop-in, XDG autostart desktop entry, KDE Plasma env/autostart script, shell startup file, system profile drop-in, user cron spool file, system cron drop-in, or browser extension manifest: {}",
            path.display()
        ));
    }
    Ok(path)
}

fn browser_extension_manifest_target_path(path: PathBuf) -> PathBuf {
    if path
        .file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|file_name| file_name.eq_ignore_ascii_case("manifest.json"))
    {
        path
    } else {
        path.join("manifest.json")
    }
}

pub(crate) fn validate_disable_persistence_source_path(path: &FsPath) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("stat persistence target {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(anyhow::anyhow!(
            "persistence target must not be a symlink: {}",
            path.display()
        ));
    }
    if !metadata.is_file() {
        return Err(anyhow::anyhow!(
            "persistence target must be a regular file: {}",
            path.display()
        ));
    }
    if !path_is_bounded_persistence_target(path) {
        return Err(anyhow::anyhow!(
            "persistence target must be a bounded LaunchAgent/LaunchDaemon plist, systemd user/system unit or drop-in, XDG autostart desktop entry, KDE Plasma env/autostart script, shell startup file, system profile drop-in, user cron spool file, system cron drop-in, or browser extension manifest: {}",
            path.display()
        ));
    }
    Ok(())
}

pub(crate) fn persistence_disable_destination_path(
    quarantine_root: &FsPath,
    plan: &EndpointResponsePlan,
    source_path: &FsPath,
    content_hash: &str,
) -> PathBuf {
    let hash_fragment = content_hash
        .trim_start_matches("0x")
        .chars()
        .take(16)
        .collect::<String>();
    let source_name = source_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("launch-agent.plist");
    quarantine_root.join(format!(
        "{}-{}-{}.disabled-persistence",
        safe_filename_fragment(&plan.action_id),
        safe_filename_fragment(&hash_fragment),
        safe_filename_fragment(source_name)
    ))
}
