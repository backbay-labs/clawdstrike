//! Honey-artifact deception plan validation and cleanup.

use anyhow::{Context, Result};
use std::collections::BTreeSet;
use std::fs;

pub(crate) fn validate_deception_cleanup_plan(
    plan: &clawdstrike_policy_event::edr::DeceptionPlan,
) -> std::result::Result<(), String> {
    if !plan.root.is_absolute() {
        return Err(format!(
            "deception cleanup root must be absolute: {}",
            plan.root.display()
        ));
    }
    for artifact in &plan.artifacts {
        validate_deception_cleanup_relative_path(&artifact.relative_path)?;
    }
    Ok(())
}

fn validate_deception_cleanup_relative_path(
    path: &std::path::Path,
) -> std::result::Result<(), String> {
    use std::path::Component;
    if path.is_absolute() {
        return Err(format!(
            "honey artifact cleanup path must be relative: {}",
            path.display()
        ));
    }
    for component in path.components() {
        if matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        ) {
            return Err(format!(
                "honey artifact cleanup path contains unsafe component: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

pub(crate) fn cleanup_deception_plan(
    plan: &clawdstrike_policy_event::edr::DeceptionPlan,
    registered_ids: &BTreeSet<String>,
    dry_run: bool,
) -> Result<(
    clawdstrike_policy_event::edr::DeceptionCleanupReport,
    BTreeSet<String>,
)> {
    use clawdstrike_policy_event::edr::DeceptionCleanupReport;
    let mut report = DeceptionCleanupReport {
        dry_run,
        removed: Vec::new(),
        would_remove: Vec::new(),
        missing: Vec::new(),
        refused: Vec::new(),
    };
    let mut artifact_ids_to_deregister = BTreeSet::new();

    for artifact in &plan.artifacts {
        let path = artifact.absolute_path(&plan.root);
        let path_text = path.display().to_string();
        if !registered_ids.contains(&artifact.artifact_id) {
            report.refused.push(format!(
                "{}: unregistered honey artifact {}",
                path_text, artifact.artifact_id
            ));
            continue;
        }

        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                report.missing.push(path_text);
                artifact_ids_to_deregister.insert(artifact.artifact_id.clone());
                continue;
            }
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("inspect honey artifact {}", path.display()));
            }
        };
        if metadata.file_type().is_symlink() {
            report
                .refused
                .push(format!("{path_text}: refusing to remove symlink"));
            continue;
        }
        if !metadata.is_file() {
            report
                .refused
                .push(format!("{path_text}: refusing to remove non-file"));
            continue;
        }

        let contents = fs::read(&path)
            .with_context(|| format!("read honey artifact before cleanup {}", path.display()))?;
        if contents != artifact.contents.as_bytes() {
            report.refused.push(format!(
                "{path_text}: content does not match registered honey artifact"
            ));
            continue;
        }

        if dry_run {
            report.would_remove.push(path_text);
        } else {
            fs::remove_file(&path)
                .with_context(|| format!("remove honey artifact {}", path.display()))?;
            report.removed.push(path_text);
            artifact_ids_to_deregister.insert(artifact.artifact_id.clone());
        }
    }

    Ok((report, artifact_ids_to_deregister))
}
