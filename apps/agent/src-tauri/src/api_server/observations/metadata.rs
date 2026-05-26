use super::*;

pub(crate) fn developer_activity_default_process_image(
    activity: &EdrDeveloperActivity,
    event: &EndpointEvent,
) -> Option<String> {
    if let Some(image) = trimmed_owned(activity.image.as_deref()) {
        return Some(image);
    }
    match event {
        EndpointEvent::ToolCall { tool_name, .. } => Some(tool_name.clone()),
        EndpointEvent::PackageScript { manager, .. } => Some(manager.as_str().to_string()),
        EndpointEvent::ProcessExec { image, .. } => Some(image.clone()),
        EndpointEvent::BrowserDownload { browser, .. }
        | EndpointEvent::BrowserExtensionInstall { browser, .. } => Some(browser.clone()),
        EndpointEvent::DnsLookup { .. } => Some("dns-collector".to_string()),
        EndpointEvent::CredentialAccess { .. } => activity
            .agent_id
            .as_deref()
            .and_then(|value| non_empty(Some(value)))
            .map(ToString::to_string)
            .or_else(|| Some("developer-collector".to_string())),
        _ => Some("developer-collector".to_string()),
    }
}

pub(crate) fn developer_activity_command_line(
    activity: &EdrDeveloperActivity,
    event: &EndpointEvent,
) -> Option<String> {
    if let Some(command_line) = trimmed_owned(activity.command_line.as_deref()) {
        return Some(command_line);
    }
    match event {
        EndpointEvent::ProcessExec { image, args, .. } if args.is_empty() => Some(image.clone()),
        EndpointEvent::ProcessExec { image, args, .. } => {
            Some(format!("{image} {}", args.join(" ")))
        }
        EndpointEvent::PackageScript {
            manager,
            phase,
            script,
            ..
        } => Some(format!("{} {phase} {script}", manager.as_str())),
        EndpointEvent::ToolCall { tool_name, .. } => Some(tool_name.clone()),
        EndpointEvent::CredentialAccess { path, name, .. } => path
            .clone()
            .or_else(|| name.clone())
            .map(|target| format!("credential_access {target}")),
        EndpointEvent::FileAccess {
            operation, path, ..
        } => Some(format!(
            "file_access {} {path}",
            file_operation_name(operation)
        )),
        EndpointEvent::NetworkFlow {
            host, port, url, ..
        } => Some(format!(
            "network_egress {}",
            url.clone().unwrap_or_else(|| format!("{host}:{port}"))
        )),
        EndpointEvent::LaunchPersistence {
            operation, path, ..
        } => Some(format!(
            "persistence_change {} {path}",
            file_operation_name(operation)
        )),
        EndpointEvent::BrowserDownload { path, .. } => Some(format!("browser_download {path}")),
        EndpointEvent::BrowserExtensionInstall { path, .. } => {
            Some(format!("browser_extension {path}"))
        }
        EndpointEvent::DnsLookup { query, .. } => Some(format!("dns_lookup {query}")),
        _ => None,
    }
}

pub(crate) fn developer_activity_metadata(
    activity: &EdrDeveloperActivity,
) -> BTreeMap<String, serde_json::Value> {
    let mut metadata = redact_developer_activity_metadata(&activity.metadata);
    metadata.insert(
        "collectorKind".to_string(),
        serde_json::Value::String("developer_activity".to_string()),
    );
    metadata.insert(
        "developerActivityKind".to_string(),
        serde_json::Value::String(activity.kind.as_str().to_string()),
    );
    let tool_kind = match activity.kind {
        EdrDeveloperActivityKind::McpTool => Some("mcp"),
        EdrDeveloperActivityKind::BrowserAutomation => Some("browser_automation"),
        _ => None,
    };
    if let Some(tool_kind) = tool_kind {
        metadata
            .entry("toolKind".to_string())
            .or_insert_with(|| serde_json::Value::String(tool_kind.to_string()));
    }
    for (key, value) in [
        ("agentId", activity.agent_id.as_deref()),
        ("workloadId", activity.workload_id.as_deref()),
        ("approvalId", activity.approval_id.as_deref()),
        ("toolCallId", activity.tool_call_id.as_deref()),
        ("method", activity.method.as_deref()),
        ("contentHash", activity.content_hash.as_deref()),
        ("patchHash", activity.patch_hash.as_deref()),
        ("mechanism", activity.mechanism.as_deref()),
    ] {
        if let Some(value) = trimmed_owned(value) {
            metadata
                .entry(key.to_string())
                .or_insert_with(|| serde_json::Value::String(value));
        }
    }
    if let Some(patch_bytes) = activity.patch_bytes {
        metadata
            .entry("patchBytes".to_string())
            .or_insert_with(|| serde_json::Value::from(patch_bytes));
    }
    if let Some(byte_count) = developer_activity_byte_count(activity) {
        metadata.insert(
            "downloadByteCount".to_string(),
            serde_json::Value::from(byte_count),
        );
    }
    metadata
}

pub(crate) fn developer_activity_byte_count(activity: &EdrDeveloperActivity) -> Option<u64> {
    activity.byte_count.or_else(|| {
        metadata_u64(
            &activity.metadata,
            &[
                "downloadByteCount",
                "download_byte_count",
                "byteCount",
                "byte_count",
                "fileSize",
                "file_size",
                "transferSize",
                "transfer_size",
            ],
        )
    })
}

fn metadata_u64(metadata: &BTreeMap<String, serde_json::Value>, keys: &[&str]) -> Option<u64> {
    for key in keys {
        let Some(value) = metadata.get(*key) else {
            continue;
        };
        if let Some(number) = value.as_u64() {
            return Some(number);
        }
        if let Some(text) = value.as_str().map(str::trim) {
            if text.is_empty() || !text.chars().all(|ch| ch.is_ascii_digit()) {
                continue;
            }
            if let Ok(number) = text.parse::<u64>() {
                return Some(number);
            }
        }
    }
    None
}

pub(crate) fn redact_developer_activity_metadata(
    metadata: &BTreeMap<String, serde_json::Value>,
) -> BTreeMap<String, serde_json::Value> {
    redact_endpoint_observation_metadata(metadata)
}

pub(crate) fn redact_endpoint_observations(
    observations: &[EndpointObservation],
) -> Vec<EndpointObservation> {
    observations
        .iter()
        .map(redact_endpoint_observation)
        .collect()
}

fn redact_endpoint_observation(observation: &EndpointObservation) -> EndpointObservation {
    let mut redacted = observation.clone();
    redacted.process = redact_endpoint_process(&redacted.process);
    redacted.event = redact_endpoint_event(&redacted.event);
    redacted.metadata = redact_endpoint_observation_metadata(&redacted.metadata);
    redacted
}

fn redact_endpoint_process(process: &EndpointProcess) -> EndpointProcess {
    let mut redacted = process.clone();
    if let Some(command_line) = trimmed_owned(redacted.command_line.as_deref()) {
        redacted.command_line = Some(redact_developer_activity_command_line(&command_line));
    }
    redacted
}

fn redact_endpoint_event(event: &EndpointEvent) -> EndpointEvent {
    match event {
        EndpointEvent::ProcessExec { image, args, env } => EndpointEvent::ProcessExec {
            image: image.clone(),
            args: redact_developer_activity_args(args),
            env: env
                .iter()
                .map(|(key, value)| {
                    let value = if developer_activity_sensitive_metadata_key(key) {
                        "[REDACTED]".to_string()
                    } else {
                        redact_developer_activity_command_line(value)
                    };
                    (key.clone(), value)
                })
                .collect(),
        },
        EndpointEvent::FileAccess {
            operation,
            path,
            source_url,
            content_preview,
        } => EndpointEvent::FileAccess {
            operation: operation.clone(),
            path: path.clone(),
            source_url: source_url
                .as_deref()
                .map(redact_developer_activity_command_line),
            content_preview: content_preview.as_ref().map(|_| "[REDACTED]".to_string()),
        },
        EndpointEvent::NetworkFlow {
            host,
            port,
            protocol,
            url,
        } => EndpointEvent::NetworkFlow {
            host: host.clone(),
            port: *port,
            protocol: protocol.clone(),
            url: url.as_deref().map(redact_developer_activity_command_line),
        },
        EndpointEvent::PackageScript {
            manager,
            package,
            phase,
            script,
            working_directory,
        } => EndpointEvent::PackageScript {
            manager: manager.clone(),
            package: package.clone(),
            phase: phase.clone(),
            script: redact_developer_activity_command_line(script),
            working_directory: working_directory.clone(),
        },
        EndpointEvent::BrowserExtensionInstall {
            browser,
            extension_id,
            path,
            source,
        } => EndpointEvent::BrowserExtensionInstall {
            browser: browser.clone(),
            extension_id: extension_id.clone(),
            path: path.clone(),
            source: source
                .as_deref()
                .map(redact_developer_activity_command_line),
        },
        EndpointEvent::BrowserDownload {
            browser,
            path,
            source_url,
            content_hash,
            byte_count,
        } => EndpointEvent::BrowserDownload {
            browser: browser.clone(),
            path: path.clone(),
            source_url: source_url
                .as_deref()
                .map(redact_developer_activity_command_line),
            content_hash: content_hash.clone(),
            byte_count: *byte_count,
        },
        EndpointEvent::ToolCall {
            tool_name,
            parameters,
        } => EndpointEvent::ToolCall {
            tool_name: tool_name.clone(),
            parameters: redact_developer_activity_metadata_value("parameters", parameters),
        },
        EndpointEvent::PolicyDecision {
            action,
            target,
            decision,
            guard,
            severity,
        } => EndpointEvent::PolicyDecision {
            action: action.clone(),
            target: target
                .as_deref()
                .map(redact_developer_activity_command_line),
            decision: decision.clone(),
            guard: guard.clone(),
            severity: severity.clone(),
        },
        EndpointEvent::Other { category, fields } => EndpointEvent::Other {
            category: category.clone(),
            fields: redact_endpoint_observation_metadata(fields),
        },
        _ => event.clone(),
    }
}

pub(crate) fn redact_endpoint_observation_metadata(
    metadata: &BTreeMap<String, serde_json::Value>,
) -> BTreeMap<String, serde_json::Value> {
    metadata
        .iter()
        .map(|(key, value)| {
            (
                key.clone(),
                redact_developer_activity_metadata_value(key, value),
            )
        })
        .collect()
}

fn redact_developer_activity_metadata_value(
    key: &str,
    value: &serde_json::Value,
) -> serde_json::Value {
    if developer_activity_sensitive_metadata_key(key) {
        return serde_json::Value::String("[REDACTED]".to_string());
    }
    match value {
        serde_json::Value::String(value) => {
            serde_json::Value::String(redact_developer_activity_command_line(value))
        }
        serde_json::Value::Array(values) => serde_json::Value::Array(
            values
                .iter()
                .map(|value| redact_developer_activity_metadata_value(key, value))
                .collect(),
        ),
        serde_json::Value::Object(values) => serde_json::Value::Object(
            values
                .iter()
                .map(|(nested_key, value)| {
                    (
                        nested_key.clone(),
                        redact_developer_activity_metadata_value(nested_key, value),
                    )
                })
                .collect(),
        ),
        _ => value.clone(),
    }
}

pub(crate) fn developer_activity_sensitive_metadata_key(key: &str) -> bool {
    let normalized_key = key
        .trim_start_matches('-')
        .rsplit(['?', '&', '/', '\\'])
        .next()
        .unwrap_or(key)
        .to_ascii_lowercase()
        .replace(['-', '_'], "");
    developer_activity_sensitive_key(key)
        || normalized_key.ends_with("token")
        || normalized_key.ends_with("secret")
        || normalized_key.ends_with("password")
        || normalized_key.ends_with("apikey")
        || matches!(
            normalized_key.as_str(),
            "authorization" | "auth" | "credential" | "credentials"
        )
}
