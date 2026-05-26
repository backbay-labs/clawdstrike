use super::*;

pub(crate) fn network_extension_event_observations(
    event: &EdrNetworkExtensionFlowEvent,
    index: usize,
) -> Result<Vec<EndpointObservation>, (StatusCode, String)> {
    let host = required_network_extension_event_string(event, "host", event.host.as_deref())?;
    if event.port == 0 {
        return Err(bad_network_extension_event_request(
            event,
            "port must be greater than zero",
        ));
    }
    let decision =
        normalized_network_extension_verdict(event.verdict.as_str()).ok_or_else(|| {
            bad_network_extension_event_request(event, "verdict must be allow or block")
        })?;
    let timestamp = event.observed_at.unwrap_or_else(chrono::Utc::now);
    let target = format!("{}:{}", host, event.port);
    let observation_id = trimmed_owned(event.event_id.as_deref()).unwrap_or_else(|| {
        let index = index.to_string();
        local_stable_id(
            "neflow",
            [
                event.session_id.as_deref().unwrap_or_default(),
                event.flow_id.as_deref().unwrap_or_default(),
                host.as_str(),
                index.as_str(),
            ],
        )
    });
    let process = network_extension_event_process(event, target.as_str(), decision);
    let metadata = network_extension_event_metadata(event, decision);
    let mut observations = Vec::with_capacity(if event.dns_query.is_some() { 3 } else { 2 });

    if let Some(query) = trimmed_owned(event.dns_query.as_deref()) {
        let mut dns_metadata = metadata.clone();
        dns_metadata.insert(
            "networkExtensionObservationKind".to_string(),
            serde_json::Value::String("dns_lookup".to_string()),
        );
        observations.push(EndpointObservation {
            observation_id: format!("{observation_id}:dns"),
            timestamp,
            host_id: trimmed_owned(event.host_id.as_deref()),
            user_id: trimmed_owned(event.user_id.as_deref()),
            session_id: trimmed_owned(event.session_id.as_deref()),
            process: process.clone(),
            event: EndpointEvent::DnsLookup {
                query,
                record_type: trimmed_owned(event.dns_record_type.as_deref()),
                answers: event
                    .dns_answers
                    .iter()
                    .filter_map(|answer| trimmed_owned(Some(answer.as_str())))
                    .collect(),
                resolver: trimmed_owned(event.dns_resolver.as_deref()),
                status: trimmed_owned(event.dns_status.as_deref()),
            },
            metadata: dns_metadata,
        });
    }

    observations.push(EndpointObservation {
        observation_id: observation_id.clone(),
        timestamp,
        host_id: trimmed_owned(event.host_id.as_deref()),
        user_id: trimmed_owned(event.user_id.as_deref()),
        session_id: trimmed_owned(event.session_id.as_deref()),
        process: process.clone(),
        event: EndpointEvent::NetworkFlow {
            host: host.clone(),
            port: event.port,
            protocol: trimmed_owned(event.protocol.as_deref()),
            url: trimmed_owned(event.url.as_deref()),
        },
        metadata: metadata.clone(),
    });
    observations.push(EndpointObservation {
        observation_id: format!("{observation_id}:decision"),
        timestamp,
        host_id: trimmed_owned(event.host_id.as_deref()),
        user_id: trimmed_owned(event.user_id.as_deref()),
        session_id: trimmed_owned(event.session_id.as_deref()),
        process,
        event: EndpointEvent::PolicyDecision {
            action: "network_extension_egress".to_string(),
            target: Some(target),
            decision: decision.to_string(),
            guard: Some("network_extension_content_filter".to_string()),
            severity: Some(
                if decision == "blocked" {
                    "high"
                } else {
                    "info"
                }
                .to_string(),
            ),
        },
        metadata,
    });
    Ok(observations)
}

fn network_extension_event_process(
    event: &EdrNetworkExtensionFlowEvent,
    target: &str,
    decision: &str,
) -> EndpointProcess {
    let mut process = event.process.clone().unwrap_or_default();
    if let Some(command_line) = trimmed_owned(process.command_line.as_deref()) {
        process.command_line = Some(redact_developer_activity_command_line(&command_line));
    }
    if process.pid.is_none() {
        process.pid = event.pid;
    }
    if trimmed_owned(process.process_guid.as_deref()).is_none() {
        process.process_guid = trimmed_owned(event.process_guid.as_deref());
    }
    if trimmed_owned(process.parent_process_guid.as_deref()).is_none() {
        process.parent_process_guid = trimmed_owned(event.parent_process_guid.as_deref());
    }
    if trimmed_owned(process.image.as_deref()).is_none() {
        process.image = trimmed_owned(event.source_app_path.as_deref())
            .or_else(|| trimmed_owned(event.source_app.as_deref()))
            .or_else(|| Some("network-extension-provider".to_string()));
    }
    if trimmed_owned(process.command_line.as_deref()).is_none() {
        process.command_line = Some(format!("network_extension_flow {target} {decision}"));
    }
    process
}

fn network_extension_event_metadata(
    event: &EdrNetworkExtensionFlowEvent,
    decision: &str,
) -> BTreeMap<String, serde_json::Value> {
    let mut metadata = redact_endpoint_observation_metadata(&event.metadata);
    metadata.insert(
        "collectorKind".to_string(),
        serde_json::Value::String("network_extension".to_string()),
    );
    metadata.insert(
        "providerId".to_string(),
        serde_json::Value::String("macos.network_extension".to_string()),
    );
    metadata.insert(
        "networkExtensionVerdict".to_string(),
        serde_json::Value::String(decision.to_string()),
    );
    for (key, value) in [
        ("flowId", event.flow_id.as_deref()),
        ("sourceApp", event.source_app.as_deref()),
        ("sourceAppPath", event.source_app_path.as_deref()),
        ("networkExtensionReason", event.reason.as_deref()),
        ("policySnapshotPath", event.policy_snapshot_path.as_deref()),
        ("policySnapshotHash", event.policy_snapshot_hash.as_deref()),
    ] {
        if let Some(value) = trimmed_owned(value) {
            metadata.insert(key.to_string(), serde_json::Value::String(value));
        }
    }
    for (key, value) in [
        ("generation", event.generation),
        ("remediationRequests", event.remediation_requests),
        ("blockedFlows", event.blocked_flows),
        ("allowedFlows", event.allowed_flows),
    ] {
        if let Some(value) = value {
            metadata.insert(key.to_string(), serde_json::json!(value));
        }
    }
    metadata
}

fn normalized_network_extension_verdict(value: &str) -> Option<&'static str> {
    match value.trim().to_ascii_lowercase().as_str() {
        "allow" | "allowed" | "pass" | "passed" | "permit" | "permitted" => Some("allowed"),
        "block" | "blocked" | "deny" | "denied" | "drop" | "dropped" => Some("blocked"),
        _ => None,
    }
}

fn required_network_extension_event_string(
    event: &EdrNetworkExtensionFlowEvent,
    field: &str,
    value: Option<&str>,
) -> Result<String, (StatusCode, String)> {
    trimmed_owned(value).ok_or_else(|| {
        bad_network_extension_event_request(
            event,
            &format!("{field} is required for NetworkExtension flow events"),
        )
    })
}

fn bad_network_extension_event_request(
    event: &EdrNetworkExtensionFlowEvent,
    message: &str,
) -> (StatusCode, String) {
    let event_id = event
        .event_id
        .as_deref()
        .and_then(|value| non_empty(Some(value)))
        .unwrap_or("unknown");
    (
        StatusCode::BAD_REQUEST,
        format!("invalid NetworkExtension flow event {event_id}: {message}"),
    )
}

pub(crate) fn package_manager_event_observation(
    event: &EdrPackageManagerEvent,
    index: usize,
) -> Result<EndpointObservation, (StatusCode, String)> {
    let phase = required_package_manager_event_string(event, "phase", Some(event.phase.as_str()))?;
    let script =
        required_package_manager_event_string(event, "script", Some(event.script.as_str()))?;
    let script = redact_developer_activity_command_line(&script);
    let observation_id = trimmed_owned(event.event_id.as_deref()).unwrap_or_else(|| {
        let index = index.to_string();
        local_stable_id(
            "pkgscript",
            [
                event.manager.as_str(),
                phase.as_str(),
                event.package.as_deref().unwrap_or_default(),
                event.working_directory.as_deref().unwrap_or_default(),
                index.as_str(),
            ],
        )
    });

    Ok(EndpointObservation {
        observation_id,
        timestamp: event.observed_at.unwrap_or_else(chrono::Utc::now),
        host_id: trimmed_owned(event.host_id.as_deref()),
        user_id: trimmed_owned(event.user_id.as_deref()),
        session_id: trimmed_owned(event.session_id.as_deref()),
        process: package_manager_event_process(event, &phase, &script),
        event: EndpointEvent::PackageScript {
            manager: event.manager.clone(),
            package: trimmed_owned(event.package.as_deref()),
            phase,
            script,
            working_directory: trimmed_owned(event.working_directory.as_deref()),
        },
        metadata: package_manager_event_metadata(event),
    })
}

fn package_manager_event_process(
    event: &EdrPackageManagerEvent,
    phase: &str,
    script: &str,
) -> EndpointProcess {
    let mut process = event.process.clone().unwrap_or_default();
    if let Some(command_line) = trimmed_owned(process.command_line.as_deref()) {
        process.command_line = Some(redact_developer_activity_command_line(&command_line));
    }
    if trimmed_owned(process.image.as_deref()).is_none() {
        process.image = Some(event.manager.as_str().to_string());
    }
    if trimmed_owned(process.command_line.as_deref()).is_none() {
        process.command_line = Some(format!("{} {phase} {script}", event.manager.as_str()));
    }
    if trimmed_owned(process.cwd.as_deref()).is_none() {
        process.cwd = trimmed_owned(event.working_directory.as_deref());
    }
    process
}

fn package_manager_event_metadata(
    event: &EdrPackageManagerEvent,
) -> BTreeMap<String, serde_json::Value> {
    let mut metadata = redact_developer_activity_metadata(&event.metadata);
    metadata.insert(
        "collectorKind".to_string(),
        serde_json::Value::String("package_manager".to_string()),
    );
    metadata.insert(
        "providerId".to_string(),
        serde_json::Value::String(format!("package_manager.{}", event.manager.as_str())),
    );
    metadata.insert(
        "packageManager".to_string(),
        serde_json::Value::String(event.manager.as_str().to_string()),
    );
    for (key, value) in [
        ("agentId", event.agent_id.as_deref()),
        ("workloadId", event.workload_id.as_deref()),
        ("approvalId", event.approval_id.as_deref()),
        ("toolCallId", event.tool_call_id.as_deref()),
        ("packageName", event.package.as_deref()),
        ("packageManagerPhase", Some(event.phase.as_str())),
        ("workingDirectory", event.working_directory.as_deref()),
    ] {
        if let Some(value) = trimmed_owned(value) {
            metadata.insert(key.to_string(), serde_json::Value::String(value));
        }
    }
    metadata
}

fn required_package_manager_event_string(
    event: &EdrPackageManagerEvent,
    field: &str,
    value: Option<&str>,
) -> Result<String, (StatusCode, String)> {
    trimmed_owned(value).ok_or_else(|| {
        let event_id = event
            .event_id
            .as_deref()
            .and_then(|value| non_empty(Some(value)))
            .unwrap_or("unknown");
        (
            StatusCode::BAD_REQUEST,
            format!("invalid package-manager event {event_id}: {field} is required"),
        )
    })
}

pub(crate) fn developer_activity_observation(
    activity: &EdrDeveloperActivity,
    index: usize,
) -> Result<EndpointObservation, (StatusCode, String)> {
    let event = developer_activity_event(activity)?;
    let process = developer_activity_process(activity, &event)?;
    let metadata = developer_activity_metadata(activity);
    let activity_id = non_empty(activity.activity_id.as_deref())
        .map(ToString::to_string)
        .unwrap_or_else(|| developer_activity_stable_id(activity, index));

    Ok(EndpointObservation {
        observation_id: activity_id,
        timestamp: activity.observed_at.unwrap_or_else(chrono::Utc::now),
        host_id: trimmed_owned(activity.host_id.as_deref()),
        user_id: trimmed_owned(activity.user_id.as_deref()),
        session_id: trimmed_owned(activity.session_id.as_deref()),
        process,
        event,
        metadata,
    })
}

fn developer_activity_event(
    activity: &EdrDeveloperActivity,
) -> Result<EndpointEvent, (StatusCode, String)> {
    match activity.kind {
        EdrDeveloperActivityKind::McpTool => Ok(EndpointEvent::ToolCall {
            tool_name: required_activity_string(
                activity,
                "toolName",
                activity.tool_name.as_deref(),
            )?,
            parameters: developer_activity_parameters(activity),
        }),
        EdrDeveloperActivityKind::BrowserAutomation => {
            let action = required_activity_string(activity, "action", activity.action.as_deref())?;
            let tool_name = activity
                .tool_name
                .as_deref()
                .and_then(|value| non_empty(Some(value)))
                .map(ToString::to_string)
                .unwrap_or_else(|| format!("browser.{action}"));
            Ok(EndpointEvent::ToolCall {
                tool_name,
                parameters: developer_activity_parameters(activity),
            })
        }
        EdrDeveloperActivityKind::BrowserDownload => Ok(EndpointEvent::BrowserDownload {
            browser: required_activity_string(activity, "browser", activity.browser.as_deref())?,
            path: required_activity_string(activity, "path", activity.path.as_deref())?,
            source_url: trimmed_owned(activity.source_url.as_deref()),
            content_hash: trimmed_owned(activity.content_hash.as_deref()),
            byte_count: developer_activity_byte_count(activity),
        }),
        EdrDeveloperActivityKind::BrowserExtension => Ok(EndpointEvent::BrowserExtensionInstall {
            browser: required_activity_string(activity, "browser", activity.browser.as_deref())?,
            extension_id: trimmed_owned(activity.extension_id.as_deref()),
            path: required_activity_string(activity, "path", activity.path.as_deref())?,
            source: trimmed_owned(activity.source.as_deref()),
        }),
        EdrDeveloperActivityKind::DnsLookup => Ok(EndpointEvent::DnsLookup {
            query: required_activity_string(
                activity,
                "query",
                activity.query.as_deref().or(activity.target.as_deref()),
            )?,
            record_type: trimmed_owned(activity.record_type.as_deref()),
            answers: activity
                .answers
                .iter()
                .filter_map(|answer| trimmed_owned(Some(answer.as_str())))
                .collect(),
            resolver: trimmed_owned(activity.resolver.as_deref()),
            status: trimmed_owned(activity.status.as_deref()),
        }),
        EdrDeveloperActivityKind::NetworkEgress => Ok(EndpointEvent::NetworkFlow {
            host: required_activity_string(activity, "host", activity.host.as_deref())?,
            port: activity.port.ok_or_else(|| {
                bad_activity_request(activity, "port is required for network_egress")
            })?,
            protocol: trimmed_owned(activity.protocol.as_deref()),
            url: trimmed_owned(activity.url.as_deref()),
        }),
        EdrDeveloperActivityKind::FileRead | EdrDeveloperActivityKind::FileWrite => {
            let fallback = if matches!(activity.kind, EdrDeveloperActivityKind::FileRead) {
                FileOperation::Read
            } else {
                FileOperation::Write
            };
            Ok(EndpointEvent::FileAccess {
                operation: developer_activity_file_operation(activity, fallback),
                path: required_activity_string(activity, "path", activity.path.as_deref())?,
                source_url: trimmed_owned(activity.source_url.as_deref()),
                content_preview: None,
            })
        }
        EdrDeveloperActivityKind::PatchApply => Ok(EndpointEvent::FileAccess {
            operation: FileOperation::Write,
            path: required_activity_string(activity, "path", activity.path.as_deref())?,
            source_url: None,
            content_preview: None,
        }),
        EdrDeveloperActivityKind::PersistenceChange => Ok(EndpointEvent::LaunchPersistence {
            path: required_activity_string(
                activity,
                "target",
                activity.target.as_deref().or(activity.path.as_deref()),
            )?,
            label: trimmed_owned(activity.name.as_deref()),
            operation: developer_activity_file_operation(activity, FileOperation::Write),
        }),
        EdrDeveloperActivityKind::PackageScript => Ok(EndpointEvent::PackageScript {
            manager: activity.manager.clone().ok_or_else(|| {
                bad_activity_request(activity, "manager is required for package_script")
            })?,
            package: trimmed_owned(activity.package.as_deref()),
            phase: required_activity_string(activity, "phase", activity.phase.as_deref())?,
            script: redact_developer_activity_command_line(&required_activity_string(
                activity,
                "script",
                activity.script.as_deref(),
            )?),
            working_directory: trimmed_owned(activity.working_directory.as_deref()),
        }),
        EdrDeveloperActivityKind::CloudCli => {
            let provider =
                required_activity_string(activity, "provider", activity.provider.as_deref())?;
            let operation =
                required_activity_string(activity, "operation", activity.operation.as_deref())?;
            let mut args = Vec::with_capacity(activity.args.len() + 1);
            args.push(operation);
            args.extend(activity.args.iter().cloned());
            let args = redact_developer_activity_args(&args);
            Ok(EndpointEvent::ProcessExec {
                image: activity
                    .image
                    .as_deref()
                    .and_then(|value| non_empty(Some(value)))
                    .map(ToString::to_string)
                    .unwrap_or(provider),
                args,
                env: BTreeMap::new(),
            })
        }
        EdrDeveloperActivityKind::ShellCommand => Ok(EndpointEvent::ProcessExec {
            image: required_activity_string(activity, "image", activity.image.as_deref())?,
            args: redact_developer_activity_args(&activity.args),
            env: BTreeMap::new(),
        }),
        EdrDeveloperActivityKind::RepoSecret => Ok(EndpointEvent::CredentialAccess {
            kind: activity
                .credential_kind
                .clone()
                .unwrap_or(CredentialKind::ApiToken),
            path: trimmed_owned(activity.path.as_deref()),
            name: trimmed_owned(activity.name.as_deref()),
        }),
        EdrDeveloperActivityKind::CiToken => Ok(EndpointEvent::CredentialAccess {
            kind: activity
                .credential_kind
                .clone()
                .unwrap_or(CredentialKind::ApiToken),
            path: trimmed_owned(activity.path.as_deref()),
            name: Some(required_activity_string(
                activity,
                "name",
                activity.name.as_deref(),
            )?),
        }),
        EdrDeveloperActivityKind::LocalApiKey => Ok(EndpointEvent::CredentialAccess {
            kind: activity
                .credential_kind
                .clone()
                .unwrap_or(CredentialKind::ApiToken),
            path: trimmed_owned(activity.path.as_deref()),
            name: trimmed_owned(activity.name.as_deref()),
        }),
        EdrDeveloperActivityKind::BrowserCookie => Ok(EndpointEvent::CredentialAccess {
            kind: CredentialKind::BrowserCookie,
            path: trimmed_owned(activity.path.as_deref()),
            name: Some(required_activity_string(
                activity,
                "name",
                activity.name.as_deref(),
            )?),
        }),
    }
}

fn developer_activity_process(
    activity: &EdrDeveloperActivity,
    event: &EndpointEvent,
) -> Result<EndpointProcess, (StatusCode, String)> {
    let mut process = activity.process.clone().unwrap_or_default();
    if let Some(command_line) = trimmed_owned(process.command_line.as_deref()) {
        process.command_line = Some(redact_developer_activity_command_line(&command_line));
    }
    if process.pid.is_none() {
        process.pid = activity.pid;
    }
    if process.ppid.is_none() {
        process.ppid = activity.ppid;
    }
    if trimmed_owned(process.process_guid.as_deref()).is_none() {
        process.process_guid = trimmed_owned(activity.process_guid.as_deref());
    }
    if trimmed_owned(process.parent_process_guid.as_deref()).is_none() {
        process.parent_process_guid = trimmed_owned(activity.parent_process_guid.as_deref());
    }
    if trimmed_owned(process.image.as_deref()).is_none() {
        process.image = trimmed_owned(activity.process_image.as_deref());
    }
    if trimmed_owned(process.command_line.as_deref()).is_none() {
        process.command_line = trimmed_owned(activity.process_command_line.as_deref())
            .map(|command_line| redact_developer_activity_command_line(&command_line));
    }
    if trimmed_owned(process.cwd.as_deref()).is_none() {
        process.cwd = trimmed_owned(activity.process_cwd.as_deref());
    }
    if trimmed_owned(process.image.as_deref()).is_none() {
        process.image = developer_activity_default_process_image(activity, event);
    }
    if trimmed_owned(process.command_line.as_deref()).is_none() {
        process.command_line = developer_activity_command_line(activity, event)
            .map(|command_line| redact_developer_activity_command_line(&command_line));
    }
    if trimmed_owned(process.cwd.as_deref()).is_none() {
        process.cwd = trimmed_owned(activity.working_directory.as_deref());
    }
    if trimmed_owned(process.image.as_deref()).is_none()
        && trimmed_owned(process.command_line.as_deref()).is_none()
    {
        return Err(bad_activity_request(
            activity,
            "activity must provide process.image, image, or enough collector fields to infer a process",
        ));
    }
    Ok(process)
}
