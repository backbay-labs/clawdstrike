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

pub(crate) fn redact_developer_activity_command_line(command_line: &str) -> String {
    let command_line = redact_developer_activity_jsonish_secret_fields(command_line);
    let parts = command_line
        .split_whitespace()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let redacted = redact_developer_activity_args(&parts).join(" ");

    if redacted != command_line.as_str() {
        redacted
    } else if developer_activity_secret_like_value(&command_line) {
        "[REDACTED]".to_string()
    } else {
        redacted
    }
}

pub(crate) fn redact_developer_activity_args(args: &[String]) -> Vec<String> {
    let mut redacted = Vec::with_capacity(args.len());
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if let Some(redacted_arg) = redact_developer_activity_userinfo_flag_assignment(arg) {
            redacted.push(redacted_arg);
            index += 1;
            continue;
        }
        if let Some(redacted_arg) = redact_developer_activity_compact_userinfo_flag(arg) {
            redacted.push(redacted_arg);
            index += 1;
            continue;
        }
        if let Some(header) = redact_developer_activity_header_flag_assignment_value(arg) {
            redacted.push(header.redacted);
            index += 1;
            if header.consumes_next_token && index < args.len() {
                index += 1;
            }
            continue;
        }
        if let Some(header) = redact_developer_activity_authorization_header_value(arg) {
            redacted.push(header.redacted);
            index += 1;
            if header.consumes_next_token && index < args.len() {
                index += 1;
            }
            continue;
        }
        if developer_activity_authorization_header_key(arg) {
            redacted.push(arg.clone());
            index += 1;
            if index < args.len() && developer_activity_authorization_scheme_marker(&args[index]) {
                redacted.push(args[index].clone());
                index += 1;
            }
            if index < args.len() {
                redacted.push("[REDACTED]".to_string());
                index += 1;
            }
            continue;
        }
        if developer_activity_userinfo_flag_without_value(arg) {
            redacted.push(arg.clone());
            index += 1;
            if index < args.len() {
                redacted.push(redact_developer_activity_userinfo_credential(&args[index]));
                index += 1;
            }
            continue;
        }
        if developer_activity_sensitive_flag_without_value(arg) {
            redacted.push(arg.clone());
            index += 1;
            if index < args.len() && developer_activity_authorization_scheme_marker(&args[index]) {
                redacted.push(args[index].clone());
                index += 1;
            }
            if index < args.len() {
                redacted.push("[REDACTED]".to_string());
                index += 1;
            }
            continue;
        }
        if developer_activity_authorization_scheme_marker(arg) {
            redacted.push(arg.clone());
            index += 1;
            if index < args.len() {
                redacted.push("[REDACTED]".to_string());
                index += 1;
            }
            continue;
        }
        if let Some(assignment) = redact_developer_activity_sensitive_assignment(arg) {
            redacted.push(assignment.redacted);
            index += 1;
            if assignment.consumes_next_token && index < args.len() {
                redacted.push("[REDACTED]".to_string());
                index += 1;
            }
            continue;
        }
        redacted.push(redact_developer_activity_command_part(arg));
        index += 1;
    }
    redacted
}

pub(crate) struct RedactedAuthorizationHeader {
    redacted: String,
    consumes_next_token: bool,
}

pub(crate) struct RedactedSensitiveAssignment {
    redacted: String,
    consumes_next_token: bool,
}

fn developer_activity_authorization_header_key(part: &str) -> bool {
    let normalized = part.trim_end_matches(':');
    if normalized.eq_ignore_ascii_case("authorization")
        || normalized.eq_ignore_ascii_case("proxy-authorization")
        || normalized.eq_ignore_ascii_case("cookie")
        || normalized.eq_ignore_ascii_case("set-cookie")
    {
        return true;
    }
    if normalized.contains(['?', '&', '/', '\\', '=']) {
        return false;
    }
    developer_activity_sensitive_key(normalized)
        || developer_activity_sensitive_auth_header_key(normalized)
}

fn developer_activity_sensitive_auth_header_key(key: &str) -> bool {
    let normalized_key = key
        .trim_start_matches('-')
        .to_ascii_lowercase()
        .replace(['-', '_'], "");
    normalized_key == "auth"
        || normalized_key.ends_with("auth")
        || normalized_key.ends_with("authentication")
        || normalized_key.ends_with("authorization")
}

fn developer_activity_userinfo_flag_key(part: &str) -> bool {
    let normalized = part
        .trim_start_matches('-')
        .to_ascii_lowercase()
        .replace('_', "-");
    matches!(
        normalized.as_str(),
        "u" | "user" | "proxy-user" | "proxyuser"
    )
}

fn developer_activity_userinfo_flag_without_value(part: &str) -> bool {
    let trimmed = part.trim_end_matches(':');
    if trimmed.contains('=') || !trimmed.starts_with('-') {
        return false;
    }
    developer_activity_userinfo_flag_key(trimmed)
}

fn redact_developer_activity_userinfo_flag_assignment(part: &str) -> Option<String> {
    let (flag, credential) = part.split_once('=')?;
    if !developer_activity_userinfo_flag_key(flag) {
        return None;
    }
    Some(format!(
        "{flag}={}",
        redact_developer_activity_userinfo_credential(credential)
    ))
}

fn redact_developer_activity_compact_userinfo_flag(part: &str) -> Option<String> {
    if part.len() <= 2 || !(part.starts_with("-u") || part.starts_with("-U")) {
        return None;
    }
    let credential = &part[2..];
    if credential.starts_with('-') || !credential.contains(':') {
        return None;
    }
    Some(format!(
        "{}{}",
        &part[..2],
        redact_developer_activity_userinfo_credential(credential)
    ))
}

fn redact_developer_activity_userinfo_credential(credential: &str) -> String {
    let Some((user, password)) = credential.split_once(':') else {
        return if developer_activity_secret_like_value(credential) {
            "[REDACTED]".to_string()
        } else {
            credential.to_string()
        };
    };
    if password.is_empty() {
        credential.to_string()
    } else {
        format!("{user}:[REDACTED]")
    }
}

fn developer_activity_header_flag_key(part: &str) -> bool {
    let normalized = part
        .trim_start_matches('-')
        .to_ascii_lowercase()
        .replace('_', "-");
    matches!(
        normalized.as_str(),
        "h" | "header" | "proxy-header" | "proxyheader"
    )
}

fn redact_developer_activity_header_flag_assignment_value(
    part: &str,
) -> Option<RedactedAuthorizationHeader> {
    let (flag, header) = part.split_once('=')?;
    if !developer_activity_header_flag_key(flag) {
        return None;
    }
    let header = header.trim();
    let redacted_header =
        redact_developer_activity_authorization_header_value(header).or_else(|| {
            let header_key = header.trim_end_matches(':');
            if developer_activity_authorization_header_key(header_key) {
                Some(RedactedAuthorizationHeader {
                    redacted: format!("{header_key}: [REDACTED]"),
                    consumes_next_token: true,
                })
            } else {
                None
            }
        })?;
    Some(RedactedAuthorizationHeader {
        redacted: format!("{flag}={}", redacted_header.redacted),
        consumes_next_token: redacted_header.consumes_next_token,
    })
}

fn redact_developer_activity_authorization_header_value(
    part: &str,
) -> Option<RedactedAuthorizationHeader> {
    let (key, value) = part.split_once(':')?;
    if !developer_activity_authorization_header_key(key) {
        return None;
    }
    let trimmed_value = value.trim();
    if trimmed_value.is_empty() {
        return None;
    }
    let mut value_parts = trimmed_value.split_whitespace();
    let first = value_parts.next()?;
    if developer_activity_authorization_scheme_marker(first) {
        Some(RedactedAuthorizationHeader {
            redacted: format!("{key}: {first} [REDACTED]"),
            consumes_next_token: value_parts.next().is_none(),
        })
    } else {
        Some(RedactedAuthorizationHeader {
            redacted: format!("{key}: [REDACTED]"),
            consumes_next_token: false,
        })
    }
}

fn developer_activity_authorization_scheme_marker(part: &str) -> bool {
    let normalized = part.trim_end_matches(':');
    matches!(
        normalized.to_ascii_lowercase().as_str(),
        "apikey"
            | "api-key"
            | "aws4-hmac-sha256"
            | "basic"
            | "bearer"
            | "digest"
            | "hawk"
            | "mac"
            | "negotiate"
            | "ntlm"
            | "oauth"
            | "oauth2"
            | "sharedkey"
            | "signature"
            | "token"
    )
}

fn developer_activity_sensitive_flag_without_value(part: &str) -> bool {
    let trimmed = part.trim_end_matches(':');
    if trimmed.contains('=') || !trimmed.starts_with('-') {
        return false;
    }
    developer_activity_sensitive_key(trimmed)
}

fn redact_developer_activity_sensitive_assignment(
    part: &str,
) -> Option<RedactedSensitiveAssignment> {
    let (key, value) = part.split_once('=')?;
    if key.is_empty()
        || key.contains(['?', '&', ';', '/', '\\'])
        || !developer_activity_sensitive_key(key)
    {
        return None;
    }
    if developer_activity_authorization_scheme_marker(value) {
        Some(RedactedSensitiveAssignment {
            redacted: part.to_string(),
            consumes_next_token: true,
        })
    } else {
        Some(RedactedSensitiveAssignment {
            redacted: format!("{key}=[REDACTED]"),
            consumes_next_token: false,
        })
    }
}

fn redact_developer_activity_command_part(part: &str) -> String {
    let part = redact_developer_activity_url_userinfo(part);
    let part = redact_developer_activity_jsonish_secret_fields(&part);
    if !part.contains('=') {
        return if developer_activity_secret_like_value(&part) {
            "[REDACTED]".to_string()
        } else {
            part
        };
    }
    let mut redacted = String::with_capacity(part.len());
    let mut remaining = part.as_str();
    while let Some(equal_index) = remaining.find('=') {
        let before_equal = &remaining[..equal_index];
        let key_start = before_equal
            .rfind(['?', '&', ';', '/', '\\'])
            .map_or(0, |position| position + 1);
        let key = &before_equal[key_start..];
        if key.is_empty() || !developer_activity_sensitive_key(key) {
            redacted.push_str(&remaining[..=equal_index]);
            remaining = &remaining[equal_index + 1..];
            continue;
        }

        redacted.push_str(before_equal);
        redacted.push_str("=[REDACTED]");
        let value_start = equal_index + 1;
        let value_end = remaining[value_start..]
            .find(['&', ';'])
            .map_or(remaining.len(), |offset| value_start + offset);
        remaining = &remaining[value_end..];
    }
    redacted.push_str(remaining);
    redacted
}

fn redact_developer_activity_jsonish_secret_fields(part: &str) -> String {
    let bytes = part.as_bytes();
    let mut redacted = String::with_capacity(part.len());
    let mut cursor = 0;
    let mut index = 0;
    while index < bytes.len() {
        let quote = bytes[index];
        if quote != b'\'' && quote != b'"' {
            index += 1;
            continue;
        }
        let Some(key_end) = find_unescaped_ascii_quote(bytes, index + 1, quote) else {
            break;
        };
        let key = &part[index + 1..key_end];
        let mut colon_index = key_end + 1;
        while colon_index < bytes.len() && bytes[colon_index].is_ascii_whitespace() {
            colon_index += 1;
        }
        if colon_index >= bytes.len()
            || bytes[colon_index] != b':'
            || !developer_activity_sensitive_metadata_key(key)
        {
            index += 1;
            continue;
        }

        let mut value_start = colon_index + 1;
        while value_start < bytes.len() && bytes[value_start].is_ascii_whitespace() {
            value_start += 1;
        }
        if value_start >= bytes.len() {
            index = value_start;
            continue;
        }

        redacted.push_str(&part[cursor..value_start]);
        let value_quote = bytes[value_start];
        if value_quote == b'\'' || value_quote == b'"' {
            redacted.push(value_quote as char);
            redacted.push_str("[REDACTED]");
            let Some(value_end) = find_unescaped_ascii_quote(bytes, value_start + 1, value_quote)
            else {
                cursor = bytes.len();
                break;
            };
            redacted.push(value_quote as char);
            cursor = value_end + 1;
            index = cursor;
        } else {
            redacted.push_str("[REDACTED]");
            let value_end = bytes[value_start..]
                .iter()
                .position(|byte| byte.is_ascii_whitespace() || matches!(byte, b',' | b'}' | b']'))
                .map_or(bytes.len(), |offset| value_start + offset);
            cursor = value_end;
            index = cursor;
        }
    }
    if cursor == 0 {
        part.to_string()
    } else {
        redacted.push_str(&part[cursor..]);
        redacted
    }
}

fn find_unescaped_ascii_quote(bytes: &[u8], start: usize, quote: u8) -> Option<usize> {
    let mut escaped = false;
    for (offset, byte) in bytes.iter().enumerate().skip(start) {
        if escaped {
            escaped = false;
        } else if *byte == b'\\' {
            escaped = true;
        } else if *byte == quote {
            return Some(offset);
        }
    }
    None
}

fn redact_developer_activity_url_userinfo(part: &str) -> String {
    let Some(scheme_end) = part.find("://") else {
        return part.to_string();
    };
    let authority_start = scheme_end + 3;
    let authority_end = part[authority_start..]
        .find(['/', '?', '#'])
        .map_or(part.len(), |offset| authority_start + offset);
    let authority = &part[authority_start..authority_end];
    let Some(at_index) = authority.rfind('@') else {
        return part.to_string();
    };
    let userinfo = &authority[..at_index];
    let Some(colon_index) = userinfo.find(':') else {
        return format!(
            "{}[REDACTED]{}",
            &part[..authority_start],
            &part[authority_start + at_index..]
        );
    };
    let password = &userinfo[colon_index + 1..];
    if password.is_empty() {
        return part.to_string();
    }

    let password_start = authority_start + colon_index + 1;
    let password_end = authority_start + at_index;
    format!(
        "{}[REDACTED]{}",
        &part[..password_start],
        &part[password_end..]
    )
}

fn developer_activity_sensitive_key(key: &str) -> bool {
    let normalized_key = key
        .trim_start_matches('-')
        .rsplit(['?', '&', '/', '\\'])
        .next()
        .unwrap_or(key)
        .to_ascii_lowercase()
        .replace(['-', '_'], "");
    matches!(normalized_key.as_str(), "p" | "passwd")
        || normalized_key == "authorization"
        || normalized_key == "cookie"
        || normalized_key.ends_with("token")
        || normalized_key.ends_with("secret")
        || normalized_key.ends_with("password")
        || normalized_key.ends_with("credential")
        || normalized_key.ends_with("credentials")
        || normalized_key.ends_with("apikey")
        || normalized_key.ends_with("authkey")
        || normalized_key.ends_with("privatekey")
        || (normalized_key.contains("secret") && normalized_key.ends_with("key"))
}

pub(crate) fn developer_activity_secret_like_value(value: &str) -> bool {
    let value = value.trim();
    if value.contains("-----BEGIN ") && value.contains("PRIVATE KEY-----") {
        return true;
    }
    if value.starts_with("AKIA")
        && value.len() >= 20
        && value
            .chars()
            .skip(4)
            .take(16)
            .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit())
    {
        return true;
    }
    [
        "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "sk-", "xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-",
    ]
    .iter()
    .any(|prefix| value.starts_with(prefix) && value.len() >= prefix.len() + 20)
}

fn developer_activity_default_process_image(
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

fn developer_activity_command_line(
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

fn developer_activity_metadata(
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

fn developer_activity_byte_count(activity: &EdrDeveloperActivity) -> Option<u64> {
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

fn redact_developer_activity_metadata(
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

fn developer_activity_sensitive_metadata_key(key: &str) -> bool {
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

fn developer_activity_file_operation(
    activity: &EdrDeveloperActivity,
    fallback: FileOperation,
) -> FileOperation {
    match activity
        .operation
        .as_deref()
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("read" | "open" | "file_read") => FileOperation::Read,
        Some("write" | "file_write") => FileOperation::Write,
        Some("create") => FileOperation::Create,
        Some("delete" | "unlink") => FileOperation::Delete,
        Some("rename" | "move") => FileOperation::Rename,
        Some("execute" | "exec") => FileOperation::Execute,
        Some("chmod") => FileOperation::Chmod,
        Some(_) | None => fallback,
    }
}

fn file_operation_name(operation: &FileOperation) -> &'static str {
    match operation {
        FileOperation::Read => "read",
        FileOperation::Write => "write",
        FileOperation::Create => "create",
        FileOperation::Delete => "delete",
        FileOperation::Rename => "rename",
        FileOperation::Execute => "execute",
        FileOperation::Chmod => "chmod",
        FileOperation::Unknown => "unknown",
    }
}

fn developer_activity_parameters(activity: &EdrDeveloperActivity) -> serde_json::Value {
    let mut parameters = activity.parameters.clone().unwrap_or_else(|| {
        serde_json::Value::Object(serde_json::Map::<String, serde_json::Value>::new())
    });
    if let serde_json::Value::Object(object) = &mut parameters {
        for (key, value) in [
            ("action", activity.action.as_deref()),
            ("target", activity.target.as_deref()),
            ("browser", activity.browser.as_deref()),
            ("path", activity.path.as_deref()),
            ("sourceUrl", activity.source_url.as_deref()),
            ("query", activity.query.as_deref()),
            ("recordType", activity.record_type.as_deref()),
            ("resolver", activity.resolver.as_deref()),
            ("status", activity.status.as_deref()),
        ] {
            if let Some(value) = trimmed_owned(value) {
                object
                    .entry(key.to_string())
                    .or_insert(serde_json::Value::String(value));
            }
        }
        if !activity.answers.is_empty() {
            let answers = activity
                .answers
                .iter()
                .filter_map(|answer| trimmed_owned(Some(answer.as_str())))
                .map(serde_json::Value::String)
                .collect::<Vec<_>>();
            if !answers.is_empty() {
                object
                    .entry("answers".to_string())
                    .or_insert(serde_json::Value::Array(answers));
            }
        }
    }
    parameters
}

fn developer_activity_stable_id(activity: &EdrDeveloperActivity, index: usize) -> String {
    let index = index.to_string();
    let primary = activity
        .path
        .as_deref()
        .or(activity.name.as_deref())
        .or(activity.query.as_deref())
        .or(activity.host.as_deref())
        .or(activity.url.as_deref())
        .or(activity.target.as_deref())
        .or(activity.tool_name.as_deref())
        .or(activity.operation.as_deref())
        .or(activity.script.as_deref())
        .unwrap_or_default();
    local_stable_id(
        "devact",
        [
            activity.kind.as_str(),
            activity.session_id.as_deref().unwrap_or_default(),
            activity.agent_id.as_deref().unwrap_or_default(),
            primary,
            index.as_str(),
        ],
    )
}

fn required_activity_string(
    activity: &EdrDeveloperActivity,
    field: &str,
    value: Option<&str>,
) -> Result<String, (StatusCode, String)> {
    trimmed_owned(value).ok_or_else(|| {
        bad_activity_request(
            activity,
            &format!("{field} is required for {}", activity.kind.as_str()),
        )
    })
}

pub(crate) fn trimmed_owned(value: Option<&str>) -> Option<String> {
    non_empty(value).map(ToString::to_string)
}

fn bad_activity_request(activity: &EdrDeveloperActivity, message: &str) -> (StatusCode, String) {
    (
        StatusCode::BAD_REQUEST,
        format!(
            "invalid {} developer activity: {message}",
            activity.kind.as_str()
        ),
    )
}

pub(crate) async fn evaluate_record_and_receipt_edr_observations(
    state: &AgentApiState,
    detection_observations: &[EndpointObservation],
    recorded_observations: &[EndpointObservation],
    submitted_honey_artifacts: Vec<HoneyArtifact>,
) -> Result<EdrEvaluatedFindings, (StatusCode, String)> {
    validate_edr_request_sizes(recorded_observations.len(), submitted_honey_artifacts.len())?;
    if detection_observations.len() != recorded_observations.len() {
        return Err((
            StatusCode::BAD_REQUEST,
            "detection and recording observation counts must match".to_string(),
        ));
    }

    let honey_artifacts = state
        .edr_honey_registry
        .lock()
        .await
        .load()
        .map_err(internal_error)?;
    require_submitted_honey_artifacts_registered(&submitted_honey_artifacts, &honey_artifacts)?;
    validate_edr_request_sizes(recorded_observations.len(), honey_artifacts.len())?;

    let guard = SupplyChainRuntimeGuard::with_honey_artifacts(honey_artifacts);
    let mut findings = Vec::new();
    for (detection_observation, recorded_observation) in
        detection_observations.iter().zip(recorded_observations)
    {
        findings.extend(guard.evaluate(recorded_observation));

        for finding in guard
            .evaluate(detection_observation)
            .into_iter()
            .filter(is_local_only_honey_marker_finding)
        {
            if !findings
                .iter()
                .any(|existing| existing.finding_id == finding.finding_id)
            {
                findings.push(finding);
            }
        }
    }
    record_edr_observations(state, recorded_observations).await?;
    let graph = state.edr_flight_recorder.lock().await.graph().clone();
    let receipts = emit_edr_detection_receipts(state, recorded_observations, &findings, &graph)
        .await
        .map_err(internal_error)?;
    append_recent_edr_findings(state, &findings).await;
    publish_current_agent_secret_touches_to_fleet_best_effort(state, recorded_observations).await;

    Ok(EdrEvaluatedFindings { findings, receipts })
}

fn require_submitted_honey_artifacts_registered(
    submitted_honey_artifacts: &[HoneyArtifact],
    registered_honey_artifacts: &[HoneyArtifact],
) -> Result<(), (StatusCode, String)> {
    for submitted in submitted_honey_artifacts {
        let Some(registered) = registered_honey_artifacts
            .iter()
            .find(|artifact| artifact.artifact_id == submitted.artifact_id)
        else {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "submitted honey artifact {} is not a registered honey artifact",
                    submitted.artifact_id
                ),
            ));
        };

        if registered != submitted {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "submitted honey artifact {} does not match the registered honey artifact",
                    submitted.artifact_id
                ),
            ));
        }
    }
    Ok(())
}

fn is_local_only_honey_marker_finding(finding: &DetectionFinding) -> bool {
    finding.rule_id == "deception.honey_artifact_touched"
        && finding
            .evidence
            .iter()
            .any(|item| item.key == "matchType" && item.value == "marker")
}
