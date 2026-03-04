use std::io::Write;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::hush_run;
use crate::policy_event::{
    CommandEventData, CustomEventData, FileEventData, NetworkEventData, PatchEventData,
    PolicyEvent, PolicyEventData, PolicyEventType, ToolEventData,
};
use crate::remote_extends::RemoteExtendsConfig;
use crate::ExitCode;

#[derive(Debug, Clone)]
pub struct PolicyObserveCommand {
    pub policy: String,
    pub out: PathBuf,
    pub hushd_url: Option<String>,
    pub hushd_token: Option<String>,
    pub session: Option<String>,
    pub ocsf_out: Option<PathBuf>,
    pub command: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct AuditEventLine {
    id: String,
    timestamp: String,
    action_type: String,
    target: Option<String>,
    decision: String,
    guard: Option<String>,
    severity: Option<String>,
    message: Option<String>,
    session_id: Option<String>,
    metadata: Option<serde_json::Value>,
}

pub async fn cmd_policy_observe(
    args: PolicyObserveCommand,
    remote_extends: &RemoteExtendsConfig,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    if args.hushd_url.is_some() {
        return observe_hushd_session(args, stdout, stderr).await;
    }

    if args.command.is_empty() {
        let _ = writeln!(
            stderr,
            "Error: command is required unless --hushd-url is provided"
        );
        return ExitCode::InvalidArgs;
    }

    let ocsf_out = args.ocsf_out.clone();
    let events_out_path = args.out.clone();

    let code = hush_run::cmd_run(
        hush_run::RunArgs {
            policy: args.policy,
            events_out: Some(args.out.to_string_lossy().to_string()),
            receipt_out: Some("clawdstrike.observe.receipt.json".to_string()),
            signing_key: "clawdstrike.key".to_string(),
            no_proxy: false,
            proxy_port: 0,
            proxy_allow_private_ips: false,
            sandbox: false,
            hushd_url: None,
            hushd_token: None,
            command: args.command,
        },
        remote_extends,
        stdout,
        stderr,
    )
    .await;

    if let Some(ref ocsf_path) = ocsf_out {
        if let Err(e) = post_process_ocsf(&events_out_path, ocsf_path) {
            let _ = writeln!(stderr, "Warning: failed to write OCSF output: {}", e);
        } else {
            let _ = writeln!(stderr, "OCSF output: {}", ocsf_path.display());
        }
    }

    if code == 0 {
        ExitCode::Ok
    } else {
        ExitCode::RuntimeError
    }
}

/// Post-process an events JSONL file and write OCSF JSONL to the given path.
fn post_process_ocsf(
    events_path: &std::path::Path,
    ocsf_path: &std::path::Path,
) -> std::io::Result<()> {
    use std::io::BufRead;

    if let Some(parent) = ocsf_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let events_file = std::fs::File::open(events_path)?;
    let reader = std::io::BufReader::new(events_file);
    let ocsf_file = std::fs::File::create(ocsf_path)?;
    let mut writer = std::io::BufWriter::new(ocsf_file);

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let event: PolicyEvent = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if let Some(ocsf_val) = clawdstrike_policy_event::ocsf::policy_event_to_ocsf(&event) {
            if let Ok(json_line) = serde_json::to_string(&ocsf_val) {
                let _ = writeln!(writer, "{json_line}");
            }
        }
    }

    writer.flush()?;
    Ok(())
}

async fn observe_hushd_session(
    args: PolicyObserveCommand,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let Some(hushd_url) = args.hushd_url else {
        let _ = writeln!(stderr, "Error: --hushd-url is required");
        return ExitCode::InvalidArgs;
    };
    let Some(session_id) = args.session else {
        let _ = writeln!(
            stderr,
            "Error: --session is required when using --hushd-url"
        );
        return ExitCode::InvalidArgs;
    };

    let base = hushd_url.trim_end_matches('/');
    let url = format!(
        "{}/api/v1/audit?session_id={}&format=jsonl",
        base, session_id
    );

    let token = args
        .hushd_token
        .or_else(|| std::env::var("CLAWDSTRIKE_ADMIN_KEY").ok())
        .or_else(|| std::env::var("CLAWDSTRIKE_API_KEY").ok());

    let client = reqwest::Client::new();
    let mut req = client.get(url);
    if let Some(token) = token {
        req = req.bearer_auth(token);
    }

    let response = match req.send().await {
        Ok(resp) => resp,
        Err(err) => {
            let _ = writeln!(stderr, "Error: failed to fetch audit stream: {}", err);
            return ExitCode::RuntimeError;
        }
    };

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        let _ = writeln!(
            stderr,
            "Error: audit stream request failed ({}): {}",
            status, body
        );
        return ExitCode::RuntimeError;
    }

    let body = match response.text().await {
        Ok(body) => body,
        Err(err) => {
            let _ = writeln!(stderr, "Error: failed to read audit stream body: {}", err);
            return ExitCode::RuntimeError;
        }
    };

    if let Some(parent) = args.out.parent() {
        if !parent.as_os_str().is_empty() {
            if let Err(err) = std::fs::create_dir_all(parent) {
                let _ = writeln!(stderr, "Error: failed to create output directory: {}", err);
                return ExitCode::RuntimeError;
            }
        }
    }

    let out_file = match std::fs::File::create(&args.out) {
        Ok(file) => file,
        Err(err) => {
            let _ = writeln!(
                stderr,
                "Error: failed to create output file {}: {}",
                args.out.display(),
                err
            );
            return ExitCode::RuntimeError;
        }
    };

    let mut writer = std::io::BufWriter::new(out_file);
    let mut ocsf_writer: Option<std::io::BufWriter<std::fs::File>> =
        if let Some(ref ocsf_path) = args.ocsf_out {
            if let Some(parent) = ocsf_path.parent() {
                if !parent.as_os_str().is_empty() {
                    let _ = std::fs::create_dir_all(parent);
                }
            }
            match std::fs::File::create(ocsf_path) {
                Ok(f) => Some(std::io::BufWriter::new(f)),
                Err(err) => {
                    let _ = writeln!(
                        stderr,
                        "Warning: failed to create OCSF output file: {}",
                        err
                    );
                    None
                }
            }
        } else {
            None
        };

    let mut count = 0usize;

    for (line_idx, line) in body.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let event: AuditEventLine = match serde_json::from_str(trimmed) {
            Ok(event) => event,
            Err(err) => {
                let _ = writeln!(
                    stderr,
                    "Warning: skipping invalid audit JSONL line {}: {}",
                    line_idx + 1,
                    err
                );
                continue;
            }
        };

        let Some(policy_event) = map_audit_event(event) else {
            continue;
        };

        if let Some(ref mut w) = ocsf_writer {
            if let Some(ocsf_val) =
                clawdstrike_policy_event::ocsf::policy_event_to_ocsf(&policy_event)
            {
                if let Ok(ocsf_line) = serde_json::to_string(&ocsf_val) {
                    let _ = writeln!(w, "{ocsf_line}");
                }
            }
        }

        match serde_json::to_string(&policy_event) {
            Ok(json_line) => {
                if let Err(err) = writeln!(writer, "{}", json_line) {
                    let _ = writeln!(stderr, "Error: failed to write output line: {}", err);
                    return ExitCode::RuntimeError;
                }
                count += 1;
            }
            Err(err) => {
                let _ = writeln!(stderr, "Warning: skipping non-serializable event: {}", err);
            }
        }
    }

    if let Err(err) = writer.flush() {
        let _ = writeln!(stderr, "Error: failed to flush output file: {}", err);
        return ExitCode::RuntimeError;
    }
    if let Some(ref mut w) = ocsf_writer {
        let _ = w.flush();
    }

    let _ = writeln!(
        stdout,
        "Observed {} event(s) from hushd session {} -> {}",
        count,
        session_id,
        args.out.display()
    );
    if let Some(ref ocsf_path) = args.ocsf_out {
        let _ = writeln!(stderr, "OCSF output: {}", ocsf_path.display());
    }

    ExitCode::Ok
}

fn map_audit_event(event: AuditEventLine) -> Option<PolicyEvent> {
    let timestamp = DateTime::parse_from_rfc3339(&event.timestamp)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());
    let (allowed, is_warn) = normalize_audit_decision(&event.decision);

    let mut metadata = serde_json::Map::new();
    metadata.insert(
        "decision".to_string(),
        serde_json::json!({
            "allowed": allowed,
            "warn": is_warn,
            "guard": event.guard,
            "severity": event.severity,
            "message": event.message,
        }),
    );
    if let Some(extra) = event.metadata {
        metadata.insert("audit".to_string(), extra);
    }

    let target = event.target.unwrap_or_default();

    let (event_type, data) = match event.action_type.as_str() {
        "file_access" => (
            PolicyEventType::FileRead,
            PolicyEventData::File(FileEventData {
                path: target,
                operation: Some("read".to_string()),
                content_base64: None,
                content: None,
                content_hash: None,
            }),
        ),
        "file_write" => (
            PolicyEventType::FileWrite,
            PolicyEventData::File(FileEventData {
                path: target,
                operation: Some("write".to_string()),
                content_base64: None,
                content: None,
                content_hash: None,
            }),
        ),
        "egress" => {
            let (host, port) = parse_host_port(&target);
            (
                PolicyEventType::NetworkEgress,
                PolicyEventData::Network(NetworkEventData {
                    host,
                    port,
                    protocol: Some("tcp".to_string()),
                    url: None,
                }),
            )
        }
        "shell" => (
            PolicyEventType::CommandExec,
            PolicyEventData::Command(CommandEventData {
                command: target,
                args: Vec::new(),
            }),
        ),
        "patch" => (
            PolicyEventType::PatchApply,
            PolicyEventData::Patch(PatchEventData {
                file_path: target,
                patch_content: String::new(),
                patch_hash: None,
            }),
        ),
        "mcp_tool" => (
            PolicyEventType::ToolCall,
            PolicyEventData::Tool(ToolEventData {
                tool_name: target,
                parameters: serde_json::json!({}),
            }),
        ),
        action_type => (
            PolicyEventType::Custom,
            PolicyEventData::Custom(CustomEventData {
                custom_type: action_type.to_string(),
                extra: serde_json::Map::new(),
            }),
        ),
    };

    Some(PolicyEvent {
        event_id: event.id,
        event_type,
        timestamp,
        session_id: event.session_id,
        data,
        metadata: Some(serde_json::Value::Object(metadata)),
        context: None,
    })
}

fn normalize_audit_decision(decision: &str) -> (bool, bool) {
    match decision.trim().to_ascii_lowercase().as_str() {
        "allow" | "allowed" | "pass" | "passed" => (true, false),
        "warn" | "warning" | "warned" | "logged" => (true, true),
        _ => (false, false),
    }
}

fn parse_host_port(target: &str) -> (String, u16) {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return (String::new(), 443);
    }

    if let Some((host, port)) = trimmed.rsplit_once(':') {
        if !host.is_empty() {
            if let Ok(port) = port.parse::<u16>() {
                return (host.to_string(), port);
            }
        }
    }

    (trimmed.to_string(), 443)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_host_port_defaults_to_443() {
        assert_eq!(
            parse_host_port("api.github.com"),
            ("api.github.com".to_string(), 443)
        );
        assert_eq!(parse_host_port(""), (String::new(), 443));
    }

    #[test]
    fn parse_host_port_parses_explicit_port() {
        assert_eq!(
            parse_host_port("api.github.com:8443"),
            ("api.github.com".to_string(), 8443)
        );
    }

    #[test]
    fn map_audit_event_maps_file_access_to_policy_event() {
        let event = AuditEventLine {
            id: "evt-1".to_string(),
            timestamp: "2026-02-06T10:00:00Z".to_string(),
            action_type: "file_access".to_string(),
            target: Some("/tmp/demo.txt".to_string()),
            decision: "allowed".to_string(),
            guard: Some("forbidden_path".to_string()),
            severity: Some("info".to_string()),
            message: Some("Allowed".to_string()),
            session_id: Some("sess-1".to_string()),
            metadata: None,
        };

        let mapped = map_audit_event(event).expect("event should map");
        assert_eq!(mapped.event_type, PolicyEventType::FileRead);
        assert_eq!(mapped.session_id.as_deref(), Some("sess-1"));

        match mapped.data {
            PolicyEventData::File(file) => {
                assert_eq!(file.path, "/tmp/demo.txt");
                assert_eq!(file.operation.as_deref(), Some("read"));
            }
            other => panic!("expected file event, got {:?}", other),
        }
    }

    #[test]
    fn map_audit_event_maps_egress_and_decision_metadata() {
        let event = AuditEventLine {
            id: "evt-2".to_string(),
            timestamp: "2026-02-06T10:00:01Z".to_string(),
            action_type: "egress".to_string(),
            target: Some("api.openai.com:443".to_string()),
            decision: "denied".to_string(),
            guard: Some("egress_allowlist".to_string()),
            severity: Some("error".to_string()),
            message: Some("blocked".to_string()),
            session_id: Some("sess-2".to_string()),
            metadata: Some(serde_json::json!({"source":"audit"})),
        };

        let mapped = map_audit_event(event).expect("event should map");
        assert_eq!(mapped.event_type, PolicyEventType::NetworkEgress);

        match mapped.data {
            PolicyEventData::Network(network) => {
                assert_eq!(network.host, "api.openai.com");
                assert_eq!(network.port, 443);
            }
            other => panic!("expected network event, got {:?}", other),
        }

        let metadata = mapped.metadata.expect("metadata should exist");
        let decision = metadata
            .get("decision")
            .and_then(|v| v.as_object())
            .expect("decision metadata should exist");
        assert_eq!(
            decision.get("allowed").and_then(|v| v.as_bool()),
            Some(false)
        );
        assert_eq!(decision.get("warn").and_then(|v| v.as_bool()), Some(false));
    }

    #[test]
    fn map_audit_event_warn_maps_to_allowed_warn_metadata() {
        let event = AuditEventLine {
            id: "evt-3".to_string(),
            timestamp: "2026-02-06T10:00:02Z".to_string(),
            action_type: "shell".to_string(),
            target: Some("rm -rf /tmp/demo".to_string()),
            decision: "warn".to_string(),
            guard: Some("ShellCommandGuard".to_string()),
            severity: Some("warning".to_string()),
            message: Some("logged".to_string()),
            session_id: Some("sess-3".to_string()),
            metadata: None,
        };

        let mapped = map_audit_event(event).expect("event should map");
        let metadata = mapped.metadata.expect("metadata should exist");
        let decision = metadata
            .get("decision")
            .and_then(|v| v.as_object())
            .expect("decision metadata should exist");
        assert_eq!(
            decision.get("allowed").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(decision.get("warn").and_then(|v| v.as_bool()), Some(true));
    }

    #[test]
    fn map_audit_event_warn_produces_logged_ocsf_outcome() {
        let event = AuditEventLine {
            id: "evt-4".to_string(),
            timestamp: "2026-02-06T10:00:03Z".to_string(),
            action_type: "shell".to_string(),
            target: Some("cat /etc/passwd".to_string()),
            decision: "warn".to_string(),
            guard: Some("ShellCommandGuard".to_string()),
            severity: Some("warning".to_string()),
            message: Some("command logged".to_string()),
            session_id: Some("sess-4".to_string()),
            metadata: None,
        };

        let mapped = map_audit_event(event).expect("event should map");
        let json = clawdstrike_policy_event::ocsf::policy_event_to_ocsf(&mapped)
            .expect("warn event should map to OCSF");
        assert_eq!(json["action_id"], 1);
        assert_eq!(json["disposition_id"], 17);
    }
}
