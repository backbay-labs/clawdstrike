//! Map Tetragon events to Spine fact schemas.
//!
//! Each Tetragon event type is mapped to a JSON fact with a well-known schema
//! identifier, severity classification, and structured payload.

use serde_json::{json, Value};

use crate::tetragon::proto::{self, get_events_response::Event, GetEventsResponse, Process};

/// Fact schema for Tetragon events published on the Spine.
pub const FACT_SCHEMA: &str = "clawdstrike.sdr.fact.tetragon_event.v1";

/// Severity levels for classified events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// Sensitive file paths that trigger critical severity.
const SENSITIVE_PATHS: &[&str] = &[
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
    "/root/.ssh/",
    "/proc/kcore",
    "/dev/mem",
    "/dev/kmem",
    "/var/run/secrets/kubernetes.io/",
];

/// Namespaces where process execution raises high severity.
const SENSITIVE_NAMESPACES: &[&str] = &["kube-system", "istio-system", "cilium"];

/// Map a `GetEventsResponse` to a Spine fact JSON value.
///
/// Returns `None` for events with no recognized variant.
pub fn map_event(resp: &GetEventsResponse) -> Option<Value> {
    let node_name = &resp.node_name;

    match &resp.event {
        Some(Event::ProcessExec(exec)) => Some(map_process_exec(exec, node_name)),
        Some(Event::ProcessExit(exit)) => Some(map_process_exit(exit, node_name)),
        Some(Event::ProcessKprobe(kprobe)) => Some(map_process_kprobe(kprobe, node_name)),
        None => None,
    }
}

/// Map a `ProcessExec` event.
fn map_process_exec(exec: &proto::ProcessExec, node_name: &str) -> Value {
    let process_json = process_to_json(exec.process.as_ref());
    let parent_json = process_to_json(exec.parent.as_ref());
    let severity = classify_exec_severity(exec);

    json!({
        "schema": FACT_SCHEMA,
        "event_type": "process_exec",
        "severity": severity.as_str(),
        "node_name": node_name,
        "process": process_json,
        "parent": parent_json,
        "ancestors": &exec.ancestors,
    })
}

/// Map a `ProcessExit` event.
fn map_process_exit(exit: &proto::ProcessExit, node_name: &str) -> Value {
    let process_json = process_to_json(exit.process.as_ref());
    let parent_json = process_to_json(exit.parent.as_ref());

    json!({
        "schema": FACT_SCHEMA,
        "event_type": "process_exit",
        "severity": Severity::Low.as_str(),
        "node_name": node_name,
        "process": process_json,
        "parent": parent_json,
        "signal": &exit.signal,
        "status": exit.status,
    })
}

/// Map a `ProcessKprobe` event.
fn map_process_kprobe(kprobe: &proto::ProcessKprobe, node_name: &str) -> Value {
    let process_json = process_to_json(kprobe.process.as_ref());
    let parent_json = process_to_json(kprobe.parent.as_ref());
    let severity = classify_kprobe_severity(kprobe);

    json!({
        "schema": FACT_SCHEMA,
        "event_type": "process_kprobe",
        "severity": severity.as_str(),
        "node_name": node_name,
        "process": process_json,
        "parent": parent_json,
        "function_name": &kprobe.function_name,
        "action": &kprobe.action,
        "policy_name": &kprobe.policy_name,
        "message": &kprobe.message,
        "tags": &kprobe.tags,
        "args": kprobe_args_to_json(&kprobe.args),
    })
}

/// Convert a `Process` protobuf to a JSON representation.
fn process_to_json(process: Option<&Process>) -> Value {
    let Some(p) = process else {
        return Value::Null;
    };

    let pod_json = p.pod.as_ref().map(|pod| {
        json!({
            "namespace": pod.namespace.as_ref().map(|ns| &ns.value),
            "name": &pod.name,
            "container": pod.container.as_ref().map(|c| json!({
                "id": &c.id,
                "name": &c.name,
                "image": c.image.as_ref().map(|img| json!({
                    "id": &img.id,
                    "name": &img.name,
                })),
            })),
            "labels": &pod.pod_labels,
            "workload": pod.workload.as_ref().map(|w| json!({
                "name": &w.name,
                "kind": &w.kind,
            })),
        })
    });

    json!({
        "pid": p.pid,
        "uid": p.uid,
        "binary": &p.binary,
        "arguments": &p.arguments,
        "cwd": &p.cwd,
        "flags": &p.flags,
        "pod": pod_json.unwrap_or(Value::Null),
        "docker": &p.docker,
    })
}

/// Classify severity for exec events.
fn classify_exec_severity(exec: &proto::ProcessExec) -> Severity {
    if let Some(process) = &exec.process {
        // Exec in a sensitive namespace = high.
        if let Some(pod) = &process.pod {
            if let Some(ns) = &pod.namespace {
                if SENSITIVE_NAMESPACES
                    .iter()
                    .any(|s| ns.value.eq_ignore_ascii_case(s))
                {
                    return Severity::High;
                }
            }
        }

        // Exec of a sensitive binary.
        if SENSITIVE_PATHS
            .iter()
            .any(|s| process.binary.starts_with(s))
        {
            return Severity::Critical;
        }
    }

    Severity::Medium
}

/// Classify severity for kprobe events.
fn classify_kprobe_severity(kprobe: &proto::ProcessKprobe) -> Severity {
    // Check for file access to sensitive paths in kprobe args.
    for arg in &kprobe.args {
        if let Some(a) = &arg.arg {
            match a {
                proto::kprobe_argument::Arg::PathArg(path) => {
                    if SENSITIVE_PATHS.iter().any(|s| path.path.starts_with(s)) {
                        return Severity::Critical;
                    }
                }
                proto::kprobe_argument::Arg::FileArg(file) => {
                    if SENSITIVE_PATHS.iter().any(|s| file.path.starts_with(s)) {
                        return Severity::Critical;
                    }
                }
                proto::kprobe_argument::Arg::SockArg(_sock) => {
                    // Network connect detected — medium baseline.
                    return Severity::Medium;
                }
                _ => {}
            }
        }
    }

    Severity::Low
}

/// Convert kprobe arguments to a JSON array for inclusion in facts.
fn kprobe_args_to_json(args: &[proto::KprobeArgument]) -> Value {
    let items: Vec<Value> = args
        .iter()
        .map(|arg| {
            let value = match &arg.arg {
                Some(proto::kprobe_argument::Arg::StringArg(s)) => json!({"string": s}),
                Some(proto::kprobe_argument::Arg::IntArg(i)) => json!({"int": i}),
                Some(proto::kprobe_argument::Arg::SizeArg(s)) => json!({"size": s}),
                Some(proto::kprobe_argument::Arg::PathArg(p)) => {
                    json!({"path": {"mount": &p.mount, "path": &p.path}})
                }
                Some(proto::kprobe_argument::Arg::FileArg(f)) => {
                    json!({"file": {"mount": &f.mount, "path": &f.path}})
                }
                Some(proto::kprobe_argument::Arg::SockArg(s)) => {
                    json!({"sock": {"saddr": &s.saddr, "daddr": &s.daddr, "sport": s.sport, "dport": s.dport, "protocol": &s.protocol}})
                }
                Some(proto::kprobe_argument::Arg::UintArg(u)) => json!({"uint": u}),
                _ => json!(null),
            };
            json!({
                "label": &arg.label,
                "value": value,
            })
        })
        .collect();
    Value::Array(items)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tetragon::proto;

    fn make_process(binary: &str, ns: Option<&str>) -> proto::Process {
        proto::Process {
            exec_id: None,
            pid: Some(1234),
            uid: Some(0),
            cwd: "/".to_string(),
            binary: binary.to_string(),
            arguments: "--help".to_string(),
            flags: String::new(),
            start_time: None,
            auid: None,
            pod: ns.map(|n| proto::Pod {
                namespace: Some(proto::Namespace {
                    value: n.to_string(),
                }),
                name: "test-pod".to_string(),
                container: None,
                pod_labels: Default::default(),
                workload: None,
            }),
            docker: String::new(),
            parent_exec_id: None,
            cap: None,
            ns: None,
            tid: None,
        }
    }

    #[test]
    fn exec_in_sensitive_namespace_is_high() {
        let exec = proto::ProcessExec {
            process: Some(make_process("/usr/bin/bash", Some("kube-system"))),
            parent: None,
            ancestors: String::new(),
        };
        assert_eq!(classify_exec_severity(&exec), Severity::High);
    }

    #[test]
    fn exec_of_sensitive_binary_is_critical() {
        let exec = proto::ProcessExec {
            process: Some(make_process("/etc/shadow", None)),
            parent: None,
            ancestors: String::new(),
        };
        assert_eq!(classify_exec_severity(&exec), Severity::Critical);
    }

    #[test]
    fn normal_exec_is_medium() {
        let exec = proto::ProcessExec {
            process: Some(make_process("/usr/bin/ls", Some("default"))),
            parent: None,
            ancestors: String::new(),
        };
        assert_eq!(classify_exec_severity(&exec), Severity::Medium);
    }

    #[test]
    fn kprobe_sensitive_path_is_critical() {
        let kprobe = proto::ProcessKprobe {
            process: None,
            parent: None,
            function_name: "security_file_open".to_string(),
            args: vec![proto::KprobeArgument {
                arg: Some(proto::kprobe_argument::Arg::FileArg(proto::KprobeFile {
                    mount: String::new(),
                    path: "/etc/shadow".to_string(),
                    flags: String::new(),
                    permission: String::new(),
                })),
                label: "file".to_string(),
            }],
            action: String::new(),
            policy_name: "file-access".to_string(),
            message: String::new(),
            tags: vec![],
        };
        assert_eq!(classify_kprobe_severity(&kprobe), Severity::Critical);
    }

    #[test]
    fn map_event_returns_none_for_empty() {
        let resp = GetEventsResponse {
            event: None,
            node_name: "node-1".to_string(),
            time: None,
            aggregation_info_count: 0,
        };
        assert!(map_event(&resp).is_none());
    }

    #[test]
    fn map_exec_event_produces_valid_fact() {
        let resp = GetEventsResponse {
            event: Some(Event::ProcessExec(proto::ProcessExec {
                process: Some(make_process("/usr/bin/curl", Some("default"))),
                parent: None,
                ancestors: String::new(),
            })),
            node_name: "worker-1".to_string(),
            time: None,
            aggregation_info_count: 0,
        };
        let fact = map_event(&resp);
        assert!(fact.is_some());
        let fact = fact.unwrap_or_default();
        assert_eq!(fact["schema"], FACT_SCHEMA);
        assert_eq!(fact["event_type"], "process_exec");
        assert_eq!(fact["node_name"], "worker-1");
    }
}
