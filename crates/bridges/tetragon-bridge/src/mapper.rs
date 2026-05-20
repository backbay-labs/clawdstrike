//! Map Tetragon events to Spine fact schemas.
//!
//! Each Tetragon event type is mapped to a JSON fact with a well-known schema
//! identifier, severity classification, and structured payload.

use std::{collections::HashMap, path::Path};

use hush_core::sha256_hex;
use serde_json::{json, Value};

use crate::tetragon::proto::{self, get_events_response::Event, GetEventsResponse, Process};

/// Fact schema for Tetragon events published on the Spine.
pub const FACT_SCHEMA: &str = "clawdstrike.sdr.fact.tetragon_event.v1";

const PRIVACY_MODE: &str = "hash_only:v1";

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
    let ancestors_json: Vec<Value> = exec
        .ancestors
        .iter()
        .map(|p| process_to_json(Some(p)))
        .collect();
    let severity = classify_exec_severity(exec);

    json!({
        "schema": FACT_SCHEMA,
        "event_type": "process_exec",
        "severity": severity.as_str(),
        "node_name": node_name,
        "process": process_json,
        "parent": parent_json,
        "ancestors": ancestors_json,
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
        "message": redacted_text(&kprobe.message),
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
            "namespace": &pod.namespace,
            "name": redacted_text(&pod.name),
            "container": pod.container.as_ref().map(|c| json!({
                "id": redacted_text(&c.id),
                "name": redacted_text(&c.name),
                "image": c.image.as_ref().map(|img| json!({
                    "id": redacted_text(&img.id),
                    "name": redacted_text(&img.name),
                })),
            })),
            "labels": redacted_label_map(&pod.pod_labels),
            "workload": redacted_text(&pod.workload),
            "workload_kind": &pod.workload_kind,
        })
    });

    json!({
        "pid": p.pid,
        "uid": p.uid,
        "binary": path_basename(&p.binary),
        "binary_path": redacted_text(&p.binary),
        "arguments": redacted_text(&p.arguments),
        "cwd": redacted_text(&p.cwd),
        "flags": redacted_text(&p.flags),
        "pod": pod_json.unwrap_or(Value::Null),
        "docker": redacted_text(&p.docker),
        "privacy": {
            "mode": PRIVACY_MODE,
        },
    })
}

/// Classify severity for exec events.
fn classify_exec_severity(exec: &proto::ProcessExec) -> Severity {
    let mut severity = Severity::Medium;

    if let Some(process) = &exec.process {
        // Exec in a sensitive namespace = high baseline.
        if let Some(pod) = &process.pod {
            if SENSITIVE_NAMESPACES
                .iter()
                .any(|s| pod.namespace.eq_ignore_ascii_case(s))
            {
                severity = Severity::High;
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

    severity
}

/// Classify severity for kprobe events.
fn classify_kprobe_severity(kprobe: &proto::ProcessKprobe) -> Severity {
    let mut saw_socket_arg = false;

    // Check for file access to sensitive paths in kprobe args.
    for arg in &kprobe.args {
        if let Some(a) = &arg.arg {
            match a {
                proto::kprobe_argument::Arg::PathArg(path)
                    if SENSITIVE_PATHS.iter().any(|s| path.path.starts_with(s)) =>
                {
                    return Severity::Critical;
                }
                proto::kprobe_argument::Arg::FileArg(file)
                    if SENSITIVE_PATHS.iter().any(|s| file.path.starts_with(s)) =>
                {
                    return Severity::Critical;
                }
                proto::kprobe_argument::Arg::SockArg(_sock) => {
                    // Network connect detected — medium baseline.
                    saw_socket_arg = true;
                }
                _ => {}
            }
        }
    }

    if saw_socket_arg {
        Severity::Medium
    } else {
        Severity::Low
    }
}

/// Convert kprobe arguments to a JSON array for inclusion in facts.
fn kprobe_args_to_json(args: &[proto::KprobeArgument]) -> Value {
    let items: Vec<Value> = args
        .iter()
        .map(|arg| {
            let value = match &arg.arg {
                Some(proto::kprobe_argument::Arg::StringArg(s)) => {
                    json!({"string": redacted_text(s)})
                }
                Some(proto::kprobe_argument::Arg::IntArg(i)) => json!({"int": i}),
                Some(proto::kprobe_argument::Arg::SizeArg(s)) => json!({"size": s}),
                Some(proto::kprobe_argument::Arg::PathArg(p)) => {
                    json!({"path": {"mount": redacted_text(&p.mount), "path": redacted_text(&p.path)}})
                }
                Some(proto::kprobe_argument::Arg::FileArg(f)) => {
                    json!({"file": {"mount": redacted_text(&f.mount), "path": redacted_text(&f.path)}})
                }
                Some(proto::kprobe_argument::Arg::SockArg(s)) => {
                    json!({
                        "sock": {
                            "family": &s.family,
                            "type": &s.r#type,
                            "saddr": redacted_text(&s.saddr),
                            "daddr": redacted_text(&s.daddr),
                            "sport": s.sport,
                            "dport": s.dport,
                            "protocol": &s.protocol,
                        }
                    })
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

fn redacted_text(value: &str) -> Value {
    if value.is_empty() {
        return Value::Null;
    }

    json!({
        "sha256": sha256_hex(value.as_bytes()),
        "byte_length": value.len(),
    })
}

fn path_basename(path: &str) -> Value {
    if path.is_empty() {
        return Value::Null;
    }

    Path::new(path)
        .file_name()
        .and_then(|value| value.to_str())
        .map_or_else(|| json!(null), |value| json!(value))
}

fn redacted_label_map(labels: &HashMap<String, String>) -> Value {
    let mut entry_hashes: Vec<String> = labels
        .iter()
        .map(|(key, value)| sha256_hex(format!("{key}={value}").as_bytes()))
        .collect();
    entry_hashes.sort();

    json!({
        "count": labels.len(),
        "entry_hashes": entry_hashes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tetragon::proto;

    fn make_process(binary: &str, ns: Option<&str>) -> proto::Process {
        let mut labels = HashMap::new();
        labels.insert(
            "secret.company.io/team".to_string(),
            "defense-research".to_string(),
        );

        proto::Process {
            exec_id: String::new(),
            pid: Some(1234),
            uid: Some(0),
            cwd: "/home/alice/work/private-repo".to_string(),
            binary: binary.to_string(),
            arguments: "--token super-secret-token".to_string(),
            flags: "execve".to_string(),
            start_time: None,
            auid: None,
            pod: ns.map(|n| proto::Pod {
                namespace: n.to_string(),
                name: "customer-secret-pod".to_string(),
                container: None,
                pod_labels: labels,
                workload: "customer-secret-workload".to_string(),
                workload_kind: "Deployment".to_string(),
            }),
            docker: "docker-container-secret-id".to_string(),
            parent_exec_id: String::new(),
            refcnt: 0,
            cap: None,
            ns: None,
            tid: None,
            process_credentials: None,
        }
    }

    #[test]
    fn exec_in_sensitive_namespace_is_high() {
        let exec = proto::ProcessExec {
            process: Some(make_process("/usr/bin/bash", Some("kube-system"))),
            parent: None,
            ancestors: vec![],
        };
        assert_eq!(classify_exec_severity(&exec), Severity::High);
    }

    #[test]
    fn exec_of_sensitive_binary_is_critical() {
        let exec = proto::ProcessExec {
            process: Some(make_process("/etc/shadow", None)),
            parent: None,
            ancestors: vec![],
        };
        assert_eq!(classify_exec_severity(&exec), Severity::Critical);
    }

    #[test]
    fn exec_sensitive_namespace_and_sensitive_binary_is_critical() {
        let exec = proto::ProcessExec {
            process: Some(make_process("/etc/shadow", Some("kube-system"))),
            parent: None,
            ancestors: vec![],
        };
        assert_eq!(classify_exec_severity(&exec), Severity::Critical);
    }

    #[test]
    fn normal_exec_is_medium() {
        let exec = proto::ProcessExec {
            process: Some(make_process("/usr/bin/ls", Some("default"))),
            parent: None,
            ancestors: vec![],
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
            return_arg: None,
            action: proto::KprobeAction::Unknown.into(),
            kernel_stack_trace: vec![],
            policy_name: "file-access".to_string(),
            return_action: proto::KprobeAction::Unknown.into(),
            message: String::new(),
            tags: vec![],
            user_stack_trace: vec![],
        };
        assert_eq!(classify_kprobe_severity(&kprobe), Severity::Critical);
    }

    #[test]
    fn kprobe_sock_then_sensitive_path_is_critical() {
        let kprobe = proto::ProcessKprobe {
            process: None,
            parent: None,
            function_name: "security_file_open".to_string(),
            args: vec![
                proto::KprobeArgument {
                    arg: Some(proto::kprobe_argument::Arg::SockArg(proto::KprobeSock {
                        family: "AF_INET".to_string(),
                        r#type: "SOCK_STREAM".to_string(),
                        protocol: "tcp".to_string(),
                        mark: 0,
                        priority: 0,
                        saddr: "10.0.0.10".to_string(),
                        daddr: "10.0.0.20".to_string(),
                        sport: 12345,
                        dport: 443,
                        cookie: 0,
                        state: String::new(),
                    })),
                    label: "sock".to_string(),
                },
                proto::KprobeArgument {
                    arg: Some(proto::kprobe_argument::Arg::PathArg(proto::KprobePath {
                        mount: String::new(),
                        path: "/etc/shadow".to_string(),
                        flags: String::new(),
                        permission: String::new(),
                    })),
                    label: "path".to_string(),
                },
            ],
            return_arg: None,
            action: proto::KprobeAction::Unknown.into(),
            kernel_stack_trace: vec![],
            policy_name: "mixed-args".to_string(),
            return_action: proto::KprobeAction::Unknown.into(),
            message: String::new(),
            tags: vec![],
            user_stack_trace: vec![],
        };
        assert_eq!(classify_kprobe_severity(&kprobe), Severity::Critical);
    }

    #[test]
    fn map_event_returns_none_for_empty() {
        let resp = GetEventsResponse {
            event: None,
            node_name: "node-1".to_string(),
            time: None,
            aggregation_info: None,
            cluster_name: String::new(),
        };
        assert!(map_event(&resp).is_none());
    }

    #[test]
    fn map_exec_event_produces_valid_fact() {
        let resp = GetEventsResponse {
            event: Some(Event::ProcessExec(proto::ProcessExec {
                process: Some(make_process("/usr/bin/curl", Some("default"))),
                parent: None,
                ancestors: vec![],
            })),
            node_name: "worker-1".to_string(),
            time: None,
            aggregation_info: None,
            cluster_name: String::new(),
        };
        let fact = map_event(&resp);
        assert!(fact.is_some());
        let fact = fact.unwrap_or_default();
        assert_eq!(fact["schema"], FACT_SCHEMA);
        assert_eq!(fact["event_type"], "process_exec");
        assert_eq!(fact["node_name"], "worker-1");
    }

    #[test]
    fn map_exec_event_redacts_process_sensitive_fields() {
        let resp = GetEventsResponse {
            event: Some(Event::ProcessExec(proto::ProcessExec {
                process: Some(make_process("/usr/bin/curl", Some("default"))),
                parent: None,
                ancestors: vec![],
            })),
            node_name: "worker-1".to_string(),
            time: None,
            aggregation_info: None,
            cluster_name: String::new(),
        };

        let fact = map_event(&resp).unwrap_or_default();
        assert_eq!(fact["process"]["binary"], "curl");
        assert_eq!(fact["process"]["privacy"]["mode"], PRIVACY_MODE);
        assert!(fact["process"]["binary_path"]["sha256"].is_string());
        assert!(fact["process"]["arguments"]["sha256"].is_string());
        assert!(fact["process"]["cwd"]["sha256"].is_string());
        assert!(fact["process"]["flags"]["sha256"].is_string());
        assert!(fact["process"]["docker"]["sha256"].is_string());
        assert_eq!(fact["process"]["pod"]["labels"]["count"], 1);
        assert!(fact["process"]["pod"]["labels"]["entry_hashes"][0].is_string());

        let serialized = serde_json::to_string(&fact).unwrap_or_default();
        assert!(!serialized.contains("super-secret-token"));
        assert!(!serialized.contains("/home/alice/work/private-repo"));
        assert!(!serialized.contains("/usr/bin/curl"));
        assert!(!serialized.contains("docker-container-secret-id"));
        assert!(!serialized.contains("defense-research"));
        assert!(!serialized.contains("customer-secret-pod"));
        assert!(!serialized.contains("customer-secret-workload"));
    }

    #[test]
    fn map_kprobe_event_redacts_arguments_but_keeps_severity() {
        let resp = GetEventsResponse {
            event: Some(Event::ProcessKprobe(proto::ProcessKprobe {
                process: Some(make_process("/usr/bin/cat", Some("default"))),
                parent: None,
                function_name: "security_file_open".to_string(),
                args: vec![
                    proto::KprobeArgument {
                        arg: Some(proto::kprobe_argument::Arg::StringArg(
                            "api-key=secret".to_string(),
                        )),
                        label: "raw-command".to_string(),
                    },
                    proto::KprobeArgument {
                        arg: Some(proto::kprobe_argument::Arg::FileArg(proto::KprobeFile {
                            mount: "/".to_string(),
                            path: "/etc/shadow".to_string(),
                            flags: String::new(),
                            permission: String::new(),
                        })),
                        label: "file".to_string(),
                    },
                    proto::KprobeArgument {
                        arg: Some(proto::kprobe_argument::Arg::SockArg(proto::KprobeSock {
                            family: "AF_INET".to_string(),
                            r#type: "SOCK_STREAM".to_string(),
                            protocol: "tcp".to_string(),
                            mark: 0,
                            priority: 0,
                            saddr: "10.0.0.10".to_string(),
                            daddr: "10.0.0.20".to_string(),
                            sport: 12345,
                            dport: 443,
                            cookie: 0,
                            state: String::new(),
                        })),
                        label: "sock".to_string(),
                    },
                ],
                return_arg: None,
                action: proto::KprobeAction::Unknown.into(),
                kernel_stack_trace: vec![],
                policy_name: "file-access".to_string(),
                return_action: proto::KprobeAction::Unknown.into(),
                message: "file access to /etc/shadow".to_string(),
                tags: vec![],
                user_stack_trace: vec![],
            })),
            node_name: "worker-2".to_string(),
            time: None,
            aggregation_info: None,
            cluster_name: String::new(),
        };

        let fact = map_event(&resp).unwrap_or_default();
        assert_eq!(fact["severity"], "critical");
        assert!(fact["message"]["sha256"].is_string());
        assert!(fact["args"][0]["value"]["string"]["sha256"].is_string());
        assert!(fact["args"][1]["value"]["file"]["path"]["sha256"].is_string());
        assert!(fact["args"][2]["value"]["sock"]["saddr"]["sha256"].is_string());
        assert!(fact["args"][2]["value"]["sock"]["daddr"]["sha256"].is_string());
        assert_eq!(fact["args"][2]["value"]["sock"]["dport"], 443);

        let serialized = serde_json::to_string(&fact).unwrap_or_default();
        assert!(!serialized.contains("api-key=secret"));
        assert!(!serialized.contains("/etc/shadow"));
        assert!(!serialized.contains("10.0.0.10"));
        assert!(!serialized.contains("10.0.0.20"));
    }
}
