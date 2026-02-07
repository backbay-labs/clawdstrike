//! Map Hubble flows to Spine fact schemas.
//!
//! Each Hubble flow is mapped to a JSON fact with a well-known schema
//! identifier, severity classification, and structured payload covering
//! source/destination endpoints, verdict, L7 info, and traffic direction.

use serde_json::{json, Value};

use crate::hubble::proto::{
    self, Flow, GetFlowsResponse, Verdict,
};

/// Fact schema for Hubble flow events published on the Spine.
pub const FACT_SCHEMA: &str = "clawdstrike.sdr.fact.hubble_flow.v1";

/// Severity levels for classified flows.
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

/// Sensitive namespaces where flow drops raise higher severity.
const SENSITIVE_NAMESPACES: &[&str] = &["kube-system", "istio-system", "cilium"];

/// Map a `GetFlowsResponse` to a Spine fact JSON value.
///
/// Returns `None` if the response contains no flow.
pub fn map_flow(resp: &GetFlowsResponse) -> Option<Value> {
    let node_name = &resp.node_name;

    resp.response_types.as_ref().map(
        |proto::get_flows_response::ResponseTypes::Flow(flow)| flow_to_fact(flow, node_name),
    )
}

/// Convert a single Hubble flow into a Spine fact.
fn flow_to_fact(flow: &Flow, node_name: &str) -> Value {
    let severity = classify_flow_severity(flow);
    let source = endpoint_to_json(flow.source.as_ref());
    let destination = endpoint_to_json(flow.destination.as_ref());
    let ip_info = ip_to_json(flow.ip.as_ref());
    let l4_info = l4_to_json(flow.l4.as_ref());
    let l7_info = l7_to_json(flow.l7.as_ref());

    let verdict_str = match Verdict::try_from(flow.verdict) {
        Ok(Verdict::Forwarded) => "FORWARDED",
        Ok(Verdict::Dropped) => "DROPPED",
        Ok(Verdict::Error) => "ERROR",
        Ok(Verdict::Audit) => "AUDIT",
        Ok(Verdict::Redirected) => "REDIRECTED",
        Ok(Verdict::Traced) => "TRACED",
        Ok(Verdict::Translated) => "TRANSLATED",
        _ => "UNKNOWN",
    };

    let direction_str = match proto::TrafficDirection::try_from(flow.traffic_direction) {
        Ok(proto::TrafficDirection::Ingress) => "INGRESS",
        Ok(proto::TrafficDirection::Egress) => "EGRESS",
        _ => "UNKNOWN",
    };

    json!({
        "schema": FACT_SCHEMA,
        "severity": severity.as_str(),
        "node_name": node_name,
        "verdict": verdict_str,
        "traffic_direction": direction_str,
        "source": source,
        "destination": destination,
        "ip": ip_info,
        "l4": l4_info,
        "l7": l7_info,
        "is_reply": flow.is_reply,
        "summary": &flow.summary,
        "source_names": &flow.source_names,
        "destination_names": &flow.destination_names,
    })
}

/// Convert an Endpoint to JSON.
fn endpoint_to_json(ep: Option<&proto::Endpoint>) -> Value {
    let Some(ep) = ep else {
        return Value::Null;
    };

    let workloads: Vec<Value> = ep
        .workloads
        .iter()
        .map(|w| {
            json!({
                "name": &w.name,
                "kind": &w.kind,
            })
        })
        .collect();

    json!({
        "id": ep.id,
        "identity": ep.identity,
        "namespace": &ep.namespace,
        "labels": &ep.labels,
        "pod_name": &ep.pod_name,
        "workloads": workloads,
        "cluster_name": &ep.cluster_name,
    })
}

/// Convert IP info to JSON.
fn ip_to_json(ip: Option<&proto::Ip>) -> Value {
    let Some(ip) = ip else {
        return Value::Null;
    };
    json!({
        "source": &ip.source,
        "destination": &ip.destination,
        "ip_version": match proto::IpVersion::try_from(ip.ip_version) {
            Ok(proto::IpVersion::IPv4) => "IPv4",
            Ok(proto::IpVersion::IPv6) => "IPv6",
            _ => "unknown",
        },
        "encrypted": ip.encrypted,
    })
}

/// Convert Layer4 info to JSON.
fn l4_to_json(l4: Option<&proto::Layer4>) -> Value {
    let Some(l4) = l4 else {
        return Value::Null;
    };
    match &l4.protocol {
        Some(proto::layer4::Protocol::Tcp(tcp)) => json!({
            "protocol": "TCP",
            "source_port": tcp.source_port,
            "destination_port": tcp.destination_port,
            "flags": tcp.flags.as_ref().map(|f| json!({
                "SYN": f.syn,
                "ACK": f.ack,
                "FIN": f.fin,
                "RST": f.rst,
                "PSH": f.psh,
            })),
        }),
        Some(proto::layer4::Protocol::Udp(udp)) => json!({
            "protocol": "UDP",
            "source_port": udp.source_port,
            "destination_port": udp.destination_port,
        }),
        Some(proto::layer4::Protocol::Icmpv4(icmp)) => json!({
            "protocol": "ICMPv4",
            "type": icmp.r#type,
            "code": icmp.code,
        }),
        Some(proto::layer4::Protocol::Icmpv6(icmp)) => json!({
            "protocol": "ICMPv6",
            "type": icmp.r#type,
            "code": icmp.code,
        }),
        Some(proto::layer4::Protocol::Sctp(sctp)) => json!({
            "protocol": "SCTP",
            "source_port": sctp.source_port,
            "destination_port": sctp.destination_port,
        }),
        None => Value::Null,
    }
}

/// Convert Layer7 info to JSON.
fn l7_to_json(l7: Option<&proto::Layer7>) -> Value {
    let Some(l7) = l7 else {
        return Value::Null;
    };

    let flow_type = match proto::Layer7FlowType::try_from(l7.r#type) {
        Ok(proto::Layer7FlowType::Request) => "REQUEST",
        Ok(proto::Layer7FlowType::Response) => "RESPONSE",
        Ok(proto::Layer7FlowType::Sample) => "SAMPLE",
        _ => "UNKNOWN",
    };

    let record = match &l7.record {
        Some(proto::layer7::Record::Http(http)) => json!({
            "type": "http",
            "method": &http.method,
            "url": &http.url,
            "code": http.code,
            "protocol": &http.protocol,
        }),
        Some(proto::layer7::Record::Dns(dns)) => json!({
            "type": "dns",
            "query": &dns.query,
            "ips": &dns.ips,
            "ttl": dns.ttl,
            "rcode": dns.rcode,
            "qtypes": &dns.qtypes,
            "rrtypes": &dns.rrtypes,
        }),
        Some(proto::layer7::Record::Kafka(kafka)) => json!({
            "type": "kafka",
            "topic": &kafka.topic,
            "api_key": &kafka.api_key,
            "api_version": kafka.api_version,
            "error_code": kafka.error_code,
            "correlation_id": kafka.correlation_id,
        }),
        None => Value::Null,
    };

    json!({
        "flow_type": flow_type,
        "latency_ns": l7.latency_ns,
        "record": record,
    })
}

/// Classify severity for a Hubble flow.
fn classify_flow_severity(flow: &Flow) -> Severity {
    let verdict = Verdict::try_from(flow.verdict).unwrap_or(Verdict::Unknown);

    // Dropped traffic in sensitive namespaces = critical.
    if verdict == Verdict::Dropped {
        if is_sensitive_namespace(flow.source.as_ref())
            || is_sensitive_namespace(flow.destination.as_ref())
        {
            return Severity::Critical;
        }
        return Severity::High;
    }

    // Errors are high.
    if verdict == Verdict::Error {
        return Severity::High;
    }

    // L7 policy drops / DNS failures in forwarded traffic still matter.
    if let Some(l7) = &flow.l7 {
        if let Some(proto::layer7::Record::Http(http)) = &l7.record {
            if http.code >= 400 {
                return Severity::Medium;
            }
        }
        if let Some(proto::layer7::Record::Dns(dns)) = &l7.record {
            // Non-zero rcode = DNS error.
            if dns.rcode != 0 {
                return Severity::Medium;
            }
        }
    }

    Severity::Low
}

/// Check if an endpoint is in a sensitive namespace.
fn is_sensitive_namespace(ep: Option<&proto::Endpoint>) -> bool {
    let Some(ep) = ep else {
        return false;
    };
    SENSITIVE_NAMESPACES
        .iter()
        .any(|s| ep.namespace.eq_ignore_ascii_case(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_endpoint(ns: &str, pod: &str) -> proto::Endpoint {
        proto::Endpoint {
            id: 1,
            identity: 100,
            namespace: ns.to_string(),
            labels: vec!["app=test".to_string()],
            pod_name: pod.to_string(),
            workloads: vec![],
            cluster_name: "default".to_string(),
        }
    }

    fn make_flow(verdict: Verdict, src_ns: &str, dst_ns: &str) -> Flow {
        Flow {
            time: None,
            verdict: verdict.into(),
            drop_reason: 0,
            ethernet: None,
            ip: Some(proto::Ip {
                source: "10.0.0.1".to_string(),
                destination: "10.0.0.2".to_string(),
                ip_version: proto::IpVersion::IPv4.into(),
                encrypted: false,
            }),
            l4: Some(proto::Layer4 {
                protocol: Some(proto::layer4::Protocol::Tcp(proto::Tcp {
                    source_port: 12345,
                    destination_port: 80,
                    flags: None,
                })),
            }),
            source: Some(make_endpoint(src_ns, "src-pod")),
            destination: Some(make_endpoint(dst_ns, "dst-pod")),
            r#type: proto::FlowType::L3L4.into(),
            node_name: "node-1".to_string(),
            source_names: vec![],
            destination_names: vec![],
            l7: None,
            reply: false,
            event_type: None,
            source_service: None,
            destination_service: None,
            traffic_direction: proto::TrafficDirection::Egress.into(),
            policy_match_type: 0,
            drop_reason_desc: 0,
            is_reply: false,
            trace_observation_point: String::new(),
            drop_reason_extra: vec![],
            summary: "TCP Flags: SYN".to_string(),
        }
    }

    #[test]
    fn dropped_in_sensitive_ns_is_critical() {
        let flow = make_flow(Verdict::Dropped, "kube-system", "default");
        assert_eq!(classify_flow_severity(&flow), Severity::Critical);
    }

    #[test]
    fn dropped_in_normal_ns_is_high() {
        let flow = make_flow(Verdict::Dropped, "default", "app-ns");
        assert_eq!(classify_flow_severity(&flow), Severity::High);
    }

    #[test]
    fn error_flow_is_high() {
        let flow = make_flow(Verdict::Error, "default", "default");
        assert_eq!(classify_flow_severity(&flow), Severity::High);
    }

    #[test]
    fn forwarded_flow_is_low() {
        let flow = make_flow(Verdict::Forwarded, "default", "default");
        assert_eq!(classify_flow_severity(&flow), Severity::Low);
    }

    #[test]
    fn map_flow_returns_none_for_empty() {
        let resp = GetFlowsResponse {
            response_types: None,
            node_name: "node-1".to_string(),
            time: None,
        };
        assert!(map_flow(&resp).is_none());
    }

    #[test]
    fn map_flow_produces_valid_fact() {
        let flow = make_flow(Verdict::Forwarded, "default", "app");
        let resp = GetFlowsResponse {
            response_types: Some(proto::get_flows_response::ResponseTypes::Flow(flow)),
            node_name: "worker-1".to_string(),
            time: None,
        };
        let fact = map_flow(&resp);
        assert!(fact.is_some());
        let fact = fact.unwrap_or_default();
        assert_eq!(fact["schema"], FACT_SCHEMA);
        assert_eq!(fact["verdict"], "FORWARDED");
        assert_eq!(fact["node_name"], "worker-1");
        assert_eq!(fact["source"]["namespace"], "default");
        assert_eq!(fact["destination"]["namespace"], "app");
    }

    #[test]
    fn l7_http_error_is_medium() {
        let mut flow = make_flow(Verdict::Forwarded, "default", "default");
        flow.l7 = Some(proto::Layer7 {
            r#type: proto::Layer7FlowType::Response.into(),
            latency_ns: 5000,
            record: Some(proto::layer7::Record::Http(proto::Http {
                code: 403,
                method: "GET".to_string(),
                url: "/api/secrets".to_string(),
                protocol: "HTTP/1.1".to_string(),
                headers: vec![],
            })),
        });
        assert_eq!(classify_flow_severity(&flow), Severity::Medium);
    }
}
