//! Egress target normalization and active-restriction matching.
//!
//! Normalizes `host:port` targets into a canonical form, validates that they
//! are non-local and non-private before being installed as restrictions, and
//! looks up the active restriction (if any) for a policy check input so the
//! engine can fail it closed at the policy layer.

use super::*;

pub(crate) async fn active_egress_restriction_for_policy_check(
    state: &AgentApiState,
    input: &PolicyCheckInput,
) -> Option<EndpointEgressRestriction> {
    let target = normalize_egress_policy_target(&input.action_type, &input.target)?;
    let ledger = state.edr_egress_restriction_ledger.lock().await;
    ledger.active_match(&target, chrono::Utc::now())
}

pub(crate) fn policy_output_for_active_egress_restriction(
    restriction: &EndpointEgressRestriction,
) -> PolicyCheckOutput {
    PolicyCheckOutput {
        allowed: false,
        guard: Some("edr_restrict_egress".to_string()),
        severity: Some("high".to_string()),
        message: Some(format!(
            "Egress to {} denied by active EDR response execution {}",
            restriction.target, restriction.execution_id
        )),
        details: Some(serde_json::json!({
            "reason": "active_edr_egress_restriction",
            "target": restriction.target.clone(),
            "executionId": restriction.execution_id.clone(),
            "actionId": restriction.action_id.clone(),
            "rollbackRef": restriction.rollback_ref.clone(),
            "graphSliceId": restriction.graph_slice_id.clone(),
            "expiresAt": restriction.expires_at,
        })),
    }
}

pub(crate) fn restrict_egress_targets(
    plan: &EndpointResponsePlan,
    graph: &CausalGraph,
) -> Result<Vec<String>> {
    let root = graph
        .nodes
        .get(&plan.root_node_id)
        .ok_or_else(|| anyhow::anyhow!("root node not found: {}", plan.root_node_id))?;
    let root_target = if root.kind == CausalNodeKind::Network {
        Some(egress_target_from_node(root)?)
    } else {
        None
    };

    let mut targets = graph
        .nodes
        .values()
        .filter(|node| node.kind == CausalNodeKind::Network)
        .map(egress_target_from_node)
        .collect::<Result<Vec<_>>>()?;
    targets.sort();
    targets.dedup();
    if targets.is_empty() {
        return Err(anyhow::anyhow!(
            "restrict_egress requires at least one network node in the graph slice"
        ));
    }
    if let Some(root_target) = root_target {
        targets.retain(|target| target != &root_target);
        targets.insert(0, root_target);
    }
    Ok(targets)
}

fn egress_target_from_node(node: &clawdstrike_policy_event::edr::CausalNode) -> Result<String> {
    normalize_egress_target(node.label.as_str())
        .with_context(|| format!("normalize network node target {}", node.label))
}

fn normalize_egress_policy_target(action_type: &str, target: &str) -> Option<String> {
    let action = action_type.trim().to_ascii_lowercase();
    if action != "egress" && action != "network" {
        return None;
    }
    let target = target.trim();
    let lower = target.to_ascii_lowercase();
    let target = if lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("ws://")
        || lower.starts_with("wss://")
    {
        let url = reqwest::Url::parse(target).ok()?;
        let host = url.host_str()?;
        let port = url.port_or_known_default()?;
        if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        }
    } else {
        target.to_string()
    };
    normalize_egress_target(target.as_str()).ok()
}

pub(crate) fn normalize_egress_target(target: &str) -> Result<String> {
    let target = target.trim();
    if target.is_empty() {
        return Err(anyhow::anyhow!("egress target must not be empty"));
    }
    if target.len() > 512 {
        return Err(anyhow::anyhow!("egress target must be at most 512 bytes"));
    }
    if target
        .chars()
        .any(|ch| ch.is_ascii_whitespace() || matches!(ch, '*' | ',' | '/'))
    {
        return Err(anyhow::anyhow!(
            "egress target must be a literal host:port without wildcards or paths"
        ));
    }
    let (host, port) = split_egress_host_port(target)?;
    let port: u16 = port
        .parse()
        .with_context(|| format!("parse egress target port {port}"))?;
    if port == 0 {
        return Err(anyhow::anyhow!("egress target port must be non-zero"));
    }
    let normalized_host = host.trim_matches(['[', ']']).to_ascii_lowercase();
    if normalized_host.is_empty() {
        return Err(anyhow::anyhow!("egress target host must not be empty"));
    }
    if matches!(
        normalized_host.as_str(),
        "localhost" | "localhost.localdomain"
    ) {
        return Err(anyhow::anyhow!("refusing to restrict local host egress"));
    }
    if let Ok(ip) = normalized_host.parse::<IpAddr>() {
        validate_egress_restriction_ip(ip)?;
    }
    if normalized_host.contains(':') {
        Ok(format!("[{normalized_host}]:{port}"))
    } else {
        Ok(format!("{normalized_host}:{port}"))
    }
}

fn split_egress_host_port(target: &str) -> Result<(&str, &str)> {
    if let Some(rest) = target.strip_prefix('[') {
        let (host, port) = rest
            .split_once("]:")
            .ok_or_else(|| anyhow::anyhow!("bracketed egress target must be [host]:port"))?;
        return Ok((host, port));
    }
    target
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("egress target must include a port"))
}

fn validate_egress_restriction_ip(ip: IpAddr) -> Result<()> {
    let blocked = match ip {
        IpAddr::V4(ip) => {
            ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_documentation()
                || ip.is_unspecified()
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ipv6_is_unique_local(&ip)
                || ipv6_is_unicast_link_local(&ip)
                || ip.is_multicast()
        }
    };
    if blocked {
        return Err(anyhow::anyhow!(
            "refusing to restrict local, private, link-local, multicast, or documentation egress target {ip}"
        ));
    }
    Ok(())
}

fn ipv6_is_unique_local(ip: &std::net::Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

fn ipv6_is_unicast_link_local(ip: &std::net::Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}
