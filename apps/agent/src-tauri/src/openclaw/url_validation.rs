//! Gateway URL parsing, DNS resolution, and IP allowlist enforcement.

use anyhow::{Context, Result};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug, Clone)]
pub(super) struct GatewayUrlValidation {
    pub(super) normalized_url: String,
    pub(super) pinned_ips: Vec<IpAddr>,
}

pub(super) async fn resolve_gateway_target_ips(parsed: &reqwest::Url) -> Result<Vec<IpAddr>> {
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("gateway_url must include a host"))?;
    let host_lower = host.to_ascii_lowercase();

    if host_lower == "localhost" {
        return Ok(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    }
    if let Ok(parsed_ip) = host_lower.parse::<IpAddr>() {
        return Ok(vec![parsed_ip]);
    }

    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| anyhow::anyhow!("gateway_url must include a valid port"))?;
    let mut resolved_ips = Vec::new();
    let resolved = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("failed to resolve gateway host {host}:{port}"))?;
    for addr in resolved {
        resolved_ips.push(addr.ip());
    }
    Ok(resolved_ips)
}

pub(super) async fn validate_gateway_url(raw: &str) -> Result<GatewayUrlValidation> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        anyhow::bail!("gateway_url cannot be empty");
    }

    let parsed =
        reqwest::Url::parse(trimmed).with_context(|| format!("invalid gateway_url '{trimmed}'"))?;
    let scheme = parsed.scheme().to_ascii_lowercase();
    if scheme != "ws" && scheme != "wss" {
        anyhow::bail!("gateway_url must use ws:// or wss://");
    }

    let target_ips = resolve_gateway_target_ips(&parsed).await?;

    validate_gateway_target_ips(&scheme, &target_ips)?;

    Ok(GatewayUrlValidation {
        normalized_url: trimmed.to_string(),
        pinned_ips: target_ips,
    })
}

fn parse_pinned_ip_set(pinned_ips: &[String]) -> Result<HashSet<IpAddr>> {
    let mut parsed = HashSet::new();
    for raw in pinned_ips {
        let candidate = raw.trim();
        if candidate.is_empty() {
            continue;
        }
        let ip = candidate
            .parse::<IpAddr>()
            .with_context(|| format!("invalid pinned gateway IP '{candidate}'"))?;
        parsed.insert(ip);
    }
    Ok(parsed)
}

pub(super) async fn validate_gateway_runtime_target(
    raw: &str,
    pinned_ips: &[String],
) -> Result<()> {
    let parsed =
        reqwest::Url::parse(raw).with_context(|| format!("invalid runtime gateway_url '{raw}'"))?;
    let scheme = parsed.scheme().to_ascii_lowercase();
    if scheme != "ws" && scheme != "wss" {
        anyhow::bail!("gateway_url must use ws:// or wss://");
    }

    let resolved_ips = resolve_gateway_target_ips(&parsed).await?;
    validate_gateway_target_ips(&scheme, &resolved_ips)?;

    let pinned = parse_pinned_ip_set(pinned_ips)?;
    if !pinned.is_empty() && resolved_ips.iter().any(|ip| !pinned.contains(ip)) {
        anyhow::bail!(
            "gateway_url resolved addresses changed outside the pinned allowlist; re-save gateway configuration"
        );
    }

    Ok(())
}

pub(super) fn validate_gateway_target_ips(scheme: &str, target_ips: &[IpAddr]) -> Result<()> {
    if target_ips.is_empty() {
        anyhow::bail!("gateway_url host did not resolve to any addresses");
    }

    if scheme == "ws" && target_ips.iter().any(|ip| !is_loopback_equivalent_ip(*ip)) {
        anyhow::bail!("non-loopback gateway_url values must use wss://");
    }

    if target_ips
        .iter()
        .any(|ip| !is_loopback_equivalent_ip(*ip) && is_private_or_link_local_ip(*ip))
    {
        anyhow::bail!("private/link-local gateway_url addresses are not allowed");
    }

    Ok(())
}

fn is_loopback_equivalent_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|mapped| mapped.is_loopback())
        }
    }
}

fn is_private_or_link_local_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private() || v4.is_link_local() || v4.is_broadcast() || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return mapped.is_private()
                    || mapped.is_link_local()
                    || mapped.is_broadcast()
                    || mapped.is_unspecified();
            }
            let segment0 = v6.segments()[0];
            let unique_local = (segment0 & 0xfe00) == 0xfc00; // fc00::/7
            let link_local = (segment0 & 0xffc0) == 0xfe80; // fe80::/10
            unique_local || link_local || v6.is_unspecified()
        }
    }
}
