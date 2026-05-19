//! JetStream consumer for endpoint-originated hunt events.
//!
//! Agents publish privacy-bounded `FleetEventEnvelope` facts to
//! `<tenant-prefix>.hunt.events.<agent-id>`. The control API validates the
//! tenant/agent subject binding, signs the canonicalized fact with the control
//! signing key, and persists through the same hunt ingest path used by the HTTP
//! API.

use std::sync::Arc;

use clawdstrike_ocsf::fleet::{FleetEventEnvelope, FleetEventPrincipal};
use serde_json::Value;
use sqlx::row::Row;
use tokio::sync::watch;
use uuid::Uuid;

use crate::db::PgPool;
use crate::error::ApiError;
use crate::services::consumer_ack::{acknowledge_after_processing, ProcessingError};
use crate::services::hunt;

pub struct HuntEventConsumerConfig {
    pub subject_filter: String,
    pub stream_subjects: Vec<String>,
    pub stream_name: String,
    pub consumer_name: String,
}

/// Run the hunt-event consumer loop until the shutdown receiver signals.
pub async fn run(
    nats: async_nats::Client,
    db: PgPool,
    signing_keypair: Arc<hush_core::Keypair>,
    config: HuntEventConsumerConfig,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let js = async_nats::jetstream::new(nats);

    if let Err(err) = spine::nats_transport::ensure_stream(
        &js,
        &config.stream_name,
        config.stream_subjects.clone(),
        1,
    )
    .await
    {
        tracing::error!(error = %err, "Failed to ensure hunt-event stream");
        return;
    }

    let consumer = match js
        .create_consumer_on_stream(
            async_nats::jetstream::consumer::pull::Config {
                durable_name: Some(config.consumer_name.clone()),
                filter_subject: config.subject_filter.clone(),
                ..Default::default()
            },
            &config.stream_name,
        )
        .await
    {
        Ok(consumer) => consumer,
        Err(err) => {
            tracing::error!(error = %err, "Failed to create hunt-event consumer");
            return;
        }
    };

    tracing::info!(
        subject = %config.subject_filter,
        stream = %config.stream_name,
        consumer = %config.consumer_name,
        "Hunt-event consumer started"
    );

    loop {
        let messages = match consumer.fetch().max_messages(20).messages().await {
            Ok(messages) => messages,
            Err(err) => {
                tracing::warn!(error = %err, "Failed to fetch hunt-event messages");
                if *shutdown_rx.borrow() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
        };

        use futures::StreamExt;
        let mut messages = std::pin::pin!(messages);

        loop {
            tokio::select! {
                msg = messages.next() => {
                    let msg = match msg {
                        Some(Ok(msg)) => msg,
                        Some(Err(err)) => {
                            tracing::warn!(error = %err, "Error reading hunt-event message");
                            continue;
                        }
                        None => break,
                    };

                    acknowledge_after_processing(
                        &msg,
                        process_hunt_event_payload(
                            &db,
                            signing_keypair.as_ref(),
                            msg.subject.as_str(),
                            &msg.payload,
                        )
                        .await
                        .map(|_| ()),
                        "hunt event",
                    )
                    .await;
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        tracing::info!("Hunt-event consumer shutting down");
                        return;
                    }
                }
            }
        }

        if *shutdown_rx.borrow() {
            break;
        }
    }

    tracing::info!("Hunt-event consumer stopped");
}

pub(crate) async fn process_hunt_event_payload(
    db: &PgPool,
    signing_keypair: &hush_core::Keypair,
    subject: &str,
    payload: &[u8],
) -> Result<hunt_query::service::HuntEvent, ProcessingError> {
    let (tenant_slug, subject_agent_id) = parse_hunt_event_subject(subject).ok_or_else(|| {
        ProcessingError::permanent(format!(
            "subject does not match hunt event pattern: {subject}"
        ))
    })?;
    let event: FleetEventEnvelope = serde_json::from_slice(payload)
        .map_err(|err| ProcessingError::permanent(format!("invalid hunt event JSON: {err}")))?;
    let agent_binding = resolve_agent_binding(db, tenant_slug, subject_agent_id).await?;
    let event = canonicalize_agent_event(event, &agent_binding, subject_agent_id)?;
    let (event, raw_envelope) = sign_hunt_event(signing_keypair, event)?;

    hunt::ingest_event(
        db,
        agent_binding.tenant_id,
        event,
        raw_envelope,
        Some(signing_keypair),
    )
    .await
    .map_err(api_error_to_processing_error)
}

struct AgentBinding {
    tenant_id: Uuid,
    principal_id: Option<Uuid>,
}

async fn resolve_agent_binding(
    db: &PgPool,
    tenant_slug: &str,
    agent_id: &str,
) -> Result<AgentBinding, ProcessingError> {
    let row = sqlx::query::query(
        r#"SELECT a.tenant_id,
                  a.principal_id
           FROM agents AS a
           JOIN tenants AS t ON t.id = a.tenant_id
           WHERE t.slug = $1
             AND a.agent_id = $2
             AND a.status IN ('active', 'stale', 'dead')"#,
    )
    .bind(tenant_slug)
    .bind(agent_id)
    .fetch_optional(db)
    .await
    .map_err(|err| ProcessingError::retryable(err.to_string()))?;

    let row = row.ok_or_else(|| {
        ProcessingError::permanent(format!(
            "hunt event subject did not match an enrolled agent: tenant={tenant_slug} agent={agent_id}"
        ))
    })?;
    Ok(AgentBinding {
        tenant_id: row
            .try_get("tenant_id")
            .map_err(|err| ProcessingError::retryable(err.to_string()))?,
        principal_id: row
            .try_get("principal_id")
            .map_err(|err| ProcessingError::retryable(err.to_string()))?,
    })
}

fn canonicalize_agent_event(
    mut event: FleetEventEnvelope,
    binding: &AgentBinding,
    subject_agent_id: &str,
) -> Result<FleetEventEnvelope, ProcessingError> {
    let event_tenant_id = Uuid::parse_str(&event.tenant_id)
        .map_err(|_| ProcessingError::permanent("event.tenantId must be a UUID".to_string()))?;
    if event_tenant_id != binding.tenant_id {
        return Err(ProcessingError::permanent(
            "event.tenantId does not match hunt-event subject tenant".to_string(),
        ));
    }

    let mut principal = event.principal.take().unwrap_or(FleetEventPrincipal {
        principal_id: None,
        endpoint_agent_id: None,
        runtime_agent_id: None,
        principal_type: Some("endpoint_agent".to_string()),
    });
    if let Some(endpoint_agent_id) = principal.endpoint_agent_id.as_deref() {
        if endpoint_agent_id != subject_agent_id {
            return Err(ProcessingError::permanent(
                "event principal.endpointAgentId does not match hunt-event subject agent"
                    .to_string(),
            ));
        }
    } else {
        principal.endpoint_agent_id = Some(subject_agent_id.to_string());
    }
    if principal.principal_id.is_none() {
        principal.principal_id = binding.principal_id.map(|id| id.to_string());
    }
    if principal.principal_type.is_none() {
        principal.principal_type = Some("endpoint_agent".to_string());
    }
    event.principal = Some(principal);
    Ok(event)
}

fn sign_hunt_event(
    signing_keypair: &hush_core::Keypair,
    mut event: FleetEventEnvelope,
) -> Result<(FleetEventEnvelope, Value), ProcessingError> {
    let event_value = serde_json::to_value(&event)
        .map_err(|err| ProcessingError::retryable(format!("serialize hunt event: {err}")))?;
    let issuer_probe =
        spine::build_signed_envelope(signing_keypair, 0, None, event_value, spine::now_rfc3339())
            .map_err(|err| ProcessingError::retryable(format!("sign hunt event probe: {err}")))?;
    let issuer = issuer_probe
        .get("issuer")
        .and_then(Value::as_str)
        .ok_or_else(|| ProcessingError::retryable("signed hunt event missing issuer"))?
        .to_string();

    event.evidence.issuer = Some(issuer);
    event.evidence.signature_valid = Some(true);
    let event_value = serde_json::to_value(&event).map_err(|err| {
        ProcessingError::retryable(format!("serialize canonical hunt event: {err}"))
    })?;
    let raw_envelope =
        spine::build_signed_envelope(signing_keypair, 0, None, event_value, spine::now_rfc3339())
            .map_err(|err| ProcessingError::retryable(format!("sign hunt event: {err}")))?;
    Ok((event, raw_envelope))
}

fn api_error_to_processing_error(err: ApiError) -> ProcessingError {
    match err {
        ApiError::BadRequest(message) | ApiError::Conflict(message) => {
            ProcessingError::permanent(message)
        }
        ApiError::Forbidden | ApiError::Unauthorized | ApiError::NotFound => {
            ProcessingError::permanent(err.to_string())
        }
        ApiError::Database(err) => ProcessingError::retryable(err.to_string()),
        ApiError::Nats(message) | ApiError::Internal(message) => {
            ProcessingError::retryable(message)
        }
        ApiError::AgentLimitReached
        | ApiError::InvalidPublicKey
        | ApiError::InvalidSignature
        | ApiError::PlanUpgradeRequired(_) => ProcessingError::permanent(err.to_string()),
    }
}

fn parse_hunt_event_subject(subject: &str) -> Option<(&str, &str)> {
    let (tenant_prefix, agent_id) = subject.rsplit_once(".hunt.events.")?;
    let tenant_slug = tenant_prefix
        .strip_prefix("tenant-")?
        .strip_suffix(".clawdstrike")?;
    if tenant_slug.is_empty() || agent_id.is_empty() {
        return None;
    }
    Some((tenant_slug, agent_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clawdstrike_ocsf::fleet::{
        FleetEventEvidence, FleetEventKind, FleetEventSource, FleetEventTarget,
    };

    #[test]
    fn parses_hunt_event_subject() {
        assert_eq!(
            parse_hunt_event_subject("tenant-acme.clawdstrike.hunt.events.agent-1"),
            Some(("acme", "agent-1"))
        );
        assert_eq!(
            parse_hunt_event_subject("tenant-acme.dev.clawdstrike.hunt.events.agent-1"),
            Some(("acme.dev", "agent-1"))
        );
        assert!(
            parse_hunt_event_subject("tenant-acme.clawdstrike.agent.heartbeat.agent-1").is_none()
        );
    }

    #[test]
    fn canonicalize_agent_event_rejects_subject_agent_mismatch() {
        let event = FleetEventEnvelope {
            event_id: "evt-1".to_string(),
            tenant_id: Uuid::nil().to_string(),
            source: FleetEventSource::Receipt,
            kind: FleetEventKind::GuardDecision,
            occurred_at: "2026-03-06T12:00:00Z".to_string(),
            ingested_at: "2026-03-06T12:00:01Z".to_string(),
            severity: None,
            verdict: None,
            summary: "agent secret touch".to_string(),
            action_type: Some("secret_access".to_string()),
            principal: Some(FleetEventPrincipal {
                principal_id: None,
                endpoint_agent_id: Some("other-agent".to_string()),
                runtime_agent_id: None,
                principal_type: Some("agent".to_string()),
            }),
            session_id: None,
            grant_id: None,
            response_action_id: None,
            detection_ids: vec!["agent_secret_touch".to_string()],
            target: Some(FleetEventTarget {
                kind: Some("credential".to_string()),
                id: Some("credential-1".to_string()),
                name: Some("OPENAI_API_KEY".to_string()),
            }),
            evidence: FleetEventEvidence {
                raw_ref: "endpoint-receipt:evt-1".to_string(),
                envelope_hash: None,
                issuer: None,
                schema_name: Some("clawdstrike.edr.agent_secret_touch.v1".to_string()),
                signature_valid: None,
            },
            attributes: serde_json::json!({"credentialKind": "api_token"}),
        };
        let binding = AgentBinding {
            tenant_id: Uuid::nil(),
            principal_id: Some(Uuid::nil()),
        };

        let err = canonicalize_agent_event(event, &binding, "agent-1")
            .expect_err("mismatched agent should be rejected");
        assert!(err.to_string().contains("endpointAgentId"));
    }
}
