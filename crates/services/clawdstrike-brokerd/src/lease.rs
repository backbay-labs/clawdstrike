use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use clawdstrike_broker_protocol::{BrokerMintedIdentity, BrokerMintedIdentityKind};
use serde::Deserialize;

use crate::api::ApiError;
use crate::state::AppState;

#[derive(Clone, Debug)]
pub struct ResolvedExecutionCredential {
    pub provider_secret: String,
    pub minted_identity: Option<BrokerMintedIdentity>,
    pub suspicion_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum SecretLeaseEnvelope {
    Static {
        value: String,
    },
    GithubAppInstallation {
        installation_token: String,
        installation_id: String,
        app_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expires_at: Option<DateTime<Utc>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expires_in_secs: Option<i64>,
    },
    SlackAppSession {
        bot_token: String,
        team_id: String,
        app_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expires_at: Option<DateTime<Utc>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expires_in_secs: Option<i64>,
    },
    AwsStsSession {
        access_key_id: String,
        secret_access_key: String,
        session_token: String,
        role_arn: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expires_at: Option<DateTime<Utc>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expires_in_secs: Option<i64>,
    },
    GenericHttpsBearer {
        value: String,
        subject: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expires_at: Option<DateTime<Utc>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expires_in_secs: Option<i64>,
    },
    GenericHttpsHeader {
        header_name: String,
        value: String,
        subject: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expires_at: Option<DateTime<Utc>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expires_in_secs: Option<i64>,
    },
    Tripwire {
        reason: String,
    },
}

pub async fn resolve_execution_credential(
    state: &AppState,
    secret_ref_id: &str,
) -> Result<ResolvedExecutionCredential, ApiError> {
    let raw_secret = state
        .secret_provider
        .resolve(secret_ref_id)
        .await
        .ok_or_else(|| {
            ApiError::forbidden(
                "BROKER_SECRET_REF_UNKNOWN",
                "secret reference is not available in the configured broker backend",
            )
        })?;

    if let Ok(envelope) = serde_json::from_str::<SecretLeaseEnvelope>(&raw_secret) {
        return resolve_envelope(envelope);
    }

    Ok(ResolvedExecutionCredential {
        provider_secret: raw_secret,
        minted_identity: None,
        suspicion_reason: None,
    })
}

fn resolve_envelope(
    envelope: SecretLeaseEnvelope,
) -> Result<ResolvedExecutionCredential, ApiError> {
    match envelope {
        SecretLeaseEnvelope::Static { value } => Ok(ResolvedExecutionCredential {
            provider_secret: value,
            minted_identity: None,
            suspicion_reason: None,
        }),
        SecretLeaseEnvelope::GithubAppInstallation {
            installation_token,
            installation_id,
            app_id,
            expires_at,
            expires_in_secs,
        } => Ok(ResolvedExecutionCredential {
            provider_secret: installation_token,
            minted_identity: Some(BrokerMintedIdentity {
                kind: BrokerMintedIdentityKind::GithubAppInstallation,
                subject: format!("github-installation:{installation_id}"),
                issued_at: Utc::now(),
                expires_at: resolve_expiry(expires_at, expires_in_secs)?,
                metadata: BTreeMap::from([
                    ("installation_id".to_string(), installation_id),
                    ("app_id".to_string(), app_id),
                ]),
            }),
            suspicion_reason: None,
        }),
        SecretLeaseEnvelope::SlackAppSession {
            bot_token,
            team_id,
            app_id,
            expires_at,
            expires_in_secs,
        } => Ok(ResolvedExecutionCredential {
            provider_secret: bot_token,
            minted_identity: Some(BrokerMintedIdentity {
                kind: BrokerMintedIdentityKind::SlackAppSession,
                subject: format!("slack-team:{team_id}"),
                issued_at: Utc::now(),
                expires_at: resolve_expiry(expires_at, expires_in_secs)?,
                metadata: BTreeMap::from([
                    ("team_id".to_string(), team_id),
                    ("app_id".to_string(), app_id),
                ]),
            }),
            suspicion_reason: None,
        }),
        SecretLeaseEnvelope::AwsStsSession {
            access_key_id,
            secret_access_key,
            session_token,
            role_arn,
            expires_at,
            expires_in_secs,
        } => Ok(ResolvedExecutionCredential {
            provider_secret: serde_json::json!({
                "type": "header",
                "header_name": "x-clawdstrike-aws-sts-session",
                "value": serde_json::json!({
                    "access_key_id": access_key_id,
                    "secret_access_key": secret_access_key,
                    "session_token": session_token,
                    "role_arn": role_arn,
                })
                .to_string(),
            })
            .to_string(),
            minted_identity: Some(BrokerMintedIdentity {
                kind: BrokerMintedIdentityKind::AwsStsSession,
                subject: role_arn.clone(),
                issued_at: Utc::now(),
                expires_at: resolve_expiry(expires_at, expires_in_secs)?,
                metadata: BTreeMap::from([("role_arn".to_string(), role_arn)]),
            }),
            suspicion_reason: None,
        }),
        SecretLeaseEnvelope::GenericHttpsBearer {
            value,
            subject,
            expires_at,
            expires_in_secs,
        } => Ok(ResolvedExecutionCredential {
            provider_secret: serde_json::json!({
                "type": "bearer",
                "value": value,
            })
            .to_string(),
            minted_identity: Some(BrokerMintedIdentity {
                kind: BrokerMintedIdentityKind::Static,
                subject,
                issued_at: Utc::now(),
                expires_at: resolve_expiry(expires_at, expires_in_secs)?,
                metadata: BTreeMap::new(),
            }),
            suspicion_reason: None,
        }),
        SecretLeaseEnvelope::GenericHttpsHeader {
            header_name,
            value,
            subject,
            expires_at,
            expires_in_secs,
        } => Ok(ResolvedExecutionCredential {
            provider_secret: serde_json::json!({
                "type": "header",
                "header_name": header_name,
                "value": value,
            })
            .to_string(),
            minted_identity: Some(BrokerMintedIdentity {
                kind: BrokerMintedIdentityKind::Static,
                subject,
                issued_at: Utc::now(),
                expires_at: resolve_expiry(expires_at, expires_in_secs)?,
                metadata: BTreeMap::new(),
            }),
            suspicion_reason: None,
        }),
        SecretLeaseEnvelope::Tripwire { reason } => Ok(ResolvedExecutionCredential {
            provider_secret: String::new(),
            minted_identity: None,
            suspicion_reason: Some(reason),
        }),
    }
}

fn resolve_expiry(
    expires_at: Option<DateTime<Utc>>,
    expires_in_secs: Option<i64>,
) -> Result<DateTime<Utc>, ApiError> {
    if let Some(expires_at) = expires_at {
        return Ok(expires_at);
    }
    if let Some(expires_in_secs) = expires_in_secs {
        return Ok(Utc::now() + Duration::seconds(expires_in_secs.max(1)));
    }
    Err(ApiError::internal(
        "BROKER_LEASE_FORMAT_INVALID",
        "minted identity descriptors must provide expires_at or expires_in_secs",
    ))
}

#[cfg(test)]
mod tests {
    use super::{resolve_envelope, SecretLeaseEnvelope};
    use clawdstrike_broker_protocol::BrokerMintedIdentityKind;

    #[test]
    fn resolves_github_app_installation_descriptor() {
        let resolved = resolve_envelope(SecretLeaseEnvelope::GithubAppInstallation {
            installation_token: "ghs_test".to_string(),
            installation_id: "42".to_string(),
            app_id: "123".to_string(),
            expires_at: None,
            expires_in_secs: Some(300),
        })
        .expect("resolved");

        assert_eq!(resolved.provider_secret, "ghs_test");
        let minted = resolved.minted_identity.expect("minted identity");
        assert_eq!(minted.kind, BrokerMintedIdentityKind::GithubAppInstallation);
        assert_eq!(minted.subject, "github-installation:42");
    }

    #[test]
    fn resolves_tripwire_descriptor() {
        let resolved = resolve_envelope(SecretLeaseEnvelope::Tripwire {
            reason: "honeypot touched".to_string(),
        })
        .expect("resolved");
        assert!(resolved.provider_secret.is_empty());
        assert_eq!(
            resolved.suspicion_reason.as_deref(),
            Some("honeypot touched")
        );
    }
}
