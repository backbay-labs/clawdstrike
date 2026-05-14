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
        #[serde(default)]
        expires_at: Option<DateTime<Utc>>,
        #[serde(default)]
        expires_in_secs: Option<i64>,
    },
    SlackAppSession {
        bot_token: String,
        team_id: String,
        app_id: String,
        #[serde(default)]
        expires_at: Option<DateTime<Utc>>,
        #[serde(default)]
        expires_in_secs: Option<i64>,
    },
    AwsStsSession {
        access_key_id: String,
        secret_access_key: String,
        session_token: String,
        role_arn: String,
        #[serde(default)]
        expires_at: Option<DateTime<Utc>>,
        #[serde(default)]
        expires_in_secs: Option<i64>,
    },
    GenericHttpsBearer {
        value: String,
        subject: String,
        #[serde(default)]
        expires_at: Option<DateTime<Utc>>,
        #[serde(default)]
        expires_in_secs: Option<i64>,
    },
    GenericHttpsHeader {
        header_name: String,
        value: String,
        subject: String,
        #[serde(default)]
        expires_at: Option<DateTime<Utc>>,
        #[serde(default)]
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
                metadata: BTreeMap::from([("role_arn".to_string(), role_arn.clone())]),
                subject: role_arn,
                issued_at: Utc::now(),
                expires_at: resolve_expiry(expires_at, expires_in_secs)?,
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
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::{resolve_envelope, resolve_expiry, SecretLeaseEnvelope};
    use crate::secret_provider::FileSecretProvider;
    use crate::state::AppState;
    use chrono::{Duration, Utc};
    use clawdstrike_broker_protocol::BrokerMintedIdentityKind;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    // ----------------------------------------------------------------
    // resolve_expiry
    // ----------------------------------------------------------------

    #[test]
    fn resolve_expiry_prefers_expires_at_over_expires_in() {
        let explicit = Utc::now() + Duration::hours(1);
        let result = resolve_expiry(Some(explicit), Some(999)).unwrap();
        assert_eq!(result, explicit);
    }

    #[test]
    fn resolve_expiry_falls_back_to_expires_in() {
        let before = Utc::now();
        let result = resolve_expiry(None, Some(600)).unwrap();
        assert!(result >= before + Duration::seconds(600));
    }

    #[test]
    fn resolve_expiry_clamps_expires_in_to_at_least_one() {
        let before = Utc::now();
        let result = resolve_expiry(None, Some(-999)).unwrap();
        // Should use max(1, -999) = 1
        assert!(result >= before + Duration::seconds(1));
    }

    #[test]
    fn resolve_expiry_neither_provided_errors() {
        let err = resolve_expiry(None, None).unwrap_err();
        assert_eq!(err.code, "BROKER_LEASE_FORMAT_INVALID");
    }

    // ----------------------------------------------------------------
    // resolve_envelope: Static
    // ----------------------------------------------------------------

    #[test]
    fn resolves_static_descriptor() {
        let resolved = resolve_envelope(SecretLeaseEnvelope::Static {
            value: "sk-test-123".to_string(),
        })
        .expect("resolved");

        assert_eq!(resolved.provider_secret, "sk-test-123");
        assert!(resolved.minted_identity.is_none());
        assert!(resolved.suspicion_reason.is_none());
    }

    // ----------------------------------------------------------------
    // resolve_envelope: GithubAppInstallation
    // ----------------------------------------------------------------

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
        assert_eq!(minted.metadata.get("installation_id").unwrap(), "42");
        assert_eq!(minted.metadata.get("app_id").unwrap(), "123");
    }

    #[test]
    fn github_app_with_expires_at() {
        let expires = Utc::now() + Duration::hours(1);
        let resolved = resolve_envelope(SecretLeaseEnvelope::GithubAppInstallation {
            installation_token: "ghs_test2".to_string(),
            installation_id: "99".to_string(),
            app_id: "456".to_string(),
            expires_at: Some(expires),
            expires_in_secs: None,
        })
        .expect("resolved");

        let minted = resolved.minted_identity.expect("minted identity");
        assert_eq!(minted.expires_at, expires);
    }

    #[test]
    fn github_app_without_expiry_errors() {
        let err = resolve_envelope(SecretLeaseEnvelope::GithubAppInstallation {
            installation_token: "ghs_test3".to_string(),
            installation_id: "55".to_string(),
            app_id: "789".to_string(),
            expires_at: None,
            expires_in_secs: None,
        })
        .unwrap_err();
        assert_eq!(err.code, "BROKER_LEASE_FORMAT_INVALID");
    }

    // ----------------------------------------------------------------
    // resolve_envelope: SlackAppSession
    // ----------------------------------------------------------------

    #[test]
    fn resolves_slack_app_session_descriptor() {
        let resolved = resolve_envelope(SecretLeaseEnvelope::SlackAppSession {
            bot_token: "xoxb-test".to_string(),
            team_id: "T123".to_string(),
            app_id: "A456".to_string(),
            expires_at: None,
            expires_in_secs: Some(600),
        })
        .expect("resolved");

        assert_eq!(resolved.provider_secret, "xoxb-test");
        let minted = resolved.minted_identity.expect("minted identity");
        assert_eq!(minted.kind, BrokerMintedIdentityKind::SlackAppSession);
        assert_eq!(minted.subject, "slack-team:T123");
        assert_eq!(minted.metadata.get("team_id").unwrap(), "T123");
        assert_eq!(minted.metadata.get("app_id").unwrap(), "A456");
    }

    #[test]
    fn slack_app_session_without_expiry_errors() {
        let err = resolve_envelope(SecretLeaseEnvelope::SlackAppSession {
            bot_token: "xoxb-test".to_string(),
            team_id: "T123".to_string(),
            app_id: "A456".to_string(),
            expires_at: None,
            expires_in_secs: None,
        })
        .unwrap_err();
        assert_eq!(err.code, "BROKER_LEASE_FORMAT_INVALID");
    }

    // ----------------------------------------------------------------
    // resolve_envelope: AwsStsSession
    // ----------------------------------------------------------------

    #[test]
    fn resolves_aws_sts_session_descriptor() {
        let resolved = resolve_envelope(SecretLeaseEnvelope::AwsStsSession {
            access_key_id: "AKIA123".to_string(),
            secret_access_key: "secret456".to_string(),
            session_token: "token789".to_string(),
            role_arn: "arn:aws:iam::123456:role/test".to_string(),
            expires_at: None,
            expires_in_secs: Some(3600),
        })
        .expect("resolved");

        let parsed: serde_json::Value =
            serde_json::from_str(&resolved.provider_secret).expect("valid JSON");
        assert_eq!(parsed["type"], "header");
        assert_eq!(parsed["header_name"], "x-clawdstrike-aws-sts-session");

        let minted = resolved.minted_identity.expect("minted identity");
        assert_eq!(minted.kind, BrokerMintedIdentityKind::AwsStsSession);
        assert_eq!(minted.subject, "arn:aws:iam::123456:role/test");
        assert_eq!(
            minted.metadata.get("role_arn").unwrap(),
            "arn:aws:iam::123456:role/test"
        );
    }

    #[test]
    fn aws_sts_session_provider_secret_embeds_credentials() {
        let resolved = resolve_envelope(SecretLeaseEnvelope::AwsStsSession {
            access_key_id: "AKIA_AK".to_string(),
            secret_access_key: "SAK".to_string(),
            session_token: "ST".to_string(),
            role_arn: "arn:aws:iam::111:role/r".to_string(),
            expires_at: None,
            expires_in_secs: Some(100),
        })
        .expect("resolved");

        let outer: serde_json::Value = serde_json::from_str(&resolved.provider_secret).unwrap();
        let inner: serde_json::Value =
            serde_json::from_str(outer["value"].as_str().unwrap()).unwrap();
        assert_eq!(inner["access_key_id"], "AKIA_AK");
        assert_eq!(inner["secret_access_key"], "SAK");
        assert_eq!(inner["session_token"], "ST");
        assert_eq!(inner["role_arn"], "arn:aws:iam::111:role/r");
    }

    #[test]
    fn aws_sts_session_without_expiry_errors() {
        let err = resolve_envelope(SecretLeaseEnvelope::AwsStsSession {
            access_key_id: "AKIA".to_string(),
            secret_access_key: "s".to_string(),
            session_token: "t".to_string(),
            role_arn: "arn:aws:iam::1:role/r".to_string(),
            expires_at: None,
            expires_in_secs: None,
        })
        .unwrap_err();
        assert_eq!(err.code, "BROKER_LEASE_FORMAT_INVALID");
    }

    // ----------------------------------------------------------------
    // resolve_envelope: GenericHttpsBearer
    // ----------------------------------------------------------------

    #[test]
    fn resolves_generic_https_bearer_descriptor() {
        let resolved = resolve_envelope(SecretLeaseEnvelope::GenericHttpsBearer {
            value: "token-abc".to_string(),
            subject: "service-account@example.com".to_string(),
            expires_at: None,
            expires_in_secs: Some(120),
        })
        .expect("resolved");

        let parsed: serde_json::Value =
            serde_json::from_str(&resolved.provider_secret).expect("valid JSON");
        assert_eq!(parsed["type"], "bearer");
        assert_eq!(parsed["value"], "token-abc");

        let minted = resolved.minted_identity.expect("minted identity");
        assert_eq!(minted.kind, BrokerMintedIdentityKind::Static);
        assert_eq!(minted.subject, "service-account@example.com");
        assert!(minted.metadata.is_empty());
    }

    #[test]
    fn generic_https_bearer_without_expiry_errors() {
        let err = resolve_envelope(SecretLeaseEnvelope::GenericHttpsBearer {
            value: "tok".to_string(),
            subject: "sub".to_string(),
            expires_at: None,
            expires_in_secs: None,
        })
        .unwrap_err();
        assert_eq!(err.code, "BROKER_LEASE_FORMAT_INVALID");
    }

    // ----------------------------------------------------------------
    // resolve_envelope: GenericHttpsHeader
    // ----------------------------------------------------------------

    #[test]
    fn resolves_generic_https_header_descriptor() {
        let resolved = resolve_envelope(SecretLeaseEnvelope::GenericHttpsHeader {
            header_name: "x-api-key".to_string(),
            value: "key-xyz".to_string(),
            subject: "api-consumer".to_string(),
            expires_at: None,
            expires_in_secs: Some(180),
        })
        .expect("resolved");

        let parsed: serde_json::Value =
            serde_json::from_str(&resolved.provider_secret).expect("valid JSON");
        assert_eq!(parsed["type"], "header");
        assert_eq!(parsed["header_name"], "x-api-key");
        assert_eq!(parsed["value"], "key-xyz");

        let minted = resolved.minted_identity.expect("minted identity");
        assert_eq!(minted.kind, BrokerMintedIdentityKind::Static);
        assert_eq!(minted.subject, "api-consumer");
        assert!(minted.metadata.is_empty());
    }

    #[test]
    fn generic_https_header_without_expiry_errors() {
        let err = resolve_envelope(SecretLeaseEnvelope::GenericHttpsHeader {
            header_name: "x-api-key".to_string(),
            value: "k".to_string(),
            subject: "s".to_string(),
            expires_at: None,
            expires_in_secs: None,
        })
        .unwrap_err();
        assert_eq!(err.code, "BROKER_LEASE_FORMAT_INVALID");
    }

    // ----------------------------------------------------------------
    // resolve_envelope: Tripwire
    // ----------------------------------------------------------------

    #[test]
    fn resolves_tripwire_descriptor() {
        let resolved = resolve_envelope(SecretLeaseEnvelope::Tripwire {
            reason: "honeypot touched".to_string(),
        })
        .expect("resolved");
        assert!(resolved.provider_secret.is_empty());
        assert!(resolved.minted_identity.is_none());
        assert_eq!(
            resolved.suspicion_reason.as_deref(),
            Some("honeypot touched")
        );
    }

    // ----------------------------------------------------------------
    // SecretLeaseEnvelope deserialization round-trips
    // ----------------------------------------------------------------

    #[test]
    fn static_envelope_deserializes() {
        let json = r#"{"type":"static","value":"sk-123"}"#;
        let envelope: SecretLeaseEnvelope = serde_json::from_str(json).expect("deser");
        let resolved = resolve_envelope(envelope).expect("resolved");
        assert_eq!(resolved.provider_secret, "sk-123");
    }

    #[test]
    fn github_envelope_deserializes() {
        let json = serde_json::json!({
            "type": "github_app_installation",
            "installation_token": "ghs_abc",
            "installation_id": "1",
            "app_id": "2",
            "expires_in_secs": 60
        });
        let envelope: SecretLeaseEnvelope = serde_json::from_value(json).expect("deser");
        let resolved = resolve_envelope(envelope).expect("resolved");
        assert_eq!(resolved.provider_secret, "ghs_abc");
    }

    #[test]
    fn slack_envelope_deserializes() {
        let json = serde_json::json!({
            "type": "slack_app_session",
            "bot_token": "xoxb-test",
            "team_id": "T1",
            "app_id": "A1",
            "expires_in_secs": 60
        });
        let envelope: SecretLeaseEnvelope = serde_json::from_value(json).expect("deser");
        let resolved = resolve_envelope(envelope).expect("resolved");
        assert_eq!(resolved.provider_secret, "xoxb-test");
    }

    #[test]
    fn aws_sts_envelope_deserializes() {
        let json = serde_json::json!({
            "type": "aws_sts_session",
            "access_key_id": "AKIA",
            "secret_access_key": "SAK",
            "session_token": "ST",
            "role_arn": "arn:aws:iam::1:role/r",
            "expires_in_secs": 60
        });
        let envelope: SecretLeaseEnvelope = serde_json::from_value(json).expect("deser");
        let resolved = resolve_envelope(envelope).expect("resolved");
        let parsed: serde_json::Value = serde_json::from_str(&resolved.provider_secret).unwrap();
        assert_eq!(parsed["type"], "header");
    }

    #[test]
    fn tripwire_envelope_deserializes() {
        let json = r#"{"type":"tripwire","reason":"canary"}"#;
        let envelope: SecretLeaseEnvelope = serde_json::from_str(json).expect("deser");
        let resolved = resolve_envelope(envelope).expect("resolved");
        assert_eq!(resolved.suspicion_reason.as_deref(), Some("canary"));
    }

    // ----------------------------------------------------------------
    // resolve_execution_credential (async, uses AppState)
    // ----------------------------------------------------------------

    fn make_test_state(secrets: BTreeMap<String, String>) -> AppState {
        use crate::config::{Config, SecretBackendConfig};
        use crate::operator::OperatorState;
        use hush_core::Keypair;

        let keypair = Keypair::generate();
        let config = Config {
            listen: "127.0.0.1:9889".to_string(),
            hushd_base_url: "http://127.0.0.1:9876".to_string(),
            hushd_token: None,
            secret_backend: SecretBackendConfig::Env {
                prefix: "TEST_".to_string(),
            },
            trusted_hushd_public_keys: vec![keypair.public_key()],
            request_timeout_secs: 5,
            binding_proof_ttl_secs: 60,
            allow_http_loopback: false,
            allow_private_upstream_hosts: false,
            allow_invalid_upstream_tls: false,
            admin_token: None,
        };
        let provider = Arc::new(FileSecretProvider::new(secrets));
        AppState {
            config: Arc::new(config),
            secret_provider: provider,
            operator_state: OperatorState::default(),
            hushd_client: reqwest::Client::new(),
            upstream_client: reqwest::Client::new(),
        }
    }

    #[tokio::test]
    async fn resolve_execution_credential_raw_string() {
        let secrets = BTreeMap::from([("openai/dev".to_string(), "sk-raw-key".to_string())]);
        let state = make_test_state(secrets);
        let result = super::resolve_execution_credential(&state, "openai/dev")
            .await
            .expect("resolved");
        assert_eq!(result.provider_secret, "sk-raw-key");
        assert!(result.minted_identity.is_none());
        assert!(result.suspicion_reason.is_none());
    }

    #[tokio::test]
    async fn resolve_execution_credential_json_envelope() {
        let envelope = serde_json::json!({
            "type": "static",
            "value": "sk-json-key"
        });
        let secrets = BTreeMap::from([("openai/prod".to_string(), envelope.to_string())]);
        let state = make_test_state(secrets);
        let result = super::resolve_execution_credential(&state, "openai/prod")
            .await
            .expect("resolved");
        assert_eq!(result.provider_secret, "sk-json-key");
    }

    #[tokio::test]
    async fn resolve_execution_credential_unknown_ref_errors() {
        let state = make_test_state(BTreeMap::new());
        let err = super::resolve_execution_credential(&state, "nonexistent")
            .await
            .unwrap_err();
        assert_eq!(err.code, "BROKER_SECRET_REF_UNKNOWN");
    }

    #[tokio::test]
    async fn resolve_execution_credential_tripwire() {
        let envelope = serde_json::json!({
            "type": "tripwire",
            "reason": "alert: canary secret accessed"
        });
        let secrets = BTreeMap::from([("trap/canary".to_string(), envelope.to_string())]);
        let state = make_test_state(secrets);
        let result = super::resolve_execution_credential(&state, "trap/canary")
            .await
            .expect("resolved");
        assert!(result.provider_secret.is_empty());
        assert_eq!(
            result.suspicion_reason.as_deref(),
            Some("alert: canary secret accessed")
        );
    }

    #[tokio::test]
    async fn resolve_execution_credential_github_envelope() {
        let envelope = serde_json::json!({
            "type": "github_app_installation",
            "installation_token": "ghs_async_test",
            "installation_id": "100",
            "app_id": "200",
            "expires_in_secs": 300
        });
        let secrets = BTreeMap::from([("github/install".to_string(), envelope.to_string())]);
        let state = make_test_state(secrets);
        let result = super::resolve_execution_credential(&state, "github/install")
            .await
            .expect("resolved");
        assert_eq!(result.provider_secret, "ghs_async_test");
        let minted = result.minted_identity.expect("minted");
        assert_eq!(minted.kind, BrokerMintedIdentityKind::GithubAppInstallation);
        assert_eq!(minted.subject, "github-installation:100");
    }
}
