use uuid::Uuid;

use crate::db::PgPool;
use crate::models::agent::NatsCredentials;

/// Build the canonical tenant-scoped NATS subject prefix.
pub fn tenant_subject_prefix(slug: &str) -> String {
    format!("tenant-{slug}.clawdstrike")
}

#[derive(Debug, thiserror::Error)]
pub enum ProvisionerError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::error::Error),
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("nats error: {0}")]
    Nats(String),
}

#[derive(Clone)]
enum ProvisioningBackend {
    /// Production mode: delegate account/user/ACL lifecycle to an external
    /// provisioning control-plane that has NATS admin privileges.
    External {
        base_url: String,
        api_token: Option<String>,
        http_client: reqwest::Client,
    },
    /// External provisioning mode was selected but no control-plane endpoint
    /// is configured. Startup should still succeed for non-enrollment workloads.
    ExternalUnconfigured,
    /// Explicitly insecure mode for local/dev only.
    Mock,
}

/// Service for provisioning NATS accounts and streams per tenant.
#[derive(Clone)]
pub struct TenantProvisioner {
    db: PgPool,
    nats_url: String,
    backend: ProvisioningBackend,
}

impl TenantProvisioner {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        db: PgPool,
        nats_url: String,
        provisioning_mode: &str,
        external_base_url: Option<String>,
        external_api_token: Option<String>,
        allow_insecure_mock: bool,
    ) -> Result<Self, ProvisionerError> {
        let backend = match provisioning_mode.trim().to_ascii_lowercase().as_str() {
            "external" => {
                if let Some(base_url) = external_base_url
                    .as_deref()
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                {
                    ProvisioningBackend::External {
                        base_url: base_url.trim_end_matches('/').to_string(),
                        api_token: external_api_token,
                        http_client: reqwest::Client::new(),
                    }
                } else {
                    tracing::warn!(
                        "NATS_PROVISIONING_MODE=external but NATS_PROVISIONER_BASE_URL is unset; \
                         tenant provisioning operations will fail until configured"
                    );
                    ProvisioningBackend::ExternalUnconfigured
                }
            }
            "mock" => {
                if !allow_insecure_mock {
                    return Err(ProvisionerError::Nats(
                        "NATS_PROVISIONING_MODE=mock requires NATS_ALLOW_INSECURE_MOCK_PROVISIONER=true"
                            .to_string(),
                    ));
                }
                tracing::warn!(
                    "Using insecure mock NATS provisioner mode; tenant isolation is not enforced in NATS"
                );
                ProvisioningBackend::Mock
            }
            other => {
                return Err(ProvisionerError::Nats(format!(
                    "Unsupported NATS provisioning mode '{other}'"
                )));
            }
        };

        Ok(Self {
            db,
            nats_url,
            backend,
        })
    }

    /// Provision NATS account and streams for a new tenant.
    pub async fn provision_tenant(
        &self,
        tenant_id: Uuid,
        slug: &str,
    ) -> Result<String, ProvisionerError> {
        let nats_account_id = match &self.backend {
            ProvisioningBackend::External { .. } => {
                self.provision_tenant_external(tenant_id, slug).await?
            }
            ProvisioningBackend::ExternalUnconfigured => {
                return Err(ProvisionerError::Nats(
                    "NATS provisioning is not configured: set NATS_PROVISIONER_BASE_URL \
                     for NATS_PROVISIONING_MODE=external"
                        .to_string(),
                ));
            }
            ProvisioningBackend::Mock => format!("tenant-{slug}"),
        };

        sqlx::query::query("UPDATE tenants SET nats_account_id = $1 WHERE id = $2")
            .bind(&nats_account_id)
            .bind(tenant_id)
            .execute(&self.db)
            .await?;

        tracing::info!(tenant_id = %tenant_id, account = %nats_account_id, "Provisioned NATS account");
        Ok(nats_account_id)
    }

    /// Create NATS credentials for a specific agent within a tenant.
    pub async fn create_agent_credentials(
        &self,
        _tenant_id: Uuid,
        slug: &str,
        agent_id: &str,
    ) -> Result<NatsCredentials, ProvisionerError> {
        let subject_prefix = tenant_subject_prefix(slug);
        let (account, token, returned_prefix) = match &self.backend {
            ProvisioningBackend::External { .. } => {
                self.issue_agent_credentials_external(slug, agent_id, &subject_prefix)
                    .await?
            }
            ProvisioningBackend::ExternalUnconfigured => {
                return Err(ProvisionerError::Nats(
                    "NATS provisioning is not configured: set NATS_PROVISIONER_BASE_URL \
                     for NATS_PROVISIONING_MODE=external"
                        .to_string(),
                ));
            }
            ProvisioningBackend::Mock => (
                format!("tenant-{slug}"),
                format!("nats-{}-{}", slug, Uuid::new_v4()),
                Some(subject_prefix.clone()),
            ),
        };
        let subject_prefix = returned_prefix.unwrap_or(subject_prefix);

        tracing::info!(agent_id = %agent_id, account = %account, "Created NATS agent credentials");

        Ok(NatsCredentials {
            nats_url: self.nats_url.clone(),
            account,
            subject_prefix,
            token,
        })
    }

    /// Deprovision NATS resources for a cancelled tenant.
    pub async fn deprovision_tenant(&self, tenant_id: Uuid) -> Result<(), ProvisionerError> {
        if let ProvisioningBackend::External { .. } = &self.backend {
            self.deprovision_tenant_external(tenant_id).await?;
        }
        if let ProvisioningBackend::ExternalUnconfigured = &self.backend {
            return Err(ProvisionerError::Nats(
                "NATS provisioning is not configured: set NATS_PROVISIONER_BASE_URL \
                 for NATS_PROVISIONING_MODE=external"
                    .to_string(),
            ));
        }

        sqlx::query::query("UPDATE tenants SET nats_account_id = NULL WHERE id = $1")
            .bind(tenant_id)
            .execute(&self.db)
            .await?;

        tracing::info!(tenant_id = %tenant_id, "Deprovisioned NATS account");
        Ok(())
    }

    async fn provision_tenant_external(
        &self,
        tenant_id: Uuid,
        slug: &str,
    ) -> Result<String, ProvisionerError> {
        let request = serde_json::json!({
            "tenant_id": tenant_id,
            "slug": slug,
            "subject_prefix": tenant_subject_prefix(slug),
        });
        let response: ExternalProvisionTenantResponse = self
            .post_external("/v1/tenants/provision", &request)
            .await?;
        if response.account_id.trim().is_empty() {
            return Err(ProvisionerError::Nats(
                "external provisioner returned empty account_id".to_string(),
            ));
        }
        Ok(response.account_id)
    }

    async fn issue_agent_credentials_external(
        &self,
        slug: &str,
        agent_id: &str,
        subject_prefix: &str,
    ) -> Result<(String, String, Option<String>), ProvisionerError> {
        let request = serde_json::json!({
            "slug": slug,
            "agent_id": agent_id,
            "subject_prefix": subject_prefix,
        });
        let response: ExternalIssueAgentCredentialsResponse = self
            .post_external("/v1/agents/credentials", &request)
            .await?;
        if response.account_id.trim().is_empty() {
            return Err(ProvisionerError::Nats(
                "external provisioner returned empty account_id".to_string(),
            ));
        }
        if response.token.trim().is_empty() {
            return Err(ProvisionerError::Nats(
                "external provisioner returned empty token".to_string(),
            ));
        }

        Ok((response.account_id, response.token, response.subject_prefix))
    }

    async fn deprovision_tenant_external(&self, tenant_id: Uuid) -> Result<(), ProvisionerError> {
        let request = serde_json::json!({
            "tenant_id": tenant_id,
        });
        let _: serde_json::Value = self
            .post_external("/v1/tenants/deprovision", &request)
            .await?;
        Ok(())
    }

    async fn post_external<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        payload: &serde_json::Value,
    ) -> Result<T, ProvisionerError> {
        let ProvisioningBackend::External {
            base_url,
            api_token,
            http_client,
        } = &self.backend
        else {
            return Err(ProvisionerError::Nats(
                "external provisioner is not configured".to_string(),
            ));
        };

        let mut request = http_client.post(format!("{base_url}{path}")).json(payload);
        if let Some(token) = api_token
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            request = request.bearer_auth(token);
        }

        let response = request.send().await?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(ProvisionerError::Nats(format!(
                "external provisioner {path} failed with {status}: {body}"
            )));
        }

        response.json::<T>().await.map_err(ProvisionerError::Http)
    }
}

#[derive(Debug, serde::Deserialize)]
struct ExternalProvisionTenantResponse {
    account_id: String,
}

#[derive(Debug, serde::Deserialize)]
struct ExternalIssueAgentCredentialsResponse {
    account_id: String,
    token: String,
    #[serde(default)]
    subject_prefix: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_subject_prefix_contract() {
        assert_eq!(tenant_subject_prefix("acme"), "tenant-acme.clawdstrike");
        assert_eq!(
            tenant_subject_prefix("north-america-prod"),
            "tenant-north-america-prod.clawdstrike"
        );
    }
}
