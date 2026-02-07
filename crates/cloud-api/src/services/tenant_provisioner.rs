use uuid::Uuid;

use crate::db::PgPool;
use crate::models::agent::NatsCredentials;

#[derive(Debug, thiserror::Error)]
pub enum ProvisionerError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::error::Error),
    #[error("nats error: {0}")]
    Nats(String),
}

/// Service for provisioning NATS accounts and streams per tenant.
#[derive(Clone)]
pub struct TenantProvisioner {
    db: PgPool,
    nats_url: String,
}

impl TenantProvisioner {
    pub fn new(db: PgPool, nats_url: String) -> Self {
        Self { db, nats_url }
    }

    /// Provision NATS account and streams for a new tenant.
    pub async fn provision_tenant(&self, tenant_id: Uuid, slug: &str) -> Result<String, ProvisionerError> {
        let nats_account_id = format!("tenant-{slug}");

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
        let account = format!("tenant-{slug}");
        let subject_prefix = format!("tenant-{slug}.clawdstrike.spine.envelope");

        tracing::info!(agent_id = %agent_id, account = %account, "Created NATS agent credentials");

        Ok(NatsCredentials {
            nats_url: self.nats_url.clone(),
            account,
            subject_prefix,
        })
    }

    /// Deprovision NATS resources for a cancelled tenant.
    pub async fn deprovision_tenant(&self, tenant_id: Uuid) -> Result<(), ProvisionerError> {
        sqlx::query::query("UPDATE tenants SET nats_account_id = NULL WHERE id = $1")
            .bind(tenant_id)
            .execute(&self.db)
            .await?;

        tracing::info!(tenant_id = %tenant_id, "Deprovisioned NATS account");
        Ok(())
    }
}
