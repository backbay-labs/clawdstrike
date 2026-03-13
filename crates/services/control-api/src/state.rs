use std::sync::Arc;

use crate::config::Config;
use crate::db::PgPool;
use crate::routes::receipts::ReceiptStore;
use crate::services::alerter::AlerterService;
use crate::services::catalog::CatalogStore;
use crate::services::metering::MeteringService;
use crate::services::retention::RetentionService;
use crate::services::tenant_provisioner::TenantProvisioner;

/// Shared application state passed to all route handlers.
#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub db: PgPool,
    pub nats: async_nats::Client,
    pub provisioner: TenantProvisioner,
    pub metering: MeteringService,
    pub alerter: AlerterService,
    pub retention: RetentionService,
    /// Optional service-level keypair for signing NATS messages (e.g. approval resolutions).
    pub signing_keypair: Option<Arc<hush_core::Keypair>>,
    /// In-memory receipt storage for fleet-wide receipt sharing.
    pub receipt_store: ReceiptStore,
    /// In-memory catalog registry for policy templates.
    pub catalog: CatalogStore,
}

#[cfg(test)]
mod tests {
    use super::AppState;

    #[test]
    fn app_state_is_cloneable() {
        fn assert_clone<T: Clone>() {}

        assert_clone::<AppState>();
    }
}
