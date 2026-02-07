use crate::config::Config;
use crate::db::PgPool;
use crate::services::alerter::AlerterService;
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
}
