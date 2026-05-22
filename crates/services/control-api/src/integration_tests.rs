#![allow(clippy::duplicate_mod, clippy::expect_used, clippy::unwrap_used)]

use std::io::{Cursor, Read};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use chrono::Utc;
use futures::StreamExt;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::row::Row;
use tower::ServiceExt;
use uuid::Uuid;

#[path = "models/case_evidence.rs"]
pub(crate) mod case_evidence;
#[path = "services/case_evidence.rs"]
pub(crate) mod case_evidence_service;

use crate::auth::api_key::hash_api_key;
use crate::config::Config;
use crate::db::{create_pool, run_migrations, PgPool};
use crate::routes;
use crate::services::alerter::AlerterService;
use crate::services::metering::MeteringService;
use crate::services::policy_distribution;
use crate::services::retention::RetentionService;
use crate::services::tenant_provisioner::{tenant_subject_prefix, TenantProvisioner};
use crate::state::AppState;

struct DockerContainer {
    id: String,
}

impl Drop for DockerContainer {
    fn drop(&mut self) {
        let _ = Command::new("docker").args(["rm", "-f", &self.id]).status();
    }
}

struct Harness {
    app: axum::Router,
    db: PgPool,
    nats: async_nats::Client,
    nats_url: String,
    tenant_id: Uuid,
    tenant_slug: String,
    api_key: String,
    signing_keypair: Arc<hush_core::Keypair>,
    _postgres: DockerContainer,
    _nats: DockerContainer,
}

struct ConsoleFixture {
    principal_id: Uuid,
    principal_stable_ref: String,
    endpoint_agent_id: String,
    endpoint_agent_row_id: Uuid,
    grant_id: Uuid,
    action_id: Uuid,
}

struct OperatorFlowFixture {
    agent_id: String,
    session_id: String,
    detection_raw_ref: String,
    response_raw_ref: String,
    principal_id: Uuid,
    response_subject: String,
    grant_id: Uuid,
    finding_id: Uuid,
    case_id: String,
    action_id: Uuid,
}

include!("integration_tests/part_1.rs");
include!("integration_tests/part_2.rs");
include!("integration_tests/part_3.rs");
include!("integration_tests/part_4.rs");
include!("integration_tests/part_5.rs");
include!("integration_tests/part_6.rs");
