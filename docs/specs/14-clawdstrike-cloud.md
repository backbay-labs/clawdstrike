# Spec #14: ClawdStrike Cloud (Managed SaaS)

> Architecture, tiers, billing, dashboard, multi-tenancy, and compliance
> for the commercial ClawdStrike Cloud managed service.
>
> **Status:** Draft | **Date:** 2026-02-07
> **Effort Estimate:** 20-30 engineer-days (full MVP)
> **Branch:** `feat/sdr-execution`

---

## 1. Summary / Objective

Design and implement **ClawdStrike Cloud**, the managed SaaS offering that
monetizes the open source ClawdStrike SDR platform. ClawdStrike Cloud provides
hosted Spine infrastructure (NATS, checkpointer, witness, proofs API), a web
dashboard, agent fleet management, alerting, and compliance reporting --
eliminating the operational burden of self-hosting the attestation pipeline.

**Revenue model:** Open core. The complete SDR platform is free and open
source (Apache 2.0). ClawdStrike Cloud sells managed infrastructure and
enterprise features that organizations do not want to operate themselves.

**Key deliverables:**

1. Multi-tenant SaaS architecture with tenant isolation
2. Three-tier pricing: Team, Enterprise, Verified Publisher
3. Web dashboard (SPA) for SDR console, agent management, and compliance
4. Stripe billing integration with per-agent/month metering
5. Multi-tenancy via NATS account isolation and per-tenant Spine stores
6. Compliance features: audit export, retention policies, SOC2/HIPAA mapping

---

## 2. Current State

### 2.1 Existing Infrastructure

From `architecture-vision.md` Section 2.2, the following is **already
deployed on EKS**:

| Component | Status | Namespace |
|---|---|---|
| SPIRE 0.13.0 | Deployed | `spire-system` |
| NATS JetStream (3 replicas) | Deployed | `aegisnet` |
| AegisNet Checkpointer | Deployed | `aegisnet` |
| AegisNet Witness | Deployed | `aegisnet` |
| AegisNet Proofs API | Deployed | `aegisnet` |
| kube-prometheus-stack | Deployed | `monitoring` |
| Envoy Gateway | Deployed | (gateway) |

This infrastructure currently serves the Backbay development environment.
For ClawdStrike Cloud, it must be scaled to multi-tenant production with
isolation, metering, and SLA guarantees.

### 2.2 Multi-Agent Identity (Existing Primitives)

From `crates/hush-multi-agent/`, the following primitives are available for
cloud multi-tenancy:

- **`AgentIdentity`** -- Ed25519 public key, role, trust level, capabilities.
  Each tenant's agents have distinct identities.
- **`SignedDelegationToken`** -- Capability grants with time bounds, audience
  validation, and redelegation chains. Used for tenant-scoped authorization.
- **`RevocationStore`** (in-memory + SQLite) -- Token revocation. Cloud needs
  a PostgreSQL-backed implementation for durability.
- **`TrustLevel`** enum -- `Untrusted`, `Low`, `Medium`, `High`, `System`.
  Maps to cloud access tiers.

### 2.3 hushd Daemon

From `crates/hushd/`, the enforcement daemon provides:

- HTTP API for guard evaluation
- SSE event broadcast to connected clients
- NATS subscriber for Spine events
- Receipt signing with Ed25519

For cloud, hushd becomes a multi-tenant service with per-tenant policy
isolation and per-tenant event streams.

### 2.4 What Does Not Exist Yet

- No multi-tenant isolation layer
- No web dashboard (only Tauri desktop app)
- No billing / metering system
- No per-tenant NATS account isolation
- No PostgreSQL-backed stores (only in-memory + SQLite)
- No RBAC for multi-team organizations
- No SSO/SAML integration
- No audit export or retention policy management
- No compliance reporting pipeline

---

## 3. Target State

### 3.1 Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────┐
│                        ClawdStrike Cloud                             │
│                                                                      │
│  ┌─────────────────┐   ┌──────────────────┐   ┌──────────────────┐  │
│  │  Web Dashboard   │   │  API Gateway      │   │  Auth Service    │  │
│  │  (React SPA)     │   │  (Envoy + rate    │   │  (OIDC + SAML)   │  │
│  │  SDR console     │   │   limiting)       │   │  JWT tokens      │  │
│  │  Agent fleet     │   │                   │   │  Tenant isolation │  │
│  │  Compliance      │   │  /api/v1/...      │   │  RBAC             │  │
│  └────────┬─────────┘   └────────┬──────────┘   └────────┬─────────┘  │
│           │                      │                        │           │
│  ┌────────▼──────────────────────▼────────────────────────▼─────────┐│
│  │                        Cloud API (Rust / Axum)                    ││
│  │                                                                   ││
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐    ││
│  │  │ Tenant Mgmt  │  │ Agent Fleet  │  │ Policy Distribution  │    ││
│  │  │ CRUD tenants │  │ Register     │  │ Per-tenant policy    │    ││
│  │  │ API keys     │  │ Heartbeat    │  │ Guard evaluation     │    ││
│  │  │ Billing      │  │ Status       │  │ Receipt signing      │    ││
│  │  └──────────────┘  └──────────────┘  └──────────────────────┘    ││
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐    ││
│  │  │ Event Stream │  │ Compliance   │  │ Alerting             │    ││
│  │  │ SSE per      │  │ Audit export │  │ PagerDuty / Slack    │    ││
│  │  │ tenant       │  │ Retention    │  │ Webhook              │    ││
│  │  │              │  │ Reports      │  │                      │    ││
│  │  └──────────────┘  └──────────────┘  └──────────────────────┘    ││
│  └──────────────────────────────┬────────────────────────────────────┘│
│                                 │                                     │
│  ┌──────────────────────────────▼────────────────────────────────────┐│
│  │                     Data Layer                                     ││
│  │                                                                    ││
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐    ││
│  │  │ PostgreSQL   │  │ NATS         │  │ Spine Store          │    ││
│  │  │ (tenants,    │  │ JetStream    │  │ (per-tenant)         │    ││
│  │  │  users,      │  │ (per-tenant  │  │ Checkpointer         │    ││
│  │  │  billing,    │  │  accounts)   │  │ Witness              │    ││
│  │  │  API keys)   │  │              │  │ Proofs API           │    ││
│  │  └──────────────┘  └──────────────┘  └──────────────────────┘    ││
│  └───────────────────────────────────────────────────────────────────┘│
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────────┐│
│  │                     Billing (Stripe)                               ││
│  │  Usage metering → Stripe meter events → Stripe invoicing          ││
│  └──────────────────────────────────────────────────────────────────┘│
└──────────────────────────────────────────────────────────────────────┘
```

### 3.2 Tier Definitions

**Tier 1: Team Plan**

| Feature | Specification |
|---|---|
| Managed Spine | Shared NATS cluster, dedicated account per tenant |
| Dashboard | Web-based SDR console (read-only initially) |
| Agent fleet | Register, heartbeat, status for up to 50 agents |
| Policy deployment | Centralized policy push to agent fleet |
| Hosted marketplace | Read access to ClawdStrike-verified policies |
| Alerting | PagerDuty, Slack, webhook on guard violations |
| Retention | 30-day event and proof retention |
| Support | Community (GitHub Discussions, Discord) |
| **Pricing** | **$15-25/agent/month** |

**Tier 2: Enterprise Plan**

Everything in Team, plus:

| Feature | Specification |
|---|---|
| RBAC | Role-based access for multi-team organizations |
| SSO/SAML | Enterprise IdP integration (Okta, Azure AD, Google) |
| Audit export | JSON, CSV, SIEM-compatible formats |
| Custom retention | Configurable up to 2 years |
| SLA | 99.95% uptime, 24/7 support |
| Dedicated infra | Isolated NATS cluster, dedicated witness |
| Compliance bundles | Pre-configured SOC2 Type II, HIPAA evidence collection |
| Priority support | Shared Slack channel, <4hr P1 response |
| Unlimited agents | Volume-based pricing |
| **Pricing** | **Starting at $5,000/month** |

**Tier 3: Verified Publisher Program**

| Feature | Specification |
|---|---|
| Verification badge | "ClawdStrike Verified" on marketplace policies |
| Automated review | CI/CD pipeline for policy quality/security checks |
| Revenue share | Authors earn 70% of commercial policy bundle sales |
| Featured placement | Priority listing in marketplace search |
| Publisher dashboard | Install analytics, vulnerability reporting |
| **Pricing** | **Free to apply; 30% revenue share** |

---

## 4. Implementation Plan

### Step 1: Database Schema (PostgreSQL)

```sql
-- Cloud control plane database

-- Tenants
CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,  -- URL-safe identifier
    plan TEXT NOT NULL DEFAULT 'team' CHECK (plan IN ('team', 'enterprise')),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'cancelled')),
    stripe_customer_id TEXT,
    stripe_subscription_id TEXT,
    agent_limit INTEGER NOT NULL DEFAULT 50,
    retention_days INTEGER NOT NULL DEFAULT 30,
    nats_account_id TEXT,       -- NATS account for isolation
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Users (linked to tenant)
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    email TEXT NOT NULL,
    name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
    auth_provider TEXT NOT NULL DEFAULT 'email',  -- email, google, okta, azure_ad
    auth_provider_id TEXT,                         -- external IdP user ID
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, email)
);

-- API keys (per-tenant, for programmatic access)
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL,     -- SHA-256 of the API key (never store raw)
    key_prefix TEXT NOT NULL,   -- first 8 chars for identification
    scopes TEXT[] NOT NULL DEFAULT '{"read"}',
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Registered agents (per-tenant)
CREATE TABLE agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    agent_id TEXT NOT NULL,             -- ClawdStrike AgentId
    name TEXT NOT NULL,
    public_key TEXT NOT NULL,           -- Ed25519 hex
    role TEXT NOT NULL DEFAULT 'coder',
    trust_level TEXT NOT NULL DEFAULT 'medium',
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'revoked')),
    last_heartbeat_at TIMESTAMPTZ,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, agent_id)
);

-- Alert configurations (per-tenant)
CREATE TABLE alert_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    name TEXT NOT NULL,
    channel TEXT NOT NULL CHECK (channel IN ('pagerduty', 'slack', 'webhook')),
    config JSONB NOT NULL,           -- channel-specific config (URL, token, etc.)
    guard_filter TEXT[],             -- filter by guard name (empty = all)
    severity_threshold TEXT NOT NULL DEFAULT 'warn',
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Usage metering (for Stripe billing)
CREATE TABLE usage_events (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    event_type TEXT NOT NULL,        -- 'agent_active', 'envelope_processed', etc.
    quantity INTEGER NOT NULL DEFAULT 1,
    metadata JSONB DEFAULT '{}',
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_usage_tenant_time ON usage_events(tenant_id, recorded_at);
```

### Step 2: Multi-Tenant NATS Isolation

Each tenant gets a dedicated NATS account with isolated subjects and streams:

```yaml
# NATS server config with multi-tenancy

accounts:
  # System account (internal services)
  SYS:
    users:
      - { user: "sys-admin", password: "${SYS_ADMIN_PASSWORD}" }

  # Per-tenant accounts (generated dynamically)
  # Template: tenant-{slug}
  tenant-acme:
    users:
      - { nkey: "UABC..." }  # generated per-tenant
    jetstream:
      max_mem: 1Gi
      max_file: 50Gi
      max_streams: 10
      max_consumers: 50
    exports:
      # Tenant publishes envelopes; cloud services consume
      - stream: "clawdstrike.spine.envelope.>"
    imports:
      # Tenant receives checkpoints and proofs from shared infra
      - stream:
          account: SYS
          subject: "aegis.spine.checkpoint.>"
```

**NATS account provisioning flow:**

1. Tenant signs up via web dashboard
2. Cloud API creates a NATS account with isolated JetStream limits
3. API key is generated and bound to the NATS account
4. Agent SDKs connect using the tenant-scoped NATS credentials
5. Per-tenant streams are created:
   - `{tenant}_SPINE_LOG` -- envelopes from this tenant's agents
   - `{tenant}_CHECKPOINTS` -- KV bucket for tenant's checkpoints

### Step 3: Cloud API Service (Rust / Axum)

**New crate: `crates/cloud-api/`**

```
crates/cloud-api/
├── Cargo.toml
├── src/
│   ├── main.rs               # Service entry point
│   ├── config.rs              # Environment-based config
│   ├── db.rs                  # PostgreSQL connection pool (sqlx)
│   ├── auth/
│   │   ├── mod.rs             # Auth middleware
│   │   ├── jwt.rs             # JWT token validation
│   │   ├── api_key.rs         # API key authentication
│   │   └── oidc.rs            # OIDC/SAML provider integration
│   ├── routes/
│   │   ├── mod.rs             # Router setup
│   │   ├── tenants.rs         # Tenant CRUD
│   │   ├── agents.rs          # Agent registration + heartbeat
│   │   ├── policies.rs        # Policy deployment
│   │   ├── events.rs          # SSE event stream (per-tenant)
│   │   ├── alerts.rs          # Alert config CRUD
│   │   ├── compliance.rs      # Audit export, retention
│   │   ├── billing.rs         # Stripe webhook handler
│   │   └── health.rs          # Health + readiness checks
│   ├── services/
│   │   ├── mod.rs
│   │   ├── tenant_provisioner.rs   # NATS account + stream setup
│   │   ├── metering.rs             # Usage event recording
│   │   ├── alerter.rs              # Alert dispatch (PD/Slack/webhook)
│   │   └── retention.rs            # Data retention enforcement
│   └── models/
│       ├── mod.rs
│       ├── tenant.rs
│       ├── user.rs
│       ├── agent.rs
│       └── api_key.rs
```

**`Cargo.toml` dependencies:**

```toml
[package]
name = "clawdstrike-cloud-api"
version = "0.1.0"
edition = "2021"

[dependencies]
axum = { version = "0.8", features = ["macros"] }
axum-extra = { version = "0.10", features = ["typed-header"] }
sqlx = { version = "0.8", features = ["runtime-tokio", "postgres", "uuid", "chrono", "json"] }
async-nats = "0.38"
hush-core = { path = "../hush-core" }
hush-multi-agent = { path = "../hush-multi-agent" }
jsonwebtoken = "9"
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "json"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
stripe-rust = "25"
tokio = { version = "1", features = ["full"] }
tower = "0.5"
tower-http = { version = "0.6", features = ["cors", "trace", "limit"] }
tracing = "0.1"
tracing-subscriber = "0.3"
uuid = { version = "1", features = ["v4", "serde"] }
```

**Core API routes:**

```rust
// crates/cloud-api/src/routes/mod.rs

use axum::{Router, middleware};

pub fn router(state: AppState) -> Router {
    Router::new()
        // Public routes
        .nest("/api/v1/health", health::router())
        .nest("/api/v1/auth", auth::router())
        // Authenticated routes (API key or JWT)
        .nest(
            "/api/v1",
            Router::new()
                .nest("/tenants", tenants::router())
                .nest("/agents", agents::router())
                .nest("/policies", policies::router())
                .nest("/events", events::router())
                .nest("/alerts", alerts::router())
                .nest("/compliance", compliance::router())
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    auth::require_auth,
                ))
        )
        // Stripe webhook (verified by signature)
        .nest("/webhooks/stripe", billing::router())
        .with_state(state)
}
```

**Agent registration endpoint:**

```rust
// crates/cloud-api/src/routes/agents.rs

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct RegisterAgentRequest {
    pub agent_id: String,
    pub name: String,
    pub public_key: String,   // Ed25519 hex
    pub role: String,
    pub trust_level: String,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Serialize)]
pub struct RegisterAgentResponse {
    pub id: uuid::Uuid,
    pub agent_id: String,
    pub nats_credentials: NatsCredentials,
}

#[derive(Serialize)]
pub struct NatsCredentials {
    pub nats_url: String,
    pub account: String,
    pub nkey_seed: String,     // per-agent NATS NKey
}

pub async fn register_agent(
    State(state): State<AppState>,
    tenant: AuthenticatedTenant,
    Json(req): Json<RegisterAgentRequest>,
) -> Result<Json<RegisterAgentResponse>, ApiError> {
    // 1. Check agent limit
    let agent_count = state.db.count_active_agents(tenant.id).await?;
    if agent_count >= tenant.agent_limit as i64 {
        return Err(ApiError::AgentLimitReached);
    }

    // 2. Validate Ed25519 public key
    hush_core::PublicKey::from_hex(&req.public_key)
        .map_err(|_| ApiError::InvalidPublicKey)?;

    // 3. Insert agent record
    let agent = state.db.insert_agent(tenant.id, &req).await?;

    // 4. Generate NATS credentials for this agent
    let nats_creds = state.tenant_provisioner
        .create_agent_nkey(tenant.id, &req.agent_id).await?;

    // 5. Record usage event
    state.metering.record(tenant.id, "agent_registered", 1).await?;

    Ok(Json(RegisterAgentResponse {
        id: agent.id,
        agent_id: agent.agent_id,
        nats_credentials: nats_creds,
    }))
}
```

### Step 4: Web Dashboard (React SPA)

**New package: `packages/cloud-dashboard/`**

The dashboard mirrors the Tauri desktop features but runs as a web SPA:

```
packages/cloud-dashboard/
├── package.json
├── vite.config.ts
├── src/
│   ├── App.tsx
│   ├── main.tsx
│   ├── pages/
│   │   ├── Dashboard.tsx         # Overview: agent count, event rate, alerts
│   │   ├── Agents.tsx            # Agent fleet table + status
│   │   ├── Events.tsx            # Real-time event stream (SSE)
│   │   ├── Policies.tsx          # Policy management + deployment
│   │   ├── Alerts.tsx            # Alert config CRUD
│   │   ├── Compliance.tsx        # Audit export + retention settings
│   │   ├── Settings.tsx          # Tenant settings, API keys, billing
│   │   └── Login.tsx             # Auth flow
│   ├── components/
│   │   ├── AgentStatusCard.tsx
│   │   ├── EventStreamView.tsx   # Reuse from desktop (without R3F)
│   │   ├── PolicyDeployModal.tsx
│   │   ├── AlertConfigForm.tsx
│   │   └── ComplianceExport.tsx
│   ├── hooks/
│   │   ├── useAuth.ts
│   │   ├── useSSE.ts             # SSE subscription to cloud API
│   │   └── useAgents.ts
│   └── api/
│       └── client.ts             # API client (fetch + auth headers)
```

**Key differences from desktop:**

| Feature | Desktop (Tauri) | Cloud Dashboard |
|---|---|---|
| 3D visualizations (R3F) | ThreatRadar, NetworkMap, AttackGraph | Deferred (2D charts initially) |
| Event transport | Tauri IPC + NATS | SSE from Cloud API |
| Auth | Local (no auth needed) | JWT + API key + OIDC |
| Deployment | Local binary | HTTPS SPA (S3 + CloudFront) |
| Multi-tenant | Single user | Tenant-scoped data |

### Step 5: Stripe Billing Integration

**Pricing model: Per-agent/month with usage-based metering**

```typescript
// Stripe product/price setup (run once via Stripe dashboard or API)

// Product: ClawdStrike Cloud Team
// Price: $20/agent/month (metered)
// Meter: "active_agents" (reported daily)

// Product: ClawdStrike Cloud Enterprise
// Price: Custom (contact sales)
// Minimum: $5,000/month
```

**Usage metering flow:**

```
1. Agent heartbeats to Cloud API
2. Cloud API records heartbeat in PostgreSQL
3. Daily cron job counts distinct active agents per tenant
4. Stripe meter event: { tenant_stripe_id, quantity: active_agent_count }
5. Stripe generates monthly invoice based on metered usage
```

**Rust metering service:**

```rust
// crates/cloud-api/src/services/metering.rs

pub struct MeteringService {
    db: PgPool,
    stripe_client: stripe::Client,
}

impl MeteringService {
    /// Record a usage event for billing purposes.
    pub async fn record(
        &self,
        tenant_id: uuid::Uuid,
        event_type: &str,
        quantity: i32,
    ) -> Result<(), MeteringError> {
        sqlx::query!(
            r#"INSERT INTO usage_events (tenant_id, event_type, quantity)
               VALUES ($1, $2, $3)"#,
            tenant_id, event_type, quantity,
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    /// Daily job: report active agent counts to Stripe.
    pub async fn report_daily_usage(&self) -> Result<(), MeteringError> {
        let tenants = sqlx::query!(
            r#"SELECT t.id, t.stripe_subscription_id,
                      COUNT(DISTINCT a.id) as agent_count
               FROM tenants t
               JOIN agents a ON a.tenant_id = t.id
               WHERE a.status = 'active'
                 AND a.last_heartbeat_at > now() - interval '24 hours'
                 AND t.status = 'active'
               GROUP BY t.id"#
        )
        .fetch_all(&self.db)
        .await?;

        for tenant in tenants {
            if let Some(sub_id) = &tenant.stripe_subscription_id {
                // Report metered usage to Stripe
                // stripe::MeterEvent::create(...)
                tracing::info!(
                    tenant_id = %tenant.id,
                    agents = tenant.agent_count.unwrap_or(0),
                    "Reported usage to Stripe"
                );
            }
        }
        Ok(())
    }
}
```

**Stripe webhook handler:**

```rust
// crates/cloud-api/src/routes/billing.rs

pub async fn stripe_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    // Verify Stripe webhook signature
    let sig = headers.get("stripe-signature")
        .ok_or(ApiError::InvalidSignature)?
        .to_str()
        .map_err(|_| ApiError::InvalidSignature)?;

    let event = stripe::Webhook::construct_event(
        &String::from_utf8_lossy(&body),
        sig,
        &state.config.stripe_webhook_secret,
    ).map_err(|_| ApiError::InvalidSignature)?;

    match event.type_ {
        stripe::EventType::InvoicePaymentSucceeded => {
            // Payment received: ensure tenant is active
        }
        stripe::EventType::InvoicePaymentFailed => {
            // Payment failed: send warning, grace period
        }
        stripe::EventType::CustomerSubscriptionDeleted => {
            // Subscription cancelled: suspend tenant
            let customer_id = extract_customer_id(&event)?;
            state.db.suspend_tenant_by_stripe_id(&customer_id).await?;
        }
        _ => {}
    }

    Ok(StatusCode::OK)
}
```

### Step 6: SSE Event Streaming (Per-Tenant)

```rust
// crates/cloud-api/src/routes/events.rs

use axum::{
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
};
use futures::stream::Stream;
use std::convert::Infallible;

pub async fn event_stream(
    State(state): State<AppState>,
    tenant: AuthenticatedTenant,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    // Subscribe to tenant-scoped NATS subjects
    let subject = format!("tenant-{}.clawdstrike.spine.envelope.>", tenant.slug);
    let mut subscriber = state.nats
        .subscribe(subject)
        .await
        .expect("NATS subscribe failed");

    let stream = async_stream::stream! {
        while let Some(msg) = subscriber.next().await {
            let data = String::from_utf8_lossy(&msg.payload);
            yield Ok(Event::default().data(data));
        }
    };

    Sse::new(stream).keep_alive(KeepAlive::default())
}
```

### Step 7: Compliance Features

**Audit export:**

```rust
// crates/cloud-api/src/routes/compliance.rs

#[derive(Deserialize)]
pub struct AuditExportRequest {
    pub from: chrono::DateTime<chrono::Utc>,
    pub to: chrono::DateTime<chrono::Utc>,
    pub format: ExportFormat, // json, csv, siem
    pub namespace: Option<String>,
    pub agent_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    Json,
    Csv,
    Siem,  // CEF (Common Event Format) for SIEM ingestion
}

pub async fn export_audit_log(
    State(state): State<AppState>,
    tenant: AuthenticatedTenant,
    Query(req): Query<AuditExportRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // Verify tenant has export capability (Enterprise plan)
    if tenant.plan != "enterprise" {
        return Err(ApiError::PlanUpgradeRequired("audit_export"));
    }

    // Query envelopes from tenant's Spine store within time range
    let envelopes = state.spine_store
        .query_envelopes(tenant.id, req.from, req.to,
                         req.namespace.as_deref(), req.agent_id.as_deref())
        .await?;

    match req.format {
        ExportFormat::Json => {
            let body = serde_json::to_string_pretty(&envelopes)?;
            Ok((
                [(header::CONTENT_TYPE, "application/json"),
                 (header::CONTENT_DISPOSITION, "attachment; filename=audit-export.json")],
                body,
            ))
        }
        ExportFormat::Csv => {
            let csv = envelopes_to_csv(&envelopes)?;
            Ok((
                [(header::CONTENT_TYPE, "text/csv"),
                 (header::CONTENT_DISPOSITION, "attachment; filename=audit-export.csv")],
                csv,
            ))
        }
        ExportFormat::Siem => {
            let cef = envelopes_to_cef(&envelopes)?;
            Ok((
                [(header::CONTENT_TYPE, "text/plain"),
                 (header::CONTENT_DISPOSITION, "attachment; filename=audit-export.cef")],
                cef,
            ))
        }
    }
}
```

**Retention enforcement:**

```rust
// crates/cloud-api/src/services/retention.rs

pub struct RetentionService {
    db: PgPool,
}

impl RetentionService {
    /// Daily job: delete envelopes older than tenant's retention period.
    pub async fn enforce_retention(&self) -> Result<(), RetentionError> {
        let tenants = sqlx::query!(
            "SELECT id, slug, retention_days FROM tenants WHERE status = 'active'"
        )
        .fetch_all(&self.db)
        .await?;

        for tenant in tenants {
            let cutoff = chrono::Utc::now()
                - chrono::Duration::days(tenant.retention_days as i64);

            let deleted = sqlx::query!(
                r#"DELETE FROM tenant_envelopes
                   WHERE tenant_id = $1 AND received_at < $2"#,
                tenant.id, cutoff,
            )
            .execute(&self.db)
            .await?;

            tracing::info!(
                tenant = %tenant.slug,
                retention_days = tenant.retention_days,
                deleted = deleted.rows_affected(),
                "Retention enforcement completed"
            );
        }

        Ok(())
    }
}
```

### Step 8: RBAC and SSO

**RBAC roles:**

| Role | Capabilities |
|---|---|
| `owner` | Full tenant management, billing, user management, all data access |
| `admin` | Agent management, policy deployment, alert config, compliance export |
| `member` | View events, view agents, view policies |
| `viewer` | Read-only access to dashboard and events |

**SSO/SAML integration:**

Enterprise tenants can configure OIDC providers:

```rust
// crates/cloud-api/src/auth/oidc.rs

#[derive(Deserialize)]
pub struct OidcConfig {
    pub provider: OidcProvider,
    pub client_id: String,
    pub client_secret: String,
    pub issuer_url: String,        // e.g., https://acme.okta.com
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub role_mapping: HashMap<String, String>,  // IdP group -> RBAC role
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OidcProvider {
    Okta,
    AzureAd,
    Google,
    Custom,
}
```

### Step 9: Alerting Service

```rust
// crates/cloud-api/src/services/alerter.rs

pub struct AlerterService {
    db: PgPool,
    http_client: reqwest::Client,
}

impl AlerterService {
    /// Process a guard violation event and dispatch alerts.
    pub async fn process_violation(
        &self,
        tenant_id: uuid::Uuid,
        event: &SecurityEvent,
    ) -> Result<(), AlertError> {
        let configs = sqlx::query_as!(
            AlertConfig,
            r#"SELECT * FROM alert_configs
               WHERE tenant_id = $1 AND enabled = true"#,
            tenant_id,
        )
        .fetch_all(&self.db)
        .await?;

        for config in configs {
            if !matches_filter(&config, event) {
                continue;
            }

            match config.channel.as_str() {
                "pagerduty" => self.send_pagerduty(&config, event).await?,
                "slack" => self.send_slack(&config, event).await?,
                "webhook" => self.send_webhook(&config, event).await?,
                _ => {}
            }
        }

        Ok(())
    }

    async fn send_slack(
        &self, config: &AlertConfig, event: &SecurityEvent,
    ) -> Result<(), AlertError> {
        let webhook_url = config.config["webhook_url"].as_str()
            .ok_or(AlertError::MissingConfig("webhook_url"))?;

        let payload = serde_json::json!({
            "text": format!(
                ":rotating_light: *ClawdStrike Alert*\n\
                 Guard: {}\n\
                 Verdict: {}\n\
                 Agent: {}\n\
                 Target: {}\n\
                 Time: {}",
                event.guard_name, event.verdict,
                event.agent_id, event.target, event.timestamp
            )
        });

        self.http_client.post(webhook_url)
            .json(&payload)
            .send()
            .await?;

        Ok(())
    }
}
```

---

## 5. File Changes

### New Files

| Path | Description | Est. LOC |
|---|---|---|
| `crates/cloud-api/Cargo.toml` | Cloud API crate config | 35 |
| `crates/cloud-api/src/main.rs` | Service entry point | 80 |
| `crates/cloud-api/src/config.rs` | Environment config | 80 |
| `crates/cloud-api/src/db.rs` | PostgreSQL pool setup | 50 |
| `crates/cloud-api/src/auth/mod.rs` | Auth middleware | 40 |
| `crates/cloud-api/src/auth/jwt.rs` | JWT validation | 100 |
| `crates/cloud-api/src/auth/api_key.rs` | API key auth | 80 |
| `crates/cloud-api/src/auth/oidc.rs` | OIDC/SAML integration | 150 |
| `crates/cloud-api/src/routes/mod.rs` | Router setup | 40 |
| `crates/cloud-api/src/routes/tenants.rs` | Tenant CRUD | 150 |
| `crates/cloud-api/src/routes/agents.rs` | Agent registration + heartbeat | 200 |
| `crates/cloud-api/src/routes/policies.rs` | Policy deployment | 150 |
| `crates/cloud-api/src/routes/events.rs` | SSE event stream | 80 |
| `crates/cloud-api/src/routes/alerts.rs` | Alert config CRUD | 120 |
| `crates/cloud-api/src/routes/compliance.rs` | Audit export + retention | 200 |
| `crates/cloud-api/src/routes/billing.rs` | Stripe webhook | 100 |
| `crates/cloud-api/src/routes/health.rs` | Health checks | 30 |
| `crates/cloud-api/src/services/mod.rs` | Service module | 10 |
| `crates/cloud-api/src/services/tenant_provisioner.rs` | NATS account setup | 150 |
| `crates/cloud-api/src/services/metering.rs` | Usage metering + Stripe | 150 |
| `crates/cloud-api/src/services/alerter.rs` | Alert dispatch | 200 |
| `crates/cloud-api/src/services/retention.rs` | Data retention enforcement | 80 |
| `crates/cloud-api/src/models/mod.rs` | Model module | 10 |
| `crates/cloud-api/src/models/tenant.rs` | Tenant model | 60 |
| `crates/cloud-api/src/models/user.rs` | User model | 50 |
| `crates/cloud-api/src/models/agent.rs` | Agent model | 50 |
| `crates/cloud-api/src/models/api_key.rs` | API key model | 50 |
| `crates/cloud-api/migrations/001_init.sql` | Initial DB migration | 80 |
| `packages/cloud-dashboard/package.json` | Dashboard package config | 30 |
| `packages/cloud-dashboard/vite.config.ts` | Vite config | 20 |
| `packages/cloud-dashboard/src/App.tsx` | Root component | 50 |
| `packages/cloud-dashboard/src/main.tsx` | Entry point | 15 |
| `packages/cloud-dashboard/src/pages/Dashboard.tsx` | Overview page | 150 |
| `packages/cloud-dashboard/src/pages/Agents.tsx` | Agent fleet page | 200 |
| `packages/cloud-dashboard/src/pages/Events.tsx` | Event stream page | 150 |
| `packages/cloud-dashboard/src/pages/Policies.tsx` | Policy management | 150 |
| `packages/cloud-dashboard/src/pages/Alerts.tsx` | Alert configuration | 120 |
| `packages/cloud-dashboard/src/pages/Compliance.tsx` | Compliance page | 150 |
| `packages/cloud-dashboard/src/pages/Settings.tsx` | Settings page | 200 |
| `packages/cloud-dashboard/src/pages/Login.tsx` | Auth flow | 100 |
| `packages/cloud-dashboard/src/hooks/useAuth.ts` | Auth hook | 60 |
| `packages/cloud-dashboard/src/hooks/useSSE.ts` | SSE subscription | 50 |
| `packages/cloud-dashboard/src/api/client.ts` | API client | 80 |
| **Total estimated** | | **~3,950** |

### Modified Files

| Path | Change | Description |
|---|---|---|
| `Cargo.toml` (workspace root) | Add `cloud-api` to members | Workspace inclusion |
| `package.json` (root) | Add `cloud-dashboard` to workspaces | Workspace inclusion |

---

## 6. Testing Strategy

### Unit Tests

- **Auth middleware:** JWT validation, API key verification, OIDC token
  parsing, role-based access control checks
- **Tenant provisioner:** NATS account creation, credential generation,
  stream setup
- **Metering service:** Usage event recording, daily aggregation, Stripe
  meter event creation
- **Alerter:** PagerDuty/Slack/webhook dispatch, filter matching, error
  handling
- **Retention:** Cutoff calculation, deletion queries, per-tenant isolation
- **Compliance export:** JSON/CSV/CEF format generation, time range filtering

### Integration Tests

- **Tenant lifecycle:** Create tenant -> register agents -> receive events
  -> export audit -> suspend -> cancel
- **NATS isolation:** Verify tenant A cannot subscribe to tenant B's
  subjects
- **Billing flow:** Stripe subscription creation -> metered usage reporting
  -> invoice generation (Stripe test mode)
- **SSO flow:** OIDC authorization code flow with mock IdP
- **Event streaming:** Publish event to tenant NATS -> SSE delivers to
  dashboard within 100ms

### Load Tests

- **50 concurrent tenants, 50 agents each (2,500 total agents)**
  - Agent heartbeat: 1/minute per agent = 42 heartbeats/sec
  - Guard events: 10/minute per agent = 420 events/sec
  - SSE connections: 50 concurrent dashboard sessions
  - Target: <100ms p99 API latency, <500ms SSE delivery

### Security Tests

- **Tenant isolation penetration test:** Attempt to access tenant B's
  data from tenant A's API key
- **API key rotation:** Verify revoked keys are immediately rejected
- **Rate limiting:** Verify API rate limits prevent abuse
- **Stripe webhook verification:** Reject unsigned/tampered webhooks

---

## 7. Rollback Plan

ClawdStrike Cloud is a **new deployment** with no impact on the open source
project:

1. **Cloud API (`crates/cloud-api/`):** Independent service. Can be shut
   down without affecting hushd, the desktop app, or any open source
   functionality.
2. **Dashboard (`packages/cloud-dashboard/`):** Static SPA served from
   CDN. Can be taken offline independently.
3. **Database:** PostgreSQL contains only cloud-specific data (tenants,
   users, API keys). No shared state with open source components.
4. **NATS accounts:** Tenant-scoped accounts can be deleted without
   affecting the shared infrastructure.
5. **Stripe subscriptions:** Can be cancelled via Stripe dashboard.

The open source project functions identically with or without ClawdStrike
Cloud. The commercial service is a pure superset.

---

## 8. Dependencies

| Dependency | Status | Notes |
|---|---|---|
| `crates/hush-core/` | **Exists** | Ed25519, SHA-256 for API key hashing |
| `crates/hush-multi-agent/` | **Exists** | AgentIdentity, DelegationToken, RevocationStore |
| `crates/hushd/` | **Exists** | Pattern reference for guard evaluation API |
| `crates/spine/` | **Exists** | Envelope format, NATS transport |
| NATS JetStream | **Deployed** | Event backbone (needs multi-account config) |
| AegisNet services | **Deployed** | Checkpointer, witness, proofs API |
| PostgreSQL | **New infrastructure** | Cloud control plane database |
| Stripe API | **External** | Billing and metering |
| Spec #12 (Reticulum adapter) | **Pending** | Cloud tenants can optionally use Reticulum |
| Spec #13 (EAS anchoring) | **Pending** | Enterprise plan includes EAS timestamps |
| Spec #9 (Helm chart) | **In progress** | Cloud deploys the Helm chart internally |

---

## 9. Acceptance Criteria

- [ ] Tenant can sign up, receive API key, and register an agent via
      Cloud API
- [ ] Registered agent can connect to tenant-scoped NATS and publish
      envelopes
- [ ] Tenant A's agents cannot access tenant B's NATS subjects or data
- [ ] Web dashboard displays real-time event stream from tenant's agents
      via SSE
- [ ] Agent fleet page shows agent status with heartbeat freshness
- [ ] Alert fires to Slack/PagerDuty/webhook within 30 seconds of a
      guard violation event
- [ ] Audit export produces valid JSON/CSV/CEF files for a specified
      time range
- [ ] Retention enforcement deletes envelopes older than the configured
      retention period
- [ ] Stripe metered billing reports correct active agent counts daily
- [ ] Stripe webhook correctly suspends tenants on subscription cancellation
- [ ] RBAC: `viewer` role cannot register agents or modify alert configs
- [ ] Enterprise SSO: user can authenticate via Okta OIDC and receive
      correct RBAC role based on IdP group mapping
- [ ] API rate limits are enforced (429 responses on excess)
- [ ] Health endpoint returns 200 with dependency status
- [ ] Load test: 50 tenants x 50 agents, <100ms p99 API latency

---

## 10. Open Questions

1. **Self-service vs sales-led Enterprise plan:** Should Enterprise
   tenants self-serve through the dashboard or require a sales conversation?
   **Recommendation:** Self-serve signup with automatic upgrade path.
   Enterprise-specific features (SSO, dedicated infra) are configured
   after manual approval. "Contact sales" button for custom pricing.

2. **Dedicated vs shared Spine infrastructure for Enterprise:**
   Enterprise plan promises "dedicated infrastructure." Should this be
   a separate NATS cluster per Enterprise tenant, or isolated accounts
   within a shared cluster? **Recommendation:** Start with isolated
   NATS accounts (same cluster, different JetStream limits). Migrate to
   dedicated clusters for tenants exceeding 500 agents or with compliance
   requirements (e.g., data residency).

3. **Data residency:** Some Enterprise tenants may require data to stay
   in specific AWS regions (EU, US, etc.). **Recommendation:** Defer to
   Phase 2. Initial launch in us-east-1 only. Add region selection when
   Enterprise demand materializes.

4. **Free tier:** Should there be a free tier for individual developers?
   **Recommendation:** Yes, limited to 5 agents, 7-day retention, no
   alerting. This drives adoption and converts to Team when projects
   grow. Implement after Team plan is stable.

5. **Desktop app integration:** Should the desktop app be able to connect
   to ClawdStrike Cloud as a backend (instead of local hushd)?
   **Recommendation:** Yes, this is a natural upsell path. The desktop
   app gains cloud features (multi-tenant, alerting, compliance) when
   pointed at a ClawdStrike Cloud instance. Implement as a config option:
   `backend: "local" | "cloud"` with Cloud API URL.

---

## References

- [Open Source Strategy](../research/open-source-strategy.md) -- Section 5 (Business Model), Section 9 (Timeline)
- [Architecture Vision](../research/architecture-vision.md) -- Section 2 (Full Stack), Section 5 (Product Positioning)
- [Marketplace Trust Evolution](../research/marketplace-trust-evolution.md) -- Section 8 (Community Curation for Publisher Program)
- `crates/hushd/` -- Existing daemon architecture (reference for Cloud API)
- `crates/hush-multi-agent/src/types.rs` -- AgentIdentity, AgentCapability, TrustLevel
- `crates/hush-multi-agent/src/token.rs` -- SignedDelegationToken for tenant-scoped auth
- `crates/spine/src/nats_transport.rs` -- NATS connection patterns
- `crates/spine/src/trust.rs` -- TrustBundle for tenant-scoped verification
