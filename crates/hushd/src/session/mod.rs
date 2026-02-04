//! Session management for identity-aware evaluation.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use clawdstrike::{
    AuthMethod, GuardContext, IdentityPrincipal, RequestContext, SessionContext, SessionMetadata,
};
use serde::{Deserialize, Serialize};

use crate::config::SessionHardeningConfig;
use crate::control_db::ControlDb;
use crate::rbac::RbacManager;

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("invalid session timestamp: {0}")]
    InvalidTimestamp(String),
    #[error("invalid session binding: {0}")]
    InvalidBinding(String),
}

pub type Result<T> = std::result::Result<T, SessionError>;

#[derive(Clone, Debug)]
pub struct StoredSession {
    pub session: SessionContext,
    pub terminated_at: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct SessionUpdates {
    pub last_activity_at: Option<String>,
    pub expires_at: Option<String>,
    pub terminated_at: Option<String>,
    pub request: Option<RequestContext>,
    pub state: Option<HashMap<String, serde_json::Value>>,
}

pub trait SessionStore: Send + Sync {
    fn set(&self, record: &StoredSession) -> Result<()>;
    fn get(&self, session_id: &str) -> Result<Option<StoredSession>>;
    fn update(&self, session_id: &str, updates: SessionUpdates) -> Result<Option<StoredSession>>;
    fn delete(&self, session_id: &str) -> Result<bool>;
    fn list_by_user(&self, user_id: &str) -> Result<Vec<StoredSession>>;
    fn cleanup_expired(&self, now: DateTime<Utc>) -> Result<u64>;
}

#[derive(Clone)]
pub struct InMemorySessionStore {
    inner: Arc<tokio::sync::RwLock<HashMap<String, StoredSession>>>,
}

impl InMemorySessionStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }
}

impl Default for InMemorySessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionStore for InMemorySessionStore {
    fn set(&self, record: &StoredSession) -> Result<()> {
        let record = record.clone();
        let key = record.session.session_id.clone();
        let inner = self.inner.clone();
        tokio::task::block_in_place(|| {
            let mut map = inner.blocking_write();
            map.insert(key, record);
        });
        Ok(())
    }

    fn get(&self, session_id: &str) -> Result<Option<StoredSession>> {
        let inner = self.inner.clone();
        let session_id = session_id.to_string();
        let record = tokio::task::block_in_place(|| {
            let map = inner.blocking_read();
            map.get(&session_id).cloned()
        });
        Ok(record)
    }

    fn update(&self, session_id: &str, updates: SessionUpdates) -> Result<Option<StoredSession>> {
        let inner = self.inner.clone();
        let session_id = session_id.to_string();
        let updated = tokio::task::block_in_place(|| {
            let mut map = inner.blocking_write();
            let mut record = map.get(&session_id).cloned()?;

            apply_updates(&mut record, updates);
            map.insert(session_id, record.clone());
            Some(record)
        });
        Ok(updated)
    }

    fn delete(&self, session_id: &str) -> Result<bool> {
        let inner = self.inner.clone();
        let session_id = session_id.to_string();
        let removed = tokio::task::block_in_place(|| {
            let mut map = inner.blocking_write();
            map.remove(&session_id).is_some()
        });
        Ok(removed)
    }

    fn list_by_user(&self, user_id: &str) -> Result<Vec<StoredSession>> {
        let inner = self.inner.clone();
        let user_id = user_id.to_string();
        let sessions = tokio::task::block_in_place(|| {
            let map = inner.blocking_read();
            map.values()
                .filter(|r| r.session.identity.id == user_id)
                .cloned()
                .collect::<Vec<_>>()
        });
        Ok(sessions)
    }

    fn cleanup_expired(&self, now: DateTime<Utc>) -> Result<u64> {
        let inner = self.inner.clone();
        let removed = tokio::task::block_in_place(|| {
            let mut map = inner.blocking_write();
            let before = map.len() as u64;
            map.retain(|_, record| !is_expired(&record.session, now));
            before - map.len() as u64
        });
        Ok(removed)
    }
}

#[derive(Clone)]
pub struct SqliteSessionStore {
    db: Arc<ControlDb>,
}

impl SqliteSessionStore {
    pub fn new(db: Arc<ControlDb>) -> Self {
        Self { db }
    }
}

impl SessionStore for SqliteSessionStore {
    fn set(&self, record: &StoredSession) -> Result<()> {
        let conn = self.db.lock_conn();
        let session = &record.session;

        let session_json = serde_json::to_string(session)?;
        let user_id = session.identity.id.clone();
        let org_id = session
            .identity
            .organization_id
            .clone()
            .or_else(|| session.organization.as_ref().map(|o| o.id.clone()));

        conn.execute(
            r#"
INSERT OR REPLACE INTO sessions
    (session_id, user_id, org_id, created_at, last_activity_at, expires_at, terminated_at, session_json)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            rusqlite::params![
                session.session_id,
                user_id,
                org_id,
                session.created_at,
                session.last_activity_at,
                session.expires_at,
                record.terminated_at,
                session_json
            ],
        )?;

        Ok(())
    }

    fn get(&self, session_id: &str) -> Result<Option<StoredSession>> {
        let conn = self.db.lock_conn();

        let mut stmt = conn.prepare(
            r#"
SELECT session_json, terminated_at
FROM sessions
WHERE session_id = ?1
            "#,
        )?;

        let mut rows = stmt.query(rusqlite::params![session_id])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };

        let session_json: String = row.get(0)?;
        let terminated_at: Option<String> = row.get(1)?;

        let session: SessionContext = serde_json::from_str(&session_json)?;
        Ok(Some(StoredSession {
            session,
            terminated_at,
        }))
    }

    fn update(&self, session_id: &str, updates: SessionUpdates) -> Result<Option<StoredSession>> {
        let Some(mut record) = self.get(session_id)? else {
            return Ok(None);
        };

        apply_updates(&mut record, updates);
        self.set(&record)?;
        Ok(Some(record))
    }

    fn delete(&self, session_id: &str) -> Result<bool> {
        let conn = self.db.lock_conn();
        let changed = conn.execute(
            "DELETE FROM sessions WHERE session_id = ?1",
            rusqlite::params![session_id],
        )?;
        Ok(changed > 0)
    }

    fn list_by_user(&self, user_id: &str) -> Result<Vec<StoredSession>> {
        let conn = self.db.lock_conn();
        let mut stmt = conn.prepare(
            r#"
SELECT session_json, terminated_at
FROM sessions
WHERE user_id = ?1
ORDER BY created_at DESC
            "#,
        )?;

        let mut out = Vec::new();
        let mut rows = stmt.query(rusqlite::params![user_id])?;
        while let Some(row) = rows.next()? {
            let session_json: String = row.get(0)?;
            let terminated_at: Option<String> = row.get(1)?;
            let session: SessionContext = serde_json::from_str(&session_json)?;
            out.push(StoredSession {
                session,
                terminated_at,
            });
        }

        Ok(out)
    }

    fn cleanup_expired(&self, now: DateTime<Utc>) -> Result<u64> {
        let conn = self.db.lock_conn();
        let now = now.to_rfc3339();
        let changed = conn.execute(
            "DELETE FROM sessions WHERE expires_at <= ?1",
            rusqlite::params![now],
        )?;
        Ok(changed as u64)
    }
}

#[derive(Clone)]
pub struct SessionManager {
    store: Arc<dyn SessionStore>,
    default_ttl_seconds: u64,
    max_ttl_seconds: u64,
    rbac: Option<Arc<RbacManager>>,
    hardening: SessionHardeningConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvalidSessionReason {
    Expired,
    Terminated,
    NotFound,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SessionValidationResult {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<InvalidSessionReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_ttl_seconds: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct CreateSessionOptions {
    #[serde(default, alias = "ttlSeconds")]
    pub ttl_seconds: Option<u64>,
    #[serde(default, alias = "requestContext", alias = "request")]
    pub request: Option<RequestContext>,
    #[serde(default)]
    pub state: Option<serde_json::Value>,
}

impl SessionManager {
    pub fn new(
        store: Arc<dyn SessionStore>,
        default_ttl_seconds: u64,
        max_ttl_seconds: u64,
        rbac: Option<Arc<RbacManager>>,
        hardening: SessionHardeningConfig,
    ) -> Self {
        Self {
            store,
            default_ttl_seconds,
            max_ttl_seconds,
            rbac,
            hardening,
        }
    }

    pub fn create_session(
        &self,
        identity: IdentityPrincipal,
        options: Option<CreateSessionOptions>,
    ) -> Result<SessionContext> {
        let now = Utc::now();
        let options = options.unwrap_or_default();

        let parent_session_id = if self.hardening.rotate_on_create {
            let sessions = self.store.list_by_user(&identity.id)?;
            let parent = sessions.first().map(|s| s.session.session_id.clone());
            for record in sessions {
                let _ = self.terminate_session(&record.session.session_id, Some("rotation"));
            }
            parent
        } else {
            None
        };

        let ttl = options.ttl_seconds.unwrap_or(self.default_ttl_seconds);
        let ttl = ttl.min(self.max_ttl_seconds).max(1);

        let expires_at = now + Duration::seconds(ttl as i64);

        let mut state: Option<HashMap<String, serde_json::Value>> = match options.state {
            Some(serde_json::Value::Object(obj)) => Some(obj.into_iter().collect()),
            Some(_) => None,
            None => None,
        };

        if self.hardening.bind_user_agent
            || self.hardening.bind_source_ip
            || self.hardening.bind_country
        {
            let request = options.request.as_ref().ok_or_else(|| {
                SessionError::InvalidBinding("request_context_required_for_binding".to_string())
            })?;

            let state_map = state.get_or_insert_with(HashMap::new);

            if self.hardening.bind_user_agent {
                let ua = request.user_agent.as_deref().ok_or_else(|| {
                    SessionError::InvalidBinding("missing_user_agent".to_string())
                })?;
                state_map.insert(
                    "bound_user_agent_hash".to_string(),
                    serde_json::Value::String(hush_core::sha256(ua.as_bytes()).to_hex()),
                );
            }

            if self.hardening.bind_source_ip {
                let ip = request
                    .source_ip
                    .as_deref()
                    .ok_or_else(|| SessionError::InvalidBinding("missing_source_ip".to_string()))?;
                state_map.insert(
                    "bound_source_ip".to_string(),
                    serde_json::Value::String(ip.to_string()),
                );
            }

            if self.hardening.bind_country {
                let country = request
                    .geo_location
                    .as_ref()
                    .and_then(|g| g.country.as_deref())
                    .ok_or_else(|| SessionError::InvalidBinding("missing_country".to_string()))?;
                state_map.insert(
                    "bound_country".to_string(),
                    serde_json::Value::String(country.to_string()),
                );
            }
        }

        let effective_roles = match self.rbac.as_ref() {
            Some(rbac) => rbac.effective_roles_for_identity(&identity),
            None => identity.roles.clone(),
        };

        let effective_permissions = match self.rbac.as_ref() {
            Some(rbac) => rbac
                .effective_permission_strings_for_roles(&effective_roles)
                .unwrap_or_default(),
            None => Vec::new(),
        };

        let session = SessionContext {
            session_id: uuid::Uuid::new_v4().to_string(),
            identity: identity.clone(),
            created_at: now.to_rfc3339(),
            last_activity_at: now.to_rfc3339(),
            expires_at: expires_at.to_rfc3339(),
            organization: None,
            effective_roles,
            effective_permissions,
            request: options.request.clone(),
            metadata: Some(SessionMetadata {
                auth_method: identity.auth_method.clone().unwrap_or(AuthMethod::Sso),
                idp_issuer: Some(identity.issuer.clone()),
                token_id: None,
                parent_session_id,
                tags: None,
            }),
            state,
        };

        self.store.set(&StoredSession {
            session: session.clone(),
            terminated_at: None,
        })?;

        Ok(session)
    }

    pub fn get_session(&self, session_id: &str) -> Result<Option<SessionContext>> {
        let Some(record) = self.store.get(session_id)? else {
            return Ok(None);
        };

        if record.terminated_at.is_some() {
            return Ok(None);
        }

        let now = Utc::now();
        if is_expired(&record.session, now) {
            return Ok(None);
        }

        Ok(Some(record.session))
    }

    pub fn validate_session(&self, session_id: &str) -> Result<SessionValidationResult> {
        let Some(record) = self.store.get(session_id)? else {
            return Ok(SessionValidationResult {
                valid: false,
                reason: Some(InvalidSessionReason::NotFound),
                session: None,
                remaining_ttl_seconds: None,
            });
        };

        if record.terminated_at.is_some() {
            return Ok(SessionValidationResult {
                valid: false,
                reason: Some(InvalidSessionReason::Terminated),
                session: None,
                remaining_ttl_seconds: None,
            });
        }

        let now = Utc::now();
        let expires_at = parse_rfc3339(&record.session.expires_at)?;
        if now >= expires_at {
            return Ok(SessionValidationResult {
                valid: false,
                reason: Some(InvalidSessionReason::Expired),
                session: None,
                remaining_ttl_seconds: None,
            });
        }

        let remaining = (expires_at - now).num_seconds().max(0) as u64;

        Ok(SessionValidationResult {
            valid: true,
            reason: None,
            session: Some(record.session),
            remaining_ttl_seconds: Some(remaining),
        })
    }

    pub fn touch_session(&self, session_id: &str) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let _ = self.store.update(
            session_id,
            SessionUpdates {
                last_activity_at: Some(now),
                ..Default::default()
            },
        )?;
        Ok(())
    }

    pub fn terminate_session(&self, session_id: &str, _reason: Option<&str>) -> Result<bool> {
        let now = Utc::now().to_rfc3339();
        let updated = self.store.update(
            session_id,
            SessionUpdates {
                terminated_at: Some(now),
                ..Default::default()
            },
        )?;
        Ok(updated.is_some())
    }

    pub fn terminate_sessions_for_user(&self, user_id: &str, reason: Option<&str>) -> Result<u64> {
        let sessions = self.store.list_by_user(user_id)?;
        let mut count = 0u64;
        for record in sessions {
            if self.terminate_session(&record.session.session_id, reason)? {
                count = count.saturating_add(1);
            }
        }
        Ok(count)
    }

    pub fn create_guard_context(
        &self,
        session: &SessionContext,
        request: Option<&RequestContext>,
    ) -> GuardContext {
        let mut ctx = GuardContext::new().with_session_id(session.session_id.clone());
        ctx = ctx
            .with_identity(session.identity.clone())
            .with_roles(session.effective_roles.clone())
            .with_permissions(session.effective_permissions.clone())
            .with_session(session.clone());

        if let Some(request) = request.cloned().or_else(|| session.request.clone()) {
            ctx = ctx.with_request(request);
        }

        ctx
    }

    pub fn validate_session_binding(
        &self,
        session: &SessionContext,
        request: &RequestContext,
    ) -> Result<()> {
        let Some(state) = session.state.as_ref() else {
            return Ok(());
        };

        if let Some(expected) = state.get("bound_user_agent_hash").and_then(|v| v.as_str()) {
            let ua = request
                .user_agent
                .as_deref()
                .ok_or_else(|| SessionError::InvalidBinding("missing_user_agent".to_string()))?;
            let got = hush_core::sha256(ua.as_bytes()).to_hex();
            if got != expected {
                return Err(SessionError::InvalidBinding(
                    "user_agent_mismatch".to_string(),
                ));
            }
        }

        if let Some(expected) = state.get("bound_source_ip").and_then(|v| v.as_str()) {
            let ip = request
                .source_ip
                .as_deref()
                .ok_or_else(|| SessionError::InvalidBinding("missing_source_ip".to_string()))?;
            if ip != expected {
                return Err(SessionError::InvalidBinding(
                    "source_ip_mismatch".to_string(),
                ));
            }
        }

        if let Some(expected) = state.get("bound_country").and_then(|v| v.as_str()) {
            let country = request
                .geo_location
                .as_ref()
                .and_then(|g| g.country.as_deref())
                .ok_or_else(|| SessionError::InvalidBinding("missing_country".to_string()))?;
            if country != expected {
                return Err(SessionError::InvalidBinding("country_mismatch".to_string()));
            }
        }

        Ok(())
    }
}

fn apply_updates(record: &mut StoredSession, updates: SessionUpdates) {
    if let Some(value) = updates.last_activity_at {
        record.session.last_activity_at = value;
    }
    if let Some(value) = updates.expires_at {
        record.session.expires_at = value;
    }
    if let Some(value) = updates.terminated_at {
        record.terminated_at = Some(value);
    }
    if let Some(value) = updates.request {
        record.session.request = Some(value);
    }
    if let Some(value) = updates.state {
        record.session.state = Some(value);
    }
}

fn is_expired(session: &SessionContext, now: DateTime<Utc>) -> bool {
    match parse_rfc3339(&session.expires_at) {
        Ok(expires_at) => now >= expires_at,
        Err(_) => true,
    }
}

fn parse_rfc3339(value: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|_| SessionError::InvalidTimestamp(value.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_identity() -> IdentityPrincipal {
        IdentityPrincipal {
            id: "user-1".to_string(),
            provider: clawdstrike::IdentityProvider::Oidc,
            issuer: "https://issuer.example".to_string(),
            display_name: None,
            email: None,
            email_verified: None,
            organization_id: Some("org-1".to_string()),
            teams: Vec::new(),
            roles: Vec::new(),
            attributes: std::collections::HashMap::new(),
            authenticated_at: chrono::Utc::now().to_rfc3339(),
            auth_method: None,
            expires_at: None,
        }
    }

    fn test_request(user_agent: &str, source_ip: &str) -> RequestContext {
        RequestContext {
            request_id: uuid::Uuid::new_v4().to_string(),
            source_ip: Some(source_ip.to_string()),
            user_agent: Some(user_agent.to_string()),
            geo_location: None,
            is_vpn: None,
            is_corporate_network: None,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    #[test]
    fn session_binding_user_agent_mismatch_denies() {
        let store = Arc::new(InMemorySessionStore::new());
        let manager = SessionManager::new(
            store,
            3600,
            86_400,
            None,
            SessionHardeningConfig {
                bind_user_agent: true,
                ..Default::default()
            },
        );

        let session = manager
            .create_session(
                test_identity(),
                Some(CreateSessionOptions {
                    ttl_seconds: Some(3600),
                    request: Some(test_request("ua-1", "10.0.0.1")),
                    state: None,
                }),
            )
            .expect("create");

        manager
            .validate_session_binding(&session, &test_request("ua-1", "10.0.0.1"))
            .expect("ok");

        let err = manager
            .validate_session_binding(&session, &test_request("ua-2", "10.0.0.1"))
            .expect_err("mismatch");
        assert!(matches!(err, SessionError::InvalidBinding(_)));
    }

    #[test]
    fn rotate_on_create_terminates_existing_sessions() {
        let store = Arc::new(InMemorySessionStore::new());
        let manager = SessionManager::new(
            store.clone(),
            3600,
            86_400,
            None,
            SessionHardeningConfig {
                rotate_on_create: true,
                ..Default::default()
            },
        );

        let s1 = manager
            .create_session(test_identity(), None)
            .expect("create1");
        assert!(manager.get_session(&s1.session_id).expect("get1").is_some());

        let _s2 = manager
            .create_session(test_identity(), None)
            .expect("create2");
        assert!(manager.get_session(&s1.session_id).expect("get1").is_none());
    }
}
