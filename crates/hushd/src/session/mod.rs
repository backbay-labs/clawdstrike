//! Session management for identity-aware evaluation.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use clawdstrike::{GuardContext, IdentityPrincipal, RequestContext, SessionContext};
use serde::{Deserialize, Serialize};

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
        let changed = conn.execute("DELETE FROM sessions WHERE session_id = ?1", rusqlite::params![session_id])?;
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
        let changed = conn.execute("DELETE FROM sessions WHERE expires_at <= ?1", rusqlite::params![now])?;
        Ok(changed as u64)
    }
}

#[derive(Clone)]
pub struct SessionManager {
    store: Arc<dyn SessionStore>,
    default_ttl_seconds: u64,
    max_ttl_seconds: u64,
    rbac: Option<Arc<RbacManager>>,
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
    ) -> Self {
        Self {
            store,
            default_ttl_seconds,
            max_ttl_seconds,
            rbac,
        }
    }

    pub fn create_session(
        &self,
        identity: IdentityPrincipal,
        options: Option<CreateSessionOptions>,
    ) -> Result<SessionContext> {
        let now = Utc::now();
        let options = options.unwrap_or_default();

        let ttl = options.ttl_seconds.unwrap_or(self.default_ttl_seconds);
        let ttl = ttl.min(self.max_ttl_seconds).max(1);

        let expires_at = now + Duration::seconds(ttl as i64);

        let state = match options.state {
            Some(serde_json::Value::Object(obj)) => Some(obj.into_iter().collect()),
            Some(_) => None,
            None => None,
        };

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
            metadata: None,
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
        let _ = self
            .store
            .update(
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

    pub fn create_guard_context(&self, session: &SessionContext, request: Option<&RequestContext>) -> GuardContext {
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
