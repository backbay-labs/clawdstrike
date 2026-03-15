//! SQLite-backed control-plane state (sessions, RBAC, scoped policies, ...).

mod schema;

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};

#[derive(Debug, thiserror::Error)]
pub enum ControlDbError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("gap: {0}")]
    Gap(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("invariant violation: {0}")]
    Invariant(String),
}

pub type Result<T> = std::result::Result<T, ControlDbError>;

/// Deduplication window for blob pin requests: 1 hour in milliseconds.
const DEDUP_WINDOW_MS: u64 = 3_600_000;

#[derive(Clone, Debug)]
pub struct SwarmBlobRefInput {
    pub blob_id: String,
    pub digest: String,
    pub media_type: String,
    pub byte_length: u64,
    pub publish_json: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SwarmFindingInput {
    pub feed_id: String,
    pub issuer_id: String,
    pub finding_id: String,
    pub feed_seq: u64,
    pub published_at: u64,
    pub envelope_hash: String,
    pub envelope_json: String,
    pub announced_at: u64,
    pub blob_refs: Vec<SwarmBlobRefInput>,
}

#[derive(Clone, Debug)]
pub struct SwarmTargetReferenceInput {
    pub schema: String,
    pub id: String,
    pub digest: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SwarmRevocationInput {
    pub feed_id: String,
    pub issuer_id: String,
    pub revocation_id: String,
    pub feed_seq: u64,
    pub issued_at: u64,
    pub action: String,
    pub target: SwarmTargetReferenceInput,
    pub replacement: Option<SwarmTargetReferenceInput>,
    pub envelope_hash: String,
    pub envelope_json: String,
    pub announced_at: u64,
}

#[derive(Clone, Debug)]
pub struct SwarmHeadRecord {
    pub feed_id: String,
    pub issuer_id: String,
    pub head_seq: u64,
    pub head_envelope_hash: String,
    pub entry_count: u64,
    pub announced_at: u64,
}

#[derive(Clone, Debug)]
pub struct SwarmAppendOutcome {
    pub idempotent: bool,
    pub head: SwarmHeadRecord,
}

#[derive(Clone, Debug)]
pub struct SwarmStoredEnvelope {
    pub feed_seq: u64,
    pub envelope_json: String,
}

#[derive(Clone, Debug)]
pub struct SwarmBlobRefRecord {
    pub digest: String,
    pub feed_id: String,
    pub issuer_id: String,
    pub feed_seq: u64,
    pub finding_id: String,
    pub blob_id: String,
    pub media_type: String,
    pub byte_length: u64,
    pub publish_json: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SwarmPinRequestRecord {
    pub request_id: String,
    pub digest: String,
    pub actor: Option<String>,
    pub note: Option<String>,
    pub request_json: String,
    pub status: String,
    pub requested_at: u64,
}

pub struct ControlDb {
    conn: Mutex<Connection>,
}

impl ControlDb {
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;
        conn.execute_batch(schema::CREATE_TABLES)?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    #[cfg(test)]
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(schema::CREATE_TABLES)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn lock_conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|err| err.into_inner())
    }

    /// Spawn a blocking DB operation on the tokio blocking pool.
    ///
    /// Requires an `Arc<ControlDb>` so the DB handle can be moved to the blocking thread.
    pub async fn spawn_blocking<F, T>(
        self: &std::sync::Arc<Self>,
        f: F,
    ) -> std::result::Result<T, ControlDbError>
    where
        F: FnOnce(&Connection) -> std::result::Result<T, ControlDbError> + Send + 'static,
        T: Send + 'static,
    {
        let db = self.clone();
        tokio::task::spawn_blocking(move || {
            let conn = db.lock_conn();
            f(&conn)
        })
        .await
        .map_err(|e| ControlDbError::Io(std::io::Error::other(e)))?
    }

    /// Spawn a blocking DB operation requiring mutable access to the connection.
    pub async fn spawn_blocking_mut<F, T>(
        self: &std::sync::Arc<Self>,
        f: F,
    ) -> std::result::Result<T, ControlDbError>
    where
        F: FnOnce(&mut Connection) -> std::result::Result<T, ControlDbError> + Send + 'static,
        T: Send + 'static,
    {
        let db = self.clone();
        tokio::task::spawn_blocking(move || {
            let mut conn = db.lock_conn();
            f(&mut conn)
        })
        .await
        .map_err(|e| ControlDbError::Io(std::io::Error::other(e)))?
    }

    pub async fn append_swarm_finding(
        self: &std::sync::Arc<Self>,
        input: SwarmFindingInput,
    ) -> Result<SwarmAppendOutcome> {
        self.spawn_blocking_mut(move |conn| Self::append_swarm_finding_inner(conn, input))
            .await
    }

    pub async fn append_swarm_revocation(
        self: &std::sync::Arc<Self>,
        input: SwarmRevocationInput,
    ) -> Result<SwarmAppendOutcome> {
        self.spawn_blocking_mut(move |conn| Self::append_swarm_revocation_inner(conn, input))
            .await
    }

    pub async fn get_swarm_head(
        self: &std::sync::Arc<Self>,
        feed_id: String,
        issuer_id: String,
    ) -> Result<Option<SwarmHeadRecord>> {
        self.spawn_blocking(move |conn| {
            Self::load_consistent_swarm_head(conn, &feed_id, &issuer_id)
        })
        .await
    }

    pub async fn get_swarm_revocation_head(
        self: &std::sync::Arc<Self>,
        feed_id: String,
        issuer_id: String,
    ) -> Result<Option<SwarmHeadRecord>> {
        self.spawn_blocking(move |conn| {
            Self::load_consistent_swarm_revocation_head(conn, &feed_id, &issuer_id)
        })
        .await
    }

    pub async fn replay_swarm_findings(
        self: &std::sync::Arc<Self>,
        feed_id: String,
        issuer_id: String,
        from_seq: u64,
        to_seq: u64,
    ) -> Result<Vec<SwarmStoredEnvelope>> {
        self.spawn_blocking(move |conn| {
            let _ = Self::load_consistent_swarm_head(conn, &feed_id, &issuer_id)?;
            let mut stmt = conn.prepare(
                r#"
                SELECT feed_seq, envelope_json
                FROM swarm_findings
                WHERE feed_id = ?1 AND issuer_id = ?2 AND feed_seq BETWEEN ?3 AND ?4
                ORDER BY feed_seq ASC
                "#,
            )?;
            let mut rows = stmt.query(params![
                feed_id,
                issuer_id,
                i64_from_u64(from_seq)?,
                i64_from_u64(to_seq)?,
            ])?;
            let mut out = Vec::new();
            while let Some(row) = rows.next()? {
                out.push(SwarmStoredEnvelope {
                    feed_seq: u64_from_i64(row.get::<_, i64>(0)?)?,
                    envelope_json: row.get(1)?,
                });
            }
            Ok(out)
        })
        .await
    }

    pub async fn replay_swarm_revocations(
        self: &std::sync::Arc<Self>,
        feed_id: String,
        issuer_id: String,
        from_seq: u64,
        to_seq: u64,
    ) -> Result<Vec<SwarmStoredEnvelope>> {
        self.spawn_blocking(move |conn| {
            let _ = Self::load_consistent_swarm_revocation_head(conn, &feed_id, &issuer_id)?;
            let mut stmt = conn.prepare(
                r#"
                SELECT feed_seq, envelope_json
                FROM swarm_revocations
                WHERE feed_id = ?1 AND issuer_id = ?2 AND feed_seq BETWEEN ?3 AND ?4
                ORDER BY feed_seq ASC
                "#,
            )?;
            let mut rows = stmt.query(params![
                feed_id,
                issuer_id,
                i64_from_u64(from_seq)?,
                i64_from_u64(to_seq)?,
            ])?;
            let mut out = Vec::new();
            while let Some(row) = rows.next()? {
                out.push(SwarmStoredEnvelope {
                    feed_seq: u64_from_i64(row.get::<_, i64>(0)?)?,
                    envelope_json: row.get(1)?,
                });
            }
            Ok(out)
        })
        .await
    }

    pub async fn lookup_swarm_blob_refs(
        self: &std::sync::Arc<Self>,
        digest: String,
    ) -> Result<Vec<SwarmBlobRefRecord>> {
        self.spawn_blocking(move |conn| {
            let mut stmt = conn.prepare(
                r#"
                SELECT digest, feed_id, issuer_id, feed_seq, finding_id, blob_id,
                       media_type, byte_length, publish_json
                FROM swarm_blob_refs
                WHERE digest = ?1
                ORDER BY feed_id ASC, issuer_id ASC, feed_seq ASC, blob_id ASC
                LIMIT 200
                "#,
            )?;
            let mut rows = stmt.query(params![digest])?;
            let mut out = Vec::new();
            while let Some(row) = rows.next()? {
                out.push(SwarmBlobRefRecord {
                    digest: row.get(0)?,
                    feed_id: row.get(1)?,
                    issuer_id: row.get(2)?,
                    feed_seq: u64_from_i64(row.get::<_, i64>(3)?)?,
                    finding_id: row.get(4)?,
                    blob_id: row.get(5)?,
                    media_type: row.get(6)?,
                    byte_length: u64_from_i64(row.get::<_, i64>(7)?)?,
                    publish_json: row.get(8)?,
                });
            }
            Ok(out)
        })
        .await
    }

    pub async fn record_swarm_blob_pin_request(
        self: &std::sync::Arc<Self>,
        digest: String,
        actor: Option<String>,
        note: Option<String>,
        request_json: String,
    ) -> Result<SwarmPinRequestRecord> {
        self.spawn_blocking_mut(move |conn| {
            Self::record_swarm_blob_pin_request_inner(conn, digest, actor, note, request_json)
        })
        .await
    }

    fn record_swarm_blob_pin_request_inner(
        conn: &mut Connection,
        digest: String,
        actor: Option<String>,
        note: Option<String>,
        request_json: String,
    ) -> Result<SwarmPinRequestRecord> {
        let now = now_millis_u64()?;
        let dedup_cutoff = now.saturating_sub(DEDUP_WINDOW_MS);

        // Check for a recent pin request with the same (digest, actor) within
        // the deduplication window.  If one exists, return it instead of
        // inserting a duplicate row.
        let existing: Option<SwarmPinRequestRecord> = conn
            .query_row(
                r#"
                SELECT request_id, digest, actor, note, request_json, status, requested_at
                FROM swarm_blob_pin_requests
                WHERE digest = ?1
                  AND ((?2 IS NULL AND actor IS NULL) OR actor = ?2)
                  AND requested_at >= ?3
                ORDER BY requested_at DESC
                LIMIT 1
                "#,
                params![&digest, &actor, i64_from_u64(dedup_cutoff)?],
                |row| {
                    Ok(SwarmPinRequestRecord {
                        request_id: row.get(0)?,
                        digest: row.get(1)?,
                        actor: row.get(2)?,
                        note: row.get(3)?,
                        request_json: row.get(4)?,
                        status: row.get(5)?,
                        requested_at: u64_from_i64(row.get::<_, i64>(6)?).unwrap_or(0),
                    })
                },
            )
            .optional()?;

        if let Some(mut record) = existing {
            record.status = "deduplicated".to_string();
            return Ok(record);
        }

        let request = SwarmPinRequestRecord {
            request_id: uuid::Uuid::new_v4().to_string(),
            digest,
            actor,
            note,
            request_json,
            status: "recorded".to_string(),
            requested_at: now,
        };
        conn.execute(
            r#"
            INSERT INTO swarm_blob_pin_requests (
                request_id,
                digest,
                actor,
                note,
                request_json,
                status,
                requested_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
            params![
                &request.request_id,
                &request.digest,
                &request.actor,
                &request.note,
                &request.request_json,
                &request.status,
                i64_from_u64(request.requested_at)?,
            ],
        )?;
        Ok(request)
    }

    pub async fn get_control_metadata(
        self: &std::sync::Arc<Self>,
        key: String,
    ) -> Result<Option<String>> {
        self.spawn_blocking(move |conn| {
            conn.query_row(
                "SELECT value FROM control_metadata WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()
            .map_err(ControlDbError::from)
        })
        .await
    }

    pub async fn set_control_metadata(
        self: &std::sync::Arc<Self>,
        key: String,
        value: String,
    ) -> Result<()> {
        self.spawn_blocking_mut(move |conn| {
            conn.execute(
                r#"
                INSERT INTO control_metadata (key, value, updated_at)
                VALUES (?1, ?2, datetime('now'))
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    updated_at = datetime('now')
                "#,
                params![key, value],
            )?;
            Ok(())
        })
        .await
    }

    fn append_swarm_finding_inner(
        conn: &mut Connection,
        input: SwarmFindingInput,
    ) -> Result<SwarmAppendOutcome> {
        let SwarmFindingInput {
            feed_id,
            issuer_id,
            finding_id,
            feed_seq,
            published_at,
            envelope_hash,
            envelope_json,
            announced_at,
            blob_refs,
        } = input;
        let tx = conn.transaction()?;

        let existing_json: Option<String> = tx
            .query_row(
                r#"
                SELECT envelope_json
                FROM swarm_findings
                WHERE feed_id = ?1 AND issuer_id = ?2 AND feed_seq = ?3
                "#,
                params![&feed_id, &issuer_id, i64_from_u64(feed_seq)?],
                |row| row.get(0),
            )
            .optional()?;

        if let Some(existing_json) = existing_json {
            let head =
                Self::load_consistent_swarm_head(&tx, &feed_id, &issuer_id)?.ok_or_else(|| {
                    ControlDbError::Invariant(
                        "swarm head missing for existing feed sequence".to_string(),
                    )
                })?;
            if existing_json == envelope_json {
                tx.commit()?;
                return Ok(SwarmAppendOutcome {
                    idempotent: true,
                    head,
                });
            }
            return Err(ControlDbError::Conflict(format!(
                "feed sequence {} already exists with different payload",
                feed_seq
            )));
        }

        let head_before = Self::load_consistent_swarm_head(&tx, &feed_id, &issuer_id)?;
        match head_before {
            None if feed_seq != 1 => {
                return Err(ControlDbError::Gap(
                    "first feed sequence must be 1".to_string(),
                ));
            }
            Some(ref head) if feed_seq != head.head_seq + 1 => {
                return Err(ControlDbError::Gap(format!(
                    "expected next feed sequence {}, got {}",
                    head.head_seq + 1,
                    feed_seq
                )));
            }
            _ => {}
        }

        tx.execute(
            r#"
            INSERT INTO swarm_findings (
                feed_id,
                issuer_id,
                feed_seq,
                finding_id,
                published_at,
                envelope_hash,
                envelope_json
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
            params![
                &feed_id,
                &issuer_id,
                i64_from_u64(feed_seq)?,
                &finding_id,
                i64_from_u64(published_at)?,
                &envelope_hash,
                &envelope_json,
            ],
        )?;

        for blob_ref in blob_refs {
            tx.execute(
                r#"
                INSERT INTO swarm_blob_refs (
                    digest,
                    feed_id,
                    issuer_id,
                    feed_seq,
                    finding_id,
                    blob_id,
                    media_type,
                    byte_length,
                    publish_json
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                "#,
                params![
                    blob_ref.digest,
                    &feed_id,
                    &issuer_id,
                    i64_from_u64(feed_seq)?,
                    &finding_id,
                    blob_ref.blob_id,
                    blob_ref.media_type,
                    i64_from_u64(blob_ref.byte_length)?,
                    blob_ref.publish_json,
                ],
            )?;
        }

        let head = SwarmHeadRecord {
            feed_id,
            issuer_id,
            head_seq: feed_seq,
            head_envelope_hash: envelope_hash,
            entry_count: feed_seq,
            announced_at,
        };

        tx.execute(
            r#"
            INSERT INTO swarm_feed_heads (
                feed_id,
                issuer_id,
                head_seq,
                head_envelope_hash,
                entry_count,
                announced_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT(feed_id, issuer_id) DO UPDATE SET
                head_seq = excluded.head_seq,
                head_envelope_hash = excluded.head_envelope_hash,
                entry_count = excluded.entry_count,
                announced_at = excluded.announced_at,
                updated_at = datetime('now')
            "#,
            params![
                &head.feed_id,
                &head.issuer_id,
                i64_from_u64(head.head_seq)?,
                &head.head_envelope_hash,
                i64_from_u64(head.entry_count)?,
                i64_from_u64(head.announced_at)?,
            ],
        )?;

        tx.commit()?;
        Ok(SwarmAppendOutcome {
            idempotent: false,
            head,
        })
    }

    fn append_swarm_revocation_inner(
        conn: &mut Connection,
        input: SwarmRevocationInput,
    ) -> Result<SwarmAppendOutcome> {
        let SwarmRevocationInput {
            feed_id,
            issuer_id,
            revocation_id,
            feed_seq,
            issued_at,
            action,
            target,
            replacement,
            envelope_hash,
            envelope_json,
            announced_at,
        } = input;
        let tx = conn.transaction()?;

        let existing_json: Option<String> = tx
            .query_row(
                r#"
                SELECT envelope_json
                FROM swarm_revocations
                WHERE feed_id = ?1 AND issuer_id = ?2 AND feed_seq = ?3
                "#,
                params![&feed_id, &issuer_id, i64_from_u64(feed_seq)?],
                |row| row.get(0),
            )
            .optional()?;

        if let Some(existing_json) = existing_json {
            let head = Self::load_consistent_swarm_revocation_head(&tx, &feed_id, &issuer_id)?
                .ok_or_else(|| {
                    ControlDbError::Invariant(
                        "swarm revocation head missing for existing feed sequence".to_string(),
                    )
                })?;
            if existing_json == envelope_json {
                tx.commit()?;
                return Ok(SwarmAppendOutcome {
                    idempotent: true,
                    head,
                });
            }
            return Err(ControlDbError::Conflict(format!(
                "feed sequence {} already exists with different payload",
                feed_seq
            )));
        }

        let head_before = Self::load_consistent_swarm_revocation_head(&tx, &feed_id, &issuer_id)?;
        match head_before {
            None if feed_seq != 1 => {
                return Err(ControlDbError::Gap(
                    "first feed sequence must be 1".to_string(),
                ));
            }
            Some(ref head) if feed_seq != head.head_seq + 1 => {
                return Err(ControlDbError::Gap(format!(
                    "expected next feed sequence {}, got {}",
                    head.head_seq + 1,
                    feed_seq
                )));
            }
            _ => {}
        }

        let target_digest = target.digest.unwrap_or_default();
        let replacement_schema = replacement.as_ref().map(|value| value.schema.as_str());
        let replacement_id = replacement.as_ref().map(|value| value.id.as_str());
        let replacement_digest = replacement
            .as_ref()
            .and_then(|value| value.digest.as_deref());

        tx.execute(
            r#"
            INSERT INTO swarm_revocations (
                feed_id,
                issuer_id,
                feed_seq,
                revocation_id,
                issued_at,
                action,
                target_schema,
                target_id,
                target_digest,
                replacement_schema,
                replacement_id,
                replacement_digest,
                envelope_hash,
                envelope_json
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
            "#,
            params![
                &feed_id,
                &issuer_id,
                i64_from_u64(feed_seq)?,
                &revocation_id,
                i64_from_u64(issued_at)?,
                &action,
                &target.schema,
                &target.id,
                &target_digest,
                replacement_schema,
                replacement_id,
                replacement_digest,
                &envelope_hash,
                &envelope_json,
            ],
        )?;

        tx.execute(
            r#"
            INSERT INTO swarm_revocation_targets (
                feed_id,
                issuer_id,
                target_schema,
                target_id,
                target_digest,
                current_action,
                replacement_schema,
                replacement_id,
                replacement_digest,
                source_revocation_id,
                source_feed_seq,
                issued_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
            ON CONFLICT(feed_id, issuer_id, target_schema, target_id, target_digest) DO UPDATE SET
                current_action = excluded.current_action,
                replacement_schema = excluded.replacement_schema,
                replacement_id = excluded.replacement_id,
                replacement_digest = excluded.replacement_digest,
                source_revocation_id = excluded.source_revocation_id,
                source_feed_seq = excluded.source_feed_seq,
                issued_at = excluded.issued_at,
                updated_at = datetime('now')
            "#,
            params![
                &feed_id,
                &issuer_id,
                &target.schema,
                &target.id,
                &target_digest,
                &action,
                replacement_schema,
                replacement_id,
                replacement_digest,
                &revocation_id,
                i64_from_u64(feed_seq)?,
                i64_from_u64(issued_at)?,
            ],
        )?;

        let head = SwarmHeadRecord {
            feed_id,
            issuer_id,
            head_seq: feed_seq,
            head_envelope_hash: envelope_hash,
            entry_count: feed_seq,
            announced_at,
        };

        tx.execute(
            r#"
            INSERT INTO swarm_revocation_heads (
                feed_id,
                issuer_id,
                head_seq,
                head_envelope_hash,
                entry_count,
                announced_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT(feed_id, issuer_id) DO UPDATE SET
                head_seq = excluded.head_seq,
                head_envelope_hash = excluded.head_envelope_hash,
                entry_count = excluded.entry_count,
                announced_at = excluded.announced_at,
                updated_at = datetime('now')
            "#,
            params![
                &head.feed_id,
                &head.issuer_id,
                i64_from_u64(head.head_seq)?,
                &head.head_envelope_hash,
                i64_from_u64(head.entry_count)?,
                i64_from_u64(head.announced_at)?,
            ],
        )?;

        tx.commit()?;
        Ok(SwarmAppendOutcome {
            idempotent: false,
            head,
        })
    }

    fn load_consistent_swarm_head(
        conn: &Connection,
        feed_id: &str,
        issuer_id: &str,
    ) -> Result<Option<SwarmHeadRecord>> {
        let finding_count = u64_from_i64(conn.query_row(
            r#"
            SELECT COUNT(*)
            FROM swarm_findings
            WHERE feed_id = ?1 AND issuer_id = ?2
            "#,
            params![feed_id, issuer_id],
            |row| row.get::<_, i64>(0),
        )?)?;
        let max_seq = conn
            .query_row(
                r#"
                SELECT MAX(feed_seq)
                FROM swarm_findings
                WHERE feed_id = ?1 AND issuer_id = ?2
                "#,
                params![feed_id, issuer_id],
                |row| row.get::<_, Option<i64>>(0),
            )
            .optional()?
            .flatten()
            .map(u64_from_i64)
            .transpose()?;

        let head_row = conn
            .query_row(
                r#"
                SELECT head_seq, head_envelope_hash, entry_count, announced_at
                FROM swarm_feed_heads
                WHERE feed_id = ?1 AND issuer_id = ?2
                "#,
                params![feed_id, issuer_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?;

        match (finding_count, max_seq, head_row) {
            (0, None, None) => Ok(None),
            (0, None, Some(_)) => Err(ControlDbError::Invariant(
                "swarm head exists without stored findings".to_string(),
            )),
            (
                count,
                Some(max_seq),
                Some((head_seq_raw, head_envelope_hash, entry_count_raw, announced_at_raw)),
            ) => {
                let head_seq = u64_from_i64(head_seq_raw)?;
                let entry_count = u64_from_i64(entry_count_raw)?;
                let announced_at = u64_from_i64(announced_at_raw)?;
                if head_seq != max_seq || entry_count != count || count != max_seq {
                    return Err(ControlDbError::Invariant(format!(
                        "swarm head is inconsistent for feed {feed_id} issuer {issuer_id}"
                    )));
                }
                let stored_hash: String = conn.query_row(
                    r#"
                    SELECT envelope_hash
                    FROM swarm_findings
                    WHERE feed_id = ?1 AND issuer_id = ?2 AND feed_seq = ?3
                    "#,
                    params![feed_id, issuer_id, i64_from_u64(head_seq)?],
                    |row| row.get(0),
                )?;
                if stored_hash != head_envelope_hash {
                    return Err(ControlDbError::Invariant(format!(
                        "swarm head hash mismatch for feed {feed_id} issuer {issuer_id}"
                    )));
                }
                Ok(Some(SwarmHeadRecord {
                    feed_id: feed_id.to_string(),
                    issuer_id: issuer_id.to_string(),
                    head_seq,
                    head_envelope_hash,
                    entry_count,
                    announced_at,
                }))
            }
            (count, Some(_), None) if count > 0 => Err(ControlDbError::Invariant(
                "stored findings exist without a materialized swarm head".to_string(),
            )),
            (count, None, Some(_)) if count > 0 => Err(ControlDbError::Invariant(
                "materialized swarm head exists without a max sequence".to_string(),
            )),
            _ => Err(ControlDbError::Invariant(
                "unexpected swarm head state".to_string(),
            )),
        }
    }

    fn load_consistent_swarm_revocation_head(
        conn: &Connection,
        feed_id: &str,
        issuer_id: &str,
    ) -> Result<Option<SwarmHeadRecord>> {
        let revocation_count = u64_from_i64(conn.query_row(
            r#"
            SELECT COUNT(*)
            FROM swarm_revocations
            WHERE feed_id = ?1 AND issuer_id = ?2
            "#,
            params![feed_id, issuer_id],
            |row| row.get::<_, i64>(0),
        )?)?;
        let max_seq = conn
            .query_row(
                r#"
                SELECT MAX(feed_seq)
                FROM swarm_revocations
                WHERE feed_id = ?1 AND issuer_id = ?2
                "#,
                params![feed_id, issuer_id],
                |row| row.get::<_, Option<i64>>(0),
            )
            .optional()?
            .flatten()
            .map(u64_from_i64)
            .transpose()?;

        let head_row = conn
            .query_row(
                r#"
                SELECT head_seq, head_envelope_hash, entry_count, announced_at
                FROM swarm_revocation_heads
                WHERE feed_id = ?1 AND issuer_id = ?2
                "#,
                params![feed_id, issuer_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?;

        match (revocation_count, max_seq, head_row) {
            (0, None, None) => Ok(None),
            (0, None, Some(_)) => Err(ControlDbError::Invariant(
                "swarm revocation head exists without stored revocations".to_string(),
            )),
            (
                count,
                Some(max_seq),
                Some((head_seq_raw, head_envelope_hash, entry_count_raw, announced_at_raw)),
            ) => {
                let head_seq = u64_from_i64(head_seq_raw)?;
                let entry_count = u64_from_i64(entry_count_raw)?;
                let announced_at = u64_from_i64(announced_at_raw)?;
                if head_seq != max_seq || entry_count != count || count != max_seq {
                    return Err(ControlDbError::Invariant(format!(
                        "swarm revocation head is inconsistent for feed {feed_id} issuer {issuer_id}"
                    )));
                }
                let stored_hash: String = conn.query_row(
                    r#"
                    SELECT envelope_hash
                    FROM swarm_revocations
                    WHERE feed_id = ?1 AND issuer_id = ?2 AND feed_seq = ?3
                    "#,
                    params![feed_id, issuer_id, i64_from_u64(head_seq)?],
                    |row| row.get(0),
                )?;
                if stored_hash != head_envelope_hash {
                    return Err(ControlDbError::Invariant(format!(
                        "swarm revocation head hash mismatch for feed {feed_id} issuer {issuer_id}"
                    )));
                }
                Ok(Some(SwarmHeadRecord {
                    feed_id: feed_id.to_string(),
                    issuer_id: issuer_id.to_string(),
                    head_seq,
                    head_envelope_hash,
                    entry_count,
                    announced_at,
                }))
            }
            (count, Some(_), None) if count > 0 => Err(ControlDbError::Invariant(
                "stored revocations exist without a materialized swarm revocation head".to_string(),
            )),
            (count, None, Some(_)) if count > 0 => Err(ControlDbError::Invariant(
                "materialized swarm revocation head exists without a max sequence".to_string(),
            )),
            _ => Err(ControlDbError::Invariant(
                "unexpected swarm revocation head state".to_string(),
            )),
        }
    }
}

fn i64_from_u64(value: u64) -> Result<i64> {
    i64::try_from(value)
        .map_err(|_| ControlDbError::Invariant("u64 value exceeded i64".to_string()))
}

fn u64_from_i64(value: i64) -> Result<u64> {
    u64::try_from(value)
        .map_err(|_| ControlDbError::Invariant("negative database integer".to_string()))
}

fn now_millis_u64() -> Result<u64> {
    u64::try_from(chrono::Utc::now().timestamp_millis())
        .map_err(|_| ControlDbError::Invariant("system clock predates unix epoch".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Arc;

    const TEST_ISSUER_ID: &str =
        "aegis:ed25519:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn swarm_finding_input(feed_seq: u64, finding_id: &str) -> SwarmFindingInput {
        SwarmFindingInput {
            feed_id: "fed.alpha".to_string(),
            issuer_id: TEST_ISSUER_ID.to_string(),
            finding_id: finding_id.to_string(),
            feed_seq,
            published_at: 1_715_000_000_000u64 + feed_seq,
            envelope_hash: format!("0x{feed_seq:064x}"),
            envelope_json: serde_json::to_string(&json!({
                "schema": "clawdstrike.swarm.finding_envelope.v1",
                "findingId": finding_id,
                "issuerId": TEST_ISSUER_ID,
                "feedId": "fed.alpha",
                "feedSeq": feed_seq,
                "publishedAt": 1_715_000_000_000u64 + feed_seq,
                "title": format!("Finding {feed_seq}"),
                "summary": format!("Summary {feed_seq}"),
                "severity": "high",
                "confidence": 0.9,
                "status": "confirmed",
                "signalCount": 1,
                "tags": ["repeat"],
                "relatedFindingIds": [],
                "blobRefs": []
            }))
            .expect("serialize finding"),
            announced_at: 1_715_000_000_000u64 + feed_seq,
            blob_refs: Vec::new(),
        }
    }

    #[tokio::test]
    async fn control_db_new_drops_legacy_swarm_finding_identity_index() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let db_path = tempdir.path().join("control.db");

        {
            let conn = Connection::open(&db_path).expect("open legacy db");
            conn.execute_batch(
                r#"
                CREATE TABLE swarm_findings (
                    feed_id TEXT NOT NULL,
                    issuer_id TEXT NOT NULL,
                    feed_seq INTEGER NOT NULL,
                    finding_id TEXT NOT NULL,
                    published_at INTEGER NOT NULL,
                    envelope_hash TEXT NOT NULL,
                    envelope_json TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    PRIMARY KEY (feed_id, issuer_id, feed_seq)
                );

                CREATE UNIQUE INDEX idx_swarm_findings_identity
                    ON swarm_findings(feed_id, issuer_id, finding_id);
                "#,
            )
            .expect("seed legacy schema");
        }

        let db = Arc::new(ControlDb::new(&db_path).expect("open upgraded control db"));

        {
            let conn = db.lock_conn();
            let legacy_index: Option<String> = conn
                .query_row(
                    "SELECT name FROM sqlite_master WHERE type = 'index' AND name = 'idx_swarm_findings_identity'",
                    [],
                    |row| row.get(0),
                )
                .optional()
                .expect("query sqlite_master");
            assert!(
                legacy_index.is_none(),
                "legacy unique findingId index should be dropped on startup"
            );
        }

        db.append_swarm_finding(swarm_finding_input(1, "fnd-repeat"))
            .await
            .expect("append seq 1");
        let second = db
            .append_swarm_finding(swarm_finding_input(2, "fnd-repeat"))
            .await
            .expect("append seq 2 with repeated finding id");

        assert_eq!(second.head.head_seq, 2);
        assert_eq!(second.head.entry_count, 2);
    }

    #[tokio::test]
    async fn control_db_spawn_blocking_helpers_execute_queries() {
        let db = Arc::new(ControlDb::in_memory().expect("db"));

        let one = db
            .spawn_blocking(|conn| {
                conn.query_row("SELECT 1", [], |row| row.get::<_, i64>(0))
                    .map_err(ControlDbError::from)
            })
            .await
            .expect("select one");
        assert_eq!(one, 1);

        db.spawn_blocking_mut(|conn| {
            conn.execute(
                "CREATE TABLE spawn_blocking_smoke (id INTEGER NOT NULL)",
                [],
            )?;
            conn.execute("INSERT INTO spawn_blocking_smoke (id) VALUES (7)", [])?;
            Ok(())
        })
        .await
        .expect("insert via spawn_blocking_mut");

        let id = db
            .spawn_blocking(|conn| {
                conn.query_row("SELECT id FROM spawn_blocking_smoke LIMIT 1", [], |row| {
                    row.get::<_, i64>(0)
                })
                .map_err(ControlDbError::from)
            })
            .await
            .expect("read inserted id");
        assert_eq!(id, 7);
    }

    #[tokio::test]
    async fn control_db_pin_request_deduplicates_and_metadata_roundtrips() {
        let db = Arc::new(ControlDb::in_memory().expect("db"));
        let digest = format!("0x{}", "a".repeat(64));

        let first = db
            .record_swarm_blob_pin_request(
                digest.clone(),
                Some("actor-1".to_string()),
                Some("initial request".to_string()),
                r#"{"digest":"test"}"#.to_string(),
            )
            .await
            .expect("first pin request");
        let second = db
            .record_swarm_blob_pin_request(
                digest,
                Some("actor-1".to_string()),
                None,
                r#"{"digest":"test-2"}"#.to_string(),
            )
            .await
            .expect("second pin request");

        assert_eq!(second.request_id, first.request_id);
        assert_eq!(second.status, "deduplicated");

        db.set_control_metadata("hub_mode".to_string(), "strict".to_string())
            .await
            .expect("set metadata");
        let metadata = db
            .get_control_metadata("hub_mode".to_string())
            .await
            .expect("get metadata");
        assert_eq!(metadata.as_deref(), Some("strict"));
    }
}
