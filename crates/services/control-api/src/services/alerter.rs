use chrono::{DateTime, Utc};
use clawdstrike_ocsf::convert::from_detection_record::{
    persisted_detection_finding_to_ocsf, PersistedDetectionFindingInput,
};
use hunt_correlate::detection::{compile_rule_source, test_rule_source, DetectionRuleTestResult};
use hunt_query::query::EventSource;
use hunt_query::timeline::{NormalizedVerdict, TimelineEvent, TimelineEventKind};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sqlx::row::Row;
use uuid::Uuid;

use crate::db::{PgPool, PgRow};
use crate::error::ApiError;

#[derive(Debug, thiserror::Error)]
pub enum AlertError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::error::Error),
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("missing config field: {0}")]
    MissingConfig(&'static str),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateDetectionRule {
    pub name: String,
    pub description: Option<String>,
    pub severity: String,
    pub source_format: String,
    pub execution_mode: String,
    pub source_text: Option<String>,
    pub source_object: Option<Value>,
    pub tags: Option<Vec<String>>,
    pub mitre_attack: Option<Vec<String>>,
    pub enabled: Option<bool>,
    pub author: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateDetectionRule {
    pub name: Option<String>,
    pub description: Option<String>,
    pub severity: Option<String>,
    pub source_format: Option<String>,
    pub execution_mode: Option<String>,
    pub source_text: Option<String>,
    pub source_object: Option<Value>,
    pub tags: Option<Vec<String>>,
    pub mitre_attack: Option<Vec<String>>,
    pub enabled: Option<bool>,
    pub author: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleTestRequest {
    #[serde(default)]
    pub sample_events: Vec<SampleTimelineEvent>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SampleTimelineEvent {
    pub timestamp: String,
    pub source: String,
    pub summary: String,
    pub verdict: Option<String>,
    pub severity: Option<String>,
    pub action_type: Option<String>,
    pub process: Option<String>,
    pub namespace: Option<String>,
    pub pod: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateDetectionSuppression {
    pub rule_id: Option<Uuid>,
    pub finding_id: Option<Uuid>,
    pub scope: Option<Value>,
    pub match_criteria: Option<Value>,
    pub reason: String,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingActionRequest {
    pub reason: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallDetectionPackRequest {
    pub package_name: String,
    pub version: String,
    pub trust_level: String,
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivateDetectionPackRequest {
    #[serde(default)]
    pub activated_rules: Vec<Uuid>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DetectionRuleRecord {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub enabled: bool,
    pub severity: String,
    pub source_format: String,
    pub engine_kind: String,
    pub execution_mode: String,
    pub tags: Value,
    pub mitre_attack: Value,
    pub author: Option<String>,
    pub source_text: Option<String>,
    pub source_object: Option<Value>,
    pub compiled_artifact: Option<Value>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DetectionFindingRecord {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub rule_id: Uuid,
    pub rule_name: String,
    pub source_format: String,
    pub severity: String,
    pub status: String,
    pub title: String,
    pub summary: String,
    pub principal_id: Option<Uuid>,
    pub session_id: Option<String>,
    pub grant_id: Option<Uuid>,
    pub response_action_ids: Value,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub metadata: Value,
    pub evidence_refs: Vec<String>,
    pub ocsf: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct DetectionSuppressionRecord {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub rule_id: Option<Uuid>,
    pub finding_id: Option<Uuid>,
    pub scope: Value,
    pub match_criteria: Value,
    pub reason: String,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct InstalledDetectionPackRecord {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub package_name: String,
    pub version: String,
    pub package_type: String,
    pub metadata: Value,
    pub trust_level: String,
    pub installed_by: String,
    pub installed_at: DateTime<Utc>,
    pub activated_rules: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct DetectionRuleTestApiResponse {
    pub rule_id: Option<Uuid>,
    pub valid: bool,
    pub findings: Vec<hunt_correlate::detection::DetectionRuleTestFinding>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

/// A security event that may trigger alerts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub guard_name: String,
    pub verdict: String,
    pub agent_id: String,
    pub target: String,
    pub timestamp: String,
    pub severity: String,
}

#[derive(Debug, Clone)]
pub struct AlertConfig {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub channel: String,
    pub config: serde_json::Value,
    pub guard_filter: Option<Vec<String>>,
    pub severity_threshold: String,
    pub enabled: bool,
}

impl AlertConfig {
    pub fn from_row(row: PgRow) -> Result<Self, sqlx::error::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            name: row.try_get("name")?,
            channel: row.try_get("channel")?,
            config: row.try_get("config")?,
            guard_filter: row.try_get("guard_filter")?,
            severity_threshold: row.try_get("severity_threshold")?,
            enabled: row.try_get("enabled")?,
        })
    }
}

impl DetectionRuleRecord {
    fn from_row(row: PgRow) -> Result<Self, sqlx::error::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            name: row.try_get("name")?,
            description: row.try_get("description")?,
            enabled: row.try_get("enabled")?,
            severity: row.try_get("severity")?,
            source_format: row.try_get("source_format")?,
            engine_kind: row.try_get("engine_kind")?,
            execution_mode: row.try_get("execution_mode")?,
            tags: row.try_get("tags")?,
            mitre_attack: row.try_get("mitre_attack")?,
            author: row.try_get("author")?,
            source_text: row.try_get("source_text")?,
            source_object: row.try_get("source_object")?,
            compiled_artifact: row.try_get("compiled_artifact")?,
            created_by: row.try_get("created_by")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

impl DetectionSuppressionRecord {
    fn from_row(row: PgRow) -> Result<Self, sqlx::error::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            rule_id: row.try_get("rule_id")?,
            finding_id: row.try_get("finding_id")?,
            scope: row.try_get("scope")?,
            match_criteria: row.try_get("match_criteria")?,
            reason: row.try_get("reason")?,
            created_by: row.try_get("created_by")?,
            created_at: row.try_get("created_at")?,
            expires_at: row.try_get("expires_at")?,
            status: row.try_get("status")?,
        })
    }
}

impl InstalledDetectionPackRecord {
    fn from_row(row: PgRow) -> Result<Self, sqlx::error::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            package_name: row.try_get("package_name")?,
            version: row.try_get("version")?,
            package_type: row.try_get("package_type")?,
            metadata: row.try_get("metadata")?,
            trust_level: row.try_get("trust_level")?,
            installed_by: row.try_get("installed_by")?,
            installed_at: row.try_get("installed_at")?,
            activated_rules: row.try_get("activated_rules")?,
        })
    }
}

impl Serialize for AlertConfig {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("AlertConfig", 8)?;
        s.serialize_field("id", &self.id)?;
        s.serialize_field("tenant_id", &self.tenant_id)?;
        s.serialize_field("name", &self.name)?;
        s.serialize_field("channel", &self.channel)?;
        s.serialize_field("config", &self.config)?;
        s.serialize_field("guard_filter", &self.guard_filter)?;
        s.serialize_field("severity_threshold", &self.severity_threshold)?;
        s.serialize_field("enabled", &self.enabled)?;
        s.end()
    }
}

/// Service for dispatching alerts to PagerDuty, Slack, and webhooks.
#[derive(Clone)]
pub struct AlerterService {
    db: PgPool,
    http_client: reqwest::Client,
}

impl AlerterService {
    pub fn new(db: PgPool) -> Self {
        Self {
            db,
            http_client: reqwest::Client::new(),
        }
    }

    pub async fn create_detection_rule(
        &self,
        tenant_id: Uuid,
        actor: &str,
        req: CreateDetectionRule,
    ) -> Result<DetectionRuleRecord, ApiError> {
        validate_detection_severity(&req.severity)?;
        validate_execution_mode(&req.execution_mode)?;
        let source_text = normalize_source_text(
            &req.source_format,
            req.source_text,
            req.source_object.as_ref(),
        )?;
        let compilation = compile_rule_source(&req.source_format, &source_text)
            .map_err(|err| ApiError::BadRequest(err.to_string()))?;
        let row = sqlx::query::query(
            r#"INSERT INTO detection_rules (
                   tenant_id,
                   name,
                   description,
                   enabled,
                   severity,
                   source_format,
                   engine_kind,
                   execution_mode,
                   tags,
                   mitre_attack,
                   author,
                   source_text,
                   source_object,
                   compiled_artifact,
                   created_by
               )
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10::jsonb, $11, $12, $13, $14, $15)
               RETURNING *"#,
        )
        .bind(tenant_id)
        .bind(&req.name)
        .bind(req.description.as_deref())
        .bind(req.enabled.unwrap_or(true))
        .bind(&req.severity)
        .bind(&req.source_format)
        .bind(&compilation.engine_kind)
        .bind(&req.execution_mode)
        .bind(Value::Array(
            req.tags.unwrap_or_default().into_iter().map(Value::String).collect(),
        ))
        .bind(Value::Array(
            req.mitre_attack
                .unwrap_or_default()
                .into_iter()
                .map(Value::String)
                .collect(),
        ))
        .bind(req.author.as_deref())
        .bind(Some(source_text))
        .bind(req.source_object)
        .bind(Some(compilation.compiled_artifact))
        .bind(actor)
        .fetch_one(&self.db)
        .await
        .map_err(ApiError::Database)?;
        DetectionRuleRecord::from_row(row).map_err(ApiError::Database)
    }

    pub async fn list_detection_rules(
        &self,
        tenant_id: Uuid,
    ) -> Result<Vec<DetectionRuleRecord>, ApiError> {
        let rows = sqlx::query::query(
            "SELECT * FROM detection_rules WHERE tenant_id = $1 ORDER BY updated_at DESC",
        )
        .bind(tenant_id)
        .fetch_all(&self.db)
        .await
        .map_err(ApiError::Database)?;
        rows.into_iter()
            .map(DetectionRuleRecord::from_row)
            .collect::<Result<Vec<_>, _>>()
            .map_err(ApiError::Database)
    }

    pub async fn get_detection_rule(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<DetectionRuleRecord, ApiError> {
        let row =
            sqlx::query::query("SELECT * FROM detection_rules WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(id)
                .fetch_optional(&self.db)
                .await
                .map_err(ApiError::Database)?
                .ok_or(ApiError::NotFound)?;
        DetectionRuleRecord::from_row(row).map_err(ApiError::Database)
    }

    pub async fn update_detection_rule(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        _actor: &str,
        req: UpdateDetectionRule,
    ) -> Result<DetectionRuleRecord, ApiError> {
        let current = self.get_detection_rule(tenant_id, id).await?;
        let source_format = req
            .source_format
            .clone()
            .unwrap_or_else(|| current.source_format.clone());
        let severity = req
            .severity
            .clone()
            .unwrap_or_else(|| current.severity.clone());
        let execution_mode = req
            .execution_mode
            .clone()
            .unwrap_or_else(|| current.execution_mode.clone());
        validate_detection_severity(&severity)?;
        validate_execution_mode(&execution_mode)?;
        let source_text = if req.source_text.is_some()
            || req.source_format.is_some()
            || req.source_object.is_some()
        {
            normalize_source_text(
                &source_format,
                req.source_text.clone().or(current.source_text.clone()),
                req.source_object
                    .as_ref()
                    .or(current.source_object.as_ref()),
            )?
        } else {
            current.source_text.clone().unwrap_or_default()
        };
        let compilation = compile_rule_source(&source_format, &source_text)
            .map_err(|err| ApiError::BadRequest(err.to_string()))?;
        let row = sqlx::query::query(
            r#"UPDATE detection_rules
               SET name = $3,
                   description = $4,
                   enabled = $5,
                   severity = $6,
                   source_format = $7,
                   engine_kind = $8,
                   execution_mode = $9,
                   tags = $10::jsonb,
                   mitre_attack = $11::jsonb,
                   author = $12,
                   source_text = $13,
                   source_object = $14,
                   compiled_artifact = $15,
                   updated_at = now()
               WHERE tenant_id = $1 AND id = $2
               RETURNING *"#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(req.name.as_deref().unwrap_or(&current.name))
        .bind(
            req.description
                .as_deref()
                .or(current.description.as_deref()),
        )
        .bind(req.enabled.unwrap_or(current.enabled))
        .bind(&severity)
        .bind(&source_format)
        .bind(&compilation.engine_kind)
        .bind(&execution_mode)
        .bind(req.tags.map(vec_to_json_array).unwrap_or(current.tags))
        .bind(
            req.mitre_attack
                .map(vec_to_json_array)
                .unwrap_or(current.mitre_attack),
        )
        .bind(req.author.as_deref().or(current.author.as_deref()))
        .bind(Some(source_text))
        .bind(req.source_object.or(current.source_object))
        .bind(Some(compilation.compiled_artifact))
        .fetch_optional(&self.db)
        .await
        .map_err(ApiError::Database)?
        .ok_or(ApiError::NotFound)?;
        DetectionRuleRecord::from_row(row).map_err(ApiError::Database)
    }

    pub async fn delete_detection_rule(&self, tenant_id: Uuid, id: Uuid) -> Result<(), ApiError> {
        let result =
            sqlx::query::query("DELETE FROM detection_rules WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(id)
                .execute(&self.db)
                .await
                .map_err(ApiError::Database)?;
        if result.rows_affected() == 0 {
            return Err(ApiError::NotFound);
        }
        Ok(())
    }

    pub async fn test_detection_rule(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        req: RuleTestRequest,
    ) -> Result<DetectionRuleTestApiResponse, ApiError> {
        let rule = self.get_detection_rule(tenant_id, id).await?;
        let source_text = rule.source_text.as_deref().ok_or_else(|| {
            ApiError::BadRequest("stored rule is missing source_text".to_string())
        })?;
        let sample_events = req
            .sample_events
            .into_iter()
            .map(SampleTimelineEvent::into_timeline_event)
            .collect::<Result<Vec<_>, _>>()?;
        let result = test_rule_source(&rule.source_format, source_text, &sample_events)
            .map_err(|err| ApiError::BadRequest(err.to_string()))?;
        Ok(map_rule_test_response(Some(id), result))
    }

    pub async fn import_detection_rule(
        &self,
        tenant_id: Uuid,
        actor: &str,
        mut req: CreateDetectionRule,
        source_format: &'static str,
    ) -> Result<DetectionRuleRecord, ApiError> {
        req.source_format = source_format.to_string();
        self.create_detection_rule(tenant_id, actor, req).await
    }

    pub async fn list_detection_findings(
        &self,
        tenant_id: Uuid,
        status: Option<&str>,
        severity: Option<&str>,
        rule_id: Option<Uuid>,
        principal_id: Option<Uuid>,
    ) -> Result<Vec<DetectionFindingRecord>, ApiError> {
        let rows = sqlx::query::query(
            r#"SELECT *
               FROM detection_findings
               WHERE tenant_id = $1
                 AND ($2::text IS NULL OR status = $2)
                 AND ($3::text IS NULL OR severity = $3)
                 AND ($4::uuid IS NULL OR rule_id = $4)
                 AND ($5::uuid IS NULL OR principal_id = $5)
               ORDER BY last_seen_at DESC"#,
        )
        .bind(tenant_id)
        .bind(status)
        .bind(severity)
        .bind(rule_id)
        .bind(principal_id)
        .fetch_all(&self.db)
        .await
        .map_err(ApiError::Database)?;
        let mut findings = Vec::with_capacity(rows.len());
        for row in rows {
            findings.push(self.finding_from_row(row).await?);
        }
        Ok(findings)
    }

    pub async fn get_detection_finding(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<DetectionFindingRecord, ApiError> {
        let row =
            sqlx::query::query("SELECT * FROM detection_findings WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(id)
                .fetch_optional(&self.db)
                .await
                .map_err(ApiError::Database)?
                .ok_or(ApiError::NotFound)?;
        self.finding_from_row(row).await
    }

    pub async fn suppress_detection_finding(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        actor: &str,
        reason: &str,
    ) -> Result<DetectionFindingRecord, ApiError> {
        let finding = self.get_detection_finding(tenant_id, id).await?;
        let suppression = CreateDetectionSuppression {
            rule_id: Some(finding.rule_id),
            finding_id: Some(finding.id),
            scope: None,
            match_criteria: Some(json!({ "status": finding.status })),
            reason: reason.to_string(),
            expires_at: None,
        };
        let _ = self
            .create_detection_suppression(tenant_id, actor, suppression)
            .await?;
        self.update_finding_status(tenant_id, id, "suppressed", reason)
            .await
    }

    pub async fn resolve_detection_finding(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        reason: &str,
    ) -> Result<DetectionFindingRecord, ApiError> {
        self.update_finding_status(tenant_id, id, "resolved", reason)
            .await
    }

    pub async fn false_positive_detection_finding(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        reason: &str,
    ) -> Result<DetectionFindingRecord, ApiError> {
        self.update_finding_status(tenant_id, id, "false_positive", reason)
            .await
    }

    pub async fn list_detection_suppressions(
        &self,
        tenant_id: Uuid,
    ) -> Result<Vec<DetectionSuppressionRecord>, ApiError> {
        let rows = sqlx::query::query(
            "SELECT * FROM detection_suppressions WHERE tenant_id = $1 ORDER BY created_at DESC",
        )
        .bind(tenant_id)
        .fetch_all(&self.db)
        .await
        .map_err(ApiError::Database)?;
        rows.into_iter()
            .map(DetectionSuppressionRecord::from_row)
            .collect::<Result<Vec<_>, _>>()
            .map_err(ApiError::Database)
    }

    pub async fn get_detection_suppression(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<DetectionSuppressionRecord, ApiError> {
        let row = sqlx::query::query(
            "SELECT * FROM detection_suppressions WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(ApiError::Database)?
        .ok_or(ApiError::NotFound)?;
        DetectionSuppressionRecord::from_row(row).map_err(ApiError::Database)
    }

    pub async fn create_detection_suppression(
        &self,
        tenant_id: Uuid,
        actor: &str,
        req: CreateDetectionSuppression,
    ) -> Result<DetectionSuppressionRecord, ApiError> {
        let CreateDetectionSuppression {
            rule_id,
            finding_id,
            scope,
            match_criteria,
            reason,
            expires_at,
        } = req;

        let mut tx = self.db.begin().await.map_err(ApiError::Database)?;
        let finding_context = if let Some(finding_id) = finding_id {
            let row = sqlx::query::query(
                r#"SELECT rule_id, metadata
                   FROM detection_findings
                   WHERE tenant_id = $1 AND id = $2"#,
            )
            .bind(tenant_id)
            .bind(finding_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(ApiError::Database)?
            .ok_or(ApiError::NotFound)?;
            let finding_rule_id: Uuid = row.try_get("rule_id").map_err(ApiError::Database)?;
            let metadata: Value = row.try_get("metadata").map_err(ApiError::Database)?;
            Some((finding_id, finding_rule_id, metadata))
        } else {
            None
        };

        if let Some(rule_id) = rule_id {
            let exists = sqlx::query_scalar::query_scalar::<_, bool>(
                r#"SELECT EXISTS(
                       SELECT 1
                       FROM detection_rules
                       WHERE tenant_id = $1 AND id = $2
                   )"#,
            )
            .bind(tenant_id)
            .bind(rule_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(ApiError::Database)?;
            if !exists {
                return Err(ApiError::NotFound);
            }
        }

        if let (Some(rule_id), Some((_, finding_rule_id, _))) = (rule_id, finding_context.as_ref())
        {
            if *finding_rule_id != rule_id {
                return Err(ApiError::BadRequest(
                    "finding_id does not belong to the provided rule_id".to_string(),
                ));
            }
        }

        let row = sqlx::query::query(
            r#"INSERT INTO detection_suppressions (
                   tenant_id,
                   rule_id,
                   finding_id,
                   scope,
                   match_criteria,
                   reason,
                   created_by,
                   expires_at
               )
               VALUES ($1, $2, $3, $4::jsonb, $5::jsonb, $6, $7, $8)
               RETURNING *"#,
        )
        .bind(tenant_id)
        .bind(rule_id)
        .bind(finding_id)
        .bind(scope.unwrap_or_else(empty_object))
        .bind(match_criteria.unwrap_or_else(empty_object))
        .bind(&reason)
        .bind(actor)
        .bind(expires_at)
        .fetch_one(&mut *tx)
        .await
        .map_err(ApiError::Database)?;
        let suppression = DetectionSuppressionRecord::from_row(row).map_err(ApiError::Database)?;

        if let Some((finding_id, _, metadata)) = finding_context {
            let mut finding_metadata = metadata.as_object().cloned().unwrap_or_else(Map::new);
            finding_metadata.insert(
                "last_status_reason".to_string(),
                Value::String(reason.clone()),
            );
            finding_metadata.insert(
                "last_status_changed_at".to_string(),
                Value::String(Utc::now().to_rfc3339()),
            );

            sqlx::query::query(
                r#"UPDATE detection_findings
                   SET status = 'suppressed',
                       metadata = $3::jsonb,
                       last_seen_at = now()
                   WHERE tenant_id = $1 AND id = $2"#,
            )
            .bind(tenant_id)
            .bind(finding_id)
            .bind(Value::Object(finding_metadata))
            .execute(&mut *tx)
            .await
            .map_err(ApiError::Database)?;
        }

        tx.commit().await.map_err(ApiError::Database)?;
        Ok(suppression)
    }

    pub async fn revoke_detection_suppression(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<DetectionSuppressionRecord, ApiError> {
        let row = sqlx::query::query(
            r#"UPDATE detection_suppressions
               SET status = 'revoked'
               WHERE tenant_id = $1 AND id = $2
               RETURNING *"#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(ApiError::Database)?
        .ok_or(ApiError::NotFound)?;
        DetectionSuppressionRecord::from_row(row).map_err(ApiError::Database)
    }

    pub async fn list_detection_packs(
        &self,
        tenant_id: Uuid,
    ) -> Result<Vec<InstalledDetectionPackRecord>, ApiError> {
        let rows = sqlx::query::query(
            "SELECT * FROM installed_detection_packs WHERE tenant_id = $1 ORDER BY installed_at DESC",
        )
        .bind(tenant_id)
        .fetch_all(&self.db)
        .await
        .map_err(ApiError::Database)?;
        rows.into_iter()
            .map(InstalledDetectionPackRecord::from_row)
            .collect::<Result<Vec<_>, _>>()
            .map_err(ApiError::Database)
    }

    pub async fn install_detection_pack(
        &self,
        tenant_id: Uuid,
        actor: &str,
        req: InstallDetectionPackRequest,
    ) -> Result<InstalledDetectionPackRecord, ApiError> {
        validate_pack_trust_level(&req.trust_level)?;
        let metadata = req.metadata.unwrap_or_else(empty_object);
        let package_type = metadata
            .get("pkg_type")
            .and_then(Value::as_str)
            .unwrap_or("policy-pack");
        if package_type != "policy-pack" {
            return Err(ApiError::BadRequest(
                "detection packs must be stored as policy-pack metadata extensions".to_string(),
            ));
        }
        let row = sqlx::query::query(
            r#"INSERT INTO installed_detection_packs (
                   tenant_id,
                   package_name,
                   version,
                   package_type,
                   metadata,
                   trust_level,
                   installed_by
               )
               VALUES ($1, $2, $3, 'policy-pack', $4::jsonb, $5, $6)
               ON CONFLICT (tenant_id, package_name, version)
               DO UPDATE SET metadata = EXCLUDED.metadata, trust_level = EXCLUDED.trust_level
               RETURNING *"#,
        )
        .bind(tenant_id)
        .bind(req.package_name)
        .bind(req.version)
        .bind(metadata)
        .bind(req.trust_level)
        .bind(actor)
        .fetch_one(&self.db)
        .await
        .map_err(ApiError::Database)?;
        InstalledDetectionPackRecord::from_row(row).map_err(ApiError::Database)
    }

    pub async fn get_detection_pack(
        &self,
        tenant_id: Uuid,
        name: &str,
        version: &str,
    ) -> Result<InstalledDetectionPackRecord, ApiError> {
        let row = sqlx::query::query(
            "SELECT * FROM installed_detection_packs WHERE tenant_id = $1 AND package_name = $2 AND version = $3",
        )
        .bind(tenant_id)
        .bind(name)
        .bind(version)
        .fetch_optional(&self.db)
        .await
        .map_err(ApiError::Database)?
        .ok_or(ApiError::NotFound)?;
        InstalledDetectionPackRecord::from_row(row).map_err(ApiError::Database)
    }

    pub async fn activate_detection_pack(
        &self,
        tenant_id: Uuid,
        name: &str,
        version: &str,
        req: ActivateDetectionPackRequest,
    ) -> Result<InstalledDetectionPackRecord, ApiError> {
        for rule_id in &req.activated_rules {
            if matches!(
                self.get_detection_rule(tenant_id, *rule_id).await,
                Err(ApiError::NotFound)
            ) {
                return Err(ApiError::BadRequest(format!(
                    "activated_rules contains unknown or cross-tenant rule id {rule_id}"
                )));
            }
        }
        let row = sqlx::query::query(
            r#"UPDATE installed_detection_packs
               SET activated_rules = $4::jsonb
               WHERE tenant_id = $1 AND package_name = $2 AND version = $3
               RETURNING *"#,
        )
        .bind(tenant_id)
        .bind(name)
        .bind(version)
        .bind(vec_uuid_to_json_array(req.activated_rules))
        .fetch_optional(&self.db)
        .await
        .map_err(ApiError::Database)?
        .ok_or(ApiError::NotFound)?;
        InstalledDetectionPackRecord::from_row(row).map_err(ApiError::Database)
    }

    pub async fn deactivate_detection_pack(
        &self,
        tenant_id: Uuid,
        name: &str,
        version: &str,
    ) -> Result<InstalledDetectionPackRecord, ApiError> {
        let row = sqlx::query::query(
            r#"UPDATE installed_detection_packs
               SET activated_rules = '[]'::jsonb
               WHERE tenant_id = $1 AND package_name = $2 AND version = $3
               RETURNING *"#,
        )
        .bind(tenant_id)
        .bind(name)
        .bind(version)
        .fetch_optional(&self.db)
        .await
        .map_err(ApiError::Database)?
        .ok_or(ApiError::NotFound)?;
        InstalledDetectionPackRecord::from_row(row).map_err(ApiError::Database)
    }

    pub async fn list_detection_pack_rules(
        &self,
        tenant_id: Uuid,
        name: &str,
        version: &str,
    ) -> Result<Vec<DetectionRuleRecord>, ApiError> {
        let pack = self.get_detection_pack(tenant_id, name, version).await?;
        let Some(rule_ids) = pack.activated_rules.as_array() else {
            return Ok(Vec::new());
        };
        let wanted: Vec<String> = rule_ids
            .iter()
            .filter_map(Value::as_str)
            .map(ToOwned::to_owned)
            .collect();
        let rules = self.list_detection_rules(tenant_id).await?;
        Ok(rules
            .into_iter()
            .filter(|rule| {
                wanted
                    .iter()
                    .any(|wanted_id| wanted_id == &rule.id.to_string())
            })
            .collect())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_detection_finding_for_test(
        &self,
        tenant_id: Uuid,
        rule_id: Uuid,
        _rule_name: &str,
        _source_format: &str,
        severity: &str,
        title: &str,
        summary: &str,
        evidence_refs: &[&str],
    ) -> Result<DetectionFindingRecord, ApiError> {
        let rule = self.get_detection_rule(tenant_id, rule_id).await?;
        let now = Utc::now();
        let row = sqlx::query::query(
            r#"INSERT INTO detection_findings (
                   tenant_id,
                   rule_id,
                   rule_name,
                   source_format,
                   severity,
                   status,
                   title,
                   summary,
                   first_seen_at,
                   last_seen_at
               )
               VALUES ($1, $2, $3, $4, $5, 'open', $6, $7, $8, $8)
               RETURNING *"#,
        )
        .bind(tenant_id)
        .bind(rule_id)
        .bind(rule.name)
        .bind(rule.source_format)
        .bind(severity)
        .bind(title)
        .bind(summary)
        .bind(now)
        .fetch_one(&self.db)
        .await
        .map_err(ApiError::Database)?;
        let finding_id: Uuid = row.try_get("id").map_err(ApiError::Database)?;
        for evidence_ref in evidence_refs {
            sqlx::query::query(
                r#"INSERT INTO detection_finding_evidence (
                       finding_id, tenant_id, artifact_kind, artifact_ref
                   ) VALUES ($1, $2, 'event_ref', $3)"#,
            )
            .bind(finding_id)
            .bind(tenant_id)
            .bind(*evidence_ref)
            .execute(&self.db)
            .await
            .map_err(ApiError::Database)?;
        }
        self.get_detection_finding(tenant_id, finding_id).await
    }

    /// Process a security event and dispatch alerts to matching configs.
    pub async fn process_violation(
        &self,
        tenant_id: Uuid,
        event: &SecurityEvent,
    ) -> Result<(), AlertError> {
        let rows = sqlx::query::query(
            "SELECT * FROM alert_configs WHERE tenant_id = $1 AND enabled = true",
        )
        .bind(tenant_id)
        .fetch_all(&self.db)
        .await?;

        let configs: Vec<AlertConfig> = rows
            .into_iter()
            .filter_map(|r| AlertConfig::from_row(r).ok())
            .collect();

        for config in configs {
            if !matches_filter(&config, event) {
                continue;
            }

            let result = match config.channel.as_str() {
                "pagerduty" => self.send_pagerduty(&config, event).await,
                "slack" => self.send_slack(&config, event).await,
                "webhook" => self.send_webhook(&config, event).await,
                _ => Ok(()),
            };

            if let Err(e) = result {
                tracing::error!(
                    alert_id = %config.id,
                    channel = %config.channel,
                    error = %e,
                    "Failed to dispatch alert"
                );
            }
        }

        Ok(())
    }

    async fn send_slack(
        &self,
        config: &AlertConfig,
        event: &SecurityEvent,
    ) -> Result<(), AlertError> {
        let webhook_url = config.config["webhook_url"]
            .as_str()
            .ok_or(AlertError::MissingConfig("webhook_url"))?;

        let payload = serde_json::json!({
            "text": format!(
                "*ClawdStrike Alert*\nGuard: {}\nVerdict: {}\nAgent: {}\nTarget: {}\nTime: {}",
                event.guard_name, event.verdict, event.agent_id, event.target, event.timestamp
            )
        });

        self.http_client
            .post(webhook_url)
            .json(&payload)
            .send()
            .await?;

        Ok(())
    }

    async fn send_pagerduty(
        &self,
        config: &AlertConfig,
        event: &SecurityEvent,
    ) -> Result<(), AlertError> {
        let routing_key = config.config["routing_key"]
            .as_str()
            .ok_or(AlertError::MissingConfig("routing_key"))?;

        let payload = serde_json::json!({
            "routing_key": routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": format!("ClawdStrike: {} - {}", event.guard_name, event.verdict),
                "source": event.agent_id,
                "severity": event.severity,
                "custom_details": event,
            }
        });

        self.http_client
            .post("https://events.pagerduty.com/v2/enqueue")
            .json(&payload)
            .send()
            .await?;

        Ok(())
    }

    async fn send_webhook(
        &self,
        config: &AlertConfig,
        event: &SecurityEvent,
    ) -> Result<(), AlertError> {
        let url = config.config["url"]
            .as_str()
            .ok_or(AlertError::MissingConfig("url"))?;

        self.http_client.post(url).json(event).send().await?;

        Ok(())
    }

    async fn finding_from_row(&self, row: PgRow) -> Result<DetectionFindingRecord, ApiError> {
        let id: Uuid = row.try_get("id").map_err(ApiError::Database)?;
        let tenant_id: Uuid = row.try_get("tenant_id").map_err(ApiError::Database)?;
        let evidence_refs = self.fetch_finding_evidence_refs(tenant_id, id).await?;
        let first_seen_at: DateTime<Utc> =
            row.try_get("first_seen_at").map_err(ApiError::Database)?;
        let source_format: String = row.try_get("source_format").map_err(ApiError::Database)?;
        let severity: String = row.try_get("severity").map_err(ApiError::Database)?;
        let status: String = row.try_get("status").map_err(ApiError::Database)?;
        let title: String = row.try_get("title").map_err(ApiError::Database)?;
        let summary: String = row.try_get("summary").map_err(ApiError::Database)?;
        let rule_id: Uuid = row.try_get("rule_id").map_err(ApiError::Database)?;
        let rule_name: String = row.try_get("rule_name").map_err(ApiError::Database)?;
        let session_id: Option<String> = row.try_get("session_id").map_err(ApiError::Database)?;
        let principal_id: Option<Uuid> = row.try_get("principal_id").map_err(ApiError::Database)?;
        let principal_id_text = principal_id.map(|value| value.to_string());
        let ocsf = serde_json::to_value(persisted_detection_finding_to_ocsf(
            &PersistedDetectionFindingInput {
                finding_id: &id.to_string(),
                time_ms: first_seen_at.timestamp_millis(),
                severity: &severity,
                status: &status,
                title: &title,
                summary: &summary,
                rule_id: &rule_id.to_string(),
                rule_name: &rule_name,
                source_format: &source_format,
                session_id: session_id.as_deref(),
                principal_id: principal_id_text.as_deref(),
                evidence_refs: &evidence_refs,
                product_version: env!("CARGO_PKG_VERSION"),
            },
        ))
        .map_err(|err| ApiError::Internal(err.to_string()))?;
        Ok(DetectionFindingRecord {
            id,
            tenant_id,
            rule_id,
            rule_name,
            source_format,
            severity,
            status,
            title,
            summary,
            principal_id,
            session_id,
            grant_id: row.try_get("grant_id").map_err(ApiError::Database)?,
            response_action_ids: row
                .try_get("response_action_ids")
                .map_err(ApiError::Database)?,
            first_seen_at,
            last_seen_at: row.try_get("last_seen_at").map_err(ApiError::Database)?,
            metadata: row.try_get("metadata").map_err(ApiError::Database)?,
            evidence_refs,
            ocsf,
        })
    }

    async fn fetch_finding_evidence_refs(
        &self,
        tenant_id: Uuid,
        finding_id: Uuid,
    ) -> Result<Vec<String>, ApiError> {
        let rows = sqlx::query::query(
            r#"SELECT artifact_ref
               FROM detection_finding_evidence
               WHERE tenant_id = $1 AND finding_id = $2
               ORDER BY created_at ASC"#,
        )
        .bind(tenant_id)
        .bind(finding_id)
        .fetch_all(&self.db)
        .await
        .map_err(ApiError::Database)?;
        let mut refs = Vec::with_capacity(rows.len());
        for row in rows {
            refs.push(row.try_get("artifact_ref").map_err(ApiError::Database)?);
        }
        Ok(refs)
    }

    async fn update_finding_status(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        status: &str,
        reason: &str,
    ) -> Result<DetectionFindingRecord, ApiError> {
        let current = self.get_detection_finding(tenant_id, id).await?;
        let mut metadata = current
            .metadata
            .as_object()
            .cloned()
            .unwrap_or_else(Map::new);
        metadata.insert(
            "last_status_reason".to_string(),
            Value::String(reason.to_string()),
        );
        metadata.insert(
            "last_status_changed_at".to_string(),
            Value::String(Utc::now().to_rfc3339()),
        );
        let row = sqlx::query::query(
            r#"UPDATE detection_findings
               SET status = $3,
                   metadata = $4::jsonb,
                   last_seen_at = now()
               WHERE tenant_id = $1 AND id = $2
               RETURNING *"#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(status)
        .bind(Value::Object(metadata))
        .fetch_optional(&self.db)
        .await
        .map_err(ApiError::Database)?
        .ok_or(ApiError::NotFound)?;
        self.finding_from_row(row).await
    }
}

fn matches_filter(config: &AlertConfig, event: &SecurityEvent) -> bool {
    if let Some(ref filters) = config.guard_filter {
        if !filters.is_empty() && !filters.iter().any(|f| f == &event.guard_name) {
            return false;
        }
    }
    let severity_rank = |s: &str| -> u8 {
        match s {
            "info" => 0,
            "warn" => 1,
            "error" => 2,
            "critical" => 3,
            _ => 0,
        }
    };
    severity_rank(&event.severity) >= severity_rank(&config.severity_threshold)
}

impl SampleTimelineEvent {
    fn into_timeline_event(self) -> Result<TimelineEvent, ApiError> {
        let timestamp = DateTime::parse_from_rfc3339(&self.timestamp)
            .map_err(|err| ApiError::BadRequest(format!("invalid sample event timestamp: {err}")))?
            .with_timezone(&Utc);
        let source = EventSource::parse(&self.source).ok_or_else(|| {
            ApiError::BadRequest(format!("invalid sample event source '{}'", self.source))
        })?;
        Ok(TimelineEvent {
            event_id: None,
            timestamp,
            source,
            kind: infer_kind(self.action_type.as_deref()),
            verdict: parse_verdict(self.verdict.as_deref()),
            severity: self.severity,
            summary: self.summary,
            process: self.process,
            namespace: self.namespace,
            pod: self.pod,
            action_type: self.action_type,
            signature_valid: Some(true),
            raw: None,
        })
    }
}

fn map_rule_test_response(
    rule_id: Option<Uuid>,
    result: DetectionRuleTestResult,
) -> DetectionRuleTestApiResponse {
    DetectionRuleTestApiResponse {
        rule_id,
        valid: result.valid,
        findings: result.findings,
        warnings: result.warnings,
        errors: result.errors,
    }
}

fn normalize_source_text(
    source_format: &str,
    source_text: Option<String>,
    source_object: Option<&Value>,
) -> Result<String, ApiError> {
    match source_format {
        "clawdstrike_policy" => {
            if let Some(text) = source_text {
                Ok(text)
            } else if let Some(value) = source_object {
                serde_json::to_string(value).map_err(|err| ApiError::BadRequest(err.to_string()))
            } else {
                Err(ApiError::BadRequest(
                    "clawdstrike_policy rules require source_text or source_object".to_string(),
                ))
            }
        }
        _ => source_text.ok_or_else(|| {
            ApiError::BadRequest(format!("{source_format} rules require source_text"))
        }),
    }
}

fn validate_detection_severity(value: &str) -> Result<(), ApiError> {
    match value {
        "low" | "medium" | "high" | "critical" => Ok(()),
        _ => Err(ApiError::BadRequest(format!(
            "unsupported severity '{value}'"
        ))),
    }
}

fn validate_execution_mode(value: &str) -> Result<(), ApiError> {
    match value {
        "streaming" | "batch" | "inline" | "scheduled" => Ok(()),
        _ => Err(ApiError::BadRequest(format!(
            "unsupported execution mode '{value}'"
        ))),
    }
}

fn validate_pack_trust_level(value: &str) -> Result<(), ApiError> {
    match value {
        "unverified" | "signed" | "verified" | "certified" => Ok(()),
        _ => Err(ApiError::BadRequest(format!(
            "unsupported trust level '{value}'"
        ))),
    }
}

fn infer_kind(action_type: Option<&str>) -> TimelineEventKind {
    match action_type {
        Some("process") => TimelineEventKind::ProcessExec,
        Some("egress") | Some("network") => TimelineEventKind::NetworkFlow,
        Some("scan") => TimelineEventKind::ScanResult,
        _ => TimelineEventKind::GuardDecision,
    }
}

fn parse_verdict(value: Option<&str>) -> NormalizedVerdict {
    match value.unwrap_or("none") {
        "allow" => NormalizedVerdict::Allow,
        "deny" => NormalizedVerdict::Deny,
        "warn" => NormalizedVerdict::Warn,
        "forwarded" => NormalizedVerdict::Forwarded,
        "dropped" => NormalizedVerdict::Dropped,
        _ => NormalizedVerdict::None,
    }
}

fn vec_to_json_array(items: Vec<String>) -> Value {
    Value::Array(items.into_iter().map(Value::String).collect())
}

fn vec_uuid_to_json_array(items: Vec<Uuid>) -> Value {
    Value::Array(
        items
            .into_iter()
            .map(|id| Value::String(id.to_string()))
            .collect(),
    )
}

fn empty_object() -> Value {
    Value::Object(Map::new())
}
