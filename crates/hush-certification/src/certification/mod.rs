use std::path::Path;
use std::sync::Mutex;

use chrono::{DateTime, Duration, SecondsFormat, Utc};
use rusqlite::{params, Connection, OptionalExtension as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::badge::{
    keypair_public_key_base64url, now_rfc3339_nanos, sign_badge, CertificationBadge,
    CertificationTier,
};
use crate::Result;

const CREATE_TABLES: &str = r#"
CREATE TABLE IF NOT EXISTS certifications (
  certification_id TEXT PRIMARY KEY,
  version TEXT NOT NULL,

  subject_type TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  subject_name TEXT NOT NULL,
  subject_organization_id TEXT NULL,
  subject_metadata TEXT NULL,

  tier TEXT NOT NULL,
  issue_date TEXT NOT NULL,
  expiry_date TEXT NOT NULL,
  frameworks TEXT NOT NULL,
  status TEXT NOT NULL,

  policy_hash TEXT NOT NULL,
  policy_version TEXT NOT NULL,
  policy_ruleset TEXT NULL,

  evidence_receipt_count INTEGER NOT NULL,
  evidence_merkle_root TEXT NULL,
  evidence_audit_log_ref TEXT NULL,
  evidence_last_updated TEXT NULL,

  issuer_id TEXT NOT NULL,
  issuer_name TEXT NOT NULL,
  issuer_public_key TEXT NOT NULL,
  issuer_signature TEXT NOT NULL,
  issuer_signed_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cert_subject ON certifications(subject_id);
CREATE INDEX IF NOT EXISTS idx_cert_org ON certifications(subject_organization_id);
CREATE INDEX IF NOT EXISTS idx_cert_status ON certifications(status);

CREATE TABLE IF NOT EXISTS revocations (
  certification_id TEXT PRIMARY KEY,
  revoked_at TEXT NOT NULL,
  reason TEXT NOT NULL,
  details TEXT NULL,
  revoked_by TEXT NOT NULL,
  superseded_by TEXT NULL
);
"#;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Subject {
    #[serde(rename = "type")]
    pub subject_type: String,
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyBinding {
    pub hash: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ruleset: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceBinding {
    #[serde(default)]
    pub receipt_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merkle_root: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_log_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_updated: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CertificationStatus {
    Active,
    Expired,
    Revoked,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Issuer {
    pub id: String,
    pub name: String,
    pub public_key: String,
    pub signature: String,
    pub signed_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificationRecord {
    pub certification_id: String,
    pub version: String,
    pub subject: Subject,
    pub tier: CertificationTier,
    pub issue_date: String,
    pub expiry_date: String,
    pub frameworks: Vec<String>,
    pub status: CertificationStatus,
    pub policy: PolicyBinding,
    pub evidence: EvidenceBinding,
    pub issuer: Issuer,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCertificationInput {
    pub subject: Subject,
    pub tier: CertificationTier,
    pub frameworks: Vec<String>,
    pub policy: PolicyBinding,
    #[serde(default)]
    pub evidence: Option<EvidenceBinding>,
    #[serde(default)]
    pub validity_days: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCertificationResult {
    pub certification_id: String,
    pub status: CertificationStatus,
    pub issue_date: String,
    pub expiry_date: String,
}

#[derive(Clone, Debug, Default)]
pub struct ListCertificationsFilter {
    pub organization_id: Option<String>,
    pub subject_id: Option<String>,
    pub tier: Option<CertificationTier>,
    pub status: Option<CertificationStatus>,
    pub framework: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeInput {
    pub reason: String,
    #[serde(default)]
    pub details: Option<String>,
    pub revoked_by: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationRecord {
    pub certification_id: String,
    pub revoked_at: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    pub revoked_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superseded_by: Option<String>,
}

#[derive(Clone, Debug)]
pub struct IssuerConfig {
    pub id: String,
    pub name: String,
}

impl Default for IssuerConfig {
    fn default() -> Self {
        Self {
            id: "iss_clawdstrike".to_string(),
            name: "Clawdstrike Certification Authority".to_string(),
        }
    }
}

pub struct SqliteCertificationStore {
    conn: Mutex<Connection>,
}

impl SqliteCertificationStore {
    fn lock_conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|err| err.into_inner())
    }

    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;
        conn.execute_batch(CREATE_TABLES)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(CREATE_TABLES)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn create_certification(
        &self,
        input: CreateCertificationInput,
        issuer_cfg: &IssuerConfig,
        signer: &hush_core::Keypair,
    ) -> Result<CreateCertificationResult> {
        let conn = self.lock_conn();
        let tx = conn.unchecked_transaction()?;

        let certification_id = format!("cert_{}", Uuid::now_v7());
        let version = "1.0.0".to_string();
        let issue_date = now_rfc3339_nanos();
        let validity_days = input.validity_days.unwrap_or(365);
        let expiry_date = (Utc::now() + Duration::days(validity_days as i64))
            .to_rfc3339_opts(SecondsFormat::Nanos, true);

        let evidence = input.evidence.unwrap_or(EvidenceBinding {
            receipt_count: 0,
            merkle_root: None,
            audit_log_ref: None,
            last_updated: None,
        });

        let issuer_public_key = keypair_public_key_base64url(signer);
        let issuer_signed_at = now_rfc3339_nanos();

        let badge = CertificationBadge {
            certification_id: certification_id.clone(),
            version: version.clone(),
            subject: crate::badge::BadgeSubject {
                subject_type: input.subject.subject_type.clone(),
                id: input.subject.id.clone(),
                name: input.subject.name.clone(),
                metadata: input.subject.metadata.clone(),
            },
            certification: crate::badge::BadgeCertificationBinding {
                tier: input.tier,
                issue_date: issue_date.clone(),
                expiry_date: expiry_date.clone(),
                frameworks: input.frameworks.clone(),
            },
            policy: crate::badge::BadgePolicyBinding {
                hash: input.policy.hash.clone(),
                version: input.policy.version.clone(),
                ruleset: input.policy.ruleset.clone(),
            },
            evidence: crate::badge::BadgeEvidenceBinding {
                receipt_count: evidence.receipt_count,
                merkle_root: evidence.merkle_root.clone(),
                audit_log_ref: evidence.audit_log_ref.clone(),
            },
            issuer: crate::badge::BadgeIssuer {
                id: issuer_cfg.id.clone(),
                name: issuer_cfg.name.clone(),
                public_key: issuer_public_key.clone(),
                signature: String::new(),
                signed_at: issuer_signed_at.clone(),
            },
        };

        let signed_badge = sign_badge(badge, signer)?;

        let issuer_signature = signed_badge.issuer.signature.clone();

        tx.execute(
            r#"INSERT INTO certifications (
              certification_id, version,
              subject_type, subject_id, subject_name, subject_organization_id, subject_metadata,
              tier, issue_date, expiry_date, frameworks, status,
              policy_hash, policy_version, policy_ruleset,
              evidence_receipt_count, evidence_merkle_root, evidence_audit_log_ref, evidence_last_updated,
              issuer_id, issuer_name, issuer_public_key, issuer_signature, issuer_signed_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"#,
            params![
                certification_id,
                version,
                input.subject.subject_type,
                input.subject.id,
                input.subject.name,
                input.subject.organization_id,
                input.subject
                    .metadata
                    .as_ref()
                    .and_then(|v| serde_json::to_string(v).ok()),
                tier_to_str(input.tier),
                issue_date,
                expiry_date,
                serde_json::to_string(&input.frameworks)?,
                status_to_str(CertificationStatus::Active),
                input.policy.hash,
                input.policy.version,
                input.policy.ruleset,
                i64::try_from(evidence.receipt_count).unwrap_or(i64::MAX),
                evidence.merkle_root,
                evidence.audit_log_ref,
                evidence.last_updated,
                issuer_cfg.id.clone(),
                issuer_cfg.name.clone(),
                issuer_public_key,
                issuer_signature,
                issuer_signed_at,
            ],
        )?;

        tx.commit()?;

        Ok(CreateCertificationResult {
            certification_id: signed_badge.certification_id,
            status: CertificationStatus::Active,
            issue_date: signed_badge.certification.issue_date,
            expiry_date: signed_badge.certification.expiry_date,
        })
    }

    pub fn get_certification(&self, certification_id: &str) -> Result<Option<CertificationRecord>> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT certification_id, version, subject_type, subject_id, subject_name, subject_organization_id, subject_metadata, tier, issue_date, expiry_date, frameworks, status, policy_hash, policy_version, policy_ruleset, evidence_receipt_count, evidence_merkle_root, evidence_audit_log_ref, evidence_last_updated, issuer_id, issuer_name, issuer_public_key, issuer_signature, issuer_signed_at FROM certifications WHERE certification_id = ?",
        )?;
        let record = stmt
            .query_row(params![certification_id], row_to_cert)
            .optional()?;
        Ok(record)
    }

    pub fn list_certifications(
        &self,
        filter: &ListCertificationsFilter,
    ) -> Result<Vec<CertificationRecord>> {
        let conn = self.lock_conn();

        let mut sql = String::from(
            "SELECT certification_id, version, subject_type, subject_id, subject_name, subject_organization_id, subject_metadata, tier, issue_date, expiry_date, frameworks, status, policy_hash, policy_version, policy_ruleset, evidence_receipt_count, evidence_merkle_root, evidence_audit_log_ref, evidence_last_updated, issuer_id, issuer_name, issuer_public_key, issuer_signature, issuer_signed_at FROM certifications WHERE 1=1",
        );
        let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

        if let Some(org) = filter.organization_id.as_ref() {
            sql.push_str(" AND subject_organization_id = ?");
            params_vec.push(Box::new(org.clone()));
        }
        if let Some(subject_id) = filter.subject_id.as_ref() {
            sql.push_str(" AND subject_id = ?");
            params_vec.push(Box::new(subject_id.clone()));
        }
        if let Some(tier) = filter.tier {
            sql.push_str(" AND tier = ?");
            params_vec.push(Box::new(tier_to_str(tier).to_string()));
        }
        if let Some(status) = filter.status.as_ref() {
            sql.push_str(" AND status = ?");
            params_vec.push(Box::new(status_to_str(status.clone()).to_string()));
        }
        if let Some(framework) = filter.framework.as_ref() {
            sql.push_str(" AND frameworks LIKE ?");
            params_vec.push(Box::new(format!("%{}%", framework)));
        }

        sql.push_str(" ORDER BY issue_date DESC");

        let limit = filter.limit.unwrap_or(20).min(100);
        let offset = filter.offset.unwrap_or(0);
        sql.push_str(&format!(" LIMIT {} OFFSET {}", limit, offset));

        let params_refs: Vec<&dyn rusqlite::ToSql> =
            params_vec.iter().map(|p| p.as_ref()).collect();

        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params_refs.as_slice(), row_to_cert)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn count_certifications(&self, filter: &ListCertificationsFilter) -> Result<u64> {
        let conn = self.lock_conn();

        let mut sql = String::from("SELECT COUNT(*) FROM certifications WHERE 1=1");
        let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

        if let Some(org) = filter.organization_id.as_ref() {
            sql.push_str(" AND subject_organization_id = ?");
            params_vec.push(Box::new(org.clone()));
        }
        if let Some(subject_id) = filter.subject_id.as_ref() {
            sql.push_str(" AND subject_id = ?");
            params_vec.push(Box::new(subject_id.clone()));
        }
        if let Some(tier) = filter.tier {
            sql.push_str(" AND tier = ?");
            params_vec.push(Box::new(tier_to_str(tier).to_string()));
        }
        if let Some(status) = filter.status.as_ref() {
            sql.push_str(" AND status = ?");
            params_vec.push(Box::new(status_to_str(status.clone()).to_string()));
        }
        if let Some(framework) = filter.framework.as_ref() {
            sql.push_str(" AND frameworks LIKE ?");
            params_vec.push(Box::new(format!("%{}%", framework)));
        }

        let params_refs: Vec<&dyn rusqlite::ToSql> =
            params_vec.iter().map(|p| p.as_ref()).collect();
        let mut stmt = conn.prepare(&sql)?;
        let count: i64 = stmt.query_row(params_refs.as_slice(), |row| row.get(0))?;
        Ok(count.try_into().unwrap_or(0))
    }

    pub fn revoke(&self, certification_id: &str, input: RevokeInput) -> Result<RevocationRecord> {
        let conn = self.lock_conn();
        let tx = conn.unchecked_transaction()?;

        let now = now_rfc3339_nanos();

        tx.execute(
            "INSERT OR REPLACE INTO revocations (certification_id, revoked_at, reason, details, revoked_by, superseded_by) VALUES (?,?,?,?,?,?)",
            params![certification_id, now, input.reason, input.details, input.revoked_by, Option::<String>::None],
        )?;

        tx.execute(
            "UPDATE certifications SET status = ? WHERE certification_id = ?",
            params![
                status_to_str(CertificationStatus::Revoked),
                certification_id
            ],
        )?;

        tx.commit()?;

        Ok(RevocationRecord {
            certification_id: certification_id.to_string(),
            revoked_at: now,
            reason: input.reason,
            details: input.details,
            revoked_by: input.revoked_by,
            superseded_by: None,
        })
    }

    pub fn get_revocation(&self, certification_id: &str) -> Result<Option<RevocationRecord>> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT certification_id, revoked_at, reason, details, revoked_by, superseded_by FROM revocations WHERE certification_id = ?",
        )?;
        let record = stmt
            .query_row(params![certification_id], |row| {
                Ok(RevocationRecord {
                    certification_id: row.get(0)?,
                    revoked_at: row.get(1)?,
                    reason: row.get(2)?,
                    details: row.get(3)?,
                    revoked_by: row.get(4)?,
                    superseded_by: row.get(5)?,
                })
            })
            .optional()?;
        Ok(record)
    }
}

fn row_to_cert(row: &rusqlite::Row<'_>) -> rusqlite::Result<CertificationRecord> {
    let subject_metadata: Option<String> = row.get(6)?;
    let frameworks_raw: String = row.get(10)?;
    let evidence_receipt_count: i64 = row.get(15)?;

    let tier_str: String = row.get(7)?;
    let status_str: String = row.get(11)?;

    Ok(CertificationRecord {
        certification_id: row.get(0)?,
        version: row.get(1)?,
        subject: Subject {
            subject_type: row.get(2)?,
            id: row.get(3)?,
            name: row.get(4)?,
            organization_id: row.get(5)?,
            metadata: subject_metadata.and_then(|s| serde_json::from_str(&s).ok()),
        },
        tier: tier_from_str(&tier_str).unwrap_or(CertificationTier::Certified),
        issue_date: row.get(8)?,
        expiry_date: row.get(9)?,
        frameworks: serde_json::from_str(&frameworks_raw).unwrap_or_default(),
        status: status_from_str(&status_str).unwrap_or(CertificationStatus::Active),
        policy: PolicyBinding {
            hash: row.get(12)?,
            version: row.get(13)?,
            ruleset: row.get(14)?,
        },
        evidence: EvidenceBinding {
            receipt_count: evidence_receipt_count.try_into().unwrap_or(0),
            merkle_root: row.get(16)?,
            audit_log_ref: row.get(17)?,
            last_updated: row.get(18)?,
        },
        issuer: Issuer {
            id: row.get(19)?,
            name: row.get(20)?,
            public_key: row.get(21)?,
            signature: row.get(22)?,
            signed_at: row.get(23)?,
        },
    })
}

fn tier_to_str(tier: CertificationTier) -> &'static str {
    match tier {
        CertificationTier::Certified => "certified",
        CertificationTier::Silver => "silver",
        CertificationTier::Gold => "gold",
        CertificationTier::Platinum => "platinum",
    }
}

fn tier_from_str(s: &str) -> Option<CertificationTier> {
    match s.to_ascii_lowercase().as_str() {
        "certified" => Some(CertificationTier::Certified),
        "silver" => Some(CertificationTier::Silver),
        "gold" => Some(CertificationTier::Gold),
        "platinum" => Some(CertificationTier::Platinum),
        _ => None,
    }
}

fn status_to_str(status: CertificationStatus) -> &'static str {
    match status {
        CertificationStatus::Active => "active",
        CertificationStatus::Expired => "expired",
        CertificationStatus::Revoked => "revoked",
    }
}

fn status_from_str(s: &str) -> Option<CertificationStatus> {
    match s.to_ascii_lowercase().as_str() {
        "active" => Some(CertificationStatus::Active),
        "expired" => Some(CertificationStatus::Expired),
        "revoked" => Some(CertificationStatus::Revoked),
        _ => None,
    }
}

pub fn parse_rfc3339(date: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(date)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

pub fn effective_status(record: &CertificationRecord) -> CertificationStatus {
    if matches!(record.status, CertificationStatus::Revoked) {
        return CertificationStatus::Revoked;
    }

    let now = Utc::now();
    let expiry = parse_rfc3339(&record.expiry_date);
    if expiry.is_some_and(|e| e < now) {
        return CertificationStatus::Expired;
    }

    CertificationStatus::Active
}

pub fn build_badge_from_record(record: &CertificationRecord) -> Result<CertificationBadge> {
    Ok(CertificationBadge {
        certification_id: record.certification_id.clone(),
        version: record.version.clone(),
        subject: crate::badge::BadgeSubject {
            subject_type: record.subject.subject_type.clone(),
            id: record.subject.id.clone(),
            name: record.subject.name.clone(),
            metadata: record.subject.metadata.clone(),
        },
        certification: crate::badge::BadgeCertificationBinding {
            tier: record.tier,
            issue_date: record.issue_date.clone(),
            expiry_date: record.expiry_date.clone(),
            frameworks: record.frameworks.clone(),
        },
        policy: crate::badge::BadgePolicyBinding {
            hash: record.policy.hash.clone(),
            version: record.policy.version.clone(),
            ruleset: record.policy.ruleset.clone(),
        },
        evidence: crate::badge::BadgeEvidenceBinding {
            receipt_count: record.evidence.receipt_count,
            merkle_root: record.evidence.merkle_root.clone(),
            audit_log_ref: record.evidence.audit_log_ref.clone(),
        },
        issuer: crate::badge::BadgeIssuer {
            id: record.issuer.id.clone(),
            name: record.issuer.name.clone(),
            public_key: record.issuer.public_key.clone(),
            signature: record.issuer.signature.clone(),
            signed_at: record.issuer.signed_at.clone(),
        },
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn create_and_load_roundtrip() {
        let store = SqliteCertificationStore::in_memory().unwrap();
        let keypair = hush_core::Keypair::generate();
        let issuer = IssuerConfig::default();

        let created = store
            .create_certification(
                CreateCertificationInput {
                    subject: Subject {
                        subject_type: "agent".to_string(),
                        id: "agent_1".to_string(),
                        name: "test".to_string(),
                        organization_id: Some("org_1".to_string()),
                        metadata: None,
                    },
                    tier: CertificationTier::Silver,
                    frameworks: vec!["soc2".to_string()],
                    policy: PolicyBinding {
                        hash: "sha256:deadbeef".to_string(),
                        version: "1.0.0".to_string(),
                        ruleset: Some("clawdstrike:strict".to_string()),
                    },
                    evidence: None,
                    validity_days: Some(10),
                },
                &issuer,
                &keypair,
            )
            .unwrap();

        let loaded = store
            .get_certification(&created.certification_id)
            .unwrap()
            .expect("missing record");
        assert_eq!(loaded.subject.id, "agent_1");
        assert_eq!(loaded.tier, CertificationTier::Silver);
    }
}
