use std::fs::File;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::{Duration, SecondsFormat, Utc};
use rusqlite::{params, Connection, OptionalExtension as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;
use zip::write::{FileOptions, ZipWriter};
use zip::CompressionMethod;

use crate::audit::AuditEventV2;
use crate::badge::CertificationBadge;
use crate::certification::CertificationRecord;
use crate::Result;

const CREATE_TABLES: &str = r#"
CREATE TABLE IF NOT EXISTS evidence_exports (
  export_id TEXT PRIMARY KEY,
  certification_id TEXT NOT NULL,
  status TEXT NOT NULL,
  requested_at TEXT NOT NULL,
  completed_at TEXT NULL,
  date_start TEXT NULL,
  date_end TEXT NULL,
  include_types TEXT NULL,
  compliance_template TEXT NULL,
  file_path TEXT NULL,
  size_bytes INTEGER NULL,
  sha256 TEXT NULL,
  expires_at TEXT NULL
);

CREATE INDEX IF NOT EXISTS idx_evidence_exports_cert ON evidence_exports(certification_id);
"#;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EvidenceExportStatus {
    Processing,
    Completed,
    Failed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceExportRecord {
    pub export_id: String,
    pub certification_id: String,
    pub status: EvidenceExportStatus,
    pub requested_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date_start: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date_end: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_types: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compliance_template: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceExportRequest {
    #[serde(default)]
    pub date_start: Option<String>,
    #[serde(default)]
    pub date_end: Option<String>,
    #[serde(default)]
    pub include_types: Option<Vec<String>>,
    #[serde(default)]
    pub compliance_template: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceBundleManifest {
    pub export_id: String,
    pub certification_id: String,
    pub generated_at: String,
    pub event_count: u64,
    pub merkle_root: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date_range: Option<DateRange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compliance_template: Option<String>,
    pub issuer: ManifestIssuer,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DateRange {
    pub start: String,
    pub end: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestIssuer {
    pub public_key: String,
    pub signature: String,
    pub signed_at: String,
}

pub struct SqliteEvidenceExportStore {
    conn: Mutex<Connection>,
}

impl SqliteEvidenceExportStore {
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

    pub fn create_job(
        &self,
        certification_id: &str,
        request: EvidenceExportRequest,
    ) -> Result<EvidenceExportRecord> {
        let conn = self.lock_conn();
        let export_id = format!("exp_{}", Uuid::now_v7());
        let requested_at = Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true);

        conn.execute(
            "INSERT INTO evidence_exports (export_id, certification_id, status, requested_at, date_start, date_end, include_types, compliance_template) VALUES (?,?,?,?,?,?,?,?)",
            params![
                export_id,
                certification_id,
                status_to_str(EvidenceExportStatus::Processing),
                requested_at,
                request.date_start,
                request.date_end,
                request.include_types.as_ref().and_then(|v| serde_json::to_string(v).ok()),
                request.compliance_template,
            ],
        )?;

        Ok(EvidenceExportRecord {
            export_id,
            certification_id: certification_id.to_string(),
            status: EvidenceExportStatus::Processing,
            requested_at,
            completed_at: None,
            date_start: request.date_start,
            date_end: request.date_end,
            include_types: request.include_types,
            compliance_template: request.compliance_template,
            file_path: None,
            size_bytes: None,
            sha256: None,
            expires_at: None,
        })
    }

    pub fn get(&self, export_id: &str) -> Result<Option<EvidenceExportRecord>> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT export_id, certification_id, status, requested_at, completed_at, date_start, date_end, include_types, compliance_template, file_path, size_bytes, sha256, expires_at FROM evidence_exports WHERE export_id = ?",
        )?;
        let record = stmt
            .query_row(params![export_id], |row| {
                let include_raw: Option<String> = row.get(7)?;
                let size: Option<i64> = row.get(10)?;
                Ok(EvidenceExportRecord {
                    export_id: row.get(0)?,
                    certification_id: row.get(1)?,
                    status: status_from_str(&row.get::<_, String>(2)?)
                        .unwrap_or(EvidenceExportStatus::Failed),
                    requested_at: row.get(3)?,
                    completed_at: row.get(4)?,
                    date_start: row.get(5)?,
                    date_end: row.get(6)?,
                    include_types: include_raw.and_then(|s| serde_json::from_str(&s).ok()),
                    compliance_template: row.get(8)?,
                    file_path: row.get(9)?,
                    size_bytes: size.and_then(|v| v.try_into().ok()),
                    sha256: row.get(11)?,
                    expires_at: row.get(12)?,
                })
            })
            .optional()?;
        Ok(record)
    }

    pub fn list_for_certification(
        &self,
        certification_id: &str,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> Result<Vec<EvidenceExportRecord>> {
        let conn = self.lock_conn();

        let limit = limit.unwrap_or(20).min(100);
        let offset = offset.unwrap_or(0);

        let mut stmt = conn.prepare(
            "SELECT export_id, certification_id, status, requested_at, completed_at, date_start, date_end, include_types, compliance_template, file_path, size_bytes, sha256, expires_at FROM evidence_exports WHERE certification_id = ? ORDER BY requested_at DESC LIMIT ? OFFSET ?",
        )?;
        let rows = stmt.query_map(
            params![certification_id, limit as i64, offset as i64],
            |row| {
                let include_raw: Option<String> = row.get(7)?;
                let size: Option<i64> = row.get(10)?;
                Ok(EvidenceExportRecord {
                    export_id: row.get(0)?,
                    certification_id: row.get(1)?,
                    status: status_from_str(&row.get::<_, String>(2)?)
                        .unwrap_or(EvidenceExportStatus::Failed),
                    requested_at: row.get(3)?,
                    completed_at: row.get(4)?,
                    date_start: row.get(5)?,
                    date_end: row.get(6)?,
                    include_types: include_raw.and_then(|s| serde_json::from_str(&s).ok()),
                    compliance_template: row.get(8)?,
                    file_path: row.get(9)?,
                    size_bytes: size.and_then(|v| v.try_into().ok()),
                    sha256: row.get(11)?,
                    expires_at: row.get(12)?,
                })
            },
        )?;

        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn mark_completed(
        &self,
        export_id: &str,
        file_path: &Path,
        sha256_hex: &str,
        size_bytes: u64,
    ) -> Result<()> {
        let conn = self.lock_conn();
        let completed_at = Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true);
        let expires_at = (Utc::now() + Duration::days(7)).to_rfc3339_opts(SecondsFormat::Nanos, true);
        conn.execute(
            "UPDATE evidence_exports SET status = ?, completed_at = ?, file_path = ?, sha256 = ?, size_bytes = ?, expires_at = ? WHERE export_id = ?",
            params![
                status_to_str(EvidenceExportStatus::Completed),
                completed_at,
                file_path.to_string_lossy().to_string(),
                sha256_hex,
                i64::try_from(size_bytes).unwrap_or(i64::MAX),
                expires_at,
                export_id,
            ],
        )?;
        Ok(())
    }

    pub fn mark_failed(&self, export_id: &str) -> Result<()> {
        let conn = self.lock_conn();
        conn.execute(
            "UPDATE evidence_exports SET status = ? WHERE export_id = ?",
            params![status_to_str(EvidenceExportStatus::Failed), export_id],
        )?;
        Ok(())
    }
}

fn status_to_str(status: EvidenceExportStatus) -> &'static str {
    match status {
        EvidenceExportStatus::Processing => "processing",
        EvidenceExportStatus::Completed => "completed",
        EvidenceExportStatus::Failed => "failed",
    }
}

fn status_from_str(s: &str) -> Option<EvidenceExportStatus> {
    match s.to_ascii_lowercase().as_str() {
        "processing" => Some(EvidenceExportStatus::Processing),
        "completed" => Some(EvidenceExportStatus::Completed),
        "failed" => Some(EvidenceExportStatus::Failed),
        _ => None,
    }
}

pub struct EvidenceBundleOutput {
    pub file_path: PathBuf,
    pub sha256_hex: String,
    pub size_bytes: u64,
    pub merkle_root: String,
}

pub fn build_evidence_bundle_zip(
    out_dir: impl AsRef<Path>,
    export_id: &str,
    certification: &CertificationRecord,
    badge: &CertificationBadge,
    events: &[AuditEventV2],
    request: &EvidenceExportRequest,
    signer: &hush_core::Keypair,
) -> Result<EvidenceBundleOutput> {
    std::fs::create_dir_all(out_dir.as_ref())?;

    let file_path = out_dir.as_ref().join(format!("{export_id}.zip"));
    let file = File::create(&file_path)?;
    let mut zip = ZipWriter::new(file);
    let opts = FileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .unix_permissions(0o644);

    // audit.jsonl
    zip.start_file("audit.jsonl", opts)?;
    for e in events {
        let line = serde_json::to_string(&e.as_spec_json())?;
        zip.write_all(line.as_bytes())?;
        zip.write_all(b"\n")?;
    }

    // badge.json
    zip.start_file("badge.json", opts)?;
    zip.write_all(serde_json::to_string_pretty(badge)?.as_bytes())?;
    zip.write_all(b"\n")?;

    // certification.json (redundant convenience)
    zip.start_file("certification.json", opts)?;
    zip.write_all(serde_json::to_string_pretty(certification)?.as_bytes())?;
    zip.write_all(b"\n")?;

    // manifest.json (signed)
    let merkle_root = merkle_root_for_events(events)?;
    let generated_at = Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true);
    let signed_at = generated_at.clone();
    let public_key = URL_SAFE_NO_PAD.encode(signer.public_key().as_bytes());

    let mut manifest_value = serde_json::json!({
        "exportId": export_id,
        "certificationId": certification.certification_id,
        "generatedAt": generated_at,
        "eventCount": events.len(),
        "merkleRoot": merkle_root,
    });

    if let (Some(start), Some(end)) = (request.date_start.as_ref(), request.date_end.as_ref()) {
        if let Some(obj) = manifest_value.as_object_mut() {
            obj.insert(
                "dateRange".to_string(),
                serde_json::json!({ "start": start, "end": end }),
            );
        }
    }

    if let Some(tpl) = request.compliance_template.as_ref() {
        if let Some(obj) = manifest_value.as_object_mut() {
            obj.insert("complianceTemplate".to_string(), Value::String(tpl.clone()));
        }
    }

    // Sign manifest (excluding issuer.signature field).
    let unsigned_for_sig = {
        let mut v = manifest_value.clone();
        if let Some(obj) = v.as_object_mut() {
            obj.insert(
                "issuer".to_string(),
                serde_json::json!({ "publicKey": public_key, "signedAt": signed_at }),
            );
        }
        v
    };

    let canonical = hush_core::canonicalize_json(&unsigned_for_sig)?;
    let sig = signer.sign(canonical.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    let issuer = ManifestIssuer {
        public_key: URL_SAFE_NO_PAD.encode(signer.public_key().as_bytes()),
        signature: sig_b64,
        signed_at,
    };

    let manifest = EvidenceBundleManifest {
        export_id: export_id.to_string(),
        certification_id: certification.certification_id.clone(),
        generated_at,
        event_count: u64::try_from(events.len()).unwrap_or(u64::MAX),
        merkle_root: merkle_root.clone(),
        date_range: match (request.date_start.as_ref(), request.date_end.as_ref()) {
            (Some(start), Some(end)) => Some(DateRange {
                start: start.clone(),
                end: end.clone(),
            }),
            _ => None,
        },
        compliance_template: request.compliance_template.clone(),
        issuer,
    };

    zip.start_file("manifest.json", opts)?;
    zip.write_all(serde_json::to_string_pretty(&manifest)?.as_bytes())?;
    zip.write_all(b"\n")?;

    let mut file = zip.finish()?;
    file.flush()?;

    let bytes = std::fs::read(&file_path)?;
    let sha = hush_core::sha256(&bytes).to_hex();
    let size_bytes = u64::try_from(bytes.len()).unwrap_or(u64::MAX);

    Ok(EvidenceBundleOutput {
        file_path,
        sha256_hex: sha,
        size_bytes,
        merkle_root,
    })
}

fn merkle_root_for_events(events: &[AuditEventV2]) -> Result<String> {
    if events.is_empty() {
        return Ok(format!("sha256:{}", hush_core::Hash::zero().to_hex()));
    }

    let leaves: Vec<Vec<u8>> = events
        .iter()
        .filter_map(|e| hex::decode(&e.content_hash).ok())
        .collect();
    if leaves.is_empty() {
        return Ok(format!("sha256:{}", hush_core::Hash::zero().to_hex()));
    }

    let tree = hush_core::MerkleTree::from_leaves(&leaves)?;
    Ok(format!("sha256:{}", tree.root().to_hex()))
}
