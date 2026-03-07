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
use zip::DateTime as ZipDateTime;

use crate::audit::AuditEventV2;
use crate::badge::CertificationBadge;
use crate::certification::CertificationRecord;
use crate::Result;

const GENERIC_BUNDLE_ENTRY_LEAF_DOMAIN: &[u8] = b"clawdstrike:evidence-entry:v1\0";

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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenericEvidenceBundleSubject {
    pub kind: String,
    pub id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenericEvidenceBundleManifest {
    pub export_id: String,
    pub subject: GenericEvidenceBundleSubject,
    pub generated_at: String,
    pub entry_count: u64,
    pub merkle_root: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
    pub issuer: ManifestIssuer,
}

#[derive(Clone, Debug)]
pub struct GenericEvidenceBundleEntry {
    pub path: String,
    pub bytes: Vec<u8>,
}

struct GenericManifestPayload<'a> {
    export_id: &'a str,
    subject: &'a GenericEvidenceBundleSubject,
    generated_at: &'a str,
    entry_count: usize,
    merkle_root: &'a str,
    metadata: Option<&'a Value>,
    public_key: &'a str,
    signed_at: &'a str,
}

struct EvidenceManifestPayload<'a> {
    export_id: &'a str,
    certification_id: &'a str,
    generated_at: &'a str,
    event_count: usize,
    merkle_root: &'a str,
    request: &'a EvidenceExportRequest,
    public_key: &'a str,
    signed_at: &'a str,
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
        let expires_at =
            (Utc::now() + Duration::days(7)).to_rfc3339_opts(SecondsFormat::Nanos, true);
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

pub fn build_signed_evidence_bundle_zip(
    out_dir: impl AsRef<Path>,
    export_id: &str,
    subject: GenericEvidenceBundleSubject,
    generated_at: &str,
    metadata: Option<Value>,
    entries: &[GenericEvidenceBundleEntry],
    signer: &hush_core::Keypair,
) -> Result<EvidenceBundleOutput> {
    std::fs::create_dir_all(out_dir.as_ref())?;

    let file_path = out_dir.as_ref().join(format!("{export_id}.zip"));
    let file = File::create(&file_path)?;
    let mut zip = ZipWriter::new(file);
    let timestamp = ZipDateTime::from_date_and_time(1980, 1, 1, 0, 0, 0)
        .map_err(|_| crate::Error::InvalidInput("invalid reproducible ZIP timestamp".into()))?;
    let opts = FileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .last_modified_time(timestamp)
        .unix_permissions(0o644);

    let mut sorted_entries = entries.to_vec();
    sorted_entries.sort_by(|left, right| left.path.cmp(&right.path));

    for entry in &sorted_entries {
        zip.start_file(&entry.path, opts)?;
        zip.write_all(&entry.bytes)?;
    }

    let merkle_root = merkle_root_for_blobs(&sorted_entries)?;
    let signed_at = generated_at.to_string();
    let public_key = manifest_public_key(signer);
    let unsigned_for_sig = generic_manifest_signature_payload(GenericManifestPayload {
        export_id,
        subject: &subject,
        generated_at,
        entry_count: sorted_entries.len(),
        merkle_root: &merkle_root,
        metadata: metadata.as_ref(),
        public_key: &public_key,
        signed_at: &signed_at,
    });
    let issuer = sign_manifest_issuer(&unsigned_for_sig, signer, signed_at.clone())?;

    let manifest = GenericEvidenceBundleManifest {
        export_id: export_id.to_string(),
        subject,
        generated_at: generated_at.to_string(),
        entry_count: u64::try_from(sorted_entries.len()).unwrap_or(u64::MAX),
        merkle_root: merkle_root.clone(),
        metadata,
        issuer,
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;

    zip.start_file("manifest.json", opts)?;
    zip.write_all(&manifest_bytes)?;
    zip.write_all(b"\n")?;

    let mut file = zip.finish()?;
    file.flush()?;

    let bytes = std::fs::read(&file_path)?;
    Ok(EvidenceBundleOutput {
        file_path,
        sha256_hex: hush_core::sha256(&bytes).to_hex(),
        size_bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        merkle_root,
    })
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
    let public_key = manifest_public_key(signer);
    let unsigned_for_sig = evidence_manifest_signature_payload(EvidenceManifestPayload {
        export_id,
        certification_id: &certification.certification_id,
        generated_at: &generated_at,
        event_count: events.len(),
        merkle_root: &merkle_root,
        request,
        public_key: &public_key,
        signed_at: &signed_at,
    });
    let issuer = sign_manifest_issuer(&unsigned_for_sig, signer, signed_at.clone())?;

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
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;

    zip.start_file("manifest.json", opts)?;
    zip.write_all(&manifest_bytes)?;
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

fn merkle_root_for_blobs(entries: &[GenericEvidenceBundleEntry]) -> Result<String> {
    if entries.is_empty() {
        return Ok(format!("sha256:{}", hush_core::Hash::zero().to_hex()));
    }

    let leaves: Vec<Vec<u8>> = entries.iter().map(entry_merkle_leaf).collect();

    let tree = hush_core::MerkleTree::from_leaves(&leaves)?;
    Ok(format!("sha256:{}", tree.root().to_hex()))
}

fn entry_merkle_leaf(entry: &GenericEvidenceBundleEntry) -> Vec<u8> {
    let path_hash = hush_core::sha256(entry.path.as_bytes());
    let blob_hash = hush_core::sha256(&entry.bytes);
    let mut leaf_material = Vec::with_capacity(GENERIC_BUNDLE_ENTRY_LEAF_DOMAIN.len() + (32 * 2));
    leaf_material.extend_from_slice(GENERIC_BUNDLE_ENTRY_LEAF_DOMAIN);
    leaf_material.extend_from_slice(path_hash.as_bytes());
    leaf_material.extend_from_slice(blob_hash.as_bytes());
    hush_core::sha256(&leaf_material).as_bytes().to_vec()
}

fn manifest_public_key(signer: &hush_core::Keypair) -> String {
    URL_SAFE_NO_PAD.encode(signer.public_key().as_bytes())
}

fn sign_manifest_issuer(
    unsigned_for_sig: &Value,
    signer: &hush_core::Keypair,
    signed_at: String,
) -> Result<ManifestIssuer> {
    let canonical = hush_core::canonicalize_json(unsigned_for_sig)?;
    let sig = signer.sign(canonical.as_bytes());
    Ok(ManifestIssuer {
        public_key: manifest_public_key(signer),
        signature: URL_SAFE_NO_PAD.encode(sig.to_bytes()),
        signed_at,
    })
}

fn generic_manifest_signature_payload(payload: GenericManifestPayload<'_>) -> Value {
    let mut unsigned_for_sig = serde_json::json!({
        "exportId": payload.export_id,
        "subject": {
            "kind": &payload.subject.kind,
            "id": &payload.subject.id,
        },
        "generatedAt": payload.generated_at,
        "entryCount": payload.entry_count,
        "merkleRoot": payload.merkle_root,
        "issuer": {
            "publicKey": payload.public_key,
            "signedAt": payload.signed_at,
        },
    });

    if let Some(extra_metadata) = payload.metadata.cloned() {
        if let Some(obj) = unsigned_for_sig.as_object_mut() {
            obj.insert("metadata".to_string(), extra_metadata);
        }
    }

    unsigned_for_sig
}

fn evidence_manifest_signature_payload(payload: EvidenceManifestPayload<'_>) -> Value {
    let mut manifest_value = serde_json::json!({
        "exportId": payload.export_id,
        "certificationId": payload.certification_id,
        "generatedAt": payload.generated_at,
        "eventCount": payload.event_count,
        "merkleRoot": payload.merkle_root,
        "issuer": {
            "publicKey": payload.public_key,
            "signedAt": payload.signed_at,
        },
    });

    if let (Some(start), Some(end)) = (
        payload.request.date_start.as_ref(),
        payload.request.date_end.as_ref(),
    ) {
        if let Some(obj) = manifest_value.as_object_mut() {
            obj.insert(
                "dateRange".to_string(),
                serde_json::json!({ "start": start, "end": end }),
            );
        }
    }

    if let Some(tpl) = payload.request.compliance_template.as_ref() {
        if let Some(obj) = manifest_value.as_object_mut() {
            obj.insert("complianceTemplate".to_string(), Value::String(tpl.clone()));
        }
    }

    manifest_value
}

#[cfg(test)]
fn verify_manifest_signature(unsigned_for_sig: &Value, issuer: &ManifestIssuer) -> Result<bool> {
    let pubkey_bytes = URL_SAFE_NO_PAD
        .decode(&issuer.public_key)
        .map_err(|e| crate::Error::InvalidInput(format!("invalid issuer public key: {e}")))?;
    let pubkey_bytes: [u8; 32] = pubkey_bytes.try_into().map_err(|_| {
        crate::Error::InvalidInput("issuer public key must be 32 bytes".to_string())
    })?;
    let pubkey = hush_core::PublicKey::from_bytes(&pubkey_bytes)?;

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(&issuer.signature)
        .map_err(|e| crate::Error::InvalidInput(format!("invalid issuer signature: {e}")))?;
    let sig_bytes: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| crate::Error::InvalidInput("issuer signature must be 64 bytes".to_string()))?;
    let sig = hush_core::Signature::from_bytes(&sig_bytes);
    let canonical = hush_core::canonicalize_json(unsigned_for_sig)?;
    Ok(pubkey.verify(canonical.as_bytes(), &sig))
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use tempfile::tempdir;
    use zip::ZipArchive;

    use super::*;

    #[test]
    fn generic_bundle_manifest_signature_verifies() -> Result<()> {
        let tempdir = tempdir()?;
        let signer = hush_core::Keypair::generate();
        let subject = GenericEvidenceBundleSubject {
            kind: "case".to_string(),
            id: "case-1".to_string(),
        };
        let metadata = Some(serde_json::json!({ "tenant": "acme" }));
        let generated_at = "2026-03-06T12:00:00Z";
        let entries = vec![
            GenericEvidenceBundleEntry {
                path: "events/a.json".to_string(),
                bytes: br#"{"id":"a"}"#.to_vec(),
            },
            GenericEvidenceBundleEntry {
                path: "events/b.json".to_string(),
                bytes: br#"{"id":"b"}"#.to_vec(),
            },
        ];

        let output = build_signed_evidence_bundle_zip(
            tempdir.path(),
            "exp-test",
            subject.clone(),
            generated_at,
            metadata.clone(),
            &entries,
            &signer,
        )?;

        let file = File::open(output.file_path)?;
        let mut archive = ZipArchive::new(file)?;
        let mut manifest_file = archive.by_name("manifest.json")?;
        let mut manifest_json = String::new();
        manifest_file.read_to_string(&mut manifest_json)?;
        let manifest: GenericEvidenceBundleManifest = serde_json::from_str(&manifest_json)?;

        let unsigned = generic_manifest_signature_payload(GenericManifestPayload {
            export_id: &manifest.export_id,
            subject: &manifest.subject,
            generated_at: &manifest.generated_at,
            entry_count: manifest.entry_count as usize,
            merkle_root: &manifest.merkle_root,
            metadata: manifest.metadata.as_ref(),
            public_key: &manifest.issuer.public_key,
            signed_at: &manifest.issuer.signed_at,
        });
        assert!(
            verify_manifest_signature(&unsigned, &manifest.issuer)?,
            "manifest signature should verify"
        );
        assert_eq!(manifest.merkle_root, output.merkle_root);
        Ok(())
    }

    #[test]
    fn generic_bundle_merkle_root_binds_entry_paths() -> Result<()> {
        let original_entries = vec![GenericEvidenceBundleEntry {
            path: "events/a.json".to_string(),
            bytes: br#"{"id":"a"}"#.to_vec(),
        }];
        let renamed_entries = vec![GenericEvidenceBundleEntry {
            path: "events/renamed.json".to_string(),
            bytes: br#"{"id":"a"}"#.to_vec(),
        }];

        let original_root = merkle_root_for_blobs(&original_entries)?;
        let renamed_root = merkle_root_for_blobs(&renamed_entries)?;

        assert_ne!(original_root, renamed_root);
        Ok(())
    }

    #[test]
    fn evidence_bundle_manifest_signature_verifies() -> Result<()> {
        let tempdir = tempdir()?;
        let signer = hush_core::Keypair::generate();
        let certification = CertificationRecord {
            certification_id: "cert-1".to_string(),
            version: "1".to_string(),
            subject: crate::certification::Subject {
                subject_type: "agent".to_string(),
                id: "agent-1".to_string(),
                name: "Agent 1".to_string(),
                organization_id: Some("org-1".to_string()),
                metadata: None,
            },
            tier: crate::badge::CertificationTier::Gold,
            issue_date: "2026-03-06T12:00:00Z".to_string(),
            expiry_date: "2027-03-06T12:00:00Z".to_string(),
            frameworks: vec!["soc2".to_string()],
            status: crate::certification::CertificationStatus::Active,
            policy: crate::certification::PolicyBinding {
                hash: "sha256:policy".to_string(),
                version: "v1".to_string(),
                ruleset: None,
            },
            evidence: crate::certification::EvidenceBinding {
                receipt_count: 1,
                merkle_root: Some("sha256:evidence".to_string()),
                audit_log_ref: None,
                last_updated: None,
            },
            issuer: crate::certification::Issuer {
                id: "issuer-1".to_string(),
                name: "Issuer".to_string(),
                public_key: manifest_public_key(&signer),
                signature: "sig".to_string(),
                signed_at: "2026-03-06T12:00:00Z".to_string(),
            },
        };
        let badge = CertificationBadge {
            certification_id: certification.certification_id.clone(),
            version: certification.version.clone(),
            subject: crate::badge::BadgeSubject {
                subject_type: certification.subject.subject_type.clone(),
                id: certification.subject.id.clone(),
                name: certification.subject.name.clone(),
                metadata: None,
            },
            certification: crate::badge::BadgeCertificationBinding {
                tier: certification.tier,
                issue_date: certification.issue_date.clone(),
                expiry_date: certification.expiry_date.clone(),
                frameworks: certification.frameworks.clone(),
            },
            policy: crate::badge::BadgePolicyBinding {
                hash: certification.policy.hash.clone(),
                version: certification.policy.version.clone(),
                ruleset: certification.policy.ruleset.clone(),
            },
            evidence: crate::badge::BadgeEvidenceBinding {
                receipt_count: certification.evidence.receipt_count,
                merkle_root: certification.evidence.merkle_root.clone(),
                audit_log_ref: certification.evidence.audit_log_ref.clone(),
            },
            issuer: crate::badge::BadgeIssuer {
                id: certification.issuer.id.clone(),
                name: certification.issuer.name.clone(),
                public_key: certification.issuer.public_key.clone(),
                signature: certification.issuer.signature.clone(),
                signed_at: certification.issuer.signed_at.clone(),
            },
        };
        let events = vec![AuditEventV2 {
            event_id: "evt-1".to_string(),
            timestamp: "2026-03-06T12:00:00Z".to_string(),
            sequence: 1,
            session_id: "sess-1".to_string(),
            agent_id: Some("agent-1".to_string()),
            organization_id: Some("org-1".to_string()),
            correlation_id: None,
            action_type: "tool_call".to_string(),
            action_resource: "terminal.exec".to_string(),
            action_parameters: None,
            action_result: None,
            decision_allowed: true,
            decision_guard: Some("allow".to_string()),
            decision_severity: Some("low".to_string()),
            decision_reason: Some("ok".to_string()),
            decision_policy_hash: "sha256:policy".to_string(),
            provenance: None,
            extensions: None,
            content_hash: hush_core::sha256(br#"{"event":"evt-1"}"#).to_hex(),
            previous_hash: hush_core::Hash::zero().to_hex(),
            signature: None,
        }];
        let request = EvidenceExportRequest {
            date_start: Some("2026-03-01T00:00:00Z".to_string()),
            date_end: Some("2026-03-06T23:59:59Z".to_string()),
            include_types: Some(vec!["audit".to_string()]),
            compliance_template: Some("soc2".to_string()),
        };

        let output = build_evidence_bundle_zip(
            tempdir.path(),
            "export-1",
            &certification,
            &badge,
            &events,
            &request,
            &signer,
        )?;

        let file = File::open(output.file_path)?;
        let mut archive = ZipArchive::new(file)?;
        let mut manifest_file = archive.by_name("manifest.json")?;
        let mut manifest_json = String::new();
        manifest_file.read_to_string(&mut manifest_json)?;
        let manifest: EvidenceBundleManifest = serde_json::from_str(&manifest_json)?;

        let unsigned = evidence_manifest_signature_payload(EvidenceManifestPayload {
            export_id: &manifest.export_id,
            certification_id: &manifest.certification_id,
            generated_at: &manifest.generated_at,
            event_count: manifest.event_count as usize,
            merkle_root: &manifest.merkle_root,
            request: &request,
            public_key: &manifest.issuer.public_key,
            signed_at: &manifest.issuer.signed_at,
        });
        assert!(
            verify_manifest_signature(&unsigned, &manifest.issuer)?,
            "evidence manifest signature should verify"
        );
        assert_eq!(manifest.merkle_root, output.merkle_root);
        Ok(())
    }
}
