//! Persistent scan history and SHA-256 change detection.
//!
//! Between scans, a JSON history file is stored at
//! `~/.clawdstrike/scan_history.json`. Each entry records a SHA-256 hash of
//! the server's tool signature so that [`diff_history`] can report new,
//! removed, and changed servers.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::models::{ScanPathResult, ServerSignature};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A snapshot of one server's signature at scan time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRecord {
    pub timestamp: DateTime<Utc>,
    pub signature_hash: String,
    pub tool_names: Vec<String>,
    pub prompt_count: usize,
    pub resource_count: usize,
}

/// The persisted scan history.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanHistory {
    pub servers: HashMap<String, ScanRecord>,
    pub last_scan: Option<DateTime<Utc>>,
}

/// A change to a single server between scans.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerChange {
    pub server_key: String,
    pub old_hash: String,
    pub new_hash: String,
    pub added_tools: Vec<String>,
    pub removed_tools: Vec<String>,
}

/// Summary of changes between two scan snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanDiff {
    pub new_servers: Vec<String>,
    pub removed_servers: Vec<String>,
    pub changed_servers: Vec<ServerChange>,
}

impl ScanDiff {
    /// Returns `true` when no changes were detected.
    pub fn is_empty(&self) -> bool {
        self.new_servers.is_empty()
            && self.removed_servers.is_empty()
            && self.changed_servers.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

/// Compute a SHA-256 hash of a server signature's full tool definitions
/// (sorted for determinism).
pub fn hash_server_signature(sig: &ServerSignature) -> String {
    let mut entries = Vec::with_capacity(sig.tools.len());
    for tool in &sig.tools {
        // Hash the full serialized tool definition (including inputSchema) so
        // drift detection catches capability changes beyond name/description.
        let entry = match serde_json::to_value(tool) {
            Ok(value) => hush_core::canonicalize_json(&value)
                .unwrap_or_else(|_| format!("{}:{value}", tool.name)),
            Err(_) => format!(
                "{}:{}",
                tool.name,
                tool.description.as_deref().unwrap_or("")
            ),
        };
        entries.push(entry);
    }
    entries.sort();

    let mut hasher = Sha256::new();
    for entry in &entries {
        hasher.update(entry.as_bytes());
        hasher.update(b"\n");
    }
    format!("{:x}", hasher.finalize())
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

/// Default storage path: `~/.clawdstrike/scan_history.json`.
pub fn default_history_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".clawdstrike").join("scan_history.json"))
}

/// Load scan history from disk. Returns a default (empty) history if the file
/// does not exist or cannot be parsed.
pub fn load_history(path: &Path) -> ScanHistory {
    match std::fs::read_to_string(path) {
        Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
        Err(_) => ScanHistory::default(),
    }
}

/// Save scan history to disk, creating parent directories as needed.
pub fn save_history(path: &Path, history: &ScanHistory) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(history).map_err(std::io::Error::other)?;
    std::fs::write(path, json)
}

// ---------------------------------------------------------------------------
// Diff
// ---------------------------------------------------------------------------

/// Build a unique key for a server within a scan result.
fn server_key(path: &str, server_name: Option<&str>) -> String {
    match server_name {
        Some(name) => format!("{path}::{name}"),
        None => path.to_string(),
    }
}

/// Compare current scan results against the previous history and produce a
/// new history plus a diff summary.
pub fn diff_history(results: &[ScanPathResult], old: &ScanHistory) -> (ScanDiff, ScanHistory) {
    let now = Utc::now();
    let mut new_history = ScanHistory {
        servers: HashMap::new(),
        last_scan: Some(now),
    };

    let mut current_keys: HashMap<String, (String, Vec<String>)> = HashMap::new();

    for result in results {
        let servers = match result.servers.as_ref() {
            Some(s) => s,
            None => continue,
        };

        for srv in servers {
            let sig = match srv.signature.as_ref() {
                Some(s) => s,
                None => continue,
            };

            let key = server_key(&result.path, srv.name.as_deref());
            let hash = hash_server_signature(sig);
            let tool_names: Vec<String> = sig.tools.iter().map(|t| t.name.clone()).collect();

            new_history.servers.insert(
                key.clone(),
                ScanRecord {
                    timestamp: now,
                    signature_hash: hash.clone(),
                    tool_names: tool_names.clone(),
                    prompt_count: sig.prompts.len(),
                    resource_count: sig.resources.len(),
                },
            );

            current_keys.insert(key, (hash, tool_names));
        }
    }

    let mut diff = ScanDiff {
        new_servers: vec![],
        removed_servers: vec![],
        changed_servers: vec![],
    };

    // Detect new and changed servers
    for (key, (hash, tool_names)) in &current_keys {
        match old.servers.get(key) {
            None => {
                diff.new_servers.push(key.clone());
            }
            Some(old_record) => {
                if old_record.signature_hash != *hash {
                    let old_set: std::collections::HashSet<&str> =
                        old_record.tool_names.iter().map(|s| s.as_str()).collect();
                    let new_set: std::collections::HashSet<&str> =
                        tool_names.iter().map(|s| s.as_str()).collect();

                    let added: Vec<String> = new_set
                        .difference(&old_set)
                        .map(|s| (*s).to_string())
                        .collect();
                    let removed: Vec<String> = old_set
                        .difference(&new_set)
                        .map(|s| (*s).to_string())
                        .collect();

                    diff.changed_servers.push(ServerChange {
                        server_key: key.clone(),
                        old_hash: old_record.signature_hash.clone(),
                        new_hash: hash.clone(),
                        added_tools: added,
                        removed_tools: removed,
                    });
                }
            }
        }
    }

    for key in old.servers.keys() {
        if !current_keys.contains_key(key) {
            diff.removed_servers.push(key.clone());
        }
    }

    (diff, new_history)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        ScanPathResult, ServerConfig, ServerScanResult, ServerSignature, StdioServer, Tool,
    };

    fn make_sig(tools: &[&str]) -> ServerSignature {
        ServerSignature {
            metadata: serde_json::json!({}),
            prompts: vec![],
            resources: vec![],
            resource_templates: vec![],
            tools: tools
                .iter()
                .map(|name| Tool {
                    name: (*name).to_string(),
                    description: Some(format!("desc for {name}")),
                    input_schema: None,
                })
                .collect(),
        }
    }

    fn make_scan_result(path: &str, server_name: &str, tools: &[&str]) -> ScanPathResult {
        ScanPathResult {
            client: Some("test".into()),
            path: path.into(),
            servers: Some(vec![ServerScanResult {
                name: Some(server_name.into()),
                server: ServerConfig::Stdio(StdioServer {
                    command: "node".into(),
                    args: None,
                    server_type: None,
                    env: None,
                    binary_identifier: None,
                }),
                signature: Some(make_sig(tools)),
                error: None,
            }]),
            issues: vec![],
            labels: vec![],
            policy_violations: vec![],
            error: None,
        }
    }

    #[test]
    fn test_hash_deterministic() {
        let sig = make_sig(&["tool_a", "tool_b"]);
        let h1 = hash_server_signature(&sig);
        let h2 = hash_server_signature(&sig);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_order_independent() {
        let sig1 = make_sig(&["tool_a", "tool_b"]);
        let sig2 = make_sig(&["tool_b", "tool_a"]);
        assert_eq!(hash_server_signature(&sig1), hash_server_signature(&sig2));
    }

    #[test]
    fn test_hash_changes_when_input_schema_changes() {
        let mut sig1 = make_sig(&["tool_a"]);
        let mut sig2 = make_sig(&["tool_a"]);
        sig1.tools[0].input_schema = Some(serde_json::json!({
            "type": "object",
            "properties": {"path": {"type": "string"}}
        }));
        sig2.tools[0].input_schema = Some(serde_json::json!({
            "type": "object",
            "properties": {"path": {"type": "number"}}
        }));

        assert_ne!(hash_server_signature(&sig1), hash_server_signature(&sig2));
    }

    #[test]
    fn test_diff_new_servers() {
        let results = vec![make_scan_result("test.json", "server1", &["tool1"])];
        let old = ScanHistory::default();
        let (diff, _new_history) = diff_history(&results, &old);
        assert_eq!(diff.new_servers.len(), 1);
        assert!(diff.removed_servers.is_empty());
        assert!(diff.changed_servers.is_empty());
    }

    #[test]
    fn test_diff_no_changes() {
        let results = vec![make_scan_result("test.json", "server1", &["tool1"])];
        let old = ScanHistory::default();
        let (_diff, new_history) = diff_history(&results, &old);

        // Second diff with same results should show no changes
        let (diff2, _) = diff_history(&results, &new_history);
        assert!(diff2.is_empty());
    }

    #[test]
    fn test_diff_removed_server() {
        let results = vec![make_scan_result("test.json", "server1", &["tool1"])];
        let old = ScanHistory::default();
        let (_diff, new_history) = diff_history(&results, &old);

        // Empty results = server was removed
        let (diff2, _) = diff_history(&[], &new_history);
        assert_eq!(diff2.removed_servers.len(), 1);
    }

    #[test]
    fn test_diff_changed_server() {
        let results1 = vec![make_scan_result("test.json", "server1", &["tool1"])];
        let old = ScanHistory::default();
        let (_diff, history1) = diff_history(&results1, &old);

        let results2 = vec![make_scan_result(
            "test.json",
            "server1",
            &["tool1", "tool2"],
        )];
        let (diff2, _) = diff_history(&results2, &history1);
        assert_eq!(diff2.changed_servers.len(), 1);
        assert!(diff2.changed_servers[0]
            .added_tools
            .contains(&"tool2".to_string()));
    }

    #[test]
    fn test_load_save_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.json");

        let mut history = ScanHistory {
            last_scan: Some(Utc::now()),
            ..ScanHistory::default()
        };
        history.servers.insert(
            "test::server".into(),
            ScanRecord {
                timestamp: Utc::now(),
                signature_hash: "abc123".into(),
                tool_names: vec!["tool1".into()],
                prompt_count: 1,
                resource_count: 0,
            },
        );

        save_history(&path, &history).unwrap();
        let loaded = load_history(&path);
        assert_eq!(loaded.servers.len(), 1);
        assert!(loaded.servers.contains_key("test::server"));
    }

    #[test]
    fn test_load_missing_file_returns_default() {
        let history = load_history(Path::new("/nonexistent/path/history.json"));
        assert!(history.servers.is_empty());
        assert!(history.last_scan.is_none());
    }
}
