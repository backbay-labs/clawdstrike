//! Detection engineering commands — Sigma, YARA, and OCSF validation, testing, and conversion.
//!
//! Provides structural validation, Sigma rule compilation/testing via `hunt_correlate`,
//! OCSF normalization via `clawdstrike_ocsf`, and Sigma-to-policy conversion.

use super::workbench::{
    check_sensitive_path, export_policy_file, read_text_file_secure, validate_file_path,
    write_text_file_secure, ExportResponse,
};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Maximum source text size accepted via IPC (2 MiB).
const MAX_SOURCE_SIZE: usize = 2 * 1024 * 1024;

// ---- Response Types ----

#[derive(Debug, Serialize, Deserialize)]
pub struct DetectionDiagnostic {
    pub severity: String, // "error" | "warning" | "info"
    pub message: String,
    pub line: Option<u32>,
    pub column: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SigmaValidationResponse {
    pub valid: bool,
    pub diagnostics: Vec<DetectionDiagnostic>,
    pub compiled_preview: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct YaraValidationResponse {
    pub valid: bool,
    pub diagnostics: Vec<DetectionDiagnostic>,
    pub rule_count: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OcsfValidationResponse {
    pub valid: bool,
    pub diagnostics: Vec<DetectionDiagnostic>,
    pub class_uid: Option<u32>,
    pub event_class: Option<String>,
}

// ---- Sigma Test/Compile Response Types ----

#[derive(Debug, Serialize, Deserialize)]
pub struct SigmaTestResponse {
    pub matched: bool,
    pub findings: Vec<SigmaTestFindingEntry>,
    pub events_tested: usize,
    pub events_matched: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SigmaTestFindingEntry {
    pub title: String,
    pub severity: String,
    pub evidence_refs: Vec<String>,
    pub event_index: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SigmaCompileResponse {
    pub valid: bool,
    pub title: Option<String>,
    pub compiled_artifact: Option<String>,
    pub diagnostics: Vec<DetectionDiagnostic>,
}

// ---- OCSF Normalize Response Types ----

#[derive(Debug, Serialize, Deserialize)]
pub struct OcsfNormalizeResponse {
    pub valid: bool,
    pub class_uid: Option<i64>,
    pub event_class: Option<String>,
    pub missing_fields: Vec<String>,
    pub invalid_fields: Vec<OcsfFieldError>,
    pub diagnostics: Vec<DetectionDiagnostic>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OcsfFieldError {
    pub field: String,
    pub error: String,
}

// ---- Sigma Convert Response Type ----

#[derive(Debug, Serialize, Deserialize)]
pub struct SigmaConvertResponse {
    pub success: bool,
    pub target_format: String,
    pub output: Option<String>,
    pub diagnostics: Vec<DetectionDiagnostic>,
    pub converter_version: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DetectionFileType {
    pub file_type: String,
    pub confidence: f32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DetectionImportResponse {
    pub content: String,
    pub file_type: String,
}

// ---- Size Guard ----

fn check_source_size(source: &str) -> Result<(), String> {
    if source.len() > MAX_SOURCE_SIZE {
        return Err(format!(
            "Source text exceeds maximum size ({} bytes > {} bytes)",
            source.len(),
            MAX_SOURCE_SIZE
        ));
    }
    Ok(())
}

/// Count structural (rule-level) braces in a YARA source line, ignoring braces
/// inside `"strings"`, `/regex/` literals, and YARA hex string literals (`{ AB CD ?? }`).
///
/// Hex string context is detected by a preceding `=` before `{` — YARA hex strings
/// are always assigned via `$hex = { ... }`. When we see `= {`, we enter hex-string
/// mode and skip all content (including `{`/`}`) until the closing `}`.
fn count_braces_outside_literals(line: &str) -> (i32, i32) {
    let mut opens = 0;
    let mut closes = 0;
    let mut in_string = false;
    let mut in_regex = false;
    let mut in_hex_string = false;
    let mut escaped = false;
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;
    // Track the last non-whitespace character before the current position to detect
    // hex string assignment context (`= {`).
    let mut last_non_ws: Option<char> = None;

    while i < chars.len() {
        let ch = chars[i];

        if escaped {
            escaped = false;
            i += 1;
            continue;
        }

        if ch == '\\' && (in_string || in_regex) {
            escaped = true;
            i += 1;
            continue;
        }

        // End-of-line comment
        if !in_string && !in_regex && !in_hex_string && ch == '/' && chars.get(i + 1) == Some(&'/') {
            break;
        }

        // Hex string closing brace — exit hex mode, don't count the brace
        if in_hex_string {
            if ch == '}' {
                in_hex_string = false;
                last_non_ws = Some(ch);
            }
            i += 1;
            continue;
        }

        if ch == '"' && !in_regex {
            in_string = !in_string;
            last_non_ws = Some(ch);
            i += 1;
            continue;
        }

        if ch == '/' && !in_string {
            let prev = if i > 0 { chars[i - 1] } else { ' ' };
            let next = chars.get(i + 1).copied().unwrap_or(' ');
            if !in_regex && !prev.is_alphanumeric() && next != '/' && next != '*' {
                in_regex = true;
                last_non_ws = Some(ch);
                i += 1;
                continue;
            }
            if in_regex {
                in_regex = false;
                last_non_ws = Some(ch);
                i += 1;
                while i < chars.len() && chars[i].is_ascii_alphabetic() {
                    i += 1;
                }
                continue;
            }
        }

        if !in_string && !in_regex {
            if ch == '{' {
                // Detect hex string context: the last non-whitespace char before `{` is `=`
                if last_non_ws == Some('=') {
                    in_hex_string = true;
                    i += 1;
                    continue;
                }
                opens += 1;
            } else if ch == '}' {
                closes += 1;
            }
        }

        if !ch.is_whitespace() {
            last_non_ws = Some(ch);
        }
        i += 1;
    }

    (opens, closes)
}

fn format_detection_diagnostic(diagnostic: &DetectionDiagnostic) -> String {
    match (diagnostic.line, diagnostic.column) {
        (Some(line), Some(column)) => format!("line {line}:{column}: {}", diagnostic.message),
        (Some(line), None) => format!("line {line}: {}", diagnostic.message),
        _ => diagnostic.message.clone(),
    }
}

fn detect_file_type_from_content(content: &str) -> DetectionFileType {
    if content.contains("guards:") || content.contains("schema_version:") {
        return DetectionFileType {
            file_type: "clawdstrike_policy".into(),
            confidence: 0.9,
        };
    }
    if content.contains("detection:") && content.contains("logsource:") {
        return DetectionFileType {
            file_type: "sigma_rule".into(),
            confidence: 0.9,
        };
    }
    // YARA check must precede JSON check — a YARA hex test like `{ rule x { condition: true } }`
    // starts with `{` but should not be misidentified as JSON/OCSF.
    if content.contains("rule ") && content.contains("condition:") {
        return DetectionFileType {
            file_type: "yara_rule".into(),
            confidence: 0.8,
        };
    }
    // Sigma heuristic: require `title:` + `status:` but not if YARA markers are also present
    // (a YARA meta section may contain `title:` and `status:` fields).
    if content.contains("title:")
        && content.contains("status:")
        && !content.contains("guards:")
        && !(content.contains("rule ") && content.contains("condition:"))
    {
        return DetectionFileType {
            file_type: "sigma_rule".into(),
            confidence: 0.7,
        };
    }
    if content.trim_start().starts_with('{') {
        return DetectionFileType {
            file_type: "ocsf_event".into(),
            confidence: 0.6,
        };
    }

    DetectionFileType {
        file_type: "clawdstrike_policy".into(),
        confidence: 0.3,
    }
}

fn detect_file_type_from_path_and_content(path: &str, content: &str) -> DetectionFileType {
    let extension = Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase());

    if matches!(extension.as_deref(), Some("yar" | "yara")) {
        return DetectionFileType {
            file_type: "yara_rule".into(),
            confidence: 1.0,
        };
    }
    if matches!(extension.as_deref(), Some("json")) {
        return DetectionFileType {
            file_type: "ocsf_event".into(),
            confidence: 1.0,
        };
    }

    detect_file_type_from_content(content)
}

// ---- Sigma Commands ----

#[tauri::command]
pub fn validate_sigma_rule(source: String) -> Result<SigmaValidationResponse, String> {
    check_source_size(&source)?;

    match serde_yaml::from_str::<serde_yaml::Value>(&source) {
        Ok(value) => {
            let mut diagnostics = Vec::new();

            let Some(map) = value.as_mapping() else {
                diagnostics.push(DetectionDiagnostic {
                    severity: "error".into(),
                    message: "Sigma rule must be a YAML mapping/object".into(),
                    line: None,
                    column: None,
                });

                return Ok(SigmaValidationResponse {
                    valid: false,
                    diagnostics,
                    compiled_preview: None,
                });
            };

            if !map.contains_key(serde_yaml::Value::String("title".into())) {
                diagnostics.push(DetectionDiagnostic {
                    severity: "error".into(),
                    message: "Missing required field: title".into(),
                    line: None,
                    column: None,
                });
            }
            if !map.contains_key(serde_yaml::Value::String("detection".into())) {
                diagnostics.push(DetectionDiagnostic {
                    severity: "error".into(),
                    message: "Missing required field: detection".into(),
                    line: None,
                    column: None,
                });
            }
            if !map.contains_key(serde_yaml::Value::String("logsource".into())) {
                diagnostics.push(DetectionDiagnostic {
                    severity: "error".into(),
                    message: "Missing required field: logsource".into(),
                    line: None,
                    column: None,
                });
            }

            if let Some(detection) = map.get(serde_yaml::Value::String("detection".into())) {
                if !detection.is_mapping() {
                    diagnostics.push(DetectionDiagnostic {
                        severity: "error".into(),
                        message: "detection must be a YAML mapping/object".into(),
                        line: None,
                        column: None,
                    });
                } else if !detection.as_mapping().is_some_and(|det| {
                    det.contains_key(serde_yaml::Value::String("condition".into()))
                }) {
                    diagnostics.push(DetectionDiagnostic {
                        severity: "error".into(),
                        message: "detection.condition is required".into(),
                        line: None,
                        column: None,
                    });
                }
            }

            if let Some(logsource) = map.get(serde_yaml::Value::String("logsource".into())) {
                if !logsource.is_mapping() {
                    diagnostics.push(DetectionDiagnostic {
                        severity: "error".into(),
                        message: "logsource must be a YAML mapping/object".into(),
                        line: None,
                        column: None,
                    });
                }
            }

            let valid = diagnostics.is_empty();
            Ok(SigmaValidationResponse {
                valid,
                diagnostics,
                compiled_preview: None,
            })
        }
        Err(e) => Ok(SigmaValidationResponse {
            valid: false,
            diagnostics: vec![DetectionDiagnostic {
                severity: "error".into(),
                message: format!("YAML parse error: {e}"),
                line: e.location().map(|l| l.line() as u32),
                column: e.location().map(|l| l.column() as u32),
            }],
            compiled_preview: None,
        }),
    }
}

// ---- YARA Commands ----

#[tauri::command]
pub fn validate_yara_rule(source: String) -> Result<YaraValidationResponse, String> {
    check_source_size(&source)?;

    let mut diagnostics = Vec::new();
    let mut rule_count = 0u32;
    // Track brace depth as i32 to detect negative depth (more closes than opens).
    let mut current_rule: Option<(String, i32, bool)> = None;

    for (idx, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        let line_no = (idx + 1) as u32;

        // Try stripping optional modifiers, then check for "rule " prefix
        let after_modifiers = trimmed
            .strip_prefix("private ")
            .or_else(|| trimmed.strip_prefix("global "))
            .unwrap_or(trimmed);
        {
            if let Some(rule_decl) = after_modifiers.strip_prefix("rule ") {
                if let Some((rule_name, _, saw_condition)) = current_rule.take() {
                    if !saw_condition {
                        diagnostics.push(DetectionDiagnostic {
                            severity: "error".into(),
                            message: format!(
                                "YARA rule '{rule_name}' is missing a required 'condition:' section"
                            ),
                            line: Some(line_no.saturating_sub(1)),
                            column: None,
                        });
                    }
                }

                let rule_name = rule_decl
                    .split(|c: char| c.is_whitespace() || c == '{' || c == ':')
                    .next()
                    .unwrap_or("unnamed")
                    .to_string();
                let (opens, closes) = count_braces_outside_literals(line);
                current_rule = Some((rule_name, opens - closes, false));
                rule_count += 1;
                continue;
            }
        }

        if let Some((rule_name, brace_depth, saw_condition)) = current_rule.as_mut() {
            if trimmed.starts_with("condition:") {
                *saw_condition = true;
            }

            let (opens, closes) = count_braces_outside_literals(line);
            *brace_depth += opens - closes;

            if *brace_depth < 0 {
                diagnostics.push(DetectionDiagnostic {
                    severity: "error".into(),
                    message: format!(
                        "YARA rule '{rule_name}' has unbalanced braces (more closing than opening)"
                    ),
                    line: Some(line_no),
                    column: None,
                });
                current_rule = None;
            } else if *brace_depth == 0 {
                if !*saw_condition {
                    diagnostics.push(DetectionDiagnostic {
                        severity: "error".into(),
                        message: format!(
                            "YARA rule '{rule_name}' is missing a required 'condition:' section"
                        ),
                        line: Some(line_no),
                        column: None,
                    });
                }
                current_rule = None;
            }
        }
    }

    if let Some((rule_name, brace_depth, saw_condition)) = current_rule {
        if !saw_condition {
            diagnostics.push(DetectionDiagnostic {
                severity: "error".into(),
                message: format!(
                    "YARA rule '{rule_name}' is missing a required 'condition:' section"
                ),
                line: None,
                column: None,
            });
        }
        if brace_depth != 0 {
            diagnostics.push(DetectionDiagnostic {
                severity: "error".into(),
                message: format!("YARA rule '{rule_name}' has unbalanced braces"),
                line: None,
                column: None,
            });
        }
    }

    if rule_count == 0 {
        diagnostics.push(DetectionDiagnostic {
            severity: "error".into(),
            message: "No YARA rule declarations found. Rules must start with 'rule <name>'".into(),
            line: None,
            column: None,
        });
    }

    let valid = diagnostics.is_empty();
    Ok(YaraValidationResponse {
        valid,
        diagnostics,
        rule_count,
    })
}

// ---- OCSF Commands ----

#[tauri::command]
pub fn validate_ocsf_event(json: String) -> Result<OcsfValidationResponse, String> {
    check_source_size(&json)?;

    match serde_json::from_str::<serde_json::Value>(&json) {
        Ok(value) => {
            if !value.is_object() {
                return Ok(OcsfValidationResponse {
                    valid: false,
                    diagnostics: vec![DetectionDiagnostic {
                        severity: "error".into(),
                        message: "OCSF event must be a JSON object".into(),
                        line: None,
                        column: None,
                    }],
                    class_uid: None,
                    event_class: None,
                });
            }

            let mut diagnostics = Vec::new();
            let has_class_uid = value.get("class_uid").is_some();
            let class_uid = match value.get("class_uid") {
                Some(v) => match v.as_u64() {
                    Some(uid) if uid <= u32::MAX as u64 => Some(uid as u32),
                    Some(_) => {
                        diagnostics.push(DetectionDiagnostic {
                            severity: "error".into(),
                            message: "class_uid exceeds the maximum supported u32 value".into(),
                            line: None,
                            column: None,
                        });
                        None
                    }
                    None => {
                        diagnostics.push(DetectionDiagnostic {
                            severity: "error".into(),
                            message: "class_uid must be an unsigned integer".into(),
                            line: None,
                            column: None,
                        });
                        None
                    }
                },
                None => None,
            };

            if !has_class_uid {
                diagnostics.push(DetectionDiagnostic {
                    severity: "error".into(),
                    message: "Missing required field: class_uid".into(),
                    line: None,
                    column: None,
                });
            }

            if value.get("activity_id").is_none() {
                diagnostics.push(DetectionDiagnostic {
                    severity: "error".into(),
                    message: "Missing required field: activity_id".into(),
                    line: None,
                    column: None,
                });
            }

            if value.get("severity_id").is_none() {
                diagnostics.push(DetectionDiagnostic {
                    severity: "error".into(),
                    message: "Missing required field: severity_id".into(),
                    line: None,
                    column: None,
                });
            }

            if value.get("metadata").is_none() {
                diagnostics.push(DetectionDiagnostic {
                    severity: "warning".into(),
                    message: "Missing recommended field: metadata".into(),
                    line: None,
                    column: None,
                });
            }

            let event_class = class_uid.map(|uid| match uid {
                1001 => "File Activity".into(),
                1007 => "Process Activity".into(),
                2004 => "Detection Finding".into(),
                4001 => "Network Activity".into(),
                _ => format!("Unknown ({})", uid),
            });

            let valid = diagnostics.iter().all(|d| d.severity != "error");
            Ok(OcsfValidationResponse {
                valid,
                diagnostics,
                class_uid,
                event_class,
            })
        }
        Err(e) => Ok(OcsfValidationResponse {
            valid: false,
            diagnostics: vec![DetectionDiagnostic {
                severity: "error".into(),
                message: format!("JSON parse error: {e}"),
                line: Some(e.line() as u32),
                column: Some(e.column() as u32),
            }],
            class_uid: None,
            event_class: None,
        }),
    }
}

// ---- File-Type Detection ----

#[tauri::command]
pub fn detect_file_type(content: String) -> Result<DetectionFileType, String> {
    check_source_size(&content)?;
    Ok(detect_file_type_from_content(&content))
}

#[tauri::command]
pub async fn import_detection_file(path: String) -> Result<DetectionImportResponse, String> {
    let import_path = validate_file_path(&path)?;

    // Check sensitive path BEFORE reading file content
    if import_path.exists() {
        if let Ok(canon) = import_path.canonicalize() {
            let canon_check = canon.to_string_lossy().replace('\\', "/").to_lowercase();
            check_sensitive_path(&canon_check)?;
        }
    }

    // Check file size via metadata BEFORE reading the full file into memory
    if let Ok(metadata) = std::fs::metadata(&import_path) {
        let file_size = metadata.len() as usize;
        if file_size > MAX_SOURCE_SIZE {
            return Err(format!(
                "File exceeds maximum size ({} bytes > {} bytes)",
                file_size, MAX_SOURCE_SIZE
            ));
        }
    }

    let content = read_text_file_secure(import_path).await?;

    let detected = detect_file_type_from_path_and_content(&path, &content);
    Ok(DetectionImportResponse {
        content,
        file_type: detected.file_type,
    })
}

#[tauri::command]
pub async fn export_detection_file(
    content: String,
    path: String,
    file_type: String,
) -> Result<ExportResponse, String> {
    if file_type == "clawdstrike_policy" {
        return export_policy_file(content, path, Some("yaml".into())).await;
    }

    check_source_size(&content)?;
    let _ = validate_file_path(&path)?;

    let validation_failed = match file_type.as_str() {
        "sigma_rule" => {
            let result = validate_sigma_rule(content.clone())?;
            if result.valid {
                None
            } else {
                let details = result
                    .diagnostics
                    .iter()
                    .map(format_detection_diagnostic)
                    .collect::<Vec<_>>()
                    .join("; ");
                Some(if details.is_empty() {
                    "Validation failed".to_string()
                } else {
                    details
                })
            }
        }
        "yara_rule" => {
            let result = validate_yara_rule(content.clone())?;
            if result.valid {
                None
            } else {
                let details = result
                    .diagnostics
                    .iter()
                    .map(format_detection_diagnostic)
                    .collect::<Vec<_>>()
                    .join("; ");
                Some(if details.is_empty() {
                    "Validation failed".to_string()
                } else {
                    details
                })
            }
        }
        "ocsf_event" => {
            let result = validate_ocsf_event(content.clone())?;
            if result.valid {
                None
            } else {
                let details = result
                    .diagnostics
                    .iter()
                    .filter(|d| d.severity == "error")
                    .map(format_detection_diagnostic)
                    .collect::<Vec<_>>()
                    .join("; ");
                Some(if details.is_empty() {
                    "Validation failed".to_string()
                } else {
                    details
                })
            }
        }
        _ => Some("Unsupported detection file type".into()),
    };

    if let Some(message) = validation_failed {
        return Ok(ExportResponse {
            success: false,
            path,
            message: format!("Validation failed: {message}"),
        });
    }

    let export_path = validate_file_path(&path)?;

    // Check sensitive path BEFORE writing to prevent writing to sensitive locations
    if let Ok(canon) = export_path.canonicalize().or_else(|_| {
        // If the file doesn't exist yet, canonicalize the parent directory
        export_path.parent()
            .and_then(|p| p.canonicalize().ok())
            .map(|p| p.join(export_path.file_name().unwrap_or_default()))
            .ok_or(std::io::Error::new(std::io::ErrorKind::NotFound, "no parent"))
    }) {
        let canon_check = canon.to_string_lossy().replace('\\', "/").to_lowercase();
        check_sensitive_path(&canon_check)?;
    }

    write_text_file_secure(export_path, content).await?;

    Ok(ExportResponse {
        success: true,
        path,
        message: "Detection file exported successfully".into(),
    })
}

// ---- Sigma Testing & Compilation Commands ----

/// Maximum events JSON payload size (8 MiB — events arrays can be larger than rules).
const MAX_EVENTS_SIZE: usize = 8 * 1024 * 1024;

/// Build a [`hunt_query::timeline::TimelineEvent`] from a user-provided JSON object.
///
/// Since `TimelineEvent` does not derive `Deserialize`, we construct it field-by-field
/// from the parsed JSON value. Unrecognized or missing optional fields fall back to
/// sensible defaults so that minimal test payloads work out of the box.
fn json_to_timeline_event(
    value: &serde_json::Value,
) -> Result<hunt_query::timeline::TimelineEvent, String> {
    let timestamp_str = value
        .get("timestamp")
        .and_then(|v| v.as_str())
        .unwrap_or("2026-01-01T00:00:00Z");
    let timestamp = chrono::DateTime::parse_from_rfc3339(timestamp_str)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| chrono::Utc::now());

    let source = value
        .get("source")
        .and_then(|v| v.as_str())
        .and_then(hunt_query::query::EventSource::parse)
        .unwrap_or(hunt_query::query::EventSource::Receipt);

    let kind = value
        .get("kind")
        .and_then(|v| v.as_str())
        .and_then(hunt_query::timeline::TimelineEventKind::parse)
        .unwrap_or(hunt_query::timeline::TimelineEventKind::GuardDecision);

    let verdict = value
        .get("verdict")
        .and_then(|v| v.as_str())
        .and_then(hunt_query::timeline::NormalizedVerdict::parse)
        .unwrap_or(hunt_query::timeline::NormalizedVerdict::None);

    Ok(hunt_query::timeline::TimelineEvent {
        event_id: value.get("event_id").and_then(|v| v.as_str()).map(String::from),
        timestamp,
        source,
        kind,
        verdict,
        severity: value.get("severity").and_then(|v| v.as_str()).map(String::from),
        summary: value
            .get("summary")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        process: value.get("process").and_then(|v| v.as_str()).map(String::from),
        namespace: value.get("namespace").and_then(|v| v.as_str()).map(String::from),
        pod: value.get("pod").and_then(|v| v.as_str()).map(String::from),
        action_type: value.get("action_type").and_then(|v| v.as_str()).map(String::from),
        signature_valid: value.get("signature_valid").and_then(|v| v.as_bool()),
        raw: Some(value.clone()),
    })
}

/// OCSF class name lookup matching the existing mapping in `validate_ocsf_event`.
fn ocsf_class_name(uid: i64) -> Option<String> {
    Some(match uid {
        1001 => "File Activity".into(),
        1007 => "Process Activity".into(),
        2004 => "Detection Finding".into(),
        4001 => "Network Activity".into(),
        _ => return None,
    })
}

#[tauri::command]
pub fn test_sigma_rule(
    source: String,
    events_json: String,
) -> Result<SigmaTestResponse, String> {
    check_source_size(&source)?;
    if events_json.len() > MAX_EVENTS_SIZE {
        return Err(format!(
            "Events JSON exceeds maximum size ({} bytes > {} bytes)",
            events_json.len(),
            MAX_EVENTS_SIZE
        ));
    }

    let events_value: Vec<serde_json::Value> = serde_json::from_str(&events_json)
        .map_err(|e| format!("Failed to parse events JSON array: {e}"))?;

    let mut timeline_events = Vec::with_capacity(events_value.len());
    for (idx, ev) in events_value.iter().enumerate() {
        timeline_events.push(
            json_to_timeline_event(ev)
                .map_err(|e| format!("Failed to parse event at index {idx}: {e}"))?,
        );
    }

    let events_tested = timeline_events.len();

    let result = hunt_correlate::detection::test_rule_source("sigma", &source, &timeline_events)
        .map_err(|e| format!("Sigma test error: {e}"))?;

    let findings: Vec<SigmaTestFindingEntry> = result
        .findings
        .iter()
        .map(|f| SigmaTestFindingEntry {
            title: f.title.clone(),
            severity: f.severity.clone(),
            evidence_refs: f.evidence_refs.clone(),
            event_index: None,
        })
        .collect();

    let events_matched = findings.len();
    let matched = !findings.is_empty();

    Ok(SigmaTestResponse {
        matched,
        findings,
        events_tested,
        events_matched,
    })
}

#[tauri::command]
pub fn compile_sigma_rule(source: String) -> Result<SigmaCompileResponse, String> {
    check_source_size(&source)?;

    match hunt_correlate::detection::compile_rule_source("sigma", &source) {
        Ok(compilation) => {
            let title = compilation
                .compiled_artifact
                .get("title")
                .and_then(|v| v.as_str())
                .map(String::from);

            let artifact_json = serde_json::to_string_pretty(&compilation.compiled_artifact)
                .unwrap_or_else(|_| "{}".to_string());

            let mut diagnostics: Vec<DetectionDiagnostic> = compilation
                .warnings
                .iter()
                .map(|w| DetectionDiagnostic {
                    severity: "warning".into(),
                    message: w.clone(),
                    line: None,
                    column: None,
                })
                .collect();

            if !diagnostics.iter().any(|d| d.severity == "error") {
                diagnostics.push(DetectionDiagnostic {
                    severity: "info".into(),
                    message: format!("Compiled as {} engine", compilation.engine_kind),
                    line: None,
                    column: None,
                });
            }

            Ok(SigmaCompileResponse {
                valid: true,
                title,
                compiled_artifact: Some(artifact_json),
                diagnostics,
            })
        }
        Err(e) => Ok(SigmaCompileResponse {
            valid: false,
            title: None,
            compiled_artifact: None,
            diagnostics: vec![DetectionDiagnostic {
                severity: "error".into(),
                message: format!("Sigma compilation failed: {e}"),
                line: None,
                column: None,
            }],
        }),
    }
}

// ---- OCSF Normalization Command ----

#[tauri::command]
pub fn normalize_ocsf_event(json: String) -> Result<OcsfNormalizeResponse, String> {
    check_source_size(&json)?;

    let value: serde_json::Value = serde_json::from_str(&json).map_err(|e| {
        format!("JSON parse error: {e}")
    })?;

    if !value.is_object() {
        return Ok(OcsfNormalizeResponse {
            valid: false,
            class_uid: None,
            event_class: None,
            missing_fields: vec![],
            invalid_fields: vec![],
            diagnostics: vec![DetectionDiagnostic {
                severity: "error".into(),
                message: "OCSF event must be a JSON object".into(),
                line: None,
                column: None,
            }],
        });
    }

    let validation_errors = clawdstrike_ocsf::validate_ocsf_json(&value);

    let mut missing_fields = Vec::new();
    let mut invalid_fields = Vec::new();
    let mut diagnostics = Vec::new();

    for err in &validation_errors {
        match err {
            clawdstrike_ocsf::OcsfValidationError::MissingField { field } => {
                missing_fields.push(field.to_string());
                diagnostics.push(DetectionDiagnostic {
                    severity: "error".into(),
                    message: format!("Missing required OCSF field: {field}"),
                    line: None,
                    column: None,
                });
            }
            clawdstrike_ocsf::OcsfValidationError::InvalidType { field, expected } => {
                invalid_fields.push(OcsfFieldError {
                    field: field.to_string(),
                    error: format!("expected {expected}"),
                });
                diagnostics.push(DetectionDiagnostic {
                    severity: "error".into(),
                    message: format!("Invalid type for OCSF field {field}: expected {expected}"),
                    line: None,
                    column: None,
                });
            }
            clawdstrike_ocsf::OcsfValidationError::TypeUidMismatch { expected, actual } => {
                invalid_fields.push(OcsfFieldError {
                    field: "type_uid".into(),
                    error: format!("expected {expected}, got {actual}"),
                });
                diagnostics.push(DetectionDiagnostic {
                    severity: "error".into(),
                    message: format!("type_uid mismatch: expected {expected}, got {actual}"),
                    line: None,
                    column: None,
                });
            }
            clawdstrike_ocsf::OcsfValidationError::InvalidSeverity { value: sev } => {
                invalid_fields.push(OcsfFieldError {
                    field: "severity_id".into(),
                    error: format!("value {sev} is not a valid OCSF severity (0-6, 99)"),
                });
                diagnostics.push(DetectionDiagnostic {
                    severity: "error".into(),
                    message: format!(
                        "severity_id {sev} is not a valid OCSF severity (0-6, 99)"
                    ),
                    line: None,
                    column: None,
                });
            }
        }
    }

    let class_uid = value
        .get("class_uid")
        .and_then(|v| v.as_i64());

    let event_class = class_uid.and_then(ocsf_class_name).or_else(|| {
        class_uid.map(|uid| format!("Unknown ({uid})"))
    });

    let valid = validation_errors.is_empty();

    if valid {
        diagnostics.push(DetectionDiagnostic {
            severity: "info".into(),
            message: "OCSF event passes all validation checks".into(),
            line: None,
            column: None,
        });
    }

    Ok(OcsfNormalizeResponse {
        valid,
        class_uid,
        event_class,
        missing_fields,
        invalid_fields,
        diagnostics,
    })
}

// ---- Sigma Conversion Command ----

#[tauri::command]
pub fn convert_sigma_rule(
    source: String,
    target_format: String,
) -> Result<SigmaConvertResponse, String> {
    check_source_size(&source)?;

    match target_format.as_str() {
        "native_policy" => convert_sigma_to_native_policy(&source),
        other => Ok(SigmaConvertResponse {
            success: false,
            target_format: other.to_string(),
            output: None,
            diagnostics: vec![DetectionDiagnostic {
                severity: "error".into(),
                message: format!(
                    "Unsupported target format '{other}'. Supported: native_policy"
                ),
                line: None,
                column: None,
            }],
            converter_version: "0.1.0".into(),
        }),
    }
}

fn convert_sigma_to_native_policy(source: &str) -> Result<SigmaConvertResponse, String> {
    // First, compile the Sigma rule to validate it
    let compilation = hunt_correlate::detection::compile_rule_source("sigma", source)
        .map_err(|e| format!("Sigma compilation failed: {e}"))?;

    // Parse the Sigma YAML to extract metadata
    let parsed: serde_json::Value = serde_yaml::from_str(source)
        .map_err(|e| format!("Sigma YAML parse error: {e}"))?;

    let title = parsed
        .get("title")
        .and_then(|v| v.as_str())
        .unwrap_or("Sigma Imported Rule");
    let description = parsed
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("Converted from Sigma rule");
    let level = parsed
        .get("level")
        .and_then(|v| v.as_str())
        .unwrap_or("medium");
    let status = parsed
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("experimental");

    // Extract logsource for guard mapping
    let logsource = parsed.get("logsource");
    let category = logsource
        .and_then(|ls| ls.get("category"))
        .and_then(|v| v.as_str())
        .unwrap_or("generic");
    let product = logsource
        .and_then(|ls| ls.get("product"))
        .and_then(|v| v.as_str())
        .unwrap_or("any");

    // Map Sigma level to policy severity
    let policy_level = match level {
        "critical" => "strict",
        "high" => "strict",
        "medium" => "default",
        "low" | "informational" => "permissive",
        _ => "default",
    };

    // Map logsource category to relevant guards
    let guard_config = match category {
        "process_creation" | "process_access" | "image_load" => {
            format!(
                "    shell_command:\n      blocked_commands:\n        - \"# Sigma: {title}\"\n      log_level: \"{level}\""
            )
        }
        "file_event" | "file_access" | "file_creation" | "file_delete" | "file_rename" => {
            format!(
                "    forbidden_path:\n      paths:\n        - \"# Sigma: {title}\"\n      log_level: \"{level}\""
            )
        }
        "network_connection" | "dns_query" | "dns" | "proxy" | "firewall" => {
            format!(
                "    egress_allowlist:\n      allowed_domains:\n        - \"# Sigma: {title}\"\n      log_level: \"{level}\""
            )
        }
        _ => {
            format!(
                "    # No direct guard mapping for logsource category '{category}'\n    # Review and configure appropriate guards manually\n    shell_command:\n      log_level: \"{level}\""
            )
        }
    };

    let policy_yaml = format!(
        r#"# Auto-generated from Sigma rule: {title}
# Status: {status} | Level: {level} | Product: {product}
# {description}
#
# Source compilation: {engine_kind} engine
# NOTE: This is a structural template. Detection logic from the Sigma
# rule's condition/selection blocks should be reviewed and mapped to
# the appropriate guard parameters.

schema_version: "1.5.0"
extends: {policy_level}

guards:
{guard_config}
"#,
        engine_kind = compilation.engine_kind,
    );

    let mut diagnostics = Vec::new();
    diagnostics.push(DetectionDiagnostic {
        severity: "info".into(),
        message: format!(
            "Converted Sigma rule '{}' to native policy template (extends: {})",
            title, policy_level
        ),
        line: None,
        column: None,
    });
    diagnostics.push(DetectionDiagnostic {
        severity: "warning".into(),
        message: "Detection logic requires manual review — Sigma condition/selection semantics \
                  are not fully translatable to guard configurations"
            .into(),
        line: None,
        column: None,
    });

    for w in &compilation.warnings {
        diagnostics.push(DetectionDiagnostic {
            severity: "warning".into(),
            message: w.clone(),
            line: None,
            column: None,
        });
    }

    Ok(SigmaConvertResponse {
        success: true,
        target_format: "native_policy".into(),
        output: Some(policy_yaml),
        diagnostics,
        converter_version: "0.1.0".into(),
    })
}
