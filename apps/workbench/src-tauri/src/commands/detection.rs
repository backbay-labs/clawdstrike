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
    pub class_uid: Option<i64>,
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

fn estimate_sigma_events_matched(findings_len: usize, events_tested: usize) -> usize {
    findings_len.min(events_tested)
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

/// Scrub a YARA source line down to structural code tokens by removing content
/// inside string literals, regex literals, hex strings (`= { ... }`), line comments,
/// and block comments.
///
/// The state is threaded through successive calls so that multi-line `/* */`
/// comments and multi-line hex strings are handled correctly. The updated state
/// is returned alongside the scrubbed code fragment.
#[derive(Clone, Copy, Debug, Default)]
struct YaraScrubState {
    in_block_comment: bool,
    in_hex_string: bool,
}

fn scrub_yara_line(line: &str, state: YaraScrubState) -> (String, YaraScrubState) {
    let mut code = String::with_capacity(line.len());
    let mut in_string = false;
    let mut in_regex = false;
    let mut in_hex_string = state.in_hex_string;
    let mut in_block = state.in_block_comment;
    let mut escaped = false;
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;
    // Track the last non-whitespace character before the current position to detect
    // hex string assignment context (`= {`).
    let mut last_non_ws: Option<char> = None;

    while i < chars.len() {
        let ch = chars[i];

        // Inside a block comment — look only for the closing `*/`
        if in_block {
            if ch == '*' && chars.get(i + 1) == Some(&'/') {
                in_block = false;
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }

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
        if !in_string && !in_regex && !in_hex_string && ch == '/' && chars.get(i + 1) == Some(&'/')
        {
            break;
        }

        // Block comment opening
        if !in_string && !in_regex && !in_hex_string && ch == '/' && chars.get(i + 1) == Some(&'*')
        {
            in_block = true;
            i += 2;
            continue;
        }

        // Hex string closing brace — exit hex mode, don't count the brace
        if in_hex_string {
            if ch == '}' {
                in_hex_string = false;
                last_non_ws = None;
            }
            i += 1;
            continue;
        }

        if ch == '"' && !in_regex {
            in_string = !in_string;
            if !in_string {
                last_non_ws = None;
            }
            i += 1;
            continue;
        }

        if ch == '/' && !in_string {
            let prev = if i > 0 { chars[i - 1] } else { ' ' };
            let next = chars.get(i + 1).copied().unwrap_or(' ');
            if !in_regex && !prev.is_alphanumeric() && next != '/' && next != '*' {
                in_regex = true;
                i += 1;
                continue;
            }
            if in_regex {
                in_regex = false;
                last_non_ws = None;
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
                    last_non_ws = None;
                    i += 1;
                    continue;
                }
            }
            code.push(ch);
        }

        if !in_string && !in_regex && !ch.is_whitespace() {
            last_non_ws = Some(ch);
        }
        i += 1;
    }

    (
        code,
        YaraScrubState {
            in_block_comment: in_block,
            in_hex_string,
        },
    )
}

/// Analyze a YARA source line for structural braces and a `condition:` token while
/// ignoring strings, regexes, hex strings, and comments.
fn analyze_yara_line(line: &str, state: YaraScrubState) -> (i32, i32, bool, YaraScrubState) {
    let (code, state) = scrub_yara_line(line, state);
    let opens = code.chars().filter(|ch| *ch == '{').count() as i32;
    let closes = code.chars().filter(|ch| *ch == '}').count() as i32;
    let has_condition = code.contains("condition:");
    (opens, closes, has_condition, state)
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
    let mut line_state = YaraScrubState::default();

    for (idx, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        let line_no = (idx + 1) as u32;

        // Strip optional YARA rule modifiers (`private`, `global`) in any order.
        // Handles `private rule`, `global rule`, `private global rule`, and
        // `global private rule`.
        let mut after_modifiers = trimmed;
        loop {
            if let Some(rest) = after_modifiers.strip_prefix("private ") {
                after_modifiers = rest.trim_start();
            } else if let Some(rest) = after_modifiers.strip_prefix("global ") {
                after_modifiers = rest.trim_start();
            } else {
                break;
            }
        }
        {
            // Only detect rule declarations outside block comments.
            if !line_state.in_block_comment && !line_state.in_hex_string {
                if let Some(rule_decl) = after_modifiers.strip_prefix("rule ") {
                    // Emit a diagnostic for the previous rule if it was not properly
                    // terminated (brace_depth != 0) before starting a new one.
                    if let Some((prev_name, prev_depth, prev_saw_condition)) = current_rule.take() {
                        if !prev_saw_condition {
                            diagnostics.push(DetectionDiagnostic {
                                severity: "error".into(),
                                message: format!(
                                    "YARA rule '{prev_name}' is missing a required 'condition:' section"
                                ),
                                line: Some(line_no.saturating_sub(1)),
                                column: None,
                            });
                        }
                        if prev_depth != 0 {
                            diagnostics.push(DetectionDiagnostic {
                                severity: "error".into(),
                                message: format!(
                                    "YARA rule '{prev_name}' has unterminated body (unbalanced braces) before next rule declaration"
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
                    let declaration_tail = rule_decl
                        .strip_prefix(&rule_name)
                        .map(str::trim_start)
                        .unwrap_or("");
                    // Count braces on the rule declaration line itself so that
                    // single-line rules (e.g. `rule x { condition: true }`) are
                    // tracked correctly.
                    let (opens, closes, saw_condition, next_state) =
                        analyze_yara_line(declaration_tail, line_state);
                    line_state = next_state;
                    current_rule = Some((rule_name, opens - closes, saw_condition));
                    rule_count += 1;
                    continue;
                }
            }
        }

        if let Some((rule_name, brace_depth, saw_condition)) = current_rule.as_mut() {
            let (opens, closes, line_has_condition, next_state) =
                analyze_yara_line(line, line_state);
            line_state = next_state;
            if line_has_condition {
                *saw_condition = true;
            }
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
                Some(v) => match v.as_i64() {
                    Some(uid) => Some(uid),
                    None => {
                        diagnostics.push(DetectionDiagnostic {
                            severity: "error".into(),
                            message: "class_uid must be an integer".into(),
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

            let event_class = class_uid
                .and_then(ocsf_class_name)
                .or_else(|| class_uid.map(|uid| format!("Unknown ({uid})")));

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

    let format_validation_message =
        |diagnostic: &DetectionDiagnostic| match (diagnostic.line, diagnostic.column) {
            (Some(line), Some(column)) => format!("line {line}:{column}: {}", diagnostic.message),
            (Some(line), None) => format!("line {line}: {}", diagnostic.message),
            _ => diagnostic.message.clone(),
        };

    let validation_failed = match file_type.as_str() {
        "sigma_rule" => {
            let result = validate_sigma_rule(content.clone())?;
            if result.valid {
                None
            } else {
                let details = result
                    .diagnostics
                    .iter()
                    .map(|diagnostic| format_validation_message(diagnostic))
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
                    .map(|diagnostic| format_validation_message(diagnostic))
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
                    .map(|diagnostic| format_validation_message(diagnostic))
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
        export_path
            .parent()
            .and_then(|p| p.canonicalize().ok())
            .map(|p| p.join(export_path.file_name().unwrap_or_default()))
            .ok_or(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no parent",
            ))
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
        event_id: value
            .get("event_id")
            .and_then(|v| v.as_str())
            .map(String::from),
        timestamp,
        source,
        kind,
        verdict,
        severity: value
            .get("severity")
            .and_then(|v| v.as_str())
            .map(String::from),
        summary: value
            .get("summary")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        process: value
            .get("process")
            .and_then(|v| v.as_str())
            .map(String::from),
        namespace: value
            .get("namespace")
            .and_then(|v| v.as_str())
            .map(String::from),
        pod: value.get("pod").and_then(|v| v.as_str()).map(String::from),
        action_type: value
            .get("action_type")
            .and_then(|v| v.as_str())
            .map(String::from),
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
pub fn test_sigma_rule(source: String, events_json: String) -> Result<SigmaTestResponse, String> {
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

    // `hunt_correlate` does not return event-level attribution yet, so
    // `events_matched` is a bounded heuristic based on distinct findings.
    let events_matched = estimate_sigma_events_matched(findings.len(), events_tested);
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

    let value: serde_json::Value =
        serde_json::from_str(&json).map_err(|e| format!("JSON parse error: {e}"))?;

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
                    message: format!("severity_id {sev} is not a valid OCSF severity (0-6, 99)"),
                    line: None,
                    column: None,
                });
            }
        }
    }

    let class_uid = value.get("class_uid").and_then(|v| v.as_i64());

    let event_class = class_uid
        .and_then(ocsf_class_name)
        .or_else(|| class_uid.map(|uid| format!("Unknown ({uid})")));

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
                message: format!("Unsupported target format '{other}'. Supported: native_policy"),
                line: None,
                column: None,
            }],
            converter_version: "0.1.0".into(),
        }),
    }
}

/// Escape a string value for safe embedding in YAML output.
///
/// If the value contains YAML-special characters (`:`, `#`, `'`, `"`, `{`, `}`,
/// `[`, `]`, `>`, `|`, `*`, `&`, `!`, `%`, `@`, `` ` ``), or has leading/trailing
/// whitespace, wrap it in double quotes and escape internal double-quotes and
/// backslashes.  Plain alphanumeric strings pass through unchanged.
fn escape_yaml_string(s: &str) -> String {
    const SPECIAL: &[char] = &[
        ':', '#', '\'', '"', '{', '}', '[', ']', '>', '|', '*', '&', '!', '%', '@', '`', ',',
    ];
    let has_control = s.chars().any(|c| c.is_control());
    let needs_quoting = s.is_empty()
        || s.starts_with(|c: char| c.is_whitespace())
        || s.ends_with(|c: char| c.is_whitespace())
        || s.contains(SPECIAL)
        || has_control;
    if needs_quoting {
        let mut escaped = String::with_capacity(s.len() + 2);
        for ch in s.chars() {
            match ch {
                '\\' => escaped.push_str("\\\\"),
                '"' => escaped.push_str("\\\""),
                '\n' => escaped.push_str("\\n"),
                '\r' => escaped.push_str("\\r"),
                '\t' => escaped.push_str("\\t"),
                c if c.is_control() => {
                    // Escape other control characters as Unicode escapes.
                    escaped.push_str(&format!("\\u{:04x}", c as u32));
                }
                c => escaped.push(c),
            }
        }
        format!("\"{escaped}\"")
    } else {
        s.to_string()
    }
}

fn sanitize_yaml_comment_text(s: &str) -> String {
    s.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

fn convert_sigma_to_native_policy(source: &str) -> Result<SigmaConvertResponse, String> {
    // First, compile the Sigma rule to validate it
    let compilation = hunt_correlate::detection::compile_rule_source("sigma", source)
        .map_err(|e| format!("Sigma compilation failed: {e}"))?;

    // Parse the Sigma YAML to extract metadata
    let parsed: serde_json::Value =
        serde_yaml::from_str(source).map_err(|e| format!("Sigma YAML parse error: {e}"))?;

    let title_raw = parsed
        .get("title")
        .and_then(|v| v.as_str())
        .unwrap_or("Sigma Imported Rule");
    let description_raw = parsed
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("Converted from Sigma rule");
    let level_raw = parsed
        .get("level")
        .and_then(|v| v.as_str())
        .unwrap_or("medium");
    let status_raw = parsed
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("experimental");

    // Escape strings that will be embedded in YAML to prevent malformed output
    // when they contain special YAML characters (`:`, `#`, `'`, `"`, etc.).
    let title_comment = sanitize_yaml_comment_text(title_raw);
    let description_comment = sanitize_yaml_comment_text(description_raw);
    let status_comment = sanitize_yaml_comment_text(status_raw);
    let level_comment = sanitize_yaml_comment_text(level_raw);

    // Extract logsource for guard mapping
    let logsource = parsed.get("logsource");
    let category = logsource
        .and_then(|ls| ls.get("category"))
        .and_then(|v| v.as_str())
        .unwrap_or("generic");
    let category_comment = sanitize_yaml_comment_text(category);
    let product_raw = logsource
        .and_then(|ls| ls.get("product"))
        .and_then(|v| v.as_str())
        .unwrap_or("any");
    let product_comment = sanitize_yaml_comment_text(product_raw);
    // Build the Sigma marker as a single YAML-safe double-quoted string.
    // Use sanitize_yaml_comment_text for the title portion to strip
    // newlines/control chars, then manually construct the quoted value so we
    // avoid the double-quoting that would occur if escape_yaml_string
    // wrapped an already-quoted result.
    let title_sanitized = sanitize_yaml_comment_text(title_raw);
    let sigma_marker = {
        let inner = title_sanitized.replace('\\', "\\\\").replace('"', "\\\"");
        format!("\"# Sigma: {inner}\"")
    };
    let level_yaml = escape_yaml_string(level_raw);

    // Map Sigma level to policy severity
    let policy_level = match level_raw {
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
                "    shell_command:\n      blocked_commands:\n        - {sigma_marker}\n      log_level: {level_yaml}"
            )
        }
        "file_event" | "file_access" | "file_creation" | "file_delete" | "file_rename" => {
            format!(
                "    forbidden_path:\n      paths:\n        - {sigma_marker}\n      log_level: {level_yaml}"
            )
        }
        "network_connection" | "dns_query" | "dns" | "proxy" | "firewall" => {
            format!(
                "    egress_allowlist:\n      allowed_domains:\n        - {sigma_marker}\n      log_level: {level_yaml}"
            )
        }
        _ => {
            format!(
                "    # No direct guard mapping for logsource category '{category_comment}'\n    # Review and configure appropriate guards manually\n    shell_command:\n      log_level: {level_yaml}"
            )
        }
    };

    let policy_yaml = format!(
        r#"# Auto-generated from Sigma rule: {title_comment}
# Status: {status_comment} | Level: {level_comment} | Product: {product_comment}
# {description_comment}
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
            title_raw, policy_level
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_yara_rule_accepts_inline_condition_on_rule_declaration_line() {
        let response = validate_yara_rule(
            "rule inline_condition { strings: $a = \"x\" condition: $a }".to_string(),
        )
        .expect("inline YARA rule should validate");

        assert!(response.valid, "expected inline condition rule to be valid");
        assert_eq!(response.rule_count, 1);
        assert!(
            response.diagnostics.iter().all(|diagnostic| !diagnostic
                .message
                .contains("missing a required 'condition:'")),
            "unexpected missing-condition diagnostic: {:?}",
            response.diagnostics
        );
    }

    #[test]
    fn validate_yara_rule_accepts_multiline_hex_strings() {
        let response = validate_yara_rule(
            r#"rule multiline_hex {
    strings:
        $hex = {
            AA BB
            CC DD
        }
    condition:
        $hex
}"#
            .to_string(),
        )
        .expect("multiline hex YARA rule should validate");

        assert!(response.valid, "expected multiline hex rule to be valid");
        assert_eq!(response.rule_count, 1);
        assert!(
            response.diagnostics.is_empty(),
            "unexpected diagnostics: {:?}",
            response.diagnostics
        );
    }

    #[test]
    fn validate_yara_rule_accepts_inline_hex_on_rule_declaration_line() {
        let response = validate_yara_rule(
            r#"rule inline_hex { strings: $hex = { AA BB CC DD } condition: $hex }"#.to_string(),
        )
        .expect("inline hex YARA rule should validate");

        assert!(response.valid, "expected inline hex rule to be valid");
        assert_eq!(response.rule_count, 1);
        assert!(
            response.diagnostics.is_empty(),
            "unexpected diagnostics: {:?}",
            response.diagnostics
        );
    }

    #[test]
    fn convert_sigma_to_native_policy_keeps_special_titles_yaml_safe() {
        let sigma = r#"title: "Suspicious Command: PowerShell #1"
description: Detects "weird" command lines
status: experimental
level: high
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains: powershell -enc
  condition: selection
"#;

        let response =
            convert_sigma_to_native_policy(sigma).expect("sigma conversion should succeed");
        let output = response.output.expect("expected native policy output");

        serde_yaml::from_str::<serde_yaml::Value>(&output)
            .expect("generated native policy should remain valid YAML");
        assert!(
            output.contains("# Auto-generated from Sigma rule: Suspicious Command: PowerShell #1")
        );
        assert!(output.contains("- \"# Sigma: Suspicious Command: PowerShell #1\""));
        assert!(!output.contains("\"# Sigma: \\\"Suspicious Command: PowerShell #1\\\"\""));
    }

    #[test]
    fn convert_sigma_to_native_policy_sanitizes_level_comments() {
        let sigma = r#"title: "Multiline Level"
description: Convert safely
status: experimental
level: |
  high
  schema_version: "9.9.9"
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    CommandLine|contains: bash
  condition: selection
"#;

        let response =
            convert_sigma_to_native_policy(sigma).expect("sigma conversion should succeed");
        let output = response.output.expect("expected native policy output");
        let parsed = serde_yaml::from_str::<serde_yaml::Value>(&output)
            .expect("generated native policy should remain valid YAML");

        assert!(output.contains("Level: high schema_version: \"9.9.9\" | Product: linux"));
        assert_eq!(
            parsed
                .get("schema_version")
                .and_then(|value| value.as_str()),
            Some("1.5.0")
        );
    }

    #[test]
    fn estimate_sigma_events_matched_never_exceeds_tested_events() {
        assert_eq!(estimate_sigma_events_matched(0, 5), 0);
        assert_eq!(estimate_sigma_events_matched(2, 5), 2);
        assert_eq!(estimate_sigma_events_matched(9, 3), 3);
    }
}
