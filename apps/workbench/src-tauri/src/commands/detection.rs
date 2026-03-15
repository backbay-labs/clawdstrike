//! Detection engineering commands — Sigma, YARA, and OCSF validation stubs.
//!
//! These commands provide basic structural validation now. Full integration with
//! `hunt_correlate` and `clawdstrike_ocsf` will be wired in Phase 1/2.

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

// Phase 1 will add test-execution commands that consume these types.
#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize)]
pub struct SigmaTestResult {
    pub passed: bool,
    pub findings: Vec<SigmaTestFinding>,
    pub duration_ms: u64,
    pub errors: Vec<String>,
}

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize)]
pub struct SigmaTestFinding {
    pub severity: String,
    pub message: String,
    pub matched_event_index: Option<usize>,
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

fn count_braces_outside_literals(line: &str) -> (i32, i32) {
    let mut opens = 0;
    let mut closes = 0;
    let mut in_string = false;
    let mut in_regex = false;
    let mut escaped = false;
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;

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

        if !in_string && !in_regex && ch == '/' && chars.get(i + 1) == Some(&'/') {
            break;
        }

        if ch == '"' && !in_regex {
            in_string = !in_string;
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
                i += 1;
                while i < chars.len() && chars[i].is_ascii_alphabetic() {
                    i += 1;
                }
                continue;
            }
        }

        if !in_string && !in_regex {
            if ch == '{' {
                opens += 1;
            } else if ch == '}' {
                closes += 1;
            }
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
    if content.contains("title:") && content.contains("status:") && !content.contains("guards:") {
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
    if content.contains("rule ") && content.contains("condition:") {
        return DetectionFileType {
            file_type: "yara_rule".into(),
            confidence: 0.8,
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

            if !map.contains_key(&serde_yaml::Value::String("title".into())) {
                diagnostics.push(DetectionDiagnostic {
                    severity: "error".into(),
                    message: "Missing required field: title".into(),
                    line: None,
                    column: None,
                });
            }
            if !map.contains_key(&serde_yaml::Value::String("detection".into())) {
                diagnostics.push(DetectionDiagnostic {
                    severity: "error".into(),
                    message: "Missing required field: detection".into(),
                    line: None,
                    column: None,
                });
            }
            if !map.contains_key(&serde_yaml::Value::String("logsource".into())) {
                diagnostics.push(DetectionDiagnostic {
                    severity: "error".into(),
                    message: "Missing required field: logsource".into(),
                    line: None,
                    column: None,
                });
            }

            if let Some(detection) = map.get(&serde_yaml::Value::String("detection".into())) {
                if !detection.is_mapping() {
                    diagnostics.push(DetectionDiagnostic {
                        severity: "error".into(),
                        message: "detection must be a YAML mapping/object".into(),
                        line: None,
                        column: None,
                    });
                } else if !detection.as_mapping().is_some_and(|det| {
                    det.contains_key(&serde_yaml::Value::String("condition".into()))
                }) {
                    diagnostics.push(DetectionDiagnostic {
                        severity: "error".into(),
                        message: "detection.condition is required".into(),
                        line: None,
                        column: None,
                    });
                }
            }

            if let Some(logsource) = map.get(&serde_yaml::Value::String("logsource".into())) {
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
    let mut current_rule: Option<(String, u32, bool)> = None;

    for (idx, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        let line_no = (idx + 1) as u32;

        if let Some(caps) = trimmed
            .strip_prefix("private ")
            .or_else(|| trimmed.strip_prefix("global "))
            .or_else(|| Some(trimmed))
        {
            if let Some(rule_decl) = caps.strip_prefix("rule ") {
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
                current_rule = Some((rule_name, (opens - closes).max(0) as u32, false));
                rule_count += 1;
                continue;
            }
        }

        if let Some((rule_name, brace_depth, saw_condition)) = current_rule.as_mut() {
            if trimmed.starts_with("condition:") {
                *saw_condition = true;
            }

            let (opens, closes) = count_braces_outside_literals(line);
            let next_depth = (*brace_depth as i32) + opens - closes;
            *brace_depth = next_depth.max(0) as u32;

            if next_depth <= 0 {
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
        if brace_depth > 0 {
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
    let content = read_text_file_secure(import_path.clone()).await?;

    if import_path.exists() {
        if let Ok(canon) = import_path.canonicalize() {
            let canon_check = canon.to_string_lossy().replace('\\', "/").to_lowercase();
            check_sensitive_path(&canon_check)?;
        }
    }

    check_source_size(&content)?;

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

    let validation_message = match file_type.as_str() {
        "sigma_rule" => {
            let result = validate_sigma_rule(content.clone())?;
            if result.valid {
                None
            } else {
                Some(
                    result
                        .diagnostics
                        .iter()
                        .map(|d| format_detection_diagnostic(d))
                        .collect::<Vec<_>>()
                        .join("; "),
                )
            }
        }
        "yara_rule" => {
            let result = validate_yara_rule(content.clone())?;
            if result.valid {
                None
            } else {
                Some(
                    result
                        .diagnostics
                        .iter()
                        .map(|d| format_detection_diagnostic(d))
                        .collect::<Vec<_>>()
                        .join("; "),
                )
            }
        }
        "ocsf_event" => {
            let result = validate_ocsf_event(content.clone())?;
            if result.valid {
                None
            } else {
                Some(
                    result
                        .diagnostics
                        .iter()
                        .filter(|d| d.severity == "error")
                        .map(|d| format_detection_diagnostic(d))
                        .collect::<Vec<_>>()
                        .join("; "),
                )
            }
        }
        _ => Some("Unsupported detection file type".into()),
    };

    if let Some(message) = validation_message {
        if !message.is_empty() {
            return Ok(ExportResponse {
                success: false,
                path,
                message: format!("Validation failed: {message}"),
            });
        }
    }

    let export_path = validate_file_path(&path)?;
    write_text_file_secure(export_path.clone(), content).await?;

    if export_path.exists() {
        if let Ok(canon) = export_path.canonicalize() {
            let canon_check = canon.to_string_lossy().replace('\\', "/").to_lowercase();
            if check_sensitive_path(&canon_check).is_err() {
                let _ = tokio::fs::remove_file(&export_path).await;
                return Err("File resolved to a sensitive path after write; removed".to_string());
            }
        }
    }

    Ok(ExportResponse {
        success: true,
        path,
        message: "Detection file exported successfully".into(),
    })
}
