//! Detection engineering commands — Sigma, YARA, and OCSF validation stubs.
//!
//! These commands provide basic structural validation now. Full integration with
//! `hunt_correlate` and `clawdstrike_ocsf` will be wired in Phase 1/2.

use serde::{Deserialize, Serialize};

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

// ---- Sigma Commands ----

#[tauri::command]
pub fn validate_sigma_rule(source: String) -> Result<SigmaValidationResponse, String> {
    check_source_size(&source)?;

    // Phase 1 TODO: Wire to hunt_correlate::detection::compile_sigma_rule()
    // For now, do basic YAML parse check
    match serde_yaml::from_str::<serde_yaml::Value>(&source) {
        Ok(value) => {
            let mut diagnostics = Vec::new();

            // Check for required Sigma fields
            if let Some(map) = value.as_mapping() {
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

    // Phase 3 TODO: Wire to yara-x parser for full validation
    // For now, check for basic rule structure.
    // Use line-by-line checks to avoid matching "rule " inside string literals or comments.
    let rule_count = source
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            trimmed.starts_with("rule ")
                || trimmed.starts_with("private rule ")
                || trimmed.starts_with("global rule ")
        })
        .count() as u32;
    let mut diagnostics = Vec::new();

    if rule_count == 0 {
        diagnostics.push(DetectionDiagnostic {
            severity: "error".into(),
            message: "No YARA rule declarations found. Rules must start with 'rule <name>'"
                .into(),
            line: None,
            column: None,
        });
    }

    // Check for "condition:" at the start of a line (ignoring leading whitespace)
    // to avoid false matches inside string literals.
    let has_condition = source
        .lines()
        .any(|line| line.trim().starts_with("condition:"));

    if !has_condition && rule_count > 0 {
        diagnostics.push(DetectionDiagnostic {
            severity: "error".into(),
            message: "YARA rule missing required 'condition:' section".into(),
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

    // Phase 2 TODO: Wire to clawdstrike_ocsf::validate::validate_ocsf_json()
    // For now, parse JSON and check for required OCSF fields
    match serde_json::from_str::<serde_json::Value>(&json) {
        Ok(value) => {
            let mut diagnostics = Vec::new();
            let class_uid = value
                .get("class_uid")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32);

            if class_uid.is_none() {
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
    // Content heuristic for YAML files
    if content.contains("guards:") || content.contains("schema_version:") {
        return Ok(DetectionFileType {
            file_type: "clawdstrike_policy".into(),
            confidence: 0.9,
        });
    }
    if content.contains("detection:") && content.contains("logsource:") {
        return Ok(DetectionFileType {
            file_type: "sigma_rule".into(),
            confidence: 0.9,
        });
    }
    if content.contains("title:") && content.contains("status:") && !content.contains("guards:") {
        return Ok(DetectionFileType {
            file_type: "sigma_rule".into(),
            confidence: 0.7,
        });
    }
    if content.trim_start().starts_with('{') {
        return Ok(DetectionFileType {
            file_type: "ocsf_event".into(),
            confidence: 0.6,
        });
    }
    if content.contains("rule ") && content.contains("condition:") {
        return Ok(DetectionFileType {
            file_type: "yara_rule".into(),
            confidence: 0.8,
        });
    }
    Ok(DetectionFileType {
        file_type: "clawdstrike_policy".into(),
        confidence: 0.3,
    })
}
