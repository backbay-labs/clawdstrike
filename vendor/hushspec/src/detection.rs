use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::evaluate::{Decision, EvaluationAction, EvaluationResult, evaluate};
use crate::schema::HushSpec;

/// Result from a single detector run.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DetectionResult {
    pub detector_name: String,
    pub category: DetectionCategory,
    /// Aggregate risk score in 0.0..=1.0.
    pub score: f64,
    pub matched_patterns: Vec<MatchedPattern>,
    pub explanation: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectionCategory {
    PromptInjection,
    Jailbreak,
    DataExfiltration,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MatchedPattern {
    pub name: String,
    /// Contribution to the aggregate score.
    pub weight: f64,
    pub matched_text: Option<String>,
}

/// Implement this trait for custom detection backends.
pub trait Detector: Send + Sync {
    fn name(&self) -> &str;
    fn category(&self) -> DetectionCategory;
    fn detect(&self, input: &str) -> DetectionResult;
}

/// Holds a set of detectors and runs them all against input.
pub struct DetectorRegistry {
    detectors: Vec<Box<dyn Detector>>,
}

impl DetectorRegistry {
    pub fn new() -> Self {
        Self {
            detectors: Vec::new(),
        }
    }

    pub fn register(&mut self, detector: Box<dyn Detector>) {
        self.detectors.push(detector);
    }

    pub fn with_defaults() -> Self {
        let mut registry = Self::new();
        registry.register(Box::new(RegexInjectionDetector::new()));
        registry.register(Box::new(RegexJailbreakDetector::new()));
        registry.register(Box::new(RegexExfiltrationDetector::new()));
        registry
    }

    pub fn detect_all(&self, input: &str) -> Vec<DetectionResult> {
        self.detectors.iter().map(|d| d.detect(input)).collect()
    }
}

impl Default for DetectorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// A compiled detection pattern used by regex-based detectors.
struct DetectionPattern {
    name: String,
    regex: Regex,
    weight: f64,
}

/// Regex-based prompt injection detector.
///
/// Patterns are compiled once at construction time.
pub struct RegexInjectionDetector {
    patterns: Vec<DetectionPattern>,
}

impl RegexInjectionDetector {
    pub fn new() -> Self {
        let patterns = vec![
            DetectionPattern {
                name: "ignore_instructions".to_string(),
                regex: Regex::new(
                    r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|prompts)",
                )
                .expect("ignore_instructions regex"),
                weight: 0.4,
            },
            DetectionPattern {
                name: "new_instructions".to_string(),
                regex: Regex::new(r"(?i)(new|updated|revised)\s+instructions?\s*:")
                    .expect("new_instructions regex"),
                weight: 0.3,
            },
            DetectionPattern {
                name: "system_prompt_extract".to_string(),
                regex: Regex::new(
                    r"(?i)(reveal|show|display|print|output)\s+(your|the)\s+(system\s+)?(prompt|instructions|rules)",
                )
                .expect("system_prompt_extract regex"),
                weight: 0.4,
            },
            DetectionPattern {
                name: "role_override".to_string(),
                regex: Regex::new(r"(?i)you\s+are\s+now\s+(a|an|the)\s+")
                    .expect("role_override regex"),
                weight: 0.3,
            },
            DetectionPattern {
                name: "pretend_mode".to_string(),
                regex: Regex::new(r"(?i)(pretend|imagine|act\s+as\s+if|suppose)\s+(you|that|we)")
                    .expect("pretend_mode regex"),
                weight: 0.2,
            },
            DetectionPattern {
                name: "delimiter_injection".to_string(),
                regex: Regex::new(
                    r"(?i)(---+|===+|```)\s*(system|assistant|user)\s*[:\n]",
                )
                .expect("delimiter_injection regex"),
                weight: 0.4,
            },
            DetectionPattern {
                name: "encoding_evasion".to_string(),
                regex: Regex::new(
                    r"(?i)(base64|rot13|hex|url.?encod|unicode)\s*(decod|encod|convert)",
                )
                .expect("encoding_evasion regex"),
                weight: 0.1,
            },
        ];

        Self { patterns }
    }
}

impl Default for RegexInjectionDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for RegexInjectionDetector {
    fn name(&self) -> &str {
        "regex_injection"
    }

    fn category(&self) -> DetectionCategory {
        DetectionCategory::PromptInjection
    }

    fn detect(&self, input: &str) -> DetectionResult {
        let mut matched_patterns = Vec::new();
        let mut total_weight = 0.0;

        for pattern in &self.patterns {
            if let Some(m) = pattern.regex.find(input) {
                total_weight += pattern.weight;
                matched_patterns.push(MatchedPattern {
                    name: pattern.name.clone(),
                    weight: pattern.weight,
                    matched_text: Some(m.as_str().to_string()),
                });
            }
        }

        let score = total_weight.min(1.0);

        let explanation = if matched_patterns.is_empty() {
            None
        } else {
            let names: Vec<&str> = matched_patterns.iter().map(|p| p.name.as_str()).collect();
            Some(format!(
                "matched {} injection pattern(s): {}",
                matched_patterns.len(),
                names.join(", ")
            ))
        };

        DetectionResult {
            detector_name: self.name().to_string(),
            category: self.category(),
            score,
            matched_patterns,
            explanation,
        }
    }
}

/// Regex-based jailbreak detector.
pub struct RegexJailbreakDetector {
    patterns: Vec<DetectionPattern>,
}

impl RegexJailbreakDetector {
    pub fn new() -> Self {
        let patterns = vec![DetectionPattern {
            name: "jailbreak_dan".to_string(),
            regex: Regex::new(r"(?i)(DAN|do\s+anything\s+now|developer\s+mode|jailbreak)")
                .expect("jailbreak_dan regex"),
            weight: 0.5,
        }];

        Self { patterns }
    }
}

impl Default for RegexJailbreakDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for RegexJailbreakDetector {
    fn name(&self) -> &str {
        "regex_jailbreak"
    }

    fn category(&self) -> DetectionCategory {
        DetectionCategory::Jailbreak
    }

    fn detect(&self, input: &str) -> DetectionResult {
        let mut matched_patterns = Vec::new();
        let mut total_weight = 0.0;

        for pattern in &self.patterns {
            if let Some(m) = pattern.regex.find(input) {
                total_weight += pattern.weight;
                matched_patterns.push(MatchedPattern {
                    name: pattern.name.clone(),
                    weight: pattern.weight,
                    matched_text: Some(m.as_str().to_string()),
                });
            }
        }

        let score = total_weight.min(1.0);

        let explanation = if matched_patterns.is_empty() {
            None
        } else {
            let names: Vec<&str> = matched_patterns.iter().map(|p| p.name.as_str()).collect();
            Some(format!(
                "matched {} jailbreak pattern(s): {}",
                matched_patterns.len(),
                names.join(", ")
            ))
        };

        DetectionResult {
            detector_name: self.name().to_string(),
            category: self.category(),
            score,
            matched_patterns,
            explanation,
        }
    }
}

/// Regex-based data exfiltration detector (PII, credentials, sensitive data).
pub struct RegexExfiltrationDetector {
    patterns: Vec<DetectionPattern>,
}

impl RegexExfiltrationDetector {
    pub fn new() -> Self {
        let patterns = vec![
            DetectionPattern {
                name: "ssn".to_string(),
                regex: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").expect("ssn regex"),
                weight: 0.8,
            },
            DetectionPattern {
                name: "credit_card".to_string(),
                regex: Regex::new(
                    r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
                )
                .expect("credit_card regex"),
                weight: 0.8,
            },
            DetectionPattern {
                name: "email_address".to_string(),
                regex: Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
                    .expect("email_address regex"),
                weight: 0.3,
            },
            DetectionPattern {
                name: "api_key_pattern".to_string(),
                regex: Regex::new(
                    r"(?i)(api[_\-]?key|secret[_\-]?key|access[_\-]?token)\s*[:=]\s*\S+",
                )
                .expect("api_key_pattern regex"),
                weight: 0.6,
            },
            DetectionPattern {
                name: "private_key".to_string(),
                regex: Regex::new(r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----")
                    .expect("private_key regex"),
                weight: 0.9,
            },
        ];

        Self { patterns }
    }
}

impl Default for RegexExfiltrationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for RegexExfiltrationDetector {
    fn name(&self) -> &str {
        "regex_exfiltration"
    }

    fn category(&self) -> DetectionCategory {
        DetectionCategory::DataExfiltration
    }

    fn detect(&self, input: &str) -> DetectionResult {
        let mut matched_patterns = Vec::new();
        let mut total_weight = 0.0;

        for pattern in &self.patterns {
            if let Some(m) = pattern.regex.find(input) {
                total_weight += pattern.weight;
                matched_patterns.push(MatchedPattern {
                    name: pattern.name.clone(),
                    weight: pattern.weight,
                    matched_text: Some(m.as_str().to_string()),
                });
            }
        }

        let score = total_weight.min(1.0);

        let explanation = if matched_patterns.is_empty() {
            None
        } else {
            let names: Vec<&str> = matched_patterns.iter().map(|p| p.name.as_str()).collect();
            Some(format!(
                "matched {} exfiltration pattern(s): {}",
                matched_patterns.len(),
                names.join(", ")
            ))
        };

        DetectionResult {
            detector_name: self.name().to_string(),
            category: self.category(),
            score,
            matched_patterns,
            explanation,
        }
    }
}

/// Configuration for the detection pipeline.
#[derive(Clone, Debug)]
pub struct DetectionConfig {
    pub enabled: bool,
    pub prompt_injection_threshold: f64,
    pub jailbreak_threshold: f64,
    pub exfiltration_threshold: f64,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            prompt_injection_threshold: 0.5,
            jailbreak_threshold: 0.5,
            exfiltration_threshold: 0.5,
        }
    }
}

#[derive(Clone, Debug)]
pub struct EvaluationWithDetection {
    pub evaluation: EvaluationResult,
    pub detections: Vec<DetectionResult>,
    pub detection_decision: Option<Decision>,
}

/// Evaluate an action against policy rules and then run detection.
///
/// Detection deny overrides a policy allow/warn but never weakens a policy deny.
pub fn evaluate_with_detection(
    spec: &HushSpec,
    action: &EvaluationAction,
    registry: &DetectorRegistry,
    config: &DetectionConfig,
) -> EvaluationWithDetection {
    let evaluation = evaluate(spec, action);

    if !config.enabled {
        return EvaluationWithDetection {
            evaluation,
            detections: vec![],
            detection_decision: None,
        };
    }

    let content = action.content.as_deref().unwrap_or_default();
    if content.is_empty() {
        return EvaluationWithDetection {
            evaluation,
            detections: vec![],
            detection_decision: None,
        };
    }

    let detections = registry.detect_all(content);
    let detection_decision = check_thresholds(&detections, config);

    let final_eval =
        if detection_decision == Some(Decision::Deny) && evaluation.decision != Decision::Deny {
            EvaluationResult {
                decision: Decision::Deny,
                matched_rule: Some("detection".to_string()),
                reason: Some("content exceeded detection threshold".to_string()),
                origin_profile: evaluation.origin_profile.clone(),
                posture: evaluation.posture.clone(),
            }
        } else {
            evaluation
        };

    EvaluationWithDetection {
        evaluation: final_eval,
        detections,
        detection_decision,
    }
}

fn check_thresholds(detections: &[DetectionResult], config: &DetectionConfig) -> Option<Decision> {
    let should_deny = detections.iter().any(|result| {
        let threshold = match result.category {
            DetectionCategory::PromptInjection => config.prompt_injection_threshold,
            DetectionCategory::Jailbreak => config.jailbreak_threshold,
            DetectionCategory::DataExfiltration => config.exfiltration_threshold,
        };
        result.score >= threshold
    });

    if should_deny {
        Some(Decision::Deny)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn injection_detector_compiles_all_patterns() {
        let detector = RegexInjectionDetector::new();
        assert_eq!(detector.patterns.len(), 7);
    }

    #[test]
    fn jailbreak_detector_compiles_all_patterns() {
        let detector = RegexJailbreakDetector::new();
        assert_eq!(detector.patterns.len(), 1);
    }

    #[test]
    fn exfiltration_detector_compiles_all_patterns() {
        let detector = RegexExfiltrationDetector::new();
        assert_eq!(detector.patterns.len(), 5);
    }

    #[test]
    fn check_thresholds_returns_none_when_below() {
        let results = vec![DetectionResult {
            detector_name: "test".to_string(),
            category: DetectionCategory::PromptInjection,
            score: 0.3,
            matched_patterns: vec![],
            explanation: None,
        }];
        let config = DetectionConfig::default();
        assert_eq!(check_thresholds(&results, &config), None);
    }

    #[test]
    fn check_thresholds_returns_deny_when_at_threshold() {
        let results = vec![DetectionResult {
            detector_name: "test".to_string(),
            category: DetectionCategory::PromptInjection,
            score: 0.5,
            matched_patterns: vec![],
            explanation: None,
        }];
        let config = DetectionConfig::default();
        assert_eq!(check_thresholds(&results, &config), Some(Decision::Deny));
    }
}
