use serde::{Deserialize, Serialize};

use crate::siem::types::{SecurityEvent, SecurityEventType, SecuritySeverity};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EventFilter {
    #[serde(default)]
    pub min_severity: Option<SecuritySeverity>,
    #[serde(default)]
    pub include_types: Vec<SecurityEventType>,
    #[serde(default)]
    pub exclude_types: Vec<SecurityEventType>,
    #[serde(default)]
    pub include_guards: Vec<String>,
    #[serde(default)]
    pub exclude_guards: Vec<String>,
}

impl EventFilter {
    pub fn matches(&self, event: &SecurityEvent) -> bool {
        if let Some(min) = &self.min_severity {
            if severity_ord(&event.decision.severity) < severity_ord(min) {
                return false;
            }
        }

        if !self.include_types.is_empty() && !self.include_types.contains(&event.event_type) {
            return false;
        }
        if self.exclude_types.contains(&event.event_type) {
            return false;
        }

        if !self.include_guards.is_empty() && !self.include_guards.contains(&event.decision.guard) {
            return false;
        }
        if self.exclude_guards.contains(&event.decision.guard) {
            return false;
        }

        true
    }
}

fn severity_ord(sev: &SecuritySeverity) -> u8 {
    match sev {
        SecuritySeverity::Info => 0,
        SecuritySeverity::Low => 1,
        SecuritySeverity::Medium => 2,
        SecuritySeverity::High => 3,
        SecuritySeverity::Critical => 4,
    }
}
