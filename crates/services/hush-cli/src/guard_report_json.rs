use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct GuardResultJson {
    pub allowed: bool,
    pub guard: String,
    pub severity: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize)]
pub struct GuardReportJson {
    pub overall: GuardResultJson,
    pub per_guard: Vec<GuardResultJson>,
}

impl GuardReportJson {
    pub fn from_report(report: &clawdstrike::GuardReport) -> Self {
        Self {
            overall: GuardResultJson::from_result(&report.overall),
            per_guard: report
                .per_guard
                .iter()
                .map(GuardResultJson::from_result)
                .collect(),
        }
    }

    pub fn synthetic_error(message: &str) -> Self {
        Self {
            overall: GuardResultJson {
                allowed: false,
                guard: "engine".to_string(),
                severity: "error".to_string(),
                message: message.to_string(),
                details: None,
            },
            per_guard: Vec::new(),
        }
    }
}

impl GuardResultJson {
    fn from_result(result: &clawdstrike::GuardResult) -> Self {
        Self {
            allowed: result.allowed,
            guard: result.guard.clone(),
            severity: canonical_guard_severity(&result.severity).to_string(),
            message: result.message.clone(),
            details: result.details.clone(),
        }
    }
}

fn canonical_guard_severity(severity: &clawdstrike::Severity) -> &'static str {
    match severity {
        clawdstrike::Severity::Info => "info",
        clawdstrike::Severity::Warning => "warning",
        clawdstrike::Severity::Error => "error",
        clawdstrike::Severity::Critical => "critical",
    }
}
