//! Session state exposed to the tray and other components.

use serde::{Deserialize, Serialize};

/// Session state exposed to the tray and other components.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionState {
    pub session_id: Option<String>,
    pub posture: String,
    pub budget_used: u64,
    pub budget_limit: u64,
}

impl Default for SessionState {
    fn default() -> Self {
        Self {
            session_id: None,
            posture: "unknown".to_string(),
            budget_used: 0,
            budget_limit: 0,
        }
    }
}

impl SessionState {
    pub fn summary(&self) -> String {
        match &self.session_id {
            Some(_) => {
                if self.budget_limit > 0 {
                    format!(
                        "Session: active | Posture: {} | Budget: {}/{}",
                        self.posture, self.budget_used, self.budget_limit
                    )
                } else {
                    format!("Session: active | Posture: {}", self.posture)
                }
            }
            None => "Session: inactive".to_string(),
        }
    }
}
