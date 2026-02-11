//! Shared decision normalization across hooks, tray, notifications, and API.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NormalizedDecision {
    Allowed,
    Blocked,
    Warn,
    Unknown,
}

impl NormalizedDecision {
    pub fn from_str(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "allowed" | "allow" => Self::Allowed,
            "blocked" | "block" | "deny" | "denied" => Self::Blocked,
            "warn" | "warning" => Self::Warn,
            _ => Self::Unknown,
        }
    }

    pub fn is_blocked(self) -> bool {
        matches!(self, Self::Blocked)
    }
}

#[cfg(test)]
mod tests {
    use super::NormalizedDecision;

    #[test]
    fn normalizes_aliases() {
        assert_eq!(
            NormalizedDecision::from_str("allow"),
            NormalizedDecision::Allowed
        );
        assert_eq!(
            NormalizedDecision::from_str("allowed"),
            NormalizedDecision::Allowed
        );
        assert_eq!(
            NormalizedDecision::from_str("block"),
            NormalizedDecision::Blocked
        );
        assert_eq!(
            NormalizedDecision::from_str("blocked"),
            NormalizedDecision::Blocked
        );
        assert_eq!(
            NormalizedDecision::from_str("warning"),
            NormalizedDecision::Warn
        );
        assert_eq!(
            NormalizedDecision::from_str("warn"),
            NormalizedDecision::Warn
        );
    }
}
