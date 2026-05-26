//! Enrollment lifecycle state persisted in agent settings.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EnrollmentState {
    #[serde(default)]
    pub enrolled: bool,
    #[serde(default)]
    pub agent_uuid: Option<String>,
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub enrollment_in_progress: bool,
}
