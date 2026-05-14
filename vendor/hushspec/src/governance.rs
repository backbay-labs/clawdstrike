//! Governance metadata validation for HushSpec policies.
//!
//! Governance metadata is **advisory only** -- it has no impact on evaluation.
//! This module provides validation checks that emit warnings (never errors)
//! to support enterprise policy lifecycle workflows.

use crate::generated_models::{Classification, LifecycleState};
use crate::schema::HushSpec;

#[derive(Debug, Clone, PartialEq)]
pub struct GovernanceWarning {
    pub code: String,
    pub message: String,
}

/// Advisory-only governance metadata checks. Never produces errors.
#[must_use]
pub fn validate_governance(spec: &HushSpec) -> Vec<GovernanceWarning> {
    let mut warnings = Vec::new();

    let Some(metadata) = &spec.metadata else {
        return warnings;
    };

    if let Some(state) = &metadata.lifecycle_state
        && matches!(state, LifecycleState::Deprecated | LifecycleState::Archived)
    {
        warnings.push(GovernanceWarning {
            code: "GOV_LIFECYCLE".into(),
            message: format!(
                "policy lifecycle state is '{}'",
                serde_json::to_value(state)
                    .ok()
                    .and_then(|v| v.as_str().map(String::from))
                    .unwrap_or_else(|| format!("{state:?}"))
            ),
        });
    }

    if let Some(expiry) = &metadata.expiry_date {
        let today = current_date_iso();
        if expiry.as_str() < today.as_str() {
            warnings.push(GovernanceWarning {
                code: "GOV_EXPIRED".into(),
                message: format!("policy expiry_date '{expiry}' is in the past"),
            });
        }
    }

    if metadata.approved_by.is_some() && metadata.approval_date.is_none() {
        warnings.push(GovernanceWarning {
            code: "GOV_MISSING_APPROVAL_DATE".into(),
            message: "approved_by is set but approval_date is missing".into(),
        });
    }

    if let Some(Classification::Restricted) = &metadata.classification
        && metadata.approved_by.is_none()
    {
        warnings.push(GovernanceWarning {
            code: "GOV_RESTRICTED_NO_APPROVER".into(),
            message: "classification is 'restricted' but no approved_by is set".into(),
        });
    }

    warnings
}

fn current_date_iso() -> String {
    let now = std::time::SystemTime::now();
    let secs = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = secs / 86400;
    let (year, month, day) = days_to_date(days);
    format!("{year:04}-{month:02}-{day:02}")
}

/// Algorithm from http://howardhinnant.github.io/date_algorithms.html
fn days_to_date(days_since_epoch: u64) -> (u64, u64, u64) {
    let z = days_since_epoch + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generated_models::{Classification, GovernanceMetadata, LifecycleState};

    fn minimal_spec() -> HushSpec {
        HushSpec {
            hushspec: "0.1.0".into(),
            name: None,
            description: None,
            extends: None,
            merge_strategy: None,
            rules: None,
            extensions: None,
            metadata: None,
        }
    }

    #[test]
    fn no_metadata_no_warnings() {
        let spec = minimal_spec();
        let warnings = validate_governance(&spec);
        assert!(warnings.is_empty());
    }

    #[test]
    fn empty_metadata_no_warnings() {
        let mut spec = minimal_spec();
        spec.metadata = Some(GovernanceMetadata {
            author: None,
            approved_by: None,
            approval_date: None,
            classification: None,
            change_ticket: None,
            lifecycle_state: None,
            policy_version: None,
            effective_date: None,
            expiry_date: None,
        });
        let warnings = validate_governance(&spec);
        assert!(warnings.is_empty());
    }

    #[test]
    fn deprecated_lifecycle_warns() {
        let mut spec = minimal_spec();
        spec.metadata = Some(GovernanceMetadata {
            author: None,
            approved_by: None,
            approval_date: None,
            classification: None,
            change_ticket: None,
            lifecycle_state: Some(LifecycleState::Deprecated),
            policy_version: None,
            effective_date: None,
            expiry_date: None,
        });
        let warnings = validate_governance(&spec);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].code, "GOV_LIFECYCLE");
    }

    #[test]
    fn archived_lifecycle_warns() {
        let mut spec = minimal_spec();
        spec.metadata = Some(GovernanceMetadata {
            author: None,
            approved_by: None,
            approval_date: None,
            classification: None,
            change_ticket: None,
            lifecycle_state: Some(LifecycleState::Archived),
            policy_version: None,
            effective_date: None,
            expiry_date: None,
        });
        let warnings = validate_governance(&spec);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].code, "GOV_LIFECYCLE");
    }

    #[test]
    fn deployed_lifecycle_no_warning() {
        let mut spec = minimal_spec();
        spec.metadata = Some(GovernanceMetadata {
            author: None,
            approved_by: None,
            approval_date: None,
            classification: None,
            change_ticket: None,
            lifecycle_state: Some(LifecycleState::Deployed),
            policy_version: None,
            effective_date: None,
            expiry_date: None,
        });
        let warnings = validate_governance(&spec);
        assert!(warnings.is_empty());
    }

    #[test]
    fn expired_policy_warns() {
        let mut spec = minimal_spec();
        spec.metadata = Some(GovernanceMetadata {
            author: None,
            approved_by: None,
            approval_date: None,
            classification: None,
            change_ticket: None,
            lifecycle_state: None,
            policy_version: None,
            effective_date: None,
            expiry_date: Some("2020-01-01".into()),
        });
        let warnings = validate_governance(&spec);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].code, "GOV_EXPIRED");
    }

    #[test]
    fn future_expiry_no_warning() {
        let mut spec = minimal_spec();
        spec.metadata = Some(GovernanceMetadata {
            author: None,
            approved_by: None,
            approval_date: None,
            classification: None,
            change_ticket: None,
            lifecycle_state: None,
            policy_version: None,
            effective_date: None,
            expiry_date: Some("2099-12-31".into()),
        });
        let warnings = validate_governance(&spec);
        assert!(warnings.is_empty());
    }

    #[test]
    fn approved_by_without_date_warns() {
        let mut spec = minimal_spec();
        spec.metadata = Some(GovernanceMetadata {
            author: None,
            approved_by: Some("ciso@company.com".into()),
            approval_date: None,
            classification: None,
            change_ticket: None,
            lifecycle_state: None,
            policy_version: None,
            effective_date: None,
            expiry_date: None,
        });
        let warnings = validate_governance(&spec);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].code, "GOV_MISSING_APPROVAL_DATE");
    }

    #[test]
    fn approved_by_with_date_no_warning() {
        let mut spec = minimal_spec();
        spec.metadata = Some(GovernanceMetadata {
            author: None,
            approved_by: Some("ciso@company.com".into()),
            approval_date: Some("2024-03-15".into()),
            classification: None,
            change_ticket: None,
            lifecycle_state: None,
            policy_version: None,
            effective_date: None,
            expiry_date: None,
        });
        let warnings = validate_governance(&spec);
        assert!(warnings.is_empty());
    }

    #[test]
    fn restricted_without_approver_warns() {
        let mut spec = minimal_spec();
        spec.metadata = Some(GovernanceMetadata {
            author: None,
            approved_by: None,
            approval_date: None,
            classification: Some(Classification::Restricted),
            change_ticket: None,
            lifecycle_state: None,
            policy_version: None,
            effective_date: None,
            expiry_date: None,
        });
        let warnings = validate_governance(&spec);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].code, "GOV_RESTRICTED_NO_APPROVER");
    }

    #[test]
    fn restricted_with_approver_no_warning() {
        let mut spec = minimal_spec();
        spec.metadata = Some(GovernanceMetadata {
            author: None,
            approved_by: Some("ciso@company.com".into()),
            approval_date: Some("2024-03-15".into()),
            classification: Some(Classification::Restricted),
            change_ticket: None,
            lifecycle_state: None,
            policy_version: None,
            effective_date: None,
            expiry_date: None,
        });
        let warnings = validate_governance(&spec);
        assert!(warnings.is_empty());
    }

    #[test]
    fn parse_with_metadata() {
        let yaml = r#"
hushspec: "0.1.0"
name: "test-policy"
metadata:
  author: "security-team@company.com"
  approved_by: "ciso@company.com"
  approval_date: "2024-03-15"
  classification: internal
  lifecycle_state: deployed
  policy_version: 3
  change_ticket: "SEC-1234"
  effective_date: "2024-03-15"
  expiry_date: "2025-03-15"
"#;
        let spec = HushSpec::parse(yaml).expect("should parse");
        assert_eq!(spec.name.as_deref(), Some("test-policy"));
        let m = spec.metadata.as_ref().unwrap();
        assert_eq!(m.author.as_deref(), Some("security-team@company.com"));
        assert_eq!(m.approved_by.as_deref(), Some("ciso@company.com"));
        assert_eq!(m.approval_date.as_deref(), Some("2024-03-15"));
        assert_eq!(m.classification, Some(Classification::Internal));
        assert_eq!(m.lifecycle_state, Some(LifecycleState::Deployed));
        assert_eq!(m.policy_version, Some(3));
        assert_eq!(m.change_ticket.as_deref(), Some("SEC-1234"));
        assert_eq!(m.effective_date.as_deref(), Some("2024-03-15"));
        assert_eq!(m.expiry_date.as_deref(), Some("2025-03-15"));
    }

    #[test]
    fn parse_without_metadata_backward_compatible() {
        let yaml = r#"
hushspec: "0.1.0"
name: "simple-policy"
rules:
  egress:
    enabled: true
    allow: ["*.example.com"]
"#;
        let spec = HushSpec::parse(yaml).expect("should parse without metadata");
        assert!(spec.metadata.is_none());
    }

    #[test]
    fn classification_enum_roundtrip() {
        for value in &["public", "internal", "confidential", "restricted"] {
            let yaml = format!(
                r#"
hushspec: "0.1.0"
metadata:
  classification: {value}
"#
            );
            let spec = HushSpec::parse(&yaml).expect("should parse");
            let m = spec.metadata.unwrap();
            assert!(m.classification.is_some());
        }
    }

    #[test]
    fn lifecycle_state_enum_roundtrip() {
        for value in &[
            "draft",
            "review",
            "approved",
            "deployed",
            "deprecated",
            "archived",
        ] {
            let yaml = format!(
                r#"
hushspec: "0.1.0"
metadata:
  lifecycle_state: {value}
"#
            );
            let spec = HushSpec::parse(&yaml).expect("should parse");
            let m = spec.metadata.unwrap();
            assert!(m.lifecycle_state.is_some());
        }
    }

    #[test]
    fn days_to_date_known_values() {
        // 2024-01-01 is day 19723 since epoch
        assert_eq!(days_to_date(19723), (2024, 1, 1));
        // 1970-01-01 is day 0
        assert_eq!(days_to_date(0), (1970, 1, 1));
    }
}
