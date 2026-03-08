//! Enclave resolver — maps an [`OriginContext`] to its effective security profile.
//!
//! The resolver evaluates match rules on each [`OriginProfile`] and selects the
//! most specific match using a deterministic priority scheme:
//!
//! 1. Exact `space_id` match (highest)
//! 2. Tag + visibility + provider match (most specific by field count)
//! 3. Provider-only match
//! 4. Default profile (empty match rules)
//! 5. `default_behavior` from [`OriginsConfig`]

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::guards::{EgressAllowlistConfig, McpDefaultAction, McpToolConfig};
use crate::origin::OriginContext;
use crate::policy::{
    BridgePolicy, OriginBudgets, OriginDataPolicy, OriginDefaultBehavior, OriginMatch,
    OriginProfile, OriginsConfig,
};

// ---------------------------------------------------------------------------
// ResolvedEnclave
// ---------------------------------------------------------------------------

/// Result of enclave resolution — the effective security profile for an origin.
#[must_use]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedEnclave {
    /// Profile ID that matched (None if default behavior applied).
    pub profile_id: Option<String>,
    /// Effective MCP tool configuration from the matched profile.
    pub mcp: Option<McpToolConfig>,
    /// Effective posture state name.
    pub posture: Option<String>,
    /// Effective egress policy.
    pub egress: Option<EgressAllowlistConfig>,
    /// Effective data policy.
    pub data: Option<OriginDataPolicy>,
    /// Effective budgets.
    pub budgets: Option<OriginBudgets>,
    /// Bridge policy.
    pub bridge_policy: Option<BridgePolicy>,
    /// Explanation from the matched profile.
    pub explanation: Option<String>,
    /// Resolution path for explainability — describes why this profile was selected.
    pub resolution_path: Vec<String>,
}

// ---------------------------------------------------------------------------
// MatchScore (internal)
// ---------------------------------------------------------------------------

/// Score of a profile match against an origin context.
struct MatchScore {
    /// Number of match fields that were specified and matched.
    specificity: usize,
    /// Whether this was an exact `space_id` match (highest priority).
    exact_space_id: bool,
}

// ---------------------------------------------------------------------------
// EnclaveResolver
// ---------------------------------------------------------------------------

/// Resolves an [`OriginContext`] against an [`OriginsConfig`] to produce a
/// [`ResolvedEnclave`].
pub struct EnclaveResolver;

impl EnclaveResolver {
    /// Resolve an origin context against an origins config to find the matching
    /// enclave profile.
    ///
    /// Match priority (deterministic):
    /// 1. Exact `space_id` match
    /// 2. Tag + visibility + provider match (most specific wins by field count)
    /// 3. Provider-only match
    /// 4. Default profile (profile with empty match_rules — all fields None/empty)
    /// 5. `default_behavior` (deny or minimal read-only)
    pub fn resolve(origin: &OriginContext, config: &OriginsConfig) -> Result<ResolvedEnclave> {
        let mut best: Option<(usize, &OriginProfile, MatchScore)> = None;

        for (idx, profile) in config.profiles.iter().enumerate() {
            if let Some(score) = Self::matches_profile(origin, profile) {
                let dominated = match &best {
                    None => true,
                    Some((_, _, prev)) => Self::score_beats(
                        &score,
                        idx,
                        prev,
                        best.as_ref().map(|(i, _, _)| *i).unwrap_or(usize::MAX),
                    ),
                };
                if dominated {
                    best = Some((idx, profile, score));
                }
            }
        }

        match best {
            Some((_idx, profile, score)) => {
                let resolution_path = vec![Self::describe_match(&profile.match_rules, &score)];
                Ok(Self::enclave_from_profile(profile, resolution_path))
            }
            None => Self::apply_default_behavior(config.effective_default_behavior()),
        }
    }

    // -----------------------------------------------------------------------
    // Matching
    // -----------------------------------------------------------------------

    /// Check each field in `match_rules` against the origin. If any specified
    /// field does **not** match, return `None` (fail-closed). Otherwise return
    /// the score.
    fn matches_profile(origin: &OriginContext, profile: &OriginProfile) -> Option<MatchScore> {
        let rules = &profile.match_rules;
        let mut specificity: usize = 0;
        let mut exact_space_id = false;

        // provider — compare via string representation to avoid Custom("slack") != Slack
        if let Some(ref rule_provider) = rules.provider {
            if origin.provider.to_string() != rule_provider.to_string() {
                return None;
            }
            specificity += 1;
        }

        // tenant_id
        if let Some(ref rule_tenant) = rules.tenant_id {
            match &origin.tenant_id {
                Some(origin_tenant) if origin_tenant == rule_tenant => {
                    specificity += 1;
                }
                _ => return None,
            }
        }

        // space_id
        if let Some(ref rule_space) = rules.space_id {
            match &origin.space_id {
                Some(origin_space) if origin_space == rule_space => {
                    specificity += 1;
                    exact_space_id = true;
                }
                _ => return None,
            }
        }

        // space_type — compare via string representation (same reason as provider)
        if let Some(ref rule_space_type) = rules.space_type {
            match &origin.space_type {
                Some(origin_space_type)
                    if origin_space_type.to_string() == rule_space_type.to_string() =>
                {
                    specificity += 1;
                }
                _ => return None,
            }
        }

        // thread_id
        if let Some(ref rule_thread) = rules.thread_id {
            match &origin.thread_id {
                Some(origin_thread) if origin_thread == rule_thread => {
                    specificity += 1;
                }
                _ => return None,
            }
        }

        // visibility — compare via string representation (same reason as provider)
        if let Some(ref rule_vis) = rules.visibility {
            match &origin.visibility {
                Some(origin_vis) if origin_vis.to_string() == rule_vis.to_string() => {
                    specificity += 1;
                }
                _ => return None,
            }
        }

        // external_participants
        if let Some(rule_ext) = rules.external_participants {
            match origin.external_participants {
                Some(origin_ext) if origin_ext == rule_ext => {
                    specificity += 1;
                }
                _ => return None,
            }
        }

        // tags: ALL specified tags must be present in origin's tags
        if !rules.tags.is_empty() {
            for tag in &rules.tags {
                if !origin.tags.contains(tag) {
                    return None;
                }
            }
            specificity += 1;
        }

        // sensitivity
        if let Some(ref rule_sens) = rules.sensitivity {
            match &origin.sensitivity {
                Some(origin_sens) if origin_sens == rule_sens => {
                    specificity += 1;
                }
                _ => return None,
            }
        }

        // actor_role
        if let Some(ref rule_actor_role) = rules.actor_role {
            match &origin.actor_role {
                Some(origin_actor_role) if origin_actor_role == rule_actor_role => {
                    specificity += 1;
                }
                _ => return None,
            }
        }

        // provenance_confidence
        if let Some(ref rule_pc) = rules.provenance_confidence {
            match &origin.provenance_confidence {
                Some(origin_pc) if origin_pc == rule_pc => {
                    specificity += 1;
                }
                _ => return None,
            }
        }

        Some(MatchScore {
            specificity,
            exact_space_id,
        })
    }

    // -----------------------------------------------------------------------
    // Score comparison
    // -----------------------------------------------------------------------

    /// Returns `true` if `candidate` beats `current` under the deterministic
    /// priority rules:
    ///
    /// 1. `exact_space_id` wins over non-exact
    /// 2. Higher specificity wins
    /// 3. Lower list index wins (stable ordering)
    fn score_beats(
        candidate: &MatchScore,
        candidate_idx: usize,
        current: &MatchScore,
        current_idx: usize,
    ) -> bool {
        if candidate.exact_space_id != current.exact_space_id {
            return candidate.exact_space_id;
        }
        if candidate.specificity != current.specificity {
            return candidate.specificity > current.specificity;
        }
        candidate_idx < current_idx
    }

    // -----------------------------------------------------------------------
    // Default behavior fallback
    // -----------------------------------------------------------------------

    pub(crate) fn apply_default_behavior(
        behavior: &OriginDefaultBehavior,
    ) -> Result<ResolvedEnclave> {
        match behavior {
            OriginDefaultBehavior::Deny => Err(Error::ConfigError(
                "no origin profile matched and default behavior is deny".into(),
            )),
            OriginDefaultBehavior::MinimalProfile => Ok(ResolvedEnclave {
                profile_id: None,
                mcp: Some(McpToolConfig {
                    enabled: true,
                    allow: vec![],
                    block: vec![],
                    require_confirmation: vec![],
                    default_action: Some(McpDefaultAction::Block),
                    max_args_size: None,
                    additional_allow: vec![],
                    additional_block: vec![],
                    remove_allow: vec![],
                    remove_block: vec![],
                }),
                posture: None,
                egress: None,
                data: None,
                budgets: None,
                bridge_policy: None,
                explanation: Some("minimal fallback profile: MCP tools blocked by default".into()),
                resolution_path: vec!["default_behavior:minimal_profile".into()],
            }),
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn enclave_from_profile(
        profile: &OriginProfile,
        resolution_path: Vec<String>,
    ) -> ResolvedEnclave {
        ResolvedEnclave {
            profile_id: Some(profile.id.clone()),
            mcp: profile.mcp.clone(),
            posture: profile.posture.clone(),
            egress: profile.egress.clone(),
            data: profile.data.clone(),
            budgets: profile.budgets.clone(),
            bridge_policy: profile.bridge_policy.clone(),
            explanation: profile.explanation.clone(),
            resolution_path,
        }
    }

    /// Build a human-readable description of why a match was selected.
    fn describe_match(rules: &OriginMatch, score: &MatchScore) -> String {
        if score.specificity == 0 {
            return "default_profile:fallback".into();
        }

        let mut parts: Vec<String> = Vec::new();

        if let Some(ref space_id) = rules.space_id {
            parts.push(format!("exact_space_id={space_id}"));
        }
        if let Some(ref provider) = rules.provider {
            parts.push(format!("provider={provider}"));
        }
        if let Some(ref tenant_id) = rules.tenant_id {
            parts.push(format!("tenant_id={tenant_id}"));
        }
        if let Some(ref space_type) = rules.space_type {
            parts.push(format!("space_type={space_type}"));
        }
        if let Some(ref thread_id) = rules.thread_id {
            parts.push(format!("thread_id={thread_id}"));
        }
        if let Some(ref vis) = rules.visibility {
            parts.push(format!("visibility={vis}"));
        }
        if let Some(ext) = rules.external_participants {
            parts.push(format!("external_participants={ext}"));
        }
        if !rules.tags.is_empty() {
            parts.push(format!("tags=[{}]", rules.tags.join(",")));
        }
        if let Some(ref sens) = rules.sensitivity {
            parts.push(format!("sensitivity={sens}"));
        }
        if let Some(ref actor_role) = rules.actor_role {
            parts.push(format!("actor_role={actor_role}"));
        }
        if let Some(ref pc) = rules.provenance_confidence {
            parts.push(format!("provenance_confidence={pc}"));
        }

        parts.join(",")
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::origin::{OriginProvider, ProvenanceConfidence, SpaceType, Visibility};

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn empty_origins_config(behavior: OriginDefaultBehavior) -> OriginsConfig {
        OriginsConfig {
            default_behavior: Some(behavior),
            profiles: Vec::new(),
        }
    }

    fn profile(id: &str, match_rules: OriginMatch) -> OriginProfile {
        OriginProfile {
            id: id.into(),
            match_rules,
            posture: None,
            mcp: None,
            egress: None,
            data: None,
            budgets: None,
            bridge_policy: None,
            explanation: None,
        }
    }

    fn slack_origin() -> OriginContext {
        OriginContext {
            provider: OriginProvider::Slack,
            tenant_id: Some("T001".into()),
            space_id: Some("C123".into()),
            space_type: Some(SpaceType::Channel),
            thread_id: Some("thread-42".into()),
            visibility: Some(Visibility::Internal),
            external_participants: Some(false),
            tags: vec!["incident".into(), "pci".into(), "hipaa".into()],
            sensitivity: Some("high".into()),
            provenance_confidence: Some(ProvenanceConfidence::Strong),
            ..OriginContext::default()
        }
    }

    // -----------------------------------------------------------------------
    // 1. Exact space_id match
    // -----------------------------------------------------------------------

    #[test]
    fn exact_space_id_match() {
        let config = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![profile(
                "channel-c123",
                OriginMatch {
                    space_id: Some("C123".into()),
                    ..Default::default()
                },
            )],
        };

        let result = EnclaveResolver::resolve(&slack_origin(), &config).unwrap();
        assert_eq!(result.profile_id.as_deref(), Some("channel-c123"));
        assert!(result.resolution_path[0].contains("exact_space_id=C123"));
    }

    // -----------------------------------------------------------------------
    // 2. Tag + visibility match
    // -----------------------------------------------------------------------

    #[test]
    fn tag_and_visibility_match() {
        let config = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![profile(
                "incident-internal",
                OriginMatch {
                    visibility: Some(Visibility::Internal),
                    tags: vec!["incident".into()],
                    ..Default::default()
                },
            )],
        };

        let result = EnclaveResolver::resolve(&slack_origin(), &config).unwrap();
        assert_eq!(result.profile_id.as_deref(), Some("incident-internal"));
        assert!(result.resolution_path[0].contains("visibility=internal"));
        assert!(result.resolution_path[0].contains("tags=[incident]"));
    }

    // -----------------------------------------------------------------------
    // 3. Provider-only match
    // -----------------------------------------------------------------------

    #[test]
    fn provider_only_match() {
        let config = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![profile(
                "slack-general",
                OriginMatch {
                    provider: Some(OriginProvider::Slack),
                    ..Default::default()
                },
            )],
        };

        let result = EnclaveResolver::resolve(&slack_origin(), &config).unwrap();
        assert_eq!(result.profile_id.as_deref(), Some("slack-general"));
        assert!(result.resolution_path[0].contains("provider=slack"));
    }

    // -----------------------------------------------------------------------
    // 4. Most specific wins
    // -----------------------------------------------------------------------

    #[test]
    fn most_specific_wins() {
        let config = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![
                profile(
                    "two-fields",
                    OriginMatch {
                        provider: Some(OriginProvider::Slack),
                        visibility: Some(Visibility::Internal),
                        ..Default::default()
                    },
                ),
                profile(
                    "three-fields",
                    OriginMatch {
                        provider: Some(OriginProvider::Slack),
                        visibility: Some(Visibility::Internal),
                        tags: vec!["incident".into()],
                        ..Default::default()
                    },
                ),
            ],
        };

        let result = EnclaveResolver::resolve(&slack_origin(), &config).unwrap();
        assert_eq!(result.profile_id.as_deref(), Some("three-fields"));
    }

    // -----------------------------------------------------------------------
    // 5. Exact space_id beats higher specificity
    // -----------------------------------------------------------------------

    #[test]
    fn exact_space_id_beats_higher_specificity() {
        let config = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![
                // 5 fields but no space_id
                profile(
                    "five-fields",
                    OriginMatch {
                        provider: Some(OriginProvider::Slack),
                        visibility: Some(Visibility::Internal),
                        tags: vec!["incident".into()],
                        sensitivity: Some("high".into()),
                        external_participants: Some(false),
                        ..Default::default()
                    },
                ),
                // Only space_id — exact match
                profile(
                    "exact-space",
                    OriginMatch {
                        space_id: Some("C123".into()),
                        ..Default::default()
                    },
                ),
            ],
        };

        let result = EnclaveResolver::resolve(&slack_origin(), &config).unwrap();
        assert_eq!(result.profile_id.as_deref(), Some("exact-space"));
        assert!(result.resolution_path[0].contains("exact_space_id=C123"));
    }

    // -----------------------------------------------------------------------
    // 6. No match + deny
    // -----------------------------------------------------------------------

    #[test]
    fn no_match_deny() {
        let config = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![profile(
                "github-only",
                OriginMatch {
                    provider: Some(OriginProvider::GitHub),
                    ..Default::default()
                },
            )],
        };

        let err = EnclaveResolver::resolve(&slack_origin(), &config).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("no origin profile matched and default behavior is deny"),
            "unexpected error: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // 7. No match + minimal_profile
    // -----------------------------------------------------------------------

    #[test]
    fn no_match_minimal_profile() {
        let config = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::MinimalProfile),
            profiles: vec![profile(
                "github-only",
                OriginMatch {
                    provider: Some(OriginProvider::GitHub),
                    ..Default::default()
                },
            )],
        };

        let result = EnclaveResolver::resolve(&slack_origin(), &config).unwrap();
        assert_eq!(result.profile_id, None);
        // MinimalProfile materializes a restrictive MCP config (block by default)
        assert!(result.mcp.is_some());
        let mcp = result.mcp.as_ref().unwrap();
        assert_eq!(mcp.default_action, Some(McpDefaultAction::Block));
        assert!(
            mcp.allow.is_empty(),
            "minimal profile should not inherit default allow list"
        );
        assert!(
            mcp.block.is_empty(),
            "minimal profile should not inherit default block list"
        );
        assert!(
            mcp.require_confirmation.is_empty(),
            "minimal profile should not inherit default require_confirmation list"
        );
        assert_eq!(result.posture, None);
        assert_eq!(result.egress, None);
        assert_eq!(result.data, None);
        assert_eq!(result.budgets, None);
        assert_eq!(result.bridge_policy, None);
        assert!(result.explanation.is_some());
        assert_eq!(
            result.resolution_path,
            vec!["default_behavior:minimal_profile"]
        );
    }

    // -----------------------------------------------------------------------
    // 8. Default profile (empty match_rules)
    // -----------------------------------------------------------------------

    #[test]
    fn default_profile_catches_unmatched() {
        let config = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![
                profile(
                    "github-only",
                    OriginMatch {
                        provider: Some(OriginProvider::GitHub),
                        ..Default::default()
                    },
                ),
                profile("fallback", OriginMatch::default()),
            ],
        };

        let result = EnclaveResolver::resolve(&slack_origin(), &config).unwrap();
        assert_eq!(result.profile_id.as_deref(), Some("fallback"));
        assert_eq!(result.resolution_path, vec!["default_profile:fallback"]);
    }

    // -----------------------------------------------------------------------
    // 9. Tag intersection — superset of required tags matches
    // -----------------------------------------------------------------------

    #[test]
    fn tag_intersection_superset_matches() {
        let config = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![profile(
                "pci-hipaa",
                OriginMatch {
                    tags: vec!["pci".into(), "hipaa".into()],
                    ..Default::default()
                },
            )],
        };

        // slack_origin() has tags ["incident", "pci", "hipaa"] — superset of ["pci", "hipaa"]
        let result = EnclaveResolver::resolve(&slack_origin(), &config).unwrap();
        assert_eq!(result.profile_id.as_deref(), Some("pci-hipaa"));
    }

    // -----------------------------------------------------------------------
    // 10. Tag mismatch — required tag not present
    // -----------------------------------------------------------------------

    #[test]
    fn tag_mismatch_no_match() {
        let config = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::MinimalProfile),
            profiles: vec![profile(
                "needs-sox",
                OriginMatch {
                    tags: vec!["pci".into(), "sox".into()],
                    ..Default::default()
                },
            )],
        };

        // slack_origin() has tags ["incident", "pci", "hipaa"] — missing "sox"
        let result = EnclaveResolver::resolve(&slack_origin(), &config).unwrap();
        // Should fall through to minimal profile since no match
        assert_eq!(result.profile_id, None);
        assert_eq!(
            result.resolution_path,
            vec!["default_behavior:minimal_profile"]
        );
    }

    // -----------------------------------------------------------------------
    // 11. Stable ordering — same specificity, first in list wins
    // -----------------------------------------------------------------------

    #[test]
    fn stable_ordering_first_wins() {
        let config = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![
                profile(
                    "first",
                    OriginMatch {
                        provider: Some(OriginProvider::Slack),
                        ..Default::default()
                    },
                ),
                profile(
                    "second",
                    OriginMatch {
                        provider: Some(OriginProvider::Slack),
                        ..Default::default()
                    },
                ),
            ],
        };

        let result = EnclaveResolver::resolve(&slack_origin(), &config).unwrap();
        assert_eq!(result.profile_id.as_deref(), Some("first"));
    }

    // -----------------------------------------------------------------------
    // 12. All fields match
    // -----------------------------------------------------------------------

    #[test]
    fn all_fields_match() {
        let config = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![profile(
                "full-match",
                OriginMatch {
                    provider: Some(OriginProvider::Slack),
                    tenant_id: Some("T001".into()),
                    space_id: Some("C123".into()),
                    space_type: Some(SpaceType::Channel),
                    thread_id: Some("thread-42".into()),
                    visibility: Some(Visibility::Internal),
                    external_participants: Some(false),
                    tags: vec!["incident".into(), "pci".into()],
                    sensitivity: Some("high".into()),
                    actor_role: None,
                    provenance_confidence: Some(ProvenanceConfidence::Strong),
                },
            )],
        };

        let result = EnclaveResolver::resolve(&slack_origin(), &config).unwrap();
        assert_eq!(result.profile_id.as_deref(), Some("full-match"));
        assert!(result.resolution_path[0].contains("exact_space_id=C123"));
        assert!(result.resolution_path[0].contains("provider=slack"));
        assert!(result.resolution_path[0].contains("visibility=internal"));
    }

    // -----------------------------------------------------------------------
    // Additional edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn empty_profiles_deny() {
        let config = empty_origins_config(OriginDefaultBehavior::Deny);
        let err = EnclaveResolver::resolve(&slack_origin(), &config).unwrap_err();
        assert!(err
            .to_string()
            .contains("no origin profile matched and default behavior is deny"));
    }

    #[test]
    fn empty_profiles_minimal() {
        let config = empty_origins_config(OriginDefaultBehavior::MinimalProfile);
        let result = EnclaveResolver::resolve(&slack_origin(), &config).unwrap();
        assert_eq!(result.profile_id, None);
    }

    #[test]
    fn profile_with_explanation_is_propagated() {
        let mut p = profile(
            "with-explanation",
            OriginMatch {
                provider: Some(OriginProvider::Slack),
                ..Default::default()
            },
        );
        p.explanation = Some("Slack channels get standard security".into());
        p.posture = Some("standard".into());

        let config = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![p],
        };

        let result = EnclaveResolver::resolve(&slack_origin(), &config).unwrap();
        assert_eq!(
            result.explanation.as_deref(),
            Some("Slack channels get standard security")
        );
        assert_eq!(result.posture.as_deref(), Some("standard"));
    }

    #[test]
    fn mismatched_provider_does_not_match() {
        let config = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::MinimalProfile),
            profiles: vec![profile(
                "teams-only",
                OriginMatch {
                    provider: Some(OriginProvider::Teams),
                    ..Default::default()
                },
            )],
        };

        let result = EnclaveResolver::resolve(&slack_origin(), &config).unwrap();
        assert_eq!(result.profile_id, None);
    }

    #[test]
    fn space_id_mismatch_does_not_match() {
        let config = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::MinimalProfile),
            profiles: vec![profile(
                "wrong-space",
                OriginMatch {
                    space_id: Some("C999".into()),
                    ..Default::default()
                },
            )],
        };

        let result = EnclaveResolver::resolve(&slack_origin(), &config).unwrap();
        assert_eq!(result.profile_id, None);
    }

    #[test]
    fn origin_missing_optional_field_fails_match() {
        // Origin has no tenant_id — rule requires one
        let origin = OriginContext {
            provider: OriginProvider::Slack,
            tenant_id: None,
            ..OriginContext::default()
        };

        let config = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::MinimalProfile),
            profiles: vec![profile(
                "needs-tenant",
                OriginMatch {
                    tenant_id: Some("T001".into()),
                    ..Default::default()
                },
            )],
        };

        let result = EnclaveResolver::resolve(&origin, &config).unwrap();
        assert_eq!(result.profile_id, None);
    }

    #[test]
    fn actor_role_matches_when_origin_supplies_role() {
        let config = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::MinimalProfile),
            profiles: vec![profile(
                "admin-role",
                OriginMatch {
                    actor_role: Some("admin".into()),
                    ..Default::default()
                },
            )],
        };

        let mut origin = slack_origin();
        origin.actor_role = Some("admin".into());

        let result = EnclaveResolver::resolve(&origin, &config).unwrap();
        assert_eq!(result.profile_id.as_deref(), Some("admin-role"));
    }

    #[test]
    fn actor_role_mismatch_fails_closed() {
        let config = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::MinimalProfile),
            profiles: vec![profile(
                "needs-role",
                OriginMatch {
                    actor_role: Some("admin".into()),
                    ..Default::default()
                },
            )],
        };

        let mut origin = slack_origin();
        origin.actor_role = Some("member".into());

        let result = EnclaveResolver::resolve(&origin, &config).unwrap();
        assert_eq!(result.profile_id, None);
    }

    #[test]
    fn actor_role_is_included_in_resolution_path() {
        let config = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::MinimalProfile),
            profiles: vec![profile(
                "admin-role",
                OriginMatch {
                    actor_role: Some("admin".into()),
                    ..Default::default()
                },
            )],
        };

        let mut origin = slack_origin();
        origin.actor_role = Some("admin".into());

        let result = EnclaveResolver::resolve(&origin, &config).unwrap();
        assert!(result
            .resolution_path
            .iter()
            .any(|part| part.contains("actor_role=admin")));
    }

    #[test]
    fn serde_roundtrip_resolved_enclave() {
        let enclave = ResolvedEnclave {
            profile_id: Some("test".into()),
            mcp: None,
            posture: Some("locked".into()),
            egress: None,
            data: Some(OriginDataPolicy {
                allow_external_sharing: false,
                redact_before_send: true,
                block_sensitive_outputs: true,
            }),
            budgets: None,
            bridge_policy: None,
            explanation: Some("test enclave".into()),
            resolution_path: vec!["provider=slack".into()],
        };

        let json = serde_json::to_string(&enclave).unwrap();
        let deserialized: ResolvedEnclave = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.profile_id.as_deref(), Some("test"));
        assert_eq!(deserialized.posture.as_deref(), Some("locked"));
        assert_eq!(deserialized.resolution_path, vec!["provider=slack"]);
    }
}
