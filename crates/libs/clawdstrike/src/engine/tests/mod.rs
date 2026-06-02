//! Engine tests, split into themed sibling modules.
#![allow(clippy::expect_used, clippy::unwrap_used)]

pub(super) use super::*;
pub(super) use async_trait::async_trait;
pub(super) use std::sync::atomic::{AtomicUsize, Ordering};
pub(super) use std::sync::Arc;
pub(super) use std::time::Duration;

pub(super) use crate::async_guards::{
    http::HttpClient, AsyncGuard, AsyncGuardConfig, AsyncGuardError,
};
pub(super) use crate::error::Error;
pub(super) use crate::guards::{CustomGuardRegistry, GuardAction, GuardResult, Severity};
pub(super) use crate::origin_runtime::OriginRuntimeState;
pub(super) use crate::policy::{AsyncExecutionMode, TimeoutBehavior};
pub(super) use crate::posture::{PostureRuntimeState, PostureTransitionRecord};

struct TestExtraGuard {
    name: &'static str,
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl Guard for TestExtraGuard {
    fn name(&self) -> &str {
        self.name
    }

    fn handles(&self, action: &GuardAction<'_>) -> bool {
        match action {
            GuardAction::Custom(kind, _) => *kind == "extra_guard_test",
            GuardAction::FileAccess(_) => self.name == "extra_guard_order",
            _ => false,
        }
    }

    async fn check(&self, _action: &GuardAction<'_>, _context: &GuardContext) -> GuardResult {
        self.calls.fetch_add(1, Ordering::Relaxed);
        GuardResult::allow(self.name())
    }
}

struct TestAsyncAllowGuard {
    config: AsyncGuardConfig,
}

impl TestAsyncAllowGuard {
    fn new() -> Self {
        Self {
            config: AsyncGuardConfig {
                timeout: Duration::from_millis(25),
                on_timeout: TimeoutBehavior::Warn,
                execution_mode: AsyncExecutionMode::Parallel,
                cache_enabled: false,
                cache_ttl: Duration::from_secs(60),
                cache_max_size_bytes: 1_024,
                rate_limit: None,
                circuit_breaker: None,
                retry: None,
            },
        }
    }
}

#[async_trait]
impl AsyncGuard for TestAsyncAllowGuard {
    fn name(&self) -> &str {
        "test_async_allow"
    }

    fn handles(&self, _action: &GuardAction<'_>) -> bool {
        true
    }

    fn config(&self) -> &AsyncGuardConfig {
        &self.config
    }

    fn cache_key(&self, action: &GuardAction<'_>, _context: &GuardContext) -> Option<String> {
        Some(format!("test_async_allow:{:?}", action))
    }

    async fn check_uncached(
        &self,
        _action: &GuardAction<'_>,
        _context: &GuardContext,
        _http: &HttpClient,
    ) -> std::result::Result<GuardResult, AsyncGuardError> {
        Ok(GuardResult::allow(self.name()))
    }
}

// Shared origin / enclave / posture test fixtures (used across the parts below).
pub(super) use crate::guards::McpDefaultAction;
pub(super) use crate::origin::{OriginContext, OriginProvider, SpaceType, Visibility};
pub(super) use crate::policy::{
    BridgePolicy, BridgeTarget, OriginDefaultBehavior, OriginMatch, OriginProfile, OriginsConfig,
};

/// Helper: create a v1.4.0 policy with an origins block.
pub(super) fn policy_with_origins(origins: OriginsConfig) -> Policy {
    let mut policy = Policy::new();
    policy.version = "1.4.0".to_string();
    policy.name = "enclave-test".to_string();
    policy.guards.mcp_tool = Some(crate::guards::McpToolConfig {
        enabled: true,
        allow: vec!["safe_tool".to_string(), "read_file".to_string()],
        block: vec!["shell_exec".to_string()],
        require_confirmation: vec![],
        default_action: Some(McpDefaultAction::Block),
        ..Default::default()
    });
    policy.origins = Some(origins);
    policy
}

/// Helper: create a simple Slack origin context.
pub(super) fn test_slack_origin() -> OriginContext {
    OriginContext {
        provider: OriginProvider::Slack,
        space_id: Some("C-test-123".into()),
        ..OriginContext::default()
    }
}

/// Helper: create a profile that matches Slack with given MCP config.
pub(super) fn slack_profile_with_mcp(id: &str, mcp: crate::guards::McpToolConfig) -> OriginProfile {
    OriginProfile {
        id: id.to_string(),
        match_rules: OriginMatch {
            provider: Some(OriginProvider::Slack),
            ..Default::default()
        },
        mcp: Some(mcp),
        posture: None,
        egress: None,
        data: None,
        budgets: None,
        bridge_policy: None,
        explanation: None,
    }
}

/// Helper: create a policy with both posture and origins configured.
pub(super) fn policy_with_posture_and_origins(
    posture_yaml: &str,
    origins: OriginsConfig,
) -> Policy {
    let mut policy = Policy::from_yaml(posture_yaml).unwrap();
    policy.version = "1.4.0".to_string();
    policy.origins = Some(origins);
    policy
}

/// Helper: create an origin profile that matches Slack and specifies a posture.
pub(super) fn slack_profile_with_posture(id: &str, posture: &str) -> OriginProfile {
    OriginProfile {
        id: id.to_string(),
        match_rules: OriginMatch {
            provider: Some(OriginProvider::Slack),
            ..Default::default()
        },
        posture: Some(posture.to_string()),
        mcp: None,
        egress: None,
        data: None,
        budgets: None,
        bridge_policy: None,
        explanation: None,
    }
}

/// Helper: create a GitHub origin context.
pub(super) fn test_github_origin() -> OriginContext {
    OriginContext {
        provider: OriginProvider::GitHub,
        space_id: Some("PR-42".into()),
        space_type: Some(SpaceType::PullRequest),
        ..OriginContext::default()
    }
}

/// Helper: create a Teams origin context.
pub(super) fn test_teams_origin() -> OriginContext {
    OriginContext {
        provider: OriginProvider::Teams,
        space_id: Some("T-channel-1".into()),
        ..OriginContext::default()
    }
}

/// Helper: create a Slack profile with a bridge policy.
pub(super) fn slack_profile_with_bridge(id: &str, bridge: Option<BridgePolicy>) -> OriginProfile {
    OriginProfile {
        id: id.to_string(),
        match_rules: OriginMatch {
            provider: Some(OriginProvider::Slack),
            ..Default::default()
        },
        mcp: None,
        posture: None,
        egress: None,
        data: None,
        budgets: None,
        bridge_policy: bridge,
        explanation: None,
    }
}

/// Helper: create a GitHub profile (so cross-origin resolves for target).
pub(super) fn github_profile() -> OriginProfile {
    OriginProfile {
        id: "github-default".to_string(),
        match_rules: OriginMatch {
            provider: Some(OriginProvider::GitHub),
            ..Default::default()
        },
        mcp: None,
        posture: None,
        egress: None,
        data: None,
        budgets: None,
        bridge_policy: None,
        explanation: None,
    }
}

/// Helper: create a Teams profile.
pub(super) fn teams_profile() -> OriginProfile {
    OriginProfile {
        id: "teams-default".to_string(),
        match_rules: OriginMatch {
            provider: Some(OriginProvider::Teams),
            ..Default::default()
        },
        mcp: None,
        posture: None,
        egress: None,
        data: None,
        budgets: None,
        bridge_policy: None,
        explanation: None,
    }
}

pub(super) async fn check_with_origin_runtime(
    engine: &HushEngine,
    context: &GuardContext,
    origin_state: &mut Option<OriginRuntimeState>,
) -> GuardReport {
    let mut posture_state = None;
    engine
        .check_action_report_with_runtime(
            &GuardAction::FileAccess("/app/src/main.rs"),
            context,
            &mut posture_state,
            origin_state,
        )
        .await
        .unwrap()
        .guard_report
}

pub(super) fn manual_enclave(
    profile_id: &str,
    posture: Option<&str>,
) -> crate::enclave::ResolvedEnclave {
    crate::enclave::ResolvedEnclave {
        profile_id: Some(profile_id.to_string()),
        mcp: None,
        posture: posture.map(str::to_string),
        egress: None,
        data: None,
        budgets: None,
        bridge_policy: None,
        explanation: Some("manual test enclave".to_string()),
        resolution_path: vec!["manual:test".to_string()],
    }
}

mod part_1_core;
mod part_2_origin;
mod part_3_posture;
mod part_4_cross_origin;
