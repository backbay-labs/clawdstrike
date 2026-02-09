//! Posture schema and runtime types (policy v1.2.0+).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Duration;

use crate::error::PolicyFieldError;
use crate::guards::GuardAction;

pub const KNOWN_POSTURE_CAPABILITIES: &[&str] = &[
    "file_access",
    "file_write",
    "egress",
    "shell",
    "mcp_tool",
    "patch",
    "custom",
];

pub const KNOWN_POSTURE_BUDGETS: &[&str] = &[
    "file_writes",
    "egress_calls",
    "shell_commands",
    "mcp_tool_calls",
    "patches",
    "custom_calls",
];

/// Optional dynamic posture model for policy v1.2.0+.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostureConfig {
    pub initial: String,
    pub states: BTreeMap<String, PostureState>,
    #[serde(default)]
    pub transitions: Vec<PostureTransition>,
}

impl PostureConfig {
    pub fn merge_with(&self, child: &Self) -> Self {
        let mut states = self.states.clone();
        for (name, state) in &child.states {
            states.insert(name.clone(), state.clone());
        }

        Self {
            initial: if child.initial.trim().is_empty() {
                self.initial.clone()
            } else {
                child.initial.clone()
            },
            states,
            transitions: if child.transitions.is_empty() {
                self.transitions.clone()
            } else {
                child.transitions.clone()
            },
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostureState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub budgets: HashMap<String, i64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostureTransition {
    pub from: String,
    pub to: String,
    pub on: TransitionTrigger,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
    #[serde(default)]
    pub requires: Vec<TransitionRequirement>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionTrigger {
    UserApproval,
    UserDenial,
    CriticalViolation,
    AnyViolation,
    Timeout,
    BudgetExhausted,
    PatternMatch,
}

impl TransitionTrigger {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UserApproval => "user_approval",
            Self::UserDenial => "user_denial",
            Self::CriticalViolation => "critical_violation",
            Self::AnyViolation => "any_violation",
            Self::Timeout => "timeout",
            Self::BudgetExhausted => "budget_exhausted",
            Self::PatternMatch => "pattern_match",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionRequirement {
    NoViolationsIn(String),
}

pub fn validate_posture_config(posture: &PostureConfig, errors: &mut Vec<PolicyFieldError>) {
    if posture.states.is_empty() {
        errors.push(PolicyFieldError::new(
            "posture.states",
            "at least one posture state is required".to_string(),
        ));
        return;
    }

    if !posture.states.contains_key(posture.initial.as_str()) {
        errors.push(PolicyFieldError::new(
            "posture.initial",
            format!("posture.initial '{}' not found in states", posture.initial),
        ));
    }

    for (state_name, state) in &posture.states {
        for (idx, capability) in state.capabilities.iter().enumerate() {
            if !KNOWN_POSTURE_CAPABILITIES.contains(&capability.as_str()) {
                errors.push(PolicyFieldError::new(
                    format!("posture.states.{}.capabilities[{}]", state_name, idx),
                    format!("unknown capability: '{}'", capability),
                ));
            }
        }

        for (budget_name, value) in &state.budgets {
            if !KNOWN_POSTURE_BUDGETS.contains(&budget_name.as_str()) {
                errors.push(PolicyFieldError::new(
                    format!("posture.states.{}.budgets.{}", state_name, budget_name),
                    format!("unknown budget type: '{}'", budget_name),
                ));
            }
            if *value < 0 {
                errors.push(PolicyFieldError::new(
                    format!("posture.states.{}.budgets.{}", state_name, budget_name),
                    format!("budget '{}' cannot be negative", budget_name),
                ));
            }
        }
    }

    for (idx, transition) in posture.transitions.iter().enumerate() {
        if transition.from != "*" && !posture.states.contains_key(transition.from.as_str()) {
            errors.push(PolicyFieldError::new(
                format!("posture.transitions[{}].from", idx),
                format!("transition references unknown state: '{}'", transition.from),
            ));
        }

        if transition.to == "*" {
            errors.push(PolicyFieldError::new(
                format!("posture.transitions[{}].to", idx),
                "wildcard in 'to' not allowed".to_string(),
            ));
        } else if !posture.states.contains_key(transition.to.as_str()) {
            errors.push(PolicyFieldError::new(
                format!("posture.transitions[{}].to", idx),
                format!("transition references unknown state: '{}'", transition.to),
            ));
        }

        if matches!(transition.on, TransitionTrigger::Timeout) {
            match transition.after.as_deref() {
                Some(after) if parse_duration(after).is_some() => {}
                Some(after) => errors.push(PolicyFieldError::new(
                    format!("posture.transitions[{}].after", idx),
                    format!("invalid duration format: '{}'", after),
                )),
                None => errors.push(PolicyFieldError::new(
                    format!("posture.transitions[{}].after", idx),
                    "timeout transition missing 'after' duration".to_string(),
                )),
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Capability {
    FileAccess,
    FileWrite,
    Egress,
    Shell,
    McpTool,
    Patch,
    Custom,
}

impl Capability {
    pub fn from_policy(value: &str) -> Option<Self> {
        match value {
            "file_access" => Some(Self::FileAccess),
            "file_write" => Some(Self::FileWrite),
            "egress" => Some(Self::Egress),
            "shell" => Some(Self::Shell),
            "mcp_tool" => Some(Self::McpTool),
            "patch" => Some(Self::Patch),
            "custom" => Some(Self::Custom),
            _ => None,
        }
    }

    pub fn from_action(action: &GuardAction<'_>) -> Self {
        match action {
            GuardAction::FileAccess(_) => Self::FileAccess,
            GuardAction::FileWrite(_, _) => Self::FileWrite,
            GuardAction::NetworkEgress(_, _) => Self::Egress,
            GuardAction::ShellCommand(_) => Self::Shell,
            GuardAction::McpTool(_, _) => Self::McpTool,
            GuardAction::Patch(_, _) => Self::Patch,
            GuardAction::Custom(_, _) => Self::Custom,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FileAccess => "file_access",
            Self::FileWrite => "file_write",
            Self::Egress => "egress",
            Self::Shell => "shell",
            Self::McpTool => "mcp_tool",
            Self::Patch => "patch",
            Self::Custom => "custom",
        }
    }

    pub fn budget_key(self) -> Option<&'static str> {
        match self {
            Self::FileAccess => None,
            Self::FileWrite => Some("file_writes"),
            Self::Egress => Some("egress_calls"),
            Self::Shell => Some("shell_commands"),
            Self::McpTool => Some("mcp_tool_calls"),
            Self::Patch => Some("patches"),
            Self::Custom => Some("custom_calls"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostureProgram {
    pub initial_state: String,
    pub states: HashMap<String, CompiledPostureState>,
    pub transitions: Vec<CompiledTransition>,
}

impl PostureProgram {
    pub fn from_config(config: &PostureConfig) -> std::result::Result<Self, String> {
        let mut states = HashMap::with_capacity(config.states.len());
        for (name, state) in &config.states {
            let mut capabilities = HashSet::with_capacity(state.capabilities.len());
            for capability in &state.capabilities {
                let parsed = Capability::from_policy(capability)
                    .ok_or_else(|| format!("unknown capability: '{}'", capability))?;
                capabilities.insert(parsed);
            }

            let mut budgets = HashMap::with_capacity(state.budgets.len());
            for (budget_name, limit) in &state.budgets {
                let parsed_limit = u64::try_from(*limit)
                    .map_err(|_| format!("budget '{}' cannot be negative", budget_name))?;
                budgets.insert(budget_name.clone(), parsed_limit);
            }

            states.insert(
                name.clone(),
                CompiledPostureState {
                    name: name.clone(),
                    description: state.description.clone(),
                    capabilities,
                    budgets,
                },
            );
        }

        let mut transitions = Vec::with_capacity(config.transitions.len());
        for transition in &config.transitions {
            let source = if transition.from == "*" {
                TransitionSource::Any
            } else {
                TransitionSource::Specific(transition.from.clone())
            };

            let trigger = match transition.on {
                TransitionTrigger::UserApproval => CompiledTransitionTrigger::UserApproval,
                TransitionTrigger::UserDenial => CompiledTransitionTrigger::UserDenial,
                TransitionTrigger::CriticalViolation => {
                    CompiledTransitionTrigger::CriticalViolation
                }
                TransitionTrigger::AnyViolation => CompiledTransitionTrigger::AnyViolation,
                TransitionTrigger::BudgetExhausted => CompiledTransitionTrigger::BudgetExhausted,
                TransitionTrigger::PatternMatch => CompiledTransitionTrigger::PatternMatch,
                TransitionTrigger::Timeout => {
                    let after = transition
                        .after
                        .as_deref()
                        .ok_or_else(|| "timeout transition missing 'after' duration".to_string())?;
                    let parsed = parse_duration(after)
                        .ok_or_else(|| format!("invalid duration format: '{}'", after))?;
                    CompiledTransitionTrigger::Timeout(parsed)
                }
            };

            transitions.push(CompiledTransition {
                from: source,
                to: transition.to.clone(),
                trigger,
            });
        }

        Ok(Self {
            initial_state: config.initial.clone(),
            states,
            transitions,
        })
    }

    pub fn initial_runtime_state(&self) -> Option<PostureRuntimeState> {
        let state = self.states.get(&self.initial_state)?;
        Some(PostureRuntimeState::new(
            &self.initial_state,
            state.initial_budgets(),
        ))
    }

    pub fn state(&self, state_name: &str) -> Option<&CompiledPostureState> {
        self.states.get(state_name)
    }

    pub fn find_transition(
        &self,
        state_name: &str,
        trigger: RuntimeTransitionTrigger,
    ) -> Option<&CompiledTransition> {
        self.transitions.iter().find(|transition| {
            transition.matches_from(state_name) && transition.trigger.matches_runtime(trigger)
        })
    }

    pub fn find_due_timeout_transition(
        &self,
        state_name: &str,
        elapsed: Duration,
    ) -> Option<&CompiledTransition> {
        self.transitions.iter().find(|transition| {
            transition.matches_from(state_name) && transition.trigger.matches_timeout(elapsed)
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledPostureState {
    pub name: String,
    pub description: Option<String>,
    pub capabilities: HashSet<Capability>,
    pub budgets: HashMap<String, u64>,
}

impl CompiledPostureState {
    pub fn initial_budgets(&self) -> HashMap<String, PostureBudgetCounter> {
        self.budgets
            .iter()
            .map(|(name, limit)| {
                (
                    name.clone(),
                    PostureBudgetCounter {
                        used: 0,
                        limit: *limit,
                    },
                )
            })
            .collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledTransition {
    pub from: TransitionSource,
    pub to: String,
    pub trigger: CompiledTransitionTrigger,
}

impl CompiledTransition {
    fn matches_from(&self, state_name: &str) -> bool {
        match &self.from {
            TransitionSource::Any => true,
            TransitionSource::Specific(name) => name == state_name,
        }
    }

    pub fn trigger_string(&self) -> &'static str {
        self.trigger.as_str()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransitionSource {
    Any,
    Specific(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeTransitionTrigger {
    UserApproval,
    UserDenial,
    CriticalViolation,
    AnyViolation,
    BudgetExhausted,
}

impl RuntimeTransitionTrigger {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UserApproval => "user_approval",
            Self::UserDenial => "user_denial",
            Self::CriticalViolation => "critical_violation",
            Self::AnyViolation => "any_violation",
            Self::BudgetExhausted => "budget_exhausted",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompiledTransitionTrigger {
    UserApproval,
    UserDenial,
    CriticalViolation,
    AnyViolation,
    Timeout(Duration),
    BudgetExhausted,
    PatternMatch,
}

impl CompiledTransitionTrigger {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UserApproval => "user_approval",
            Self::UserDenial => "user_denial",
            Self::CriticalViolation => "critical_violation",
            Self::AnyViolation => "any_violation",
            Self::Timeout(_) => "timeout",
            Self::BudgetExhausted => "budget_exhausted",
            Self::PatternMatch => "pattern_match",
        }
    }

    fn matches_runtime(&self, runtime: RuntimeTransitionTrigger) -> bool {
        matches!(
            (self, runtime),
            (Self::UserApproval, RuntimeTransitionTrigger::UserApproval)
                | (Self::UserDenial, RuntimeTransitionTrigger::UserDenial)
                | (
                    Self::CriticalViolation,
                    RuntimeTransitionTrigger::CriticalViolation
                )
                | (Self::AnyViolation, RuntimeTransitionTrigger::AnyViolation)
                | (
                    Self::BudgetExhausted,
                    RuntimeTransitionTrigger::BudgetExhausted
                )
        )
    }

    fn matches_timeout(&self, elapsed: Duration) -> bool {
        matches!(self, Self::Timeout(required) if elapsed >= *required)
    }
}

/// Runtime posture state persisted under `SessionContext.state["posture"]`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostureRuntimeState {
    pub current_state: String,
    pub entered_at: String,
    #[serde(default)]
    pub transition_history: Vec<PostureTransitionRecord>,
    #[serde(default)]
    pub budgets: HashMap<String, PostureBudgetCounter>,
}

impl PostureRuntimeState {
    pub fn new(initial_state: &str, budgets: HashMap<String, PostureBudgetCounter>) -> Self {
        Self {
            current_state: initial_state.to_string(),
            entered_at: Utc::now().to_rfc3339(),
            transition_history: Vec::new(),
            budgets,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostureTransitionRecord {
    pub from: String,
    pub to: String,
    pub trigger: String,
    pub at: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostureBudgetCounter {
    pub used: u64,
    pub limit: u64,
}

impl PostureBudgetCounter {
    pub fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.used)
    }

    pub fn is_exhausted(&self) -> bool {
        self.used >= self.limit
    }

    pub fn try_consume(&mut self) -> bool {
        if self.is_exhausted() {
            return false;
        }
        self.used += 1;
        true
    }
}

pub fn parse_duration(value: &str) -> Option<Duration> {
    if value.len() < 2 {
        return None;
    }

    let (num, suffix) = value.split_at(value.len() - 1);
    if num.is_empty() || !num.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }

    let magnitude = num.parse::<u64>().ok()?;
    match suffix {
        "s" => Some(Duration::from_secs(magnitude)),
        "m" => Some(Duration::from_secs(magnitude.saturating_mul(60))),
        "h" => Some(Duration::from_secs(magnitude.saturating_mul(60 * 60))),
        _ => None,
    }
}

pub fn elapsed_since_timestamp(timestamp: &str, now: DateTime<Utc>) -> Option<Duration> {
    let entered = DateTime::parse_from_rfc3339(timestamp)
        .ok()?
        .with_timezone(&Utc);

    if entered >= now {
        return Some(Duration::from_secs(0));
    }

    (now - entered).to_std().ok()
}
