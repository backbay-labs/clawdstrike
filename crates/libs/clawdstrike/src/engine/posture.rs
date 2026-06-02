//! Posture-aware evaluation entrypoints and the runtime posture state machine.

use std::collections::HashMap;

use tracing::debug;

use crate::error::{Error, Result};
use crate::guards::{GuardAction, GuardContext, GuardResult, Severity};
use crate::origin_runtime::OriginRuntimeState;
use crate::posture::{
    elapsed_since_timestamp, Capability, PostureBudgetCounter, PostureProgram, PostureRuntimeState,
    PostureTransitionRecord, RuntimeTransitionTrigger,
};

use super::types::PostureAwareReport;
use super::{HushEngine, PreparedContext, PreparedEvaluation};

struct PosturePrecheck {
    allowed: bool,
    guard: &'static str,
    severity: Severity,
    message: String,
    trigger: Option<RuntimeTransitionTrigger>,
}

impl PosturePrecheck {
    fn allow() -> Self {
        Self {
            allowed: true,
            guard: "posture",
            severity: Severity::Info,
            message: String::new(),
            trigger: None,
        }
    }

    fn deny(
        guard: &'static str,
        severity: Severity,
        message: String,
        trigger: Option<RuntimeTransitionTrigger>,
    ) -> Self {
        Self {
            allowed: false,
            guard,
            severity,
            message,
            trigger,
        }
    }
}

impl HushEngine {
    pub async fn check_action_report_with_posture(
        &self,
        action: &GuardAction<'_>,
        context: &GuardContext,
        posture_state: &mut Option<PostureRuntimeState>,
    ) -> Result<PostureAwareReport> {
        let mut origin_state = posture_state
            .as_ref()
            .and_then(|state| state.origin_runtime.clone());
        let report = self
            .check_action_report_with_runtime(action, context, posture_state, &mut origin_state)
            .await?;
        if let Some(origin_state) = origin_state {
            let state = posture_state
                .get_or_insert_with(|| PostureRuntimeState::new("default", HashMap::new()));
            state.origin_runtime = Some(origin_state);
        }
        Ok(report)
    }

    pub async fn check_action_report_with_runtime(
        &self,
        action: &GuardAction<'_>,
        context: &GuardContext,
        posture_state: &mut Option<PostureRuntimeState>,
        origin_state: &mut Option<OriginRuntimeState>,
    ) -> Result<PostureAwareReport> {
        let Some(program) = self.posture_program.as_ref() else {
            let prepared = match self
                .prepare_origin_context(context, Some(origin_state))
                .await?
            {
                PreparedEvaluation::Continue(prepared) => *prepared,
                PreparedEvaluation::Complete(report) => {
                    return Ok(PostureAwareReport {
                        guard_report: *report,
                        posture_before: "default".to_string(),
                        posture_after: "default".to_string(),
                        budgets_before: HashMap::new(),
                        budgets_after: HashMap::new(),
                        budget_deltas: HashMap::new(),
                        transition: None,
                    });
                }
            };
            let guard_report = self
                .check_action_report_prepared(action, prepared, Some(origin_state))
                .await?;
            return Ok(PostureAwareReport {
                guard_report,
                posture_before: "default".to_string(),
                posture_after: "default".to_string(),
                budgets_before: HashMap::new(),
                budgets_after: HashMap::new(),
                budget_deltas: HashMap::new(),
                transition: None,
            });
        };

        self.ensure_posture_initialized(program, posture_state)?;
        let prepared = match self
            .prepare_origin_context(context, Some(origin_state))
            .await?
        {
            PreparedEvaluation::Continue(prepared) => *prepared,
            PreparedEvaluation::Complete(report) => {
                let state = posture_state.as_ref().ok_or_else(|| {
                    Error::ConfigError("failed to initialize posture runtime state".to_string())
                })?;
                return Ok(PostureAwareReport {
                    guard_report: *report,
                    posture_before: state.current_state.clone(),
                    posture_after: state.current_state.clone(),
                    budgets_before: state.budgets.clone(),
                    budgets_after: state.budgets.clone(),
                    budget_deltas: HashMap::new(),
                    transition: None,
                });
            }
        };
        let posture_context = prepared.context.clone();

        // Apply enclave posture override regardless of how the enclave was
        // obtained (pre-set or freshly resolved).
        if let Some(ref enclave) = posture_context.enclave {
            if let Some(ref enclave_posture) = enclave.posture {
                let state = posture_state.as_mut().ok_or_else(|| {
                    Error::ConfigError("posture state not initialized".to_string())
                })?;

                // Only override if the session is still in its initial state
                // (hasn't transitioned yet) — don't override mid-session.
                if state.transition_history.is_empty() {
                    // Validate that the enclave's posture state exists in the program.
                    if program.state(enclave_posture).is_some() {
                        if state.current_state != *enclave_posture {
                            let from = state.current_state.clone();
                            debug!(
                                from = %from,
                                to = %enclave_posture,
                                "Enclave overriding initial posture"
                            );
                            state.current_state = enclave_posture.clone();
                            state.entered_at = chrono::Utc::now().to_rfc3339();
                            // Re-initialize budgets for the new state.
                            if let Some(compiled) = program.state(enclave_posture) {
                                state.budgets = compiled.initial_budgets();
                            }
                            // Record synthetic transition so subsequent
                            // calls cannot re-override the posture.
                            state.transition_history.push(
                                crate::posture::PostureTransitionRecord {
                                    from,
                                    to: enclave_posture.clone(),
                                    trigger: "enclave_init".to_string(),
                                    at: state.entered_at.clone(),
                                },
                            );
                        }
                    } else {
                        // Fail-closed: enclave references nonexistent posture state.
                        let available: Vec<&String> = program.states.keys().collect();
                        return Err(Error::ConfigError(format!(
                            "enclave profile references unknown posture state \
                             '{}' (available: {:?})",
                            enclave_posture, available
                        )));
                    }
                }
            }
        }

        let state = posture_state.as_mut().ok_or_else(|| {
            Error::ConfigError("failed to initialize posture runtime state".to_string())
        })?;
        self.normalize_state_budgets(program, state);

        let mut transition = self.apply_timeout_transitions(program, state);

        let posture_before = state.current_state.clone();
        let budgets_before = state.budgets.clone();

        let precheck = self.posture_precheck(action, state, program);
        if !precheck.allowed {
            if let Some(trigger) = precheck.trigger {
                if let Some(record) = self.apply_trigger_transition(program, state, trigger) {
                    transition = Some(record);
                }
            }

            let denied = GuardResult::block(precheck.guard, precheck.severity, precheck.message);
            let guard_report = self
                .single_result_report(denied, prepared.metadata.clone())
                .await;

            return Ok(PostureAwareReport {
                guard_report,
                posture_before,
                posture_after: state.current_state.clone(),
                budgets_before,
                budgets_after: state.budgets.clone(),
                budget_deltas: HashMap::new(),
                transition,
            });
        }

        let guard_report = self
            .check_action_report_prepared(
                action,
                PreparedContext {
                    context: posture_context,
                    metadata: prepared.metadata.clone(),
                },
                Some(origin_state),
            )
            .await?;
        let mut budget_deltas: HashMap<String, i64> = HashMap::new();

        let mut trigger: Option<RuntimeTransitionTrigger> = None;
        if guard_report.overall.allowed {
            let capability = Capability::from_action(action);
            if let Some(budget_key) = capability.budget_key() {
                if let Some(counter) = state.budgets.get_mut(budget_key) {
                    if counter.try_consume() {
                        budget_deltas.insert(budget_key.to_string(), 1);
                    }
                    if counter.is_exhausted() {
                        trigger = Some(RuntimeTransitionTrigger::BudgetExhausted);
                    }
                }
            }
        } else {
            trigger = Some(if guard_report.overall.severity == Severity::Critical {
                RuntimeTransitionTrigger::CriticalViolation
            } else {
                RuntimeTransitionTrigger::AnyViolation
            });
        }

        if let Some(trigger) = trigger {
            if let Some(record) = self.apply_trigger_transition(program, state, trigger) {
                transition = Some(record);
            }
        }

        Ok(PostureAwareReport {
            guard_report,
            posture_before,
            posture_after: state.current_state.clone(),
            budgets_before,
            budgets_after: state.budgets.clone(),
            budget_deltas,
            transition,
        })
    }

    fn ensure_posture_initialized(
        &self,
        program: &PostureProgram,
        posture_state: &mut Option<PostureRuntimeState>,
    ) -> Result<()> {
        if posture_state.is_some() {
            return Ok(());
        }

        let initial = program.initial_runtime_state().ok_or_else(|| {
            Error::ConfigError(format!(
                "posture initial state '{}' is not defined",
                program.initial_state
            ))
        })?;

        *posture_state = Some(initial);
        Ok(())
    }

    fn normalize_state_budgets(&self, program: &PostureProgram, state: &mut PostureRuntimeState) {
        let Some(compiled) = program.state(&state.current_state) else {
            return;
        };

        state
            .budgets
            .retain(|name, _| compiled.budgets.contains_key(name));

        for (name, limit) in &compiled.budgets {
            let counter = state
                .budgets
                .entry(name.clone())
                .or_insert(PostureBudgetCounter {
                    used: 0,
                    limit: *limit,
                });
            counter.limit = *limit;
            if counter.used > counter.limit {
                counter.used = counter.limit;
            }
        }
    }

    fn apply_timeout_transitions(
        &self,
        program: &PostureProgram,
        state: &mut PostureRuntimeState,
    ) -> Option<PostureTransitionRecord> {
        let mut last_transition: Option<PostureTransitionRecord> = None;
        let max_hops = program.transitions.len().max(1);

        for _ in 0..max_hops {
            let now = chrono::Utc::now();
            let Some(elapsed) = elapsed_since_timestamp(&state.entered_at, now) else {
                break;
            };

            let Some(transition) =
                program.find_due_timeout_transition(&state.current_state, elapsed)
            else {
                break;
            };

            let trigger = transition.trigger_string();
            let record = self.apply_transition(program, state, &transition.to, trigger)?;
            last_transition = Some(record);
        }

        last_transition
    }

    fn posture_precheck(
        &self,
        action: &GuardAction<'_>,
        state: &PostureRuntimeState,
        program: &PostureProgram,
    ) -> PosturePrecheck {
        let Some(current_state) = program.state(&state.current_state) else {
            return PosturePrecheck::deny(
                "posture",
                Severity::Error,
                format!("unknown posture state '{}'", state.current_state),
                None,
            );
        };

        let capability = Capability::from_action(action);
        if !current_state.capabilities.contains(&capability) {
            return PosturePrecheck::deny(
                "posture",
                Severity::Error,
                format!(
                    "action '{}' is not allowed in posture state '{}'",
                    capability.as_str(),
                    state.current_state
                ),
                None,
            );
        }

        if let Some(budget_key) = capability.budget_key() {
            if let Some(counter) = state.budgets.get(budget_key) {
                if counter.is_exhausted() {
                    return PosturePrecheck::deny(
                        "posture_budget",
                        Severity::Error,
                        format!(
                            "budget '{}' exhausted ({}/{})",
                            budget_key, counter.used, counter.limit
                        ),
                        Some(RuntimeTransitionTrigger::BudgetExhausted),
                    );
                }
            }
        }

        PosturePrecheck::allow()
    }

    fn apply_trigger_transition(
        &self,
        program: &PostureProgram,
        state: &mut PostureRuntimeState,
        trigger: RuntimeTransitionTrigger,
    ) -> Option<PostureTransitionRecord> {
        let transition = program.find_transition(&state.current_state, trigger)?;
        self.apply_transition(program, state, &transition.to, trigger.as_str())
    }

    fn apply_transition(
        &self,
        program: &PostureProgram,
        state: &mut PostureRuntimeState,
        to_state: &str,
        trigger: &str,
    ) -> Option<PostureTransitionRecord> {
        let target = program.state(to_state)?;
        let from_state = state.current_state.clone();
        let now = chrono::Utc::now().to_rfc3339();

        state.current_state = to_state.to_string();
        state.entered_at = now.clone();
        state.budgets = target.initial_budgets();

        let record = PostureTransitionRecord {
            from: from_state,
            to: to_state.to_string(),
            trigger: trigger.to_string(),
            at: now,
        };
        state.transition_history.push(record.clone());

        Some(record)
    }
}
