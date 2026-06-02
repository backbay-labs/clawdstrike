//! Construction and builders for [`HushEngine`].

use std::sync::Arc;

use tokio::sync::RwLock;

use hush_core::Keypair;

use crate::async_guards::AsyncGuardRuntime;
use crate::error::{Error, Result};
use crate::guards::{CustomGuardRegistry, Guard};
use crate::policy::{Policy, RuleSet};
use crate::posture::PostureProgram;

use super::{EngineState, HushEngine};

impl HushEngine {
    /// Create a new engine with default policy
    pub fn new() -> Self {
        Self::with_policy(Policy::default())
    }

    pub fn builder(policy: Policy) -> HushEngineBuilder {
        HushEngineBuilder {
            policy,
            custom_guard_registry: None,
            keypair: None,
        }
    }

    /// Create with a specific policy
    pub fn with_policy(policy: Policy) -> Self {
        let guards = policy.create_guards();
        let async_runtime = Arc::new(AsyncGuardRuntime::new());
        let (async_guards, async_guard_init_error) =
            match crate::async_guards::registry::build_async_guards(&policy) {
                Ok(v) => (v, None),
                Err(e) => (Vec::new(), Some(e.to_string())),
            };

        let (custom_guards, mut config_error) = match build_custom_guards_from_policy(&policy, None)
        {
            Ok(v) => (v, None),
            Err(e) => (Vec::new(), Some(e.to_string())),
        };

        let posture_program = match policy.posture.as_ref() {
            Some(config) => match PostureProgram::from_config(config) {
                Ok(program) => Some(program),
                Err(err) => {
                    config_error = Some(err);
                    None
                }
            },
            None => None,
        };

        Self {
            policy,
            guards,
            custom_guards,
            extra_guards: Vec::new(),
            keypair: None,
            state: Arc::new(RwLock::new(EngineState::default())),
            config_error,
            async_runtime,
            async_guards,
            async_guard_init_error,
            posture_program,
        }
    }

    /// Create from a named ruleset
    pub fn from_ruleset(name: &str) -> Result<Self> {
        let ruleset = RuleSet::by_name(name)?
            .ok_or_else(|| Error::ConfigError(format!("Unknown ruleset: {}", name)))?;
        Ok(Self::with_policy(ruleset.policy))
    }

    /// Set the signing keypair
    pub fn with_keypair(mut self, keypair: Keypair) -> Self {
        self.keypair = Some(keypair);
        self
    }

    /// Generate a new signing keypair
    pub fn with_generated_keypair(mut self) -> Self {
        self.keypair = Some(Keypair::generate());
        self
    }

    /// Append an additional guard (evaluated after all built-in guards).
    ///
    /// Note: when `fail_fast` is enabled, guards after the first violation (including extras)
    /// will not run.
    pub fn with_extra_guard<G>(mut self, guard: G) -> Self
    where
        G: Guard + 'static,
    {
        self.extra_guards.push(Box::new(guard));
        self
    }

    /// Append an additional guard (evaluated after all built-in guards).
    ///
    /// Note: when `fail_fast` is enabled, guards after the first violation (including extras)
    /// will not run.
    pub fn with_extra_guard_box(mut self, guard: Box<dyn Guard>) -> Self {
        self.extra_guards.push(guard);
        self
    }

    /// Append an additional guard (evaluated after all built-in guards).
    ///
    /// Note: when `fail_fast` is enabled, guards after the first violation (including extras)
    /// will not run.
    pub fn add_extra_guard<G>(&mut self, guard: G) -> &mut Self
    where
        G: Guard + 'static,
    {
        self.extra_guards.push(Box::new(guard));
        self
    }

    /// Append an additional guard (evaluated after all built-in guards).
    ///
    /// Note: when `fail_fast` is enabled, guards after the first violation (including extras)
    /// will not run.
    pub fn add_extra_guard_box(&mut self, guard: Box<dyn Guard>) -> &mut Self {
        self.extra_guards.push(guard);
        self
    }
}

pub struct HushEngineBuilder {
    policy: Policy,
    custom_guard_registry: Option<CustomGuardRegistry>,
    keypair: Option<Keypair>,
}

impl HushEngineBuilder {
    pub fn with_custom_guard_registry(mut self, registry: CustomGuardRegistry) -> Self {
        self.custom_guard_registry = Some(registry);
        self
    }

    pub fn with_keypair(mut self, keypair: Keypair) -> Self {
        self.keypair = Some(keypair);
        self
    }

    pub fn with_generated_keypair(mut self) -> Self {
        self.keypair = Some(Keypair::generate());
        self
    }

    pub fn build(self) -> Result<HushEngine> {
        let guards = self.policy.create_guards();
        let async_runtime = Arc::new(AsyncGuardRuntime::new());
        let (async_guards, async_guard_init_error) =
            match crate::async_guards::registry::build_async_guards(&self.policy) {
                Ok(v) => (v, None),
                Err(e) => (Vec::new(), Some(e.to_string())),
            };
        let custom_guards =
            build_custom_guards_from_policy(&self.policy, self.custom_guard_registry.as_ref())?;
        let posture_program = self
            .policy
            .posture
            .as_ref()
            .map(PostureProgram::from_config)
            .transpose()
            .map_err(Error::ConfigError)?;

        Ok(HushEngine {
            policy: self.policy,
            guards,
            custom_guards,
            extra_guards: Vec::new(),
            keypair: self.keypair,
            state: Arc::new(RwLock::new(EngineState::default())),
            config_error: None,
            async_runtime,
            async_guards,
            async_guard_init_error,
            posture_program,
        })
    }
}

impl Default for HushEngine {
    fn default() -> Self {
        Self::new()
    }
}

pub(super) fn build_custom_guards_from_policy(
    policy: &Policy,
    registry: Option<&CustomGuardRegistry>,
) -> Result<Vec<Box<dyn Guard>>> {
    let mut out: Vec<Box<dyn Guard>> = Vec::new();

    for spec in &policy.custom_guards {
        if !spec.enabled {
            continue;
        }

        let Some(registry) = registry else {
            return Err(Error::ConfigError(format!(
                "Policy requires custom guard {} but no CustomGuardRegistry was provided",
                spec.id
            )));
        };

        let config = crate::placeholders::resolve_placeholders_in_json(spec.config.clone())?;
        let guard = registry.build(&spec.id, config)?;
        out.push(guard);
    }

    Ok(out)
}
