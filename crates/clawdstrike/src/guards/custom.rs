use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;

use crate::error::{Error, Result};

use super::Guard;

pub trait CustomGuardFactory: Send + Sync {
    fn id(&self) -> &str;
    fn build(&self, config: Value) -> Result<Box<dyn Guard>>;
}

#[derive(Clone, Default)]
pub struct CustomGuardRegistry {
    factories: HashMap<String, Arc<dyn CustomGuardFactory>>,
}

impl std::fmt::Debug for CustomGuardRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustomGuardRegistry")
            .field("count", &self.factories.len())
            .finish()
    }
}

impl CustomGuardRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register<F>(&mut self, factory: F) -> &mut Self
    where
        F: CustomGuardFactory + 'static,
    {
        self.factories
            .insert(factory.id().to_string(), Arc::new(factory));
        self
    }

    pub fn get(&self, id: &str) -> Option<&Arc<dyn CustomGuardFactory>> {
        self.factories.get(id)
    }

    pub fn build(&self, id: &str, config: Value) -> Result<Box<dyn Guard>> {
        let factory = self.factories.get(id).ok_or_else(|| {
            Error::ConfigError(format!("Custom guard factory not found for id: {}", id))
        })?;
        factory.build(config)
    }
}

