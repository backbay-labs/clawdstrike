use std::collections::HashMap;
use std::sync::RwLock;

use crate::error::{Error, Result};
use crate::types::{AgentId, AgentIdentity};

pub trait IdentityRegistry: Send + Sync {
    fn register(&self, identity: AgentIdentity) -> Result<()>;
    fn get(&self, id: &AgentId) -> Result<Option<AgentIdentity>>;
    fn list(&self) -> Result<Vec<AgentIdentity>>;
    fn remove(&self, id: &AgentId) -> Result<Option<AgentIdentity>>;
}

#[derive(Default)]
pub struct InMemoryIdentityRegistry {
    identities: RwLock<HashMap<AgentId, AgentIdentity>>,
}

impl InMemoryIdentityRegistry {
    fn lock_read(&self) -> std::sync::RwLockReadGuard<'_, HashMap<AgentId, AgentIdentity>> {
        self.identities.read().unwrap_or_else(|e| e.into_inner())
    }

    fn lock_write(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<AgentId, AgentIdentity>> {
        self.identities.write().unwrap_or_else(|e| e.into_inner())
    }
}

impl IdentityRegistry for InMemoryIdentityRegistry {
    fn register(&self, identity: AgentIdentity) -> Result<()> {
        identity.validate_basic()?;

        let mut identities = self.lock_write();
        if identities.contains_key(&identity.id) {
            return Err(Error::IdentityAlreadyExists(identity.id.to_string()));
        }
        identities.insert(identity.id.clone(), identity);
        Ok(())
    }

    fn get(&self, id: &AgentId) -> Result<Option<AgentIdentity>> {
        let identities = self.lock_read();
        Ok(identities.get(id).cloned())
    }

    fn list(&self) -> Result<Vec<AgentIdentity>> {
        let identities = self.lock_read();
        let mut values = identities.values().cloned().collect::<Vec<_>>();
        values.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
        Ok(values)
    }

    fn remove(&self, id: &AgentId) -> Result<Option<AgentIdentity>> {
        let mut identities = self.lock_write();
        Ok(identities.remove(id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hush_core::Keypair;

    use crate::types::{AgentRole, TrustLevel};

    fn identity(id: &str, name: &str) -> AgentIdentity {
        AgentIdentity {
            id: AgentId::new(id).unwrap(),
            name: name.to_string(),
            role: AgentRole::Planner,
            trust_level: TrustLevel::Medium,
            public_key: Keypair::generate().public_key(),
            capabilities: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn register_get_list_remove_round_trip() {
        let reg = InMemoryIdentityRegistry::default();

        let a = identity("agent:a", "A");
        let b = identity("agent:b", "B");
        reg.register(a.clone()).unwrap();
        reg.register(b.clone()).unwrap();

        let got = reg.get(&a.id).unwrap().unwrap();
        assert_eq!(got.id, a.id);

        let listed = reg.list().unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].id.as_str(), "agent:a");
        assert_eq!(listed[1].id.as_str(), "agent:b");

        let removed = reg.remove(&a.id).unwrap().unwrap();
        assert_eq!(removed.id, a.id);
        assert!(reg.get(&a.id).unwrap().is_none());
    }

    #[test]
    fn duplicate_registration_fails() {
        let reg = InMemoryIdentityRegistry::default();
        let a = identity("agent:a", "A");
        reg.register(a.clone()).unwrap();
        let err = reg.register(a).unwrap_err().to_string();
        assert!(err.contains("already exists"));
    }
}
