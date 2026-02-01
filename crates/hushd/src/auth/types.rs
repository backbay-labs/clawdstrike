//! API key types and scope definitions

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// Permission scope for API keys
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    /// Can call /api/v1/check
    Check,
    /// Can read policy, audit, events
    Read,
    /// Can modify policy, reload
    Admin,
    /// Wildcard - all scopes
    #[serde(rename = "*")]
    All,
}

impl Scope {
    /// Parse scope from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "check" => Some(Self::Check),
            "read" => Some(Self::Read),
            "admin" => Some(Self::Admin),
            "*" | "all" => Some(Self::All),
            _ => None,
        }
    }

    /// Convert to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Check => "check",
            Self::Read => "read",
            Self::Admin => "admin",
            Self::All => "*",
        }
    }
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// API key with associated metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    /// Unique identifier
    pub id: String,
    /// SHA-256 hash of the actual key (never store plaintext)
    pub key_hash: String,
    /// Human-readable name for the key
    pub name: String,
    /// Permissions granted to this key
    pub scopes: HashSet<Scope>,
    /// When the key was created
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Optional expiration time
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl ApiKey {
    /// Check if this key has the required scope
    pub fn has_scope(&self, required: Scope) -> bool {
        self.scopes.contains(&Scope::All) || self.scopes.contains(&required)
    }

    /// Check if this key has expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires) = self.expires_at {
            chrono::Utc::now() > expires
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scope_from_str() {
        assert_eq!(Scope::from_str("check"), Some(Scope::Check));
        assert_eq!(Scope::from_str("read"), Some(Scope::Read));
        assert_eq!(Scope::from_str("admin"), Some(Scope::Admin));
        assert_eq!(Scope::from_str("*"), Some(Scope::All));
        assert_eq!(Scope::from_str("all"), Some(Scope::All));
        assert_eq!(Scope::from_str("CHECK"), Some(Scope::Check)); // case insensitive
        assert_eq!(Scope::from_str("invalid"), None);
    }

    #[test]
    fn test_scope_as_str() {
        assert_eq!(Scope::Check.as_str(), "check");
        assert_eq!(Scope::Read.as_str(), "read");
        assert_eq!(Scope::Admin.as_str(), "admin");
        assert_eq!(Scope::All.as_str(), "*");
    }

    #[test]
    fn test_api_key_has_scope_direct() {
        let mut scopes = HashSet::new();
        scopes.insert(Scope::Check);
        scopes.insert(Scope::Read);

        let key = ApiKey {
            id: "test-id".to_string(),
            key_hash: "hash".to_string(),
            name: "test".to_string(),
            scopes,
            created_at: chrono::Utc::now(),
            expires_at: None,
        };

        assert!(key.has_scope(Scope::Check));
        assert!(key.has_scope(Scope::Read));
        assert!(!key.has_scope(Scope::Admin));
    }

    #[test]
    fn test_api_key_has_scope_wildcard() {
        let mut scopes = HashSet::new();
        scopes.insert(Scope::All);

        let key = ApiKey {
            id: "admin-id".to_string(),
            key_hash: "hash".to_string(),
            name: "admin".to_string(),
            scopes,
            created_at: chrono::Utc::now(),
            expires_at: None,
        };

        // Wildcard grants all scopes
        assert!(key.has_scope(Scope::Check));
        assert!(key.has_scope(Scope::Read));
        assert!(key.has_scope(Scope::Admin));
    }

    #[test]
    fn test_api_key_not_expired() {
        let key = ApiKey {
            id: "test".to_string(),
            key_hash: "hash".to_string(),
            name: "test".to_string(),
            scopes: HashSet::new(),
            created_at: chrono::Utc::now(),
            expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
        };

        assert!(!key.is_expired());
    }

    #[test]
    fn test_api_key_expired() {
        let key = ApiKey {
            id: "test".to_string(),
            key_hash: "hash".to_string(),
            name: "test".to_string(),
            scopes: HashSet::new(),
            created_at: chrono::Utc::now(),
            expires_at: Some(chrono::Utc::now() - chrono::Duration::hours(1)),
        };

        assert!(key.is_expired());
    }

    #[test]
    fn test_api_key_no_expiration() {
        let key = ApiKey {
            id: "test".to_string(),
            key_hash: "hash".to_string(),
            name: "test".to_string(),
            scopes: HashSet::new(),
            created_at: chrono::Utc::now(),
            expires_at: None,
        };

        assert!(!key.is_expired());
    }
}
