//! API key types and scope definitions

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// Rate limit / billing tier for API keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApiKeyTier {
    Free,
    Silver,
    Gold,
    Platinum,
}

/// Permission scope for API keys
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Scope {
    /// Can call /api/v1/check
    #[serde(rename = "check")]
    Check,
    /// Can read policy, audit, events
    #[serde(rename = "read")]
    Read,
    /// Can modify policy, reload
    #[serde(rename = "admin")]
    Admin,
    /// Read certification details.
    #[serde(rename = "certifications:read")]
    CertificationsRead,
    /// Verify certification validity.
    #[serde(rename = "certifications:verify")]
    CertificationsVerify,
    /// Create/update certifications.
    #[serde(rename = "certifications:write")]
    CertificationsWrite,
    /// Read evidence and export job status.
    #[serde(rename = "evidence:read")]
    EvidenceRead,
    /// Export evidence bundles.
    #[serde(rename = "evidence:export")]
    EvidenceExport,
    /// Generate badge assets.
    #[serde(rename = "badges:generate")]
    BadgesGenerate,
    /// Manage webhook subscriptions.
    #[serde(rename = "webhooks:manage")]
    WebhooksManage,
    /// Wildcard - all scopes
    #[serde(rename = "*")]
    All,
}

impl std::str::FromStr for Scope {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "check" => Ok(Self::Check),
            "read" => Ok(Self::Read),
            "admin" => Ok(Self::Admin),
            "certifications:read" => Ok(Self::CertificationsRead),
            "certifications:verify" => Ok(Self::CertificationsVerify),
            "certifications:write" => Ok(Self::CertificationsWrite),
            "evidence:read" => Ok(Self::EvidenceRead),
            "evidence:export" => Ok(Self::EvidenceExport),
            "badges:generate" => Ok(Self::BadgesGenerate),
            "webhooks:manage" => Ok(Self::WebhooksManage),
            "*" | "all" => Ok(Self::All),
            _ => Err(()),
        }
    }
}

impl Scope {
    /// Convert to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Check => "check",
            Self::Read => "read",
            Self::Admin => "admin",
            Self::CertificationsRead => "certifications:read",
            Self::CertificationsVerify => "certifications:verify",
            Self::CertificationsWrite => "certifications:write",
            Self::EvidenceRead => "evidence:read",
            Self::EvidenceExport => "evidence:export",
            Self::BadgesGenerate => "badges:generate",
            Self::WebhooksManage => "webhooks:manage",
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
    /// Hash of the actual key (never store plaintext)
    pub key_hash: String,
    /// Human-readable name for the key
    pub name: String,
    /// Rate limit tier (optional; defaults are inferred).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<ApiKeyTier>,
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
        assert_eq!("check".parse::<Scope>().ok(), Some(Scope::Check));
        assert_eq!("read".parse::<Scope>().ok(), Some(Scope::Read));
        assert_eq!("admin".parse::<Scope>().ok(), Some(Scope::Admin));
        assert_eq!(
            "certifications:read".parse::<Scope>().ok(),
            Some(Scope::CertificationsRead)
        );
        assert_eq!(
            "certifications:verify".parse::<Scope>().ok(),
            Some(Scope::CertificationsVerify)
        );
        assert_eq!(
            "certifications:write".parse::<Scope>().ok(),
            Some(Scope::CertificationsWrite)
        );
        assert_eq!(
            "evidence:read".parse::<Scope>().ok(),
            Some(Scope::EvidenceRead)
        );
        assert_eq!(
            "evidence:export".parse::<Scope>().ok(),
            Some(Scope::EvidenceExport)
        );
        assert_eq!(
            "badges:generate".parse::<Scope>().ok(),
            Some(Scope::BadgesGenerate)
        );
        assert_eq!(
            "webhooks:manage".parse::<Scope>().ok(),
            Some(Scope::WebhooksManage)
        );
        assert_eq!("*".parse::<Scope>().ok(), Some(Scope::All));
        assert_eq!("all".parse::<Scope>().ok(), Some(Scope::All));
        assert_eq!("CHECK".parse::<Scope>().ok(), Some(Scope::Check)); // case insensitive
        assert_eq!("invalid".parse::<Scope>().ok(), None);
    }

    #[test]
    fn test_scope_as_str() {
        assert_eq!(Scope::Check.as_str(), "check");
        assert_eq!(Scope::Read.as_str(), "read");
        assert_eq!(Scope::Admin.as_str(), "admin");
        assert_eq!(Scope::CertificationsRead.as_str(), "certifications:read");
        assert_eq!(
            Scope::CertificationsVerify.as_str(),
            "certifications:verify"
        );
        assert_eq!(Scope::CertificationsWrite.as_str(), "certifications:write");
        assert_eq!(Scope::EvidenceRead.as_str(), "evidence:read");
        assert_eq!(Scope::EvidenceExport.as_str(), "evidence:export");
        assert_eq!(Scope::BadgesGenerate.as_str(), "badges:generate");
        assert_eq!(Scope::WebhooksManage.as_str(), "webhooks:manage");
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
            tier: None,
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
            tier: None,
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
            tier: None,
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
            tier: None,
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
            tier: None,
            scopes: HashSet::new(),
            created_at: chrono::Utc::now(),
            expires_at: None,
        };

        assert!(!key.is_expired());
    }
}
