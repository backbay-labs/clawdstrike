use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Identity provider types.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityProvider {
    Oidc,
    Saml,
    Okta,
    Auth0,
    AzureAd,
    Custom,
}

/// Authentication methods used to establish the identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    Password,
    Mfa,
    Sso,
    Certificate,
    ApiKey,
    ServiceAccount,
}

/// An authenticated principal (user or service identity).
///
/// Note: timestamps are kept as ISO 8601/RFC 3339 strings for cross-language portability.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityPrincipal {
    /// Unique identifier (OIDC `sub`, SAML NameID, etc).
    pub id: String,

    /// Identity provider type.
    pub provider: IdentityProvider,

    /// Provider-specific issuer URL.
    pub issuer: String,

    /// Display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,

    /// Email address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,

    /// Email verification status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,

    /// Organization/tenant identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,

    /// Team memberships.
    #[serde(default)]
    pub teams: Vec<String>,

    /// Assigned roles.
    #[serde(default)]
    pub roles: Vec<String>,

    /// Custom attributes from IdP.
    #[serde(default)]
    pub attributes: HashMap<String, serde_json::Value>,

    /// Authentication timestamp (ISO 8601).
    pub authenticated_at: String,

    /// Authentication method used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_method: Option<AuthMethod>,

    /// Token expiration (ISO 8601).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

/// Organization tier levels.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OrganizationTier {
    Free,
    Pro,
    Enterprise,
}

/// Organization context.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrganizationContext {
    pub id: String,
    pub name: String,
    pub tier: OrganizationTier,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings: Option<serde_json::Value>,
}

/// Geo location information.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GeoLocation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latitude: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub longitude: Option<f64>,
}

/// Request context (per-request information).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestContext {
    /// Request ID.
    pub request_id: String,
    /// Source IP address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,
    /// User agent string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    /// Geo location (if resolved).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geo_location: Option<GeoLocation>,
    /// Whether request is from VPN.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_vpn: Option<bool>,
    /// Whether request is from corporate network.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_corporate_network: Option<bool>,
    /// Request timestamp (ISO 8601).
    pub timestamp: String,
}

/// Session metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionMetadata {
    pub auth_method: AuthMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idp_issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
}

/// Complete session context snapshot (control-plane view).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionContext {
    pub session_id: String,
    pub identity: IdentityPrincipal,
    pub created_at: String,
    pub last_activity_at: String,
    pub expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<OrganizationContext>,
    #[serde(default)]
    pub effective_roles: Vec<String>,
    #[serde(default)]
    pub effective_permissions: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<RequestContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<SessionMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<HashMap<String, serde_json::Value>>,
}

