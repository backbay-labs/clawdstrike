# OIDC and SAML Integration for Clawdstrike

## Problem Statement

Enterprise organizations use federated identity providers (IdPs) to manage user authentication and authorization. Clawdstrike must integrate with these systems to:

1. **Authenticate Users**: Validate that requests come from authenticated users
2. **Extract Identity Claims**: Map IdP claims to Clawdstrike identity context
3. **Scope Policies**: Apply different policies based on user/team/org from IdP claims
4. **Attribute Actions**: Include identity in all audit logs for compliance

Without IdP integration, Clawdstrike cannot participate in enterprise Zero Trust architectures or meet compliance requirements for user-attributable audit trails.

## Use Cases

### UC-OIDC-1: OIDC JWT Validation
An AI agent runtime receives a JWT from the enterprise SSO system. The runtime passes this token to Clawdstrike, which validates it and extracts user identity to include in policy evaluation.

### UC-OIDC-2: OIDC Claims-Based Policy
A policy rule specifies that only users with the `engineering` role can execute shell commands. Clawdstrike evaluates the `roles` claim from the JWT to enforce this rule.

### UC-SAML-1: SAML Assertion Processing
An enterprise uses SAML 2.0 for SSO. The application receives a SAML assertion after authentication and passes it to Clawdstrike for identity extraction.

### UC-SAML-2: SAML Attribute Mapping
The SAML assertion contains custom attributes (e.g., `department`, `costCenter`). Clawdstrike maps these to identity context for policy scoping.

### UC-HYBRID-1: Multi-Protocol Support
An organization has some applications using OIDC and others using SAML. Clawdstrike normalizes both into a common identity model.

## Architecture

### OIDC Flow

```
+-------------+      +--------------+      +------------------+
|             |      |              |      |                  |
|  User/Agent +----->+  Application +----->+  Clawdstrike     |
|             | (1)  |              | (2)  |  Identity Bridge |
+-------------+      +------+-------+      +--------+---------+
                            |                       |
                            | (3) Redirect          | (4) Validate
                            v                       v
                     +------+-------+      +--------+---------+
                     |              |      |                  |
                     |  OIDC IdP    |      |  JWKS Endpoint   |
                     |  (Auth)      +<-----+  (Keys)          |
                     |              | (5)  |                  |
                     +--------------+      +------------------+
```

1. User/Agent initiates action
2. Application provides JWT to Clawdstrike
3. (Prior) User authenticated with IdP
4. Clawdstrike validates JWT signature
5. Fetches public keys from JWKS endpoint

### SAML Flow

```
+-------------+      +--------------+      +------------------+
|             |      |              |      |                  |
|  User/Agent +----->+  Application +----->+  Clawdstrike     |
|             | (1)  |              | (2)  |  SAML Processor  |
+-------------+      +------+-------+      +--------+---------+
                            |                       |
                            | (3) SAML SSO          | (4) Validate
                            v                       |
                     +------+-------+               |
                     |              |               |
                     |  SAML IdP    |               |
                     |  (Assertion) |               |
                     |              |               |
                     +------+-------+               |
                            |                       |
                            | (5) Certificates      |
                            v                       |
                     +------+-------+               |
                     |              |               |
                     |  IdP Metadata+<--------------+
                     |  (Public Key)|  (Fetch for validation)
                     |              |
                     +--------------+
```

1. User/Agent initiates action
2. Application provides SAML assertion to Clawdstrike
3. (Prior) User authenticated with SAML IdP via SSO
4. Clawdstrike validates assertion signature
5. Clawdstrike fetches IdP certificates from metadata endpoint for signature verification

## API Design

### TypeScript SDK

```typescript
/**
 * OIDC Configuration
 */
export interface OIDCConfig {
  /** OIDC issuer URL (e.g., https://auth.example.com) */
  issuer: string;

  /** Expected audience (client ID) */
  audience: string | string[];

  /** JWKS URI (auto-discovered from issuer if not provided) */
  jwksUri?: string;

  /** Clock tolerance in seconds for expiration checks */
  clockTolerance?: number;

  /** Maximum token age in seconds */
  maxAge?: number;

  /** Required claims that must be present */
  requiredClaims?: string[];

  /** Claim mapping configuration */
  claimMapping?: OIDCClaimMapping;

  /** Cache settings for JWKS */
  jwksCache?: {
    /** Cache TTL in seconds */
    ttl: number;
    /** Maximum cached keys */
    maxKeys: number;
  };
}

/**
 * OIDC claim mapping to Clawdstrike identity
 */
export interface OIDCClaimMapping {
  /** Claim for user ID (default: 'sub') */
  userId?: string;

  /** Claim for email (default: 'email') */
  email?: string;

  /** Claim for display name (default: 'name') */
  displayName?: string;

  /** Claim for organization ID */
  organizationId?: string;

  /** Claim for roles (default: 'roles' or 'groups') */
  roles?: string;

  /** Claim for teams */
  teams?: string;

  /** Additional claims to extract */
  additionalClaims?: string[];
}

/**
 * SAML Configuration
 */
export interface SAMLConfig {
  /** Service Provider entity ID */
  entityId: string;

  /** IdP metadata URL or inline XML */
  idpMetadata: string | SAMLIdPMetadata;

  /** Assertion Consumer Service URL */
  acsUrl: string;

  /** Whether to validate assertion signature */
  validateSignature: boolean;

  /** Whether to validate assertion conditions */
  validateConditions: boolean;

  /** Attribute mapping configuration */
  attributeMapping?: SAMLAttributeMapping;

  /** Maximum assertion age in seconds */
  maxAssertionAge?: number;

  /** Service Provider certificate for encryption */
  spCertificate?: string;

  /** Service Provider private key for decryption */
  spPrivateKey?: string;
}

/**
 * SAML IdP Metadata (when provided inline)
 */
export interface SAMLIdPMetadata {
  /** IdP entity ID */
  entityId: string;

  /** SSO URL */
  ssoUrl: string;

  /** IdP signing certificate (PEM format) */
  certificate: string;

  /** Optional logout URL */
  sloUrl?: string;
}

/**
 * SAML attribute mapping to Clawdstrike identity
 */
export interface SAMLAttributeMapping {
  /** Attribute for user ID (default: NameID) */
  userId?: string;

  /** Attribute for email */
  email?: string;

  /** Attribute for display name */
  displayName?: string;

  /** Attribute for organization ID */
  organizationId?: string;

  /** Attribute for roles */
  roles?: string;

  /** Attribute for teams */
  teams?: string;

  /** Additional attributes to extract */
  additionalAttributes?: string[];
}

/**
 * Identity Bridge - Main interface for token processing
 */
export interface IdentityBridge {
  /**
   * Validate an OIDC JWT and extract identity
   */
  validateOIDCToken(token: string): Promise<IdentityResult>;

  /**
   * Process a SAML assertion and extract identity
   */
  processSAMLAssertion(assertion: string): Promise<IdentityResult>;

  /**
   * Refresh JWKS cache
   */
  refreshJWKS(): Promise<void>;

  /**
   * Get current configuration
   */
  getConfig(): OIDCConfig | SAMLConfig;
}

/**
 * Result of identity extraction
 */
export interface IdentityResult {
  /** Whether validation succeeded */
  success: boolean;

  /** Extracted identity principal */
  principal?: IdentityPrincipal;

  /** Error message if validation failed */
  error?: string;

  /** Detailed validation errors */
  validationErrors?: ValidationError[];

  /** Raw claims/attributes for debugging */
  rawClaims?: Record<string, unknown>;
}

/**
 * Validation error details
 */
export interface ValidationError {
  /** Error code */
  code: 'INVALID_SIGNATURE' | 'EXPIRED' | 'INVALID_AUDIENCE' | 'INVALID_ISSUER' |
        'MISSING_CLAIM' | 'INVALID_ASSERTION' | 'REPLAY_DETECTED';

  /** Human-readable message */
  message: string;

  /** Field that failed validation */
  field?: string;
}

/**
 * Create an OIDC identity bridge
 */
export function createOIDCBridge(config: OIDCConfig): IdentityBridge;

/**
 * Create a SAML identity bridge
 */
export function createSAMLBridge(config: SAMLConfig): IdentityBridge;

/**
 * Create a multi-protocol identity bridge
 */
export function createIdentityBridge(config: {
  oidc?: OIDCConfig;
  saml?: SAMLConfig;
}): IdentityBridge;
```

### Rust SDK

```rust
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// OIDC Configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OidcConfig {
    /// OIDC issuer URL
    pub issuer: String,

    /// Expected audience (client ID)
    pub audience: Vec<String>,

    /// JWKS URI (auto-discovered if not provided)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,

    /// Clock tolerance for expiration checks
    #[serde(default = "default_clock_tolerance")]
    pub clock_tolerance_secs: u64,

    /// Maximum token age
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_age_secs: Option<u64>,

    /// Required claims
    #[serde(default)]
    pub required_claims: Vec<String>,

    /// Claim mapping
    #[serde(default)]
    pub claim_mapping: OidcClaimMapping,

    /// JWKS cache TTL
    #[serde(default = "default_jwks_cache_ttl")]
    pub jwks_cache_ttl_secs: u64,
}

fn default_clock_tolerance() -> u64 { 30 }
fn default_jwks_cache_ttl() -> u64 { 3600 }

/// OIDC claim mapping
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OidcClaimMapping {
    /// Claim for user ID
    #[serde(default = "default_user_id_claim")]
    pub user_id: String,

    /// Claim for email
    #[serde(default = "default_email_claim")]
    pub email: String,

    /// Claim for display name
    #[serde(default = "default_name_claim")]
    pub display_name: String,

    /// Claim for organization ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,

    /// Claim for roles
    #[serde(default = "default_roles_claim")]
    pub roles: String,

    /// Claim for teams
    #[serde(skip_serializing_if = "Option::is_none")]
    pub teams: Option<String>,

    /// Additional claims to extract
    #[serde(default)]
    pub additional_claims: Vec<String>,
}

fn default_user_id_claim() -> String { "sub".to_string() }
fn default_email_claim() -> String { "email".to_string() }
fn default_name_claim() -> String { "name".to_string() }
fn default_roles_claim() -> String { "roles".to_string() }

/// SAML Configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SamlConfig {
    /// Service Provider entity ID
    pub entity_id: String,

    /// IdP metadata URL or inline
    pub idp_metadata: IdpMetadataSource,

    /// Assertion Consumer Service URL
    pub acs_url: String,

    /// Validate assertion signature
    #[serde(default = "default_true")]
    pub validate_signature: bool,

    /// Validate assertion conditions
    #[serde(default = "default_true")]
    pub validate_conditions: bool,

    /// Attribute mapping
    #[serde(default)]
    pub attribute_mapping: SamlAttributeMapping,

    /// Maximum assertion age
    #[serde(default = "default_max_assertion_age")]
    pub max_assertion_age_secs: u64,
}

fn default_true() -> bool { true }
fn default_max_assertion_age() -> u64 { 300 }

/// IdP metadata source
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum IdpMetadataSource {
    /// URL to fetch metadata from
    Url(String),
    /// Inline metadata
    Inline(IdpMetadata),
}

/// Inline IdP metadata
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdpMetadata {
    pub entity_id: String,
    pub sso_url: String,
    pub certificate: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slo_url: Option<String>,
}

/// SAML attribute mapping
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SamlAttributeMapping {
    /// Attribute for user ID (default: NameID)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,

    /// Attribute for email
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,

    /// Attribute for display name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,

    /// Attribute for organization ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,

    /// Attribute for roles
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<String>,

    /// Attribute for teams
    #[serde(skip_serializing_if = "Option::is_none")]
    pub teams: Option<String>,
}

/// Identity extraction result
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityResult {
    pub success: bool,
    pub principal: Option<IdentityPrincipal>,
    pub error: Option<String>,
    pub validation_errors: Vec<ValidationError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_claims: Option<serde_json::Value>,
}

/// Validation error
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidationError {
    pub code: ValidationErrorCode,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

/// Validation error codes
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ValidationErrorCode {
    InvalidSignature,
    Expired,
    InvalidAudience,
    InvalidIssuer,
    MissingClaim,
    InvalidAssertion,
    ReplayDetected,
}

/// Identity Bridge trait
#[async_trait::async_trait]
pub trait IdentityBridge: Send + Sync {
    /// Validate an OIDC JWT
    async fn validate_oidc_token(&self, token: &str) -> Result<IdentityResult, Error>;

    /// Process a SAML assertion
    async fn process_saml_assertion(&self, assertion: &str) -> Result<IdentityResult, Error>;

    /// Refresh JWKS cache
    async fn refresh_jwks(&self) -> Result<(), Error>;
}

/// Create OIDC identity bridge
pub fn create_oidc_bridge(config: OidcConfig) -> impl IdentityBridge;

/// Create SAML identity bridge
pub fn create_saml_bridge(config: SamlConfig) -> impl IdentityBridge;
```

## Token/Claims Mapping

### Standard OIDC Claims

| OIDC Claim | Description | Clawdstrike Mapping |
|------------|-------------|---------------------|
| `sub` | Subject identifier | `identity.id` |
| `iss` | Issuer | `identity.issuer` |
| `aud` | Audience | Validated, not stored |
| `exp` | Expiration | `identity.expiresAt` |
| `iat` | Issued at | Validated for freshness |
| `auth_time` | Authentication time | `identity.authenticatedAt` |
| `nonce` | Replay prevention (links token to session) | Validated against session, not stored |
| `at_hash` | Access token hash (for token binding) | Validated when ID token accompanies access token |
| `c_hash` | Authorization code hash | Validated in authorization code flow |
| `jti` | JWT ID (unique token identifier) | Used for replay detection |
| `email` | Email | `identity.email` |
| `email_verified` | Email verified | `identity.emailVerified` |
| `name` | Full name | `identity.displayName` |
| `amr` | Auth methods | `identity.authMethod` |

### Custom Claims (Enterprise)

| Custom Claim | Typical Source | Clawdstrike Mapping |
|--------------|----------------|---------------------|
| `org_id` / `tenant_id` | Enterprise IdP | `identity.organizationId` |
| `groups` / `roles` | IdP directory | `identity.roles` |
| `teams` | IdP directory | `identity.teams` |
| `department` | HR sync | `identity.attributes.department` |
| `employee_type` | HR sync | `identity.attributes.employeeType` |
| `security_clearance` | Custom | `identity.attributes.securityClearance` |

### SAML Attribute Examples

```xml
<saml:Attribute Name="urn:oid:0.9.2342.19200300.100.1.3" FriendlyName="mail">
  <saml:AttributeValue>user@example.com</saml:AttributeValue>
</saml:Attribute>

<saml:Attribute Name="http://schemas.example.com/claims/roles">
  <saml:AttributeValue>engineer</saml:AttributeValue>
  <saml:AttributeValue>deployer</saml:AttributeValue>
</saml:Attribute>

<saml:Attribute Name="http://schemas.example.com/claims/orgId">
  <saml:AttributeValue>org_123456</saml:AttributeValue>
</saml:Attribute>
```

## Multi-Tenancy Considerations

### Issuer Isolation

Each tenant should have a distinct issuer configuration:

```yaml
# Multi-tenant OIDC configuration
identity:
  oidc:
    tenants:
      acme_corp:
        issuer: https://acme.okta.com
        audience: clawdstrike-acme
      globex:
        issuer: https://globex.auth0.com
        audience: clawdstrike-globex

    # Tenant resolution strategy
    tenantResolution:
      # Extract from token claim
      claim: org_id
      # Or from request header
      header: X-Tenant-ID
```

### Organization Boundary Enforcement

```typescript
/**
 * Validate that identity matches expected organization
 */
async function validateOrganizationBoundary(
  identity: IdentityPrincipal,
  expectedOrgId: string
): Promise<boolean> {
  // Strict match - no cross-org access
  if (identity.organizationId !== expectedOrgId) {
    auditLog.warn('Cross-organization access attempt', {
      identityOrg: identity.organizationId,
      requestedOrg: expectedOrgId,
      userId: identity.id,
    });
    return false;
  }
  return true;
}
```

### Tenant-Specific JWKS Caching

```typescript
class MultiTenantJWKSCache {
  private caches = new Map<string, JWKSCache>();

  async getKeys(issuer: string): Promise<JWK[]> {
    let cache = this.caches.get(issuer);
    if (!cache) {
      cache = new JWKSCache(issuer);
      this.caches.set(issuer, cache);
    }
    return cache.getKeys();
  }

  // Isolate cache poisoning to single tenant
  invalidate(issuer: string): void {
    this.caches.delete(issuer);
  }
}
```

## Security Considerations

### Token Validation Checklist

1. **Signature Verification**
   - Fetch keys from JWKS endpoint over HTTPS
   - Validate key ID (`kid`) matches
   - Verify signature algorithm is allowed (RS256, ES256)
   - Reject `none` algorithm

2. **Claims Validation**
   - `iss` matches configured issuer exactly
   - `aud` contains expected audience
   - `exp` is in the future (with clock tolerance)
   - `iat` is in the past
   - `nbf` (if present) is in the past

3. **Security Headers**
   - Reject tokens in URL query parameters
   - Require `Authorization: Bearer` header
   - Validate `Content-Type` for SAML

### Replay Protection

```typescript
interface ReplayProtection {
  /**
   * Check if token/assertion has been seen before
   */
  checkAndStore(
    tokenId: string,  // jti claim or assertion ID
    expiration: Date
  ): Promise<boolean>;

  /**
   * Clean up expired entries
   */
  cleanup(): Promise<void>;
}

// Implementation using Redis
class RedisReplayProtection implements ReplayProtection {
  async checkAndStore(tokenId: string, expiration: Date): Promise<boolean> {
    const key = `replay:${tokenId}`;
    const ttl = Math.ceil((expiration.getTime() - Date.now()) / 1000);

    // SETNX returns 1 if key was set (first time seen)
    const result = await this.redis.setnx(key, '1');
    if (result === 1) {
      await this.redis.expire(key, ttl);
      return true; // New token, not a replay
    }
    return false; // Replay detected
  }
}
```

### Token Binding Validation

For enhanced security, validate token binding claims when present:

```typescript
/**
 * Validate access token hash in ID token
 */
function validateAtHash(idToken: DecodedJWT, accessToken: string): boolean {
  if (!idToken.at_hash) return true; // Not present, skip validation

  const alg = idToken.header.alg;
  const hashAlg = alg.startsWith('RS') || alg.startsWith('PS') ? 'sha256' :
                  alg.startsWith('ES256') ? 'sha256' :
                  alg.startsWith('ES384') ? 'sha384' : 'sha512';

  const hash = crypto.createHash(hashAlg).update(accessToken).digest();
  const halfHash = hash.slice(0, hash.length / 2);
  const expectedAtHash = base64url.encode(halfHash);

  return crypto.timingSafeEqual(
    Buffer.from(idToken.at_hash),
    Buffer.from(expectedAtHash)
  );
}
```

### SAML-Specific Security

1. **XML Signature Validation**
   - Validate signature covers entire assertion
   - Check for XML signature wrapping attacks
   - Validate certificate chain to trusted root

2. **Assertion Conditions**
   - Validate `NotBefore` and `NotOnOrAfter`
   - Validate `Audience` restriction
   - Check `InResponseTo` for solicited assertions

3. **Encryption (if used)**
   - Decrypt with SP private key
   - Validate encrypted assertion signature after decryption

## Configuration Examples

### OIDC with Okta

```yaml
identity:
  oidc:
    issuer: https://dev-123456.okta.com/oauth2/default
    audience: 0oa1234567890abcdef
    jwksUri: https://dev-123456.okta.com/oauth2/default/v1/keys
    clockTolerance: 30
    requiredClaims:
      - email
      - groups
    claimMapping:
      organizationId: org_id
      roles: groups
      teams: teams
```

### OIDC with Auth0

```yaml
identity:
  oidc:
    issuer: https://example.auth0.com/
    audience: https://api.clawdstrike.example.com
    clockTolerance: 60
    claimMapping:
      organizationId: "https://example.com/org_id"
      roles: "https://example.com/roles"
```

### SAML with Azure AD

```yaml
identity:
  saml:
    entityId: https://clawdstrike.example.com/saml
    idpMetadata: https://login.microsoftonline.com/{tenant}/federationmetadata/2007-06/federationmetadata.xml
    acsUrl: https://clawdstrike.example.com/saml/acs
    validateSignature: true
    validateConditions: true
    attributeMapping:
      email: http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress
      displayName: http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name
      roles: http://schemas.microsoft.com/ws/2008/06/identity/claims/groups
```

### Multi-Protocol Configuration

```yaml
identity:
  # Support both OIDC and SAML
  oidc:
    issuer: https://auth.example.com
    audience: clawdstrike
  saml:
    entityId: https://clawdstrike.example.com/saml
    idpMetadata: https://idp.example.com/metadata
    acsUrl: https://clawdstrike.example.com/saml/acs

  # Protocol selection strategy
  protocolSelection:
    # Prefer OIDC if both available
    priority: [oidc, saml]
    # Or detect from token format
    autoDetect: true
```

## Implementation Phases

### Phase 1: OIDC Foundation (2 weeks)
- JWT parsing and validation
- JWKS fetching and caching
- Basic claim extraction
- Integration with `GuardContext`

### Phase 2: SAML Support (2 weeks)
- SAML assertion parsing
- XML signature validation
- Attribute extraction
- IdP metadata handling

### Phase 3: Enterprise Features (2 weeks)
- Multi-tenant isolation
- Replay protection
- Advanced claim mapping
- Token refresh handling

### Phase 4: Hardening (1 week)
- Security audit
- Performance optimization
- Error handling refinement
- Documentation completion

## Testing Strategy

### Unit Tests
- Token validation with various claim combinations
- Signature verification with test keys
- Claim mapping correctness
- Error handling for malformed tokens

### Integration Tests
- End-to-end flow with test IdP
- JWKS cache refresh
- Multi-tenant isolation
- Replay protection

### Security Tests
- Signature bypass attempts
- Algorithm confusion attacks
- Claim injection
- XML signature wrapping (SAML)
- Token replay

## Dependencies

### TypeScript
- `jose`: JWT validation (OIDC)
- `@node-saml/node-saml`: SAML processing
- `xml-crypto`: XML signature validation

### Rust
- `jsonwebtoken`: JWT validation
- `samael`: SAML processing
- `reqwest`: HTTP client for metadata fetching
