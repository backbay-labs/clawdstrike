# Okta and Auth0 Integration for Clawdstrike

## Problem Statement

While Clawdstrike supports generic OIDC integration, enterprise customers predominantly use Okta and Auth0 as their identity providers. These platforms have specific features, claim structures, and best practices that require dedicated integration support:

1. **Platform-Specific Claims**: Okta and Auth0 use different claim names and structures for roles, groups, and custom attributes
2. **Organization Features**: Both platforms have multi-tenant/organization features that map to Clawdstrike's policy scoping
3. **Webhooks and Events**: Real-time user deprovisioning requires webhook integration
4. **Management APIs**: Admin operations require platform-specific API integration
5. **Session Management**: Platform-specific session lifecycle handling

## Use Cases

### UC-OKTA-1: Okta Groups to Policy Roles
An organization uses Okta groups to manage access. The `payments-team` Okta group maps to the `payments` policy scope, granting access to payment service files.

### UC-OKTA-2: Okta Organizations for Multi-Tenancy
A SaaS provider uses Okta Organizations to manage their customers. Each Okta Org maps to a Clawdstrike tenant with isolated policies.

### UC-OKTA-3: Okta User Deprovisioning
When a user is deprovisioned in Okta, a webhook notifies Clawdstrike to invalidate all active sessions for that user.

### UC-AUTH0-1: Auth0 Roles and Permissions
Auth0 RBAC is used to manage fine-grained permissions. Auth0 permissions map to Clawdstrike guard allowlists.

### UC-AUTH0-2: Auth0 Organizations
A B2B SaaS uses Auth0 Organizations to manage customer tenants. Each Auth0 org maps to isolated Clawdstrike policies.

### UC-AUTH0-3: Auth0 Actions for Custom Claims
Auth0 Actions inject custom claims (e.g., `security_level`, `department`) that Clawdstrike uses for policy decisions.

## Architecture

### Okta Integration Architecture

```
+------------------+     +-------------------+     +------------------+
|                  |     |                   |     |                  |
|  Okta            |     |   Clawdstrike     |     |   Policy         |
|  Authorization   +---->+   Okta Adapter    +---->+   Engine         |
|  Server          |     |                   |     |                  |
+--------+---------+     +--------+----------+     +------------------+
         |                        |
         | JWT with               | Normalized
         | Okta claims            | Identity
         v                        v
+--------+---------+     +--------+----------+
|                  |     |                   |
|  Okta Groups     |     |  Session Store    |
|  & Attributes    |     |  (Redis/Memory)   |
|                  |     |                   |
+--------+---------+     +-------------------+
         |
         | Webhook
         v
+--------+---------+
|                  |
|  Okta System Log |
|  Event Hooks     |
|                  |
+------------------+
```

### Auth0 Integration Architecture

```
+------------------+     +-------------------+     +------------------+
|                  |     |                   |     |                  |
|  Auth0           |     |   Clawdstrike     |     |   Policy         |
|  Authorization   +---->+   Auth0 Adapter   +---->+   Engine         |
|  Server          |     |                   |     |                  |
+--------+---------+     +--------+----------+     +------------------+
         |                        |
         | JWT with               | Normalized
         | Auth0 claims           | Identity
         v                        v
+--------+---------+     +--------+----------+
|                  |     |                   |
|  Auth0 RBAC      |     |  Org Context      |
|  Roles/Perms     |     |  Resolution       |
|                  |     |                   |
+--------+---------+     +-------------------+
         |
         | Log Stream
         v
+--------+---------+
|                  |
|  Auth0 Log       |
|  Streams/Hooks   |
|                  |
+------------------+
```

## API Design

### TypeScript SDK - Okta

```typescript
/**
 * Okta-specific configuration
 */
export interface OktaConfig {
  /** Okta domain (e.g., 'dev-123456.okta.com') */
  domain: string;

  /** Authorization Server ID (default: 'default') */
  authorizationServerId?: string;

  /** Client ID for token validation */
  clientId: string;

  /** Client secret for Management API (optional) */
  clientSecret?: string;

  /** API token for Management API (optional) */
  apiToken?: string;

  /** Group to role mapping */
  groupMapping?: OktaGroupMapping;

  /** Webhook configuration */
  webhooks?: OktaWebhookConfig;

  /** Session configuration */
  session?: OktaSessionConfig;
}

/**
 * Okta group to Clawdstrike role mapping
 */
export interface OktaGroupMapping {
  /** Direct group name to role mapping */
  direct?: Record<string, string[]>;

  /** Pattern-based mapping (group pattern -> roles) */
  patterns?: Array<{
    /** Group name pattern (glob or regex) */
    pattern: string;
    /** Roles to assign */
    roles: string[];
    /** Whether pattern is regex */
    isRegex?: boolean;
  }>;

  /** Whether to include all groups as roles */
  includeAllGroups?: boolean;

  /** Prefix for auto-generated role names from groups */
  rolePrefix?: string;
}

/**
 * Okta webhook configuration
 */
export interface OktaWebhookConfig {
  /** Webhook verification key */
  verificationKey: string;

  /** Events to handle */
  events: OktaEventType[];

  /** Endpoint path for webhook receiver */
  endpointPath?: string;
}

/**
 * Okta event types for webhooks
 */
export type OktaEventType =
  | 'user.lifecycle.deactivate'
  | 'user.lifecycle.suspend'
  | 'user.lifecycle.delete.initiated'
  | 'user.session.end'
  | 'user.mfa.factor.deactivate'
  | 'group.user_membership.remove'
  | 'group.user_membership.add';

/**
 * Okta session configuration
 */
export interface OktaSessionConfig {
  /** Whether to validate session is still active with Okta */
  validateActiveSession?: boolean;

  /** Session check interval in seconds */
  sessionCheckInterval?: number;

  /** Whether to respect Okta session timeout */
  respectOktaTimeout?: boolean;
}

/**
 * Okta identity adapter
 */
export interface OktaAdapter {
  /**
   * Validate Okta access token
   */
  validateToken(token: string): Promise<OktaIdentityResult>;

  /**
   * Get user's Okta groups
   */
  getUserGroups(userId: string): Promise<string[]>;

  /**
   * Check if user session is active in Okta
   */
  isSessionActive(userId: string, sessionId?: string): Promise<boolean>;

  /**
   * Handle Okta webhook event
   */
  handleWebhook(event: OktaWebhookEvent): Promise<void>;

  /**
   * Revoke all sessions for user
   */
  revokeUserSessions(userId: string): Promise<void>;
}

/**
 * Okta identity result with platform-specific data
 */
export interface OktaIdentityResult extends IdentityResult {
  /** Okta-specific user data */
  oktaUser?: {
    /** Okta user ID */
    id: string;
    /** User status in Okta */
    status: 'ACTIVE' | 'PROVISIONED' | 'DEPROVISIONED' | 'SUSPENDED';
    /** Okta groups */
    groups: string[];
    /** Last login timestamp */
    lastLogin?: string;
    /** User profile */
    profile: Record<string, unknown>;
  };
}

/**
 * Create Okta adapter
 */
export function createOktaAdapter(config: OktaConfig): OktaAdapter;
```

### TypeScript SDK - Auth0

```typescript
/**
 * Auth0-specific configuration
 */
export interface Auth0Config {
  /** Auth0 domain (e.g., 'example.auth0.com') */
  domain: string;

  /** API audience */
  audience: string;

  /** Client ID for token validation */
  clientId: string;

  /** Client secret for Management API (optional) */
  clientSecret?: string;

  /** Management API audience (optional) */
  managementAudience?: string;

  /** RBAC configuration */
  rbac?: Auth0RBACConfig;

  /** Organization configuration */
  organizations?: Auth0OrganizationConfig;

  /** Log stream configuration */
  logStream?: Auth0LogStreamConfig;
}

/**
 * Auth0 RBAC configuration
 */
export interface Auth0RBACConfig {
  /** Whether to use Auth0 RBAC */
  enabled: boolean;

  /** Permission namespace in token */
  permissionsClaim?: string;

  /** Roles namespace in token */
  rolesClaim?: string;

  /** Permission to Clawdstrike guard mapping */
  permissionMapping?: Record<string, GuardPermission>;

  /** Role to policy scope mapping */
  roleMapping?: Record<string, string[]>;
}

/**
 * Guard permission from Auth0 permission
 */
export interface GuardPermission {
  /** Guard name */
  guard: string;
  /** Action allowed */
  action: 'allow' | 'deny' | 'warn';
  /** Scope (optional) */
  scope?: string;
}

/**
 * Auth0 organization configuration
 */
export interface Auth0OrganizationConfig {
  /** Whether to use Auth0 Organizations */
  enabled: boolean;

  /** Organization claim in token */
  orgIdClaim?: string;

  /** Organization name claim */
  orgNameClaim?: string;

  /** Per-organization policy overrides */
  policyOverrides?: Record<string, Partial<Policy>>;

  /** Default policy for organizations */
  defaultPolicy?: string;
}

/**
 * Auth0 log stream configuration
 */
export interface Auth0LogStreamConfig {
  /** Log stream type */
  type: 'webhook' | 'eventbridge' | 'datadog';

  /** Webhook endpoint (if webhook type) */
  webhookEndpoint?: string;

  /** Webhook authorization header */
  webhookAuthorization?: string;

  /** Events to subscribe to */
  events?: Auth0EventType[];
}

/**
 * Auth0 event types
 */
export type Auth0EventType =
  | 'ss'   // Success silent auth
  | 's'    // Success login
  | 'f'    // Failed login
  | 'du'   // Deleted user
  | 'slo'  // Success logout
  | 'sui'  // Success user import
  | 'sce'  // Success change email
  | 'scp'  // Success change password
  | 'limit_mu'  // Too many login attempts
  | 'limit_wc'; // Too many auth attempts

/**
 * Auth0 identity adapter
 */
export interface Auth0Adapter {
  /**
   * Validate Auth0 access token
   */
  validateToken(token: string): Promise<Auth0IdentityResult>;

  /**
   * Get user's Auth0 roles
   */
  getUserRoles(userId: string): Promise<string[]>;

  /**
   * Get user's Auth0 permissions
   */
  getUserPermissions(userId: string): Promise<string[]>;

  /**
   * Get organization details
   */
  getOrganization(orgId: string): Promise<Auth0Organization>;

  /**
   * Handle Auth0 log stream event
   */
  handleLogStreamEvent(event: Auth0LogEvent): Promise<void>;

  /**
   * Check if user is member of organization
   */
  isOrgMember(userId: string, orgId: string): Promise<boolean>;
}

/**
 * Auth0 identity result with platform-specific data
 */
export interface Auth0IdentityResult extends IdentityResult {
  /** Auth0-specific user data */
  auth0User?: {
    /** Auth0 user ID */
    userId: string;
    /** Roles from RBAC */
    roles: string[];
    /** Permissions from RBAC */
    permissions: string[];
    /** Organization membership */
    organization?: Auth0Organization;
    /** App metadata */
    appMetadata?: Record<string, unknown>;
    /** User metadata */
    userMetadata?: Record<string, unknown>;
  };
}

/**
 * Auth0 organization data
 */
export interface Auth0Organization {
  /** Organization ID */
  id: string;
  /** Organization name */
  name: string;
  /** Display name */
  displayName?: string;
  /** Organization metadata */
  metadata?: Record<string, unknown>;
  /** Branding */
  branding?: {
    logoUrl?: string;
    colors?: Record<string, string>;
  };
}

/**
 * Create Auth0 adapter
 */
export function createAuth0Adapter(config: Auth0Config): Auth0Adapter;
```

### Rust SDK

```rust
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Okta configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OktaConfig {
    /// Okta domain
    pub domain: String,

    /// Authorization server ID
    #[serde(default = "default_auth_server")]
    pub authorization_server_id: String,

    /// Client ID
    pub client_id: String,

    /// API token for management API
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_token: Option<String>,

    /// Group mapping configuration
    #[serde(default)]
    pub group_mapping: OktaGroupMapping,

    /// Session configuration
    #[serde(default)]
    pub session: OktaSessionConfig,
}

fn default_auth_server() -> String {
    "default".to_string()
}

/// Okta group mapping
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OktaGroupMapping {
    /// Direct group to role mapping
    #[serde(default)]
    pub direct: HashMap<String, Vec<String>>,

    /// Pattern-based mapping
    #[serde(default)]
    pub patterns: Vec<GroupPattern>,

    /// Include all groups as roles
    #[serde(default)]
    pub include_all_groups: bool,

    /// Role prefix for auto-generated roles
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role_prefix: Option<String>,
}

/// Group pattern for role mapping
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupPattern {
    pub pattern: String,
    pub roles: Vec<String>,
    #[serde(default)]
    pub is_regex: bool,
}

/// Okta session configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OktaSessionConfig {
    /// Validate active session with Okta
    #[serde(default)]
    pub validate_active_session: bool,

    /// Session check interval in seconds
    #[serde(default = "default_session_check")]
    pub session_check_interval_secs: u64,

    /// Respect Okta session timeout
    #[serde(default = "default_true")]
    pub respect_okta_timeout: bool,
}

fn default_session_check() -> u64 { 300 }
fn default_true() -> bool { true }

impl Default for OktaSessionConfig {
    fn default() -> Self {
        Self {
            validate_active_session: false,
            session_check_interval_secs: default_session_check(),
            respect_okta_timeout: true,
        }
    }
}

/// Auth0 configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Auth0Config {
    /// Auth0 domain
    pub domain: String,

    /// API audience
    pub audience: String,

    /// Client ID
    pub client_id: String,

    /// Client secret
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,

    /// RBAC configuration
    #[serde(default)]
    pub rbac: Auth0RbacConfig,

    /// Organization configuration
    #[serde(default)]
    pub organizations: Auth0OrgConfig,
}

/// Auth0 RBAC configuration
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Auth0RbacConfig {
    /// Enable RBAC
    #[serde(default)]
    pub enabled: bool,

    /// Permissions claim
    #[serde(default = "default_permissions_claim")]
    pub permissions_claim: String,

    /// Roles claim
    #[serde(default = "default_roles_claim")]
    pub roles_claim: String,

    /// Permission to guard mapping
    #[serde(default)]
    pub permission_mapping: HashMap<String, GuardPermission>,

    /// Role to policy scope mapping
    #[serde(default)]
    pub role_mapping: HashMap<String, Vec<String>>,
}

fn default_permissions_claim() -> String {
    "permissions".to_string()
}

fn default_roles_claim() -> String {
    // NOTE: This MUST be customized per deployment. Auth0 requires namespaced
    // custom claims using a domain you control.
    // Example: "https://your-company.com/roles"
    "https://clawdstrike.example.com/roles".to_string()
}

/// Guard permission
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardPermission {
    pub guard: String,
    pub action: PermissionAction,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// Permission action
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PermissionAction {
    Allow,
    Deny,
    Warn,
}

/// Auth0 organization configuration
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Auth0OrgConfig {
    /// Enable organizations
    #[serde(default)]
    pub enabled: bool,

    /// Org ID claim
    #[serde(default = "default_org_id_claim")]
    pub org_id_claim: String,

    /// Org name claim
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_name_claim: Option<String>,

    /// Default policy for orgs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_policy: Option<String>,
}

fn default_org_id_claim() -> String {
    "org_id".to_string()
}

/// Okta identity adapter trait
#[async_trait::async_trait]
pub trait OktaAdapter: Send + Sync {
    async fn validate_token(&self, token: &str) -> Result<OktaIdentityResult, Error>;
    async fn get_user_groups(&self, user_id: &str) -> Result<Vec<String>, Error>;
    async fn is_session_active(&self, user_id: &str, session_id: Option<&str>) -> Result<bool, Error>;
    async fn revoke_user_sessions(&self, user_id: &str) -> Result<(), Error>;
}

/// Auth0 identity adapter trait
#[async_trait::async_trait]
pub trait Auth0Adapter: Send + Sync {
    async fn validate_token(&self, token: &str) -> Result<Auth0IdentityResult, Error>;
    async fn get_user_roles(&self, user_id: &str) -> Result<Vec<String>, Error>;
    async fn get_user_permissions(&self, user_id: &str) -> Result<Vec<String>, Error>;
    async fn is_org_member(&self, user_id: &str, org_id: &str) -> Result<bool, Error>;
}

/// Create Okta adapter
pub fn create_okta_adapter(config: OktaConfig) -> impl OktaAdapter;

/// Create Auth0 adapter
pub fn create_auth0_adapter(config: Auth0Config) -> impl Auth0Adapter;
```

## Token/Claims Mapping

### Okta Claims

| Okta Claim | Description | Clawdstrike Mapping |
|------------|-------------|---------------------|
| `sub` | User ID | `identity.id` |
| `email` | Email | `identity.email` |
| `email_verified` | Verified flag | `identity.emailVerified` |
| `name` | Display name | `identity.displayName` |
| `groups` | Group memberships | `identity.roles` (after mapping) |
| `org_id` | Okta Org ID | `identity.organizationId` |
| `auth_time` | Auth timestamp | `identity.authenticatedAt` |
| `amr` | Auth method | `identity.authMethod` |

#### Okta Custom Claims (via Authorization Server)

```javascript
// Okta token customization rule example
const customClaims = {
  department: user.profile.department,
  cost_center: user.profile.costCenter,
  manager_id: user.profile.managerId,
  security_clearance: user.profile.securityClearance,
};
```

### Auth0 Claims

| Auth0 Claim | Description | Clawdstrike Mapping |
|-------------|-------------|---------------------|
| `sub` | User ID | `identity.id` |
| `email` | Email | `identity.email` |
| `email_verified` | Verified flag | `identity.emailVerified` |
| `name` | Display name | `identity.displayName` |
| `permissions` | RBAC permissions | `identity.attributes.permissions` |
| `org_id` | Organization ID | `identity.organizationId` |
| `org_name` | Organization name | `identity.attributes.orgName` |

#### Auth0 Custom Claims (via Actions)

```javascript
// Auth0 Action example
exports.onExecutePostLogin = async (event, api) => {
  const namespace = 'https://clawdstrike.example.com/';

  api.accessToken.setCustomClaim(`${namespace}roles`, event.authorization?.roles || []);
  api.accessToken.setCustomClaim(`${namespace}permissions`, event.authorization?.permissions || []);
  api.accessToken.setCustomClaim(`${namespace}department`, event.user.user_metadata?.department);
  api.accessToken.setCustomClaim(`${namespace}security_level`, event.user.app_metadata?.security_level || 'standard');
};
```

## Multi-Tenancy Considerations

### Okta Organizations

```yaml
# Configuration for Okta Org-based multi-tenancy
identity:
  okta:
    # Parent org for management
    managementDomain: admin.example.okta.com
    managementApiToken: ${OKTA_ADMIN_API_TOKEN}

    # Child org configurations
    childOrgs:
      acme_corp:
        domain: acme.okta.com
        clientId: 0oa123...
        policies:
          extends: strict
          guards:
            egress_allowlist:
              additional_allow:
                - "*.acme.com"

      globex:
        domain: globex.okta.com
        clientId: 0oa456...
        policies:
          extends: default

    # Org resolution from token
    orgResolution:
      claim: org_id
      # Or domain-based
      domainMapping:
        acme.okta.com: acme_corp
        globex.okta.com: globex
```

### Auth0 Organizations

```yaml
# Configuration for Auth0 Organizations multi-tenancy
identity:
  auth0:
    domain: example.auth0.com
    audience: https://api.clawdstrike.example.com

    organizations:
      enabled: true

      # Extract org from token
      orgIdClaim: org_id
      orgNameClaim: org_name

      # Per-org policy configuration
      policyByOrg:
        org_acme:
          extends: strict
          guards:
            forbidden_path:
              additional_patterns:
                - "**/acme-secrets/**"

        org_globex:
          extends: default

      # Default for unknown orgs
      defaultPolicy: minimal

      # Org metadata to policy mapping
      tierPolicies:
        free: minimal
        pro: default
        enterprise: strict
```

### Cross-Tenant Isolation

```typescript
/**
 * Ensure strict tenant isolation
 */
class TenantIsolation {
  private sessionOrgMap = new Map<string, string>();

  bindSessionToOrg(sessionId: string, orgId: string): void {
    const existing = this.sessionOrgMap.get(sessionId);
    if (existing && existing !== orgId) {
      throw new SecurityError('Session already bound to different organization');
    }
    this.sessionOrgMap.set(sessionId, orgId);
  }

  validateOrgAccess(sessionId: string, requestedOrgId: string): boolean {
    const boundOrg = this.sessionOrgMap.get(sessionId);
    return boundOrg === requestedOrgId;
  }
}
```

## Security Considerations

### Okta-Specific Security

1. **Token Binding**
   - Validate `cid` (client ID) matches configured client
   - Validate `aud` contains the configured audience
   - Check `scp` (scopes) include required scopes

2. **Session Validation**
   - Optionally validate session is still active via Okta API
   - Handle session revocation webhooks
   - Respect Okta's `session_idle_timeout`

3. **Group Claim Security**
   - Only trust groups from token, not user-supplied
   - Validate group membership hasn't been revoked
   - Rate limit group membership checks

### Auth0-Specific Security

1. **Namespace Isolation**
   - Custom claims must use registered namespace (e.g., `https://your-domain.com/`)
   - Reject tokens with unnamespaced custom claims (Auth0 strips these by default)
   - Validate namespace matches expected value for your deployment

2. **Authorized Party Validation**
   - Validate `azp` (authorized party) claim when multiple audiences are present
   - Ensure the client that requested the token is authorized
   ```typescript
   if (token.aud && Array.isArray(token.aud) && token.aud.length > 1) {
     if (!config.authorizedParties.includes(token.azp)) {
       throw new Error('Unauthorized party');
     }
   }
   ```

3. **Organization Security**
   - Validate org membership for every request
   - Handle org removal via log streams
   - Prevent org ID spoofing by validating against Auth0 Management API

4. **RBAC Validation**
   - Validate permissions are from authorized sources
   - Don't trust client-side permission lists
   - Audit permission usage

### Webhook Security

```typescript
/**
 * Okta Event Hook verification
 * Okta uses a verification challenge for initial setup, then sends signed events
 */
interface OktaEventHookVerification {
  /**
   * Handle Okta's one-time verification challenge
   * Okta sends: {"verification": "challenge-string"}
   * You must respond with: {"verification": "challenge-string"}
   */
  handleVerificationChallenge(body: { verification: string }): { verification: string };

  /**
   * Verify event hook signature using Okta's signing key
   * Header: x-okta-verification-challenge (for initial setup)
   * Header: authorization (Bearer token for events)
   */
  verifyEventSignature(
    authHeader: string,
    expectedToken: string
  ): boolean;
}

/**
 * Okta Event Hook signature verification
 * Okta sends events with an Authorization header containing a verification token
 */
function verifyOktaEventHook(
  authHeader: string,
  expectedToken: string
): boolean {
  // Okta sends: "Bearer <your-configured-token>"
  const [scheme, token] = authHeader.split(' ');
  if (scheme !== 'Bearer') return false;

  return crypto.timingSafeEqual(
    Buffer.from(token),
    Buffer.from(expectedToken)
  );
}

/**
 * Legacy Okta System Log webhook verification (deprecated)
 * For older integrations using HMAC signatures
 */
function verifyOktaWebhookLegacy(
  payload: string,
  signature: string,
  key: string
): boolean {
  const hmac = crypto.createHmac('sha256', key);
  hmac.update(payload);
  const expected = hmac.digest('base64');
  return crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(expected)
  );
}

/**
 * Auth0 log stream signature verification
 */
function verifyAuth0LogStream(
  payload: string,
  authorization: string,
  expectedToken: string
): boolean {
  // Auth0 uses Bearer token authorization
  const [scheme, token] = authorization.split(' ');
  if (scheme !== 'Bearer') return false;
  return crypto.timingSafeEqual(
    Buffer.from(token),
    Buffer.from(expectedToken)
  );
}
```

## Configuration Examples

### Complete Okta Configuration

```yaml
identity:
  provider: okta
  okta:
    domain: dev-123456.okta.com
    authorizationServerId: default
    clientId: 0oa1234567890abcdef

    # Group to role mapping
    groupMapping:
      direct:
        "Engineering": ["engineer", "deployer"]
        "Security": ["security-admin", "auditor"]
        "Ops": ["operator", "deployer"]
      patterns:
        - pattern: "team-*"
          roles: ["team-member"]
        - pattern: "project-*-admin"
          roles: ["project-admin"]
          isRegex: false
      includeAllGroups: false
      rolePrefix: "okta:"

    # Session handling
    session:
      validateActiveSession: true
      sessionCheckInterval: 300
      respectOktaTimeout: true

    # Webhook configuration (optional)
    webhooks:
      verificationKey: ${OKTA_WEBHOOK_KEY}
      events:
        - user.lifecycle.deactivate
        - user.lifecycle.suspend
        - user.session.end
        - group.user_membership.remove
      endpointPath: /webhooks/okta

    # Claim mapping
    claimMapping:
      groups: groups
      department: department
      securityLevel: security_level
```

### Complete Auth0 Configuration

```yaml
identity:
  provider: auth0
  auth0:
    domain: example.auth0.com
    audience: https://api.clawdstrike.example.com
    clientId: abc123def456

    # RBAC configuration
    rbac:
      enabled: true
      permissionsClaim: permissions
      rolesClaim: "https://clawdstrike.example.com/roles"

      # Permission to guard mapping
      permissionMapping:
        "deploy:production":
          guard: mcp_tool
          action: allow
          scope: deploy
        "file:sensitive":
          guard: forbidden_path
          action: allow
          scope: sensitive-files

      # Role to policy scope mapping
      roleMapping:
        admin: ["admin-policy", "all-access"]
        developer: ["developer-policy"]
        viewer: ["read-only-policy"]

    # Organization support
    organizations:
      enabled: true
      orgIdClaim: org_id
      orgNameClaim: org_name
      defaultPolicy: default

    # Log stream for real-time events
    logStream:
      type: webhook
      webhookEndpoint: /webhooks/auth0
      webhookAuthorization: ${AUTH0_LOG_STREAM_TOKEN}
      events:
        - du  # deleted user
        - slo # logout
        - limit_mu # rate limited
```

### Hybrid Okta + Auth0 Configuration

```yaml
# Support both IdPs (for migration or multi-provider setup)
identity:
  providers:
    - type: okta
      priority: 1
      config:
        domain: example.okta.com
        clientId: okta_client_id

    - type: auth0
      priority: 2
      config:
        domain: example.auth0.com
        audience: https://api.example.com

  # Provider selection
  providerSelection:
    # Detect from token issuer
    autoDetect: true

    # Or use header
    header: X-Identity-Provider

    # Fallback provider
    fallback: okta
```

## Implementation Phases

### Phase 1: Okta Core (2 weeks)
- Token validation with Okta-specific claims
- Group extraction and mapping
- Basic session binding
- Integration tests with Okta developer org

### Phase 2: Auth0 Core (2 weeks)
- Token validation with Auth0 claims
- RBAC integration (roles and permissions)
- Namespace handling
- Integration tests with Auth0 tenant

### Phase 3: Organizations (2 weeks)
- Okta Organizations support
- Auth0 Organizations support
- Per-org policy resolution
- Tenant isolation enforcement

### Phase 4: Webhooks & Events (1 week)
- Okta event hooks handler
- Auth0 log streams handler
- Real-time session invalidation
- Event-driven audit logging

### Phase 5: Management APIs (1 week)
- Okta Management API integration
- Auth0 Management API integration
- Admin operations support
- Bulk user operations

## Testing Strategy

### Unit Tests
- Token parsing with platform-specific claims
- Group/role mapping logic
- Permission resolution
- Webhook signature verification

### Integration Tests
- End-to-end token validation
- Group membership lookup
- Organization resolution
- Session validation

### Platform-Specific Tests

```typescript
describe('Okta Integration', () => {
  it('should validate Okta access token', async () => {
    const adapter = createOktaAdapter(testConfig);
    const result = await adapter.validateToken(oktaTestToken);
    expect(result.success).toBe(true);
    expect(result.principal?.provider).toBe('okta');
  });

  it('should map Okta groups to roles', async () => {
    const adapter = createOktaAdapter({
      ...testConfig,
      groupMapping: {
        direct: { 'Engineering': ['engineer'] }
      }
    });
    const result = await adapter.validateToken(tokenWithEngGroup);
    expect(result.principal?.roles).toContain('engineer');
  });
});

describe('Auth0 Integration', () => {
  it('should validate Auth0 access token', async () => {
    const adapter = createAuth0Adapter(testConfig);
    const result = await adapter.validateToken(auth0TestToken);
    expect(result.success).toBe(true);
    expect(result.principal?.provider).toBe('auth0');
  });

  it('should extract Auth0 permissions', async () => {
    const adapter = createAuth0Adapter({
      ...testConfig,
      rbac: { enabled: true }
    });
    const result = await adapter.validateToken(tokenWithPermissions);
    expect(result.auth0User?.permissions).toContain('read:secrets');
  });
});
```

## Dependencies

### Okta
- `@okta/jwt-verifier`: Official Okta JWT verification
- `@okta/okta-sdk-nodejs`: Management API (optional)

### Auth0
- `jwks-rsa`: JWKS key fetching
- `auth0`: Auth0 Management API client (optional)
- `express-oauth2-jwt-bearer`: Token validation (optional)

### Common
- `jose`: JWT validation
- `crypto`: Webhook signature verification
