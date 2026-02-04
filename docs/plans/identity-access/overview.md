# Identity & Access Management for Clawdstrike/OpenClaw

## Executive Summary

This specification defines the Identity & Access Management (IAM) architecture for Clawdstrike, enabling enterprise-grade security policy enforcement that is aware of user identity, team membership, and organizational context. By integrating identity into the security enforcement layer, organizations can implement fine-grained access controls, audit trails tied to specific users, and dynamic policy scoping based on authentication context.

## Problem Statement

### Current Limitations

Today, Clawdstrike enforces security policies uniformly across all users and contexts:

1. **No User Attribution**: Guard violations and audit logs lack user identity information, making incident investigation difficult
2. **Uniform Policies**: The same policy applies to all users regardless of role, team, or trust level
3. **No Session Binding**: Actions cannot be correlated across a user's session for behavioral analysis
4. **Missing Organizational Context**: Multi-tenant deployments cannot scope policies by organization
5. **No Authentication Integration**: External identity providers (Okta, Auth0, Azure AD) cannot inform policy decisions

### Business Drivers

- **Compliance Requirements**: SOC 2, SOX, HIPAA, and GDPR require user-attributable audit trails
- **Least Privilege**: Different users need different levels of access to tools and resources
- **Incident Response**: Security teams need to trace actions to specific users
- **Multi-Tenancy**: SaaS deployments require tenant isolation at the policy level
- **Zero Trust**: Modern security architectures require identity verification at every decision point

## Use Cases

### UC-1: Role-Based Tool Access
A senior engineer can execute deployment tools, while a junior engineer cannot. The policy engine evaluates the user's roles from their identity token to make this decision.

### UC-2: Team-Scoped File Access
The payments team can access payment service files, while the marketing team cannot. Policy rules reference team membership from identity claims.

### UC-3: Organization Isolation
In a multi-tenant SaaS deployment, Org A's policies are completely isolated from Org B's. Each organization can customize their own policies within their tenant boundary.

### UC-4: User-Attributable Audit
Every security decision is logged with the authenticated user's identity, enabling compliance reporting and forensic analysis.

### UC-5: Session-Based Rate Limiting
Individual users can be rate-limited on sensitive operations (e.g., maximum 10 deployments per day) using session-bound identity context.

### UC-6: Dynamic Policy Escalation
A user's policy strictness can be dynamically adjusted based on their authentication context (e.g., VPN vs public internet, MFA vs password-only).

## Architecture Overview

```
+------------------+     +-------------------+     +------------------+
|                  |     |                   |     |                  |
|  Identity        |     |   Clawdstrike     |     |   Policy         |
|  Provider        +---->+   Identity        +---->+   Engine         |
|  (Okta/Auth0/    |     |   Bridge          |     |                  |
|   OIDC/SAML)     |     |                   |     |                  |
|                  |     +--------+----------+     +--------+---------+
+------------------+              |                         |
                                  v                         v
                        +---------+----------+    +---------+---------+
                        |                    |    |                   |
                        |  Session Context   |    |  Guard Context    |
                        |  Store             |    |  (Enhanced)       |
                        |                    |    |                   |
                        +--------------------+    +-------------------+
```

### Core Components

1. **Identity Bridge**: Validates tokens, extracts claims, and normalizes identity data
2. **Session Context Store**: Maintains identity context for the duration of a session
3. **Enhanced Guard Context**: Extends `GuardContext` with identity information
4. **Policy Scoping Engine**: Resolves which policies apply based on identity

## Data Model

### Identity Principal

```typescript
interface IdentityPrincipal {
  /** Unique identifier (sub claim in OIDC) */
  id: string;

  /** Identity provider type */
  provider: 'oidc' | 'saml' | 'okta' | 'auth0' | 'azure_ad' | 'custom';

  /** Provider-specific issuer URL */
  issuer: string;

  /** Display name */
  displayName?: string;

  /** Email address */
  email?: string;

  /** Email verification status */
  emailVerified?: boolean;

  /** Organization/tenant identifier */
  organizationId?: string;

  /** Team memberships */
  teams?: string[];

  /** Assigned roles */
  roles?: string[];

  /** Custom attributes from IdP */
  attributes?: Record<string, unknown>;

  /** Authentication timestamp */
  authenticatedAt: string;

  /** Authentication method used */
  authMethod?: 'password' | 'mfa' | 'sso' | 'certificate';

  /** Token expiration */
  expiresAt?: string;
}
```

### Identity Principal (Rust)

```rust
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Identity principal representing an authenticated user
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityPrincipal {
    /// Unique identifier (sub claim in OIDC)
    pub id: String,

    /// Identity provider type
    pub provider: IdentityProvider,

    /// Provider-specific issuer URL
    pub issuer: String,

    /// Display name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,

    /// Email address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,

    /// Email verification status
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,

    /// Organization/tenant identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,

    /// Team memberships
    #[serde(default)]
    pub teams: Vec<String>,

    /// Assigned roles
    #[serde(default)]
    pub roles: Vec<String>,

    /// Custom attributes from IdP
    #[serde(default)]
    pub attributes: HashMap<String, serde_json::Value>,

    /// Authentication timestamp (ISO 8601)
    pub authenticated_at: String,

    /// Authentication method used
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_method: Option<AuthMethod>,

    /// Token expiration (ISO 8601)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

/// Identity provider types
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityProvider {
    Oidc,
    Saml,
    Okta,
    Auth0,
    AzureAd,
    Custom,
}

/// Authentication methods
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    Password,
    Mfa,
    Sso,
    Certificate,
}
```

### Enhanced Guard Context

```typescript
interface EnhancedGuardContext extends GuardContext {
  /** Authenticated identity */
  identity?: IdentityPrincipal;

  /** Session identifier (bound to identity) */
  sessionId?: string;

  /** Organization context */
  organization?: {
    id: string;
    name: string;
    tier: 'free' | 'pro' | 'enterprise';
  };

  /** Request context */
  request?: {
    sourceIp?: string;
    userAgent?: string;
    geoLocation?: string;
    isVpn?: boolean;
  };
}
```

### Enhanced Guard Context (Rust)

```rust
/// Enhanced guard context with identity information
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EnhancedGuardContext {
    /// Authenticated identity
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<IdentityPrincipal>,

    /// Session identifier (bound to identity)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,

    /// Organization context
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<OrganizationContext>,

    /// Request context
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<RequestContext>,
}

/// Organization context
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrganizationContext {
    pub id: String,
    pub name: String,
    pub tier: OrganizationTier,
}

/// Organization tier levels
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OrganizationTier {
    Free,
    Pro,
    Enterprise,
}

/// Request context for security decisions
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geo_location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_vpn: Option<bool>,
}
```

## Integration Points

### Token Flow

1. User authenticates with Identity Provider
2. IdP issues JWT (OIDC) or SAML assertion
3. Application passes token to Clawdstrike Identity Bridge
4. Bridge validates token (signature, expiration, audience)
5. Bridge extracts and normalizes claims
6. Identity context is attached to Guard Context
7. Policy engine evaluates rules with identity awareness
8. Audit logs include identity attribution

### Claim Mapping

| IdP Claim | Clawdstrike Field | Description |
|-----------|-------------------|-------------|
| `sub` | `identity.id` | Unique user identifier |
| `email` | `identity.email` | User email |
| `name` | `identity.displayName` | Display name |
| `org_id` / `tenant_id` | `identity.organizationId` | Organization |
| `groups` / `roles` | `identity.roles` | Role assignments |
| `teams` | `identity.teams` | Team memberships |
| `auth_time` | `identity.authenticatedAt` | Auth timestamp |
| `amr` | `identity.authMethod` | Auth method reference |

## Security Considerations

### Token Validation

- **Signature Verification**: All tokens must be cryptographically validated against IdP public keys
  - Reject `alg: none` tokens
  - Only accept configured algorithms (RS256, ES256, etc.)
  - Validate key ID (`kid`) matches JWKS keys
- **Issuer Validation**: Only configured issuers are accepted (exact string match)
- **Audience Validation**: Tokens must be issued for Clawdstrike's audience (`aud` claim)
- **Expiration Checking**: Expired tokens are rejected with configurable clock skew tolerance
- **Replay Protection**: Multiple layers of protection:
  - `jti` (JWT ID) tracking to detect reused tokens
  - `nonce` validation for OIDC flows
  - `at_hash` validation when ID token accompanies access token
  - Short-lived tokens with refresh token rotation

### Session Security

- **Session Fixation Prevention**: Rotate session ID after authentication
- **Session Binding**: Optionally bind sessions to client characteristics (user agent, IP)
- **Idle Timeout**: Terminate sessions after period of inactivity
- **Absolute Timeout**: Maximum session lifetime regardless of activity
- **CSRF Protection**: Double-submit cookies or synchronizer tokens for state-changing operations

### Privilege Boundaries

- Identity claims are immutable within a session
- Role/team claims cannot be elevated by the user
- Organization boundaries are strictly enforced
- Policy inheritance cannot cross organization boundaries
- Lower-scoped policies cannot grant more permissions than parent policies

### Audit Requirements

- All identity-aware decisions must be logged
- Logs must include identity principal information
- Failed authentication attempts must be recorded
- Token validation failures must be alerted
- Session lifecycle events (create, access, terminate) must be audited

## Implementation Phases

### Phase 1: Foundation (v1.1)
- Enhanced `GuardContext` with identity fields
- Basic JWT validation library integration
- Identity-attributed audit logging
- TypeScript SDK implementation

### Phase 2: IdP Integration (v1.2)
- OIDC standard integration
- SAML 2.0 support
- Okta-specific connector
- Auth0-specific connector

### Phase 3: Policy Scoping (v1.3)
- Role-based policy conditions
- Team-based policy scoping
- Organization tenant isolation
- Dynamic policy resolution

### Phase 4: Advanced Features (v1.4)
- Session context persistence
- Cross-service identity propagation
- Identity-based rate limiting
- Behavioral analytics integration

## Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Token validation latency | < 5ms (cached) | P99 latency |
| Identity coverage in audit logs | 100% | % of logs with identity |
| IdP integration time | < 1 day | Time to first token validation |
| Policy scoping accuracy | 100% | Correct policy resolution rate |

## Dependencies

- `jsonwebtoken` / `jose`: JWT validation
- `xml-crypto`: SAML signature verification
- `jwks-rsa`: JWKS key fetching
- `hush-core`: Base types and signing

## Related Documents

- [OIDC/SAML Integration](./oidc-saml.md)
- [Okta and Auth0 Integration](./okta-auth0.md)
- [Role-Based Access Control](./rbac.md)
- [Session Context Flow](./session-context.md)
- [Policy Scoping](./policy-scoping.md)
