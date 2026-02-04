# Session Context: Identity Flow Through Guard Context

## Problem Statement

When an identity is established through OIDC, SAML, or direct IdP integration, that identity information must flow through the entire Clawdstrike execution pipeline:

1. **Guard Evaluation**: Guards need identity to make user-aware decisions
2. **Audit Logging**: All actions must be attributed to the authenticated user
3. **Policy Resolution**: Identity determines which policies apply
4. **Rate Limiting**: Per-user rate limits require identity tracking
5. **Session Correlation**: Related actions must be grouped by session

Currently, `GuardContext` has minimal identity support (`session_id`, `agent_id`), which is insufficient for enterprise identity requirements.

## Use Cases

### UC-SESSION-1: Identity-Aware File Guard
The ForbiddenPathGuard checks if the user has permission to access a specific path. A user with `security-team` role can access `/var/log/security/`, while others cannot.

### UC-SESSION-2: Session-Bound Audit Trail
All actions within a user session are correlated in audit logs. An auditor can query "show me all actions by user X in session Y."

### UC-SESSION-3: Per-User Rate Limiting
Each user is limited to 100 shell commands per hour. The rate limiter tracks usage against the identity principal.

### UC-SESSION-4: Session Timeout Enforcement
When a user's IdP session expires, their Clawdstrike session is also terminated, preventing orphaned sessions with elevated privileges.

### UC-SESSION-5: Cross-Service Identity Propagation
When Clawdstrike makes calls to other services (e.g., audit backend, policy store), the user identity is propagated for proper authorization and attribution.

### UC-SESSION-6: Session Metadata for Analytics
Session context includes metadata (source IP, user agent, geo location) that enables security analytics and anomaly detection.

## Architecture

### Session Lifecycle

```
+------------------+     +-------------------+     +------------------+
|                  |     |                   |     |                  |
|  Application     |     |   Session         |     |   Guard          |
|  (with token)    +---->+   Manager         +---->+   Evaluation     |
|                  | (1) |                   | (4) |                  |
+------------------+     +--------+----------+     +------------------+
                                  |
                                  | (2) Validate
                                  v
                         +--------+---------+
                         |                  |
                         |  Identity        |
                         |  Bridge          |
                         |                  |
                         +--------+---------+
                                  |
                                  | (3) Create Session
                                  v
                         +--------+---------+
                         |                  |
                         |  Session Store   |
                         |  (Redis/Memory)  |
                         |                  |
                         +------------------+
```

1. Application provides token to Session Manager
2. Session Manager validates via Identity Bridge
3. Session is created/retrieved from Session Store
4. Session context is passed to Guard evaluation

### Enhanced Guard Context Flow

```
+------------------+
|                  |
|  SessionContext  |
|                  |
+--------+---------+
         |
         | Enriches
         v
+--------+---------+
|                  |
|  GuardContext    |
|  (Enhanced)      |
|                  |
+--------+---------+
         |
         | Passed to
         v
+--------+---------+     +------------------+     +------------------+
|                  |     |                  |     |                  |
|  ForbiddenPath   |     |  EgressAllowlist |     |  SecretLeak      |
|  Guard           |     |  Guard           |     |  Guard           |
|                  |     |                  |     |                  |
+------------------+     +------------------+     +------------------+
         |                       |                       |
         +------------+----------+-----------+-----------+
                      |
                      v
              +-------+--------+
              |                |
              |  Audit Logger  |
              |  (with identity|
              |   context)     |
              +----------------+
```

## Data Model

### Session Context

```typescript
/**
 * Complete session context
 */
export interface SessionContext {
  /** Unique session identifier */
  sessionId: string;

  /** Authenticated identity */
  identity: IdentityPrincipal;

  /** Session creation time */
  createdAt: string;

  /** Last activity time */
  lastActivityAt: string;

  /** Session expiration */
  expiresAt: string;

  /** Organization context */
  organization?: OrganizationContext;

  /** Effective roles for this session */
  effectiveRoles: string[];

  /** Effective permissions for this session */
  effectivePermissions: string[];

  /** Request context (from current request) */
  request?: RequestContext;

  /** Session metadata */
  metadata?: SessionMetadata;

  /** Session state (custom key-value) */
  state?: Record<string, unknown>;
}

/**
 * Organization context
 */
export interface OrganizationContext {
  /** Organization ID */
  id: string;

  /** Organization name */
  name: string;

  /** Organization tier */
  tier: 'free' | 'pro' | 'enterprise';

  /** Organization settings */
  settings?: Record<string, unknown>;
}

/**
 * Request context (per-request information)
 */
export interface RequestContext {
  /** Request ID */
  requestId: string;

  /** Source IP address */
  sourceIp?: string;

  /** User agent string */
  userAgent?: string;

  /** Geo location (if resolved) */
  geoLocation?: GeoLocation;

  /** Whether request is from VPN */
  isVpn?: boolean;

  /** Whether request is from corporate network */
  isCorporateNetwork?: boolean;

  /** Request timestamp */
  timestamp: string;
}

/**
 * Geo location information
 */
export interface GeoLocation {
  /** Country code (ISO 3166-1 alpha-2) */
  country?: string;

  /** Region/state */
  region?: string;

  /** City */
  city?: string;

  /** Latitude */
  latitude?: number;

  /** Longitude */
  longitude?: number;
}

/**
 * Session metadata
 */
export interface SessionMetadata {
  /** How the session was created */
  authMethod: 'oidc' | 'saml' | 'api_key' | 'service_account';

  /** IdP that authenticated the user */
  idpIssuer?: string;

  /** Original token ID (jti) */
  tokenId?: string;

  /** Parent session ID (for impersonation) */
  parentSessionId?: string;

  /** Tags for categorization */
  tags?: string[];
}

/**
 * Enhanced Guard Context (extends existing GuardContext)
 */
export interface EnhancedGuardContext {
  // Existing fields from GuardContext
  cwd?: string;
  sessionId?: string;
  agentId?: string;
  metadata?: Record<string, unknown>;

  // New identity fields
  identity?: IdentityPrincipal;

  // Full session context
  session?: SessionContext;

  // Organization context
  organization?: OrganizationContext;

  // Request context
  request?: RequestContext;

  // Effective permissions (pre-computed)
  permissions?: string[];

  // Effective roles (pre-computed)
  roles?: string[];
}
```

### Rust Data Model

```rust
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Complete session context
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionContext {
    pub session_id: String,
    pub identity: IdentityPrincipal,
    pub created_at: String,
    pub last_activity_at: String,
    pub expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<OrganizationContext>,
    pub effective_roles: Vec<String>,
    pub effective_permissions: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<RequestContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<SessionMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<HashMap<String, serde_json::Value>>,
}

/// Organization context
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrganizationContext {
    pub id: String,
    pub name: String,
    pub tier: OrganizationTier,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings: Option<serde_json::Value>,
}

/// Organization tier
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OrganizationTier {
    Free,
    Pro,
    Enterprise,
}

/// Request context
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestContext {
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geo_location: Option<GeoLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_vpn: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_corporate_network: Option<bool>,
    pub timestamp: String,
}

/// Geo location
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

/// Session metadata
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

/// Authentication method
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    Oidc,
    Saml,
    ApiKey,
    ServiceAccount,
}

/// Enhanced guard context
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EnhancedGuardContext {
    // Existing fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,

    // New identity fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<IdentityPrincipal>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<OrganizationContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<RequestContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
}
```

## API Design

### TypeScript SDK

```typescript
/**
 * Session Manager interface
 */
export interface SessionManager {
  /**
   * Create a new session from a validated identity
   */
  createSession(
    identity: IdentityPrincipal,
    options?: CreateSessionOptions
  ): Promise<SessionContext>;

  /**
   * Get existing session by ID
   */
  getSession(sessionId: string): Promise<SessionContext | null>;

  /**
   * Update session activity timestamp
   */
  touchSession(sessionId: string): Promise<void>;

  /**
   * Update session state
   */
  updateSessionState(
    sessionId: string,
    updates: Record<string, unknown>
  ): Promise<SessionContext>;

  /**
   * Terminate a session
   */
  terminateSession(sessionId: string, reason?: string): Promise<void>;

  /**
   * Terminate all sessions for a user
   */
  terminateUserSessions(userId: string, reason?: string): Promise<number>;

  /**
   * List active sessions for a user
   */
  listUserSessions(userId: string): Promise<SessionContext[]>;

  /**
   * Create guard context from session
   */
  createGuardContext(
    session: SessionContext,
    request?: RequestContext
  ): EnhancedGuardContext;

  /**
   * Validate session is still valid
   */
  validateSession(sessionId: string): Promise<SessionValidationResult>;
}

/**
 * Session creation options
 */
export interface CreateSessionOptions {
  /** Override default session TTL */
  ttlSeconds?: number;

  /** Initial session state */
  initialState?: Record<string, unknown>;

  /** Session tags */
  tags?: string[];

  /** Request context from initial request */
  request?: RequestContext;

  /** Bind session to specific organization */
  organizationId?: string;
}

/**
 * Session validation result
 */
export interface SessionValidationResult {
  /** Whether session is valid */
  valid: boolean;

  /** Reason if invalid */
  reason?: 'expired' | 'terminated' | 'not_found' | 'identity_revoked';

  /** Session context if valid */
  session?: SessionContext;

  /** Remaining TTL in seconds */
  remainingTtlSeconds?: number;
}

/**
 * Session store interface (for custom implementations)
 */
export interface SessionStore {
  /** Store a session */
  set(session: SessionContext, ttlSeconds: number): Promise<void>;

  /** Retrieve a session */
  get(sessionId: string): Promise<SessionContext | null>;

  /** Delete a session */
  delete(sessionId: string): Promise<boolean>;

  /** Update session fields */
  update(sessionId: string, updates: Partial<SessionContext>): Promise<SessionContext | null>;

  /** List sessions by user ID */
  listByUser(userId: string): Promise<SessionContext[]>;

  /** List sessions by organization ID */
  listByOrganization(orgId: string): Promise<SessionContext[]>;

  /** Clean up expired sessions */
  cleanup(): Promise<number>;
}

/**
 * Create session manager
 */
export function createSessionManager(config: SessionManagerConfig): SessionManager;

/**
 * Session manager configuration
 */
export interface SessionManagerConfig {
  /** Session store implementation */
  store: 'memory' | 'redis' | SessionStore;

  /** Redis configuration (if using Redis) */
  redis?: {
    url: string;
    prefix?: string;
  };

  /** Default session TTL in seconds */
  defaultTtlSeconds: number;

  /** Maximum session TTL in seconds */
  maxTtlSeconds: number;

  /** Session idle timeout in seconds */
  idleTimeoutSeconds?: number;

  /** Whether to validate identity on each request */
  validateIdentityOnRequest: boolean;

  /** RBAC manager for permission resolution */
  rbac?: RBACManager;

  /** Identity bridge for identity validation */
  identityBridge?: IdentityBridge;
}
```

### Rust SDK

```rust
use async_trait::async_trait;

/// Session manager trait
#[async_trait]
pub trait SessionManager: Send + Sync {
    /// Create a new session
    async fn create_session(
        &self,
        identity: IdentityPrincipal,
        options: Option<CreateSessionOptions>,
    ) -> Result<SessionContext, Error>;

    /// Get session by ID
    async fn get_session(&self, session_id: &str) -> Result<Option<SessionContext>, Error>;

    /// Touch session (update last activity)
    async fn touch_session(&self, session_id: &str) -> Result<(), Error>;

    /// Update session state
    async fn update_session_state(
        &self,
        session_id: &str,
        updates: HashMap<String, serde_json::Value>,
    ) -> Result<SessionContext, Error>;

    /// Terminate session
    async fn terminate_session(&self, session_id: &str, reason: Option<&str>) -> Result<(), Error>;

    /// Terminate all sessions for user
    async fn terminate_user_sessions(&self, user_id: &str, reason: Option<&str>) -> Result<u64, Error>;

    /// List user sessions
    async fn list_user_sessions(&self, user_id: &str) -> Result<Vec<SessionContext>, Error>;

    /// Create guard context from session
    fn create_guard_context(
        &self,
        session: &SessionContext,
        request: Option<&RequestContext>,
    ) -> EnhancedGuardContext;

    /// Validate session
    async fn validate_session(&self, session_id: &str) -> Result<SessionValidationResult, Error>;
}

/// Session creation options
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CreateSessionOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_state: Option<HashMap<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<RequestContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
}

/// Session validation result
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionValidationResult {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<InvalidSessionReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_ttl_seconds: Option<u64>,
}

/// Reasons for invalid session
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvalidSessionReason {
    Expired,
    Terminated,
    NotFound,
    IdentityRevoked,
}

/// Session store trait
#[async_trait]
pub trait SessionStore: Send + Sync {
    async fn set(&self, session: SessionContext, ttl_seconds: u64) -> Result<(), Error>;
    async fn get(&self, session_id: &str) -> Result<Option<SessionContext>, Error>;
    async fn delete(&self, session_id: &str) -> Result<bool, Error>;
    async fn update(&self, session_id: &str, updates: SessionUpdates) -> Result<Option<SessionContext>, Error>;
    async fn list_by_user(&self, user_id: &str) -> Result<Vec<SessionContext>, Error>;
    async fn list_by_organization(&self, org_id: &str) -> Result<Vec<SessionContext>, Error>;
    async fn cleanup(&self) -> Result<u64, Error>;
}

/// Create session manager
pub fn create_session_manager(config: SessionManagerConfig) -> impl SessionManager;
```

## Session Lifecycle

### Session Creation Flow

```typescript
async function handleAuthenticatedRequest(
  token: string,
  request: IncomingRequest
): Promise<void> {
  // 1. Validate token and extract identity
  const identityResult = await identityBridge.validateOIDCToken(token);
  if (!identityResult.success) {
    throw new AuthenticationError(identityResult.error);
  }

  // 2. Create or retrieve session
  let session = await sessionManager.getSession(request.sessionId);
  if (!session) {
    session = await sessionManager.createSession(identityResult.principal!, {
      request: extractRequestContext(request),
      organizationId: identityResult.principal!.organizationId,
    });
  } else {
    // Validate existing session matches identity
    if (session.identity.id !== identityResult.principal!.id) {
      throw new SecurityError('Session identity mismatch');
    }
    await sessionManager.touchSession(session.sessionId);
  }

  // 3. Create guard context
  const guardContext = sessionManager.createGuardContext(
    session,
    extractRequestContext(request)
  );

  // 4. Process request with identity-aware guards
  await processRequestWithContext(request, guardContext);
}
```

### Session Expiration Handling

```typescript
/**
 * Background job to handle session expiration
 */
async function sessionExpirationWorker(): Promise<void> {
  // Clean up expired sessions from store
  const cleanedCount = await sessionStore.cleanup();
  logger.info(`Cleaned up ${cleanedCount} expired sessions`);

  // Check sessions nearing expiration for warning
  const nearingExpiration = await getNearingExpirationSessions(300); // 5 min warning
  for (const session of nearingExpiration) {
    await notifySessionExpiring(session);
  }
}

/**
 * Handle IdP session revocation webhook
 */
async function handleSessionRevocation(userId: string, reason: string): Promise<void> {
  // Terminate all Clawdstrike sessions for the user
  const count = await sessionManager.terminateUserSessions(userId, reason);

  // Log for audit
  auditLog.info('User sessions terminated due to IdP revocation', {
    userId,
    reason,
    terminatedCount: count,
  });
}
```

### Request Context Extraction

```typescript
/**
 * Extract request context from incoming request
 */
function extractRequestContext(request: IncomingRequest): RequestContext {
  return {
    requestId: request.headers['x-request-id'] || generateRequestId(),
    sourceIp: getClientIp(request),
    userAgent: request.headers['user-agent'],
    geoLocation: resolveGeoLocation(getClientIp(request)),
    isVpn: isVpnIp(getClientIp(request)),
    isCorporateNetwork: isCorporateIp(getClientIp(request)),
    timestamp: new Date().toISOString(),
  };
}

/**
 * Get client IP, handling proxies
 */
function getClientIp(request: IncomingRequest): string {
  // Respect X-Forwarded-For from trusted proxies
  const forwardedFor = request.headers['x-forwarded-for'];
  if (forwardedFor && isTrustedProxy(request.remoteAddress)) {
    return forwardedFor.split(',')[0].trim();
  }
  return request.remoteAddress;
}
```

## Guard Context Enhancement

### Using Identity in Guards

```typescript
/**
 * Example: Identity-aware forbidden path guard
 */
class IdentityAwareForbiddenPathGuard implements Guard {
  async check(
    action: GuardAction,
    context: EnhancedGuardContext
  ): Promise<GuardResult> {
    if (action.type !== 'FileAccess') {
      return GuardResult.allow(this.name());
    }

    const path = action.path;

    // Check if user has override permission
    if (context.permissions?.includes('file:sensitive:read')) {
      return GuardResult.allow(this.name());
    }

    // Check role-based path access
    if (this.isRoleBasedPath(path)) {
      const requiredRole = this.getRequiredRole(path);
      if (!context.roles?.includes(requiredRole)) {
        return GuardResult.block(
          this.name(),
          Severity.Error,
          `Role '${requiredRole}' required to access ${path}`
        );
      }
    }

    // Standard forbidden path check
    if (this.isForbiddenPath(path)) {
      return GuardResult.block(
        this.name(),
        Severity.Error,
        `Access to ${path} is forbidden`
      );
    }

    return GuardResult.allow(this.name());
  }

  private isRoleBasedPath(path: string): boolean {
    return path.startsWith('/var/log/security/') ||
           path.startsWith('/etc/pki/') ||
           path.includes('/secrets/');
  }

  private getRequiredRole(path: string): string {
    if (path.startsWith('/var/log/security/')) return 'security-team';
    if (path.startsWith('/etc/pki/')) return 'pki-admin';
    if (path.includes('/secrets/')) return 'secrets-reader';
    return 'admin';
  }
}
```

### Rust Guard Implementation

```rust
/// Identity-aware forbidden path guard
impl Guard for IdentityAwareForbiddenPathGuard {
    fn name(&self) -> &str {
        "identity_aware_forbidden_path"
    }

    fn handles(&self, action: &GuardAction<'_>) -> bool {
        matches!(action, GuardAction::FileAccess(_) | GuardAction::FileWrite(_, _))
    }

    async fn check(&self, action: &GuardAction<'_>, context: &EnhancedGuardContext) -> GuardResult {
        let path = match action {
            GuardAction::FileAccess(p) => *p,
            GuardAction::FileWrite(p, _) => *p,
            _ => return GuardResult::allow(self.name()),
        };

        // Check permission override
        if let Some(permissions) = &context.permissions {
            if permissions.contains(&"file:sensitive:read".to_string()) {
                return GuardResult::allow(self.name());
            }
        }

        // Check role-based access
        if let Some(required_role) = self.get_required_role(path) {
            if let Some(roles) = &context.roles {
                if !roles.contains(&required_role.to_string()) {
                    return GuardResult::block(
                        self.name(),
                        Severity::Error,
                        format!("Role '{}' required to access {}", required_role, path),
                    );
                }
            } else {
                return GuardResult::block(
                    self.name(),
                    Severity::Error,
                    format!("Authentication required to access {}", path),
                );
            }
        }

        // Delegate to standard check
        self.inner_guard.check(action, context).await
    }
}
```

## Multi-Tenancy Considerations

### Session Isolation by Organization

```typescript
/**
 * Ensure sessions are isolated by organization
 */
class OrganizationIsolatedSessionStore implements SessionStore {
  async set(session: SessionContext, ttlSeconds: number): Promise<void> {
    const orgId = session.organization?.id;
    if (!orgId) {
      throw new Error('Session must have organization context');
    }

    // Store with organization-prefixed key
    const key = `org:${orgId}:session:${session.sessionId}`;
    await this.backend.set(key, session, ttlSeconds);

    // Add to user's session index within org
    await this.backend.sadd(
      `org:${orgId}:user:${session.identity.id}:sessions`,
      session.sessionId
    );
  }

  async get(sessionId: string): Promise<SessionContext | null> {
    // Need to search across organizations or require org context
    // For security, we require the caller to provide org context
    throw new Error('Use getWithOrg() for organization-isolated sessions');
  }

  async getWithOrg(sessionId: string, orgId: string): Promise<SessionContext | null> {
    const key = `org:${orgId}:session:${sessionId}`;
    return this.backend.get(key);
  }

  async listByOrganization(orgId: string): Promise<SessionContext[]> {
    const pattern = `org:${orgId}:session:*`;
    const keys = await this.backend.keys(pattern);
    const sessions = await Promise.all(keys.map(k => this.backend.get(k)));
    return sessions.filter((s): s is SessionContext => s !== null);
  }
}
```

### Cross-Organization Session Prevention

```typescript
/**
 * Prevent session from being used across organizations
 */
async function validateSessionOrganization(
  session: SessionContext,
  requestedOrgId: string
): Promise<boolean> {
  const sessionOrgId = session.organization?.id;

  if (!sessionOrgId) {
    // Session has no org - might be super-admin
    return session.effectiveRoles.includes('super-admin');
  }

  if (sessionOrgId !== requestedOrgId) {
    auditLog.warn('Cross-organization session usage attempted', {
      sessionId: session.sessionId,
      sessionOrg: sessionOrgId,
      requestedOrg: requestedOrgId,
      userId: session.identity.id,
    });
    return false;
  }

  return true;
}
```

## Security Considerations

### Session Fixation Prevention

```typescript
/**
 * Rotate session ID after authentication
 */
async function rotateSessionAfterAuth(
  oldSessionId: string,
  identity: IdentityPrincipal
): Promise<SessionContext> {
  // Get old session
  const oldSession = await sessionStore.get(oldSessionId);

  // Create new session with new ID
  const newSession = await sessionManager.createSession(identity, {
    initialState: oldSession?.state,
    tags: oldSession?.metadata?.tags,
  });

  // Delete old session
  if (oldSession) {
    await sessionStore.delete(oldSessionId);
  }

  return newSession;
}
```

### Session Binding

```typescript
/**
 * Bind session to client characteristics
 */
interface SessionBinding {
  /** Hash of user agent (detect browser change) */
  userAgentHash: string;
  /** Country of origin (detect geo change) */
  originCountry?: string;
  /** Whether originally from VPN */
  wasVpn: boolean;
}

function validateSessionBinding(
  session: SessionContext,
  currentRequest: RequestContext
): boolean {
  const binding = session.state?.binding as SessionBinding | undefined;
  if (!binding) return true; // No binding configured

  // Check user agent consistency
  if (binding.userAgentHash) {
    const currentHash = hashUserAgent(currentRequest.userAgent);
    if (currentHash !== binding.userAgentHash) {
      auditLog.warn('Session binding violation: user agent changed', {
        sessionId: session.sessionId,
      });
      return false;
    }
  }

  // Check geo consistency (allow some variance)
  if (binding.originCountry && currentRequest.geoLocation?.country) {
    if (binding.originCountry !== currentRequest.geoLocation.country) {
      auditLog.warn('Session binding violation: country changed', {
        sessionId: session.sessionId,
        originalCountry: binding.originCountry,
        currentCountry: currentRequest.geoLocation.country,
      });
      // Could be traveling - log but don't block
    }
  }

  return true;
}
```

### CSRF Protection

For session-based authentication, implement CSRF protection:

```typescript
/**
 * CSRF token management for session-based auth
 */
interface CSRFProtection {
  /**
   * Generate a CSRF token for a session
   */
  generateToken(sessionId: string): string;

  /**
   * Validate CSRF token from request
   */
  validateToken(sessionId: string, token: string): boolean;
}

/**
 * Double-submit cookie pattern implementation
 */
class DoubleSubmitCSRF implements CSRFProtection {
  private readonly secret: string;
  private readonly tokenTTL: number = 3600; // 1 hour

  generateToken(sessionId: string): string {
    const timestamp = Math.floor(Date.now() / 1000);
    const payload = `${sessionId}.${timestamp}`;
    const signature = crypto.createHmac('sha256', this.secret)
      .update(payload)
      .digest('base64url');
    return `${payload}.${signature}`;
  }

  validateToken(sessionId: string, token: string): boolean {
    const parts = token.split('.');
    if (parts.length !== 3) return false;

    const [tokenSessionId, timestampStr, signature] = parts;

    // Verify session ID matches
    if (tokenSessionId !== sessionId) return false;

    // Verify not expired
    const timestamp = parseInt(timestampStr, 10);
    if (Date.now() / 1000 - timestamp > this.tokenTTL) return false;

    // Verify signature
    const payload = `${tokenSessionId}.${timestampStr}`;
    const expectedSig = crypto.createHmac('sha256', this.secret)
      .update(payload)
      .digest('base64url');

    return crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expectedSig)
    );
  }
}
```

### Session Replay Protection

Prevent session token replay attacks:

```typescript
/**
 * Session replay protection using sliding window
 */
interface SessionReplayProtection {
  /**
   * Record request and check for replay
   * Returns false if this request ID has been seen
   */
  checkAndRecord(sessionId: string, requestId: string): Promise<boolean>;
}

class RedisSessionReplayProtection implements SessionReplayProtection {
  async checkAndRecord(sessionId: string, requestId: string): Promise<boolean> {
    const key = `session:${sessionId}:requests`;

    // Use Redis sorted set with timestamp as score
    const score = Date.now();
    const added = await this.redis.zadd(key, 'NX', score, requestId);

    // Clean old entries (older than 5 minutes)
    await this.redis.zremrangebyscore(key, '-inf', score - 300000);

    // Set expiry on the set
    await this.redis.expire(key, 600);

    return added === 1; // 1 if new, 0 if already existed
  }
}
```

### Session Audit Trail

```typescript
/**
 * Log all session lifecycle events
 */
interface SessionAuditEvent {
  eventType: 'created' | 'accessed' | 'updated' | 'terminated' | 'expired';
  sessionId: string;
  identity: {
    id: string;
    email?: string;
  };
  organization?: {
    id: string;
    name: string;
  };
  request?: {
    sourceIp?: string;
    userAgent?: string;
  };
  timestamp: string;
  metadata?: Record<string, unknown>;
}

class AuditingSessionManager implements SessionManager {
  async createSession(
    identity: IdentityPrincipal,
    options?: CreateSessionOptions
  ): Promise<SessionContext> {
    const session = await this.inner.createSession(identity, options);

    await this.auditLog.write({
      eventType: 'created',
      sessionId: session.sessionId,
      identity: { id: identity.id, email: identity.email },
      organization: session.organization,
      request: options?.request,
      timestamp: new Date().toISOString(),
    });

    return session;
  }

  async terminateSession(sessionId: string, reason?: string): Promise<void> {
    const session = await this.inner.getSession(sessionId);

    await this.inner.terminateSession(sessionId, reason);

    if (session) {
      await this.auditLog.write({
        eventType: 'terminated',
        sessionId,
        identity: { id: session.identity.id, email: session.identity.email },
        organization: session.organization,
        timestamp: new Date().toISOString(),
        metadata: { reason },
      });
    }
  }
}
```

## Configuration Examples

### Complete Session Configuration

```yaml
session:
  # Storage backend
  store: redis
  redis:
    url: redis://localhost:6379
    prefix: clawdstrike:session:
    tls: true

  # TTL settings
  defaultTtlSeconds: 3600      # 1 hour
  maxTtlSeconds: 86400         # 24 hours
  idleTimeoutSeconds: 1800     # 30 minutes

  # Security settings
  validateIdentityOnRequest: true
  sessionBinding:
    enabled: true
    bindUserAgent: true
    bindOriginCountry: false
    bindVpnStatus: false

  # Rate limiting per session
  rateLimiting:
    enabled: true
    limits:
      - action: shell_command
        maxPerHour: 100
      - action: file_write
        maxPerHour: 500
      - action: network_egress
        maxPerHour: 1000

  # Organization isolation
  organizationIsolation:
    enabled: true
    requireOrgContext: true

  # Audit settings
  audit:
    enabled: true
    logAccess: true
    logUpdates: true
```

### Integration with Engine

```typescript
// Initialize session manager
const sessionManager = createSessionManager({
  store: 'redis',
  redis: { url: process.env.REDIS_URL },
  defaultTtlSeconds: 3600,
  maxTtlSeconds: 86400,
  validateIdentityOnRequest: true,
  rbac: rbacManager,
  identityBridge: identityBridge,
});

// Use in request handler
app.use(async (req, res, next) => {
  // Get token from Authorization header
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) {
    return res.status(401).json({ error: 'Missing authentication' });
  }

  // Validate and get/create session
  const identity = await identityBridge.validateOIDCToken(token);
  if (!identity.success) {
    return res.status(401).json({ error: identity.error });
  }

  const session = await sessionManager.createSession(identity.principal!, {
    request: extractRequestContext(req),
  });

  // Attach to request for use in handlers
  req.guardContext = sessionManager.createGuardContext(
    session,
    extractRequestContext(req)
  );

  next();
});

// Use in guard evaluation
const decision = await engine.checkAction(action, req.guardContext);
```

## Implementation Phases

### Phase 1: Core Session Management (1 week)
- Session data model
- In-memory session store
- Basic create/get/terminate
- Integration with existing GuardContext

### Phase 2: Identity Integration (1 week)
- Session creation from IdentityPrincipal
- Permission resolution on session creation
- Session validation against identity
- IdP session revocation handling

### Phase 3: Storage Backends (1 week)
- Redis session store
- Session expiration handling
- Distributed session management
- Session cleanup workers

### Phase 4: Security Enhancements (1 week)
- Session binding
- Session rotation
- Audit logging
- Rate limiting integration

### Phase 5: Multi-Tenancy (1 week)
- Organization isolation
- Cross-org prevention
- Per-org session limits
- Organization-scoped queries

## Dependencies

- `uuid` / `nanoid`: Session ID generation
- `ioredis`: Redis client
- `@maxmind/geoip2-node`: Geo IP resolution (optional)
- `ua-parser-js`: User agent parsing
