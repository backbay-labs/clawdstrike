# Role-Based Access Control (RBAC) for Clawdstrike Policy Management

## Problem Statement

Clawdstrike policies define what actions AI agents can and cannot perform. In enterprise environments, different stakeholders need different levels of access to manage these policies:

1. **Policy Administration**: Who can create, modify, and delete policies?
2. **Policy Assignment**: Who can assign policies to agents, sessions, or tenants?
3. **Policy Viewing**: Who can view policy configurations and audit logs?
4. **Guard Configuration**: Who can enable/disable specific guards or modify their settings?
5. **Override Authority**: Who can grant exceptions to policy rules?

Without RBAC, organizations face:
- All-or-nothing access to policy management
- No separation of duties between policy authors and administrators
- Inability to delegate policy management to teams
- Compliance failures due to lack of access controls on security configurations

## Use Cases

### UC-RBAC-1: Security Team Manages Global Policies
The security team has `policy-admin` role, allowing them to create and modify organization-wide policies. They define baseline security rules that all AI agents must follow.

### UC-RBAC-2: Team Leads Configure Team Policies
Team leads have `policy-contributor` role scoped to their team, allowing them to customize policies within boundaries set by the security team.

### UC-RBAC-3: Developers View Policies
Developers have `policy-viewer` role, allowing them to understand what restrictions apply to their AI agents without being able to modify them.

### UC-RBAC-4: On-Call Grants Emergency Exceptions
On-call engineers have `exception-granter` role, allowing them to temporarily bypass specific policy restrictions during incidents.

### UC-RBAC-5: Auditors Review Policy Changes
Compliance auditors have `audit-viewer` role, allowing them to review all policy changes and access decisions without modifying anything.

### UC-RBAC-6: Platform Team Manages Guard Configurations
The platform team has `guard-admin` role, allowing them to enable/disable guards and tune their sensitivity across the organization.

## Architecture

### RBAC Model

```
+------------------+     +-------------------+     +------------------+
|                  |     |                   |     |                  |
|  Identity        +---->+  RBAC Engine      +---->+  Policy          |
|  Principal       |     |                   |     |  Management      |
|                  |     +--------+----------+     |  API             |
+------------------+              |                +--------+---------+
                                  |                         |
                                  v                         v
                        +---------+----------+    +---------+---------+
                        |                    |    |                   |
                        |  Role Definitions  |    |  Permission       |
                        |  & Assignments     |    |  Checks           |
                        |                    |    |                   |
                        +--------------------+    +-------------------+
```

### Permission Hierarchy

```
                    +------------------+
                    |                  |
                    |  super-admin     |
                    |  (all perms)     |
                    |                  |
                    +--------+---------+
                             |
            +----------------+----------------+
            |                |                |
   +--------+--------+  +----+----+  +--------+--------+
   |                 |  |         |  |                 |
   |  policy-admin   |  | guard-  |  |  audit-admin    |
   |                 |  | admin   |  |                 |
   +--------+--------+  +----+----+  +--------+--------+
            |                |                |
   +--------+--------+       |       +--------+--------+
   |                 |       |       |                 |
   |  policy-        |       |       |  audit-viewer   |
   |  contributor    |       |       |                 |
   +--------+--------+       |       +-----------------+
            |                |
   +--------+--------+  +----+----+
   |                 |  |         |
   |  policy-viewer  |  | guard-  |
   |                 |  | viewer  |
   +-----------------+  +---------+
```

## Data Model

### Role Definition

```typescript
/**
 * Role definition
 */
export interface Role {
  /** Unique role identifier */
  id: string;

  /** Human-readable name */
  name: string;

  /** Description */
  description: string;

  /** Permissions granted by this role */
  permissions: Permission[];

  /** Parent role(s) for inheritance */
  inherits?: string[];

  /** Scope constraints */
  scope?: RoleScope;

  /** Whether this is a built-in role */
  builtin: boolean;

  /** Metadata */
  metadata?: Record<string, unknown>;

  /** Created/updated timestamps */
  createdAt: string;
  updatedAt: string;
}

/**
 * Permission definition
 */
export interface Permission {
  /** Resource type */
  resource: ResourceType;

  /** Actions allowed */
  actions: Action[];

  /** Optional resource constraints */
  constraints?: PermissionConstraint[];
}

/**
 * Resource types in Clawdstrike
 */
export type ResourceType =
  | 'policy'           // Policy definitions
  | 'policy_assignment' // Policy-to-entity assignments
  | 'guard'            // Guard configurations
  | 'ruleset'          // Built-in and custom rulesets
  | 'audit_log'        // Audit trail
  | 'session'          // Active sessions
  | 'exception'        // Policy exceptions
  | 'tenant'           // Multi-tenant entities
  | 'user'             // User management
  | 'role';            // Role management

/**
 * Actions on resources
 */
export type Action =
  | 'create'
  | 'read'
  | 'update'
  | 'delete'
  | 'assign'
  | 'unassign'
  | 'enable'
  | 'disable'
  | 'grant'
  | 'revoke'
  | 'export'
  | 'import';

/**
 * Permission constraints
 */
export interface PermissionConstraint {
  /** Constraint type */
  type: 'scope' | 'attribute' | 'time' | 'approval';

  /** Constraint configuration */
  config: ScopeConstraint | AttributeConstraint | TimeConstraint | ApprovalConstraint;
}

/**
 * Scope constraint - limits permission to specific scopes
 */
export interface ScopeConstraint {
  type: 'scope';
  /** Allowed scope types */
  scopeTypes: ('organization' | 'team' | 'project' | 'user')[];
  /** Specific scope values (optional) */
  scopeValues?: string[];
}

/**
 * Attribute constraint - limits based on resource attributes
 */
export interface AttributeConstraint {
  type: 'attribute';
  /** Attribute to check */
  attribute: string;
  /** Operator */
  operator: 'eq' | 'ne' | 'in' | 'not_in' | 'matches';
  /** Value(s) to compare */
  value: unknown;
}

/**
 * Time constraint - limits when permission is valid
 */
export interface TimeConstraint {
  type: 'time';
  /** Valid from (ISO 8601) */
  validFrom?: string;
  /** Valid until (ISO 8601) */
  validUntil?: string;
  /** Valid during hours (UTC) */
  validHours?: { start: number; end: number };
  /** Valid on days */
  validDays?: number[];  // 0=Sunday, 6=Saturday
}

/**
 * Approval constraint - requires approval for action
 */
export interface ApprovalConstraint {
  type: 'approval';
  /** Roles that can approve */
  approverRoles: string[];
  /** Number of approvals required */
  requiredApprovals: number;
  /** Approval expiration in seconds */
  approvalTtlSecs: number;
}

/**
 * Role scope - where the role applies
 */
export interface RoleScope {
  /** Scope type */
  type: 'global' | 'organization' | 'team' | 'project';

  /** Specific scope ID (for non-global) */
  scopeId?: string;

  /** Whether to include child scopes */
  includeChildren?: boolean;
}

/**
 * Role assignment
 */
export interface RoleAssignment {
  /** Assignment ID */
  id: string;

  /** Principal (user or service account) */
  principal: {
    type: 'user' | 'service_account' | 'group';
    id: string;
  };

  /** Role being assigned */
  roleId: string;

  /** Scope of assignment */
  scope: RoleScope;

  /** Assignment metadata */
  grantedBy: string;
  grantedAt: string;
  expiresAt?: string;
  reason?: string;
}
```

### Rust Data Model

```rust
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Role definition
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Role {
    pub id: String,
    pub name: String,
    pub description: String,
    pub permissions: Vec<Permission>,
    #[serde(default)]
    pub inherits: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<RoleScope>,
    pub builtin: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    pub created_at: String,
    pub updated_at: String,
}

/// Permission definition
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Permission {
    pub resource: ResourceType,
    pub actions: Vec<Action>,
    #[serde(default)]
    pub constraints: Vec<PermissionConstraint>,
}

/// Resource types
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceType {
    Policy,
    PolicyAssignment,
    Guard,
    Ruleset,
    AuditLog,
    Session,
    Exception,
    Tenant,
    User,
    Role,
}

/// Actions on resources
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Create,
    Read,
    Update,
    Delete,
    Assign,
    Unassign,
    Enable,
    Disable,
    Grant,
    Revoke,
    Export,
    Import,
}

/// Permission constraint
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PermissionConstraint {
    Scope(ScopeConstraint),
    Attribute(AttributeConstraint),
    Time(TimeConstraint),
    Approval(ApprovalConstraint),
}

/// Scope constraint
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScopeConstraint {
    pub scope_types: Vec<ScopeType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_values: Option<Vec<String>>,
}

/// Scope types (matches PolicyScopeType for consistency)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeType {
    Global,
    Organization,
    Team,
    Project,
    User,
}

/// Attribute constraint
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttributeConstraint {
    pub attribute: String,
    pub operator: AttributeOperator,
    pub value: serde_json::Value,
}

/// Attribute operators
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributeOperator {
    Eq,
    Ne,
    In,
    NotIn,
    Matches,
}

/// Time constraint
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimeConstraint {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_hours: Option<HourRange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_days: Option<Vec<u8>>,
}

/// Hour range
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HourRange {
    pub start: u8,
    pub end: u8,
}

/// Approval constraint
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApprovalConstraint {
    pub approver_roles: Vec<String>,
    pub required_approvals: u32,
    pub approval_ttl_secs: u64,
}

/// Role scope
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoleScope {
    #[serde(rename = "type")]
    pub scope_type: ScopeType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_id: Option<String>,
    #[serde(default)]
    pub include_children: bool,
}

/// Role assignment
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoleAssignment {
    pub id: String,
    pub principal: Principal,
    pub role_id: String,
    pub scope: RoleScope,
    pub granted_by: String,
    pub granted_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Principal (who is assigned the role)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Principal {
    #[serde(rename = "type")]
    pub principal_type: PrincipalType,
    pub id: String,
}

/// Principal types
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalType {
    User,
    ServiceAccount,
    Group,
}
```

## API Design

### TypeScript SDK

```typescript
/**
 * RBAC Manager interface
 */
export interface RBACManager {
  // Role Management
  createRole(role: Omit<Role, 'id' | 'createdAt' | 'updatedAt'>): Promise<Role>;
  getRole(roleId: string): Promise<Role | null>;
  updateRole(roleId: string, updates: Partial<Role>): Promise<Role>;
  deleteRole(roleId: string): Promise<void>;
  listRoles(filter?: RoleFilter): Promise<Role[]>;

  // Role Assignment
  assignRole(assignment: Omit<RoleAssignment, 'id' | 'grantedAt'>): Promise<RoleAssignment>;
  revokeRole(assignmentId: string): Promise<void>;
  listAssignments(filter?: AssignmentFilter): Promise<RoleAssignment[]>;

  // Permission Checking
  checkPermission(check: PermissionCheck): Promise<PermissionResult>;
  getEffectivePermissions(principalId: string, scope?: RoleScope): Promise<Permission[]>;

  // Audit
  getPermissionAuditLog(filter?: AuditFilter): Promise<PermissionAuditEntry[]>;
}

/**
 * Permission check request
 */
export interface PermissionCheck {
  /** Principal requesting access */
  principal: {
    type: 'user' | 'service_account' | 'group';
    id: string;
  };

  /** Resource being accessed */
  resource: {
    type: ResourceType;
    id?: string;
    attributes?: Record<string, unknown>;
  };

  /** Action being performed */
  action: Action;

  /** Scope context */
  scope?: RoleScope;

  /** Additional context */
  context?: Record<string, unknown>;
}

/**
 * Permission check result
 */
export interface PermissionResult {
  /** Whether permission is granted */
  allowed: boolean;

  /** Reason for decision */
  reason: string;

  /** Role that granted permission (if allowed) */
  grantingRole?: string;

  /** Constraints that applied */
  appliedConstraints?: PermissionConstraint[];

  /** Whether approval is required */
  requiresApproval?: boolean;

  /** Approval requirements (if applicable) */
  approvalRequirements?: ApprovalRequirement;
}

/**
 * Approval requirement details
 */
export interface ApprovalRequirement {
  /** Roles that can approve */
  approverRoles: string[];
  /** Number of approvals needed */
  requiredApprovals: number;
  /** Approval request ID */
  requestId?: string;
}

/**
 * Filter for listing roles
 */
export interface RoleFilter {
  /** Filter by builtin status */
  builtin?: boolean;
  /** Filter by scope type */
  scopeType?: 'global' | 'organization' | 'team' | 'project';
  /** Search by name */
  search?: string;
  /** Pagination */
  limit?: number;
  offset?: number;
}

/**
 * Filter for listing assignments
 */
export interface AssignmentFilter {
  /** Filter by principal */
  principalId?: string;
  principalType?: 'user' | 'service_account' | 'group';
  /** Filter by role */
  roleId?: string;
  /** Filter by scope */
  scopeType?: 'global' | 'organization' | 'team' | 'project';
  scopeId?: string;
  /** Include expired */
  includeExpired?: boolean;
  /** Pagination */
  limit?: number;
  offset?: number;
}

/**
 * Create RBAC manager
 */
export function createRBACManager(config: RBACConfig): RBACManager;

/**
 * RBAC configuration
 */
export interface RBACConfig {
  /** Storage backend */
  storage: 'memory' | 'redis' | 'postgres' | 'dynamodb';

  /** Storage connection config */
  storageConfig?: Record<string, unknown>;

  /** Cache configuration */
  cache?: {
    enabled: boolean;
    ttlSecs: number;
    maxEntries: number;
  };

  /** Built-in roles to initialize */
  builtinRoles?: Role[];

  /** Super admin principals (bypass all checks) */
  superAdmins?: string[];
}
```

### Rust SDK

```rust
use async_trait::async_trait;

/// RBAC Manager trait
#[async_trait]
pub trait RBACManager: Send + Sync {
    // Role Management
    async fn create_role(&self, role: CreateRole) -> Result<Role, Error>;
    async fn get_role(&self, role_id: &str) -> Result<Option<Role>, Error>;
    async fn update_role(&self, role_id: &str, updates: UpdateRole) -> Result<Role, Error>;
    async fn delete_role(&self, role_id: &str) -> Result<(), Error>;
    async fn list_roles(&self, filter: Option<RoleFilter>) -> Result<Vec<Role>, Error>;

    // Role Assignment
    async fn assign_role(&self, assignment: CreateAssignment) -> Result<RoleAssignment, Error>;
    async fn revoke_role(&self, assignment_id: &str) -> Result<(), Error>;
    async fn list_assignments(&self, filter: Option<AssignmentFilter>) -> Result<Vec<RoleAssignment>, Error>;

    // Permission Checking
    async fn check_permission(&self, check: PermissionCheck) -> Result<PermissionResult, Error>;
    async fn get_effective_permissions(&self, principal_id: &str, scope: Option<RoleScope>) -> Result<Vec<Permission>, Error>;
}

/// Permission check request
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PermissionCheck {
    pub principal: Principal,
    pub resource: ResourceRef,
    pub action: Action,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<RoleScope>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,
}

/// Resource reference
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResourceRef {
    #[serde(rename = "type")]
    pub resource_type: ResourceType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<serde_json::Value>,
}

/// Permission check result
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PermissionResult {
    pub allowed: bool,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub granting_role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applied_constraints: Option<Vec<PermissionConstraint>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requires_approval: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_requirements: Option<ApprovalRequirement>,
}

/// Create RBAC manager
pub fn create_rbac_manager(config: RBACConfig) -> impl RBACManager;
```

## Built-in Roles

### Role Definitions

```yaml
# Built-in roles for Clawdstrike RBAC
roles:
  # Super administrator - all permissions
  - id: super-admin
    name: Super Administrator
    description: Full access to all Clawdstrike resources
    permissions:
      - resource: "*"
        actions: ["*"]
    builtin: true

  # Policy administrator
  - id: policy-admin
    name: Policy Administrator
    description: Full access to policy management
    permissions:
      - resource: policy
        actions: [create, read, update, delete, import, export]
      - resource: policy_assignment
        actions: [create, read, update, delete, assign, unassign]
      - resource: ruleset
        actions: [create, read, update, delete]
      - resource: exception
        actions: [create, read, update, delete, grant, revoke]
    builtin: true

  # Policy contributor (scoped)
  - id: policy-contributor
    name: Policy Contributor
    description: Can modify policies within assigned scope
    permissions:
      - resource: policy
        actions: [read, update]
        constraints:
          - type: scope
            config:
              scopeTypes: [team, project]
      - resource: policy_assignment
        actions: [read, assign, unassign]
        constraints:
          - type: scope
            config:
              scopeTypes: [team, project]
    builtin: true

  # Policy viewer
  - id: policy-viewer
    name: Policy Viewer
    description: Read-only access to policies
    permissions:
      - resource: policy
        actions: [read]
      - resource: policy_assignment
        actions: [read]
      - resource: ruleset
        actions: [read]
    builtin: true

  # Guard administrator
  - id: guard-admin
    name: Guard Administrator
    description: Full access to guard configuration
    permissions:
      - resource: guard
        actions: [create, read, update, delete, enable, disable]
    builtin: true

  # Guard viewer
  - id: guard-viewer
    name: Guard Viewer
    description: Read-only access to guard configuration
    permissions:
      - resource: guard
        actions: [read]
    builtin: true

  # Audit administrator
  - id: audit-admin
    name: Audit Administrator
    description: Full access to audit logs
    permissions:
      - resource: audit_log
        actions: [read, export]
      - resource: session
        actions: [read]
    builtin: true

  # Audit viewer
  - id: audit-viewer
    name: Audit Viewer
    description: Read-only access to audit logs
    permissions:
      - resource: audit_log
        actions: [read]
    builtin: true

  # Exception granter
  - id: exception-granter
    name: Exception Granter
    description: Can grant temporary policy exceptions
    permissions:
      - resource: exception
        actions: [create, read, grant]
        constraints:
          - type: time
            config:
              # Only valid during business hours
              validHours: { start: 9, end: 17 }
          - type: approval
            config:
              approverRoles: [policy-admin]
              requiredApprovals: 1
              approvalTtlSecs: 3600
    builtin: true

  # Session manager
  - id: session-manager
    name: Session Manager
    description: Can view and terminate sessions
    permissions:
      - resource: session
        actions: [read, delete]
    builtin: true

  # Tenant administrator
  - id: tenant-admin
    name: Tenant Administrator
    description: Full access to tenant management
    permissions:
      - resource: tenant
        actions: [create, read, update, delete]
      - resource: user
        actions: [create, read, update, delete]
      - resource: role
        actions: [read, assign, unassign]
    builtin: true
```

## Multi-Tenancy Considerations

### Scoped Role Assignments

```typescript
// Assign role scoped to specific organization
await rbac.assignRole({
  principal: { type: 'user', id: 'user-123' },
  roleId: 'policy-contributor',
  scope: {
    type: 'organization',
    scopeId: 'org-456',
    includeChildren: true,  // Includes all teams/projects in org
  },
  grantedBy: 'admin-user',
  reason: 'Team lead for engineering',
});

// Assign role scoped to specific team
await rbac.assignRole({
  principal: { type: 'user', id: 'user-789' },
  roleId: 'policy-viewer',
  scope: {
    type: 'team',
    scopeId: 'team-payments',
    includeChildren: false,
  },
  grantedBy: 'team-lead',
  reason: 'Developer on payments team',
});
```

### Tenant Isolation

```typescript
/**
 * Ensure permission checks respect tenant boundaries
 */
class TenantAwareRBACManager implements RBACManager {
  async checkPermission(check: PermissionCheck): Promise<PermissionResult> {
    // Get principal's tenant
    const principalTenant = await this.getPrincipalTenant(check.principal.id);

    // Get resource's tenant (if applicable)
    const resourceTenant = check.resource.id
      ? await this.getResourceTenant(check.resource.type, check.resource.id)
      : null;

    // Cross-tenant access is never allowed (except super-admin)
    if (resourceTenant && principalTenant !== resourceTenant) {
      if (!await this.isSuperAdmin(check.principal.id)) {
        return {
          allowed: false,
          reason: 'Cross-tenant access denied',
        };
      }
    }

    // Proceed with normal permission check
    return this.innerCheck(check);
  }
}
```

### Hierarchical Scope Resolution

```typescript
/**
 * Resolve effective permissions through scope hierarchy
 *
 * Organization -> Team -> Project -> User
 */
async function resolveEffectivePermissions(
  principalId: string,
  targetScope: RoleScope
): Promise<Permission[]> {
  const permissions: Permission[] = [];

  // Get all role assignments for principal
  const assignments = await rbac.listAssignments({
    principalId,
    includeExpired: false,
  });

  for (const assignment of assignments) {
    // Check if assignment scope contains target scope
    if (scopeContains(assignment.scope, targetScope)) {
      const role = await rbac.getRole(assignment.roleId);
      if (role) {
        permissions.push(...role.permissions);
      }
    }
  }

  // Also check inherited roles
  const inheritedPerms = await resolveInheritedPermissions(assignments);
  permissions.push(...inheritedPerms);

  return deduplicatePermissions(permissions);
}

/**
 * Check if scope A contains scope B
 */
function scopeContains(scopeA: RoleScope, scopeB: RoleScope): boolean {
  // Global scope contains all scopes
  if (scopeA.type === 'global') return true;

  // Same scope type and ID
  if (scopeA.type === scopeB.type && scopeA.scopeId === scopeB.scopeId) {
    return true;
  }

  // Check hierarchy
  if (scopeA.includeChildren) {
    const hierarchy = ['organization', 'team', 'project', 'user'];
    const aIndex = hierarchy.indexOf(scopeA.type);
    const bIndex = hierarchy.indexOf(scopeB.type);

    if (aIndex < bIndex) {
      // scopeA is higher in hierarchy, check if scopeB is child
      return isChildScope(scopeA, scopeB);
    }
  }

  return false;
}
```

## Security Considerations

### Principle of Least Privilege

1. **Default Deny**: No permissions are granted by default
2. **Explicit Grant**: All permissions must be explicitly assigned
3. **Scoped Assignments**: Assign roles at the narrowest scope possible
4. **Time-Limited**: Use expiration for elevated privileges

### Separation of Duties

```yaml
# Example: Require approval for sensitive actions
- id: production-deployer
  name: Production Deployer
  permissions:
    - resource: policy_assignment
      actions: [assign]
      constraints:
        - type: attribute
          config:
            attribute: environment
            operator: eq
            value: production
        - type: approval
          config:
            approverRoles: [policy-admin, security-admin]
            requiredApprovals: 2
            approvalTtlSecs: 3600
```

### Audit Trail

```typescript
/**
 * All RBAC operations are logged
 */
interface PermissionAuditEntry {
  /** Audit entry ID */
  id: string;

  /** Timestamp */
  timestamp: string;

  /** Action type */
  action: 'check' | 'grant' | 'revoke' | 'create_role' | 'update_role' | 'delete_role';

  /** Principal performing action */
  actor: Principal;

  /** Target principal (for grant/revoke) */
  target?: Principal;

  /** Resource accessed */
  resource?: ResourceRef;

  /** Result */
  result: 'allowed' | 'denied' | 'error';

  /** Additional context */
  context?: {
    roleId?: string;
    scope?: RoleScope;
    reason?: string;
    constraints?: PermissionConstraint[];
  };

  /** Source information */
  source?: {
    ip?: string;
    userAgent?: string;
    sessionId?: string;
  };
}
```

### Role Explosion Prevention

```typescript
/**
 * Prevent role explosion through validation
 */
async function validateRoleAssignment(assignment: CreateAssignment): Promise<ValidationResult> {
  const errors: string[] = [];

  // Check maximum roles per principal
  const existingAssignments = await rbac.listAssignments({
    principalId: assignment.principal.id,
  });

  if (existingAssignments.length >= MAX_ROLES_PER_PRINCIPAL) {
    errors.push(`Principal already has ${MAX_ROLES_PER_PRINCIPAL} roles`);
  }

  // Check for conflicting permissions
  const newRole = await rbac.getRole(assignment.roleId);
  for (const existing of existingAssignments) {
    const existingRole = await rbac.getRole(existing.roleId);
    if (hasConflictingPermissions(newRole, existingRole)) {
      errors.push(`Role ${assignment.roleId} conflicts with ${existing.roleId}`);
    }
  }

  return { valid: errors.length === 0, errors };
}
```

### Session Token Binding

RBAC decisions should be bound to authenticated sessions to prevent token theft:

```typescript
/**
 * Bind RBAC context to session for tamper detection
 */
interface SessionBoundRBAC {
  /**
   * Create a signed context binding roles to session
   */
  createBinding(sessionId: string, roles: string[], permissions: string[]): string;

  /**
   * Verify binding hasn't been tampered with
   */
  verifyBinding(binding: string, sessionId: string): {
    valid: boolean;
    roles: string[];
    permissions: string[];
  };
}

/**
 * Implementation using HMAC
 */
class HMACSessionBoundRBAC implements SessionBoundRBAC {
  constructor(private secret: string) {}

  createBinding(sessionId: string, roles: string[], permissions: string[]): string {
    const payload = JSON.stringify({ sessionId, roles, permissions, ts: Date.now() });
    const signature = crypto.createHmac('sha256', this.secret)
      .update(payload)
      .digest('base64url');
    return `${Buffer.from(payload).toString('base64url')}.${signature}`;
  }

  verifyBinding(binding: string, sessionId: string): { valid: boolean; roles: string[]; permissions: string[] } {
    const [payloadB64, signature] = binding.split('.');
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());

    const expectedSig = crypto.createHmac('sha256', this.secret)
      .update(JSON.stringify(payload))
      .digest('base64url');

    if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSig))) {
      return { valid: false, roles: [], permissions: [] };
    }

    if (payload.sessionId !== sessionId) {
      return { valid: false, roles: [], permissions: [] };
    }

    return { valid: true, roles: payload.roles, permissions: payload.permissions };
  }
}
```

## Configuration Examples

### Complete RBAC Configuration

```yaml
rbac:
  # Storage backend
  storage: postgres
  storageConfig:
    connectionString: ${DATABASE_URL}
    tableName: clawdstrike_rbac

  # Cache settings
  cache:
    enabled: true
    ttlSecs: 300
    maxEntries: 10000

  # Super admin principals (use sparingly)
  superAdmins:
    - user:admin@example.com
    - service_account:clawdstrike-admin

  # Custom roles (in addition to built-in)
  customRoles:
    - id: ml-engineer
      name: ML Engineer
      description: Access for ML/AI team members
      inherits: [policy-viewer]
      permissions:
        - resource: guard
          actions: [read, update]
          constraints:
            - type: attribute
              config:
                attribute: guard_type
                operator: in
                value: [prompt_injection, secret_leak]
        - resource: session
          actions: [read]

    - id: security-oncall
      name: Security On-Call
      description: Elevated access for on-call security engineers
      inherits: [audit-viewer]
      permissions:
        - resource: exception
          actions: [create, grant]
          constraints:
            - type: time
              config:
                # Valid any time (24/7 on-call)
            - type: approval
              config:
                approverRoles: [policy-admin]
                requiredApprovals: 1
                approvalTtlSecs: 14400  # 4 hours
        - resource: session
          actions: [read, delete]

  # Default role assignments for identity attributes
  defaultAssignments:
    # All authenticated users get policy-viewer in their org
    - condition:
        attribute: identity.organizationId
        operator: exists
      roleId: policy-viewer
      scope:
        type: organization
        scopeIdFrom: identity.organizationId

    # Security team members get audit-viewer
    - condition:
        attribute: identity.teams
        operator: contains
        value: security
      roleId: audit-viewer
      scope:
        type: global
```

### Integration with Identity

```yaml
# Map identity claims to RBAC roles
identity:
  oidc:
    issuer: https://auth.example.com
    claimMapping:
      roles: groups  # Map OIDC groups to RBAC lookup

rbac:
  # Map identity groups to Clawdstrike roles
  groupMapping:
    # Direct mapping
    direct:
      "Security Team": [policy-admin, audit-admin]
      "Engineering Leads": [policy-contributor]
      "All Engineers": [policy-viewer]

    # Pattern mapping
    patterns:
      - pattern: "team-*-leads"
        roles: [policy-contributor]
        scopeFrom: group  # Extract scope from group name

  # Sync roles from IdP on login
  syncOnLogin: true
  syncInterval: 300  # Re-sync every 5 minutes
```

## Implementation Phases

### Phase 1: Core RBAC (2 weeks)
- Permission data model
- Built-in role definitions
- Basic permission checking
- In-memory storage backend

### Phase 2: Role Management (1 week)
- Role CRUD operations
- Role assignment/revocation
- Role inheritance resolution
- PostgreSQL storage backend

### Phase 3: Constraints (2 weeks)
- Scope constraints
- Attribute constraints
- Time constraints
- Approval workflow

### Phase 4: Integration (1 week)
- Identity provider integration
- Guard context enhancement
- Audit logging
- Admin API/UI

### Phase 5: Advanced Features (2 weeks)
- Multi-tenant isolation
- Hierarchical scope resolution
- Group synchronization
- Performance optimization

## Testing Strategy

### Unit Tests
- Permission matching logic
- Constraint evaluation
- Role inheritance resolution
- Scope containment checks

### Integration Tests
- Full permission check flow
- Role assignment workflows
- Storage backend operations
- Cache invalidation

### Security Tests
- Cross-tenant isolation
- Privilege escalation attempts
- Constraint bypass attempts
- Role explosion scenarios

## Dependencies

- `casbin` (optional): Policy engine for complex ABAC
- `uuid`: Unique ID generation
- `chrono`: Time handling for constraints
- Storage: `sqlx` (Postgres), `redis`, `aws-sdk` (DynamoDB)
