# Policy Scoping: Identity-Based Policy Resolution

## Problem Statement

In enterprise environments, a single security policy for all users is insufficient:

1. **Team-Specific Rules**: The security team needs stricter egress rules than the marketing team
2. **Role-Based Access**: Senior engineers may have privileges that junior engineers do not
3. **Project Isolation**: Production projects need stricter rules than sandbox projects
4. **Tenant Customization**: In multi-tenant SaaS, each customer needs their own policy
5. **Dynamic Policies**: Policies may change based on context (time of day, location, risk level)

Policy scoping connects identity context to policy resolution, enabling fine-grained, identity-aware security enforcement.

## Use Cases

### UC-SCOPE-1: Team-Based Policy
The `payments-team` has a policy that allows access to payment service files and APIs, while blocking access to HR systems. The `hr-team` has the inverse policy.

### UC-SCOPE-2: Role-Based Policy Escalation
Users with the `senior-engineer` role can execute deployment commands. Users with `junior-engineer` role can only execute read-only commands. The role is extracted from their identity.

### UC-SCOPE-3: Organization Policy Hierarchy
Organization `Acme Corp` has a base policy. Within Acme, team `Platform` has additional egress allowances. Within Platform, project `Production` has stricter rules than project `Staging`.

### UC-SCOPE-4: Dynamic Risk-Based Policy
When a user logs in from an unusual location (high risk), a stricter policy is applied. When they log in from the corporate network (low risk), a more permissive policy is used.

### UC-SCOPE-5: Time-Based Policy Scoping
During business hours, developers can deploy to staging. Outside business hours, deployments require additional approval. The policy scope changes based on time.

### UC-SCOPE-6: User-Specific Exceptions
A specific user has been granted an exception to access a normally forbidden path for incident investigation. This exception is scoped to that user only.

## Architecture

### Policy Resolution Flow

```
+------------------+     +-------------------+     +------------------+
|                  |     |                   |     |                  |
|  Session Context +---->+  Policy Resolver  +---->+  Merged Policy   |
|  (with identity) |     |                   |     |                  |
+------------------+     +--------+----------+     +------------------+
                                  |
              +-------------------+-------------------+
              |                   |                   |
              v                   v                   v
      +-------+--------+  +-------+--------+  +-------+--------+
      |                |  |                |  |                |
      |  Organization  |  |  Team Policy   |  |  User Policy   |
      |  Policy        |  |  Layer         |  |  Layer         |
      |                |  |                |  |                |
      +----------------+  +----------------+  +----------------+
```

### Scope Hierarchy

```
                    +------------------+
                    |                  |
                    |  Global Policy   |
                    |  (defaults)      |
                    |                  |
                    +--------+---------+
                             |
              +--------------+--------------+
              |                             |
    +---------+---------+         +---------+---------+
    |                   |         |                   |
    |  Organization A   |         |  Organization B   |
    |  Policy           |         |  Policy           |
    |                   |         |                   |
    +--------+----------+         +-------------------+
             |
    +--------+--------+
    |                 |
+---+---+         +---+---+
|       |         |       |
| Team 1|         | Team 2|
| Policy|         | Policy|
|       |         |       |
+---+---+         +-------+
    |
+---+---+
|       |
|Project|
| Policy|
|       |
+---+---+
    |
+---+---+
|       |
| User  |
|Policy |
|(exceptions)|
+-------+
```

## Data Model

### Policy Scope Definition

```typescript
/**
 * Defines where a policy applies
 */
export interface PolicyScope {
  /** Scope type */
  type: PolicyScopeType;

  /** Scope identifier (for non-global) */
  id?: string;

  /** Human-readable name */
  name?: string;

  /** Parent scope (for hierarchy) */
  parent?: PolicyScope;

  /** Conditions for scope to apply */
  conditions?: ScopeCondition[];
}

/**
 * Scope types from broad to narrow
 */
export type PolicyScopeType =
  | 'global'
  | 'organization'
  | 'team'
  | 'project'
  | 'role'
  | 'user';

/**
 * Condition for scope application
 */
export interface ScopeCondition {
  /** Condition type */
  type: 'identity_attribute' | 'request_context' | 'time' | 'custom';

  /** Condition configuration */
  config: IdentityCondition | RequestCondition | TimeCondition | CustomCondition;
}

/**
 * Identity-based condition
 */
export interface IdentityCondition {
  type: 'identity_attribute';
  /** Attribute path (e.g., 'roles', 'teams', 'attributes.department') */
  attribute: string;
  /** Comparison operator */
  operator: 'eq' | 'ne' | 'in' | 'not_in' | 'contains' | 'matches';
  /** Value(s) to compare */
  value: unknown;
}

/**
 * Request context condition
 */
export interface RequestCondition {
  type: 'request_context';
  /** Context field */
  field: 'sourceIp' | 'geoLocation.country' | 'isVpn' | 'isCorporateNetwork' | 'userAgent';
  /** Operator */
  operator: 'eq' | 'ne' | 'in' | 'not_in' | 'matches';
  /** Value */
  value: unknown;
}

/**
 * Time-based condition
 */
export interface TimeCondition {
  type: 'time';
  /** Timezone (IANA format) */
  timezone?: string;
  /** Valid hours (0-23) */
  validHours?: { start: number; end: number };
  /** Valid days (0=Sunday, 6=Saturday) */
  validDays?: number[];
  /** Date range */
  dateRange?: { start: string; end: string };
}

/**
 * Custom condition (evaluated by callback)
 */
export interface CustomCondition {
  type: 'custom';
  /** Condition name */
  name: string;
  /** Parameters for evaluation */
  params?: Record<string, unknown>;
}

/**
 * Scoped policy definition
 */
export interface ScopedPolicy {
  /** Policy ID */
  id: string;

  /** Policy name */
  name: string;

  /** Scope where this policy applies */
  scope: PolicyScope;

  /** Priority (higher = evaluated first) */
  priority: number;

  /** Base policy to extend */
  extends?: string;

  /** Merge strategy */
  mergeStrategy: 'replace' | 'merge' | 'deep_merge';

  /** Policy configuration */
  policy: Policy;

  /** Whether this policy is active */
  enabled: boolean;

  /** Metadata */
  metadata?: {
    createdAt: string;
    updatedAt: string;
    createdBy: string;
    description?: string;
    tags?: string[];
  };
}

/**
 * Policy assignment to entity
 */
export interface PolicyAssignment {
  /** Assignment ID */
  id: string;

  /** Policy being assigned */
  policyId: string;

  /** Target entity */
  target: {
    type: 'organization' | 'team' | 'project' | 'user';
    id: string;
  };

  /** Assignment priority (for conflicts) */
  priority: number;

  /** Effective date range */
  effectiveFrom?: string;
  effectiveUntil?: string;

  /** Who assigned */
  assignedBy: string;
  assignedAt: string;

  /** Reason for assignment */
  reason?: string;
}
```

### Rust Data Model

```rust
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Policy scope definition
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyScope {
    #[serde(rename = "type")]
    pub scope_type: PolicyScopeType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<Box<PolicyScope>>,
    #[serde(default)]
    pub conditions: Vec<ScopeCondition>,
}

/// Scope types
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyScopeType {
    Global,
    Organization,
    Team,
    Project,
    Role,
    User,
}

/// Scope condition
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ScopeCondition {
    IdentityAttribute(IdentityCondition),
    RequestContext(RequestCondition),
    Time(TimeCondition),
    Custom(CustomCondition),
}

/// Identity condition
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityCondition {
    pub attribute: String,
    pub operator: ConditionOperator,
    pub value: serde_json::Value,
}

/// Request context condition
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestCondition {
    pub field: String,
    pub operator: ConditionOperator,
    pub value: serde_json::Value,
}

/// Condition operator
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionOperator {
    Eq,
    Ne,
    In,
    NotIn,
    Contains,
    Matches,
}

/// Time condition
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimeCondition {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_hours: Option<HourRange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_days: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_range: Option<DateRange>,
}

/// Hour range
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HourRange {
    pub start: u8,
    pub end: u8,
}

/// Date range
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DateRange {
    pub start: String,
    pub end: String,
}

/// Custom condition
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CustomCondition {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<HashMap<String, serde_json::Value>>,
}

/// Scoped policy
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScopedPolicy {
    pub id: String,
    pub name: String,
    pub scope: PolicyScope,
    pub priority: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extends: Option<String>,
    pub merge_strategy: MergeStrategy,
    pub policy: Policy,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<PolicyMetadata>,
}

/// Policy metadata
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyMetadata {
    pub created_at: String,
    pub updated_at: String,
    pub created_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
}

/// Merge strategy for scoped policies
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MergeStrategy {
    Replace,
    Merge,
    #[default]
    DeepMerge,
}
```

## API Design

### TypeScript SDK

```typescript
/**
 * Policy Resolver interface
 */
export interface PolicyResolver {
  /**
   * Resolve effective policy for a session context
   */
  resolvePolicy(context: EnhancedGuardContext): Promise<ResolvedPolicy>;

  /**
   * Get all applicable policies for a context
   */
  getApplicablePolicies(context: EnhancedGuardContext): Promise<ScopedPolicy[]>;

  /**
   * Register a scoped policy
   */
  registerPolicy(policy: ScopedPolicy): Promise<void>;

  /**
   * Update a scoped policy
   */
  updatePolicy(policyId: string, updates: Partial<ScopedPolicy>): Promise<ScopedPolicy>;

  /**
   * Delete a scoped policy
   */
  deletePolicy(policyId: string): Promise<void>;

  /**
   * Assign policy to an entity
   */
  assignPolicy(assignment: Omit<PolicyAssignment, 'id' | 'assignedAt'>): Promise<PolicyAssignment>;

  /**
   * Remove policy assignment
   */
  unassignPolicy(assignmentId: string): Promise<void>;

  /**
   * List policy assignments
   */
  listAssignments(filter?: AssignmentFilter): Promise<PolicyAssignment[]>;

  /**
   * Register custom condition evaluator
   */
  registerConditionEvaluator(name: string, evaluator: ConditionEvaluator): void;
}

/**
 * Resolved policy with provenance
 */
export interface ResolvedPolicy {
  /** The merged policy */
  policy: Policy;

  /** Policies that contributed (in order of application) */
  contributingPolicies: Array<{
    id: string;
    name: string;
    scope: PolicyScope;
    priority: number;
  }>;

  /** Resolution timestamp */
  resolvedAt: string;

  /** Cache key (for invalidation) */
  cacheKey: string;
}

/**
 * Custom condition evaluator
 */
export type ConditionEvaluator = (
  context: EnhancedGuardContext,
  params?: Record<string, unknown>
) => Promise<boolean> | boolean;

/**
 * Policy store interface
 */
export interface PolicyStore {
  /** Get policy by ID */
  getPolicy(id: string): Promise<ScopedPolicy | null>;

  /** List policies by scope */
  listPoliciesByScope(scope: PolicyScope): Promise<ScopedPolicy[]>;

  /** Save policy */
  savePolicy(policy: ScopedPolicy): Promise<void>;

  /** Delete policy */
  deletePolicy(id: string): Promise<void>;

  /** Get assignments for target */
  getAssignmentsForTarget(
    targetType: string,
    targetId: string
  ): Promise<PolicyAssignment[]>;

  /** Save assignment */
  saveAssignment(assignment: PolicyAssignment): Promise<void>;

  /** Delete assignment */
  deleteAssignment(id: string): Promise<void>;
}

/**
 * Create policy resolver
 */
export function createPolicyResolver(config: PolicyResolverConfig): PolicyResolver;

/**
 * Policy resolver configuration
 */
export interface PolicyResolverConfig {
  /** Policy store */
  store: PolicyStore | 'memory' | 'postgres' | 'redis';

  /** Storage connection config */
  storageConfig?: Record<string, unknown>;

  /** Default/global policy */
  defaultPolicy?: Policy;

  /** Cache settings */
  cache?: {
    enabled: boolean;
    ttlSeconds: number;
    maxEntries: number;
  };

  /** Condition evaluators */
  conditionEvaluators?: Record<string, ConditionEvaluator>;
}
```

### Rust SDK

```rust
use async_trait::async_trait;

/// Policy resolver trait
#[async_trait]
pub trait PolicyResolver: Send + Sync {
    /// Resolve effective policy
    async fn resolve_policy(&self, context: &EnhancedGuardContext) -> Result<ResolvedPolicy, Error>;

    /// Get applicable policies
    async fn get_applicable_policies(&self, context: &EnhancedGuardContext) -> Result<Vec<ScopedPolicy>, Error>;

    /// Register scoped policy
    async fn register_policy(&self, policy: ScopedPolicy) -> Result<(), Error>;

    /// Update scoped policy
    async fn update_policy(&self, policy_id: &str, updates: PolicyUpdates) -> Result<ScopedPolicy, Error>;

    /// Delete scoped policy
    async fn delete_policy(&self, policy_id: &str) -> Result<(), Error>;

    /// Assign policy
    async fn assign_policy(&self, assignment: CreateAssignment) -> Result<PolicyAssignment, Error>;

    /// Unassign policy
    async fn unassign_policy(&self, assignment_id: &str) -> Result<(), Error>;
}

/// Resolved policy
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolvedPolicy {
    pub policy: Policy,
    pub contributing_policies: Vec<ContributingPolicy>,
    pub resolved_at: String,
    pub cache_key: String,
}

/// Contributing policy info
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContributingPolicy {
    pub id: String,
    pub name: String,
    pub scope: PolicyScope,
    pub priority: i32,
}

/// Create policy resolver
pub fn create_policy_resolver(config: PolicyResolverConfig) -> impl PolicyResolver;
```

## Policy Resolution Algorithm

### Resolution Steps

```typescript
/**
 * Resolve effective policy for a context
 */
async function resolvePolicy(
  context: EnhancedGuardContext
): Promise<ResolvedPolicy> {
  // 1. Get all potentially applicable policies
  const allPolicies = await getAllPolicies();

  // 2. Filter to policies whose scope matches context
  const matchingPolicies = await filterMatchingPolicies(allPolicies, context);

  // 3. Sort by scope hierarchy then priority
  const sortedPolicies = sortPolicies(matchingPolicies);

  // 4. Merge policies in order
  let mergedPolicy = getDefaultPolicy();
  const contributingPolicies: ContributingPolicy[] = [];

  for (const scopedPolicy of sortedPolicies) {
    if (!scopedPolicy.enabled) continue;
    if (!(await evaluateConditions(scopedPolicy.scope.conditions, context))) continue;

    mergedPolicy = mergePolicy(mergedPolicy, scopedPolicy.policy, scopedPolicy.mergeStrategy);
    contributingPolicies.push({
      id: scopedPolicy.id,
      name: scopedPolicy.name,
      scope: scopedPolicy.scope,
      priority: scopedPolicy.priority,
    });
  }

  return {
    policy: mergedPolicy,
    contributingPolicies,
    resolvedAt: new Date().toISOString(),
    cacheKey: computeCacheKey(context),
  };
}

/**
 * Filter policies that match the context
 */
async function filterMatchingPolicies(
  policies: ScopedPolicy[],
  context: EnhancedGuardContext
): Promise<ScopedPolicy[]> {
  const matching: ScopedPolicy[] = [];

  for (const policy of policies) {
    if (await scopeMatchesContext(policy.scope, context)) {
      matching.push(policy);
    }
  }

  return matching;
}

/**
 * Check if scope matches context
 */
async function scopeMatchesContext(
  scope: PolicyScope,
  context: EnhancedGuardContext
): Promise<boolean> {
  switch (scope.type) {
    case 'global':
      return true;

    case 'organization':
      return context.organization?.id === scope.id;

    case 'team':
      return context.identity?.teams?.includes(scope.id!) ?? false;

    case 'project':
      // Project would come from session state or context
      return context.session?.state?.projectId === scope.id;

    case 'role':
      return context.roles?.includes(scope.id!) ?? false;

    case 'user':
      return context.identity?.id === scope.id;

    default:
      return false;
  }
}

/**
 * Sort policies by hierarchy and priority
 */
function sortPolicies(policies: ScopedPolicy[]): ScopedPolicy[] {
  const scopeOrder: Record<PolicyScopeType, number> = {
    global: 0,
    organization: 1,
    team: 2,
    project: 3,
    role: 4,
    user: 5,
  };

  return policies.sort((a, b) => {
    // First by scope type (global first, user last)
    const scopeDiff = scopeOrder[a.scope.type] - scopeOrder[b.scope.type];
    if (scopeDiff !== 0) return scopeDiff;

    // Then by priority (higher priority applied later = wins)
    return a.priority - b.priority;
  });
}

/**
 * Evaluate scope conditions
 */
async function evaluateConditions(
  conditions: ScopeCondition[] | undefined,
  context: EnhancedGuardContext
): Promise<boolean> {
  if (!conditions || conditions.length === 0) return true;

  // All conditions must match (AND logic)
  for (const condition of conditions) {
    if (!(await evaluateCondition(condition, context))) {
      return false;
    }
  }
  return true;
}

/**
 * Evaluate single condition
 */
async function evaluateCondition(
  condition: ScopeCondition,
  context: EnhancedGuardContext
): Promise<boolean> {
  switch (condition.type) {
    case 'identity_attribute':
      return evaluateIdentityCondition(condition.config as IdentityCondition, context);

    case 'request_context':
      return evaluateRequestCondition(condition.config as RequestCondition, context);

    case 'time':
      return evaluateTimeCondition(condition.config as TimeCondition);

    case 'custom':
      return evaluateCustomCondition(condition.config as CustomCondition, context);

    default:
      return false;
  }
}
```

### Condition Evaluation

```typescript
/**
 * Evaluate identity-based condition
 */
function evaluateIdentityCondition(
  condition: IdentityCondition,
  context: EnhancedGuardContext
): boolean {
  const value = getNestedValue(context.identity, condition.attribute);

  switch (condition.operator) {
    case 'eq':
      return value === condition.value;

    case 'ne':
      return value !== condition.value;

    case 'in':
      return Array.isArray(condition.value) && condition.value.includes(value);

    case 'not_in':
      return Array.isArray(condition.value) && !condition.value.includes(value);

    case 'contains':
      return Array.isArray(value) && value.includes(condition.value);

    case 'matches':
      return typeof value === 'string' &&
             new RegExp(condition.value as string).test(value);

    default:
      return false;
  }
}

/**
 * Evaluate time-based condition
 */
function evaluateTimeCondition(condition: TimeCondition): boolean {
  const now = condition.timezone
    ? new Date().toLocaleString('en-US', { timeZone: condition.timezone })
    : new Date();
  const date = new Date(now);

  // Check hours
  if (condition.validHours) {
    const hour = date.getHours();
    if (hour < condition.validHours.start || hour >= condition.validHours.end) {
      return false;
    }
  }

  // Check days
  if (condition.validDays) {
    const day = date.getDay();
    if (!condition.validDays.includes(day)) {
      return false;
    }
  }

  // Check date range
  if (condition.dateRange) {
    const start = new Date(condition.dateRange.start);
    const end = new Date(condition.dateRange.end);
    if (date < start || date > end) {
      return false;
    }
  }

  return true;
}
```

### Policy Merging

```typescript
/**
 * Merge child policy into base policy
 */
function mergePolicy(
  base: Policy,
  child: Policy,
  strategy: MergeStrategy
): Policy {
  switch (strategy) {
    case 'replace':
      return child;

    case 'merge':
      return shallowMerge(base, child);

    case 'deep_merge':
    default:
      return deepMerge(base, child);
  }
}

/**
 * Deep merge policies
 */
function deepMerge(base: Policy, child: Policy): Policy {
  return {
    version: child.version || base.version,
    name: child.name || base.name,
    description: child.description || base.description,

    // Deep merge guards
    guards: deepMergeGuards(base.guards, child.guards),

    // Deep merge settings
    settings: {
      ...base.settings,
      ...child.settings,
    },

    // Child on_violation overrides
    on_violation: child.on_violation ?? base.on_violation,
  };
}

/**
 * Deep merge guard configurations
 */
function deepMergeGuards(base: GuardConfigs, child: GuardConfigs): GuardConfigs {
  return {
    forbidden_path: mergeGuardConfig(base.forbidden_path, child.forbidden_path),
    egress_allowlist: mergeGuardConfig(base.egress_allowlist, child.egress_allowlist),
    secret_leak: mergeGuardConfig(base.secret_leak, child.secret_leak),
    patch_integrity: mergeGuardConfig(base.patch_integrity, child.patch_integrity),
    mcp_tool: mergeGuardConfig(base.mcp_tool, child.mcp_tool),
    prompt_injection: mergeGuardConfig(base.prompt_injection, child.prompt_injection),
  };
}

/**
 * Merge individual guard config
 */
function mergeGuardConfig<T extends object>(
  base: T | undefined,
  child: T | undefined
): T | undefined {
  if (!child) return base;
  if (!base) return child;

  // Handle array fields specially (concatenate with additional_*, remove with remove_*)
  const merged = { ...base } as Record<string, unknown>;

  for (const [key, value] of Object.entries(child)) {
    if (key.startsWith('additional_') && Array.isArray(value)) {
      const baseKey = key.replace('additional_', '');
      const baseArray = (merged[baseKey] as unknown[]) || [];
      merged[baseKey] = [...baseArray, ...value];
    } else if (key.startsWith('remove_') && Array.isArray(value)) {
      const baseKey = key.replace('remove_', '');
      const baseArray = (merged[baseKey] as unknown[]) || [];
      merged[baseKey] = baseArray.filter(v => !value.includes(v));
    } else {
      merged[key] = value;
    }
  }

  return merged as T;
}
```

## Multi-Tenancy Considerations

### Organization Policy Isolation

```typescript
/**
 * Ensure policies are isolated by organization
 */
class OrganizationIsolatedPolicyStore implements PolicyStore {
  async getPolicy(id: string, orgId: string): Promise<ScopedPolicy | null> {
    const policy = await this.backend.get(id);

    // Verify policy belongs to organization or is global
    if (policy && policy.scope.type !== 'global') {
      if (!this.isPolicyInOrg(policy, orgId)) {
        throw new SecurityError('Policy not accessible from this organization');
      }
    }

    return policy;
  }

  async listPoliciesByScope(
    scope: PolicyScope,
    orgId: string
  ): Promise<ScopedPolicy[]> {
    // Only return policies within the organization hierarchy
    const allPolicies = await this.backend.listByScope(scope);
    return allPolicies.filter(p =>
      p.scope.type === 'global' || this.isPolicyInOrg(p, orgId)
    );
  }

  private isPolicyInOrg(policy: ScopedPolicy, orgId: string): boolean {
    let scope: PolicyScope | undefined = policy.scope;
    while (scope) {
      if (scope.type === 'organization' && scope.id === orgId) {
        return true;
      }
      scope = scope.parent;
    }
    return false;
  }
}
```

### Policy Inheritance Boundary Enforcement

Policies cannot inherit from or extend policies outside their organizational boundary:

```typescript
/**
 * Validate policy extension is within org boundary
 */
async function validatePolicyExtension(
  policy: ScopedPolicy,
  orgId: string
): Promise<ValidationResult> {
  const errors: string[] = [];

  if (policy.extends) {
    const parentPolicy = await policyStore.getPolicy(policy.extends);

    if (!parentPolicy) {
      errors.push(`Extended policy '${policy.extends}' not found`);
      return { valid: false, errors };
    }

    // Global policies can be extended by anyone
    if (parentPolicy.scope.type === 'global') {
      return { valid: true, errors: [] };
    }

    // Verify parent is in same org hierarchy
    if (!isPolicyInOrgHierarchy(parentPolicy, orgId)) {
      errors.push(`Cannot extend policy '${policy.extends}' from different organization`);
    }

    // Verify no circular dependencies
    if (await hasCircularDependency(policy.id, policy.extends)) {
      errors.push(`Circular dependency detected: ${policy.id} -> ${policy.extends}`);
    }
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Check for circular policy dependencies
 */
async function hasCircularDependency(policyId: string, extendsId: string): Promise<boolean> {
  const visited = new Set<string>([policyId]);
  let current = extendsId;

  while (current) {
    if (visited.has(current)) return true;
    visited.add(current);

    const policy = await policyStore.getPolicy(current);
    if (!policy?.extends) break;
    current = policy.extends;
  }

  return false;
}
```

### Cross-Tenant Policy Templates

```typescript
/**
 * Global policy templates that orgs can adopt
 */
interface PolicyTemplate {
  /** Template ID */
  id: string;

  /** Template name */
  name: string;

  /** Description */
  description: string;

  /** The policy configuration */
  policy: Policy;

  /** Whether orgs can customize */
  allowCustomization: boolean;

  /** Which parts can be customized */
  customizableFields?: string[];
}

/**
 * Adopt a template for an organization
 */
async function adoptPolicyTemplate(
  templateId: string,
  orgId: string,
  customizations?: Partial<Policy>
): Promise<ScopedPolicy> {
  const template = await getTemplate(templateId);

  // Validate customizations are allowed
  if (customizations && !template.allowCustomization) {
    throw new Error('Template does not allow customization');
  }

  if (customizations && template.customizableFields) {
    for (const field of Object.keys(customizations)) {
      if (!template.customizableFields.includes(field)) {
        throw new Error(`Field '${field}' is not customizable`);
      }
    }
  }

  // Create scoped policy from template
  const scopedPolicy: ScopedPolicy = {
    id: generateId(),
    name: `${template.name} (${orgId})`,
    scope: { type: 'organization', id: orgId },
    priority: 0,
    extends: templateId,
    mergeStrategy: 'deep_merge',
    policy: customizations || {},
    enabled: true,
    metadata: {
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      createdBy: 'system',
      description: `Adopted from template: ${template.name}`,
      tags: ['from-template', templateId],
    },
  };

  await policyStore.savePolicy(scopedPolicy);
  return scopedPolicy;
}
```

## Security Considerations

### Policy Resolution Rate Limiting

Policy resolution can be computationally expensive. Implement rate limiting to prevent abuse:

```typescript
/**
 * Rate limit policy resolution to prevent DoS
 */
interface PolicyResolutionRateLimiter {
  /**
   * Check if resolution is allowed
   */
  checkLimit(orgId: string, userId: string): Promise<{
    allowed: boolean;
    retryAfterMs?: number;
  }>;
}

class SlidingWindowRateLimiter implements PolicyResolutionRateLimiter {
  private readonly maxResolutionsPerMinute = 100;
  private readonly maxResolutionsPerHour = 1000;

  async checkLimit(orgId: string, userId: string): Promise<{ allowed: boolean; retryAfterMs?: number }> {
    const minuteKey = `policy:ratelimit:${orgId}:${userId}:minute`;
    const hourKey = `policy:ratelimit:${orgId}:${userId}:hour`;

    const [minuteCount, hourCount] = await Promise.all([
      this.redis.incr(minuteKey),
      this.redis.incr(hourKey),
    ]);

    // Set expiry on first request
    if (minuteCount === 1) await this.redis.expire(minuteKey, 60);
    if (hourCount === 1) await this.redis.expire(hourKey, 3600);

    if (minuteCount > this.maxResolutionsPerMinute) {
      const ttl = await this.redis.ttl(minuteKey);
      return { allowed: false, retryAfterMs: ttl * 1000 };
    }

    if (hourCount > this.maxResolutionsPerHour) {
      const ttl = await this.redis.ttl(hourKey);
      return { allowed: false, retryAfterMs: ttl * 1000 };
    }

    return { allowed: true };
  }
}
```

### Policy Escalation Prevention

```typescript
/**
 * Prevent lower-scoped policies from escalating privileges
 */
function validatePolicyEscalation(
  childPolicy: ScopedPolicy,
  parentPolicy: Policy
): ValidationResult {
  const errors: string[] = [];

  // Check that child doesn't allow more than parent
  const childGuards = childPolicy.policy.guards;
  const parentGuards = parentPolicy.guards;

  // Egress: child cannot add domains parent doesn't allow
  if (childGuards?.egress_allowlist?.additional_allow) {
    for (const domain of childGuards.egress_allowlist.additional_allow) {
      if (!isDomainAllowedByParent(domain, parentGuards?.egress_allowlist)) {
        errors.push(`Cannot add egress domain '${domain}' - not allowed by parent policy`);
      }
    }
  }

  // Forbidden paths: child cannot remove parent's forbidden paths
  if (childGuards?.forbidden_path?.remove_patterns) {
    for (const pattern of childGuards.forbidden_path.remove_patterns) {
      if (isPatternRequiredByParent(pattern, parentGuards?.forbidden_path)) {
        errors.push(`Cannot remove forbidden path '${pattern}' - required by parent policy`);
      }
    }
  }

  // Tools: child cannot enable tools parent blocks
  if (childGuards?.mcp_tool?.allow) {
    const parentBlocked = parentGuards?.mcp_tool?.block || [];
    for (const tool of childGuards.mcp_tool.allow) {
      if (parentBlocked.includes(tool)) {
        errors.push(`Cannot allow tool '${tool}' - blocked by parent policy`);
      }
    }
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}
```

### Audit Trail for Policy Changes

```typescript
/**
 * All policy changes are logged
 */
interface PolicyAuditEvent {
  eventType: 'created' | 'updated' | 'deleted' | 'assigned' | 'unassigned' | 'enabled' | 'disabled';
  timestamp: string;
  actor: {
    type: 'user' | 'service_account';
    id: string;
  };
  target: {
    type: 'policy' | 'assignment';
    id: string;
  };
  scope?: PolicyScope;
  changes?: {
    before?: unknown;
    after?: unknown;
  };
  reason?: string;
}

class AuditingPolicyResolver implements PolicyResolver {
  async registerPolicy(policy: ScopedPolicy): Promise<void> {
    await this.inner.registerPolicy(policy);

    await this.audit.log({
      eventType: 'created',
      timestamp: new Date().toISOString(),
      actor: this.getCurrentActor(),
      target: { type: 'policy', id: policy.id },
      scope: policy.scope,
      changes: { after: policy },
    });
  }

  async updatePolicy(
    policyId: string,
    updates: Partial<ScopedPolicy>
  ): Promise<ScopedPolicy> {
    const before = await this.inner.getPolicy(policyId);
    const after = await this.inner.updatePolicy(policyId, updates);

    await this.audit.log({
      eventType: 'updated',
      timestamp: new Date().toISOString(),
      actor: this.getCurrentActor(),
      target: { type: 'policy', id: policyId },
      changes: { before, after },
    });

    return after;
  }
}
```

## Configuration Examples

### Complete Policy Scoping Configuration

```yaml
# Policy scoping configuration
policyScoping:
  # Enable scoped policies
  enabled: true

  # Default/global policy
  defaultPolicy:
    extends: clawdstrike:ai-agent
    guards:
      egress_allowlist:
        default_action: block
      forbidden_path:
        patterns:
          - "**/.ssh/**"
          - "**/.aws/**"

  # Cache settings
  cache:
    enabled: true
    ttlSeconds: 60
    maxEntries: 1000

  # Escalation prevention
  escalationPrevention:
    enabled: true
    # Fields that child policies cannot override
    lockedFields:
      - guards.forbidden_path.patterns
      - guards.secret_leak.patterns

  # Custom condition evaluators
  customConditions:
    is_incident:
      type: external
      endpoint: http://incident-service/api/check
    is_high_risk_action:
      type: inline
      function: |
        (ctx) => ctx.session?.state?.riskScore > 0.8

# Scoped policies
scopedPolicies:
  # Organization-level policy
  - id: acme-org-policy
    name: Acme Corp Policy
    scope:
      type: organization
      id: org_acme
    priority: 100
    extends: default
    policy:
      guards:
        egress_allowlist:
          additional_allow:
            - "*.acme.com"
            - "internal.acme-api.com"

  # Team-level policy
  - id: security-team-policy
    name: Security Team Policy
    scope:
      type: team
      id: team_security
    priority: 200
    policy:
      guards:
        forbidden_path:
          # Security team can access logs
          exceptions:
            - "/var/log/security/**"
            - "/var/log/audit/**"

  # Role-based policy
  - id: senior-engineer-policy
    name: Senior Engineer Policy
    scope:
      type: role
      id: senior-engineer
    priority: 300
    policy:
      guards:
        mcp_tool:
          allow:
            - deploy
            - kubectl

  # Time-based policy
  - id: after-hours-policy
    name: After Hours Restrictions
    scope:
      type: global
      conditions:
        - type: time
          config:
            validHours:
              start: 18
              end: 9
            validDays: [0, 6]  # Weekends
    priority: 500  # High priority to override others
    policy:
      guards:
        mcp_tool:
          additional_block:
            - deploy
            - publish

  # Risk-based policy
  - id: high-risk-context-policy
    name: High Risk Context Restrictions
    scope:
      type: global
      conditions:
        - type: request_context
          config:
            field: isVpn
            operator: eq
            value: false
        - type: request_context
          config:
            field: geoLocation.country
            operator: not_in
            value: [US, CA, GB]
    priority: 600
    policy:
      guards:
        forbidden_path:
          additional_patterns:
            - "**/production/**"
            - "**/secrets/**"
        mcp_tool:
          additional_block:
            - deploy
            - kubectl

  # User exception policy
  - id: user-incident-exception
    name: Incident Investigation Exception
    scope:
      type: user
      id: user_alice
      conditions:
        - type: time
          config:
            dateRange:
              start: "2024-01-15T00:00:00Z"
              end: "2024-01-22T23:59:59Z"
    priority: 1000  # Highest priority
    policy:
      guards:
        forbidden_path:
          exceptions:
            - "/var/log/compromised-service/**"
```

### Integration with Engine

```typescript
// Initialize policy resolver
const policyResolver = createPolicyResolver({
  store: 'postgres',
  storageConfig: { connectionString: process.env.DATABASE_URL },
  defaultPolicy: defaultPolicy,
  cache: { enabled: true, ttlSeconds: 60, maxEntries: 1000 },
});

// Register custom condition
policyResolver.registerConditionEvaluator('is_incident', async (context) => {
  const response = await fetch('http://incident-service/api/check', {
    method: 'POST',
    body: JSON.stringify({ sessionId: context.sessionId }),
  });
  const data = await response.json();
  return data.hasActiveIncident;
});

// Use in engine
class ScopedPolicyEngine {
  async evaluate(event: PolicyEvent, context: EnhancedGuardContext): Promise<Decision> {
    // Resolve policy for this context
    const resolved = await this.policyResolver.resolvePolicy(context);

    // Log which policies applied
    this.logger.debug('Policy resolved', {
      contributingPolicies: resolved.contributingPolicies.map(p => p.name),
    });

    // Create engine with resolved policy
    const engine = new PolicyEngine({
      policy: resolved.policy,
      mode: this.config.mode,
    });

    return engine.evaluate(event);
  }
}
```

## Implementation Phases

### Phase 1: Core Scoping (2 weeks)
- Policy scope data model
- Basic scope matching (global, org, team, user)
- Policy merging logic
- In-memory policy store

### Phase 2: Conditions (1 week)
- Identity attribute conditions
- Request context conditions
- Time-based conditions
- Custom condition evaluators

### Phase 3: Policy Management (1 week)
- Policy CRUD API
- Assignment management
- PostgreSQL policy store
- Policy validation

### Phase 4: Advanced Features (2 weeks)
- Policy hierarchy resolution
- Escalation prevention
- Policy templates
- Audit logging

### Phase 5: Performance (1 week)
- Policy caching
- Resolution optimization
- Lazy loading
- Cache invalidation

## Testing Strategy

### Unit Tests
- Scope matching logic
- Condition evaluation
- Policy merging
- Priority sorting

### Integration Tests
- Full policy resolution flow
- Multi-scope scenarios
- Cache behavior
- Database storage

### Security Tests
- Escalation prevention
- Cross-org isolation
- Condition bypass attempts

## Dependencies

- Existing Clawdstrike policy types
- Session context (from session-context.md)
- RBAC (from rbac.md)
- Storage: `sqlx`, `redis`, `serde_json`
