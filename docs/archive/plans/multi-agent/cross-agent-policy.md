# Cross-Agent Policy Specification

## Problem Statement

In multi-agent systems, resources created or accessed by one agent must be protected from unauthorized access by other agents. Without explicit cross-agent policy enforcement:

1. **Data Leakage**: Agent A writes sensitive data that Agent B can read without authorization
2. **Resource Conflicts**: Multiple agents modify the same resource leading to corruption
3. **Privilege Confusion**: Agent A's high-privilege access is indirectly available to Agent B
4. **Audit Gaps**: No visibility into which agent accessed which resource

## Threat Model

### Attack Scenarios

#### Scenario 1: Indirect Data Exfiltration

```
Research-Agent writes /tmp/findings.json (contains API analysis)
                    |
                    v
Malicious-Agent reads /tmp/findings.json
                    |
                    v
Malicious-Agent exfiltrates via allowed egress
```

**Without Cross-Agent Policy**: Default filesystem permissions allow any agent to read `/tmp/`

**With Cross-Agent Policy**: Read denied because `malicious-agent` has no delegation from `research-agent`

#### Scenario 2: Confused Deputy via Shared Filesystem

```
Attacker controls file content via Agent A
                    |
                    v
Agent A writes malicious config to /workspace/.tool-config
                    |
                    v
Agent B reads config and executes malicious instructions
```

**Mitigation**: Cross-agent policy requires Agent B to explicitly accept files from Agent A's write set

#### Scenario 3: Privilege Escalation via Resource Tainting

```
Low-privilege Agent writes /workspace/deploy.sh
                    |
                    v
High-privilege Agent executes /workspace/deploy.sh
```

**Mitigation**: Execution policy checks resource provenance (who wrote it)

### Threat Actors

| Actor | Capabilities | Goals |
|-------|--------------|-------|
| Compromised Agent | Full control of one agent | Lateral movement to other agents |
| Prompt Injection | Influence agent behavior via content | Execute unauthorized actions |
| Malicious Orchestrator | Deploy rogue agents | Access sensitive resources |
| Insider | Deploy agents with excessive permissions | Data exfiltration |

## Architecture

### Resource Ownership Model

Every resource in the system has an owner:

```
+------------------+
| Resource         |
+------------------+
| path: string     |
| owner: AgentId   |
| created_at: Time |
| acl: AccessList  |
+------------------+
        |
        v
+------------------+
| AccessList       |
+------------------+
| entries: [       |
|   {              |
|     agent: Id,   |
|     perms: Set,  |
|     granted_by,  |
|     expires_at   |
|   }              |
| ]                |
+------------------+
```

### Policy Evaluation Flow

```
+----------------+     +-------------------+     +------------------+
| Agent Request  | --> | Resource Lookup   | --> | Ownership Check  |
| (read /path)   |     | (who owns /path?) |     | (is agent owner?)|
+----------------+     +-------------------+     +--------+---------+
                                                         |
                              +----------------+---------+
                              |                |
                              v                v
                        +----------+    +--------------+
                        | ALLOW    |    | ACL Check    |
                        | (owner)  |    | (delegation?)|
                        +----------+    +------+-------+
                                               |
                              +----------------+----------------+
                              |                |                |
                              v                v                v
                        +----------+    +-----------+    +----------+
                        | ALLOW    |    | DENY      |    | ESCALATE |
                        | (has ACL)|    | (no ACL)  |    | (needs   |
                        +----------+    +-----------+    | approval)|
                                                         +----------+
```

### Cross-Agent Guard Implementation

```
+------------------------------------------------------------------+
|                      CrossAgentGuard                              |
+------------------------------------------------------------------+
| - resource_registry: ResourceRegistry                             |
| - policy: CrossAgentPolicy                                        |
| - delegation_verifier: DelegationVerifier                         |
+------------------------------------------------------------------+
| + check(action, context) -> GuardResult                           |
| + register_resource(path, owner) -> Result<ResourceId>            |
| + transfer_ownership(path, from, to) -> Result<()>                |
| + grant_access(path, owner, grantee, perms) -> Result<()>         |
| + revoke_access(path, owner, grantee) -> Result<()>               |
+------------------------------------------------------------------+
```

## API Design

### TypeScript Interface

```typescript
/**
 * Cross-agent policy configuration
 */
export interface CrossAgentPolicy {
  /** Policy version */
  version: string;

  /** Default action when no rule matches */
  defaultAction: 'deny' | 'allow' | 'audit';

  /** Agent-to-agent rules */
  rules: CrossAgentRule[];

  /** Resource isolation settings */
  isolation: IsolationConfig;
}

/**
 * Rule for cross-agent access
 */
export interface CrossAgentRule {
  /** Source agent ID or pattern */
  from: string | string[];

  /** Target agent ID or pattern */
  to: string | string[];

  /** Allowed capabilities */
  allow: Capability[];

  /** Denied capabilities (takes precedence) */
  deny?: Capability[];

  /** Whether delegation token is required */
  requireDelegation?: boolean;

  /** Maximum delegation TTL */
  maxDelegationTtl?: string;

  /** Additional approval requirements */
  requireApproval?: ApprovalRequirement[];

  /** Conditions for rule application */
  conditions?: RuleCondition[];
}

/**
 * Capability specification
 */
export type Capability =
  | `file:read:${string}`
  | `file:write:${string}`
  | `file:execute:${string}`
  | `network:egress:${string}`
  | `secret:read:${string}`
  | `tool:invoke:${string}`;

/**
 * Resource ownership record
 */
export interface ResourceOwnership {
  /** Resource path or identifier */
  resourceId: string;

  /** Owning agent ID */
  owner: AgentId;

  /** Creation timestamp */
  createdAt: Date;

  /** Access control list */
  acl: AccessControlEntry[];

  /** Resource metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Access control entry
 */
export interface AccessControlEntry {
  /** Grantee agent ID */
  agent: AgentId;

  /** Granted permissions */
  permissions: Permission[];

  /** Who granted this access */
  grantedBy: AgentId;

  /** When the grant expires */
  expiresAt?: Date;

  /** Delegation token if applicable */
  delegationToken?: string;
}

/**
 * Permission types
 */
export type Permission = 'read' | 'write' | 'execute' | 'delete' | 'grant';

/**
 * Cross-agent guard for policy enforcement
 */
export class CrossAgentGuard implements Guard {
  private registry: ResourceRegistry;
  private policy: CrossAgentPolicy;
  private delegationVerifier: DelegationVerifier;

  constructor(config: CrossAgentGuardConfig) {
    this.registry = new ResourceRegistry(config.registryBackend);
    this.policy = config.policy;
    this.delegationVerifier = new DelegationVerifier(config.tokenVerifier);
  }

  /**
   * Check if an action is allowed under cross-agent policy
   */
  async check(
    action: GuardAction,
    context: GuardContext
  ): Promise<GuardResult> {
    const agentId = context.agentId;
    if (!agentId) {
      return GuardResult.deny('cross_agent', 'critical', 'No agent ID in context');
    }

    // Extract resource from action
    const resource = this.extractResource(action);
    if (!resource) {
      return GuardResult.allow('cross_agent');
    }

    // Check ownership
    const ownership = await this.registry.getOwnership(resource);

    // Unowned resources: apply default policy
    if (!ownership) {
      return this.applyDefaultPolicy(action, context);
    }

    // Owner always has access
    if (ownership.owner === agentId) {
      return GuardResult.allow('cross_agent');
    }

    // Check ACL
    const permission = this.actionToPermission(action);
    const aclEntry = ownership.acl.find(e =>
      e.agent === agentId &&
      e.permissions.includes(permission) &&
      (!e.expiresAt || e.expiresAt > new Date())
    );

    if (aclEntry) {
      // Verify delegation token if present
      if (aclEntry.delegationToken) {
        const valid = await this.delegationVerifier.verify(
          aclEntry.delegationToken,
          { agent: agentId, resource, permission }
        );
        if (!valid) {
          return GuardResult.deny(
            'cross_agent',
            'error',
            'Invalid or expired delegation token'
          );
        }
      }
      return GuardResult.allow('cross_agent');
    }

    // Check policy rules
    return this.evaluateRules(action, context, ownership);
  }

  /**
   * Register a new resource with ownership
   */
  async registerResource(
    path: string,
    owner: AgentId,
    metadata?: Record<string, unknown>
  ): Promise<ResourceOwnership> {
    const existing = await this.registry.getOwnership(path);
    if (existing) {
      throw new Error(`Resource already owned by ${existing.owner}`);
    }

    const ownership: ResourceOwnership = {
      resourceId: path,
      owner,
      createdAt: new Date(),
      acl: [],
      metadata
    };

    await this.registry.setOwnership(ownership);
    return ownership;
  }

  /**
   * Grant access to another agent
   */
  async grantAccess(
    path: string,
    grantingAgent: AgentId,
    granteeAgent: AgentId,
    permissions: Permission[],
    options?: {
      expiresAt?: Date;
      delegationToken?: string;
    }
  ): Promise<void> {
    const ownership = await this.registry.getOwnership(path);
    if (!ownership) {
      throw new Error('Resource not found');
    }

    // Only owner or agents with 'grant' permission can grant
    const canGrant = ownership.owner === grantingAgent ||
      ownership.acl.some(e =>
        e.agent === grantingAgent &&
        e.permissions.includes('grant')
      );

    if (!canGrant) {
      throw new Error('Agent does not have grant permission');
    }

    // Add or update ACL entry
    const existingIndex = ownership.acl.findIndex(e => e.agent === granteeAgent);
    const entry: AccessControlEntry = {
      agent: granteeAgent,
      permissions,
      grantedBy: grantingAgent,
      expiresAt: options?.expiresAt,
      delegationToken: options?.delegationToken
    };

    if (existingIndex >= 0) {
      ownership.acl[existingIndex] = entry;
    } else {
      ownership.acl.push(entry);
    }

    await this.registry.setOwnership(ownership);
  }

  /**
   * Revoke access from an agent
   */
  async revokeAccess(
    path: string,
    revokingAgent: AgentId,
    revokedAgent: AgentId
  ): Promise<void> {
    const ownership = await this.registry.getOwnership(path);
    if (!ownership) {
      throw new Error('Resource not found');
    }

    // Only owner can revoke
    if (ownership.owner !== revokingAgent) {
      throw new Error('Only owner can revoke access');
    }

    ownership.acl = ownership.acl.filter(e => e.agent !== revokedAgent);
    await this.registry.setOwnership(ownership);
  }

  private extractResource(action: GuardAction): string | null {
    switch (action.type) {
      case 'FileAccess':
      case 'FileWrite':
        return action.path;
      case 'Patch':
        return action.filePath;
      default:
        return null;
    }
  }

  private actionToPermission(action: GuardAction): Permission {
    switch (action.type) {
      case 'FileAccess':
        return 'read';
      case 'FileWrite':
      case 'Patch':
        return 'write';
      default:
        return 'read';
    }
  }

  private applyDefaultPolicy(
    action: GuardAction,
    context: GuardContext
  ): GuardResult {
    switch (this.policy.defaultAction) {
      case 'allow':
        return GuardResult.allow('cross_agent');
      case 'audit':
        return GuardResult.warn('cross_agent', 'Unowned resource access (auditing)');
      case 'deny':
      default:
        return GuardResult.deny(
          'cross_agent',
          'error',
          'Access to unowned resource denied by default policy'
        );
    }
  }

  private async evaluateRules(
    action: GuardAction,
    context: GuardContext,
    ownership: ResourceOwnership
  ): Promise<GuardResult> {
    const fromAgent = context.agentId!;
    const toAgent = ownership.owner;
    const resource = this.extractResource(action)!;
    const capability = this.actionToCapability(action);

    for (const rule of this.policy.rules) {
      // Check if rule applies to this agent pair
      if (!this.ruleApplies(rule, fromAgent, toAgent)) {
        continue;
      }

      // Check deny first (precedence)
      if (rule.deny?.some(cap => this.capabilityMatches(cap, capability, resource))) {
        return GuardResult.deny(
          'cross_agent',
          'error',
          `Capability ${capability} explicitly denied by cross-agent rule`
        );
      }

      // Check allow
      if (rule.allow.some(cap => this.capabilityMatches(cap, capability, resource))) {
        // Check if delegation required
        if (rule.requireDelegation) {
          const token = context.metadata?.delegationToken as string | undefined;
          if (!token) {
            return GuardResult.deny(
              'cross_agent',
              'error',
              'Delegation token required for this cross-agent access'
            );
          }
          const valid = await this.delegationVerifier.verify(token, {
            agent: fromAgent,
            resource,
            permission: this.actionToPermission(action)
          });
          if (!valid) {
            return GuardResult.deny(
              'cross_agent',
              'error',
              'Invalid delegation token'
            );
          }
        }

        // Check approval requirements
        if (rule.requireApproval?.length) {
          // This would integrate with approval workflow
          return GuardResult.deny(
            'cross_agent',
            'warning',
            `Approval required from: ${rule.requireApproval.join(', ')}`
          );
        }

        return GuardResult.allow('cross_agent');
      }
    }

    // No matching rule - apply default
    return GuardResult.deny(
      'cross_agent',
      'error',
      `No cross-agent rule allows ${fromAgent} to access ${toAgent}'s resource`
    );
  }

  private ruleApplies(rule: CrossAgentRule, from: AgentId, to: AgentId): boolean {
    const fromMatches = Array.isArray(rule.from)
      ? rule.from.some(p => this.agentMatches(p, from))
      : this.agentMatches(rule.from, from);

    const toMatches = Array.isArray(rule.to)
      ? rule.to.some(p => this.agentMatches(p, to))
      : this.agentMatches(rule.to, to);

    return fromMatches && toMatches;
  }

  private agentMatches(pattern: string, agent: AgentId): boolean {
    if (pattern === '*') return true;
    if (pattern.endsWith('*')) {
      return agent.startsWith(pattern.slice(0, -1));
    }
    return pattern === agent;
  }

  private actionToCapability(action: GuardAction): string {
    switch (action.type) {
      case 'FileAccess':
        return `file:read:${action.path}`;
      case 'FileWrite':
        return `file:write:${action.path}`;
      case 'Patch':
        return `file:write:${action.filePath}`;
      case 'NetworkEgress':
        return `network:egress:${action.host}`;
      default:
        return 'unknown';
    }
  }

  private capabilityMatches(pattern: Capability, actual: string, resource: string): boolean {
    const [patternType, patternAction, patternResource] = pattern.split(':');
    const [actualType, actualAction] = actual.split(':');

    if (patternType !== actualType) return false;
    if (patternAction !== actualAction) return false;

    // Glob match on resource
    return this.globMatch(patternResource, resource);
  }

  private globMatch(pattern: string, value: string): boolean {
    if (pattern === '*') return true;
    if (pattern.endsWith('/**')) {
      const prefix = pattern.slice(0, -3);
      return value.startsWith(prefix);
    }
    if (pattern.includes('*')) {
      const regex = new RegExp('^' + pattern.replace(/\*/g, '[^/]*') + '$');
      return regex.test(value);
    }
    return pattern === value;
  }
}

/**
 * Resource registry for tracking ownership
 */
export interface ResourceRegistry {
  getOwnership(resourceId: string): Promise<ResourceOwnership | null>;
  setOwnership(ownership: ResourceOwnership): Promise<void>;
  deleteOwnership(resourceId: string): Promise<void>;
  listByOwner(owner: AgentId): Promise<ResourceOwnership[]>;
}

/**
 * In-memory resource registry (for testing/single-node)
 */
export class InMemoryResourceRegistry implements ResourceRegistry {
  private resources = new Map<string, ResourceOwnership>();

  async getOwnership(resourceId: string): Promise<ResourceOwnership | null> {
    return this.resources.get(resourceId) ?? null;
  }

  async setOwnership(ownership: ResourceOwnership): Promise<void> {
    this.resources.set(ownership.resourceId, ownership);
  }

  async deleteOwnership(resourceId: string): Promise<void> {
    this.resources.delete(resourceId);
  }

  async listByOwner(owner: AgentId): Promise<ResourceOwnership[]> {
    return Array.from(this.resources.values()).filter(r => r.owner === owner);
  }
}
```

### Rust Interface

```rust
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};

/// Agent identifier
pub type AgentId = String;

/// Cross-agent policy configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrossAgentPolicy {
    pub version: String,
    pub default_action: DefaultAction,
    pub rules: Vec<CrossAgentRule>,
    pub isolation: IsolationConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultAction {
    Deny,
    Allow,
    Audit,
}

/// Cross-agent rule
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrossAgentRule {
    pub from: AgentPattern,
    pub to: AgentPattern,
    pub allow: Vec<Capability>,
    #[serde(default)]
    pub deny: Vec<Capability>,
    #[serde(default)]
    pub require_delegation: bool,
    pub max_delegation_ttl: Option<String>,
    #[serde(default)]
    pub require_approval: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AgentPattern {
    Single(String),
    Multiple(Vec<String>),
}

/// Capability specification
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Capability(String);

impl Capability {
    pub fn file_read(path: &str) -> Self {
        Self(format!("file:read:{}", path))
    }

    pub fn file_write(path: &str) -> Self {
        Self(format!("file:write:{}", path))
    }

    pub fn network_egress(host: &str) -> Self {
        Self(format!("network:egress:{}", host))
    }

    pub fn matches(&self, action: &str, resource: &str) -> bool {
        let parts: Vec<&str> = self.0.split(':').collect();
        if parts.len() < 3 {
            return false;
        }

        let action_parts: Vec<&str> = action.split(':').collect();
        if action_parts.len() < 2 {
            return false;
        }

        if parts[0] != action_parts[0] || parts[1] != action_parts[1] {
            return false;
        }

        glob_match(parts[2], resource)
    }
}

fn glob_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if pattern.ends_with("/**") {
        let prefix = &pattern[..pattern.len() - 3];
        return value.starts_with(prefix);
    }
    if pattern.contains('*') {
        let regex_pattern = format!("^{}$", pattern.replace("*", "[^/]*"));
        if let Ok(re) = regex::Regex::new(&regex_pattern) {
            return re.is_match(value);
        }
    }
    pattern == value
}

/// Resource ownership record
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResourceOwnership {
    pub resource_id: String,
    pub owner: AgentId,
    pub created_at: DateTime<Utc>,
    pub acl: Vec<AccessControlEntry>,
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Access control entry
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessControlEntry {
    pub agent: AgentId,
    pub permissions: Vec<Permission>,
    pub granted_by: AgentId,
    pub expires_at: Option<DateTime<Utc>>,
    pub delegation_token: Option<String>,
}

/// Permission types
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Permission {
    Read,
    Write,
    Execute,
    Delete,
    Grant,
}

/// Cross-agent guard
pub struct CrossAgentGuard {
    registry: Arc<dyn ResourceRegistry>,
    policy: CrossAgentPolicy,
    delegation_verifier: Arc<dyn DelegationVerifier>,
}

impl CrossAgentGuard {
    pub fn new(
        registry: Arc<dyn ResourceRegistry>,
        policy: CrossAgentPolicy,
        delegation_verifier: Arc<dyn DelegationVerifier>,
    ) -> Self {
        Self {
            registry,
            policy,
            delegation_verifier,
        }
    }

    pub async fn check(
        &self,
        action: &GuardAction<'_>,
        context: &GuardContext,
    ) -> GuardResult {
        let agent_id = match &context.agent_id {
            Some(id) => id,
            None => {
                return GuardResult::block(
                    "cross_agent",
                    Severity::Critical,
                    "No agent ID in context",
                );
            }
        };

        let resource = match self.extract_resource(action) {
            Some(r) => r,
            None => return GuardResult::allow("cross_agent"),
        };

        let ownership = match self.registry.get_ownership(&resource).await {
            Ok(Some(o)) => o,
            Ok(None) => return self.apply_default_policy(),
            Err(e) => {
                return GuardResult::block(
                    "cross_agent",
                    Severity::Error,
                    format!("Registry error: {}", e),
                );
            }
        };

        // Owner always has access
        if ownership.owner == *agent_id {
            return GuardResult::allow("cross_agent");
        }

        // Check ACL
        let permission = self.action_to_permission(action);
        if let Some(entry) = self.find_acl_entry(&ownership.acl, agent_id, permission) {
            if let Some(ref token) = entry.delegation_token {
                match self.delegation_verifier.verify(token, agent_id, &resource, permission).await {
                    Ok(true) => return GuardResult::allow("cross_agent"),
                    Ok(false) => {
                        return GuardResult::block(
                            "cross_agent",
                            Severity::Error,
                            "Invalid delegation token",
                        );
                    }
                    Err(e) => {
                        return GuardResult::block(
                            "cross_agent",
                            Severity::Error,
                            format!("Delegation verification error: {}", e),
                        );
                    }
                }
            }
            return GuardResult::allow("cross_agent");
        }

        // Evaluate policy rules
        self.evaluate_rules(action, context, &ownership).await
    }

    pub async fn register_resource(
        &self,
        path: &str,
        owner: &AgentId,
        metadata: Option<HashMap<String, serde_json::Value>>,
    ) -> Result<ResourceOwnership, Error> {
        if let Ok(Some(_)) = self.registry.get_ownership(path).await {
            return Err(Error::ResourceAlreadyOwned);
        }

        let ownership = ResourceOwnership {
            resource_id: path.to_string(),
            owner: owner.clone(),
            created_at: Utc::now(),
            acl: vec![],
            metadata: metadata.unwrap_or_default(),
        };

        self.registry.set_ownership(&ownership).await?;
        Ok(ownership)
    }

    pub async fn grant_access(
        &self,
        path: &str,
        granting_agent: &AgentId,
        grantee_agent: &AgentId,
        permissions: Vec<Permission>,
        expires_at: Option<DateTime<Utc>>,
        delegation_token: Option<String>,
    ) -> Result<(), Error> {
        let mut ownership = self
            .registry
            .get_ownership(path)
            .await?
            .ok_or(Error::ResourceNotFound)?;

        // Check grant permission
        let can_grant = ownership.owner == *granting_agent
            || ownership
                .acl
                .iter()
                .any(|e| e.agent == *granting_agent && e.permissions.contains(&Permission::Grant));

        if !can_grant {
            return Err(Error::PermissionDenied);
        }

        let entry = AccessControlEntry {
            agent: grantee_agent.clone(),
            permissions,
            granted_by: granting_agent.clone(),
            expires_at,
            delegation_token,
        };

        // Update or add entry
        if let Some(idx) = ownership.acl.iter().position(|e| e.agent == *grantee_agent) {
            ownership.acl[idx] = entry;
        } else {
            ownership.acl.push(entry);
        }

        self.registry.set_ownership(&ownership).await
    }

    pub async fn revoke_access(
        &self,
        path: &str,
        revoking_agent: &AgentId,
        revoked_agent: &AgentId,
    ) -> Result<(), Error> {
        let mut ownership = self
            .registry
            .get_ownership(path)
            .await?
            .ok_or(Error::ResourceNotFound)?;

        if ownership.owner != *revoking_agent {
            return Err(Error::PermissionDenied);
        }

        ownership.acl.retain(|e| e.agent != *revoked_agent);
        self.registry.set_ownership(&ownership).await
    }

    fn extract_resource(&self, action: &GuardAction<'_>) -> Option<String> {
        match action {
            GuardAction::FileAccess(path) => Some(path.to_string()),
            GuardAction::FileWrite(path, _) => Some(path.to_string()),
            GuardAction::Patch(path, _) => Some(path.to_string()),
            _ => None,
        }
    }

    fn action_to_permission(&self, action: &GuardAction<'_>) -> Permission {
        match action {
            GuardAction::FileAccess(_) => Permission::Read,
            GuardAction::FileWrite(_, _) | GuardAction::Patch(_, _) => Permission::Write,
            _ => Permission::Read,
        }
    }

    fn find_acl_entry<'a>(
        &self,
        acl: &'a [AccessControlEntry],
        agent: &AgentId,
        permission: Permission,
    ) -> Option<&'a AccessControlEntry> {
        acl.iter().find(|e| {
            e.agent == *agent
                && e.permissions.contains(&permission)
                && e.expires_at.map_or(true, |exp| exp > Utc::now())
        })
    }

    fn apply_default_policy(&self) -> GuardResult {
        match self.policy.default_action {
            DefaultAction::Allow => GuardResult::allow("cross_agent"),
            DefaultAction::Audit => {
                GuardResult::warn("cross_agent", "Unowned resource access (auditing)")
            }
            DefaultAction::Deny => GuardResult::block(
                "cross_agent",
                Severity::Error,
                "Access to unowned resource denied by default policy",
            ),
        }
    }

    async fn evaluate_rules(
        &self,
        action: &GuardAction<'_>,
        context: &GuardContext,
        ownership: &ResourceOwnership,
    ) -> GuardResult {
        let from_agent = context.agent_id.as_ref().unwrap();
        let to_agent = &ownership.owner;
        let resource = self.extract_resource(action).unwrap();

        for rule in &self.policy.rules {
            if !self.rule_applies(rule, from_agent, to_agent) {
                continue;
            }

            let action_str = self.action_to_capability_str(action);

            // Check deny first
            if rule.deny.iter().any(|cap| cap.matches(&action_str, &resource)) {
                return GuardResult::block(
                    "cross_agent",
                    Severity::Error,
                    "Capability explicitly denied by cross-agent rule",
                );
            }

            // Check allow
            if rule.allow.iter().any(|cap| cap.matches(&action_str, &resource)) {
                if rule.require_delegation {
                    let token = context
                        .metadata
                        .as_ref()
                        .and_then(|m| m.get("delegationToken"))
                        .and_then(|v| v.as_str());

                    match token {
                        Some(t) => {
                            let permission = self.action_to_permission(action);
                            match self
                                .delegation_verifier
                                .verify(t, from_agent, &resource, permission)
                                .await
                            {
                                Ok(true) => return GuardResult::allow("cross_agent"),
                                _ => {
                                    return GuardResult::block(
                                        "cross_agent",
                                        Severity::Error,
                                        "Invalid delegation token",
                                    );
                                }
                            }
                        }
                        None => {
                            return GuardResult::block(
                                "cross_agent",
                                Severity::Error,
                                "Delegation token required for this cross-agent access",
                            );
                        }
                    }
                }

                if !rule.require_approval.is_empty() {
                    return GuardResult::block(
                        "cross_agent",
                        Severity::Warning,
                        format!("Approval required from: {:?}", rule.require_approval),
                    );
                }

                return GuardResult::allow("cross_agent");
            }
        }

        GuardResult::block(
            "cross_agent",
            Severity::Error,
            format!(
                "No cross-agent rule allows {} to access {}'s resource",
                from_agent, to_agent
            ),
        )
    }

    fn rule_applies(&self, rule: &CrossAgentRule, from: &AgentId, to: &AgentId) -> bool {
        let from_matches = match &rule.from {
            AgentPattern::Single(p) => self.agent_matches(p, from),
            AgentPattern::Multiple(patterns) => patterns.iter().any(|p| self.agent_matches(p, from)),
        };

        let to_matches = match &rule.to {
            AgentPattern::Single(p) => self.agent_matches(p, to),
            AgentPattern::Multiple(patterns) => patterns.iter().any(|p| self.agent_matches(p, to)),
        };

        from_matches && to_matches
    }

    fn agent_matches(&self, pattern: &str, agent: &AgentId) -> bool {
        if pattern == "*" {
            return true;
        }
        if pattern.ends_with('*') {
            return agent.starts_with(&pattern[..pattern.len() - 1]);
        }
        pattern == agent
    }

    fn action_to_capability_str(&self, action: &GuardAction<'_>) -> String {
        match action {
            GuardAction::FileAccess(path) => format!("file:read:{}", path),
            GuardAction::FileWrite(path, _) => format!("file:write:{}", path),
            GuardAction::Patch(path, _) => format!("file:write:{}", path),
            GuardAction::NetworkEgress(host, _) => format!("network:egress:{}", host),
            _ => "unknown".to_string(),
        }
    }
}

/// Resource registry trait
#[async_trait]
pub trait ResourceRegistry: Send + Sync {
    async fn get_ownership(&self, resource_id: &str) -> Result<Option<ResourceOwnership>, Error>;
    async fn set_ownership(&self, ownership: &ResourceOwnership) -> Result<(), Error>;
    async fn delete_ownership(&self, resource_id: &str) -> Result<(), Error>;
    async fn list_by_owner(&self, owner: &AgentId) -> Result<Vec<ResourceOwnership>, Error>;
}

/// Delegation verifier trait
#[async_trait]
pub trait DelegationVerifier: Send + Sync {
    async fn verify(
        &self,
        token: &str,
        agent: &AgentId,
        resource: &str,
        permission: Permission,
    ) -> Result<bool, Error>;
}

/// In-memory resource registry
pub struct InMemoryResourceRegistry {
    resources: RwLock<HashMap<String, ResourceOwnership>>,
}

impl InMemoryResourceRegistry {
    pub fn new() -> Self {
        Self {
            resources: RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl ResourceRegistry for InMemoryResourceRegistry {
    async fn get_ownership(&self, resource_id: &str) -> Result<Option<ResourceOwnership>, Error> {
        let resources = self.resources.read().await;
        Ok(resources.get(resource_id).cloned())
    }

    async fn set_ownership(&self, ownership: &ResourceOwnership) -> Result<(), Error> {
        let mut resources = self.resources.write().await;
        resources.insert(ownership.resource_id.clone(), ownership.clone());
        Ok(())
    }

    async fn delete_ownership(&self, resource_id: &str) -> Result<(), Error> {
        let mut resources = self.resources.write().await;
        resources.remove(resource_id);
        Ok(())
    }

    async fn list_by_owner(&self, owner: &AgentId) -> Result<Vec<ResourceOwnership>, Error> {
        let resources = self.resources.read().await;
        Ok(resources
            .values()
            .filter(|r| r.owner == *owner)
            .cloned()
            .collect())
    }
}

/// Error types
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Resource not found")]
    ResourceNotFound,
    #[error("Resource already owned")]
    ResourceAlreadyOwned,
    #[error("Permission denied")]
    PermissionDenied,
    #[error("Registry error: {0}")]
    Registry(String),
}
```

## Token/Capability Formats

### Resource Ownership Record

```json
{
  "resourceId": "/workspace/research/findings.json",
  "owner": "research-agent-001",
  "createdAt": "2026-01-15T10:30:00Z",
  "acl": [
    {
      "agent": "code-agent-001",
      "permissions": ["read"],
      "grantedBy": "research-agent-001",
      "expiresAt": "2026-01-15T11:30:00Z",
      "delegationToken": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9..."
    }
  ],
  "metadata": {
    "contentType": "application/json",
    "tags": ["research", "api-analysis"]
  }
}
```

### Cross-Agent Access Event (Audit)

```json
{
  "eventId": "evt-2026-01-15-abc123",
  "timestamp": "2026-01-15T10:45:00Z",
  "type": "cross_agent_access",
  "traceId": "trace-xyz789",
  "source": {
    "agentId": "code-agent-001",
    "sessionId": "sess-456"
  },
  "target": {
    "resourceId": "/workspace/research/findings.json",
    "owner": "research-agent-001"
  },
  "action": "read",
  "decision": "allowed",
  "evidence": {
    "aclEntry": {
      "permissions": ["read"],
      "grantedBy": "research-agent-001",
      "expiresAt": "2026-01-15T11:30:00Z"
    },
    "delegationToken": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9..."
  }
}
```

## Attack Scenarios and Mitigations

### Attack 1: ACL Bypass via Path Traversal

**Attack**: Agent requests `/workspace/../research/secret.txt` to bypass ownership check

**Mitigation**:
- Canonicalize all paths before ownership lookup
- Apply path normalization at guard entry point
- Reject paths containing `..` in sensitive contexts

### Attack 2: Token Replay

**Attack**: Agent captures delegation token and replays after legitimate grant expires

**Mitigation**:
- Include nonce in delegation tokens
- Server-side token revocation list
- Short-lived tokens with refresh mechanism

### Attack 3: Ownership Race Condition

**Attack**: Two agents simultaneously claim ownership of new resource

**Mitigation**:
- Atomic compare-and-swap for ownership registration
- Distributed locking for registry operations
- Deterministic tie-breaking (first agent ID lexicographically)

### Attack 4: ACL Accumulation

**Attack**: Agent accumulates many ACL entries across resources, creating hidden persistent access

**Mitigation**:
- Periodic ACL audit and cleanup
- Maximum ACL entries per agent
- Expiration required for all non-owner entries

## Implementation Phases

### Phase 1: Core Ownership Model
- Implement ResourceOwnership type
- Implement InMemoryResourceRegistry
- Basic cross-agent guard with ownership check

### Phase 2: ACL and Delegation Integration
- ACL entry management
- Integration with DelegationVerifier
- Time-based expiration

### Phase 3: Policy Rules Engine
- Rule parsing and evaluation
- Pattern matching for agents and capabilities
- Approval workflow integration

### Phase 4: Distributed Registry
- Redis/etcd-backed registry
- Consistent hashing for sharding
- Cross-datacenter replication

## Configuration Example

```yaml
version: "1.0.0"
name: "Cross-Agent Development Policy"

cross_agent:
  default_action: deny

  rules:
    # Research can share with code generation
    - from: research-agent-*
      to: code-agent-*
      allow:
        - file:read:/workspace/research/**
      require_delegation: true
      max_delegation_ttl: 1h

    # Code can share artifacts with deployment
    - from: code-agent-*
      to: deploy-agent-*
      allow:
        - file:read:/workspace/dist/**
        - file:read:/workspace/package.json
      require_delegation: true
      require_approval:
        - human-operator

    # All agents can read shared config
    - from: "*"
      to: config-agent
      allow:
        - file:read:/etc/agent-config/**
      require_delegation: false

  isolation:
    filesystem:
      per_agent_root: /sandbox/{agent_id}
      shared_paths:
        - /workspace (read-only by default)
```

## Trust Model and Assumptions

### Trusted Components

1. **Clawdstrike Runtime**: Assumed to correctly enforce policies
2. **Resource Registry**: Assumed to maintain integrity of ownership records
3. **Cryptographic Primitives**: Assumed secure (Ed25519, SHA-256)
4. **Orchestrator**: Assumed to correctly provision agent identities

### Untrusted Components

1. **Individual Agents**: May be compromised or malicious
2. **External Data Sources**: May contain adversarial content
3. **Network**: Observable but not modifiable (TLS assumption)

### Security Invariants

1. **Ownership Immutability**: Once assigned, ownership cannot be changed without owner consent
2. **ACL Monotonicity**: ACL entries can only be added/removed by owner or grantees with Grant permission
3. **Delegation Bound**: Delegated permissions cannot exceed delegator's permissions
4. **Audit Completeness**: Every cross-agent access produces an audit event
