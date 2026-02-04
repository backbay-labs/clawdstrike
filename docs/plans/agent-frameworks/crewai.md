# CrewAI Integration

## Overview

CrewAI is a framework for orchestrating role-playing AI agents that collaborate to accomplish complex tasks. Unlike single-agent systems, CrewAI manages multiple agents with distinct roles, goals, and tools, coordinating their interactions through defined workflows (crews).

This document details the architecture for integrating Clawdstrike's security enforcement into CrewAI's multi-agent orchestration layer.

## Version Compatibility

| Package | Minimum Version | Tested Up To | Notes |
|---------|----------------|--------------|-------|
| **crewai** (Python) | 0.28.0 | 0.80.x | Core CrewAI framework |
| **crewai-tools** (Python) | 0.4.0 | 0.12.x | Tool definitions |
| **@clawdstrike/crewai** (TypeScript) | 1.0.0 | 1.x | TypeScript bindings for Node.js agents |

> **Note**: CrewAI is primarily a Python framework. The TypeScript interfaces shown in this document represent the `@clawdstrike/crewai` package, which provides TypeScript bindings for use with Node.js-based CrewAI implementations or for type-safe configuration. For pure Python usage, see the Python SDK documentation.

## Problem Statement

### Challenges with CrewAI Security

1. **Multi-Agent Complexity**: Multiple agents with different roles may have different security requirements, but current implementations apply uniform permissions.

2. **Inter-Agent Communication**: Agents pass information between each other, potentially propagating sensitive data or malicious instructions.

3. **Tool Sharing**: Tools can be shared across agents or assigned to specific roles, requiring fine-grained access control.

4. **Delegation Chains**: Agents can delegate tasks to other agents, creating complex execution paths that may bypass security checks.

5. **Process Orchestration**: Sequential and hierarchical processes have different security implications based on execution order.

### Use Cases

| Use Case | Security Requirement |
|----------|---------------------|
| Research team (multiple analysts) | Restrict each agent to domain-specific resources |
| Development crew (architect, developer, reviewer) | Limit code execution to sandboxed environments |
| Customer support team | Prevent PII leakage between agents |
| Content creation crew | Control external API access per role |
| Security audit team | Allow elevated privileges only for designated agents |

## CrewAI Architecture Analysis

### Core Components

```
┌─────────────────────────────────────────────────────────────────┐
│                           Crew                                   │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                     Process                              │   │
│  │  (sequential | hierarchical | consensual)               │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                   │
│           ┌──────────────────┼──────────────────┐               │
│           ▼                  ▼                  ▼               │
│     ┌─────────┐        ┌─────────┐        ┌─────────┐         │
│     │ Agent 1 │        │ Agent 2 │        │ Agent 3 │         │
│     │ (role)  │        │ (role)  │        │ (role)  │         │
│     └────┬────┘        └────┬────┘        └────┬────┘         │
│          │                  │                  │               │
│     ┌────▼────┐        ┌────▼────┐        ┌────▼────┐         │
│     │  Tools  │        │  Tools  │        │  Tools  │         │
│     └─────────┘        └─────────┘        └─────────┘         │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                      Tasks                               │   │
│  │  [Task 1] ──> [Task 2] ──> [Task 3]                    │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### Execution Flow

```
┌──────────┐    ┌──────────┐    ┌──────────────┐    ┌──────────┐
│  Crew    │───>│  Task    │───>│    Agent     │───>│   Tool   │
│ kickoff  │    │ execute  │    │ execute_task │    │ execute  │
└──────────┘    └──────────┘    └──────────────┘    └──────────┘
                                       │
                                       ▼
                               ┌──────────────┐
                               │   LLM Call   │
                               │  (reasoning) │
                               └──────────────┘
```

### Interception Points in CrewAI

1. **Agent Initialization**: Configure security per agent role
2. **Tool Execution**: Intercept all tool calls at the agent level
3. **Task Handoff**: Validate data passed between tasks
4. **Delegation**: Control when agents can delegate to others
5. **Crew Callbacks**: Global hooks for crew-wide enforcement

## Proposed Architecture

### Clawdstrike CrewAI Integration

```
┌─────────────────────────────────────────────────────────────────┐
│                      SecureCrew                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │               ClawdstrikeCrewCallback                    │   │
│  │  ├── on_crew_start(crew) -> inject security context     │   │
│  │  ├── on_task_start(task, agent) -> preflight check      │   │
│  │  ├── on_tool_use(agent, tool, input) -> policy eval     │   │
│  │  ├── on_task_complete(task, output) -> sanitize         │   │
│  │  └── on_crew_complete(results) -> audit log             │   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                   │
│           ┌──────────────────┼──────────────────┐               │
│           ▼                  ▼                  ▼               │
│     ┌───────────┐      ┌───────────┐      ┌───────────┐        │
│     │SecureAgent│      │SecureAgent│      │SecureAgent│        │
│     │ (policy A)│      │ (policy B)│      │ (policy C)│        │
│     └─────┬─────┘      └─────┬─────┘      └─────┬─────┘        │
│           │                  │                  │               │
│     ┌─────▼─────┐      ┌─────▼─────┐      ┌─────▼─────┐        │
│     │SecureTools│      │SecureTools│      │SecureTools│        │
│     └───────────┘      └───────────┘      └───────────┘        │
└─────────────────────────────────────────────────────────────────┘
```

### Architecture Components

```typescript
// Core integration layer
┌─────────────────────────────────────────────────────────────────┐
│                    @clawdstrike/crewai                          │
├─────────────────────────────────────────────────────────────────┤
│  ClawdstrikeCrewCallback                                        │
│  ├── onCrewStart(crew) -> SecurityContext                       │
│  ├── onTaskStart(task, agent) -> Decision                       │
│  ├── onToolUse(agent, tool, input) -> Decision                  │
│  ├── onAgentDelegation(from, to, task) -> Decision              │
│  ├── onTaskComplete(task, output) -> SanitizedOutput            │
│  └── onCrewComplete(results) -> AuditReport                     │
├─────────────────────────────────────────────────────────────────┤
│  SecureAgent                                                     │
│  ├── withPolicy(policy) -> SecureAgent                          │
│  ├── withAllowedTools(tools[]) -> SecureAgent                   │
│  ├── withDelegationPolicy(policy) -> SecureAgent                │
│  └── getSecurityContext() -> AgentSecurityContext               │
├─────────────────────────────────────────────────────────────────┤
│  SecureTool                                                      │
│  ├── wrap(tool) -> SecureTool                                   │
│  ├── withPolicy(policy) -> SecureTool                           │
│  └── forAgent(agentRole) -> SecureTool                          │
├─────────────────────────────────────────────────────────────────┤
│  SecureCrew                                                      │
│  ├── create(config) -> SecureCrew                               │
│  ├── withGlobalPolicy(policy) -> SecureCrew                     │
│  ├── withAgentPolicies(map) -> SecureCrew                       │
│  └── kickoff(inputs) -> SecureCrewResult                        │
├─────────────────────────────────────────────────────────────────┤
│  PolicyManager                                                   │
│  ├── loadRolePolicies(config) -> RolePolicyMap                  │
│  ├── getPolicyForAgent(agent) -> Policy                         │
│  ├── mergePolicies(global, role) -> Policy                      │
│  └── validatePolicyHierarchy(policies) -> ValidationResult      │
└─────────────────────────────────────────────────────────────────┘
```

## API Design

### TypeScript Interfaces

```typescript
import { Agent, Crew, Task, Tool, Process } from 'crewai';
import { PolicyEngine, Decision, Policy, ClawdstrikeConfig } from '@clawdstrike/openclaw';

/**
 * Configuration for CrewAI integration
 */
export interface CrewAIClawdstrikeConfig extends ClawdstrikeConfig {
  /** Global policy applied to all agents */
  globalPolicy?: string | Policy;

  /** Role-specific policy overrides */
  rolePolicies?: Record<string, string | Policy>;

  /** Agent-specific policy overrides (by agent name) */
  agentPolicies?: Record<string, string | Policy>;

  /** Whether agents can delegate tasks */
  allowDelegation?: boolean;

  /** Delegation policy restrictions */
  delegationPolicy?: DelegationPolicy;

  /** Whether to enforce policy on inter-agent communication */
  enforceInterAgentPolicy?: boolean;

  /** Maximum task chain depth before requiring re-authorization */
  maxTaskChainDepth?: number;

  /** Callback handlers */
  callbacks?: CrewSecurityCallbacks;
}

/**
 * Delegation policy configuration
 */
export interface DelegationPolicy {
  /** Allowed delegation pairs (from_role -> to_roles[]) */
  allowedDelegations?: Record<string, string[]>;

  /** Denied delegation pairs */
  deniedDelegations?: Record<string, string[]>;

  /** Whether to inherit security context on delegation */
  inheritSecurityContext?: boolean;

  /** Whether delegated tasks require re-authorization */
  reauthorizeOnDelegation?: boolean;
}

/**
 * Security callbacks for crew events
 */
export interface CrewSecurityCallbacks {
  /** Called when crew starts */
  onCrewStart?: (crew: Crew, context: SecurityContext) => void;

  /** Called before task execution */
  onTaskStart?: (task: Task, agent: Agent, decision: Decision) => void;

  /** Called when tool is used */
  onToolUse?: (agent: Agent, tool: Tool, input: unknown, decision: Decision) => void;

  /** Called on delegation attempt */
  onDelegation?: (from: Agent, to: Agent, task: Task, decision: Decision) => void;

  /** Called when task completes */
  onTaskComplete?: (task: Task, output: unknown, sanitized: boolean) => void;

  /** Called when security violation occurs */
  onViolation?: (violation: SecurityViolation) => void;

  /** Called when crew completes */
  onCrewComplete?: (results: unknown, auditReport: AuditReport) => void;
}

/**
 * Security violation details
 */
export interface SecurityViolation {
  timestamp: string;
  agentName: string;
  agentRole: string;
  taskId?: string;
  toolName?: string;
  action: string;
  decision: Decision;
  context: Record<string, unknown>;
}

/**
 * Audit report for crew execution
 */
export interface AuditReport {
  crewId: string;
  startTime: string;
  endTime: string;
  duration: number;
  agents: AgentAuditSummary[];
  tasks: TaskAuditSummary[];
  violations: SecurityViolation[];
  toolUsage: ToolUsageSummary[];
  delegations: DelegationAuditEntry[];
}

/**
 * Per-agent security context
 */
export interface AgentSecurityContext {
  agentName: string;
  agentRole: string;
  policy: Policy;
  allowedTools: string[];
  deniedTools: string[];
  canDelegate: boolean;
  delegationTargets: string[];
  taskChainDepth: number;
  parentTask?: string;
}

/**
 * Secure agent wrapper
 */
export interface SecureAgent {
  /** Underlying CrewAI agent */
  readonly agent: Agent;

  /** Security context */
  readonly securityContext: AgentSecurityContext;

  /** Policy engine instance */
  readonly engine: PolicyEngine;

  /** Check if tool is allowed for this agent */
  canUseTool(toolName: string): boolean;

  /** Check if agent can delegate to another */
  canDelegateTo(targetRole: string): boolean;

  /** Execute with security enforcement */
  executeSecurely<T>(fn: () => Promise<T>): Promise<T>;
}

/**
 * Secure crew wrapper
 */
export interface SecureCrew {
  /** Underlying CrewAI crew */
  readonly crew: Crew;

  /** Global policy */
  readonly globalPolicy: Policy;

  /** Security-wrapped agents */
  readonly agents: SecureAgent[];

  /** Audit trail */
  readonly auditLog: AuditReport;

  /** Kick off crew with security enforcement */
  kickoff(inputs?: Record<string, unknown>): Promise<SecureCrewResult>;

  /** Get security summary */
  getSecuritySummary(): SecuritySummary;
}

/**
 * Result of secure crew execution
 */
export interface SecureCrewResult {
  /** Raw crew result */
  result: unknown;

  /** Whether execution completed without violations */
  clean: boolean;

  /** Violations encountered (may still complete in warn mode) */
  violations: SecurityViolation[];

  /** Audit report */
  audit: AuditReport;

  /** Sanitized output (secrets redacted) */
  sanitizedResult: unknown;
}
```

### Callback Handler Implementation

```typescript
import { CrewCallback, Agent, Task, Tool, Crew } from 'crewai';
import { PolicyEngine, Decision, PolicyEvent } from '@clawdstrike/openclaw';

/**
 * Clawdstrike callback handler for CrewAI
 */
export class ClawdstrikeCrewCallback implements CrewCallback {
  private readonly config: CrewAIClawdstrikeConfig;
  private readonly globalEngine: PolicyEngine;
  private readonly agentEngines: Map<string, PolicyEngine> = new Map();
  private readonly auditEvents: SecurityViolation[] = [];
  private readonly toolUsage: ToolUsageSummary[] = [];
  private readonly delegations: DelegationAuditEntry[] = [];
  private crewStartTime: number = 0;

  constructor(config: CrewAIClawdstrikeConfig = {}) {
    this.config = {
      allowDelegation: true,
      enforceInterAgentPolicy: true,
      maxTaskChainDepth: 10,
      ...config,
    };
    this.globalEngine = new PolicyEngine(config);
  }

  /**
   * Initialize security context for crew
   */
  onCrewStart(crew: Crew): void {
    this.crewStartTime = Date.now();

    // Initialize per-agent policy engines
    for (const agent of crew.agents) {
      const policy = this.resolveAgentPolicy(agent);
      const engine = new PolicyEngine({ ...this.config, policy });
      this.agentEngines.set(agent.name, engine);
    }

    // Inject security prompt into each agent
    for (const agent of crew.agents) {
      this.injectSecurityContext(agent);
    }

    this.config.callbacks?.onCrewStart?.(crew, this.getGlobalContext());
  }

  /**
   * Validate task before execution
   */
  async onTaskStart(task: Task, agent: Agent): Promise<Decision> {
    const engine = this.getAgentEngine(agent);

    // Check task chain depth
    const depth = this.getTaskChainDepth(task);
    if (depth > (this.config.maxTaskChainDepth ?? 10)) {
      const decision: Decision = {
        allowed: false,
        denied: true,
        warn: false,
        reason: `Task chain depth (${depth}) exceeds maximum (${this.config.maxTaskChainDepth})`,
        guard: 'task_chain',
        severity: 'high',
      };

      this.recordViolation(agent, task, decision);
      this.config.callbacks?.onTaskStart?.(task, agent, decision);
      return decision;
    }

    // Check if agent is allowed to execute this task type
    const event = this.createTaskEvent(task, agent);
    const decision = await engine.evaluate(event);

    if (decision.denied || decision.warn) {
      this.recordViolation(agent, task, decision);
    }

    this.config.callbacks?.onTaskStart?.(task, agent, decision);
    return decision;
  }

  /**
   * Intercept tool usage
   */
  async onToolUse(
    agent: Agent,
    tool: Tool,
    input: unknown,
  ): Promise<{ decision: Decision; modifiedInput?: unknown }> {
    const engine = this.getAgentEngine(agent);
    const startTime = Date.now();

    // Create policy event for tool usage
    const event = this.createToolEvent(agent, tool, input);
    const decision = await engine.evaluate(event);

    // Record tool usage
    this.toolUsage.push({
      agentName: agent.name,
      toolName: tool.name,
      timestamp: new Date().toISOString(),
      allowed: decision.allowed,
      duration: Date.now() - startTime,
    });

    if (decision.denied) {
      this.recordViolation(agent, null, decision, tool.name);
    }

    this.config.callbacks?.onToolUse?.(agent, tool, input, decision);

    // Return decision and potentially modified input
    return {
      decision,
      modifiedInput: decision.allowed ? this.sanitizeInput(input, engine) : undefined,
    };
  }

  /**
   * Handle delegation between agents
   */
  async onDelegation(
    fromAgent: Agent,
    toAgent: Agent,
    task: Task,
  ): Promise<Decision> {
    // Check if delegation is globally allowed
    if (!this.config.allowDelegation) {
      const decision: Decision = {
        allowed: false,
        denied: true,
        warn: false,
        reason: 'Delegation is disabled',
        guard: 'delegation',
        severity: 'high',
      };

      this.recordDelegation(fromAgent, toAgent, task, decision);
      return decision;
    }

    // Check delegation policy
    const delegationPolicy = this.config.delegationPolicy;
    if (delegationPolicy) {
      const fromRole = fromAgent.role;
      const toRole = toAgent.role;

      // Check denied delegations
      if (delegationPolicy.deniedDelegations?.[fromRole]?.includes(toRole)) {
        const decision: Decision = {
          allowed: false,
          denied: true,
          warn: false,
          reason: `Delegation from '${fromRole}' to '${toRole}' is denied`,
          guard: 'delegation_policy',
          severity: 'high',
        };

        this.recordDelegation(fromAgent, toAgent, task, decision);
        return decision;
      }

      // Check allowed delegations (if specified, must be in list)
      if (
        delegationPolicy.allowedDelegations &&
        !delegationPolicy.allowedDelegations[fromRole]?.includes(toRole)
      ) {
        const decision: Decision = {
          allowed: false,
          denied: true,
          warn: false,
          reason: `Delegation from '${fromRole}' to '${toRole}' is not in allowed list`,
          guard: 'delegation_policy',
          severity: 'high',
        };

        this.recordDelegation(fromAgent, toAgent, task, decision);
        return decision;
      }
    }

    // Re-authorize if required
    if (this.config.delegationPolicy?.reauthorizeOnDelegation) {
      const toEngine = this.getAgentEngine(toAgent);
      const event = this.createTaskEvent(task, toAgent);
      const decision = await toEngine.evaluate(event);

      this.recordDelegation(fromAgent, toAgent, task, decision);
      return decision;
    }

    const decision: Decision = { allowed: true, denied: false, warn: false };
    this.recordDelegation(fromAgent, toAgent, task, decision);
    return decision;
  }

  /**
   * Process task completion
   */
  async onTaskComplete(
    task: Task,
    agent: Agent,
    output: unknown,
  ): Promise<unknown> {
    const engine = this.getAgentEngine(agent);

    // Sanitize output
    let sanitized = output;
    let wasSanitized = false;

    if (typeof output === 'string') {
      const redacted = engine.redactSecrets(output);
      if (redacted !== output) {
        sanitized = redacted;
        wasSanitized = true;
      }
    } else if (typeof output === 'object' && output !== null) {
      sanitized = this.deepSanitize(output as Record<string, unknown>, engine);
      wasSanitized = JSON.stringify(sanitized) !== JSON.stringify(output);
    }

    this.config.callbacks?.onTaskComplete?.(task, output, wasSanitized);

    return sanitized;
  }

  /**
   * Generate audit report on crew completion
   */
  onCrewComplete(results: unknown): AuditReport {
    const endTime = Date.now();

    const report: AuditReport = {
      crewId: `crew-${this.crewStartTime}`,
      startTime: new Date(this.crewStartTime).toISOString(),
      endTime: new Date(endTime).toISOString(),
      duration: endTime - this.crewStartTime,
      agents: this.generateAgentSummaries(),
      tasks: this.generateTaskSummaries(),
      violations: [...this.auditEvents],
      toolUsage: [...this.toolUsage],
      delegations: [...this.delegations],
    };

    this.config.callbacks?.onCrewComplete?.(results, report);

    return report;
  }

  // Private helper methods

  private resolveAgentPolicy(agent: Agent): string | Policy {
    // Check agent-specific policy
    if (this.config.agentPolicies?.[agent.name]) {
      return this.config.agentPolicies[agent.name];
    }

    // Check role-specific policy
    if (this.config.rolePolicies?.[agent.role]) {
      return this.config.rolePolicies[agent.role];
    }

    // Fall back to global policy
    return this.config.globalPolicy ?? this.config.policy ?? 'clawdstrike:ai-agent-minimal';
  }

  private getAgentEngine(agent: Agent): PolicyEngine {
    return this.agentEngines.get(agent.name) ?? this.globalEngine;
  }

  private injectSecurityContext(agent: Agent): void {
    const engine = this.getAgentEngine(agent);
    const policy = engine.getPolicy();
    const enabledGuards = engine.enabledGuards();

    // Append security context to agent's backstory
    const securityContext = `

## Security Policy

You are operating under the following security constraints:

### Forbidden Paths
${policy.filesystem?.forbidden_paths?.map(p => `- ${p}`).join('\n') ?? 'None specified'}

### Network Restrictions
${policy.egress?.mode === 'allowlist'
  ? `Allowed domains:\n${policy.egress.allowed_domains?.map(d => `- ${d}`).join('\n') ?? 'None'}`
  : policy.egress?.mode === 'denylist'
    ? `Denied domains:\n${policy.egress.denied_domains?.map(d => `- ${d}`).join('\n') ?? 'None'}`
    : 'No network restrictions'}

### Tool Restrictions
${policy.tools?.denied?.length
  ? `Denied tools: ${policy.tools.denied.join(', ')}`
  : 'No tool restrictions'}

### Active Guards
${enabledGuards.map(g => `- ${g}`).join('\n')}

Always verify actions against these policies before proceeding.
`;

    // Inject into agent (implementation depends on CrewAI version)
    if (agent.backstory) {
      agent.backstory += securityContext;
    }
  }

  private createTaskEvent(task: Task, agent: Agent): PolicyEvent {
    return {
      eventId: `task-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      eventType: 'tool_call',
      timestamp: new Date().toISOString(),
      sessionId: agent.name,
      data: {
        type: 'tool',
        toolName: 'task_execution',
        parameters: {
          taskDescription: task.description,
          agentRole: agent.role,
          expectedOutput: task.expected_output,
        },
      },
      metadata: {
        source: 'crewai',
        agentName: agent.name,
        agentRole: agent.role,
      },
    };
  }

  private createToolEvent(
    agent: Agent,
    tool: Tool,
    input: unknown,
  ): PolicyEvent {
    const toolName = tool.name.toLowerCase();

    // Infer event type from tool name
    let eventType: PolicyEvent['eventType'] = 'tool_call';
    if (toolName.includes('file') || toolName.includes('read')) {
      eventType = 'file_read';
    } else if (toolName.includes('write') || toolName.includes('save')) {
      eventType = 'file_write';
    } else if (toolName.includes('shell') || toolName.includes('exec') || toolName.includes('bash')) {
      eventType = 'command_exec';
    } else if (toolName.includes('http') || toolName.includes('request') || toolName.includes('fetch')) {
      eventType = 'network_egress';
    }

    return {
      eventId: `tool-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      eventType,
      timestamp: new Date().toISOString(),
      sessionId: agent.name,
      data: this.createEventData(eventType, tool.name, input),
      metadata: {
        source: 'crewai',
        agentName: agent.name,
        agentRole: agent.role,
        toolName: tool.name,
      },
    };
  }

  private createEventData(
    eventType: PolicyEvent['eventType'],
    toolName: string,
    input: unknown,
  ): PolicyEvent['data'] {
    const params = typeof input === 'object' && input !== null
      ? (input as Record<string, unknown>)
      : { raw: input };

    switch (eventType) {
      case 'file_read':
      case 'file_write':
        return {
          type: 'file',
          path: String(params.path ?? params.file ?? ''),
          operation: eventType === 'file_read' ? 'read' : 'write',
        };

      case 'command_exec':
        return {
          type: 'command',
          command: String(params.command ?? params.cmd ?? ''),
          args: Array.isArray(params.args) ? params.args : [],
        };

      case 'network_egress':
        return {
          type: 'network',
          host: String(params.host ?? params.url ?? ''),
          port: Number(params.port ?? 443),
          url: params.url as string | undefined,
        };

      default:
        return {
          type: 'tool',
          toolName,
          parameters: params,
        };
    }
  }

  private getTaskChainDepth(task: Task): number {
    // Track task chain depth through parent task references
    let depth = 0;
    let current: Task | null = task;

    while (current && depth < 100) { // Safety limit
      depth++;
      current = (current as any).parent_task ?? null;
    }

    return depth;
  }

  private recordViolation(
    agent: Agent,
    task: Task | null,
    decision: Decision,
    toolName?: string,
  ): void {
    const violation: SecurityViolation = {
      timestamp: new Date().toISOString(),
      agentName: agent.name,
      agentRole: agent.role,
      taskId: task?.id,
      toolName,
      action: toolName ? 'tool_use' : 'task_execution',
      decision,
      context: {
        taskDescription: task?.description,
      },
    };

    this.auditEvents.push(violation);
    this.config.callbacks?.onViolation?.(violation);
  }

  private recordDelegation(
    from: Agent,
    to: Agent,
    task: Task,
    decision: Decision,
  ): void {
    this.delegations.push({
      timestamp: new Date().toISOString(),
      fromAgent: from.name,
      fromRole: from.role,
      toAgent: to.name,
      toRole: to.role,
      taskDescription: task.description,
      allowed: decision.allowed,
      reason: decision.reason,
    });

    if (decision.denied) {
      this.recordViolation(from, task, decision);
    }

    this.config.callbacks?.onDelegation?.(from, to, task, decision);
  }

  private sanitizeInput(input: unknown, engine: PolicyEngine): unknown {
    if (typeof input === 'string') {
      return engine.redactSecrets(input);
    }
    if (typeof input === 'object' && input !== null) {
      return this.deepSanitize(input as Record<string, unknown>, engine);
    }
    return input;
  }

  private deepSanitize(
    obj: Record<string, unknown>,
    engine: PolicyEngine,
  ): Record<string, unknown> {
    const result: Record<string, unknown> = {};

    for (const [key, value] of Object.entries(obj)) {
      if (typeof value === 'string') {
        result[key] = engine.redactSecrets(value);
      } else if (Array.isArray(value)) {
        result[key] = value.map(item =>
          typeof item === 'string'
            ? engine.redactSecrets(item)
            : typeof item === 'object' && item !== null
              ? this.deepSanitize(item as Record<string, unknown>, engine)
              : item
        );
      } else if (typeof value === 'object' && value !== null) {
        result[key] = this.deepSanitize(value as Record<string, unknown>, engine);
      } else {
        result[key] = value;
      }
    }

    return result;
  }

  private getGlobalContext(): SecurityContext {
    return {
      sessionId: `crew-${this.crewStartTime}`,
      policyOverrides: undefined,
    };
  }

  private generateAgentSummaries(): AgentAuditSummary[] {
    const summaries: Map<string, AgentAuditSummary> = new Map();

    for (const [agentName] of this.agentEngines) {
      const violations = this.auditEvents.filter(v => v.agentName === agentName);
      const tools = this.toolUsage.filter(t => t.agentName === agentName);

      summaries.set(agentName, {
        agentName,
        violationCount: violations.length,
        toolUsageCount: tools.length,
        blockedTools: tools.filter(t => !t.allowed).map(t => t.toolName),
      });
    }

    return Array.from(summaries.values());
  }

  private generateTaskSummaries(): TaskAuditSummary[] {
    // Implementation depends on task tracking
    return [];
  }
}
```

### Secure Agent Factory

```typescript
import { Agent, Tool } from 'crewai';
import { PolicyEngine, Policy } from '@clawdstrike/openclaw';

/**
 * Factory for creating security-wrapped CrewAI agents
 */
export class SecureAgentFactory {
  private readonly globalConfig: CrewAIClawdstrikeConfig;

  constructor(config: CrewAIClawdstrikeConfig = {}) {
    this.globalConfig = config;
  }

  /**
   * Create a secure agent with role-based policy
   */
  createSecureAgent(
    agentConfig: {
      name: string;
      role: string;
      goal: string;
      backstory: string;
      tools?: Tool[];
      llm?: unknown;
    },
    securityConfig?: Partial<CrewAIClawdstrikeConfig>,
  ): SecureAgent {
    const mergedConfig = { ...this.globalConfig, ...securityConfig };

    // Resolve policy for this agent
    const policy = this.resolvePolicy(agentConfig.role, agentConfig.name, mergedConfig);
    const engine = new PolicyEngine({ ...mergedConfig, policy });

    // Wrap tools with security
    const secureTools = agentConfig.tools?.map(tool =>
      this.wrapTool(tool, engine, agentConfig.name)
    );

    // Create base agent
    const agent = new Agent({
      name: agentConfig.name,
      role: agentConfig.role,
      goal: agentConfig.goal,
      backstory: this.enhanceBackstory(agentConfig.backstory, engine),
      tools: secureTools,
      llm: agentConfig.llm,
    });

    // Create security context
    const securityContext: AgentSecurityContext = {
      agentName: agentConfig.name,
      agentRole: agentConfig.role,
      policy: engine.getPolicy(),
      allowedTools: this.getAllowedTools(engine.getPolicy(), agentConfig.tools),
      deniedTools: engine.getPolicy().tools?.denied ?? [],
      canDelegate: this.canDelegate(agentConfig.role, mergedConfig),
      delegationTargets: this.getDelegationTargets(agentConfig.role, mergedConfig),
      taskChainDepth: 0,
    };

    return {
      agent,
      securityContext,
      engine,

      canUseTool(toolName: string): boolean {
        const policy = engine.getPolicy();
        const denied = policy.tools?.denied?.map(t => t.toLowerCase()) ?? [];
        const allowed = policy.tools?.allowed?.map(t => t.toLowerCase()) ?? [];

        if (denied.includes(toolName.toLowerCase())) return false;
        if (allowed.length > 0 && !allowed.includes(toolName.toLowerCase())) return false;
        return true;
      },

      canDelegateTo(targetRole: string): boolean {
        return securityContext.delegationTargets.includes(targetRole);
      },

      async executeSecurely<T>(fn: () => Promise<T>): Promise<T> {
        // Wrapper for secure execution context
        return fn();
      },
    };
  }

  /**
   * Wrap a tool with security checks
   */
  private wrapTool(
    tool: Tool,
    engine: PolicyEngine,
    agentName: string,
  ): Tool {
    const originalRun = tool.run.bind(tool);

    tool.run = async (input: string): Promise<string> => {
      // Pre-execution check
      const event: PolicyEvent = {
        eventId: `${agentName}-${tool.name}-${Date.now()}`,
        eventType: 'tool_call',
        timestamp: new Date().toISOString(),
        sessionId: agentName,
        data: {
          type: 'tool',
          toolName: tool.name,
          parameters: this.parseInput(input),
        },
      };

      const decision = await engine.evaluate(event);

      if (decision.denied) {
        throw new Error(`Tool '${tool.name}' blocked by policy: ${decision.reason}`);
      }

      // Execute original
      let result = await originalRun(input);

      // Post-execution sanitization
      if (typeof result === 'string') {
        result = engine.redactSecrets(result);
      }

      return result;
    };

    return tool;
  }

  private resolvePolicy(
    role: string,
    name: string,
    config: CrewAIClawdstrikeConfig,
  ): string | Policy {
    return (
      config.agentPolicies?.[name] ??
      config.rolePolicies?.[role] ??
      config.globalPolicy ??
      config.policy ??
      'clawdstrike:ai-agent-minimal'
    );
  }

  private enhanceBackstory(backstory: string, engine: PolicyEngine): string {
    const policy = engine.getPolicy();
    const guards = engine.enabledGuards();

    return `${backstory}

SECURITY CONSTRAINTS:
- Active security guards: ${guards.join(', ')}
- You must verify all file access, network requests, and command execution against policy
- Sensitive paths like ~/.ssh, ~/.aws, .env files are forbidden
- Network access is restricted to approved domains only
- Always use the policy_check tool before potentially restricted operations`;
  }

  private getAllowedTools(policy: Policy, tools?: Tool[]): string[] {
    if (!tools) return [];

    const allowed = policy.tools?.allowed?.map(t => t.toLowerCase()) ?? [];
    const denied = policy.tools?.denied?.map(t => t.toLowerCase()) ?? [];

    return tools
      .map(t => t.name)
      .filter(name => {
        const lower = name.toLowerCase();
        if (denied.includes(lower)) return false;
        if (allowed.length > 0) return allowed.includes(lower);
        return true;
      });
  }

  private canDelegate(role: string, config: CrewAIClawdstrikeConfig): boolean {
    if (!config.allowDelegation) return false;

    const policy = config.delegationPolicy;
    if (!policy) return true;

    if (policy.deniedDelegations?.[role]) {
      // Has specific denials, but might still be able to delegate to others
      return true;
    }

    if (policy.allowedDelegations && !policy.allowedDelegations[role]) {
      // Has allowed list but this role not in it
      return false;
    }

    return true;
  }

  private getDelegationTargets(
    role: string,
    config: CrewAIClawdstrikeConfig,
  ): string[] {
    const policy = config.delegationPolicy;
    if (!policy || !config.allowDelegation) return [];

    const allowed = policy.allowedDelegations?.[role] ?? [];
    const denied = policy.deniedDelegations?.[role] ?? [];

    if (allowed.length > 0) {
      return allowed.filter(r => !denied.includes(r));
    }

    // If no explicit allows, return empty (would need full role list to compute)
    return [];
  }

  private parseInput(input: string): Record<string, unknown> {
    try {
      return JSON.parse(input);
    } catch {
      return { raw: input };
    }
  }
}
```

## Usage Examples

### Basic Crew with Security

```typescript
import { Agent, Crew, Task, Process } from 'crewai';
import { ClawdstrikeCrewCallback, SecureAgentFactory } from '@clawdstrike/crewai';

// Create security configuration
const securityConfig: CrewAIClawdstrikeConfig = {
  policy: 'clawdstrike:ai-agent',
  mode: 'deterministic',

  // Role-specific policies
  rolePolicies: {
    researcher: 'research-policy.yaml',
    developer: 'developer-policy.yaml',
    reviewer: 'reviewer-policy.yaml',
  },

  // Delegation rules
  delegationPolicy: {
    allowedDelegations: {
      researcher: ['developer'], // Researcher can delegate to developer
      developer: ['reviewer'],    // Developer can delegate to reviewer
    },
    deniedDelegations: {
      reviewer: ['*'], // Reviewer cannot delegate
    },
    reauthorizeOnDelegation: true,
  },

  callbacks: {
    onViolation: (violation) => {
      console.error('[SECURITY]', violation.agentRole, violation.decision.reason);
    },
    onCrewComplete: (results, audit) => {
      console.log('Audit Report:', JSON.stringify(audit, null, 2));
    },
  },
};

// Create secure agent factory
const factory = new SecureAgentFactory(securityConfig);

// Create secure agents
const researcher = factory.createSecureAgent({
  name: 'Research Analyst',
  role: 'researcher',
  goal: 'Gather and analyze information',
  backstory: 'Expert research analyst with deep domain knowledge',
  tools: [searchTool, readFileTool],
});

const developer = factory.createSecureAgent({
  name: 'Software Developer',
  role: 'developer',
  goal: 'Implement solutions based on research',
  backstory: 'Senior developer with expertise in TypeScript',
  tools: [codeTool, bashTool, writeFileTool],
});

const reviewer = factory.createSecureAgent({
  name: 'Code Reviewer',
  role: 'reviewer',
  goal: 'Review and validate code quality',
  backstory: 'Principal engineer focused on code quality',
  tools: [readFileTool, lintTool],
});

// Create crew with security callback
const securityCallback = new ClawdstrikeCrewCallback(securityConfig);

const crew = new Crew({
  agents: [researcher.agent, developer.agent, reviewer.agent],
  tasks: [researchTask, developTask, reviewTask],
  process: Process.sequential,
  callbacks: [securityCallback],
});

// Execute with security enforcement
const result = await crew.kickoff({
  topic: 'Build a secure REST API',
});

// Get audit report
const audit = securityCallback.onCrewComplete(result);
console.log(`Violations: ${audit.violations.length}`);
console.log(`Tools used: ${audit.toolUsage.length}`);
```

### Hierarchical Crew with Security

```typescript
import { Crew, Process } from 'crewai';
import { ClawdstrikeCrewCallback } from '@clawdstrike/crewai';

const securityConfig: CrewAIClawdstrikeConfig = {
  globalPolicy: 'clawdstrike:ai-agent',

  // Manager has elevated privileges
  rolePolicies: {
    manager: {
      version: 'clawdstrike-v1.0',
      egress: { mode: 'open' }, // Manager can access any domain
      tools: { allowed: ['*'] },
    },
    worker: {
      version: 'clawdstrike-v1.0',
      egress: {
        mode: 'allowlist',
        allowed_domains: ['api.github.com'],
      },
      tools: {
        denied: ['bash', 'shell'],
      },
    },
  },

  // Only manager can delegate
  delegationPolicy: {
    allowedDelegations: {
      manager: ['worker'],
    },
    deniedDelegations: {
      worker: ['*'],
    },
  },
};

const crew = new Crew({
  agents: [managerAgent, ...workerAgents],
  tasks: tasks,
  process: Process.hierarchical,
  manager_llm: managerLLM,
  callbacks: [new ClawdstrikeCrewCallback(securityConfig)],
});

const result = await crew.kickoff();
```

## Configuration Examples

### Role-Based Policy Files

```yaml
# research-policy.yaml - For research agents
version: "clawdstrike-v1.0"
extends: ai-agent-minimal

egress:
  mode: allowlist
  allowed_domains:
    - "scholar.google.com"
    - "arxiv.org"
    - "pubmed.ncbi.nlm.nih.gov"
    - "api.semanticscholar.org"

filesystem:
  allowed_read_paths:
    - "./research"
    - "./papers"
  forbidden_paths:
    - "~/.ssh"
    - ".env"

tools:
  allowed:
    - "search"
    - "read_file"
    - "summarize"
  denied:
    - "bash"
    - "write_file"

on_violation: cancel
```

```yaml
# developer-policy.yaml - For developer agents
version: "clawdstrike-v1.0"
extends: ai-agent-minimal

egress:
  mode: allowlist
  allowed_domains:
    - "api.github.com"
    - "registry.npmjs.org"
    - "pypi.org"

filesystem:
  allowed_write_roots:
    - "./src"
    - "./tests"
  forbidden_paths:
    - "~/.ssh"
    - "~/.aws"
    - ".env"
    - "*.key"

execution:
  allowed_commands:
    - "npm"
    - "node"
    - "python"
    - "pytest"
  denied_patterns:
    - "rm -rf"
    - "sudo"

on_violation: cancel
```

## Testing Strategies

### Unit Tests

```typescript
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { ClawdstrikeCrewCallback, SecureAgentFactory } from '@clawdstrike/crewai';

describe('ClawdstrikeCrewCallback', () => {
  let callback: ClawdstrikeCrewCallback;

  beforeEach(() => {
    callback = new ClawdstrikeCrewCallback({
      policy: 'clawdstrike:ai-agent',
    });
  });

  it('should block forbidden tool usage', async () => {
    const agent = createMockAgent('test', 'worker');
    const tool = createMockTool('bash');

    const { decision } = await callback.onToolUse(agent, tool, {
      command: 'rm -rf /',
    });

    expect(decision.denied).toBe(true);
    expect(decision.reason).toContain('denied');
  });

  it('should enforce delegation policy', async () => {
    callback = new ClawdstrikeCrewCallback({
      delegationPolicy: {
        deniedDelegations: {
          worker: ['manager'],
        },
      },
    });

    const fromAgent = createMockAgent('worker1', 'worker');
    const toAgent = createMockAgent('manager1', 'manager');
    const task = createMockTask('test task');

    const decision = await callback.onDelegation(fromAgent, toAgent, task);

    expect(decision.denied).toBe(true);
    expect(decision.reason).toContain('denied');
  });

  it('should sanitize task output', async () => {
    const agent = createMockAgent('test', 'worker');
    const task = createMockTask('test task');
    const output = 'API key: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';

    const sanitized = await callback.onTaskComplete(task, agent, output);

    expect(sanitized).not.toContain('ghp_');
    expect(sanitized).toContain('[REDACTED]');
  });
});

describe('SecureAgentFactory', () => {
  it('should apply role-specific policies', () => {
    const factory = new SecureAgentFactory({
      rolePolicies: {
        admin: { tools: { allowed: ['*'] } },
        user: { tools: { denied: ['bash'] } },
      },
    });

    const admin = factory.createSecureAgent({
      name: 'Admin',
      role: 'admin',
      goal: 'Manage system',
      backstory: 'System admin',
    });

    const user = factory.createSecureAgent({
      name: 'User',
      role: 'user',
      goal: 'Use system',
      backstory: 'Regular user',
    });

    expect(admin.canUseTool('bash')).toBe(true);
    expect(user.canUseTool('bash')).toBe(false);
  });
});
```

### Integration Tests

```typescript
import { describe, it, expect } from 'vitest';
import { Agent, Crew, Task, Process } from 'crewai';
import { ClawdstrikeCrewCallback } from '@clawdstrike/crewai';

describe('CrewAI Integration', () => {
  it('should enforce policy across full crew execution', async () => {
    const violations: SecurityViolation[] = [];

    const callback = new ClawdstrikeCrewCallback({
      policy: 'clawdstrike:ai-agent',
      callbacks: {
        onViolation: (v) => violations.push(v),
      },
    });

    const agent = new Agent({
      name: 'Test Agent',
      role: 'tester',
      goal: 'Test security',
      backstory: 'Security tester',
      tools: [dangerousTool],
    });

    const task = new Task({
      description: 'Access ~/.ssh/id_rsa',
      agent: agent,
    });

    const crew = new Crew({
      agents: [agent],
      tasks: [task],
      process: Process.sequential,
      callbacks: [callback],
    });

    await crew.kickoff();

    expect(violations.length).toBeGreaterThan(0);
    expect(violations[0].decision.denied).toBe(true);
  });
});
```

## Implementation Phases

### Phase 1: Core Callback (Week 1-2)

- [ ] Implement `ClawdstrikeCrewCallback`
- [ ] Tool interception and policy evaluation
- [ ] Basic audit logging
- [ ] Delegation policy enforcement

### Phase 2: Secure Agent Factory (Week 3)

- [ ] Role-based policy resolution
- [ ] Tool wrapping with security
- [ ] Security context injection
- [ ] Agent-level permission checks

### Phase 3: Advanced Features (Week 4-5)

- [ ] Task chain depth tracking
- [ ] Inter-agent communication policy
- [ ] Output sanitization
- [ ] Comprehensive audit reports

### Phase 4: Testing & Documentation (Week 6)

- [ ] Unit test suite
- [ ] Integration tests with real crews
- [ ] Performance benchmarks
- [ ] Usage documentation and examples

## Appendix: CrewAI Callback Interface

```typescript
// CrewAI callback interface (TypeScript representation of Python callbacks)
// Note: CrewAI's native Python API uses step_callback and task_callback parameters
// This interface represents the Clawdstrike adapter's callback model

interface CrewCallback {
  // Called when crew starts (maps to crew.kickoff() entry)
  onCrewStart?(crew: Crew): void;

  // Called before task execution (maps to task_callback pre-hook)
  onTaskStart?(task: Task, agent: Agent): void;

  // Called when tool is invoked (maps to step_callback)
  onToolStart?(tool: Tool, input: string): void;
  onToolEnd?(tool: Tool, output: string): void;
  onToolError?(tool: Tool, error: Error): void;

  // Called on delegation (captured via agent.allow_delegation events)
  onDelegation?(fromAgent: Agent, toAgent: Agent, task: Task): void;

  // Called after task completion (maps to task_callback post-hook)
  onTaskEnd?(task: Task, output: string): void;

  // Called when crew completes (maps to crew.kickoff() exit)
  onCrewEnd?(crew: Crew, result: unknown): void;
}

// Native CrewAI Python callback signature for reference:
// step_callback: Callable[[AgentAction], None]
// task_callback: Callable[[Task, str], None]
```
