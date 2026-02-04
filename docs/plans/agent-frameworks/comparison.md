# Agent Framework Integration Comparison

## Executive Summary

This document provides a comprehensive comparison of Clawdstrike integration approaches across different AI agent frameworks. It analyzes the architectural patterns, implementation complexity, feature coverage, and trade-offs for each integration to help guide implementation priorities and inform architectural decisions.

## Version Reference

| Framework | Min Version | Package |
|-----------|------------|---------|
| LangChain/LangGraph | @langchain/core 0.2.0 | @clawdstrike/langchain |
| CrewAI | crewai 0.28.0 | @clawdstrike/crewai |
| AutoGPT | Auto-GPT 0.5.0 | @clawdstrike/autogpt |
| Vercel AI SDK | ai 3.0.0 | @clawdstrike/vercel-ai |
| Microsoft AutoGen | autogen 0.2.0 | @clawdstrike/autogen (P2) |

> See individual framework documentation for detailed version compatibility matrices.

## Framework Overview

| Framework | Primary Language | Tool Call Model | Streaming | Multi-Agent | Maturity |
|-----------|-----------------|-----------------|-----------|-------------|----------|
| **LangChain/LangGraph** | Python/TypeScript | Callback-based | Yes | Via LangGraph | High |
| **CrewAI** | Python | Role-based agents | Limited | Native | Medium |
| **AutoGPT/AgentGPT** | Python | Command registry | No | No | Medium |
| **Vercel AI SDK** | TypeScript | Middleware | Yes | No | High |
| **Microsoft AutoGen** | Python | Message-based | Yes | Native | Medium |

> **Note**: Microsoft AutoGen is marked as P2 priority. See overview.md for implementation phases.

## Interception Point Comparison

### Tool Call Lifecycle

```
                    LangChain    CrewAI    AutoGPT    Vercel AI    AutoGen
                    ─────────    ──────    ───────    ─────────    ───────
Pre-Definition          ✓           ✓         ✓          ✓          ✓
  (wrap tool)

Pre-Execution           ✓           ✓         ✓          ✓          ✓
  (before call)

During Execution        ○           ○         ○          ✓          ✓
  (streaming)

Post-Execution          ✓           ✓         ✓          ✓          ✓
  (after call)

Output Transform        ✓           ✓         ✓          ✓          ✓
  (sanitize)

Legend: ✓ = Full support, ○ = Partial/Limited, ✗ = Not supported
```

### Interception Mechanisms

| Framework | Primary Mechanism | Secondary Mechanism | Fallback |
|-----------|------------------|---------------------|----------|
| **LangChain** | CallbackHandler | Tool wrapper | RunnableConfig |
| **CrewAI** | Crew callbacks | Agent hooks | Tool decorator |
| **AutoGPT** | Command registry | Loop interceptor | Plugin sandbox |
| **Vercel AI** | Middleware | Tool wrapper | Stream transform |
| **AutoGen** (P2) | Message interceptor | Agent wrapper | Function decorator |

### Code Complexity for Basic Integration

```
Framework        Lines of Code    Concepts Required         Integration Time
───────────────────────────────────────────────────────────────────────────
LangChain             ~300         Callbacks, Runnables           2-3 days
CrewAI                ~250         Crews, Agents, Tasks           2 days
AutoGPT               ~400         Commands, Plugins              3-4 days
Vercel AI             ~200         Middleware, Streams            1-2 days
AutoGen               ~350         Messages, Agents               2-3 days
Generic Adapter       ~500         All patterns                   4-5 days
```

## Architecture Comparison

### LangChain/LangGraph

```
┌────────────────────────────────────────────────────────────┐
│                     LangChain Agent                         │
├────────────────────────────────────────────────────────────┤
│  ┌──────────────────────────────────────────────────────┐ │
│  │           ClawdstrikeCallbackHandler                  │ │
│  │  handleToolStart() ─────> Policy Evaluation           │ │
│  │  handleToolEnd() ───────> Output Sanitization         │ │
│  └──────────────────────────────────────────────────────┘ │
│                           │                                │
│  ┌──────────────────────────────────────────────────────┐ │
│  │              SecureToolWrapper                        │ │
│  │  _call() ───────────────> Pre-check + Execute         │ │
│  └──────────────────────────────────────────────────────┘ │
│                           │                                │
│  ┌──────────────────────────────────────────────────────┐ │
│  │          LangGraph Security Node                      │ │
│  │  check() ───────────────> State Validation            │ │
│  │  route() ───────────────> Conditional Edge            │ │
│  └──────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────┘

Strengths:
✓ Multiple interception points
✓ Works with any chain/agent type
✓ LangGraph state machine integration
✓ Rich callback event system

Weaknesses:
✗ Callbacks can't modify output directly
✗ Complex callback hierarchy
✗ Async context management
```

### CrewAI

```
┌────────────────────────────────────────────────────────────┐
│                      SecureCrew                             │
├────────────────────────────────────────────────────────────┤
│  ┌──────────────────────────────────────────────────────┐ │
│  │           ClawdstrikeCrewCallback                     │ │
│  │  onToolUse() ───────────> Per-agent policy eval       │ │
│  │  onDelegation() ────────> Delegation control          │ │
│  │  onTaskComplete() ──────> Output sanitization         │ │
│  └──────────────────────────────────────────────────────┘ │
│                           │                                │
│  ┌──────────────────────────────────────────────────────┐ │
│  │              SecureAgentFactory                       │ │
│  │  createSecureAgent() ───> Role-based policy           │ │
│  │  wrapTool() ────────────> Tool-level security         │ │
│  └──────────────────────────────────────────────────────┘ │
│                           │                                │
│  ┌──────────────────────────────────────────────────────┐ │
│  │              PolicyManager                            │ │
│  │  loadRolePolicies() ────> Multi-policy support        │ │
│  │  mergePolicies() ───────> Policy composition          │ │
│  └──────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────┘

Strengths:
✓ Role-based security (matches CrewAI model)
✓ Delegation control
✓ Per-agent policies
✓ Clean callback model

Weaknesses:
✗ Limited streaming support
✗ Less mature callback system
✗ Hierarchical process complexity
```

### AutoGPT

```
┌────────────────────────────────────────────────────────────┐
│                   SecureAutoGPTAgent                        │
├────────────────────────────────────────────────────────────┤
│  ┌──────────────────────────────────────────────────────┐ │
│  │          ClawdstrikeSecurityLayer                     │ │
│  │  wrapCommandRegistry() ─> Intercept all commands      │ │
│  │  wrapRunLoop() ─────────> Iteration control           │ │
│  │  wrapMemory() ──────────> Memory sanitization         │ │
│  └──────────────────────────────────────────────────────┘ │
│                           │                                │
│  ┌──────────────────────────────────────────────────────┐ │
│  │              CommandInterceptor                       │ │
│  │  intercept() ───────────> Pre-execution check         │ │
│  │  checkDangerousPatterns() -> Pattern matching         │ │
│  └──────────────────────────────────────────────────────┘ │
│                           │                                │
│  ┌──────────────────────────────────────────────────────┐ │
│  │              PluginSandbox                            │ │
│  │  loadPlugin() ──────────> Capability-based sandbox    │ │
│  │  executeInSandbox() ────> Isolated execution          │ │
│  └──────────────────────────────────────────────────────┘ │
│                           │                                │
│  ┌──────────────────────────────────────────────────────┐ │
│  │              ResourceLimiter                          │ │
│  │  checkResource() ───────> Usage tracking              │ │
│  │  enforceLimit() ────────> Resource caps               │ │
│  └──────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────┘

Strengths:
✓ Comprehensive security layer
✓ Plugin sandboxing
✓ Resource limiting
✓ Human-in-the-loop approval

Weaknesses:
✗ Complex architecture
✗ No streaming support
✗ Autonomous nature requires more controls
✗ Memory security is challenging
```

### Vercel AI SDK

```
┌────────────────────────────────────────────────────────────┐
│                   Secure AI Pipeline                        │
├────────────────────────────────────────────────────────────┤
│  ┌──────────────────────────────────────────────────────┐ │
│  │          ClawdstrikeMiddleware                        │ │
│  │  wrapLanguageModel() ───> Model-level interception    │ │
│  │  wrapTools() ───────────> Tool wrapping               │ │
│  └──────────────────────────────────────────────────────┘ │
│                           │                                │
│  ┌──────────────────────────────────────────────────────┐ │
│  │            StreamingToolGuard                         │ │
│  │  processChunk() ────────> Incremental evaluation      │ │
│  │  accumulateToolCall() ──> Stream accumulation         │ │
│  └──────────────────────────────────────────────────────┘ │
│                           │                                │
│  ┌──────────────────────────────────────────────────────┐ │
│  │              useSecureChat                            │ │
│  │  securityStatus ────────> React state                 │ │
│  │  preflightCheck() ──────> UI-level checks             │ │
│  └──────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────┘

Strengths:
✓ Native streaming support
✓ React hooks integration
✓ Simple middleware pattern
✓ Edge runtime compatible

Weaknesses:
✗ Limited to Vercel AI patterns
✗ No multi-agent support
✗ TypeScript only
```

## Feature Matrix

### Security Features

| Feature | LangChain | CrewAI | AutoGPT | Vercel AI | AutoGen |
|---------|-----------|--------|---------|-----------|---------|
| Pre-execution policy check | ✓ | ✓ | ✓ | ✓ | ✓ |
| Post-execution sanitization | ✓ | ✓ | ✓ | ✓ | ✓ |
| Secret redaction | ✓ | ✓ | ✓ | ✓ | ✓ |
| Path blocking | ✓ | ✓ | ✓ | ✓ | ✓ |
| Network egress control | ✓ | ✓ | ✓ | ✓ | ✓ |
| Command validation | ✓ | ✓ | ✓ | ✓ | ✓ |
| Tool allow/deny lists | ✓ | ✓ | ✓ | ✓ | ✓ |
| Role-based policies | ○ | ✓ | ○ | ○ | ✓ |
| Resource limiting | ○ | ○ | ✓ | ○ | ○ |
| Human-in-the-loop | ○ | ○ | ✓ | ○ | ✓ |
| Plugin sandboxing | ✗ | ✗ | ✓ | ✗ | ✗ |
| Memory sanitization | ○ | ○ | ✓ | ✗ | ○ |
| Streaming evaluation | ○ | ✗ | ✗ | ✓ | ✓ |

### Integration Features

| Feature | LangChain | CrewAI | AutoGPT | Vercel AI | AutoGen |
|---------|-----------|--------|---------|-----------|---------|
| Callback handler | ✓ | ✓ | ○ | ○ | ✓ |
| Tool wrapper | ✓ | ✓ | ✓ | ✓ | ✓ |
| Middleware pattern | ○ | ○ | ○ | ✓ | ○ |
| State machine integration | ✓ | ○ | ✗ | ✗ | ○ |
| React hooks | ○ | ✗ | ✗ | ✓ | ✗ |
| Security prompt injection | ✓ | ✓ | ✓ | ✓ | ✓ |
| Audit logging | ✓ | ✓ | ✓ | ✓ | ✓ |
| Configuration portability | ✓ | ✓ | ✓ | ✓ | ✓ |

## API Consistency

### Tool Wrapping Pattern

All frameworks follow a similar wrapping pattern:

```typescript
// LangChain
const secureTools = wrapTools([tool1, tool2], config);

// CrewAI
const secureTools = factory.wrapTools([tool1, tool2]);

// AutoGPT
const secureRegistry = securityLayer.wrapCommandRegistry(registry);

// Vercel AI
const secureTools = middleware.wrapTools({ tool1, tool2 });
```

### Policy Evaluation

Consistent policy evaluation across frameworks:

```typescript
// All frameworks use the same PolicyEngine
const engine = new PolicyEngine(config);

// Same PolicyEvent structure
const event: PolicyEvent = {
  eventId: string,
  eventType: 'tool_call' | 'file_read' | 'network_egress' | ...,
  timestamp: string,
  data: EventData,
};

// Same Decision structure
const decision: Decision = {
  allowed: boolean,
  denied: boolean,
  warn: boolean,
  reason?: string,
  guard?: string,
  severity?: Severity,
};
```

### Configuration

Shared configuration base:

```typescript
// Base config works for all frameworks
const baseConfig: ClawdstrikeConfig = {
  policy: 'clawdstrike:ai-agent',
  mode: 'deterministic',
  logLevel: 'info',
  guards: {
    forbidden_path: true,
    egress: true,
    secret_leak: true,
    patch_integrity: true,
  },
};

// Framework-specific extensions
const langchainConfig: LangChainClawdstrikeConfig = {
  ...baseConfig,
  blockOnViolation: true,
  toolNameMapping: { ... },
};

const crewaiConfig: CrewAIClawdstrikeConfig = {
  ...baseConfig,
  rolePolicies: { ... },
  delegationPolicy: { ... },
};
```

## Performance Comparison

### Latency Overhead

```
Operation                    LangChain   CrewAI   AutoGPT   Vercel AI   AutoGen
───────────────────────────────────────────────────────────────────────────────
Policy evaluation (avg)         2ms        2ms      2ms       2ms        2ms
Output sanitization (avg)       1ms        1ms      1ms       1ms        1ms
Full interception cycle         5ms        5ms      6ms       4ms        5ms
Streaming chunk process          -          -        -       0.5ms      0.5ms
```

### Memory Overhead

```
Component                    Size (approx)
────────────────────────────────────────────
PolicyEngine instance           ~50KB
Guard instances (5)             ~25KB
Audit log (1000 events)         ~200KB
Security context                ~5KB
```

### Scalability Considerations

| Framework | Concurrent Sessions | Memory Growth | GC Impact |
|-----------|-------------------|---------------|-----------|
| LangChain | High | Linear | Low |
| CrewAI | Medium | Linear per agent | Medium |
| AutoGPT | Low (autonomous) | Can grow unbounded | High |
| Vercel AI | High (stateless) | Minimal | Very Low |
| AutoGen | Medium | Linear per agent | Medium |

## Implementation Priority Recommendation

### Priority Matrix

```
                    Impact
                    High │ LangChain    Vercel AI
                         │ (P0)         (P0)
                         │
                         │ CrewAI
                         │ (P1)
                         │
                    Low  │              AutoGPT
                         │              (P1)
                         └──────────────────────────
                              Low            High
                                    Effort
```

### Recommended Order

1. **Phase 1 (P0)**: Vercel AI SDK + Generic Adapter Core
   - Rationale: Simplest integration, high impact, TypeScript-first
   - Timeline: 4-5 weeks

2. **Phase 2 (P0)**: LangChain/LangGraph
   - Rationale: Largest user base, comprehensive feature set
   - Timeline: 5-6 weeks

3. **Phase 3 (P1)**: CrewAI
   - Rationale: Growing adoption, good role-based model fit
   - Timeline: 4 weeks

4. **Phase 4 (P1)**: AutoGPT/AgentGPT
   - Rationale: Most complex, but critical for autonomous agents
   - Timeline: 6-7 weeks

## Migration Path

### From Framework-Specific to Generic

If teams need to switch frameworks, the generic adapter provides a migration path:

```typescript
// Step 1: Use generic adapter interface
import { FrameworkAdapter, AdapterConfig } from '@clawdstrike/adapter-core';

// Step 2: Create framework-agnostic security layer
const config: AdapterConfig = {
  policy: 'clawdstrike:ai-agent',
  blockOnViolation: true,
};

// Step 3: Initialize with specific adapter
import { LangChainAdapter } from '@clawdstrike/langchain';
// or
import { VercelAIAdapter } from '@clawdstrike/vercel-ai';

const adapter: FrameworkAdapter = new LangChainAdapter();
// Switching is just changing the import and instantiation
await adapter.initialize(config);
```

## Testing Strategy Comparison

### Unit Testing

| Framework | Test Complexity | Mock Requirements | Coverage Target |
|-----------|----------------|-------------------|-----------------|
| LangChain | Medium | Serialized objects | 90% |
| CrewAI | Medium | Agent/Crew mocks | 85% |
| AutoGPT | High | Command registry | 85% |
| Vercel AI | Low | Tool definitions | 95% |
| AutoGen | Medium | Agent/message mocks | 85% |

### Integration Testing

| Framework | E2E Test Approach | Dependencies | CI Time |
|-----------|-------------------|--------------|---------|
| LangChain | Agent executor | LLM mock | 2-3 min |
| CrewAI | Full crew run | Multiple LLM mocks | 3-4 min |
| AutoGPT | Loop iterations | LLM + commands | 4-5 min |
| Vercel AI | Stream simulation | LLM mock | 1-2 min |
| AutoGen | Multi-agent conversation | Multiple LLM mocks | 3-4 min |

### Property-Based Testing

All frameworks benefit from property-based tests for security invariants:

```typescript
// Common property tests applicable to all frameworks
describe('Security Invariants', () => {
  // Forbidden paths should always be blocked regardless of encoding
  fc.assert(
    fc.property(forbiddenPathArbitrary, async (path) => {
      const result = await interceptor.beforeExecute('read_file', { path }, ctx);
      return !result.proceed;
    })
  );

  // Secret patterns should always be redacted
  fc.assert(
    fc.property(secretPatternArbitrary, (secret) => {
      const sanitized = sanitizer.sanitize(secret, ctx);
      return !containsSecret(sanitized);
    })
  );
});
```

## Conclusion

### Key Findings

1. **Architectural Consistency**: Despite different framework APIs, all integrations can share:
   - PolicyEngine and guards
   - Policy configuration format
   - Audit event structure
   - Decision model

2. **Framework-Specific Adaptations**:
   - LangChain: Callback system + state machine
   - CrewAI: Role-based policies + delegation control
   - AutoGPT: Resource limiting + human approval
   - Vercel AI: Streaming evaluation + React hooks

3. **Generic Adapter Value**: The generic adapter pattern enables:
   - Faster onboarding for new frameworks
   - Consistent security semantics
   - Easier testing and maintenance
   - Migration flexibility

### Recommendations

1. **Start with Vercel AI + Generic Adapter**: Establishes patterns and core components
2. **Prioritize LangChain**: Largest ecosystem impact
3. **Design for extensibility**: New frameworks should be < 1 week to integrate
4. **Maintain consistency**: Same policy files should work across all frameworks
5. **Invest in testing**: Property-based tests for security invariants are critical
