# Guard Composition DSL

## Document Information

| Field | Value |
|-------|-------|
| **Status** | Draft |
| **Version** | 0.1.0 |
| **Authors** | Clawdstrike Architecture Team |
| **Last Updated** | 2026-02-02 |
| **Prerequisites** | overview.md, plugin-system.md |

---

## 1. Problem Statement

### 1.1 Current Limitations

Today, guards operate independently:

```yaml
guards:
  forbidden_path: { ... }
  egress_allowlist: { ... }
  secret_leak: { ... }
```

Each guard produces a result, and the policy engine applies a simple "any deny = deny" logic. This is insufficient for complex security policies:

1. **Conditional enforcement**: "Block this action ONLY IF both conditions are met"
2. **Exception handling**: "Allow this action IF it passes guard A OR guard B"
3. **Risk scoring**: "Warn if 2+ guards flag, block if 3+ guards flag"
4. **Context-dependent rules**: "If the user is admin, skip this check"

### 1.2 Use Cases

1. **Defense in depth**: Block only if multiple independent signals agree
2. **Compliance exceptions**: Allow certain actions for compliance-approved tools
3. **Progressive rollout**: Warn first, then block after confidence builds
4. **Complex threat detection**: Multi-stage attack detection

### 1.3 Goals

1. Express complex guard relationships declaratively in YAML
2. Support AND, OR, NOT, IF_THEN, and custom logic
3. Maintain deterministic evaluation order
4. Provide clear debugging and audit trails

---

## 2. DSL Design

### 2.1 Basic Syntax

```yaml
guards:
  composition:
    # Simple AND: both must allow
    - name: "dual_check_secrets"
      AND:
        - guard: secret_leak
        - guard: custom_secrets
      action: deny

    # Simple OR: at least one must allow
    - name: "approved_egress"
      OR:
        - guard: egress_allowlist
        - guard: approved_vendors
      action: allow

    # NOT: invert a guard result
    - name: "not_internal_path"
      NOT:
        guard: internal_paths
      action: deny

    # IF_THEN: conditional execution
    - name: "admin_bypass"
      IF_THEN:
        if:
          context: "user.role == 'admin'"
        then:
          action: allow
        else:
          guard: strict_egress
```

### 2.2 Extended Syntax

```yaml
guards:
  composition:
    # Nested composition
    - name: "complex_policy"
      AND:
        - OR:
            - guard: approved_tools
            - guard: emergency_override
        - NOT:
            guard: known_malicious
        - guard: rate_limit

    # With event filtering
    - name: "write_only_check"
      when:
        eventType: [file_write, patch_apply]
      AND:
        - guard: forbidden_path
        - guard: secret_leak

    # With severity override
    - name: "warn_not_block"
      OR:
        - guard: suspicious_pattern
        - guard: unusual_time
      action: warn
      severity: warning

    # With threshold (N of M)
    - name: "consensus_deny"
      N_OF:
        n: 2
        guards:
          - secret_leak
          - prompt_injection
          - suspicious_egress
      action: deny
      message: "Multiple security signals triggered"

    # With weighted scoring
    - name: "risk_score"
      SCORE:
        threshold: 70
        weights:
          - guard: secret_leak
            score: 50
          - guard: suspicious_pattern
            score: 30
          - guard: unusual_time
            score: 20
          - guard: new_tool
            score: 10
      action: deny
      message: "Risk score exceeded threshold"
```

### 2.3 Grammar Specification

```ebnf
(* Composition DSL Grammar *)

composition     = composition_rule+ ;
composition_rule = name , operator , action? , options? ;

name            = "name" , ":" , string ;
operator        = and_op | or_op | not_op | if_then_op | n_of_op | score_op ;

and_op          = "AND" , ":" , guard_list ;
or_op           = "OR" , ":" , guard_list ;
not_op          = "NOT" , ":" , guard_ref ;
if_then_op      = "IF_THEN" , ":" , if_clause , then_clause , else_clause? ;
n_of_op         = "N_OF" , ":" , n_value , guard_list ;
score_op        = "SCORE" , ":" , threshold , weighted_guards ;

guard_list      = "[" , (guard_ref | operator) , ("," , (guard_ref | operator))* , "]" ;
guard_ref       = "guard" , ":" , string , guard_options? ;
guard_options   = "config" , ":" , object ;

if_clause       = "if" , ":" , condition ;
then_clause     = "then" , ":" , (action | guard_ref) ;
else_clause     = "else" , ":" , (action | guard_ref) ;

condition       = context_condition | guard_condition ;
context_condition = "context" , ":" , expression ;
guard_condition = "guard" , ":" , string , result_matcher? ;
result_matcher  = "result" , ":" , ("allow" | "deny" | "warn") ;

action          = "action" , ":" , ("allow" | "deny" | "warn") ;
options         = (severity | message | when | metadata)* ;
severity        = "severity" , ":" , ("low" | "medium" | "high" | "critical") ;
message         = "message" , ":" , string ;
when            = "when" , ":" , event_filter ;
event_filter    = "eventType" , ":" , event_type_list ;

n_value         = "n" , ":" , integer ;
threshold       = "threshold" , ":" , number ;
weighted_guards = "weights" , ":" , weighted_guard+ ;
weighted_guard  = "guard" , ":" , string , "score" , ":" , number ;
```

---

## 3. Evaluation Semantics

### 3.1 Evaluation Order

```
+------------------------------------------------------------------+
|                    Composition Evaluation                         |
+------------------------------------------------------------------+
|                                                                    |
|  1. Pre-filter by event type (when clause)                        |
|     └── Skip composition if event doesn't match                   |
|                                                                    |
|  2. Evaluate operands (depth-first)                               |
|     └── AND: Evaluate left-to-right, short-circuit on deny       |
|     └── OR: Evaluate left-to-right, short-circuit on allow       |
|     └── NOT: Evaluate inner, invert result                        |
|     └── IF_THEN: Evaluate condition, then branch                  |
|     └── N_OF: Evaluate all, count results                         |
|     └── SCORE: Evaluate all, sum weighted scores                  |
|                                                                    |
|  3. Apply action override (if specified)                          |
|     └── Can change deny→warn, warn→allow, etc.                   |
|                                                                    |
|  4. Apply severity override (if specified)                        |
|                                                                    |
|  5. Return CompositionResult                                      |
|                                                                    |
+------------------------------------------------------------------+
```

### 3.2 Truth Tables

#### AND Operator

| Guard A | Guard B | Result |
|---------|---------|--------|
| allow   | allow   | allow  |
| allow   | deny    | deny   |
| allow   | warn    | warn   |
| deny    | *       | deny   |
| warn    | allow   | warn   |
| warn    | deny    | deny   |
| warn    | warn    | warn   |

#### OR Operator

| Guard A | Guard B | Result |
|---------|---------|--------|
| allow   | *       | allow  |
| deny    | allow   | allow  |
| deny    | deny    | deny   |
| deny    | warn    | warn   |
| warn    | allow   | allow  |
| warn    | deny    | warn   |
| warn    | warn    | warn   |

#### NOT Operator

| Guard   | Result |
|---------|--------|
| allow   | deny   |
| deny    | allow  |
| warn    | warn   |

> **Note on `warn` semantics:** The NOT operator preserves `warn` status because warnings represent an advisory state that should not be logically inverted. Inverting a warning would lose the informational signal that something noteworthy occurred. If you need to invert warning behavior, use explicit IF_THEN logic with action overrides.

### 3.3 Short-Circuit Evaluation

```typescript
// AND short-circuits on first deny
async function evaluateAnd(guards: Guard[], event: PolicyEvent): Promise<GuardResult> {
  for (const guard of guards) {
    const result = await guard.check(event);
    if (result.status === 'deny') {
      return result; // Short-circuit
    }
  }
  return { status: 'allow', guard: 'composition' };
}

// OR short-circuits on first allow
async function evaluateOr(guards: Guard[], event: PolicyEvent): Promise<GuardResult> {
  let lastResult: GuardResult | null = null;

  for (const guard of guards) {
    const result = await guard.check(event);
    if (result.status === 'allow') {
      return result; // Short-circuit
    }
    lastResult = result;
  }

  return lastResult ?? { status: 'deny', guard: 'composition' };
}
```

---

## 4. API Design

### 4.1 TypeScript Interface

```typescript
// @clawdstrike/guard-sdk

/**
 * Composition rule types
 */
export type CompositionRule =
  | AndRule
  | OrRule
  | NotRule
  | IfThenRule
  | NOfRule
  | ScoreRule;

export interface AndRule {
  name: string;
  AND: (GuardRef | CompositionRule)[];
  action?: 'allow' | 'deny' | 'warn';
  when?: EventFilter;
  severity?: Severity;
  message?: string;
}

export interface OrRule {
  name: string;
  OR: (GuardRef | CompositionRule)[];
  action?: 'allow' | 'deny' | 'warn';
  when?: EventFilter;
  severity?: Severity;
  message?: string;
}

export interface NotRule {
  name: string;
  NOT: GuardRef;
  action?: 'allow' | 'deny' | 'warn';
  when?: EventFilter;
  severity?: Severity;
  message?: string;
}

export interface IfThenRule {
  name: string;
  IF_THEN: {
    if: Condition;
    then: GuardRef | ActionSpec;
    else?: GuardRef | ActionSpec;
  };
  when?: EventFilter;
}

export interface NOfRule {
  name: string;
  N_OF: {
    n: number;
    guards: GuardRef[];
  };
  action?: 'allow' | 'deny' | 'warn';
  when?: EventFilter;
  severity?: Severity;
  message?: string;
}

export interface ScoreRule {
  name: string;
  SCORE: {
    threshold: number;
    weights: WeightedGuard[];
  };
  action?: 'allow' | 'deny' | 'warn';
  when?: EventFilter;
  severity?: Severity;
  message?: string;
}

export interface GuardRef {
  guard: string;
  config?: Record<string, unknown>;
  result?: 'allow' | 'deny' | 'warn';
}

export interface WeightedGuard {
  guard: string;
  score: number;
}

export interface Condition {
  context?: string;  // Expression like "user.role == 'admin'"
  guard?: string;
  result?: 'allow' | 'deny' | 'warn';
}

export interface EventFilter {
  eventType?: EventType[];
  sessionId?: string;
  metadata?: Record<string, unknown>;
}

export interface ActionSpec {
  action: 'allow' | 'deny' | 'warn';
  reason?: string;
}

/**
 * Composition evaluator
 */
export interface CompositionEvaluator {
  /**
   * Evaluate a composition rule against an event
   */
  evaluate(
    rule: CompositionRule,
    event: PolicyEvent,
    context: EvaluationContext
  ): Promise<CompositionResult>;

  /**
   * Validate composition rule syntax
   */
  validate(rule: CompositionRule): ValidationResult;

  /**
   * Get dependency graph for a composition
   */
  getDependencies(rule: CompositionRule): string[];
}

/**
 * Result from composition evaluation
 */
export interface CompositionResult {
  status: 'allow' | 'deny' | 'warn';
  rule: string;
  severity?: Severity;
  message?: string;

  /**
   * Trace of evaluated guards
   */
  trace: EvaluationTrace[];

  /**
   * Final score (for SCORE rules)
   */
  score?: number;
}

export interface EvaluationTrace {
  guard: string;
  result: GuardResult;
  durationMs: number;
  skipped?: boolean;
  skipReason?: string;
}
```

### 4.2 Rust Interface

```rust
// clawdstrike-guard-sdk

use serde::{Deserialize, Serialize};

/// Composition rule types
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CompositionRule {
    And(AndRule),
    Or(OrRule),
    Not(NotRule),
    IfThen(IfThenRule),
    NOf(NOfRule),
    Score(ScoreRule),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AndRule {
    pub name: String,
    #[serde(rename = "AND")]
    pub operands: Vec<Operand>,
    pub action: Option<GuardStatus>,
    pub when: Option<EventFilter>,
    pub severity: Option<Severity>,
    pub message: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrRule {
    pub name: String,
    #[serde(rename = "OR")]
    pub operands: Vec<Operand>,
    pub action: Option<GuardStatus>,
    pub when: Option<EventFilter>,
    pub severity: Option<Severity>,
    pub message: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NotRule {
    pub name: String,
    #[serde(rename = "NOT")]
    pub operand: GuardRef,
    pub action: Option<GuardStatus>,
    pub when: Option<EventFilter>,
    pub severity: Option<Severity>,
    pub message: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IfThenRule {
    pub name: String,
    #[serde(rename = "IF_THEN")]
    pub branches: IfThenBranches,
    pub when: Option<EventFilter>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IfThenBranches {
    pub r#if: Condition,
    pub then: ThenBranch,
    pub r#else: Option<ThenBranch>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NOfRule {
    pub name: String,
    #[serde(rename = "N_OF")]
    pub spec: NOfSpec,
    pub action: Option<GuardStatus>,
    pub when: Option<EventFilter>,
    pub severity: Option<Severity>,
    pub message: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NOfSpec {
    pub n: usize,
    pub guards: Vec<GuardRef>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScoreRule {
    pub name: String,
    #[serde(rename = "SCORE")]
    pub spec: ScoreSpec,
    pub action: Option<GuardStatus>,
    pub when: Option<EventFilter>,
    pub severity: Option<Severity>,
    pub message: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScoreSpec {
    pub threshold: f64,
    pub weights: Vec<WeightedGuard>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Operand {
    Guard(GuardRef),
    Composition(Box<CompositionRule>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardRef {
    pub guard: String,
    pub config: Option<serde_json::Value>,
    pub result: Option<GuardStatus>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WeightedGuard {
    pub guard: String,
    pub score: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Condition {
    pub context: Option<String>,
    pub guard: Option<String>,
    pub result: Option<GuardStatus>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ThenBranch {
    Guard(GuardRef),
    Action(ActionSpec),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActionSpec {
    pub action: GuardStatus,
    pub reason: Option<String>,
}

/// Composition evaluator trait
#[async_trait]
pub trait CompositionEvaluator: Send + Sync {
    /// Evaluate a composition rule against an event
    async fn evaluate(
        &self,
        rule: &CompositionRule,
        event: &PolicyEvent,
        context: &EvaluationContext,
    ) -> Result<CompositionResult, CompositionError>;

    /// Validate composition rule syntax
    fn validate(&self, rule: &CompositionRule) -> ValidationResult;

    /// Get dependency graph for a composition
    fn get_dependencies(&self, rule: &CompositionRule) -> Vec<String>;
}

/// Result from composition evaluation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompositionResult {
    pub status: GuardStatus,
    pub rule: String,
    pub severity: Option<Severity>,
    pub message: Option<String>,
    pub trace: Vec<EvaluationTrace>,
    pub score: Option<f64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvaluationTrace {
    pub guard: String,
    pub result: GuardResult,
    pub duration_ms: u64,
    pub skipped: bool,
    pub skip_reason: Option<String>,
}
```

---

## 5. Context Expressions

### 5.1 Expression Language

For the `context` field in IF_THEN conditions, we use a simple expression language:

```
# Variable access
user.role
event.metadata.priority
session.startTime

# Comparison operators
user.role == 'admin'
event.data.size > 1000000
session.duration < 3600

# Logical operators
user.role == 'admin' && user.verified
file.path.startsWith('/tmp') || file.path.startsWith('/var/tmp')
!user.mfaEnabled

# List operations
user.groups.contains('security-team')
event.tags.any(t => t.startsWith('critical'))

# Time functions
now() > session.startTime + 3600
event.timestamp.hour >= 9 && event.timestamp.hour <= 17
```

### 5.2 Available Context Variables

```typescript
interface EvaluationContext {
  // User/agent context
  user?: {
    id: string;
    role?: string;
    groups?: string[];
    verified?: boolean;
    mfaEnabled?: boolean;
  };

  // Session context
  session?: {
    id: string;
    startTime: number;      // Unix timestamp
    duration: number;       // Seconds since start
    eventCount: number;     // Events in this session
  };

  // Event context (always available)
  event: {
    id: string;
    type: EventType;
    timestamp: number;
    metadata: Record<string, unknown>;
    data: EventData;
  };

  // Environment context
  env?: {
    name: string;           // 'production', 'staging', 'development'
    region?: string;
    timezone?: string;
  };

  // Custom context (plugin-provided)
  custom?: Record<string, unknown>;
}
```

### 5.3 Expression Parser

```typescript
// expression-parser.ts

import { Parser, Expression, Value } from './parser-types';

export class ContextExpressionParser implements Parser {
  /**
   * Parse expression string into AST
   */
  parse(expr: string): Expression {
    const tokens = this.tokenize(expr);
    return this.parseExpression(tokens);
  }

  /**
   * Evaluate expression against context
   */
  evaluate(expr: Expression, context: EvaluationContext): Value {
    switch (expr.type) {
      case 'literal':
        return expr.value;

      case 'variable':
        return this.resolveVariable(expr.path, context);

      case 'binary':
        const left = this.evaluate(expr.left, context);
        const right = this.evaluate(expr.right, context);
        return this.applyOperator(expr.operator, left, right);

      case 'unary':
        const operand = this.evaluate(expr.operand, context);
        return this.applyUnaryOperator(expr.operator, operand);

      case 'call':
        const args = expr.args.map(a => this.evaluate(a, context));
        return this.callFunction(expr.name, args, context);

      default:
        throw new Error(`Unknown expression type: ${(expr as any).type}`);
    }
  }

  private resolveVariable(path: string[], context: EvaluationContext): Value {
    let current: any = context;
    for (const segment of path) {
      if (current == null) return null;
      current = current[segment];
    }
    return current;
  }

  private applyOperator(op: string, left: Value, right: Value): Value {
    switch (op) {
      case '==': return left === right;
      case '!=': return left !== right;
      case '<': return (left as number) < (right as number);
      case '>': return (left as number) > (right as number);
      case '<=': return (left as number) <= (right as number);
      case '>=': return (left as number) >= (right as number);
      case '&&': return left && right;
      case '||': return left || right;
      case '+': return (left as number) + (right as number);
      case '-': return (left as number) - (right as number);
      default:
        throw new Error(`Unknown operator: ${op}`);
    }
  }

  private callFunction(name: string, args: Value[], context: EvaluationContext): Value {
    switch (name) {
      case 'now':
        return Date.now() / 1000;

      case 'contains':
        return (args[0] as any[]).includes(args[1]);

      case 'startsWith':
        return (args[0] as string).startsWith(args[1] as string);

      case 'endsWith':
        return (args[0] as string).endsWith(args[1] as string);

      case 'matches':
        return new RegExp(args[1] as string).test(args[0] as string);

      default:
        throw new Error(`Unknown function: ${name}`);
    }
  }
}
```

---

## 6. Configuration Schema

### 6.1 Full Policy Example

```yaml
version: "1.1.0"
name: "Complex Security Policy"

guards:
  # Standard guards
  forbidden_path:
    patterns: ["**/.ssh/**", "**/.aws/**"]

  egress_allowlist:
    allow: ["*.github.com", "api.anthropic.com"]

  secret_leak:
    patterns:
      - name: api_key
        pattern: "sk-[A-Za-z0-9]{48}"

  # Custom guards
  custom:
    - package: "@company/clawdstrike-rate-limiter"
      config:
        requests_per_minute: 100

    - package: "@company/clawdstrike-business-hours"
      config:
        timezone: "America/Los_Angeles"
        start_hour: 9
        end_hour: 17

  # Composition rules
  composition:
    # Defense in depth: require multiple signals to block
    - name: "high_confidence_threat"
      AND:
        - guard: secret_leak
        - guard: suspicious_pattern
        - guard: unusual_time
      action: deny
      severity: critical
      message: "Multiple threat indicators detected"

    # Allow emergency access
    - name: "emergency_bypass"
      IF_THEN:
        if:
          context: "user.groups.contains('incident-response')"
        then:
          action: allow
        else:
          guard: strict_egress

    # Time-based enforcement
    - name: "after_hours_strict"
      IF_THEN:
        if:
          context: "event.timestamp.hour < 9 || event.timestamp.hour > 17"
        then:
          AND:
            - guard: forbidden_path
            - guard: egress_allowlist
            - guard: rate_limiter
        else:
          guard: forbidden_path

    # Risk scoring
    - name: "risk_based_blocking"
      SCORE:
        threshold: 60
        weights:
          - guard: secret_leak
            score: 40
          - guard: unusual_egress
            score: 25
          - guard: high_volume
            score: 20
          - guard: new_tool
            score: 15
      action: deny
      message: "Risk score exceeded threshold"

    # Consensus-based detection
    - name: "multi_signal_alert"
      N_OF:
        n: 2
        guards:
          - prompt_injection
          - data_exfiltration
          - privilege_escalation
      action: warn
      severity: warning
      message: "Multiple security signals - investigate"
```

### 6.2 Composition JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://clawdstrike.dev/schemas/composition.json",
  "title": "Guard Composition Schema",
  "type": "array",
  "items": {
    "$ref": "#/$defs/compositionRule"
  },
  "$defs": {
    "compositionRule": {
      "type": "object",
      "required": ["name"],
      "oneOf": [
        { "$ref": "#/$defs/andRule" },
        { "$ref": "#/$defs/orRule" },
        { "$ref": "#/$defs/notRule" },
        { "$ref": "#/$defs/ifThenRule" },
        { "$ref": "#/$defs/nOfRule" },
        { "$ref": "#/$defs/scoreRule" }
      ]
    },
    "andRule": {
      "type": "object",
      "required": ["name", "AND"],
      "properties": {
        "name": { "type": "string" },
        "AND": { "$ref": "#/$defs/operandList" },
        "action": { "$ref": "#/$defs/action" },
        "when": { "$ref": "#/$defs/eventFilter" },
        "severity": { "$ref": "#/$defs/severity" },
        "message": { "type": "string" }
      }
    },
    "orRule": {
      "type": "object",
      "required": ["name", "OR"],
      "properties": {
        "name": { "type": "string" },
        "OR": { "$ref": "#/$defs/operandList" },
        "action": { "$ref": "#/$defs/action" },
        "when": { "$ref": "#/$defs/eventFilter" },
        "severity": { "$ref": "#/$defs/severity" },
        "message": { "type": "string" }
      }
    },
    "notRule": {
      "type": "object",
      "required": ["name", "NOT"],
      "properties": {
        "name": { "type": "string" },
        "NOT": { "$ref": "#/$defs/guardRef" },
        "action": { "$ref": "#/$defs/action" },
        "when": { "$ref": "#/$defs/eventFilter" },
        "severity": { "$ref": "#/$defs/severity" },
        "message": { "type": "string" }
      }
    },
    "ifThenRule": {
      "type": "object",
      "required": ["name", "IF_THEN"],
      "properties": {
        "name": { "type": "string" },
        "IF_THEN": {
          "type": "object",
          "required": ["if", "then"],
          "properties": {
            "if": { "$ref": "#/$defs/condition" },
            "then": { "$ref": "#/$defs/thenBranch" },
            "else": { "$ref": "#/$defs/thenBranch" }
          }
        },
        "when": { "$ref": "#/$defs/eventFilter" }
      }
    },
    "nOfRule": {
      "type": "object",
      "required": ["name", "N_OF"],
      "properties": {
        "name": { "type": "string" },
        "N_OF": {
          "type": "object",
          "required": ["n", "guards"],
          "properties": {
            "n": { "type": "integer", "minimum": 1 },
            "guards": {
              "type": "array",
              "items": { "$ref": "#/$defs/guardRef" }
            }
          }
        },
        "action": { "$ref": "#/$defs/action" },
        "when": { "$ref": "#/$defs/eventFilter" },
        "severity": { "$ref": "#/$defs/severity" },
        "message": { "type": "string" }
      }
    },
    "scoreRule": {
      "type": "object",
      "required": ["name", "SCORE"],
      "properties": {
        "name": { "type": "string" },
        "SCORE": {
          "type": "object",
          "required": ["threshold", "weights"],
          "properties": {
            "threshold": { "type": "number" },
            "weights": {
              "type": "array",
              "items": {
                "type": "object",
                "required": ["guard", "score"],
                "properties": {
                  "guard": { "type": "string" },
                  "score": { "type": "number" }
                }
              }
            }
          }
        },
        "action": { "$ref": "#/$defs/action" },
        "when": { "$ref": "#/$defs/eventFilter" },
        "severity": { "$ref": "#/$defs/severity" },
        "message": { "type": "string" }
      }
    },
    "operandList": {
      "type": "array",
      "items": {
        "oneOf": [
          { "$ref": "#/$defs/guardRef" },
          { "$ref": "#/$defs/compositionRule" }
        ]
      }
    },
    "guardRef": {
      "type": "object",
      "required": ["guard"],
      "properties": {
        "guard": { "type": "string" },
        "config": { "type": "object" },
        "result": { "$ref": "#/$defs/action" }
      }
    },
    "condition": {
      "type": "object",
      "properties": {
        "context": { "type": "string" },
        "guard": { "type": "string" },
        "result": { "$ref": "#/$defs/action" }
      }
    },
    "thenBranch": {
      "oneOf": [
        { "$ref": "#/$defs/guardRef" },
        {
          "type": "object",
          "required": ["action"],
          "properties": {
            "action": { "$ref": "#/$defs/action" },
            "reason": { "type": "string" }
          }
        }
      ]
    },
    "eventFilter": {
      "type": "object",
      "properties": {
        "eventType": {
          "type": "array",
          "items": { "$ref": "#/$defs/eventType" }
        }
      }
    },
    "action": {
      "type": "string",
      "enum": ["allow", "deny", "warn"]
    },
    "severity": {
      "type": "string",
      "enum": ["low", "medium", "high", "critical"]
    },
    "eventType": {
      "type": "string",
      "enum": ["file_read", "file_write", "command_exec", "network_egress", "tool_call", "patch_apply", "secret_access"]
    }
  }
}
```

---

## 7. Testing Framework

### 7.1 Composition Test Utilities

```typescript
// @clawdstrike/guard-sdk/testing

import { CompositionRule, CompositionResult, EvaluationContext, PolicyEvent } from '../types';

/**
 * Test harness for composition rules
 */
export class CompositionTestHarness {
  private evaluator: CompositionEvaluator;
  private mockGuards: Map<string, MockGuard> = new Map();

  /**
   * Mock a guard's behavior
   */
  mockGuard(name: string, behavior: MockGuardBehavior): this {
    this.mockGuards.set(name, new MockGuard(name, behavior));
    return this;
  }

  /**
   * Set guard to always allow
   */
  guardAllows(name: string): this {
    return this.mockGuard(name, { status: 'allow' });
  }

  /**
   * Set guard to always deny
   */
  guardDenies(name: string, reason?: string): this {
    return this.mockGuard(name, { status: 'deny', reason });
  }

  /**
   * Set guard to return based on event
   */
  guardConditional(name: string, fn: (event: PolicyEvent) => GuardResult): this {
    return this.mockGuard(name, { conditional: fn });
  }

  /**
   * Evaluate composition and return result
   */
  async evaluate(
    rule: CompositionRule,
    event: PolicyEvent,
    context?: Partial<EvaluationContext>
  ): Promise<CompositionResult> {
    const fullContext: EvaluationContext = {
      event: {
        id: event.eventId,
        type: event.eventType,
        timestamp: Date.now(),
        metadata: event.metadata ?? {},
        data: event.data,
      },
      ...context,
    };

    return this.evaluator.evaluate(rule, event, fullContext);
  }

  /**
   * Assert composition allows
   */
  async expectAllow(
    rule: CompositionRule,
    event: PolicyEvent,
    context?: Partial<EvaluationContext>
  ): Promise<void> {
    const result = await this.evaluate(rule, event, context);
    if (result.status !== 'allow') {
      throw new Error(
        `Expected allow, got ${result.status}. ` +
        `Trace: ${JSON.stringify(result.trace, null, 2)}`
      );
    }
  }

  /**
   * Assert composition denies
   */
  async expectDeny(
    rule: CompositionRule,
    event: PolicyEvent,
    context?: Partial<EvaluationContext>
  ): Promise<void> {
    const result = await this.evaluate(rule, event, context);
    if (result.status !== 'deny') {
      throw new Error(
        `Expected deny, got ${result.status}. ` +
        `Trace: ${JSON.stringify(result.trace, null, 2)}`
      );
    }
  }

  /**
   * Get evaluation trace for debugging
   */
  async getTrace(
    rule: CompositionRule,
    event: PolicyEvent,
    context?: Partial<EvaluationContext>
  ): Promise<EvaluationTrace[]> {
    const result = await this.evaluate(rule, event, context);
    return result.trace;
  }
}

interface MockGuardBehavior {
  status?: 'allow' | 'deny' | 'warn';
  reason?: string;
  conditional?: (event: PolicyEvent) => GuardResult;
}
```

### 7.2 Composition Test Example

```typescript
// tests/composition.test.ts

import { describe, it, expect, beforeEach } from 'vitest';
import { CompositionTestHarness, fileWriteEvent } from '@clawdstrike/guard-sdk/testing';

describe('Guard Composition', () => {
  let harness: CompositionTestHarness;

  beforeEach(() => {
    harness = new CompositionTestHarness();
  });

  describe('AND composition', () => {
    const rule = {
      name: 'both_must_pass',
      AND: [
        { guard: 'guard_a' },
        { guard: 'guard_b' },
      ],
    };

    it('allows when both guards allow', async () => {
      harness.guardAllows('guard_a');
      harness.guardAllows('guard_b');

      await harness.expectAllow(rule, fileWriteEvent('/app/file.txt'));
    });

    it('denies when first guard denies', async () => {
      harness.guardDenies('guard_a', 'guard_a denied');
      harness.guardAllows('guard_b');

      await harness.expectDeny(rule, fileWriteEvent('/app/file.txt'));
    });

    it('denies when second guard denies', async () => {
      harness.guardAllows('guard_a');
      harness.guardDenies('guard_b', 'guard_b denied');

      await harness.expectDeny(rule, fileWriteEvent('/app/file.txt'));
    });

    it('short-circuits on first deny', async () => {
      harness.guardDenies('guard_a');
      harness.guardDenies('guard_b');

      const result = await harness.evaluate(rule, fileWriteEvent('/app/file.txt'));
      const trace = result.trace;

      expect(trace[0].guard).toBe('guard_a');
      expect(trace[0].skipped).toBeFalsy();
      expect(trace[1]?.skipped).toBeTruthy();
    });
  });

  describe('IF_THEN composition', () => {
    const rule = {
      name: 'admin_bypass',
      IF_THEN: {
        if: { context: "user.role == 'admin'" },
        then: { action: 'allow' },
        else: { guard: 'strict_guard' },
      },
    };

    it('allows for admin users', async () => {
      await harness.expectAllow(rule, fileWriteEvent('/app/file.txt'), {
        user: { id: '1', role: 'admin' },
      });
    });

    it('evaluates else branch for non-admin', async () => {
      harness.guardDenies('strict_guard');

      await harness.expectDeny(rule, fileWriteEvent('/app/file.txt'), {
        user: { id: '2', role: 'user' },
      });
    });
  });

  describe('SCORE composition', () => {
    const rule = {
      name: 'risk_score',
      SCORE: {
        threshold: 50,
        weights: [
          { guard: 'high_risk', score: 40 },
          { guard: 'medium_risk', score: 20 },
          { guard: 'low_risk', score: 10 },
        ],
      },
      action: 'deny',
    };

    it('allows when score below threshold', async () => {
      harness.guardDenies('low_risk');  // 10 points
      harness.guardAllows('medium_risk');
      harness.guardAllows('high_risk');

      const result = await harness.evaluate(rule, fileWriteEvent('/app/file.txt'));
      expect(result.status).toBe('allow');
      expect(result.score).toBe(10);
    });

    it('denies when score exceeds threshold', async () => {
      harness.guardDenies('high_risk');  // 40 points
      harness.guardDenies('medium_risk'); // 20 points
      harness.guardAllows('low_risk');

      const result = await harness.evaluate(rule, fileWriteEvent('/app/file.txt'));
      expect(result.status).toBe('deny');
      expect(result.score).toBe(60);
    });
  });
});
```

---

## 8. Security Considerations

### 8.1 Expression Injection

The context expression language must be secure against injection attacks:

```typescript
// UNSAFE - never do this
const expr = `user.name == '${userInput}'`;

// SAFE - parameterized expressions
const expr = `user.name == $param`;
const result = evaluator.evaluate(expr, context, { param: userInput });
```

### 8.2 Infinite Loops

Prevent recursive composition definitions:

```typescript
function detectCycle(rule: CompositionRule, visited: Set<string>): boolean {
  if (visited.has(rule.name)) {
    return true; // Cycle detected
  }

  visited.add(rule.name);

  for (const operand of getOperands(rule)) {
    if (isComposition(operand)) {
      if (detectCycle(operand, new Set(visited))) {
        return true;
      }
    }
  }

  return false;
}
```

### 8.3 Resource Exhaustion

Limit composition depth and breadth:

```typescript
const LIMITS = {
  maxDepth: 10,
  maxOperands: 100,
  maxEvaluationTime: 5000, // ms
};

function validateLimits(rule: CompositionRule, depth: number = 0): void {
  if (depth > LIMITS.maxDepth) {
    throw new Error(`Composition depth exceeds limit of ${LIMITS.maxDepth}`);
  }

  const operands = getOperands(rule);
  if (operands.length > LIMITS.maxOperands) {
    throw new Error(`Operand count exceeds limit of ${LIMITS.maxOperands}`);
  }

  for (const operand of operands) {
    if (isComposition(operand)) {
      validateLimits(operand, depth + 1);
    }
  }
}
```

---

## 9. Implementation Phases

### Phase 1: Basic Operators (Weeks 1-2)

- [ ] AND operator implementation
- [ ] OR operator implementation
- [ ] NOT operator implementation
- [ ] Basic policy parser support

### Phase 2: Conditional Logic (Weeks 3-4)

- [ ] IF_THEN operator implementation
- [ ] Context expression parser
- [ ] Expression evaluation engine
- [ ] Context variable system

### Phase 3: Advanced Operators (Weeks 5-6)

- [ ] N_OF operator implementation
- [ ] SCORE operator implementation
- [ ] Event filtering (when clause)
- [ ] Action/severity overrides

### Phase 4: Testing & Validation (Weeks 7-8)

- [ ] Composition test harness
- [ ] Cycle detection
- [ ] Resource limit enforcement
- [ ] Schema validation

### Phase 5: Tooling (Weeks 9-10)

- [ ] Composition visualizer (CLI/Web)
- [ ] Trace viewer for debugging
- [ ] Policy linter for compositions
- [ ] Documentation

---

## 10. Open Questions

1. **Q: Should compositions be named and reusable?**
   - Current: Yes, via `name` field
   - Alternative: Anonymous inline compositions

2. **Q: How do we handle async guards in compositions?**
   - Current: Await all guards in evaluation order
   - Alternative: Parallel evaluation where possible (no short-circuit)

3. **Q: Should we support custom operators?**
   - Pro: Maximum flexibility
   - Con: Complexity, security concerns
   - Proposed: Defer, evaluate demand

4. **Q: How do we visualize complex compositions?**
   - Proposed: Tree view in CLI, graph visualization in web UI

---

*Next: See async-guards.md for guards that call external services.*
