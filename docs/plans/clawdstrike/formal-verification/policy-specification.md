# Policy Specification: IMP-Style Formal Semantics for ClawdStrike

**Status:** Design
**Authors:** Security Engineering
**Last updated:** 2026-03-16
**Depends on:** `crates/libs/clawdstrike` (policy.rs, engine.rs, guards/mod.rs, posture.rs)

---

## 1. Overview

Formal specification of ClawdStrike's policy evaluation engine, inspired by the IMP formalization from Software Foundations. Serves as:

1. **Theorem proving** target in Lean 4
2. **Differential testing** oracle against the Rust implementation
3. **Specification review** reference for security engineers

### 1.1 The Key Insight: Policy Evaluation Is Simpler Than IMP

IMP is a small imperative language with assignment, sequencing, conditionals, and while-loops. ClawdStrike's policy evaluator has **none of IMP's complications**:

| Property | IMP | ClawdStrike Policy Evaluator |
|----------|-----|------------------------------|
| Loops | `while` loops, unbounded iteration | **No loops.** Guard evaluation is a single pass over a finite list. |
| Recursion | Not in IMP, but present in extensions | **No recursion.** `extends` is resolved at load time with a depth bound (32). |
| State mutation | Assignment to mutable variables | **No mutation during evaluation.** Policy is immutable after load. Guards are pure functions of (action, config, context). |
| Turing-completeness | Yes (while loops) | **No.** The evaluator is a total decision procedure. |
| Decidability of properties | Undecidable in general | **Decidable.** All properties in this spec are decidable via finite enumeration or SMT. |

Consequence: evaluation is total, properties are decidable (SMT/enumeration), and the spec is a function definition (not a relation).

### 1.2 What This Spec Covers

- The core evaluation pipeline: policy load, guard instantiation, per-guard check, aggregation
- The merge semantics for `extends` inheritance (including additive/subtractive merge fields)
- The posture state machine (the one stateful component)
- Seven core theorems: determinism, deny monotonicity, fail-closed, forbidden path soundness, inheritance restrictiveness, merge idempotence, severity total order

### 1.3 What This Spec Does Not Cover

- I/O operations (file system access, network calls) -- axiomatized as opaque actions
- Cryptographic correctness (Ed25519 signatures, SHA-256 hashing) -- axiomatized
- Async guard behavior -- modeled as synchronous (the async boundary does not affect verdict semantics)
- Content-dependent detection (jailbreak scoring, prompt injection heuristics, Spider Sense embedding similarity) -- modeled as opaque boolean functions
- YAML parsing -- the spec operates on the parsed `Policy` struct, not raw YAML

---

## 2. Abstract Syntax

All types are defined as algebraic data types. The pseudo-Lean 4 syntax below is intended to be directly transcribable into a Lean 4 `.lean` file.

### 2.1 Actions

```lean
/-- A filesystem path (opaque string). -/
abbrev Path := String

/-- A network domain (opaque string). -/
abbrev Domain := String

/-- A shell command (opaque string). -/
abbrev Command := String

/-- A tool name for MCP invocations. -/
abbrev ToolName := String

/-- Opaque JSON arguments. -/
abbrev Args := String

/-- A unified diff. -/
abbrev Diff := String

/-- A custom action type identifier. -/
abbrev ActionType := String

/-- The action domain. Every guard check evaluates one action.
    Mirrors `GuardAction<'a>` in `guards/mod.rs`. -/
inductive Action where
  | fileAccess   : Path -> Action
  | fileWrite    : Path -> List UInt8 -> Action
  | networkEgress : Domain -> UInt16 -> Action
  | shellCommand : Command -> Action
  | mcpTool      : ToolName -> Args -> Action
  | patch        : Path -> Diff -> Action
  | custom       : ActionType -> Args -> Action
```

### 2.2 Verdicts and Results

```lean
/-- Severity levels. Total order: info < warning < error < critical.
    Mirrors `Severity` in `guards/mod.rs`. -/
inductive Severity where
  | info     : Severity
  | warning  : Severity
  | error    : Severity
  | critical : Severity
deriving DecidableEq

/-- Severity ordering function.
    Mirrors `severity_ord()` in `engine.rs:1699-1706`. -/
def severityOrd : Severity -> Nat
  | .info     => 0
  | .warning  => 1
  | .error    => 2
  | .critical => 3

instance : LT Severity where
  lt a b := severityOrd a < severityOrd b

instance : LE Severity where
  le a b := severityOrd a <= severityOrd b

/-- The result of a single guard check.
    Mirrors `GuardResult` in `guards/mod.rs`. -/
structure GuardResult where
  allowed    : Bool
  guard      : String
  severity   : Severity
  message    : String
  sanitized  : Bool := false   -- tracks is_sanitized() for tiebreaking
deriving DecidableEq

/-- Convenience constructors matching the Rust API. -/
def GuardResult.allow (guard : String) : GuardResult :=
  { allowed := true, guard, severity := .info, message := "Allowed" }

def GuardResult.block (guard : String) (sev : Severity) (msg : String) : GuardResult :=
  { allowed := false, guard, severity := sev, message := msg }
```

### 2.3 Guard Configurations

```lean
/-- Pattern for glob matching (opaque -- matching is axiomatized). -/
abbrev GlobPattern := String

/-- Mirrors `ForbiddenPathConfig` in `guards/forbidden_path.rs`.
    Note: `patterns = none` means "use defaults" (computed by `default_forbidden_patterns()`). -/
structure ForbiddenPathConfig where
  enabled            : Bool := true
  patterns           : Option (List GlobPattern)  -- None = use defaults
  exceptions         : List GlobPattern
  additionalPatterns : List GlobPattern
  removePatterns     : List GlobPattern

structure PathAllowlistConfig where
  enabled : Bool := true
  paths   : List GlobPattern

/-- Mirrors `EgressAllowlistConfig` in `guards/egress_allowlist.rs`. -/
structure EgressAllowlistConfig where
  enabled         : Bool := true
  allow           : List Domain
  block           : List Domain
  defaultAction   : Option PolicyAction  -- None | Some Block | Some Allow | Some Log
  additionalAllow : List Domain
  removeAllow     : List Domain
  additionalBlock : List Domain
  removeBlock     : List Domain

/-- Mirrors `ShellCommandConfig` in `guards/shell_command.rs`.
    Note: forbiddenPatterns are regex patterns, not exact strings. -/
structure ShellCommandConfig where
  enabled              : Bool := true
  forbiddenPatterns    : List String       -- regex patterns
  enforceForbiddenPaths : Bool := true

/-- Mirrors `McpToolConfig` in `guards/mcp_tool.rs`. -/
structure McpToolConfig where
  enabled             : Bool := true
  allow               : List ToolName
  block               : List ToolName
  requireConfirmation : List ToolName
  defaultAction       : Option McpDefaultAction
  maxArgsSize         : Option Nat
  additionalAllow     : List ToolName
  removeAllow         : List ToolName
  additionalBlock     : List ToolName
  removeBlock         : List ToolName

/-- Mirrors `SecretLeakConfig` in `guards/secret_leak.rs`. -/
structure SecretLeakConfig where
  enabled            : Bool := true
  patterns           : List SecretPattern
  additionalPatterns : List SecretPattern
  removePatterns     : List String   -- pattern names to remove
  skipPaths          : List GlobPattern

structure PatchIntegrityConfig where
  maxAdditions      : Nat
  maxDeletions      : Nat
  requireBalance    : Bool
  maxImbalanceRatio : Float
  forbiddenPatterns : List String

/-- Content-dependent guard configs are modeled opaquely.
    In reality, each has many fields (thresholds, layers, etc.)
    but their verdicts depend on runtime content analysis, not
    structural policy properties. -/
structure ContentGuardConfig where
  enabled : Bool

/-- Union of all guard configurations.
    Mirrors `GuardConfigs` in `policy.rs:230-277`. -/
structure GuardConfigs where
  forbiddenPath             : Option ForbiddenPathConfig
  pathAllowlist             : Option PathAllowlistConfig
  egressAllowlist           : Option EgressAllowlistConfig
  shellCommand              : Option ShellCommandConfig
  mcpTool                   : Option McpToolConfig
  secretLeak                : Option SecretLeakConfig
  patchIntegrity            : Option PatchIntegrityConfig
  promptInjection           : Option ContentGuardConfig
  jailbreak                 : Option ContentGuardConfig
  computerUse               : Option ContentGuardConfig
  remoteDesktopSideChannel  : Option ContentGuardConfig
  inputInjectionCapability  : Option ContentGuardConfig
  spiderSense               : Option ContentGuardConfig
```

### 2.4 Policy

```lean
/-- Semantic version (major, minor, patch). -/
structure Version where
  major : Nat
  minor : Nat
  patch : Nat
deriving DecidableEq

def supportedVersions : List Version :=
  [⟨1,1,0⟩, ⟨1,2,0⟩, ⟨1,3,0⟩, ⟨1,4,0⟩, ⟨1,5,0⟩]

inductive PolicyRef where
  | ruleset : String -> PolicyRef
  | file    : Path -> PolicyRef
  | url     : String -> PolicyRef

structure PolicySettings where
  failFast           : Bool
  verboseLogging     : Bool
  sessionTimeoutSecs : Nat

/-- A fully resolved policy (after extends chain resolution). -/
structure Policy where
  version       : Version
  name          : String
  extends       : Option PolicyRef
  guards        : GuardConfigs
  settings      : PolicySettings
  posture       : Option PostureConfig
```

### 2.5 Evaluation Context

```lean
structure Context where
  cwd       : Option Path
  sessionId : Option String
  agentId   : Option String
  metadata  : Option String
```

### 2.6 Posture State Machine

```lean
abbrev StateName := String
abbrev Capability := String
abbrev BudgetName := String

structure PostureState where
  capabilities : List Capability
  budgets      : List (BudgetName × Int)

inductive TransitionTrigger where
  | userApproval      : TransitionTrigger
  | userDenial        : TransitionTrigger
  | criticalViolation : TransitionTrigger
  | anyViolation      : TransitionTrigger
  | timeout           : TransitionTrigger
  | budgetExhausted   : TransitionTrigger
  | patternMatch      : TransitionTrigger

structure PostureTransition where
  from    : StateName
  to      : StateName
  trigger : TransitionTrigger

structure PostureConfig where
  initial     : StateName
  states      : List (StateName × PostureState)
  transitions : List PostureTransition

structure PostureRuntime where
  currentState : StateName
  budgets      : List (BudgetName × Int)
```

---

## 3. Evaluation Semantics

The evaluation is defined as a composition of total functions. No function in this section can diverge or fail -- errors are represented as explicit `Except.error` values.

### 3.1 Glob Pattern Matching (Axiomatized)

```lean
/-- Axiom: glob pattern matching is decidable.
    In the Rust implementation, this is provided by the `glob` crate. -/
axiom globMatch : GlobPattern -> Path -> Bool

def matchesAny (patterns : List GlobPattern) (path : Path) : Bool :=
  patterns.any (fun p => globMatch p path)
```

### 3.2 Content Guard Evaluation (Axiomatized)

```lean
/-- Axiom: content-dependent guard evaluation is an opaque total function. -/
axiom evalContentGuard : String -> Action -> Context -> GuardResult
```

These axioms capture the interface contract without specifying the detection algorithm.

### 3.3 ForbiddenPathConfig Effective Patterns

The `effective_patterns()` method computes the final pattern list from the config's fields. This is critical for both evaluation and merge correctness.

```lean
/-- Default forbidden patterns (SSH keys, AWS credentials, env files, etc.)
    Axiomatized as an opaque constant since the exact list is large. -/
axiom defaultForbiddenPatterns : List GlobPattern

/-- Compute the effective patterns for a ForbiddenPathConfig.
    Mirrors `ForbiddenPathConfig::effective_patterns()` in forbidden_path.rs. -/
def effectivePatterns (cfg : ForbiddenPathConfig) : List GlobPattern :=
  let base := match cfg.patterns with
    | some ps => ps
    | none    => defaultForbiddenPatterns
  let withAdditions := base ++ cfg.additionalPatterns.filter (fun p => !base.elem p)
  withAdditions.filter (fun p => !cfg.removePatterns.elem p)
```

### 3.4 Single Guard Evaluation

Each guard is a total function from (config, action, context) to GuardResult.

```lean
def evalForbiddenPath (cfg : ForbiddenPathConfig) (action : Action) (_ : Context) : GuardResult :=
  if !cfg.enabled then GuardResult.allow "forbidden_path"
  else match action with
  | .fileAccess path | .fileWrite path _ =>
    let patterns := effectivePatterns cfg
    if matchesAny patterns path && !matchesAny cfg.exceptions path then
      GuardResult.block "forbidden_path" .error s!"Access to {path} is forbidden"
    else
      GuardResult.allow "forbidden_path"
  | _ => GuardResult.allow "forbidden_path"

def evalPathAllowlist (cfg : PathAllowlistConfig) (action : Action) (_ : Context) : GuardResult :=
  if !cfg.enabled then GuardResult.allow "path_allowlist"
  else match action with
  | .fileAccess path | .fileWrite path _ =>
    if matchesAny cfg.paths path then
      GuardResult.allow "path_allowlist"
    else
      GuardResult.block "path_allowlist" .error s!"Access to {path} is not in allowlist"
  | _ => GuardResult.allow "path_allowlist"

/-- Egress evaluation follows block > allow > default precedence.
    Mirrors the DomainPolicy evaluation in the Rust implementation. -/
def evalEgressAllowlist (cfg : EgressAllowlistConfig) (action : Action) (_ : Context)
    : GuardResult :=
  if !cfg.enabled then GuardResult.allow "egress_allowlist"
  else match action with
  | .networkEgress domain _ =>
    if cfg.block.elem domain then
      GuardResult.block "egress_allowlist" .error
        s!"Egress to {domain} is explicitly blocked"
    else if cfg.allow.elem domain then
      GuardResult.allow "egress_allowlist"
    else
      -- Neither explicitly allowed nor blocked: apply default
      match cfg.defaultAction with
      | some .block => GuardResult.block "egress_allowlist" .error
          s!"Egress to {domain} is not in allowlist (default: block)"
      | _ => GuardResult.allow "egress_allowlist"
  | _ => GuardResult.allow "egress_allowlist"

/-- Shell command evaluation uses regex matching (axiomatized).
    The actual guard applies regex patterns, not exact string match. -/
axiom regexMatch : String -> Command -> Bool

def evalShellCommand (cfg : ShellCommandConfig) (action : Action) (_ : Context)
    : GuardResult :=
  if !cfg.enabled then GuardResult.allow "shell_command"
  else match action with
  | .shellCommand cmd =>
    if cfg.forbiddenPatterns.any (fun pat => regexMatch pat cmd) then
      GuardResult.block "shell_command" .error s!"Command matches forbidden pattern"
    else
      GuardResult.allow "shell_command"
  | _ => GuardResult.allow "shell_command"

def evalMcpTool (cfg : McpToolConfig) (action : Action) (_ : Context) : GuardResult :=
  if !cfg.enabled then GuardResult.allow "mcp_tool"
  else match action with
  | .mcpTool tool _ =>
    if cfg.block.elem tool then
      GuardResult.block "mcp_tool" .error s!"MCP tool '{tool}' is blocked"
    else if cfg.allow.elem tool then
      GuardResult.allow "mcp_tool"
    else
      match cfg.defaultAction with
      | some .block => GuardResult.block "mcp_tool" .error
          s!"MCP tool '{tool}' is not in allowlist (default: block)"
      | _ => GuardResult.allow "mcp_tool"
  | _ => GuardResult.allow "mcp_tool"
```

#### Unified guard dispatch

```lean
def evalGuard (cfg : GuardConfigs) (action : Action) (ctx : Context) : List GuardResult :=
  let results : List (Option GuardResult) := [
    cfg.forbiddenPath.map    (fun c => evalForbiddenPath c action ctx),
    cfg.pathAllowlist.map    (fun c => evalPathAllowlist c action ctx),
    cfg.egressAllowlist.map  (fun c => evalEgressAllowlist c action ctx),
    cfg.shellCommand.map     (fun c => evalShellCommand c action ctx),
    cfg.mcpTool.map          (fun c => evalMcpTool c action ctx),
    cfg.secretLeak.map       (fun _ => evalContentGuard "secret_leak" action ctx),
    cfg.patchIntegrity.map   (fun _ => evalContentGuard "patch_integrity" action ctx),
    cfg.promptInjection.bind (fun c =>
      if c.enabled then some (evalContentGuard "prompt_injection" action ctx) else none),
    cfg.jailbreak.bind       (fun c =>
      if c.enabled then some (evalContentGuard "jailbreak" action ctx) else none),
    cfg.computerUse.map      (fun _ => evalContentGuard "computer_use" action ctx),
    cfg.remoteDesktopSideChannel.map
      (fun _ => evalContentGuard "remote_desktop_side_channel" action ctx),
    cfg.inputInjectionCapability.map
      (fun _ => evalContentGuard "input_injection_capability" action ctx),
    cfg.spiderSense.map      (fun _ => evalContentGuard "spider_sense" action ctx)
  ]
  results.filterMap id
```

### 3.5 Aggregation: Deny-Wins

This is the most critical function in the specification. It mirrors `aggregate_overall()` in `engine.rs:1785-1818`.

**Implementation note:** The Rust code uses a left-to-right iterative scan, tracking a "best" (worst) result. The spec below uses a left fold to match the iteration order precisely. This matters for the sanitize tiebreaker: when two non-blocking results have equal severity, the _later_ one wins if it is sanitized and the current best is not.

```lean
/-- Compare two GuardResults, returning the "worse" one.
    Mirrors the three-branch logic in aggregate_overall():
    1. A blocking result always beats a non-blocking result.
    2. Among results with the same blocking status, higher severity wins.
    3. Among non-blocking results with equal severity, sanitized beats non-sanitized. -/
def worseResult (best candidate : GuardResult) : GuardResult :=
  let bestBlocks := !best.allowed
  let candBlocks := !candidate.allowed
  -- Branch 1: candidate blocks, best doesn't -> candidate wins
  if candBlocks && !bestBlocks then candidate
  -- Branch 2: same blocking status, candidate has higher severity -> candidate wins
  else if candBlocks == bestBlocks && severityOrd candidate.severity > severityOrd best.severity
    then candidate
  -- Branch 3: both non-blocking, same severity, candidate sanitized, best not -> candidate wins
  else if candBlocks == bestBlocks
       && severityOrd candidate.severity == severityOrd best.severity
       && !candBlocks
       && candidate.sanitized
       && !best.sanitized
    then candidate
  else best

/-- Aggregate a list of guard results into an overall verdict.
    Uses left fold to match the Rust implementation's iteration order.
    Invariant: if any result denies, the overall result denies. -/
def aggregate : List GuardResult -> GuardResult
  | []      => GuardResult.allow "engine"
  | r :: rs => rs.foldl worseResult r
```

### 3.6 Policy Merge

The merge semantics are more complex than a simple union or override. Deep-merge guards use additive/subtractive fields.

```lean
/-- Merge ForbiddenPathConfig.
    Mirrors `ForbiddenPathConfig::merge_with()` in forbidden_path.rs:139-180.
    Key semantics:
    - If child has explicit `patterns`, those replace the base.
    - Otherwise, start with base's effective_patterns.
    - Add child's additional_patterns.
    - Remove child's remove_patterns.
    - Exceptions are unioned. -/
def mergeForbiddenPath (base child : ForbiddenPathConfig) : ForbiddenPathConfig :=
  let startPatterns := match child.patterns with
    | some ps => ps
    | none    => effectivePatterns base
  let withAdditions := startPatterns ++ child.additionalPatterns.filter
    (fun p => !startPatterns.elem p)
  let finalPatterns := withAdditions.filter (fun p => !child.removePatterns.elem p)
  -- Merge exceptions (union)
  let mergedExceptions := base.exceptions ++ child.exceptions.filter
    (fun e => !base.exceptions.elem e)
  { enabled := child.enabled,
    patterns := some finalPatterns,
    exceptions := mergedExceptions,
    additionalPatterns := [],
    removePatterns := [] }

/-- Merge EgressAllowlistConfig.
    Mirrors `EgressAllowlistConfig::merge_with()` in egress_allowlist.rs:78-119.
    Key semantics:
    - Start with base allow/block lists.
    - Add child's additional_allow/additional_block.
    - Remove child's remove_allow/remove_block.
    - If child has non-empty allow/block, REPLACE (not union) base lists.
    - Default action: child's if present, else base's. -/
def mergeEgress (base child : EgressAllowlistConfig) : EgressAllowlistConfig :=
  let mut_allow := base.allow
    |> (fun a => a ++ child.additionalAllow.filter (fun d => !a.elem d))
    |> (fun a => a.filter (fun d => !child.removeAllow.elem d))
  let mut_block := base.block
    |> (fun b => b ++ child.additionalBlock.filter (fun d => !b.elem d))
    |> (fun b => b.filter (fun d => !child.removeBlock.elem d))
  -- Non-empty child lists REPLACE (this happens after add/remove in Rust)
  let finalAllow := if child.allow.isEmpty then mut_allow else child.allow
  let finalBlock := if child.block.isEmpty then mut_block else child.block
  { enabled := child.enabled,
    allow := finalAllow,
    block := finalBlock,
    defaultAction := child.defaultAction.orElse (fun _ => base.defaultAction),
    additionalAllow := [],
    removeAllow := [],
    additionalBlock := [],
    removeBlock := [] }

/-- Merge two Option configs with child-overrides-base semantics.
    Used for simple-override guards (patch_integrity, shell_command, etc.). -/
def childOverrides (base child : Option α) : Option α :=
  child.orElse (fun _ => base)

/-- Merge two GuardConfigs.
    Mirrors `GuardConfigs::merge_with()` in `policy.rs:280-368`.

    Deep-merge guards: forbidden_path, egress_allowlist, mcp_tool, secret_leak
    Deep-merge with present-field tracking: spider_sense (under `full` feature)
    Merge-with method: path_allowlist
    Child-overrides guards: patch_integrity, shell_command, prompt_injection,
      jailbreak, computer_use, remote_desktop_side_channel, input_injection_capability
    Custom guards: child replaces if non-empty -/
def mergeGuardConfigs (base child : GuardConfigs) : GuardConfigs :=
  { forbiddenPath := match base.forbiddenPath, child.forbiddenPath with
      | some b, some c => some (mergeForbiddenPath b c)
      | some b, none   => some b
      -- When base is None but child exists, merge child with default
      | none,   some c => some (mergeForbiddenPath ⟨true, none, [], [], []⟩ c)
      | none,   none   => none,
    pathAllowlist := match base.pathAllowlist, child.pathAllowlist with
      | some b, some c => some (mergePathAllowlist b c)  -- has its own merge_with
      | some b, none   => some b
      | none,   some c => some c
      | none,   none   => none,
    egressAllowlist := match base.egressAllowlist, child.egressAllowlist with
      | some b, some c => some (mergeEgress b c)
      | some b, none   => some b
      | none,   some c => some (mergeEgress defaultEgressConfig c)
      | none,   none   => none,
    shellCommand := childOverrides base.shellCommand child.shellCommand,
    mcpTool := match base.mcpTool, child.mcpTool with
      | some b, some c => some (mergeMcpTool b c)
      | some b, none   => some b
      | none,   some c => some (mergeMcpTool defaultMcpConfig c)
      | none,   none   => none,
    secretLeak := match base.secretLeak, child.secretLeak with
      | some b, some c => some (mergeSecretLeak b c)
      | some b, none   => some b
      | none,   some c => some (mergeSecretLeak defaultSecretLeakConfig c)
      | none,   none   => none,
    patchIntegrity := childOverrides base.patchIntegrity child.patchIntegrity,
    promptInjection := childOverrides base.promptInjection child.promptInjection,
    jailbreak := childOverrides base.jailbreak child.jailbreak,
    computerUse := childOverrides base.computerUse child.computerUse,
    remoteDesktopSideChannel := childOverrides base.remoteDesktopSideChannel
        child.remoteDesktopSideChannel,
    inputInjectionCapability := childOverrides base.inputInjectionCapability
        child.inputInjectionCapability,
    spiderSense := childOverrides base.spiderSense child.spiderSense }
    -- Note: spider_sense under `full` feature uses deep merge with
    -- present-field tracking (merge_with_present_fields), simplified here
    -- to childOverrides. The full merge semantics are complex and
    -- should be specified separately when spider_sense verification is in scope.

/-- Merge two policies (parent extended by child). -/
def mergePolicy (parent child : Policy) : Policy :=
  { version := child.version,
    name := if child.name.isEmpty then parent.name else child.name,
    extends := none,  -- extends chain is fully resolved
    guards := mergeGuardConfigs parent.guards child.guards,
    settings := child.settings,
    posture := child.posture.orElse (fun _ => parent.posture) }
```

### 3.7 Full Policy Evaluation

```lean
def hasConfigError (policy : Policy) : Bool :=
  !supportedVersions.elem policy.version

/-- Full policy evaluation. Top-level function that the implementation must agree with. -/
def evalPolicy (policy : Policy) (action : Action) (ctx : Context)
    : Except String GuardResult :=
  if hasConfigError policy then
    .error s!"Unsupported schema version: {policy.version}"
  else
    let results := evalGuard policy.guards action ctx
    let effectiveResults :=
      if policy.settings.failFast then
        match results.find? (fun r => !r.allowed) with
        | some firstDeny => [firstDeny]
        | none           => results
      else
        results
    .ok (aggregate effectiveResults)
```

### 3.8 Posture-Aware Evaluation

The posture state machine introduces the one stateful aspect. We model it as a pure function that takes the current runtime state and returns both the verdict and the updated state.

```lean
def stateCapabilities (config : PostureConfig) (stateName : StateName)
    : List Capability :=
  match config.states.find? (fun (name, _) => name == stateName) with
  | some (_, state) => state.capabilities
  | none => []

def actionCapability : Action -> Capability
  | .fileAccess _      => "file_access"
  | .fileWrite _ _     => "file_write"
  | .networkEgress _ _ => "egress"
  | .shellCommand _    => "shell"
  | .mcpTool _ _       => "mcp_tool"
  | .patch _ _         => "patch"
  | .custom _ _        => "custom"

def posturePrecheck (config : PostureConfig) (runtime : PostureRuntime)
    (action : Action) : GuardResult :=
  let cap := actionCapability action
  let caps := stateCapabilities config runtime.currentState
  if caps.elem cap then
    GuardResult.allow "posture"
  else
    GuardResult.block "posture" .error
      s!"Capability '{cap}' not available in posture state '{runtime.currentState}'"

def applyTransition (config : PostureConfig) (runtime : PostureRuntime)
    (trigger : TransitionTrigger) : PostureRuntime :=
  match config.transitions.find? (fun t =>
    t.from == runtime.currentState && t.trigger == trigger) with
  | some transition =>
    let newBudgets := match config.states.find? (fun (name, _) => name == transition.to) with
      | some (_, state) => state.budgets
      | none => runtime.budgets
    { currentState := transition.to, budgets := newBudgets }
  | none => runtime

def decrementBudget (runtime : PostureRuntime) (action : Action)
    : PostureRuntime × Bool :=
  let budgetName := actionCapability action ++ "s"
  match runtime.budgets.find? (fun (name, _) => name == budgetName) with
  | some (name, count) =>
    let newCount := count - 1
    let newBudgets := runtime.budgets.map (fun (n, c) =>
      if n == name then (n, newCount) else (n, c))
    ({ runtime with budgets := newBudgets }, newCount <= 0)
  | none => (runtime, false)

def evalPolicyWithPosture (policy : Policy) (action : Action) (ctx : Context)
    (runtime : PostureRuntime) : Except String (GuardResult × PostureRuntime) :=
  match policy.posture with
  | none =>
    (evalPolicy policy action ctx).map (fun r => (r, runtime))
  | some config =>
    let precheck := posturePrecheck config runtime action
    if !precheck.allowed then
      .ok (precheck, runtime)
    else
      match evalPolicy policy action ctx with
      | .error e => .error e
      | .ok result =>
        let trigger := if !result.allowed then
          if result.severity == .critical then TransitionTrigger.criticalViolation
          else TransitionTrigger.anyViolation
        else TransitionTrigger.userApproval
        let runtime' := applyTransition config runtime trigger
        let (runtime'', exhausted) := decrementBudget runtime' action
        let runtime''' := if exhausted then
          applyTransition config runtime'' TransitionTrigger.budgetExhausted
        else runtime''
        .ok (result, runtime''')
```

---

## 4. Properties to Prove

### 4.1 P1: Determinism

**Statement:** Policy evaluation is a deterministic function. The same inputs always produce the same output.

```lean
theorem determinism :
    forall (policy : Policy) (action : Action) (ctx : Context),
      evalPolicy policy action ctx = evalPolicy policy action ctx := by
  intros
  rfl
```

Trivially true in the spec (`rfl`), but non-obvious in the implementation which uses `async`, `Arc<RwLock<EngineState>>`, and interior mutability. Differential testing (section 6) validates that these details do not affect the verdict.

### 4.2 P2: Deny Monotonicity (Forbid-Overrides-Permit)

**Statement:** If any guard result in the list is a denial, the aggregated result is a denial.

```lean
theorem deny_monotonicity :
    forall (results : List GuardResult) (v : GuardResult),
      v ∈ results ->
      v.allowed = false ->
      (aggregate results).allowed = false := by
  intro results v hMem hDeny
  induction results with
  | nil => exact absurd hMem (List.not_mem_nil v)
  | cons r rs ih =>
    simp [aggregate]
    sorry  -- see proof sketch below
```

**Proof sketch:** The key lemma is that `worseResult` preserves denial:

```lean
/-- If either input to worseResult is a denial, the output is a denial. -/
lemma worseResult_preserves_deny (a b : GuardResult) :
    a.allowed = false ∨ b.allowed = false ->
    (worseResult a b).allowed = false := by
  intro h
  simp [worseResult]
  cases h with
  | inl ha => -- a denies
    by_cases hb : b.allowed
    · simp [ha, hb]  -- a blocks, b doesn't -> a is worse or stays best
      sorry
    · simp [ha, hb]  -- both block -> higher severity wins, both deny
      sorry
  | inr hb => -- b denies
    sorry
```

Given this lemma, the theorem follows by induction on the list: `aggregate` folds `worseResult` over the list, and if any element denies, the fold accumulator becomes a denial and stays a denial.

### 4.3 P3: Fail-Closed on Config Error

**Statement:** If the policy has a configuration error, evaluation returns `Except.error`.

```lean
theorem fail_closed_config :
    forall (policy : Policy) (action : Action) (ctx : Context),
      hasConfigError policy = true ->
      exists (msg : String), evalPolicy policy action ctx = .error msg := by
  intro policy action ctx hError
  simp [evalPolicy, hError]
  exact ⟨_, rfl⟩
```

**Implementation correspondence:** In `engine.rs`, `check_action_report()` begins with:
```rust
if let Some(msg) = self.config_error.as_ref() {
    return Err(Error::ConfigError(msg.clone()));
}
```

### 4.4 P4: Forbidden Path Soundness

**Statement:** If a policy has a forbidden_path guard with effective patterns, and an action accesses a path matching one of those patterns (and not matching any exception), then the overall verdict is deny.

```lean
theorem forbidden_path_sound :
    forall (policy : Policy) (action : Action) (ctx : Context)
           (path : Path) (cfg : ForbiddenPathConfig),
      policy.guards.forbiddenPath = some cfg ->
      cfg.enabled = true ->
      action = .fileAccess path ->
      matchesAny (effectivePatterns cfg) path = true ->
      matchesAny cfg.exceptions path = false ->
      hasConfigError policy = false ->
      exists (result : GuardResult),
        evalPolicy policy action ctx = .ok result ∧
        result.allowed = false := by
  sorry  -- compose evalForbiddenPath denial with deny_monotonicity
```

**Proof sketch:** `evalForbiddenPath` produces a denial for the matching path; this denial appears in the guard result list; by `deny_monotonicity`, the aggregate is also a denial.

### 4.5 P5: Inheritance Restrictiveness

**Statement:** If a child policy's evaluation denies an action, then the merged policy (parent extended by child) also denies that action.

```lean
theorem extends_no_weaken :
    forall (parent child : Policy) (action : Action) (ctx : Context)
           (childResult : GuardResult),
      hasConfigError child = false ->
      hasConfigError (mergePolicy parent child) = false ->
      evalPolicy child action ctx = .ok childResult ->
      childResult.allowed = false ->
      exists (mergedResult : GuardResult),
        evalPolicy (mergePolicy parent child) action ctx = .ok mergedResult ∧
        mergedResult.allowed = false := by
  sorry
```

**Proof strategy:** For each guard, the merged config is at least as restrictive as the child's config:

1. **Deep-merge guards with no removals:** The merged effective pattern set includes all of the child's patterns, so any child denial is preserved.
2. **Deep-merge guards with removals:** The child's own explicit patterns and additions are preserved in the merge. Removals only apply to the _base's_ patterns.
3. **Child-overrides guards:** The merged config is identical to the child's config (when present) or the parent's (when the child omits it). Child denials are preserved verbatim.

**Subtle case:** A child that _omits_ a guard inherits the parent's config. The merged evaluation might produce a denial from the parent that the child alone would not. This is _more_ restrictive, which is fine -- the theorem only states that child denials are preserved.

### 4.6 P6: Merge Idempotence

**Statement:** Merging a **normalized / fully resolved** policy with itself produces a policy that evaluates identically to the original.

Here, "normalized" means:

- `extends` has already been resolved away.
- Deep-merge helper fields such as `additional_*` / `remove_*` have already been materialized into the effective allow/block/pattern lists.

```lean
theorem merge_policy_idempotent :
    forall (policy : Policy) (action : Action) (ctx : Context),
      Policy.Normalized policy ->
      evalPolicy (mergePolicy policy policy) action ctx =
      evalPolicy policy action ctx := by
  sorry
```

**Proof strategy:** For each guard config field:
- **Deep-merge guards:** First prove self-merge is structural identity once additive/removal helper fields are empty or already materialized. This is the interesting part for `forbidden_path`, `egress_allowlist`, `secret_leak`, and `mcp_tool`.
- **Child-overrides:** `childOverrides (some c) (some c) = some c`. Trivially idempotent.

**Why the normalization precondition matters:** The raw `Policy` type can still encode pre-resolution additive helper fields. In the current runtime semantics, unrestricted self-merge is false. A concrete counterexample is an `egress_allowlist` config with `allow = []`, `default_action = block`, and `additional_allow = ["good.com"]`: the original standalone policy blocks `good.com`, but `mergePolicy policy policy` materializes `additional_allow` into `allow`, changing evaluation. The normalized theorem matches the intended "fully resolved policy" domain without changing runtime behavior.

### 4.7 P7: Severity Total Order

See Appendix A.

---

## 5. Comparison to IMP

| IMP Concept | ClawdStrike Equivalent | Simplification |
|-------------|----------------------|----------------|
| **Arithmetic expressions** | Guard config fields (patterns, thresholds) | Evaluated at load time |
| **Boolean expressions** | `globMatch`, pattern matching, list membership | Decidable predicates over finite domains |
| **Commands** | Guard evaluation pipeline | No sequencing, assignment, or loops |
| **State** | `Context` (immutable during evaluation) | Read-only during guard checks |
| **While loops** | **Nothing.** | No loops. Guard list is traversed once. |
| **Big-step semantics** | `evalPolicy policy action ctx = result` | Total function, not a relation |
| **Hoare triples** | Property theorems (P1--P7) | Pre/post conditions are directly expressible as function properties |
| **Loop invariants** | Posture budget invariants | Bounded (finite integers), checkable by BMC |
| **Termination** | Trivially total | No loops, no recursion, no divergence |

---

## 6. Connection to Rust Implementation

### 6.1 Differential Testing Architecture

Differential testing bridges the Lean 4 spec and the Rust implementation (following Cedar's approach).

```
                     ┌──────────────────────┐
                     │  proptest generator   │
                     │  (random policies +   │
                     │   random actions)     │
                     └──────────┬────────────┘
                                │
                    ┌───────────┴───────────┐
                    │                       │
                    v                       v
          ┌─────────────────┐     ┌─────────────────┐
          │   Lean 4 spec   │     │ Rust impl        │
          │  (evalPolicy)   │     │ (HushEngine::    │
          │                 │     │  check_action)   │
          └────────┬────────┘     └────────┬────────┘
                   │                       │
                   v                       v
              result_spec            result_impl
                   │                       │
                   └───────────┬───────────┘
                               │
                               v
                     assert_eq!(result_spec.allowed,
                                result_impl.allowed)
```

### 6.2 Property-Based Test Generator

```rust
use proptest::prelude::*;

fn arb_policy() -> impl Strategy<Value = Policy> {
    (
        proptest::option::of(arb_forbidden_path_config()),
        proptest::option::of(arb_egress_config()),
        proptest::option::of(arb_mcp_tool_config()),
        proptest::option::of(arb_shell_command_config()),
        arb_policy_settings(),
    ).prop_map(|(fp, eg, mcp, sc, settings)| {
        Policy {
            version: "1.5.0".into(),
            guards: GuardConfigs {
                forbidden_path: fp,
                egress_allowlist: eg,
                mcp_tool: mcp,
                shell_command: sc,
                ..Default::default()
            },
            settings,
            ..Default::default()
        }
    })
}

fn arb_action() -> impl Strategy<Value = GuardAction<'static>> {
    prop_oneof![
        any::<String>().prop_map(|s| GuardAction::FileAccess(Box::leak(s.into_boxed_str()))),
        any::<String>().prop_map(|s| GuardAction::ShellCommand(Box::leak(s.into_boxed_str()))),
        (any::<String>(), any::<u16>())
            .prop_map(|(h, p)| GuardAction::NetworkEgress(
                Box::leak(h.into_boxed_str()), p)),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1_000_000))]

    #[test]
    fn deny_monotonicity_differential(
        policy in arb_policy(),
        action in arb_action(),
    ) {
        let engine = HushEngine::with_policy(policy.clone());
        let ctx = GuardContext::new();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let report = rt.block_on(engine.check_action_report(&action, &ctx));

        match report {
            Ok(report) => {
                let any_deny = report.per_guard.iter().any(|r| !r.allowed);
                if any_deny {
                    assert!(!report.overall.allowed,
                        "Deny monotonicity violated: guard denied but overall allowed");
                }
            }
            Err(_) => {
                // Config error = fail-closed, which is correct
            }
        }
    }
}
```

### 6.3 Test Coverage Targets

| Property | Test Type | Target Volume |
|----------|----------|---------------|
| P1 (Determinism) | Run same input twice, assert equal | 10M |
| P2 (Deny monotonicity) | Random policies, check aggregate invariant | 10M |
| P3 (Fail-closed) | Invalid versions, broken configs | 1M |
| P4 (Forbidden path) | Random paths against random patterns | 10M |
| P5 (Inheritance) | Random parent+child merges | 10M |
| P6 (Merge idempotence) | Merge policy with self, compare | 10M |

Total: ~50M differential tests, run as a nightly CI job.

---

## 7. Scope and Limitations

### 7.1 What Is Specified

- The structure of policies, guards, actions, and results (section 2)
- The evaluation logic for 5 guards with explicit pattern/list semantics: forbidden_path, path_allowlist, egress_allowlist, shell_command, mcp_tool (section 3.4)
- The effective_patterns computation for ForbiddenPathConfig (section 3.3)
- The aggregation function including sanitize tiebreaker (section 3.5)
- The merge function with additive/subtractive fields (section 3.6)
- The posture state machine (section 3.8)
- Seven core properties (section 4)

### 7.2 What Is Axiomatized

- **Glob pattern matching** (`globMatch`): The `glob` crate's matching algorithm is treated as a black box.
- **Regex matching** (`regexMatch`): The `regex` crate used by ShellCommandGuard is axiomatized.
- **Content-dependent guard evaluation** (`evalContentGuard`): Jailbreak detector, prompt injection detector, Spider Sense, etc. are treated as opaque boolean functions.
- **Cryptographic operations**: Ed25519, SHA-256, canonical JSON -- assumed correct.
- **YAML parsing**: The spec operates on the parsed `Policy` struct.
- **Default forbidden patterns**: The exact list is axiomatized as a constant since it is large (~30 patterns) and platform-dependent.

### 7.3 What Is Out of Scope

- **I/O side effects**: File system access, network calls, process execution are not modeled.
- **Concurrency**: The claim that concurrency does not affect the verdict is validated by differential testing, not by proof.
- **Custom guards**: User-supplied code; treated like content guards.
- **Broker subsystem**: Network I/O, capability lifecycle, cryptographic tokens.
- **Origin enclaves**: Modeled minimally (pre-check produces a GuardResult feeding into the pipeline).
- **Spider Sense deep merge with present-field tracking**: The `merge_with_present_fields` method uses `BTreeSet<String>` to track which YAML fields were explicitly provided. This is too complex for the initial specification and is simplified to `childOverrides`.

### 7.4 The Posture Exception

The posture state machine is the one component that does not fit the "purely functional decision procedure" model. It has mutable state that evolves across evaluations. For the posture subsystem, the IMP comparison is more apt: budget counters behave like IMP variables. The key difference is that the counter space is finite and bounded, so termination and reachability are decidable via bounded model checking (see the [Logos Integration](./logos-integration.md) document, section 4.6).

---

## 8. Appendix: Severity Total Order

```lean
theorem severity_ord_total_order :
    (forall s, severityOrd s <= severityOrd s) ∧
    (forall s1 s2, severityOrd s1 <= severityOrd s2 ->
                   severityOrd s2 <= severityOrd s1 ->
                   s1 = s2) ∧
    (forall s1 s2 s3, severityOrd s1 <= severityOrd s2 ->
                      severityOrd s2 <= severityOrd s3 ->
                      severityOrd s1 <= severityOrd s3) ∧
    (forall s1 s2, severityOrd s1 <= severityOrd s2 ∨
                   severityOrd s2 <= severityOrd s1) := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · intro s; omega
  · intro s1 s2 h1 h2
    cases s1 <;> cases s2 <;> simp [severityOrd] at h1 h2 <;> rfl
  · intro s1 s2 s3 h1 h2; omega
  · intro s1 s2; omega
```

**Implementation correspondence:** In `engine.rs:1699-1706`:
```rust
fn severity_ord(s: &Severity) -> u8 {
    match s {
        Severity::Info => 0,
        Severity::Warning => 1,
        Severity::Error => 2,
        Severity::Critical => 3,
    }
}
```

The spec's `severityOrd` exactly mirrors this function. The total order proof guarantees that `worseResult` is well-defined -- there are no incomparable severities.

---

## 9. Appendix: Aggregate Commutativity (Partial)

The `aggregate` function uses `foldl`, so the result depends on list order. However, the _allowed field_ of the result is order-independent: if any input denies, the output denies regardless of position. We state this restricted commutativity:

```lean
/-- The `allowed` field of `aggregate` is independent of list permutations.
    This is the security-relevant commutativity property. -/
theorem aggregate_allowed_perm_invariant :
    forall (results : List GuardResult) (perm : List GuardResult),
      perm.Perm results ->
      (aggregate results).allowed = (aggregate perm).allowed := by
  sorry
```

**Why full commutativity does not hold:** When two results tie on blocking status and severity, `worseResult` keeps the current best (breaking ties left). So `aggregate [a, b]` and `aggregate [b, a]` may return results with different `guard` names and `message` fields even though the `allowed` field agrees. Full commutativity would require a canonical tiebreaker (e.g., lexicographic on guard name).

**Why `allowed`-commutativity suffices for security:** The critical invariant is "deny wins" (P2). The specific guard name and message in the denial are informational, not security-critical.

---

## 10. Implementation Roadmap

| Phase | Deliverable | Estimated Effort |
|-------|------------|-----------------|
| **Phase 1** | Lean 4 spec for sections 2 and 3 (types + evaluation functions) | 1 week |
| **Phase 2** | Lean 4 proofs for P1 (determinism) and P3 (fail-closed) | 3 days |
| **Phase 3** | Lean 4 proof for P2 (deny monotonicity) | 1 week |
| **Phase 4** | `proptest` differential test harness (section 6) | 3 days |
| **Phase 5** | 10M differential tests in CI nightly | 2 days |
| **Phase 6** | Lean 4 proofs for P4, P5, P6, P7 | 2 weeks |
| **Phase 7** | Posture state machine spec and bounded model checking | 1 week |
| **Phase 8** | Scale to 100M differential tests | 1 week |

---

## 11. References

- Pierce, B.C. et al. _Software Foundations, Volume 1: Logical Foundations._ Chapter 8 (IMP). https://softwarefoundations.cis.upenn.edu/
- Cutler, J. et al. "Cedar: A New Language for Expressive, Fast, Safe, and Analyzable Authorization." _OOPSLA_, 2024. https://www.cedarpolicy.com/
- Aeneas: Rust-to-Lean 4 translator. https://github.com/AeneasVerif/aeneas
- de Moura, L. et al. _The Lean 4 Theorem Prover._ https://lean-lang.org/
- ClawdStrike source: `crates/libs/clawdstrike/src/engine.rs` (aggregate_overall, check_action_report), `policy.rs` (GuardConfigs::merge_with, Policy), `guards/mod.rs` (Guard, GuardResult, GuardAction, Severity), `guards/forbidden_path.rs` (ForbiddenPathConfig, effective_patterns, merge_with), `guards/egress_allowlist.rs` (EgressAllowlistConfig, merge_with, intersect_with)
