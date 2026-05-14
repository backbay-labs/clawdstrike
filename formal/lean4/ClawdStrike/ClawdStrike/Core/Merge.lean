/-
  Policy merge semantics (Replace, Merge, DeepMerge).
  Mirrors: core/merge.rs, policy.rs merge_with, guards/*.rs merge_with
-/

import ClawdStrike.Core.Verdict

set_option autoImplicit false

namespace ClawdStrike.Core

/-- Mirrors: child_overrides in core/merge.rs -/
def childOverrides {α : Type} (base child : Option α) : Option α :=
  match child with
  | some c => some c
  | none => base

/-- Mirrors: child_overrides_str in core/merge.rs -/
def childOverridesStr (base child : String) : String :=
  if child.isEmpty then base else child

/-- Axiom: default_forbidden_patterns() in forbidden_path.rs (~30 entries). -/
axiom defaultForbiddenPatterns : List GlobPattern

/-- Mirrors: ForbiddenPathConfig::effective_patterns() in forbidden_path.rs -/
noncomputable def ForbiddenPathConfig.effectivePatterns (cfg : ForbiddenPathConfig) : List GlobPattern :=
  let base := match cfg.patterns with
    | some ps => ps
    | none => defaultForbiddenPatterns
  let withAdditions := base ++ cfg.additionalPatterns.filter (fun p => !base.contains p)
  withAdditions.filter (fun p => !cfg.removePatterns.contains p)

/-- Mirrors: ForbiddenPathConfig::merge_with() in forbidden_path.rs -/
noncomputable def ForbiddenPathConfig.mergeWith (base child : ForbiddenPathConfig) : ForbiddenPathConfig :=
  let startPatterns := match child.patterns with
    | some ps => ps
    | none => base.effectivePatterns
  let withAdditions := startPatterns ++ child.additionalPatterns.filter
    (fun p => !startPatterns.contains p)
  let finalPatterns := withAdditions.filter (fun p => !child.removePatterns.contains p)
  let mergedExceptions := base.exceptions ++ child.exceptions.filter
    (fun e => !base.exceptions.contains e)
  { enabled := child.enabled
  , patterns := some finalPatterns
  , exceptions := mergedExceptions
  , additionalPatterns := []
  , removePatterns := [] }

/-- Mirrors: PathAllowlistConfig::merge_with() in path_allowlist.rs -/
def PathAllowlistConfig.mergeWith (base child : PathAllowlistConfig) : PathAllowlistConfig :=
  { enabled := child.enabled
  , fileAccessAllow := if child.fileAccessAllow.isEmpty then base.fileAccessAllow
                       else child.fileAccessAllow
  , fileWriteAllow := if child.fileWriteAllow.isEmpty then base.fileWriteAllow
                      else child.fileWriteAllow
  , patchAllow := if child.patchAllow.isEmpty then base.patchAllow
                  else child.patchAllow }

/-- Mirrors: EgressAllowlistConfig::with_defaults() in egress_allowlist.rs -/
def EgressAllowlistConfig.defaults : EgressAllowlistConfig :=
  { enabled := true
  , allow := ["*.openai.com", "*.anthropic.com", "api.github.com",
              "*.npmjs.org", "registry.npmjs.org", "pypi.org",
              "files.pythonhosted.org", "crates.io", "static.crates.io"]
  , block := []
  , defaultAction := some .block
  , additionalAllow := []
  , removeAllow := []
  , additionalBlock := []
  , removeBlock := [] }

/-- Mirrors: EgressAllowlistConfig::merge_with() in egress_allowlist.rs
    Non-empty child allow/block lists REPLACE base lists. -/
def EgressAllowlistConfig.mergeWith (base child : EgressAllowlistConfig) : EgressAllowlistConfig :=
  let mutAllow := (base.allow ++ child.additionalAllow.filter (fun d => !base.allow.contains d))
    |>.filter (fun d => !child.removeAllow.contains d)
  let mutBlock := (base.block ++ child.additionalBlock.filter (fun d => !base.block.contains d))
    |>.filter (fun d => !child.removeBlock.contains d)
  let finalAllow := if child.allow.isEmpty then mutAllow else child.allow
  let finalBlock := if child.block.isEmpty then mutBlock else child.block
  { enabled := child.enabled
  , allow := finalAllow
  , block := finalBlock
  , defaultAction := match child.defaultAction with
      | some a => some a
      | none => base.defaultAction
  , additionalAllow := []
  , removeAllow := []
  , additionalBlock := []
  , removeBlock := [] }

/-- Mirrors: McpToolConfig::with_defaults() in mcp_tool.rs -/
def McpToolConfig.defaults : McpToolConfig :=
  { enabled := true
  , allow := []
  , block := ["shell_exec", "run_command", "raw_file_write", "raw_file_delete"]
  , requireConfirmation := ["file_write", "file_delete", "git_push"]
  , defaultAction := some .allow
  , maxArgsSize := some 1048576
  , additionalAllow := []
  , removeAllow := []
  , additionalBlock := []
  , removeBlock := [] }

/-- Mirrors: McpToolConfig::merge_with() in mcp_tool.rs -/
def McpToolConfig.mergeWith (base child : McpToolConfig) : McpToolConfig :=
  let mutAllow := (base.allow ++ child.additionalAllow.filter (fun t => !base.allow.contains t))
    |>.filter (fun t => !child.removeAllow.contains t)
  let mutBlock := (base.block ++ child.additionalBlock.filter (fun t => !base.block.contains t))
    |>.filter (fun t => !child.removeBlock.contains t)
  let finalAllow := if child.allow.isEmpty then mutAllow else child.allow
  let finalBlock := if child.block.isEmpty then mutBlock else child.block
  let finalConfirm := if child.requireConfirmation.isEmpty then base.requireConfirmation
                      else child.requireConfirmation
  { enabled := child.enabled
  , allow := finalAllow
  , block := finalBlock
  , requireConfirmation := finalConfirm
  , defaultAction := match child.defaultAction with
      | some a => some a
      | none => base.defaultAction
  , maxArgsSize := match child.maxArgsSize with
      | some s => some s
      | none => base.maxArgsSize
  , additionalAllow := []
  , removeAllow := []
  , additionalBlock := []
  , removeBlock := [] }

/-- SecretLeakConfig deep merge (simplified). -/
def SecretLeakConfig.mergeWith (base child : SecretLeakConfig) : SecretLeakConfig :=
  { enabled := child.enabled
  , patterns := if child.patterns.isEmpty then base.patterns else child.patterns
  , additionalPatterns := []
  , removePatterns := []
  , skipPaths := if child.skipPaths.isEmpty then base.skipPaths else child.skipPaths }

/-- Mirrors: GuardConfigs::merge_with() in policy.rs -/
noncomputable def GuardConfigs.mergeWith (base child : GuardConfigs) : GuardConfigs :=
  { forbiddenPath := match base.forbiddenPath, child.forbiddenPath with
      | some b, some c => some (ForbiddenPathConfig.mergeWith b c)
      | some b, none   => some b
      | none,   some c => some (ForbiddenPathConfig.mergeWith
          { enabled := true, patterns := none, exceptions := [],
            additionalPatterns := [], removePatterns := [] } c)
      | none,   none   => none
  , pathAllowlist := match base.pathAllowlist, child.pathAllowlist with
      | some b, some c => some (PathAllowlistConfig.mergeWith b c)
      | some b, none   => some b
      | none,   some c => some c
      | none,   none   => none
  , egressAllowlist := match base.egressAllowlist, child.egressAllowlist with
      | some b, some c => some (EgressAllowlistConfig.mergeWith b c)
      | some b, none   => some b
      | none,   some c => some (EgressAllowlistConfig.mergeWith EgressAllowlistConfig.defaults c)
      | none,   none   => none
  , secretLeak := match base.secretLeak, child.secretLeak with
      | some b, some c => some (SecretLeakConfig.mergeWith b c)
      | some b, none   => some b
      | none,   some c => some c
      | none,   none   => none
  , patchIntegrity := childOverrides base.patchIntegrity child.patchIntegrity
  , shellCommand := childOverrides base.shellCommand child.shellCommand
  , mcpTool := match base.mcpTool, child.mcpTool with
      | some b, some c => some (McpToolConfig.mergeWith b c)
      | some b, none   => some b
      | none,   some c => some (McpToolConfig.mergeWith McpToolConfig.defaults c)
      | none,   none   => none
  , promptInjection := childOverrides base.promptInjection child.promptInjection
  , jailbreak := childOverrides base.jailbreak child.jailbreak
  , computerUse := childOverrides base.computerUse child.computerUse
  , remoteDesktopSideChannel := childOverrides base.remoteDesktopSideChannel
      child.remoteDesktopSideChannel
  , inputInjectionCapability := childOverrides base.inputInjectionCapability
      child.inputInjectionCapability
  , spiderSense := childOverrides base.spiderSense child.spiderSense }

/-- Mirrors: policy merge in extends resolution. -/
noncomputable def Policy.mergeWith (parent child : Policy) : Policy :=
  { version := child.version
  , name := if child.name.isEmpty then parent.name else child.name
  , description := if child.description.isEmpty then parent.description else child.description
  , extends_ := none
  , mergeStrategy := child.mergeStrategy
  , guards := GuardConfigs.mergeWith parent.guards child.guards
  , settings := child.settings }

/-- Abstract model of policy restrictiveness for P5 monotonicity proofs. -/
structure PolicyRestriction where
  forbiddenCount : Nat
  failFast : Bool
  deriving Repr, BEq

def PolicyRestriction.atLeastAsRestrictive (a b : PolicyRestriction) : Prop :=
  b.forbiddenCount ≤ a.forbiddenCount

def PolicyRestriction.deepMerge (base child : PolicyRestriction) : PolicyRestriction :=
  { forbiddenCount := base.forbiddenCount + child.forbiddenCount
  , failFast := base.failFast || child.failFast }

def PolicyRestriction.replaceMerge (_base child : PolicyRestriction) : PolicyRestriction :=
  child

end ClawdStrike.Core
