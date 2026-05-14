/-
  Per-guard evaluation functions and full policy evaluation pipeline.
  Mirrors: guards/*.rs, engine.rs
-/

import ClawdStrike.Core.Verdict
import ClawdStrike.Core.Aggregate
import ClawdStrike.Core.Merge

set_option autoImplicit false

namespace ClawdStrike.Core

noncomputable section

-- Axiomatized pattern matching (glob crate, regex crate)

axiom globMatch : GlobPattern → Path → Bool

def matchesAny (patterns : List GlobPattern) (path : Path) : Bool :=
  patterns.any (fun p => globMatch p path)

axiom regexMatch : String → Command → Bool

/-- Opaque evaluation for content-dependent guards. -/
axiom evalContentGuard : String → Action → Context → GuardResult

/-- Mirrors: guards/forbidden_path.rs check() -/
def evalForbiddenPath (cfg : ForbiddenPathConfig) (action : Action) (_ : Context) : GuardResult :=
  if !cfg.enabled then GuardResult.allow "forbidden_path"
  else match action with
  | .fileAccess path | .fileWrite path _ | .patch path _ =>
    let patterns := cfg.effectivePatterns
    if matchesAny patterns path && !matchesAny cfg.exceptions path then
      GuardResult.block "forbidden_path" .error s!"Access to {path} is forbidden"
    else
      GuardResult.allow "forbidden_path"
  | _ => GuardResult.allow "forbidden_path"

/-- Mirrors: guards/path_allowlist.rs check() -/
def evalPathAllowlist (cfg : PathAllowlistConfig) (action : Action) (_ : Context) : GuardResult :=
  if !cfg.enabled then GuardResult.allow "path_allowlist"
  else match action with
  | .fileAccess path =>
    if matchesAny cfg.fileAccessAllow path then
      GuardResult.allow "path_allowlist"
    else
      GuardResult.block "path_allowlist" .error s!"Access to {path} is not in allowlist"
  | .fileWrite path _ =>
    if matchesAny cfg.fileWriteAllow path then
      GuardResult.allow "path_allowlist"
    else
      GuardResult.block "path_allowlist" .error s!"Write to {path} is not in allowlist"
  | .patch path _ =>
    let patterns := if cfg.patchAllow.isEmpty then cfg.fileWriteAllow else cfg.patchAllow
    if matchesAny patterns path then
      GuardResult.allow "path_allowlist"
    else
      GuardResult.block "path_allowlist" .error s!"Patch to {path} is not in allowlist"
  | _ => GuardResult.allow "path_allowlist"

/-- Mirrors: guards/egress_allowlist.rs check()
    Uses exact string matching (real impl uses glob wildcards). -/
def evalEgressAllowlist (cfg : EgressAllowlistConfig) (action : Action) (_ : Context)
    : GuardResult :=
  if !cfg.enabled then GuardResult.allow "egress_allowlist"
  else match action with
  | .networkEgress domain _ =>
    if cfg.block.contains domain then
      GuardResult.block "egress_allowlist" .error
        s!"Egress to {domain} is explicitly blocked"
    else if cfg.allow.contains domain then
      GuardResult.allow "egress_allowlist"
    else
      match cfg.defaultAction with
      | some .block => GuardResult.block "egress_allowlist" .error
          s!"Egress to {domain} is not in allowlist (default: block)"
      | _ => GuardResult.allow "egress_allowlist"
  | _ => GuardResult.allow "egress_allowlist"

/-- Mirrors: guards/shell_command.rs check()
    Path-token extraction from commands is simplified away. -/
def evalShellCommand (cfg : ShellCommandConfig) (action : Action) (_ : Context) : GuardResult :=
  if !cfg.enabled then GuardResult.allow "shell_command"
  else match action with
  | .shellCommand cmd =>
    if cfg.forbiddenPatterns.any (fun pat => regexMatch pat cmd) then
      GuardResult.block "shell_command" .error s!"Command matches forbidden pattern"
    else
      GuardResult.allow "shell_command"
  | _ => GuardResult.allow "shell_command"

/-- Mirrors: guards/mcp_tool.rs check() -/
def evalMcpTool (cfg : McpToolConfig) (action : Action) (_ : Context) : GuardResult :=
  if !cfg.enabled then GuardResult.allow "mcp_tool"
  else match action with
  | .mcpTool tool _ =>
    if cfg.block.contains tool then
      GuardResult.block "mcp_tool" .error s!"MCP tool '{tool}' is blocked"
    else if cfg.allow.isEmpty || cfg.allow.contains tool then
      GuardResult.allow "mcp_tool"
    else
      match cfg.defaultAction with
      | some .block => GuardResult.block "mcp_tool" .error
          s!"MCP tool '{tool}' is not in allowlist (default: block)"
      | _ => GuardResult.allow "mcp_tool"
  | _ => GuardResult.allow "mcp_tool"

/-- Mirrors: guard evaluation pipeline in engine.rs -/
def evalGuards (cfg : GuardConfigs) (action : Action) (ctx : Context) : List GuardResult :=
  let results : List (Option GuardResult) := [
    cfg.forbiddenPath.map (fun c => evalForbiddenPath c action ctx),
    cfg.pathAllowlist.map (fun c => evalPathAllowlist c action ctx),
    cfg.egressAllowlist.map (fun c => evalEgressAllowlist c action ctx),
    cfg.shellCommand.map (fun c => evalShellCommand c action ctx),
    cfg.mcpTool.map (fun c => evalMcpTool c action ctx),
    cfg.secretLeak.map (fun _ => evalContentGuard "secret_leak" action ctx),
    cfg.patchIntegrity.map (fun _ => evalContentGuard "patch_integrity" action ctx),
    cfg.promptInjection.bind (fun c =>
      if c.enabled then some (evalContentGuard "prompt_injection" action ctx) else none),
    cfg.jailbreak.bind (fun c =>
      if c.enabled then some (evalContentGuard "jailbreak" action ctx) else none),
    cfg.computerUse.map (fun _ => evalContentGuard "computer_use" action ctx),
    cfg.remoteDesktopSideChannel.map
      (fun _ => evalContentGuard "remote_desktop_side_channel" action ctx),
    cfg.inputInjectionCapability.map
      (fun _ => evalContentGuard "input_injection_capability" action ctx),
    cfg.spiderSense.map (fun _ => evalContentGuard "spider_sense" action ctx)
  ]
  results.filterMap id

/-- Mirrors: version check in Rust engine initialization. -/
def hasConfigError (policy : Policy) : Bool :=
  !supportedVersions.contains policy.version

/-- Full policy evaluation. Mirrors: engine.rs evaluation pipeline. -/
def evalPolicy (policy : Policy) (action : Action) (ctx : Context)
    : Except String GuardResult :=
  if hasConfigError policy then
    .error s!"Unsupported schema version"
  else
    let results := evalGuards policy.guards action ctx
    let effectiveResults :=
      if policy.settings.effectiveFailFast then
        match results.find? (fun r => !r.allowed) with
        | some firstDeny => [firstDeny]
        | none => results
      else
        results
    .ok (aggregateOverall effectiveResults)

end

end ClawdStrike.Core
