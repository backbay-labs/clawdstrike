/-
  Core type definitions: Severity, GuardResult, Action, guard configs, Policy.
  Mirrors: core/verdict.rs, guards/mod.rs, guards/*.rs, policy.rs
-/

set_option autoImplicit false

namespace ClawdStrike.Core

abbrev Path := String
abbrev Domain := String
abbrev Command := String
abbrev ToolName := String
abbrev Args := String
abbrev Diff := String
abbrev ActionType := String
abbrev GlobPattern := String

/-- Mirrors: core/verdict.rs CoreSeverity -/
inductive Severity where
  | info
  | warning
  | error
  | critical
  deriving Repr, BEq, DecidableEq, Inhabited

/-- Mirrors: severity_ord in core/verdict.rs -/
def Severity.toNat : Severity → Nat
  | .info => 0
  | .warning => 1
  | .error => 2
  | .critical => 3

instance : LE Severity where
  le a b := a.toNat ≤ b.toNat

instance : LT Severity where
  lt a b := a.toNat < b.toNat

instance (a b : Severity) : Decidable (a ≤ b) :=
  inferInstanceAs (Decidable (a.toNat ≤ b.toNat))

instance (a b : Severity) : Decidable (a < b) :=
  inferInstanceAs (Decidable (a.toNat < b.toNat))

/-- toNat is injective. -/
theorem Severity.toNat_injective (a b : Severity) (h : a.toNat = b.toNat) : a = b := by
  cases a <;> cases b <;> simp [Severity.toNat] at h <;> rfl

/-- Mirrors: CoreVerdict in core/verdict.rs -/
structure GuardResult where
  allowed : Bool
  severity : Severity
  guardName : String
  message : String
  sanitized : Bool := false
  deriving Repr, BEq

/-- Mirrors: CoreVerdict::allow() -/
def GuardResult.allow (guard : String) : GuardResult :=
  { allowed := true
  , severity := .info
  , guardName := guard
  , message := "Allowed"
  , sanitized := false }

/-- Mirrors: CoreVerdict::block() -/
def GuardResult.block (guard : String) (sev : Severity) (msg : String) : GuardResult :=
  { allowed := false
  , severity := sev
  , guardName := guard
  , message := msg
  , sanitized := false }

/-- Mirrors: CoreVerdict::warn() -/
def GuardResult.warn (guard : String) (msg : String) : GuardResult :=
  { allowed := true
  , severity := .warning
  , guardName := guard
  , message := msg
  , sanitized := false }

/-- Mirrors: CoreVerdict::sanitize() -/
def GuardResult.sanitize (guard : String) (msg : String) : GuardResult :=
  { allowed := true
  , severity := .warning
  , guardName := guard
  , message := msg
  , sanitized := true }

/-- Mirrors: GuardAction in guards/mod.rs -/
inductive Action where
  | fileAccess   : Path → Action
  | fileWrite    : Path → List UInt8 → Action
  | networkEgress : Domain → UInt16 → Action
  | shellCommand : Command → Action
  | mcpTool      : ToolName → Args → Action
  | patch        : Path → Diff → Action
  | custom       : ActionType → Args → Action
  deriving Repr, BEq

/-- Mirrors: guards/forbidden_path.rs ForbiddenPathConfig
    `patterns = none` means use default_forbidden_patterns(). -/
structure ForbiddenPathConfig where
  enabled : Bool := true
  patterns : Option (List GlobPattern) := none
  exceptions : List GlobPattern := []
  additionalPatterns : List GlobPattern := []
  removePatterns : List GlobPattern := []
  deriving Repr, BEq

/-- Mirrors: guards/path_allowlist.rs PathAllowlistConfig -/
structure PathAllowlistConfig where
  enabled : Bool := true
  fileAccessAllow : List GlobPattern := []
  fileWriteAllow : List GlobPattern := []
  patchAllow : List GlobPattern := []
  deriving Repr, BEq

/-- Mirrors: PolicyAction in the Rust proxy crate. -/
inductive PolicyAction where
  | allow
  | block
  | log
  deriving Repr, BEq, DecidableEq

/-- Mirrors: guards/egress_allowlist.rs EgressAllowlistConfig -/
structure EgressAllowlistConfig where
  enabled : Bool := true
  allow : List Domain := []
  block : List Domain := []
  defaultAction : Option PolicyAction := none
  additionalAllow : List Domain := []
  removeAllow : List Domain := []
  additionalBlock : List Domain := []
  removeBlock : List Domain := []
  deriving Repr, BEq

/-- Mirrors: guards/shell_command.rs ShellCommandConfig -/
structure ShellCommandConfig where
  enabled : Bool := true
  forbiddenPatterns : List String := []
  enforceForbiddenPaths : Bool := true
  deriving Repr, BEq

/-- Mirrors: guards/mcp_tool.rs McpDefaultAction -/
inductive McpDefaultAction where
  | allow
  | block
  deriving Repr, BEq, DecidableEq

/-- Mirrors: guards/mcp_tool.rs McpToolConfig -/
structure McpToolConfig where
  enabled : Bool := true
  allow : List ToolName := []
  block : List ToolName := []
  requireConfirmation : List ToolName := []
  defaultAction : Option McpDefaultAction := none
  maxArgsSize : Option Nat := none
  additionalAllow : List ToolName := []
  removeAllow : List ToolName := []
  additionalBlock : List ToolName := []
  removeBlock : List ToolName := []
  deriving Repr, BEq

/-- Mirrors: guards/secret_leak.rs SecretPattern -/
structure SecretPattern where
  name : String
  pattern : String
  deriving Repr, BEq

/-- Mirrors: guards/secret_leak.rs SecretLeakConfig (simplified). -/
structure SecretLeakConfig where
  enabled : Bool := true
  patterns : List SecretPattern := []
  additionalPatterns : List SecretPattern := []
  removePatterns : List String := []
  skipPaths : List GlobPattern := []
  deriving Repr, BEq

/-- Mirrors: guards/patch_integrity.rs PatchIntegrityConfig (simplified). -/
structure PatchIntegrityConfig where
  maxAdditions : Nat := 500
  maxDeletions : Nat := 500
  requireBalance : Bool := false
  forbiddenPatterns : List String := []
  deriving Repr, BEq

/-- Opaque config for content-dependent guards (prompt injection, jailbreak, etc.).
    Only the `enabled` flag is modeled. -/
structure ContentGuardConfig where
  enabled : Bool := true
  deriving Repr, BEq

/-- Mirrors: policy.rs GuardConfigs. `none` = guard not configured. -/
structure GuardConfigs where
  forbiddenPath : Option ForbiddenPathConfig := none
  pathAllowlist : Option PathAllowlistConfig := none
  egressAllowlist : Option EgressAllowlistConfig := none
  secretLeak : Option SecretLeakConfig := none
  patchIntegrity : Option PatchIntegrityConfig := none
  shellCommand : Option ShellCommandConfig := none
  mcpTool : Option McpToolConfig := none
  promptInjection : Option ContentGuardConfig := none
  jailbreak : Option ContentGuardConfig := none
  computerUse : Option ContentGuardConfig := none
  remoteDesktopSideChannel : Option ContentGuardConfig := none
  inputInjectionCapability : Option ContentGuardConfig := none
  spiderSense : Option ContentGuardConfig := none
  deriving Repr, BEq

instance : Inhabited GuardConfigs where
  default := {}

/-- Mirrors: core/merge.rs CoreMergeStrategy -/
inductive MergeStrategy where
  | replace
  | merge
  | deepMerge
  deriving Repr, BEq, DecidableEq

/-- Mirrors: policy.rs PolicySettings -/
structure PolicySettings where
  failFast : Option Bool := none
  verboseLogging : Option Bool := none
  sessionTimeoutSecs : Option Nat := none
  deriving Repr, BEq

def PolicySettings.effectiveFailFast (s : PolicySettings) : Bool :=
  s.failFast.getD false

def PolicySettings.effectiveVerboseLogging (s : PolicySettings) : Bool :=
  s.verboseLogging.getD false

def PolicySettings.effectiveSessionTimeoutSecs (s : PolicySettings) : Nat :=
  s.sessionTimeoutSecs.getD 3600

instance : Inhabited PolicySettings where
  default := {}

/-- Semantic version (major, minor, patch). -/
structure Version where
  major : Nat
  minor : Nat
  patch : Nat
  deriving Repr, BEq, DecidableEq

/-- Mirrors: POLICY_SUPPORTED_SCHEMA_VERSIONS in policy.rs -/
def supportedVersions : List Version :=
  [⟨1,1,0⟩, ⟨1,2,0⟩, ⟨1,3,0⟩, ⟨1,4,0⟩, ⟨1,5,0⟩]

/-- Mirrors: POLICY_SCHEMA_VERSION in policy.rs -/
def currentSchemaVersion : Version := ⟨1,5,0⟩

/-- Mirrors: PolicyLocation in policy.rs -/
inductive PolicyRef where
  | ruleset : String → PolicyRef
  | file    : Path → PolicyRef
  | url     : String → PolicyRef
  deriving Repr, BEq

/-- Mirrors: policy.rs Policy (fully resolved, extends_ = none after resolution). -/
structure Policy where
  version : Version := currentSchemaVersion
  name : String := ""
  description : String := ""
  extends_ : Option PolicyRef := none
  mergeStrategy : MergeStrategy := .deepMerge
  guards : GuardConfigs := {}
  settings : PolicySettings := {}
  deriving Repr, BEq

instance : Inhabited Policy where
  default := {}

/-- Mirrors: GuardContext in guards/mod.rs -/
structure Context where
  cwd : Option Path := none
  sessionId : Option String := none
  agentId : Option String := none
  metadata : Option String := none
  deriving Repr, BEq

instance : Inhabited Context where
  default := {}

end ClawdStrike.Core
