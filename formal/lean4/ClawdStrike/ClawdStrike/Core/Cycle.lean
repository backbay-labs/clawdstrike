/-
  Cycle detection for policy `extends` chains.
  Mirrors: core/cycle.rs, policy.rs (extends resolution)
-/

set_option autoImplicit false

namespace ClawdStrike.Core

/-- Mirrors: MAX_POLICY_EXTENDS_DEPTH in core/cycle.rs -/
def maxExtendsDepth : Nat := 32

/-- Mirrors: CycleCheckResult in core/cycle.rs -/
inductive CycleCheckResult where
  | ok
  | depthExceeded (depth : Nat) (limit : Nat)
  | cycleDetected (key : String)
  deriving Repr, BEq

abbrev Visited := List String

def Visited.contains (visited : Visited) (key : String) : Bool :=
  visited.any (· == key)

/-- Mirrors: check_extends_cycle in core/cycle.rs
    Rust uses `depth > MAX_POLICY_EXTENDS_DEPTH` (strictly greater). -/
def checkExtendsCycle (key : String) (visited : Visited) (depth : Nat) : CycleCheckResult :=
  if depth > maxExtendsDepth then
    .depthExceeded depth maxExtendsDepth
  else if visited.contains key then
    .cycleDetected key
  else
    .ok

/-- A policy node in the extends graph. -/
structure PolicyNode where
  key : String
  extends_ : Option String
  deriving Repr, BEq

inductive ResolveResult where
  | ok (chain : List String)
  | cycleDetected (key : String)
  | depthExceeded (depth : Nat)
  deriving Repr

/-- Resolve a policy chain with fuel-bounded recursion. -/
def resolveChain (lookup : String → Option PolicyNode) (key : String)
    (visited : Visited) (fuel : Nat) : ResolveResult :=
  match fuel with
  | 0 => .depthExceeded (visited.length)
  | fuel' + 1 =>
    if visited.contains key then
      .cycleDetected key
    else
      match lookup key with
      | none => .ok (key :: visited)
      | some node =>
        match node.extends_ with
        | none => .ok (key :: visited)
        | some parent => resolveChain lookup parent (key :: visited) fuel'

/-- Resolve a chain using the standard fuel bound (maxExtendsDepth + 1). -/
def resolveChainBounded (lookup : String → Option PolicyNode) (key : String) : ResolveResult :=
  resolveChain lookup key [] (maxExtendsDepth + 1)

end ClawdStrike.Core
