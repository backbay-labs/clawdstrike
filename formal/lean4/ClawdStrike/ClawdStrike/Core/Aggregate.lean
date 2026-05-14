/-
  Verdict aggregation: selects the "worst" guard result via left fold.
  Mirrors: core/aggregate.rs (aggregate_index, aggregate_overall)
-/

import ClawdStrike.Core.Verdict

set_option autoImplicit false

namespace ClawdStrike.Core

/-- Mirrors: aggregate_index comparison in core/aggregate.rs
    Priority: blocking > higher severity > sanitized. Ties preserve accumulator. -/
def worseResult (best candidate : GuardResult) : GuardResult :=
  let bestBlocks := !best.allowed
  let candBlocks := !candidate.allowed
  if candBlocks && !bestBlocks then candidate
  else if candBlocks == bestBlocks
       && candidate.severity.toNat > best.severity.toNat then candidate
  else if candBlocks == bestBlocks
       && candidate.severity.toNat == best.severity.toNat
       && !candBlocks
       && candidate.sanitized
       && !best.sanitized then candidate
  else best

/-- Mirrors: CoreVerdict::allow("engine") at core/aggregate.rs:82 -/
def defaultResult : GuardResult :=
  { allowed := true
  , severity := .info
  , guardName := "engine"
  , message := "No guards matched"
  , sanitized := false }

/-- Aggregate guard results via left fold with defaultResult as initial accumulator. -/
def aggregateOverall (results : List GuardResult) : GuardResult :=
  results.foldl worseResult defaultResult

/-- Alternative form matching the formal spec (section 3.5). -/
def aggregateSpec : List GuardResult → GuardResult
  | [] => GuardResult.allow "engine"
  | r :: rs => rs.foldl worseResult r

end ClawdStrike.Core
