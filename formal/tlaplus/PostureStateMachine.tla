---- MODULE PostureStateMachine ----
(***************************************************************************)
(* TLA+ specification for ClawdStrike's posture state machine.             *)
(*                                                                         *)
(* This models the runtime behavior of the posture subsystem defined in:   *)
(*   crates/libs/clawdstrike/src/posture.rs   -- types & compiled program  *)
(*   crates/libs/clawdstrike/src/engine.rs    -- runtime evaluation logic  *)
(*                                                                         *)
(* The posture system enforces progressive capability restriction:          *)
(*   - Agents start in an initial posture state (e.g., "restricted")       *)
(*   - Each state grants a set of capabilities and per-capability budgets  *)
(*   - Allowed actions consume budget; exhaustion triggers transitions     *)
(*   - Violations also trigger transitions to more restricted states       *)
(*   - The system is fail-closed: unknown states or exhausted budgets deny *)
(*                                                                         *)
(* Corresponds to Phase 6 of the formal verification roadmap:              *)
(*   docs/plans/clawdstrike/formal-verification/ROADMAP.md                 *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, Sequences, TLC

(***************************************************************************)
(* CONSTANTS                                                               *)
(*                                                                         *)
(* States: set of posture state names (strings)                            *)
(*   Maps to: PostureConfig.states keys in posture.rs:35-38               *)
(*                                                                         *)
(* InitState: the initial posture state                                    *)
(*   Maps to: PostureConfig.initial in posture.rs:36                      *)
(*                                                                         *)
(* StateOrder: function from States -> Nat giving the restrictiveness      *)
(*   ordering. Higher number = more restrictive. This models the           *)
(*   monotonicity invariant from the roadmap: "capability sets are         *)
(*   monotonically non-increasing along enforcement paths."                *)
(*   No direct Rust field -- this is an implicit design invariant.         *)
(*                                                                         *)
(* BudgetLimit: function from States -> Nat giving the budget for each     *)
(*   state. Abstracts per-capability budgets into a single counter.        *)
(*   Maps to: CompiledPostureState.budgets in posture.rs:376              *)
(*                                                                         *)
(* TransitionMap: set of records [from |-> s1, to |-> s2, trigger |-> t]   *)
(*   Maps to: PostureProgram.transitions in posture.rs:264                *)
(*   Triggers: "budget_exhausted", "violation", "critical_violation"        *)
(*   Maps to: RuntimeTransitionTrigger in posture.rs:423-429              *)
(*                                                                         *)
(* AbsorbingStates: subset of States with no outgoing transitions          *)
(*   The roadmap requires: "locked state has no outgoing transitions"      *)
(***************************************************************************)

CONSTANTS
    States,              \* Set of posture state names
    InitState,           \* The initial state (member of States)
    StateOrder,          \* Function: States -> Nat (restrictiveness rank)
    BudgetLimit,         \* Function: States -> Nat (initial budget per state)
    TransitionMap,       \* Set of [from: States, to: States, trigger: STRING]
    AbsorbingStates      \* Subset of States with no outgoing transitions

(***************************************************************************)
(* VARIABLES                                                               *)
(*                                                                         *)
(* currentState: the current posture state name                            *)
(*   Maps to: PostureRuntimeState.current_state in posture.rs:493         *)
(*                                                                         *)
(* budget: remaining action budget in the current state                    *)
(*   Maps to: PostureBudgetCounter (limit - used) via remaining()          *)
(*   in posture.rs:534-536                                                 *)
(*                                                                         *)
(* transitionHistory: sequence of [from, to, trigger] records              *)
(*   Maps to: PostureRuntimeState.transition_history in posture.rs:496    *)
(*                                                                         *)
(* terminated: flag indicating the system has reached a final state        *)
(*   with no remaining actions (models absorbing state behavior)           *)
(***************************************************************************)

VARIABLES
    currentState,
    budget,
    transitionHistory,
    terminated

vars == <<currentState, budget, transitionHistory, terminated>>

(***************************************************************************)
(* TYPE INVARIANT                                                          *)
(*                                                                         *)
(* Establishes the type correctness of all variables.                      *)
(***************************************************************************)

TypeOK ==
    /\ currentState \in States
    /\ budget \in Nat
    /\ terminated \in BOOLEAN
    /\ transitionHistory \in Seq([from : States, to : States, trigger : {"budget_exhausted", "violation", "critical_violation"}])

(***************************************************************************)
(* HELPER OPERATORS                                                        *)
(***************************************************************************)

\* Find matching transitions for a given state and trigger.
\* Models PostureProgram::find_transition() in posture.rs:350-358
\* Note: the Rust code uses first-match semantics (iter().find()).
\* We model this as the set of all matching transitions; the spec
\* nondeterministically chooses one if multiple match.
MatchingTransitions(state, trigger) ==
    { t \in TransitionMap : t.from = state /\ t.trigger = trigger }

\* Check whether a state has any outgoing transition for any trigger.
HasOutgoingTransition(state) ==
    \E t \in TransitionMap : t.from = state

(***************************************************************************)
(* INITIAL STATE                                                           *)
(*                                                                         *)
(* Models PostureProgram::initial_runtime_state() in posture.rs:338-344   *)
(* and HushEngine::ensure_posture_initialized() in engine.rs:1258-1276    *)
(***************************************************************************)

Init ==
    /\ currentState = InitState
    /\ budget = BudgetLimit[InitState]
    /\ transitionHistory = << >>
    /\ terminated = FALSE

(***************************************************************************)
(* ACTIONS                                                                 *)
(***************************************************************************)

(* -------------------------------------------------------------------- *)
(* ConsumeBudgetedAction: An allowed action that has a budget key         *)
(* consumes one unit of budget.                                           *)
(*                                                                        *)
(* Models the budget consumption path in engine.rs:1221-1232:            *)
(*   if guard_report.overall.allowed {                                    *)
(*       if let Some(budget_key) = capability.budget_key() {             *)
(*           if let Some(counter) = state.budgets.get_mut(budget_key) {  *)
(*               if counter.try_consume() { ... }                        *)
(*               if counter.is_exhausted() {                              *)
(*                   trigger = Some(BudgetExhausted);                    *)
(*               }                                                        *)
(*           }                                                            *)
(*       }                                                                *)
(*   }                                                                    *)
(*                                                                        *)
(* PostureBudgetCounter::try_consume() in posture.rs:542-548:            *)
(*   Returns false if exhausted, otherwise increments `used` by 1.       *)
(*                                                                        *)
(* Precondition: budget > 0 (try_consume returns false otherwise) and     *)
(* the system has not terminated.                                         *)
(* -------------------------------------------------------------------- *)

ConsumeBudgetedAction ==
    /\ ~terminated
    /\ budget > 0
    /\ budget' = budget - 1
    /\ currentState' = currentState
    /\ transitionHistory' = transitionHistory
    /\ terminated' = terminated

(* -------------------------------------------------------------------- *)
(* ConsumeUnbudgetedAction: An allowed action whose capability has no     *)
(* budget key (e.g., file_access -> budget_key() returns None).           *)
(*                                                                        *)
(* In posture.rs:247-249, Capability::budget_key() returns None for      *)
(* FileAccess. In engine.rs:1222-1223, when budget_key is None, no       *)
(* counter is consumed and no exhaustion trigger fires.                   *)
(*                                                                        *)
(* This is a stuttering step (UNCHANGED vars) -- it models the fact that *)
(* budget-free actions can occur indefinitely without changing the        *)
(* posture state. Included in Next to document the behavior, though      *)
(* [][Next]_vars already permits stuttering.                              *)
(* See rulesets/ai-agent-posture.yaml lines 12-15 (restricted state).   *)
(* -------------------------------------------------------------------- *)

ConsumeUnbudgetedAction ==
    /\ ~terminated
    /\ budget = 0
    /\ currentState \notin AbsorbingStates
    /\ MatchingTransitions(currentState, "budget_exhausted") = {}
    /\ UNCHANGED vars

(* -------------------------------------------------------------------- *)
(* BudgetExhaustedTransition: When budget reaches zero, fire the          *)
(* budget_exhausted transition if one exists.                             *)
(*                                                                        *)
(* Models the transition trigger in engine.rs:1228-1230:                 *)
(*   if counter.is_exhausted() {                                         *)
(*       trigger = Some(RuntimeTransitionTrigger::BudgetExhausted);      *)
(*   }                                                                    *)
(*                                                                        *)
(* Followed by apply_trigger_transition in engine.rs:1241-1244:          *)
(*   if let Some(trigger) = trigger {                                    *)
(*       if let Some(record) = self.apply_trigger_transition(...) {      *)
(*           transition = Some(record);                                  *)
(*       }                                                                *)
(*   }                                                                    *)
(*                                                                        *)
(* And apply_transition in engine.rs:1388-1412 which:                    *)
(*   - Sets current_state to the target                                  *)
(*   - Reinitializes budgets from target state (initial_budgets())       *)
(*   - Records the transition in transition_history                      *)
(* -------------------------------------------------------------------- *)

BudgetExhaustedTransition ==
    /\ ~terminated
    /\ budget = 0
    /\ MatchingTransitions(currentState, "budget_exhausted") /= {}
    /\ \E t \in MatchingTransitions(currentState, "budget_exhausted") :
        /\ currentState' = t.to
        /\ budget' = BudgetLimit[t.to]
        /\ transitionHistory' = Append(transitionHistory,
               [from |-> currentState, to |-> t.to, trigger |-> "budget_exhausted"])
        /\ terminated' = (t.to \in AbsorbingStates /\ BudgetLimit[t.to] = 0)

(* -------------------------------------------------------------------- *)
(* ViolationTransition: A guard violation triggers a transition.          *)
(*                                                                        *)
(* Models the violation path in engine.rs:1233-1238:                     *)
(*   } else {                                                            *)
(*       trigger = Some(if guard_report.overall.severity == Critical {   *)
(*           RuntimeTransitionTrigger::CriticalViolation                 *)
(*       } else {                                                        *)
(*           RuntimeTransitionTrigger::AnyViolation                      *)
(*       });                                                              *)
(*   }                                                                    *)
(*                                                                        *)
(* We model both violation types as nondeterministic triggers.            *)
(* The environment can produce a violation at any time.                   *)
(* -------------------------------------------------------------------- *)

ViolationTransition ==
    /\ ~terminated
    /\ \E trigger \in {"violation", "critical_violation"} :
        /\ MatchingTransitions(currentState, trigger) /= {}
        /\ \E t \in MatchingTransitions(currentState, trigger) :
            /\ currentState' = t.to
            /\ budget' = BudgetLimit[t.to]
            /\ transitionHistory' = Append(transitionHistory,
                   [from |-> currentState, to |-> t.to, trigger |-> trigger])
            /\ terminated' = (t.to \in AbsorbingStates /\ BudgetLimit[t.to] = 0)

(* -------------------------------------------------------------------- *)
(* Terminate: The system enters a final absorbing state with zero budget  *)
(* and no outgoing transitions. No further actions are possible.          *)
(*                                                                        *)
(* This models the posture precheck denial in engine.rs:1330-1376:       *)
(* when a state has no capabilities or all budgets are exhausted and     *)
(* there is no transition to fire, the system effectively deadlocks      *)
(* (all subsequent actions are denied).                                   *)
(* -------------------------------------------------------------------- *)

Terminate ==
    /\ ~terminated
    /\ currentState \in AbsorbingStates
    /\ budget = 0
    /\ terminated' = TRUE
    /\ UNCHANGED <<currentState, budget, transitionHistory>>

(***************************************************************************)
(* NEXT-STATE RELATION                                                     *)
(*                                                                         *)
(* Note: stuttering is implicit via [][Next]_vars in the Spec formula.     *)
(* When terminated=TRUE, no disjunct of Next is enabled with changed vars, *)
(* so the system stutters forever -- which is the desired behavior for     *)
(* absorbing states.                                                       *)
(***************************************************************************)

Next ==
    \/ ConsumeBudgetedAction
    \/ ConsumeUnbudgetedAction
    \/ BudgetExhaustedTransition
    \/ ViolationTransition
    \/ Terminate

(***************************************************************************)
(* FAIRNESS                                                                *)
(*                                                                         *)
(* Weak fairness on BudgetExhaustedTransition ensures that when budget    *)
(* hits zero, the transition eventually fires (not starved forever).       *)
(* This is needed for the liveness property BudgetExhaustionProgress.      *)
(***************************************************************************)

Fairness ==
    /\ WF_vars(BudgetExhaustedTransition)
    /\ WF_vars(Terminate)

Spec == Init /\ [][Next]_vars /\ Fairness

(***************************************************************************)
(* SAFETY PROPERTIES                                                       *)
(***************************************************************************)

(* -------------------------------------------------------------------- *)
(* BudgetNonNegative: The budget counter is always >= 0.                  *)
(*                                                                        *)
(* This is guaranteed by the Rust type system (u64) and                   *)
(* PostureBudgetCounter::remaining() using saturating_sub (posture.rs:535)*)
(* as well as try_consume() checking is_exhausted() before incrementing  *)
(* (posture.rs:542-548). The TLA+ spec must also satisfy this since      *)
(* budget is declared as Nat.                                             *)
(*                                                                        *)
(* Roadmap requirement: "Budget counters never underflow"                  *)
(* -------------------------------------------------------------------- *)

BudgetNonNegative == budget >= 0

(* -------------------------------------------------------------------- *)
(* AbsorbingStateProperty: Once the system enters an absorbing state      *)
(* with zero budget, it never leaves.                                     *)
(*                                                                        *)
(* Roadmap requirement: "locked state has no outgoing transitions"        *)
(*                                                                        *)
(* This is enforced structurally: AbsorbingStates have no entries in     *)
(* TransitionMap, so no transition action can fire. Once terminated is    *)
(* set, only Stutter is enabled.                                          *)
(* -------------------------------------------------------------------- *)

AbsorbingStateStable ==
    \* Temporal property: once terminated, the system stays terminated
    \* forever. Formulated as an action invariant: if terminated is TRUE
    \* in the current state, then terminated remains TRUE and currentState
    \* is unchanged in the next state.
    [][terminated => terminated' /\ currentState' = currentState]_vars

\* Simpler invariant form: absorbing states have no outgoing transitions.
\* This is checkable as a state invariant (no primed variables).
AbsorbingStatesHaveNoTransitions ==
    \A s \in AbsorbingStates : ~HasOutgoingTransition(s)

(* -------------------------------------------------------------------- *)
(* MonotonicityInvariant: Transitions only move toward more restrictive   *)
(* states (higher StateOrder values), never toward less restrictive.      *)
(*                                                                        *)
(* Roadmap requirement: "Capability sets are monotonically                *)
(* non-increasing along enforcement paths"                                *)
(*                                                                        *)
(* This is an invariant over the transition history: for every recorded   *)
(* transition, the target state is at least as restrictive as the source. *)
(*                                                                        *)
(* NOTE: In the real system (ai-agent-posture.yaml), user_approval       *)
(* transitions can RELAX the posture (restricted -> standard -> elevated).*)
(* This property applies ONLY to enforcement-triggered transitions        *)
(* (budget_exhausted, violation, critical_violation), not user-initiated  *)
(* ones. Our model only includes enforcement triggers, so this holds     *)
(* universally within the model.                                          *)
(* -------------------------------------------------------------------- *)

MonotonicityInvariant ==
    \A i \in 1..Len(transitionHistory) :
        LET record == transitionHistory[i]
        IN StateOrder[record.to] >= StateOrder[record.from]

(* -------------------------------------------------------------------- *)
(* StateValid: The current state is always a member of the declared       *)
(* States set. Models the fail-closed behavior in engine.rs:1336-1343   *)
(* where an unknown state causes a deny.                                  *)
(* -------------------------------------------------------------------- *)

StateValid == currentState \in States

(* -------------------------------------------------------------------- *)
(* Combined safety invariant checked by TLC.                              *)
(* -------------------------------------------------------------------- *)

Safety ==
    /\ TypeOK
    /\ BudgetNonNegative
    /\ StateValid
    /\ MonotonicityInvariant

(***************************************************************************)
(* LIVENESS PROPERTIES                                                     *)
(***************************************************************************)

(* -------------------------------------------------------------------- *)
(* BudgetExhaustionProgress: If budget reaches zero and a                  *)
(* budget_exhausted transition exists, the transition eventually fires.    *)
(*                                                                        *)
(* Roadmap requirement: "if budget reaches zero, a transition eventually  *)
(* occurs"                                                                 *)
(*                                                                        *)
(* This requires WF_vars(BudgetExhaustedTransition).                      *)
(* -------------------------------------------------------------------- *)

BudgetExhaustionProgress ==
    \A s \in States :
        (currentState = s /\ budget = 0 /\ MatchingTransitions(s, "budget_exhausted") /= {})
            ~> (currentState /= s \/ terminated)

(* -------------------------------------------------------------------- *)
(* EventualQuiescence: The system eventually reaches a stable condition:  *)
(* either terminated, or has budget remaining, or is in a budget-free     *)
(* steady state (zero budget, no budget_exhausted transition, not         *)
(* absorbing). This ensures no unreachable deadlocks exist.              *)
(*                                                                        *)
(* Budget-free steady states (like "restricted" with only file_access)   *)
(* can persist indefinitely -- this is correct behavior, not a deadlock. *)
(* -------------------------------------------------------------------- *)

IsSteadyState(s) ==
    /\ s \notin AbsorbingStates
    /\ MatchingTransitions(s, "budget_exhausted") = {}
    /\ BudgetLimit[s] = 0

EventualQuiescence ==
    <>(terminated \/ budget > 0 \/ IsSteadyState(currentState))

(***************************************************************************)
(* MODEL VALUES (for concrete TLC checking)                                *)
(*                                                                         *)
(* These operators define a concrete instantiation matching the            *)
(* ai-agent-posture.yaml built-in ruleset:                                *)
(*                                                                         *)
(*   restricted -> standard -> elevated                                   *)
(*   (enforcement transitions go in reverse direction)                    *)
(*                                                                         *)
(* See: rulesets/ai-agent-posture.yaml                                    *)
(***************************************************************************)

\* Concrete model for the ai-agent-posture ruleset.
\* Use via MC_PostureStateMachine.tla or .cfg overrides.

ModelStates == {"restricted", "standard", "elevated", "locked"}

ModelInitState == "restricted"

\* Restrictiveness ordering: 0 = least restrictive, 3 = most restrictive
\* elevated (full caps) < standard (partial) < restricted (read-only) < locked (none)
ModelStateOrder ==
    [s \in ModelStates |->
        CASE s = "elevated"   -> 0
        []   s = "standard"   -> 1
        []   s = "restricted" -> 2
        []   s = "locked"     -> 3
    ]

\* Budget limits per state (abstracted from per-capability to single counter)
\* elevated: 200 (file_writes), standard: 50 (file_writes), restricted: 0, locked: 0
ModelBudgetLimit ==
    [s \in ModelStates |->
        CASE s = "elevated"   -> 3   \* Small for model checking; represents 200 in prod
        []   s = "standard"   -> 2   \* Small for model checking; represents 50 in prod
        []   s = "restricted" -> 0
        []   s = "locked"     -> 0
    ]

\* Enforcement-triggered transitions only (no user_approval, no timeout).
\* These are the transitions where monotonicity must hold.
\*
\* From ai-agent-posture.yaml:
\*   - from: "*", to: restricted, on: critical_violation
\*   - from: standard, to: restricted, on: budget_exhausted
\*
\* We add the enforcement transitions and a locked absorbing state:
\*   - from: elevated, to: standard, on: budget_exhausted
\*   - from: restricted, to: locked, on: critical_violation
ModelTransitionMap == {
    \* Budget exhaustion: elevated -> standard (budget runs out at elevated)
    [from |-> "elevated",   to |-> "standard",   trigger |-> "budget_exhausted"],
    \* Budget exhaustion: standard -> restricted (matches ai-agent-posture.yaml)
    [from |-> "standard",   to |-> "restricted", trigger |-> "budget_exhausted"],
    \* Critical violation from any non-locked state goes to restricted
    [from |-> "elevated",   to |-> "restricted", trigger |-> "critical_violation"],
    [from |-> "standard",   to |-> "restricted", trigger |-> "critical_violation"],
    \* Critical violation in restricted goes to locked (absorbing)
    [from |-> "restricted", to |-> "locked",     trigger |-> "critical_violation"],
    \* Non-critical violations: elevated -> standard, standard -> restricted
    [from |-> "elevated",   to |-> "standard",   trigger |-> "violation"],
    [from |-> "standard",   to |-> "restricted", trigger |-> "violation"]
}

ModelAbsorbingStates == {"locked"}

====
