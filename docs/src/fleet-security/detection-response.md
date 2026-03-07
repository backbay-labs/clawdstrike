# Detection, Hunt, and Response

This is the operator workflow layer of Fleet Security.

The platform is not useful if it can only block actions. It has to help teams
understand what happened, decide whether it matters, and contain it without
destroying context.

## Detection

Detections turn normalized fleet activity into findings.

The important user-facing outcome is simple:

- operators get a finding tied to real fleet entities
- findings can be tuned, suppressed, or escalated
- findings can be linked forward into response actions and cases

## Hunt

Hunt is for questions that do not fit into a single alert.

Use hunts to answer things like:

- where else did this principal appear
- which runtimes executed the same pattern
- what changed before the posture transition
- which agents were connected through a delegation chain

## Response

Response actions are the containment layer.

Examples include:

- transition posture
- request policy reload
- kill switch
- revoke grant
- revoke or quarantine principal

The response ledger matters as much as the action itself. Operators should be
able to see why an action was requested, what it targeted, and what happened
afterward.

## Cases

A case is where a fleet incident becomes durable.

Cases pull together:

- findings
- response actions
- graph pivots
- notes and artifacts
- exported evidence

## Recommended Workflow

1. Start with the finding or hunt result.
2. Pivot into the timeline or graph until the affected scope is clear.
3. Apply the narrowest response that contains the problem.
4. Open or update a case if the activity needs durable handling.
5. Export evidence when the issue needs review outside the console.
