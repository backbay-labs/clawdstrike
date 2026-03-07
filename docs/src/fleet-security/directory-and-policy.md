# Identity, Policy, and Posture

Fleet Security treats identity as the control plane for autonomous systems.

That means the important question is not only "what policy is installed?" It is
"which principal is acting, what trust does it have, and what posture should it
be allowed to operate under right now?"

## Principals

The platform tracks more than one kind of identity:

- endpoint agents
- runtime agents
- delegated agents
- operators
- service accounts

Each principal has a stable reference, lifecycle state, liveness state, and
optionally key material used for trust and attestation.

## Policy

Policy answers what a principal is allowed to do. In practice that covers:

- tools and actions
- environments and targets
- approval requirements
- threat-detection behavior

The useful operator habit is to attach policy to stable fleet structure instead
of baking it into one-off agent configurations.

## Posture

Posture answers how much freedom the fleet has right now.

Examples:

- normal operation
- tighter observation
- restricted execution
- quarantine

Posture is intentionally operational. It is the quickest way to reduce risk
when the environment changes or an incident is underway.

## Grants and Delegation

Autonomous systems do not just act directly. They delegate, spawn subagents,
and pass authority.

That is why Fleet Security tracks grants and delegated authority as first-class
objects instead of pretending every action comes straight from one long-lived
agent identity.

## Operator Guidance

- Keep principal identity stable even when individual sessions are ephemeral.
- Use policy to describe steady-state behavior.
- Use posture to describe temporary operating conditions.
- Revoke grants or quarantine principals when you need to cut off authority fast.
