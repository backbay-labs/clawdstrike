# For Users

If you are building or owning an autonomous agent product, Fleet Security is
the part of Clawdstrike that helps you run that product safely without turning
it into a manual approval treadmill.

## What You Get

- A stable identity for each endpoint agent, runtime, delegated agent, and operator
- Policy and posture controls that follow the fleet instead of living in ad hoc prompts
- A shared event trail for what the fleet did, why it was allowed, and what changed
- A response path for containing a bad agent without shutting down the whole system
- Evidence you can hand to security, compliance, or customers when something matters

## Typical User Journey

1. Enroll agent endpoints or runtimes into a tenant.
2. Assign a baseline posture and attach policy for the team, project, or fleet.
3. Let agents work under bounded capability and approval rules.
4. Review detections, hunts, or cases only when the platform says something is off.
5. Export signed evidence when you need to explain or prove what happened.

## The Mental Model

Think of Clawdstrike as three things working together:

- a directory for agents and operators
- an EDR-style activity and response layer
- a hunt and investigation surface for multi-agent behavior

That matters because agent systems fail differently than normal SaaS systems.
They spawn subagents, switch contexts, borrow human intent, and touch tools
instead of just logging in. Fleet Security gives you a control plane that can
follow those transitions.

## What Changes for Your Team

Without Fleet Security, teams usually end up with prompt-level guardrails,
partial audit logs, and manual incident response.

With Fleet Security, the operating model becomes clearer:

- builders define what an agent should be allowed to do
- operators decide what posture the fleet should be in right now
- reviewers can see the activity, detections, and evidence in one place

## What to Read Next

- Read [Rollout](rollout.md) if you are preparing an initial deployment.
- Read [Identity, Policy, and Posture](directory-and-policy.md) if you need to decide how to segment a fleet.
- Read [Evidence and Attestation](evidence-attestation.md) if auditability is the main driver.
