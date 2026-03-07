# Operator Guide

This is the day-two view of Fleet Security: what an operator or security team
actually does with it after agents are enrolled and producing signal.

## Core Jobs

- keep the fleet in the right posture for the current risk level
- watch detections and hunt results across endpoints, runtimes, sessions, and principals
- contain bad behavior quickly without losing the surrounding context
- preserve evidence for review, escalation, or compliance

## Recommended Operating Loop

1. Watch the fleet overview for posture, liveness, and active findings.
2. Triage detections into benign, actionable, or case-worthy events.
3. Pivot into hunt timelines and graph views when behavior spans multiple agents.
4. Apply the smallest response action that actually contains the issue.
5. Open or update a case when the investigation needs a durable record.
6. Export evidence when the incident needs external review or sign-off.

## What Operators Should Care About First

### Identity

If the operator cannot answer "which agent was this and what trust did it have
at the time," everything downstream gets weaker.

### Posture

Posture is the fastest way to change how much power the fleet has right now.
Use it to move from normal operation into tighter controls without redeploying
every agent.

### Cases

A case is where detections, response actions, graph pivots, notes, and evidence
start to become an investigation instead of a pile of events.

## Good Defaults

- Keep new fleets in a more observable posture before tightening to production norms.
- Prefer revoking a grant or quarantining a principal over broad kill switches when possible.
- Use saved hunts for recurring questions, not one-off incidents.
- Treat evidence export as part of incident closure, not as an afterthought.

## What to Read Next

- Read [Detection, Hunt, and Response](detection-response.md) for the investigation workflow.
- Read [Evidence and Attestation](evidence-attestation.md) for signed bundle behavior.
- Read [Target Architecture](architecture.md) if you need a system view of the moving parts.
