# Autonomous Fleet Security

This section is the working documentation spine for framing Clawdstrike as an
EDR x directory-grade control plane x threat-hunting platform for autonomous
agent fleets.

It is intentionally forward-looking. Some components described here already
exist in the repository, some exist only as partial building blocks, and some
are still design targets.

## Scope

The goal is not to restate the entire Clawdstrike product surface. The goal is
to define the architecture needed for these three platform claims to be true at
the same time:

- Fleet EDR for agent endpoints, runtimes, and tool-boundary activity
- Directory-grade identity, policy inheritance, and lifecycle control
- Threat hunting, investigation, and response across multi-agent systems

## Reading Order

If you are starting fresh, use this sequence:

1. [Platform Framing](positioning.md)
2. [Current State](current-state.md)
3. [Target Architecture](architecture.md)
4. [Directory and Policy Plane](directory-and-policy.md)
5. [Directory Object Model Spec](directory-object-model.md)
6. [Effective Policy Resolution Spec](effective-policy-resolution.md)
7. [Principal Lifecycle Spec](principal-lifecycle.md)
8. [Directory API Contract Spec](directory-api-contract.md)
9. [Enrollment and Join Protocol Spec](enrollment-join-protocol.md)
10. [Grants and Delegation Graph Contract Spec](grants-delegation-graph.md)
11. [Directory Implementation Plan](directory-implementation.md)
12. [Directory Migration Plan](directory-migrations.md)
13. [Detection, Hunt, and Response](detection-response.md)
14. [Response Action Contract Spec](response-action-contract.md)
15. [Response Execution Pipeline Spec](response-execution-pipeline.md)
16. [Normalized Fleet Event Envelope Spec](normalized-fleet-event-envelope.md)
17. [Hunt Backend API and Data Model Spec](hunt-backend.md)
18. [Detection and Rule Model Spec](detection-rule-model.md)
19. [Suppression and Tuning Model Spec](suppression-tuning-model.md)
20. [Case and Evidence Bundle Model Spec](case-evidence-bundle-model.md)
21. [Rule Packaging and Distribution Model Spec](rule-packaging-distribution.md)
22. [Detection API Contract Spec](detection-api-contract.md)
23. [Detection Storage Model Spec](detection-storage-model.md)
24. [Fleet Console Read Model Spec](fleet-console-read-model.md)
25. [Code and Artifact Map](code-map.md)
26. [Delivery Roadmap](roadmap.md)
27. [Multi-Agent Execution Overview](execution-orchestration.md)
28. [Workstream Map](workstream-map.md)
29. [Dependency and Merge Graph](dependency-graph.md)
30. [Verification Matrix](verification-matrix.md)
31. [Codex CLI Orchestration Playbook](codex-cli-playbook.md)
32. [Agent Brief Pack](agent-briefs.md)
33. [Codex Swarm Pack](codex-swarm-pack.md)

## Relationship to Existing Docs

This section builds on existing documentation rather than replacing it.

- For current deployment modes, see [Adaptive Architecture](../concepts/adaptive-architecture.md).
- For enterprise bootstrap and connected-agent flows, see [Enterprise Enrollment](../guides/enterprise-enrollment.md).
- For the current threat-hunting subsystem, see [Hunt Overview](../hunt/index.md) and [Hunt Architecture](../hunt/architecture.md).
- For the broad product roadmap, see [Implementation Roadmap](../roadmap.md).

## Expected Outputs

This documentation track is meant to produce:

- A stable architecture vocabulary for the fleet platform
- A clear current-state inventory tied to code and artifacts
- A target system design for identity, policy, telemetry, hunt, and response
- Harder specs for the most important control-plane and investigation contracts
- Protocol-level specs for effective policy, principal state, and directory APIs
- A phased plan that can be implemented incrementally without losing product coherence

## Document Status

Second pass. The architecture and protocol docs are now detailed enough to
support implementation planning, parallel workstream assignment, and Codex CLI
orchestration. The remaining gap is code execution rather than documentation
shape.
