# Rollout

Fleet Security works best when teams treat rollout as a control-plane adoption
problem, not just an agent binary deployment problem.

## What You Roll Out

- the control API and control console for tenant-scoped fleet management
- endpoint agents that represent user-facing or workstation-style agent surfaces
- runtime integrations that represent container, cluster, or service execution
- hunt and evidence infrastructure so investigations do not depend on local logs

## Suggested Rollout Sequence

1. Start with one tenant and one bounded fleet.
2. Enroll endpoints and runtimes before you try to automate response.
3. Put the fleet in an observable baseline posture first.
4. Attach policy and approval rules after identities and telemetry are stable.
5. Add response actions only after the team is comfortable with detection quality.

## What "Done" Looks Like

- Every meaningful agent surface has an identity in the platform.
- Operators can see posture, liveness, and recent activity in one place.
- Detections can be turned into cases and evidence without manual data gathering.
- The team can quarantine or revoke a compromised identity without stopping the whole fleet.

## Common Mistakes

- Treating runtime rollout and endpoint rollout as separate products
- Skipping identity hygiene and going straight to alerting
- Shipping policy without first confirming who or what it will attach to
- Waiting until an incident to test evidence export

## Related Guides

- [Enterprise Enrollment](../guides/enterprise-enrollment.md)
- [Desktop Agent Deployment](../guides/desktop-agent.md)
- [Adaptive Deployment](../guides/adaptive-deployment.md)
