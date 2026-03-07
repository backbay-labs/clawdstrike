# Autonomous Fleet Security

Clawdstrike is the security control plane for autonomous agent fleets. It gives
teams one place to enroll agents, assign policy, watch activity, investigate
findings, contain bad behavior, and export signed evidence.

This section is intentionally written for people using and operating the
platform. The older internal specs, migration notes, and implementation plans
have been removed from the published book so the section stays focused on what
Fleet Security is, how it works, and how to run it.

## What This Section Covers

- How teams roll Fleet Security out to agent endpoints and runtimes
- How operators reason about identity, policy, posture, and trust
- How detections, hunts, response actions, cases, and evidence fit together
- What the major moving pieces are without dropping into internal API design

## Reading Paths

If you are evaluating or adopting the platform as a product user, start here:

1. [For Users](for-users.md)
2. [Rollout](rollout.md)
3. [Identity, Policy, and Posture](directory-and-policy.md)
4. [Evidence and Attestation](evidence-attestation.md)

If you are operating the platform day to day, start here:

1. [Operator Guide](operator-guide.md)
2. [Detection, Hunt, and Response](detection-response.md)
3. [Evidence and Attestation](evidence-attestation.md)
4. [Target Architecture](architecture.md)

## Related Docs

- For connected-agent deployment details, see [Enterprise Enrollment](../guides/enterprise-enrollment.md).
- For desktop agent rollout details, see [Desktop Agent Deployment](../guides/desktop-agent.md).
- For adaptive deployment modes, see [Adaptive Deployment](../guides/adaptive-deployment.md).
- For the hunt CLI and workflow details, see [Hunt Overview](../hunt/index.md).
