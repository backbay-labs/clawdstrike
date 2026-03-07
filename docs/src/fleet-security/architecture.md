# Target Architecture

Fleet Security has six major planes. You can think of them as one operator
system with six jobs rather than six separate products.

## 1. Identity Plane

The identity plane answers:

- what this agent or runtime is
- which tenant it belongs to
- what stable reference and key material it presents
- what lifecycle and liveness state it is currently in

This is the foundation for the rest of the system. If identity is wrong,
policy, detections, and response attribution all degrade.

## 2. Policy and Posture Plane

This plane decides what a principal is allowed to do and what posture the fleet
should be operating in right now.

In practice, that means:

- attached policy and inherited rules
- posture transitions such as normal, restricted, observe-only, or quarantined
- grants and delegated authority for multi-agent workflows

## 3. Telemetry Plane

The telemetry plane collects activity from the places agent systems actually
operate:

- endpoint agent activity
- runtime and cluster activity
- network and process signals
- policy and response events

The goal is not just raw logging. The goal is a normalized fleet event stream
that supports investigation and response.

## 4. Detection and Hunt Plane

This plane turns telemetry into operator signal.

- detections produce findings
- hunts answer open questions across the fleet
- saved hunts and correlation jobs make recurring investigations repeatable

## 5. Response Plane

This plane records and executes containment actions.

Today the most important response actions are posture changes, policy reloads,
kill switch paths, grant revocation, and principal quarantine.

## 6. Evidence Plane

This plane turns events, cases, and artifacts into something durable and
portable.

- cases keep investigation state together
- evidence bundles preserve relevant artifacts
- signed manifests make those bundles auditable outside the live system

## How the Planes Work Together

1. A principal enrolls and receives an identity.
2. Policy and posture determine what it can do.
3. Activity is emitted into the telemetry plane.
4. Detections and hunts turn that into operator signal.
5. Response actions contain or correct the problem.
6. Cases and evidence preserve the story of what happened.
