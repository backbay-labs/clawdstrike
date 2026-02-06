# @clawdstrike/policy

Canonical policy loader + engine for JavaScript/TypeScript.

This package parses the Clawdstrike policy YAML schema and evaluates canonical `PolicyEvent`s using:

- the built-in async guards (egress, forbidden paths, patch integrity, etc.)
- optional custom guards via `CustomGuardRegistry`
- optional “threat intel” style plugins (see `src/async/` + `src/plugins/`)

## Usage

```ts
import { createPolicyEngineFromPolicy, loadPolicyFromFile } from "@clawdstrike/policy";

const policy = loadPolicyFromFile("./policy.yaml", { resolve: true });
const engine = createPolicyEngineFromPolicy(policy);

const decision = await engine.evaluate({
  eventId: "evt_1",
  eventType: "network_egress",
  timestamp: new Date().toISOString(),
  data: { type: "network", host: "api.github.com", port: 443 },
});

if (decision.status === "deny") throw new Error(decision.message);
```

## Loading and validation

- `loadPolicyFromFile()` / `loadPolicyFromString()` parse YAML into the canonical policy schema.
- `validatePolicy()` returns a lint-style report (`{ valid, errors }`) and is enforced by the engine constructor.

## Remote `extends`

Remote `extends` is intentionally **disabled by default** in the Rust tooling (`hush` / `hushd`).
When enabled, remote references must be **pinned** with `#sha256=<64-hex>` and fetched only from
explicitly allowlisted hosts.

## Relationship to Rust

The Rust implementation (`crates/clawdstrike`) is the reference for schema and behavior. This JS engine
aims to stay in lockstep with the canonical schema and decision semantics; when in doubt, prefer the Rust
engine (or the `@clawdstrike/hushd-engine` adapter) for maximum parity.
