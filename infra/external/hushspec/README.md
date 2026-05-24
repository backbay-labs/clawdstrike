# hushspec

Portable specification types for AI agent security rules.

`hushspec` is the Rust reference implementation of the [HushSpec](https://github.com/backbay-labs/hush) open policy format. It provides parsing, validation, evaluation, resolution, detection, signing, and audit trail capabilities for HushSpec policy documents.

## Installation

```toml
[dependencies]
hushspec = "0.1"
```

Optional features:

```toml
# Ed25519 policy signing and verification
hushspec = { version = "0.1", features = ["signing"] }

# HTTPS-based extends resolution
hushspec = { version = "0.1", features = ["http"] }
```

## Quick Start

```rust
use hushspec::{HushSpec, validate, evaluate, EvaluationAction};

// Parse a policy
let yaml = r#"
hushspec: "0.1.0"
name: my-policy
rules:
  egress:
    allow: ["api.github.com"]
    block: []
    default: block
"#;
let spec = HushSpec::parse(yaml)?;

// Validate
let result = validate(&spec);
assert!(result.is_valid());

// Evaluate an action
let action = EvaluationAction {
    action_type: "egress".into(),
    target: Some("api.github.com".into()),
    ..Default::default()
};
let decision = evaluate(&spec, &action);
assert_eq!(decision.decision, hushspec::Decision::Allow);
```

## Core API

| Module | Purpose |
|--------|---------|
| `schema` | Parse and serialize HushSpec YAML/JSON documents |
| `validate` | Structural validation with typed errors and warnings |
| `evaluate` | Evaluate actions against policies (allow/warn/deny) |
| `resolve` | Resolve `extends` chains from filesystem, HTTP, or builtins |
| `merge` | Merge child policies into base policies |
| `conditions` | Conditional rule evaluation (time windows, runtime context) |
| `detection` | Prompt injection, jailbreak, and exfiltration detection |
| `receipt` | Structured audit trail with decision receipts |
| `sink` | Receipt sinks (file, stderr, callback, filtered, multi) |
| `panic` | Emergency deny-all kill switch |
| `signing` | Ed25519 policy signing and verification (feature-gated) |
| `governance` | Governance metadata validation |

## Fail-Closed Design

HushSpec follows a fail-closed philosophy:

- Unknown YAML/JSON fields are rejected at parse time (`deny_unknown_fields`)
- Invalid documents produce typed `ValidationError` values
- Ambiguous or unrecognized rules result in `Deny`
- All regex patterns are validated at parse time

## CLI

The `h2h` CLI tool is available as a separate crate:

```bash
cargo install hushspec-cli
```

See [`hushspec-cli`](https://crates.io/crates/hushspec-cli) for details.

## License

Apache-2.0
