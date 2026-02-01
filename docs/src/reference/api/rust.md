# Rust API

Native Rust library for hushclaw.

## Crates

| Crate | Purpose |
|-------|---------|
| `hushclaw` | Runtime enforcement (guards, policy) |
| `hush-core` | Crypto primitives (signing, hashing) |
| `hush-proxy` | Network interception utilities |

## Installation

```toml
[dependencies]
hushclaw = "0.1"
hush-core = "0.1"
```

## Quick Start

```rust
use hushclaw::{HushEngine, HushEngineBuilder, Policy, Event, Decision};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load policy
    let policy = Policy::from_yaml_file("policy.yaml")?;

    // Build engine
    let engine = HushEngineBuilder::new()
        .with_policy(policy)
        .build()?;

    // Create event
    let event = Event::file_read("~/.ssh/id_rsa");

    // Evaluate
    let decision = engine.evaluate(&event).await;

    match decision {
        Decision::Allow => println!("Allowed"),
        Decision::Warn { message, .. } => println!("Warning: {}", message),
        Decision::Deny { reason, .. } => println!("Denied: {}", reason),
    }

    Ok(())
}
```

## HushEngine

### Builder

```rust
let engine = HushEngineBuilder::new()
    .with_policy(policy)
    .with_guards(custom_guards)
    .with_mode(EvaluationMode::Deterministic)
    .with_cache(CacheConfig::default())
    .build()?;
```

### Evaluation

```rust
// Async evaluation (with I/O)
let decision = engine.evaluate(&event).await;

// Sync evaluation (cached)
let decision = engine.evaluate_sync(&event);

// Batch evaluation
let decisions = engine.evaluate_batch(&events).await;
```

### Policy Management

```rust
// Load policy
engine.load_policy(new_policy)?;

// Hot reload
engine.reload_policy(updated_policy)?;

// Get current policy
let policy = engine.current_policy();
```

## Event Types

```rust
use hushclaw::{Event, EventType, EventData};

// File read
let event = Event {
    event_id: uuid::Uuid::new_v4().to_string(),
    event_type: EventType::FileRead,
    timestamp: chrono::Utc::now(),
    session_id: None,
    data: EventData::File(FileEventData {
        path: "~/.ssh/id_rsa".into(),
        content_hash: None,
    }),
    metadata: HashMap::new(),
};

// Convenience constructors
let event = Event::file_read("path/to/file");
let event = Event::file_write("path/to/file");
let event = Event::network_egress("api.github.com", 443);
let event = Event::tool_call("write_file", params);
```

## Decision Types

```rust
use hushclaw::{Decision, Severity};

match decision {
    Decision::Allow => {
        // Proceed
    }
    Decision::Warn { message, guard } => {
        println!("Warning from {:?}: {}", guard, message);
        // Proceed with logging
    }
    Decision::Deny { reason, guard, severity } => {
        println!("Denied by {}: {} ({:?})", guard, reason, severity);
        // Block operation
    }
}

// Helper methods
decision.is_allowed()  // true for Allow and Warn
decision.is_denied()   // true for Deny
decision.severity()    // Option<Severity>
```

## Custom Guards

```rust
use async_trait::async_trait;
use hushclaw::{Guard, GuardResult, Event, Policy, Severity};

pub struct MyGuard;

#[async_trait]
impl Guard for MyGuard {
    fn name(&self) -> &str {
        "MyGuard"
    }

    fn handles(&self) -> &[EventType] {
        &[EventType::FileWrite]
    }

    async fn check(&self, event: &Event, policy: &Policy) -> GuardResult {
        // Your logic
        GuardResult::Allow
    }
}

// Register
let mut registry = GuardRegistry::with_defaults();
registry.register(Arc::new(MyGuard));
```

## Crypto (hush-core)

```rust
use hush_core::{Keypair, sign, verify, sha256_hex, MerkleTree};

// Generate keypair
let keypair = Keypair::generate();

// Sign data
let signature = keypair.sign(b"data");

// Verify
let valid = keypair.public_key().verify(b"data", &signature);

// Hash
let hash = sha256_hex(b"data");

// Merkle tree
let tree = MerkleTree::from_leaves(&hashes);
let proof = tree.prove(index);
let valid = tree.verify(&hash, &proof);
```

## Error Handling

```rust
use hushclaw::{Error, PolicyError};

match engine.load_policy(policy) {
    Ok(_) => println!("Policy loaded"),
    Err(Error::Policy(PolicyError::Parse(e))) => {
        println!("Parse error: {}", e);
    }
    Err(Error::Policy(PolicyError::Validation(e))) => {
        println!("Validation error: {}", e);
    }
    Err(e) => println!("Other error: {}", e),
}
```

## Feature Flags

```toml
[dependencies]
hushclaw = { version = "0.1", features = ["all-guards"] }
```

| Feature | Description |
|---------|-------------|
| `default` | Local runner only |
| `all-guards` | All built-in guards |
| `wasm-runner` | WASM sandbox runner |
| `serde` | Serialization support |

## Examples

See [Rust examples](https://github.com/hushclaw/hushclaw/tree/main/examples/rust).
