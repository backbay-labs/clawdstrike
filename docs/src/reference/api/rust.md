# Rust API

Native Rust API for policy evaluation and receipt signing.

## Crates

- `clawdstrike`: policy type, built-in guards, and `HushEngine`
- `hush-core`: hashing/signing, Merkle trees, and `SignedReceipt`
- `hush-proxy`: domain matching + DNS/SNI parsing utilities

## Installation

If you depend on a published version, use `0.1.0`. If you are working from a checkout, use a path dependency.

## Quick start: evaluate actions + create a receipt

```rust
use clawdstrike::{GuardContext, HushEngine, Policy};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load a policy file and resolve `extends`
    let policy = Policy::from_yaml_file_with_extends("policy.yaml")?;

    // Engine with a signing keypair for receipts
    let engine = HushEngine::with_policy(policy).with_generated_keypair();
    let ctx = GuardContext::new();

    // Evaluate an action
    let result = engine
        .check_file_access("/home/user/.ssh/id_rsa", &ctx)
        .await?;
    println!("allowed={} severity={:?} msg={}", result.allowed, result.severity, result.message);

    // Create a signed receipt for some artifact hash
    let artifact_hash = hush_core::sha256(b"example artifact");
    let signed = engine.create_signed_receipt(artifact_hash).await?;
    std::fs::write("receipt.json", signed.to_json()?)?;

    Ok(())
}
```

## Getting per-guard evidence

`HushEngine::check_action_report` returns a `GuardReport` with per-guard results and an aggregated verdict:

```rust
use clawdstrike::{guards::GuardAction, GuardContext, HushEngine};

async fn report(engine: &HushEngine) -> anyhow::Result<()> {
    let ctx = GuardContext::new();
    let report = engine
        .check_action_report(&GuardAction::FileAccess("/tmp/test.txt"), &ctx)
        .await?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
```

## Guard API (direct use)

All guards implement `clawdstrike::guards::Guard` and operate over `GuardAction` + `GuardContext`.

```rust
use clawdstrike::guards::{ForbiddenPathGuard, Guard, GuardAction, GuardContext};

async fn check_one() {
    let guard = ForbiddenPathGuard::new();
    let ctx = GuardContext::new();
    let r = guard.check(&GuardAction::FileAccess("/home/user/.ssh/id_rsa"), &ctx).await;
    assert!(!r.allowed);
}
```

## Policy validation (fail closed)

Loading a policy validates glob and regex patterns. Invalid patterns fail policy loading with a structured error (`Error::PolicyValidation`).
