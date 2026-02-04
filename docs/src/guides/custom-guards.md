# Custom Guards (advanced)

Clawdstrike guards are plain Rust types that implement `clawdstrike::guards::Guard`.

## Implementing a guard

```rust,ignore
use async_trait::async_trait;
use clawdstrike::guards::{Guard, GuardAction, GuardContext, GuardResult};

pub struct AlwaysWarn;

#[async_trait]
impl Guard for AlwaysWarn {
    fn name(&self) -> &str {
        "always_warn"
    }

    fn handles(&self, _action: &GuardAction<'_>) -> bool {
        true
    }

    async fn check(&self, _action: &GuardAction<'_>, _ctx: &GuardContext) -> GuardResult {
        GuardResult::warn(self.name(), "this is a warning")
    }
}
```

## Using a custom guard today

`HushEngine` supports registering extra guards programmatically.

Extra guards run **after** the built-in guard set (built-ins first, extras last).

```rust,ignore
use clawdstrike::{HushEngine, Policy};

let policy = Policy::from_yaml_file("policy.yaml")?;
let engine = HushEngine::with_policy(policy).with_extra_guard(Box::new(AlwaysWarn));
```

`guards.custom[]` supports a small reserved set of built-in threat-intel guards (see [Threat Intel Guards](threat-intel.md)). Dynamic plugin loading/marketplaces are still planned work.
