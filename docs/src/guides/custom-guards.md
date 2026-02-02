# Custom Guards (advanced)

Clawdstrike guards are plain Rust types that implement `clawdstrike::guards::Guard`.

## Implementing a guard

```rust
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

`HushEngine` currently evaluates the built-in guard set. If you want to add custom guards, the supported approach today is to:

1. Run your custom guard alongside `HushEngine::check_action_report`, and
2. Aggregate results in your own runtime layer.

Extending `HushEngine` to support a pluggable guard registry is planned work (see `docs/plans/`).
