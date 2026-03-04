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

## Policy-driven custom guards (`custom_guards[]`)

Custom guards can also be declared in the policy YAML at the top level using the `custom_guards` array. Each entry is a `PolicyCustomGuardSpec`:

```yaml
custom_guards:
  - id: "my_custom_guard"
    enabled: true
    config:
      threshold: 0.8
      mode: strict
```

### PolicyCustomGuardSpec fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `id` | string | (required) | Installed guard id, resolved via `CustomGuardRegistry`. |
| `enabled` | bool | `true` | Enable/disable this custom guard. |
| `config` | JSON object | `{}` | Factory configuration passed to the guard constructor. |

## Plugin-shaped guards (`guards.custom[]`)

The `guards.custom[]` array supports plugin-shaped guard references with package resolution:

```yaml
guards:
  custom:
    - package: "@clawdstrike/guard-threat-intel"
      version: "^1.0.0"
      enabled: true
      config:
        feed_url: "https://feeds.example.com/indicators.json"
```

### CustomGuardSpec fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `package` | string | (required) | Package identifier for the guard. |
| `registry` | string or null | `null` | Optional registry URL for resolution. |
| `version` | string or null | `null` | Optional semver constraint. |
| `enabled` | bool | `true` | Enable/disable this guard. |
| `config` | JSON object | `{}` | Configuration passed to the guard factory. |
| `async` | object or null | `null` | Optional async guard policy config (rate limiting, retries, timeouts). |

`guards.custom[]` supports a reserved set of built-in threat-intel guards (see [Threat Intel Guards](threat-intel.md)) plus manifest-based plugin loading. Use `clawdstrike guard inspect` and `clawdstrike guard validate` (or the `hush` alias) to verify plugin metadata/compatibility, and use `executionMode: wasm` for sandboxed plugin execution paths.
