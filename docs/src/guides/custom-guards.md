# Custom Guards

Extend hushclaw with your own security checks.

## Overview

Guards are modular security checks. You can implement custom guards to:

- Add domain-specific security rules
- Integrate with external systems
- Enforce company policies

## Guard Trait

Implement the `Guard` trait:

```rust
use async_trait::async_trait;
use hushclaw::{Guard, GuardResult, Event, Policy, Severity};

pub struct MyCustomGuard {
    // Your state here
}

#[async_trait]
impl Guard for MyCustomGuard {
    fn name(&self) -> &str {
        "MyCustomGuard"
    }

    fn handles(&self) -> &[EventType] {
        // Return event types this guard handles
        // Empty = handles all events
        &[EventType::FileWrite, EventType::ToolCall]
    }

    async fn check(&self, event: &Event, policy: &Policy) -> GuardResult {
        // Your logic here
        if self.is_dangerous(event) {
            GuardResult::Deny {
                reason: "Custom check failed".into(),
                severity: Severity::High,
            }
        } else {
            GuardResult::Allow
        }
    }
}
```

## Example: Rate Limit Guard

```rust
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

pub struct RateLimitGuard {
    requests: AtomicUsize,
    limit: usize,
    window_start: Instant,
    window_duration: Duration,
}

impl RateLimitGuard {
    pub fn new(limit: usize, window: Duration) -> Self {
        Self {
            requests: AtomicUsize::new(0),
            limit,
            window_start: Instant::now(),
            window_duration: window,
        }
    }
}

#[async_trait]
impl Guard for RateLimitGuard {
    fn name(&self) -> &str {
        "RateLimitGuard"
    }

    async fn check(&self, _event: &Event, _policy: &Policy) -> GuardResult {
        // Reset counter if window expired
        if self.window_start.elapsed() > self.window_duration {
            self.requests.store(0, Ordering::Relaxed);
        }

        let count = self.requests.fetch_add(1, Ordering::Relaxed);
        if count >= self.limit {
            GuardResult::Deny {
                reason: format!(
                    "Rate limit exceeded: {} requests in {:?}",
                    count, self.window_duration
                ),
                severity: Severity::Medium,
            }
        } else {
            GuardResult::Allow
        }
    }
}
```

## Example: Business Hours Guard

```rust
use chrono::{Local, Timelike, Weekday, Datelike};

pub struct BusinessHoursGuard {
    start_hour: u32,
    end_hour: u32,
}

#[async_trait]
impl Guard for BusinessHoursGuard {
    fn name(&self) -> &str {
        "BusinessHoursGuard"
    }

    async fn check(&self, _event: &Event, _policy: &Policy) -> GuardResult {
        let now = Local::now();
        let hour = now.hour();
        let weekday = now.weekday();

        // Block on weekends
        if weekday == Weekday::Sat || weekday == Weekday::Sun {
            return GuardResult::Deny {
                reason: "Operations not allowed on weekends".into(),
                severity: Severity::Low,
            };
        }

        // Block outside business hours
        if hour < self.start_hour || hour >= self.end_hour {
            return GuardResult::Deny {
                reason: format!(
                    "Operations only allowed between {}:00 and {}:00",
                    self.start_hour, self.end_hour
                ),
                severity: Severity::Low,
            };
        }

        GuardResult::Allow
    }
}
```

## Registering Guards

Add your guard to the registry:

```rust
use hushclaw::{HushEngineBuilder, GuardRegistry};
use std::sync::Arc;

// Create registry with defaults
let mut registry = GuardRegistry::with_defaults();

// Add your custom guards
registry.register(Arc::new(RateLimitGuard::new(100, Duration::from_secs(60))));
registry.register(Arc::new(BusinessHoursGuard {
    start_hour: 9,
    end_hour: 17,
}));

// Build engine with custom guards
let engine = HushEngineBuilder::new()
    .with_policy(policy)
    .with_guards(registry)
    .build()?;
```

## Guard Best Practices

### 1. Be Specific About Events

Only handle events you care about:

```rust
fn handles(&self) -> &[EventType] {
    &[EventType::NetworkEgress]  // Only network events
}
```

### 2. Use Appropriate Severity

- `Low` - Informational, not security-critical
- `Medium` - Worth investigating
- `High` - Likely dangerous
- `Critical` - Definitely dangerous

### 3. Provide Helpful Messages

```rust
GuardResult::Deny {
    reason: format!(
        "Request to {} blocked: rate limit of {} per minute exceeded",
        host, self.limit
    ),
    severity: Severity::Medium,
}
```

### 4. Avoid Blocking I/O

Guards should be fast. For external checks, use async:

```rust
async fn check(&self, event: &Event, _policy: &Policy) -> GuardResult {
    // Async calls are OK
    let allowed = self.external_service.check(event).await?;
    // ...
}
```

### 5. Test Your Guards

```rust
#[tokio::test]
async fn test_rate_limit_guard() {
    let guard = RateLimitGuard::new(2, Duration::from_secs(60));
    let policy = Policy::default();
    let event = Event::mock_file_read("test.txt");

    // First two should pass
    assert!(guard.check(&event, &policy).await.is_allow());
    assert!(guard.check(&event, &policy).await.is_allow());

    // Third should fail
    assert!(guard.check(&event, &policy).await.is_deny());
}
```

## Policy-Aware Guards

Read configuration from policy:

```rust
async fn check(&self, event: &Event, policy: &Policy) -> GuardResult {
    // Get custom config from policy
    if let Some(config) = policy.custom.get("my_guard") {
        let threshold = config.get("threshold")
            .and_then(|v| v.as_u64())
            .unwrap_or(100);
        // Use threshold...
    }
    GuardResult::Allow
}
```

Policy YAML:

```yaml
custom:
  my_guard:
    threshold: 50
```

## Next Steps

- [Guards Reference](../reference/guards/README.md) - Built-in guard details
- [Policy Inheritance](./policy-inheritance.md) - Configure guard behavior
- [Audit Logging](./audit-logging.md) - Log guard decisions
