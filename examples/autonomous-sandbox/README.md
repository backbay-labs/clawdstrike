# Autonomous Sandbox (Example)

This example demonstrates the **IRM sandbox wrapper** in `clawdstrike`:

- It does **not** provide OS isolation (containers/cgroups/VMs).
- It evaluates *host-call intents* (filesystem/network/exec) against a policy and emits events.

## Run

```bash
cd examples/autonomous-sandbox
cargo run
```

