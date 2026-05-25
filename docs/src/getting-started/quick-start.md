# Quick Start

Evaluate actions against policies in a few minutes.

## Step 1: Install

```bash
cargo install --path crates/services/hush-cli
```

## Step 2: Pick a ruleset

List the built-ins:

```bash
clawdstrike policy list
```

Inspect one:

```bash
clawdstrike policy show ai-agent
```

## Step 3: Run checks

### File access

```bash
# Allowed example (depends on your local paths)
clawdstrike check --action-type file --ruleset default ./README.md

# Blocked example
clawdstrike check --action-type file --ruleset strict ~/.ssh/id_rsa
```

### Network egress

```bash
# Allowed in default ruleset
clawdstrike check --action-type egress --ruleset default api.github.com:443

# Blocked in strict ruleset (strict defaults to deny)
clawdstrike check --action-type egress --ruleset strict api.github.com:443
```

## Step 4: Create a policy file

Policies configure built-in guards under `guards.*` and can inherit via `extends`.

Create `policy.yaml`:

```yaml
version: "1.5.0"
name: My Policy
extends: clawdstrike:ai-agent

guards:
  egress_allowlist:
    additional_allow:
      - "api.stripe.com"
```

Validate (and optionally resolve `extends`):

```bash
clawdstrike policy validate policy.yaml
clawdstrike policy validate --resolve policy.yaml
```

Run checks using the file:

```bash
clawdstrike check --action-type egress --policy policy.yaml api.stripe.com:443
```

## Step 5: Observe -> Synth -> Tighten (recommended)

Use observed real activity to generate and tighten least-privilege policy:

```bash
# Observe one representative run
clawdstrike policy observe --out run.events.jsonl -- your-agent-command

# Synthesize candidate policy
clawdstrike policy synth run.events.jsonl \
  --extends clawdstrike:default \
  --out candidate.yaml \
  --risk-out candidate.risks.md

# Validate and replay against observed events
clawdstrike policy validate candidate.yaml
clawdstrike policy simulate candidate.yaml run.events.jsonl --fail-on-deny
```

`PolicyLab` examples below require package versions that expose PolicyLab bindings.

TypeScript SDK automation (real SDK calls, no subprocess wrapper):

```typescript
import { readFileSync, writeFileSync } from "node:fs";
import { PolicyLab } from "@clawdstrike/sdk";

const eventsJsonl = readFileSync("run.events.jsonl", "utf8");

const synth = await PolicyLab.synth(eventsJsonl);
writeFileSync("candidate.yaml", synth.policyYaml);
writeFileSync("candidate.risks.md", synth.risks.map((risk) => `- ${risk}`).join("\n") + "\n");
writeFileSync("run.ocsf.jsonl", await PolicyLab.toOcsf(eventsJsonl));

await PolicyLab.create(synth.policyYaml);
console.log("candidate.yaml validated");
```

`PolicyLab.simulate()` is not available in TypeScript WASM. Use Python, Go, Rust, or CLI for replay simulation.

Python SDK automation (real SDK calls, no subprocess wrapper):

```python
from pathlib import Path
from clawdstrike import PolicyLab

events_jsonl = Path("run.events.jsonl").read_text(encoding="utf-8")

synth = PolicyLab.synth(events_jsonl)
policy_yaml = synth["policy_yaml"]
Path("candidate.yaml").write_text(policy_yaml, encoding="utf-8")
Path("candidate.risks.md").write_text(
    "".join(f"- {risk}\n" for risk in synth["risks"]),
    encoding="utf-8",
)
Path("run.ocsf.jsonl").write_text(PolicyLab.to_ocsf(events_jsonl), encoding="utf-8")

lab = PolicyLab(policy_yaml)  # validates policy structure
simulation = lab.simulate(events_jsonl)
blocked = simulation["summary"]["blocked"]
if blocked > 0:
    raise SystemExit(f"tightening needed: blocked={blocked}")
```

For the full end-to-end flow (including hunt analysis and OCSF export), see [Observe -> Synth -> Tighten](../guides/observe-synth.md).

## Notes

- `clawdstrike check` evaluates a single action; it does not sandbox or wrap a process.
- For integration into an agent runtime, call the Rust API (`clawdstrike::HushEngine`) before performing actions.

## Next Steps

- [Your First Policy](./first-policy.md)
- [Policy Schema](../reference/policy-schema.md)
- [CLI Reference](../reference/api/cli.md)
