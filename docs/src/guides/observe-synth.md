# Guide: Observe -> Synth -> Tighten

Use observation to generate a least-privilege starting policy.

## 1. Observe activity

Local command mode:

```bash
hush policy observe --out run.events.jsonl -- your-agent-command --arg value
```

hushd session mode:

```bash
hush policy observe \
  --hushd-url http://127.0.0.1:9876 \
  --session <session_id> \
  --out session.events.jsonl
```

## 2. Synthesize a candidate policy

```bash
hush policy synth run.events.jsonl \
  --extends clawdstrike:default \
  --out candidate.yaml \
  --diff-out candidate.diff.json \
  --risk-out candidate.risks.md \
  --with-posture
```

Outputs:

- `candidate.yaml`: synthesized overlay policy
- `candidate.diff.json`: structural diff vs base policy
- `candidate.risks.md`: review checklist and risk notes

See `examples/policies/synthesized-example.yaml` for a representative output shape.

## 3. Validate and simulate

```bash
hush policy validate candidate.yaml
hush policy simulate candidate.yaml run.events.jsonl --json --track-posture
```

## 4. Tighten manually

Synthesis is intentionally conservative, but still a starting point. Review and tighten:

- filesystem allowlists
- egress host lists
- posture capabilities and budgets
- transition semantics
