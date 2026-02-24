# Demo Script: Securing Agent Swarms

**Talk title:** Securing Agent Swarms  
**Demo duration:** ~12 minutes inside a longer talk  
**Setup:** Two terminal tabs. Tab 1 runs the demo. Tab 2 is for code/policy. Font size 18+. Dark theme.

"The scary part of swarms isn't that one agent can do damage. It's that one agent can teach the others how to do damage."

---

## Pre-Demo Setup (before you go on stage)

Primary demo (swarm infection):

```bash
cd examples/swarm-infection

# Pick a port that won't collide with other local daemons.
export HUSHD_PORT=19876

# Pre-build so the demo is instant.
cargo build -p hushd --bin hushd --manifest-path ../../Cargo.toml
npm install

# Pre-build required adapter packages.
for d in adapter-core hushd-engine openai; do
  (cd ../../packages/adapters/clawdstrike-$d && npm run build)
done

# Dry-run to make sure everything works.
./run.sh

clear
```

Fallback demo (multi-framework red/blue swarm), only if needed:

```bash
cd ../red-blue-swarm
./run.sh
clear
```

---

## Act 1: The Problem (2 min) - slides/talking, no terminal

> "In a single-agent app, the failure mode is obvious: the agent makes one bad tool call.
>
> In a swarm, the failure mode is quieter and more dangerous:
> **one compromised agent can infect the shared context, and now every downstream agent becomes an amplifier.**
>
> It doesn't take a malicious model.
> It takes one untrusted document. One poisoned memory entry. One agent that gets steered off-course.
>
> Most stacks focus on tools. But swarms have two attack surfaces:
>
> 1. The **tool boundary**: what can execute.
> 2. The **memory boundary**: what can be trusted and shared.
>
> So here's the question I care about:
> **Can we stop lateral movement inside the swarm, and still get real-time attribution of who tried what?**
>
> In the next few minutes I'll run a small orchestrated swarm twice:
> first naive, then hardened.
> You'll watch the same attack land in shared context, spread, and then get contained."

---

## Act 2: The Architecture (1 min) - show diagram

Switch to terminal tab 2. Show this diagram (or a slide):

```
            Orchestrator / Conductor
        (handoffs + shared blackboard)
                      |
          +-----------+-----------+
          |                       |
  Memory boundary (ingestion)     Tool boundary (execution)
  /api/v1/eval: Custom(untrusted_text)   @clawdstrike/openai tool dispatcher
          |                       |
          +-----------+-----------+
                      |
                    hushd
           (policy engine + audit + SSE)
                      |
              Blue team SSE view
```

> "This is what makes the story real:
>
> The orchestrator is doing what every Agents SDK orchestrator does: handoffs plus shared context.
> The difference is we add two choke points:
>
> - A **memory boundary**: untrusted text gets evaluated before it's written into shared context.
> - A **tool boundary**: every tool call gets evaluated before execution.
>
> hushd sits in the middle as the enforcement point, and every decision streams out over SSE for attribution."

---

## Act 3: The Policy (1 min) - keep it boring on purpose

**[SHOW POLICY]** In terminal tab 2:

```bash
sed -n '/forbidden_path:/,/egress_allowlist:/p' ../../rulesets/strict.yaml
sed -n '/prompt_injection:/,/jailbreak:/p' ../../rulesets/strict.yaml
```

> "Two things I want you to notice:
>
> **Forbidden paths**: anything that looks like credentials or keys is off-limits.
>
> And the one that's swarm-specific:
> **prompt injection is evaluated on untrusted text at ingestion.**
> That is the difference between a swarm that is merely 'blocked' and a swarm that is actually 'contained'."

---

## Act 4: The Two Boundaries (2 min) - show the choke points

**[SHOW CODE]** In terminal tab 2:

```bash
rg -n "evalUntrustedText|customType: 'untrusted_text'|prompt" index.ts
rg -n "OpenAIToolBoundary|wrapOpenAIToolDispatcher|createSecurityContext" index.ts
```

> "These are the only two places you need to be strict:
>
> 1. When untrusted text is about to become shared memory.
> 2. When an agent is about to execute a tool.
>
> Everything else is just orchestration.
>
> Watch the behavior difference between naive and hardened. Same swarm. Same poison. One extra boundary."

Optional credibility anchor (10 seconds, only if useful):

```bash
sed -n '1,120p' ../../packages/adapters/clawdstrike-openai/README.md
```

---

## Act 5: Run It (3 min) - the main event

**[SWITCH TO TERMINAL TAB 1]**

```bash
cd examples/swarm-infection
./run.sh
```

Narration guide:

### Phase A: Naive (ingestion boundary OFF)

> "First run: naive swarm.
> The compromised agent gets one shot at shared context."

Callouts as it scrolls:

> "It writes the poison into the blackboard. No ingestion scan, so it lands.
>
> Now the key moment: a *benign* agent builds a plan from that shared memory.
> And the runner attempts two actions it would never attempt on its own:
> reading an SSH key and a download-and-exec commandline."

> "Notice two things:
> - The tool boundary blocks execution.
> - The blue team stream attributes the violation to the *agent that attempted the tool call*.
>
> That's how lateral movement looks in production: the compromised cell causes other cells to trip alarms."

### Phase B: Hardened (ingestion boundary ON)

> "Second run: same attack, but now we add the memory boundary."

Callouts:

> "The untrusted_text scan fires. prompt_injection blocks the write.
> The poison never lands, so the plan is clean, and the runner stays boring.
>
> Same tool boundary, but now the swarm is quiet because the infection didn't spread."

When the blue summary table prints:

> "That's the containment story:
> Phase A: blocks, but noisy.
> Phase B: contained, and calm.
>
> It takes one compromised agent to infect a swarm.
> It takes one boundary to stop the infection."

---

## Act 6: The Takeaway (1 min) - slides/talking

> "Three takeaways:
>
> **One: tool boundaries prevent execution.**
> That's necessary, but it's not sufficient for swarms.
>
> **Two: memory boundaries prevent contagion.**
> Treat shared context like a data plane. Put a perimeter around it.
>
> **Three: attribution in real time is how you isolate the compromised cell.**
> Blocking is good. Knowing which agent tried what is incident response."

---

## Contingency Plans

### If hushd fails to start

Port might be in use. Run `HUSHD_PORT=19876 ./run.sh` (or pick a new port).

If it still fails, `./run.sh` will print which process is holding the port so you can stop it.

### If npm install fails

Run `npm install` manually, then:

```bash
HUSHD_URL=http://127.0.0.1:$HUSHD_PORT npx tsx index.ts
```

### If the swarm-infection demo flakes

Use the fallback demo:

```bash
cd examples/red-blue-swarm
./run.sh
```

### If the audience asks "what if the agent bypasses the adapter?"

> "That's the architecture: keep privileges behind one choke point.
>
> If tool access only exists behind the boundary, the model cannot bypass it because it doesn't have raw filesystem/network privileges.
> It can only propose actions, and policy decides what executes."

### If someone asks about performance

> "There is no model call in the enforcement path. These are deterministic checks.
> Locally it's fast. Remotely you pay a network hop because you get audit and streaming in return."

---

## Timing Guide

| Section         | Duration | What's on screen                     |
| --------------- | -------- | ------------------------------------ |
| The Problem     | 2:00     | Slides                               |
| Architecture    | 1:00     | Diagram                              |
| Policy excerpt  | 1:00     | `rulesets/strict.yaml` in terminal   |
| Two boundaries  | 2:00     | `examples/swarm-infection/index.ts`  |
| Run the demo    | 3:00     | Terminal output (live)               |
| Takeaway        | 1:00     | Slides                               |
| Total           | ~10:00   |                                      |

Buffer: 2 minutes for transitions and questions.

---

## Terminal Layout

- **Tab 1 (main):** where you run `./run.sh` (keep clean; clear before demo)
- **Tab 2 (secondary):** policy/code viewing (pretype the `sed`/`rg` commands)

Font size 18-20pt. Dark background. Disable terminal bell.
