# Enforcement Tiers & Integration Contract

Clawdstrike enforces policy at the boundary between model intent and real side effects (filesystem, network, exec, and tool calls).
It does **not** automatically intercept syscalls or sandbox arbitrary code.

This page defines:

- **Enforcement tiers**: what you can and cannot claim in production.
- **Integration contract**: what your runtime/adapter must do to make enforcement real.

## Enforcement tiers

### Tier 0: Checks + receipts (attestation only)

You evaluate actions against policy (and optionally sign receipts), but you do not block execution.

You can claim:

- "Under policy X, Clawdstrike evaluated action Y and returned verdict Z."

You cannot claim:

- "The OS prevented the side effect."

### Tier 1: Tool-boundary enforcement (in-process)

Your runtime enforces decisions by mediating side effects:

- **Preflight**: call Clawdstrike before the side effect and block/modify when denied.
- **Post-action**: sanitize/redact outputs, and block persistence/logging when required.

You can claim:

- "Side effects performed through the mediated tool layer are enforced by policy."

You must assume bypass is possible if:

- Any code path can touch the filesystem/network without going through the same tool layer.

### Tier 2: Brokered tools (recommended for untrusted code execution)

You run agent-generated code in a restricted worker that cannot directly access host I/O.
All side effects go through a separate broker that exposes a small set of tools and calls Clawdstrike.

You can claim:

- "Untrusted code cannot route around the policy broker, because it has no ambient OS capabilities."

### Tier 3: OS-level isolation (containers / microVMs / sandboxes)

You add a real OS boundary (namespaces, seccomp/landlock, gVisor, Firecracker, etc.):

- Minimal mounts (workspace only)
- No host secrets mounted
- Egress blocked by default, opened only when explicitly allowed

This complements Tier 1/2. Clawdstrike remains the policy brain; the OS sandbox is the hard boundary.

## Integration contract

To get Tier 1 or better, your integration must satisfy all of these:

1. Centralize side effects into a small tool surface:
   - File read/write/delete/list
   - Network egress (HTTP/TCP)
   - Process spawn / shell
   - Patch apply (before writing)
   - MCP/framework tool dispatch
2. Check immediately before the side effect:
   - Avoid "decide now, act later" gaps.
   - Normalize inputs (absolute paths, resolve `..`, handle symlinks consistently).
   - For network, check the actual `host:port` that will be dialed (not just a URL string).
3. Fail closed on ambiguity:
   - If policy can't be loaded/validated, deny.
   - Treat general `exec`/`shell` as a privileged tool class; prefer narrower tools when possible.
4. Treat post-action hooks as output controls, not undo:
   - Post-action checks can redact/block persistence of results.
   - They cannot undo a side effect that already happened (for example, a request already sent).

## Where `clawdstrike run` fits

`clawdstrike run` / `hush run` is a best-effort process wrapper:

- Audit log + signed receipt over run artifacts
- Optional CONNECT proxy egress enforcement (when the child respects proxy environment variables)
- Optional OS wrapper (`sandbox-exec` on macOS, `bwrap` on Linux when available)

It is not equivalent to a full sandbox. For hard guarantees, combine it with an OS-level sandbox (Tier 3) or brokered tools (Tier 2).

## Minimal tool wrapper pattern (TypeScript)

The only enforceable point is the code that performs the side effect. The pattern is:

1. Preflight check
2. Execute tool (only if allowed)
3. Post-process output

```ts
const pre = await interceptor.beforeExecute(toolName, input, ctx);
if (!pre.proceed) throw new Error(pre.decision.message ?? 'Blocked by policy');

const output = await realDispatch(toolName, pre.modifiedParameters ?? input, runId);
const post = await interceptor.afterExecute(toolName, input, output, ctx);
return post.output;
```

