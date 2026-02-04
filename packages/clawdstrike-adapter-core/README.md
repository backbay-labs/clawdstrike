# @clawdstrike/adapter-core

Framework-agnostic adapter interfaces for Clawdstrike tool-boundary enforcement.

## Installation

```bash
npm install @clawdstrike/adapter-core
```

## Usage

```ts
import { BaseToolInterceptor, createSecurityContext } from "@clawdstrike/adapter-core";

// Create an engine for policy evaluation (implementation-specific).
// For example, use @clawdstrike/hush-cli-engine to shell out to `hush`.
const engine = /* ... */;

const interceptor = new BaseToolInterceptor(engine, { blockOnViolation: true });
const ctx = createSecurityContext({ sessionId: "session-123" });

const preflight = await interceptor.beforeExecute("bash", { cmd: "echo hello" }, ctx);
if (!preflight.proceed) throw new Error("Blocked by policy");
```
