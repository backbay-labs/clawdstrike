# Quick Start (TypeScript)

Get Clawdstrike running in your TypeScript/Node.js project in under 5 minutes.

## Installation

```bash
npm install @clawdstrike/sdk
# or
yarn add @clawdstrike/sdk
# or
pnpm add @clawdstrike/sdk
```

## Basic Usage

### Check File Access

```typescript
import { HushEngine, GuardContext } from "@clawdstrike/sdk";

const engine = new HushEngine();
const ctx = new GuardContext();

// Check if a file access is allowed
const result = await engine.checkFileAccess("/home/user/.ssh/id_rsa", ctx);

if (!result.allowed) {
  console.log("Access denied:", result.violations);
} else {
  console.log("Access allowed");
}
```

### Check Network Egress

```typescript
const result = await engine.checkEgress("api.openai.com", 443, ctx);

if (result.allowed) {
  // Proceed with network request
  const response = await fetch("https://api.openai.com/v1/chat/completions");
}
```

### Check MCP Tool Invocation

```typescript
const result = await engine.checkMcpTool("shell_exec", { command: "ls -la" }, ctx);

if (!result.allowed) {
  throw new Error(`Tool blocked: ${result.violations[0].reason}`);
}
```

## Using Rulesets

Load a pre-configured ruleset instead of the default:

```typescript
const engine = new HushEngine({
  ruleset: "strict",  // or "ai-agent", "cicd", "permissive"
});
```

## Custom Policy

Load a custom policy file:

```typescript
const engine = await HushEngine.fromPolicyFile("./my-policy.yaml");
```

Or define inline:

```typescript
const engine = new HushEngine({
  policy: {
    version: "1.0.0",
    name: "My Custom Policy",
    extends: "clawdstrike:default",
    guards: {
      egress_allowlist: {
        additional_allow: ["api.mycompany.com"],
      },
    },
  },
});
```

## Jailbreak Detection

Detect jailbreak attempts in user input:

```typescript
import { JailbreakDetector } from "@clawdstrike/sdk";

const detector = new JailbreakDetector({
  blockThreshold: 70,
  warnThreshold: 30,
  sessionAggregation: true,
});

const sessionId = "user-123-session-456";

async function handleUserMessage(message: string) {
  const result = await detector.detect(message, sessionId);

  if (result.blocked) {
    console.warn(`Jailbreak detected: ${result.severity}`);
    console.warn(`Signals: ${result.signals.map(s => s.id).join(", ")}`);
    return "I can't process that request.";
  }

  if (result.riskScore >= 30) {
    console.log(`Suspicious input (score: ${result.riskScore})`);
  }

  // Proceed with LLM call
  return await callLLM(message);
}
```

## Output Sanitization

Redact secrets and PII from LLM output:

```typescript
import { OutputSanitizer } from "@clawdstrike/sdk";

const sanitizer = new OutputSanitizer({
  categories: { secrets: true, pii: true },
  redactionStrategies: {
    secret: "full",
    pii: "partial",
  },
});

async function processLLMResponse(response: string) {
  const result = await sanitizer.sanitize(response);

  if (result.wasRedacted) {
    console.log(`Redacted ${result.findings.length} sensitive items`);
  }

  return result.sanitized;
}
```

## Signed Receipts

Create tamper-evident records of your checks:

```typescript
import { HushEngine, sha256 } from "@clawdstrike/sdk";

// Engine with signing enabled
const engine = new HushEngine({
  signing: { enabled: true },
});

// Run your checks
const result = await engine.checkFileAccess("/app/config.json", ctx);

// Create a signed receipt
const contentHash = sha256(JSON.stringify(result));
const receipt = await engine.createSignedReceipt(contentHash);

// Save for audit
await saveReceipt(receipt);

// Later: verify the receipt
import { verifyReceipt } from "@clawdstrike/sdk";

const isValid = verifyReceipt(receipt, engine.getPublicKey());
console.log(`Receipt valid: ${isValid}`);
```

## With Context

Provide execution context for better policy decisions:

```typescript
const ctx = new GuardContext({
  cwd: "/app/workspace",
  sessionId: "session-123",
  agentId: "coding-assistant",
  metadata: {
    userId: "user-456",
    environment: "production",
  },
});

const result = await engine.checkFileAccess("./src/index.ts", ctx);
```

## Streaming Output Sanitization

For real-time LLM streaming:

```typescript
import { OutputSanitizer } from "@clawdstrike/sdk";

const sanitizer = new OutputSanitizer();
const stream = sanitizer.createStream();

async function* sanitizeStream(llmStream: AsyncIterable<string>) {
  for await (const chunk of llmStream) {
    const safeChunk = stream.write(chunk);
    if (safeChunk) {
      yield safeChunk;
    }
  }

  // Flush remaining buffer
  const final = stream.flush();
  if (final) {
    yield final;
  }

  // Log any findings
  const findings = stream.getFindings();
  if (findings.length > 0) {
    console.log(`Sanitized ${findings.length} sensitive items`);
  }
}
```

## Error Handling

```typescript
import { PolicyValidationError, GuardError } from "@clawdstrike/sdk";

try {
  const engine = await HushEngine.fromPolicyFile("./policy.yaml");
} catch (error) {
  if (error instanceof PolicyValidationError) {
    console.error("Invalid policy:", error.validationErrors);
  }
  throw error;
}

try {
  const result = await engine.checkFileAccess(path, ctx);
} catch (error) {
  if (error instanceof GuardError) {
    // Guard evaluation failed - fail closed
    console.error("Guard error, denying access:", error.message);
    return { allowed: false };
  }
  throw error;
}
```

## Next Steps

- [OpenClaw Integration](../guides/openclaw-integration.md) — Integrate with OpenClaw
- [Vercel AI Integration](../guides/vercel-ai-integration.md) — Use with Vercel AI SDK
- [Custom Guards](../guides/custom-guards.md) — Create your own guards
- [Policy Schema](../reference/policy-schema.md) — Full policy reference
