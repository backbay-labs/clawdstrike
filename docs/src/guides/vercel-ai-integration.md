# Vercel AI SDK Integration

Integrate Clawdstrike with the Vercel AI SDK for secure streaming AI applications.

## Installation

```bash
npm install @clawdstrike/vercel-ai ai
```

## Overview

The `@clawdstrike/vercel-ai` package provides:

- **Middleware** — Intercept and guard tool calls
- **React Hooks** — Stream-safe tool guards for UI
- **Secure Tool Wrappers** — Wrap tools with policy enforcement
- **Error Handling** — Typed security errors

## Basic Middleware

Add Clawdstrike as middleware to your AI calls:

```typescript
import { streamText } from "ai";
import { openai } from "@ai-sdk/openai";
import { createClawdstrikeMiddleware } from "@clawdstrike/vercel-ai";

const middleware = createClawdstrikeMiddleware({
  ruleset: "ai-agent",
  onViolation: (violation) => {
    console.warn("Security violation:", violation);
  },
});

export async function POST(req: Request) {
  const { messages } = await req.json();

  const result = await streamText({
    model: openai("gpt-4"),
    messages,
    experimental_toolCallStreaming: true,
    middleware,
  });

  return result.toAIStreamResponse();
}
```

## Secure Tool Definitions

Wrap your tools with security enforcement:

```typescript
import { tool } from "ai";
import { z } from "zod";
import { secureTool } from "@clawdstrike/vercel-ai";

// Define a tool
const readFileTool = tool({
  description: "Read a file from the filesystem",
  parameters: z.object({
    path: z.string().describe("Path to the file"),
  }),
  execute: async ({ path }) => {
    const content = await fs.readFile(path, "utf-8");
    return content;
  },
});

// Wrap with security
const secureReadFile = secureTool(readFileTool, {
  guardType: "file_access",
  ruleset: "strict",
});

// Use in your AI call
const result = await generateText({
  model: openai("gpt-4"),
  tools: { readFile: secureReadFile },
  prompt: "Read the config file",
});
```

## React Integration

Use the `useSecureChat` hook for client-side streaming with security:

```tsx
"use client";

import { useSecureChat } from "@clawdstrike/vercel-ai/react";

export function Chat() {
  const { messages, input, handleInputChange, handleSubmit, securityStatus } =
    useSecureChat({
      api: "/api/chat",
      onSecurityViolation: (violation) => {
        toast.error(`Blocked: ${violation.reason}`);
      },
    });

  return (
    <div>
      {securityStatus.blocked && (
        <div className="alert alert-warning">
          Security policy blocked a tool call
        </div>
      )}

      <div className="messages">
        {messages.map((m) => (
          <div key={m.id} className={m.role}>
            {m.content}
          </div>
        ))}
      </div>

      <form onSubmit={handleSubmit}>
        <input value={input} onChange={handleInputChange} />
        <button type="submit">Send</button>
      </form>
    </div>
  );
}
```

## Streaming Tool Guards

Guard tool calls during streaming:

```typescript
import { streamText } from "ai";
import { ClawdstrikeStreamGuard } from "@clawdstrike/vercel-ai";

const guard = new ClawdstrikeStreamGuard({
  ruleset: "ai-agent",
  onToolCallStart: (toolCall) => {
    console.log(`Tool starting: ${toolCall.name}`);
  },
  onToolCallBlocked: (toolCall, violation) => {
    console.error(`Tool blocked: ${toolCall.name}`, violation);
  },
});

const result = await streamText({
  model: openai("gpt-4"),
  messages,
  tools: myTools,
  onToolCall: guard.createHandler(),
});
```

## Jailbreak Detection in Chat

Add jailbreak detection to user input:

```typescript
import { createClawdstrikeMiddleware } from "@clawdstrike/vercel-ai";

const middleware = createClawdstrikeMiddleware({
  ruleset: "ai-agent",
  jailbreakDetection: {
    enabled: true,
    blockThreshold: 70,
    warnThreshold: 30,
    sessionAggregation: true,
  },
  onJailbreakDetected: (result) => {
    console.warn("Jailbreak attempt:", result.severity, result.signals);
  },
});
```

## Output Sanitization

Sanitize LLM output before sending to clients:

```typescript
import { streamText } from "ai";
import { createSanitizingTransform } from "@clawdstrike/vercel-ai";

const result = await streamText({
  model: openai("gpt-4"),
  messages,
});

// Wrap the stream with sanitization
const sanitizedStream = result.textStream.pipeThrough(
  createSanitizingTransform({
    categories: { secrets: true, pii: true },
    onRedaction: (finding) => {
      console.log(`Redacted: ${finding.type}`);
    },
  })
);
```

## Full Example: Secure Chat API

```typescript
// app/api/chat/route.ts
import { streamText } from "ai";
import { openai } from "@ai-sdk/openai";
import {
  createClawdstrikeMiddleware,
  secureTool,
  createSanitizingTransform,
} from "@clawdstrike/vercel-ai";
import { tool } from "ai";
import { z } from "zod";

// Secure tools
const tools = {
  readFile: secureTool(
    tool({
      description: "Read a file",
      parameters: z.object({ path: z.string() }),
      execute: async ({ path }) => fs.readFile(path, "utf-8"),
    }),
    { guardType: "file_access" }
  ),

  fetchUrl: secureTool(
    tool({
      description: "Fetch a URL",
      parameters: z.object({ url: z.string() }),
      execute: async ({ url }) => {
        const res = await fetch(url);
        return res.text();
      },
    }),
    { guardType: "network_egress" }
  ),
};

// Middleware
const middleware = createClawdstrikeMiddleware({
  ruleset: "ai-agent",
  jailbreakDetection: { enabled: true },
  signing: { enabled: true },
});

export async function POST(req: Request) {
  const { messages, sessionId } = await req.json();

  const result = await streamText({
    model: openai("gpt-4"),
    messages,
    tools,
    middleware,
    experimental_toolCallStreaming: true,
  });

  // Sanitize output
  const sanitizedStream = result.textStream.pipeThrough(
    createSanitizingTransform({
      categories: { secrets: true, pii: true },
    })
  );

  return new Response(sanitizedStream, {
    headers: { "Content-Type": "text/event-stream" },
  });
}
```

## Configuration Options

### Middleware Options

```typescript
interface ClawdstrikeMiddlewareOptions {
  // Policy configuration
  ruleset?: "default" | "strict" | "ai-agent" | "cicd" | "permissive";
  policyFile?: string;
  policy?: PolicyConfig;

  // Jailbreak detection
  jailbreakDetection?: {
    enabled: boolean;
    blockThreshold?: number;
    warnThreshold?: number;
    sessionAggregation?: boolean;
  };

  // Output sanitization
  outputSanitization?: {
    enabled: boolean;
    categories?: { secrets?: boolean; pii?: boolean };
  };

  // Signing
  signing?: {
    enabled: boolean;
    keyPair?: { privateKey: string; publicKey: string };
  };

  // Callbacks
  onViolation?: (violation: SecurityViolation) => void;
  onJailbreakDetected?: (result: JailbreakDetectionResult) => void;
  onRedaction?: (finding: SensitiveDataFinding) => void;
}
```

### Secure Tool Options

```typescript
interface SecureToolOptions {
  guardType: "file_access" | "file_write" | "network_egress" | "mcp_tool";
  ruleset?: string;
  onBlocked?: (violation: SecurityViolation) => void;
  failOpen?: boolean; // Default: false (fail closed)
}
```

## Error Handling

```typescript
import {
  SecurityViolationError,
  JailbreakDetectedError,
} from "@clawdstrike/vercel-ai";

try {
  const result = await streamText({
    model: openai("gpt-4"),
    messages,
    middleware,
  });
} catch (error) {
  if (error instanceof SecurityViolationError) {
    return new Response(
      JSON.stringify({
        error: "security_violation",
        violations: error.violations,
      }),
      { status: 403 }
    );
  }

  if (error instanceof JailbreakDetectedError) {
    return new Response(
      JSON.stringify({
        error: "jailbreak_detected",
        severity: error.result.severity,
      }),
      { status: 400 }
    );
  }

  throw error;
}
```

## Next Steps

- [LangChain Integration](./langchain-integration.md) — Use with LangChain
- [Custom Guards](./custom-guards.md) — Create your own guards
- [Output Sanitizer Reference](../reference/guards/output-sanitizer.md) — Full sanitizer docs
