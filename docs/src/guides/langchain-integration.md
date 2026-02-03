# LangChain Integration

Integrate Clawdstrike with LangChain for secure agent applications.

## Installation

```bash
npm install @clawdstrike/langchain langchain
# or
pip install clawdstrike-langchain langchain
```

## Overview

The `@clawdstrike/langchain` package provides:

- **Tool Wrappers** — Wrap LangChain tools with policy enforcement
- **Chain Callbacks** — Monitor and guard chain execution
- **Agent Interceptors** — Guard agent actions before execution
- **Retriever Guards** — Secure RAG pipelines

## TypeScript

### Secure Tool Wrapper

Wrap any LangChain tool with security enforcement:

```typescript
import { ClawdstrikeToolWrapper } from "@clawdstrike/langchain";
import { ReadFileTool } from "langchain/tools";

const readFile = new ReadFileTool();

const secureReadFile = new ClawdstrikeToolWrapper(readFile, {
  ruleset: "ai-agent",
  guardType: "file_access",
  onBlocked: (violation) => {
    console.warn(`Tool blocked: ${violation.reason}`);
  },
});

// Use in your agent
const agent = createReactAgent({
  llm: model,
  tools: [secureReadFile],
});
```

### Agent Interceptor

Add security to the entire agent execution:

```typescript
import { ClawdstrikeAgentInterceptor } from "@clawdstrike/langchain";

const interceptor = new ClawdstrikeAgentInterceptor({
  ruleset: "strict",
  jailbreakDetection: {
    enabled: true,
    blockThreshold: 70,
  },
  outputSanitization: {
    enabled: true,
    categories: { secrets: true, pii: true },
  },
});

const agent = createReactAgent({
  llm: model,
  tools: secureTools,
});

// Wrap agent execution
const secureAgent = interceptor.wrap(agent);

const result = await secureAgent.invoke({
  input: userMessage,
  sessionId: "session-123",
});
```

### Chain Callbacks

Monitor chain execution with security callbacks:

```typescript
import { ClawdstrikeCallbackHandler } from "@clawdstrike/langchain";

const callbacks = [
  new ClawdstrikeCallbackHandler({
    ruleset: "ai-agent",
    onToolStart: (tool, input) => {
      console.log(`Tool starting: ${tool.name}`);
    },
    onToolBlocked: (tool, violation) => {
      console.error(`Tool blocked: ${tool.name}`, violation);
    },
    onChainEnd: (receipt) => {
      // Save signed receipt for audit
      saveReceipt(receipt);
    },
  }),
];

const result = await chain.invoke(
  { input: userMessage },
  { callbacks }
);
```

### Secure All Tools

Wrap all tools in one call:

```typescript
import { secureAllTools } from "@clawdstrike/langchain";

const tools = [
  new ReadFileTool(),
  new WriteFileTool(),
  new ShellTool(),
  new RequestsTool(),
];

const secureTools = secureAllTools(tools, {
  ruleset: "ai-agent",
  mappings: {
    ReadFileTool: { guardType: "file_access" },
    WriteFileTool: { guardType: "file_write" },
    ShellTool: { guardType: "mcp_tool", toolName: "shell_exec" },
    RequestsTool: { guardType: "network_egress" },
  },
});
```

## Python

### Secure Tool Wrapper

```python
from clawdstrike_langchain import ClawdstrikeToolWrapper
from langchain_community.tools import ReadFileTool

read_file = ReadFileTool()

secure_read_file = ClawdstrikeToolWrapper(
    read_file,
    ruleset="ai-agent",
    guard_type="file_access",
    on_blocked=lambda v: print(f"Blocked: {v.reason}")
)

# Use in agent
agent = create_react_agent(llm=model, tools=[secure_read_file])
```

### Agent Interceptor

```python
from clawdstrike_langchain import ClawdstrikeAgentInterceptor

interceptor = ClawdstrikeAgentInterceptor(
    ruleset="strict",
    jailbreak_detection={
        "enabled": True,
        "block_threshold": 70
    },
    output_sanitization={
        "enabled": True,
        "categories": {"secrets": True, "pii": True}
    }
)

agent = create_react_agent(llm=model, tools=secure_tools)
secure_agent = interceptor.wrap(agent)

result = await secure_agent.ainvoke({
    "input": user_message,
    "session_id": "session-123"
})
```

### Chain Callbacks

```python
from clawdstrike_langchain import ClawdstrikeCallbackHandler

callbacks = [
    ClawdstrikeCallbackHandler(
        ruleset="ai-agent",
        on_tool_start=lambda t, i: print(f"Tool: {t.name}"),
        on_tool_blocked=lambda t, v: print(f"Blocked: {t.name}"),
        on_chain_end=lambda r: save_receipt(r)
    )
]

result = await chain.ainvoke(
    {"input": user_message},
    config={"callbacks": callbacks}
)
```

### RAG Pipeline Security

Guard retrieval in RAG pipelines:

```python
from clawdstrike_langchain import SecureRetriever

# Wrap your retriever
secure_retriever = SecureRetriever(
    retriever=vector_store.as_retriever(),
    output_sanitization={
        "enabled": True,
        "categories": {"secrets": True, "pii": True}
    },
    # Don't return documents containing secrets
    filter_sensitive=True
)

# Use in RAG chain
rag_chain = (
    {"context": secure_retriever, "question": RunnablePassthrough()}
    | prompt
    | llm
    | StrOutputParser()
)
```

## LCEL Integration

Use with LangChain Expression Language:

```typescript
import { ClawdstrikeRunnable } from "@clawdstrike/langchain";

const securityGuard = new ClawdstrikeRunnable({
  ruleset: "ai-agent",
  jailbreakDetection: { enabled: true },
});

const chain = securityGuard
  .pipe(prompt)
  .pipe(model)
  .pipe(new ClawdstrikeRunnable({
    outputSanitization: { enabled: true },
  }))
  .pipe(outputParser);

const result = await chain.invoke({ input: userMessage });
```

## Configuration

### Tool Wrapper Options

```typescript
interface ClawdstrikeToolWrapperOptions {
  ruleset?: string;
  policyFile?: string;
  guardType: "file_access" | "file_write" | "network_egress" | "mcp_tool";
  toolName?: string;  // For mcp_tool guard
  onBlocked?: (violation: SecurityViolation) => void;
  failOpen?: boolean;  // Default: false
}
```

### Agent Interceptor Options

```typescript
interface ClawdstrikeAgentInterceptorOptions {
  ruleset?: string;
  policyFile?: string;

  jailbreakDetection?: {
    enabled: boolean;
    blockThreshold?: number;
    warnThreshold?: number;
    sessionAggregation?: boolean;
  };

  outputSanitization?: {
    enabled: boolean;
    categories?: { secrets?: boolean; pii?: boolean };
  };

  signing?: {
    enabled: boolean;
  };

  onViolation?: (violation: SecurityViolation) => void;
  onJailbreakDetected?: (result: JailbreakDetectionResult) => void;
}
```

## Full Example: Secure Agent

```typescript
import { ChatOpenAI } from "@langchain/openai";
import { createReactAgent, AgentExecutor } from "langchain/agents";
import {
  ClawdstrikeAgentInterceptor,
  secureAllTools,
  ClawdstrikeCallbackHandler,
} from "@clawdstrike/langchain";

// Create model
const model = new ChatOpenAI({ model: "gpt-4" });

// Define and secure tools
const tools = [
  new ReadFileTool(),
  new WriteFileTool(),
  new ShellTool(),
];

const secureTools = secureAllTools(tools, {
  ruleset: "strict",
  mappings: {
    ReadFileTool: { guardType: "file_access" },
    WriteFileTool: { guardType: "file_write" },
    ShellTool: { guardType: "mcp_tool", toolName: "shell_exec" },
  },
});

// Create agent
const agent = createReactAgent({
  llm: model,
  tools: secureTools,
});

// Add interceptor
const interceptor = new ClawdstrikeAgentInterceptor({
  ruleset: "strict",
  jailbreakDetection: { enabled: true },
  outputSanitization: { enabled: true },
  signing: { enabled: true },
});

const secureAgent = interceptor.wrap(
  new AgentExecutor({ agent, tools: secureTools })
);

// Run with callbacks
const callbacks = [
  new ClawdstrikeCallbackHandler({
    onChainEnd: (receipt) => saveAuditReceipt(receipt),
  }),
];

const result = await secureAgent.invoke(
  { input: userMessage },
  { callbacks, configurable: { sessionId: "session-123" } }
);
```

## Error Handling

```typescript
import {
  SecurityViolationError,
  JailbreakDetectedError,
} from "@clawdstrike/langchain";

try {
  const result = await secureAgent.invoke({ input: userMessage });
} catch (error) {
  if (error instanceof SecurityViolationError) {
    console.error("Security violation:", error.violations);
    return "Sorry, that action isn't allowed.";
  }

  if (error instanceof JailbreakDetectedError) {
    console.error("Jailbreak detected:", error.result.severity);
    return "I can't process that request.";
  }

  throw error;
}
```

## Next Steps

- [Vercel AI Integration](./vercel-ai-integration.md) — Use with Vercel AI SDK
- [Custom Guards](./custom-guards.md) — Create your own guards
- [Audit Logging](./audit-logging.md) — Set up audit trails
