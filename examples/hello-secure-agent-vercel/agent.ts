/**
 * hello-secure-agent-vercel
 *
 * Demonstrates Clawdstrike policy enforcement with the Vercel AI SDK.
 * Shows how to protect tool calls in a Vercel AI generateText() loop.
 *
 * Usage:
 *   npx tsx agent.ts --dry-run   # No API key needed
 *   npx tsx agent.ts             # Requires OPENAI_API_KEY
 */

import { Clawdstrike } from "@clawdstrike/sdk";
import * as fs from "node:fs";
import * as path from "node:path";

const dryRun = process.argv.includes("--dry-run");

// ---------------------------------------------------------------------------
// 1. Load policy and create a session for audit tracking
// ---------------------------------------------------------------------------

const policyPath = path.resolve(import.meta.dirname ?? ".", "policy.yaml");
const cs = await Clawdstrike.fromPolicy(policyPath);
const session = cs.session({ agentId: "hello-secure-agent-vercel" });

// ---------------------------------------------------------------------------
// 2. Define tools with Clawdstrike guards
//    Each tool checks the policy before executing. In a real Vercel AI app
//    these would be passed to generateText({ tools: { ... } }).
// ---------------------------------------------------------------------------

const tools = {
  read_file: {
    description: "Read a file from disk",
    parameters: { type: "object", properties: { path: { type: "string" } }, required: ["path"] },
    execute: async ({ path: filePath }: { path: string }): Promise<string> => {
      const decision = await session.checkFile(filePath, "read");
      if (decision.status === "deny") {
        return `BLOCKED by ${decision.guard}: ${decision.message}`;
      }
      return fs.readFileSync(filePath, "utf-8");
    },
  },

  write_file: {
    description: "Write content to a file",
    parameters: { type: "object", properties: { path: { type: "string" }, content: { type: "string" } }, required: ["path", "content"] },
    execute: async ({ path: filePath, content }: { path: string; content: string }): Promise<string> => {
      const decision = await session.checkFile(filePath, "write");
      if (decision.status === "deny") {
        return `BLOCKED by ${decision.guard}: ${decision.message}`;
      }
      fs.writeFileSync(filePath, content, "utf-8");
      return `Wrote ${content.length} bytes to ${filePath}`;
    },
  },

  fetch_url: {
    description: "Fetch a URL",
    parameters: { type: "object", properties: { url: { type: "string" } }, required: ["url"] },
    execute: async ({ url }: { url: string }): Promise<string> => {
      const decision = await session.checkNetwork(url);
      if (decision.status === "deny") {
        return `BLOCKED by ${decision.guard}: ${decision.message}`;
      }
      const res = await fetch(url);
      return (await res.text()).slice(0, 500);
    },
  },
};

// ---------------------------------------------------------------------------
// 3. Dry-run scenarios
// ---------------------------------------------------------------------------

const scenarios = [
  { name: "Read allowed file (/tmp/workspace/notes.txt)", fn: () => tools.read_file.execute({ path: "/tmp/workspace/notes.txt" }) },
  { name: "Read blocked file (/etc/shadow)", fn: () => tools.read_file.execute({ path: "/etc/shadow" }) },
  { name: "Write to workspace", fn: () => tools.write_file.execute({ path: "/tmp/workspace/out.txt", content: "agent output" }) },
  { name: "Write to ~/.ssh/evil_key", fn: () => tools.write_file.execute({ path: `${process.env.HOME}/.ssh/evil_key`, content: "hacked" }) },
  { name: "Fetch allowed domain (api.openai.com)", fn: () => tools.fetch_url.execute({ url: "https://api.openai.com" }) },
  { name: "Fetch blocked domain (evil.com)", fn: () => tools.fetch_url.execute({ url: "https://evil.com" }) },
];

if (dryRun) {
  console.log("=== Clawdstrike + Vercel AI Demo (dry-run) ===\n");

  // Set up sandbox
  fs.mkdirSync("/tmp/workspace", { recursive: true });
  fs.writeFileSync("/tmp/workspace/notes.txt", "Hello from the secure agent!");

  for (const { name, fn } of scenarios) {
    console.log(`Scenario: ${name}`);
    try {
      const result = await fn();
      const preview = String(result).split("\n")[0]?.slice(0, 80) ?? "";
      console.log(`  Result: ${preview}\n`);
    } catch (err) {
      console.log(`  Error: ${(err as Error).message}\n`);
    }
  }

  // Session summary
  const summary = session.getSummary();
  console.log("=== Session Summary ===");
  console.log(`  Total checks:    ${summary.checkCount}`);
  console.log(`  Allowed:         ${summary.allowCount}`);
  console.log(`  Denied:          ${summary.denyCount}`);
  if (summary.blockedActions.length > 0) {
    console.log(`  Blocked actions: ${summary.blockedActions.join(", ")}`);
  }
} else {
  // -------------------------------------------------------------------------
  // Full agent mode with Vercel AI SDK
  // Requires OPENAI_API_KEY in the environment.
  // -------------------------------------------------------------------------
  const { generateText, tool } = await import("ai");
  const { openai } = await import("@ai-sdk/openai");
  const { z } = await import("zod");

  // Set up sandbox
  fs.mkdirSync("/tmp/workspace", { recursive: true });
  fs.writeFileSync("/tmp/workspace/notes.txt", "Hello from the secure agent!");

  const result = await generateText({
    model: openai("gpt-4o-mini"),
    tools: {
      read_file: tool({
        description: "Read a file from disk",
        parameters: z.object({ path: z.string() }),
        execute: tools.read_file.execute,
      }),
      write_file: tool({
        description: "Write content to a file",
        parameters: z.object({ path: z.string(), content: z.string() }),
        execute: tools.write_file.execute,
      }),
      fetch_url: tool({
        description: "Fetch a URL and return its content",
        parameters: z.object({ url: z.string() }),
        execute: tools.fetch_url.execute,
      }),
    },
    maxSteps: 5,
    prompt: "Read the file /tmp/workspace/notes.txt and tell me what it says. Then try to read /etc/shadow and tell me what happens.",
  });

  console.log("Agent response:", result.text);

  // Session summary
  const summary = session.getSummary();
  console.log(`\n=== Session Summary ===`);
  console.log(`  Total checks:    ${summary.checkCount}`);
  console.log(`  Allowed:         ${summary.allowCount}`);
  console.log(`  Denied:          ${summary.denyCount}`);
  if (summary.blockedActions.length > 0) {
    console.log(`  Blocked actions: ${summary.blockedActions.join(", ")}`);
  }
}
