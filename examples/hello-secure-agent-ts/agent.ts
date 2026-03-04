/**
 * hello-secure-agent-ts
 *
 * Demonstrates Clawdstrike policy enforcement with the OpenAI Agents SDK
 * tool shape. Run with --dry-run to see allow/deny decisions without an
 * OpenAI API key.
 *
 * Usage:
 *   npx tsx agent.ts --dry-run
 */

import { Clawdstrike, type Decision } from "@clawdstrike/sdk";
import * as fs from "node:fs";
import * as path from "node:path";

// ---------------------------------------------------------------------------
// Parse flags
// ---------------------------------------------------------------------------

const dryRun = process.argv.includes("--dry-run");

// ---------------------------------------------------------------------------
// Load policy and create session
// ---------------------------------------------------------------------------

const policyPath = path.resolve(import.meta.dirname ?? ".", "policy.yaml");
const cs = await Clawdstrike.fromPolicy(policyPath);
const session = cs.session({ agentId: "hello-secure-agent" });

// ---------------------------------------------------------------------------
// Define tools with inline security checks
// (Same shape as OpenAI Agents SDK function tools)
// ---------------------------------------------------------------------------

const tools = {
  read_file: {
    execute: async (input: { path: string }): Promise<string> => {
      const decision = await session.checkFile(input.path, "read");
      if (decision.status === "deny") {
        return `BLOCKED by ${decision.guard}: ${decision.message}`;
      }
      return fs.readFileSync(input.path, "utf-8");
    },
  },

  write_file: {
    execute: async (input: { path: string; content: string }): Promise<string> => {
      const decision = await session.checkFile(input.path, "write");
      if (decision.status === "deny") {
        return `BLOCKED by ${decision.guard}: ${decision.message}`;
      }
      fs.writeFileSync(input.path, input.content, "utf-8");
      return `Wrote ${input.content.length} bytes to ${input.path}`;
    },
  },

  fetch_url: {
    execute: async (input: { url: string }): Promise<string> => {
      const decision = await session.checkNetwork(input.url);
      if (decision.status === "deny") {
        return `BLOCKED by ${decision.guard}: ${decision.message}`;
      }
      const resp = await fetch(input.url);
      return (await resp.text()).slice(0, 500);
    },
  },
};

// ---------------------------------------------------------------------------
// Dry-run scenarios
// ---------------------------------------------------------------------------

const scenarios = [
  { label: "Read allowed file", fn: () => tools.read_file.execute({ path: "/tmp/workspace/notes.txt" }) },
  { label: "Read /etc/shadow", fn: () => tools.read_file.execute({ path: "/etc/shadow" }) },
  { label: "Write to /tmp/workspace/out.txt", fn: () => tools.write_file.execute({ path: "/tmp/workspace/out.txt", content: "agent output" }) },
  { label: "Write to ~/.ssh/evil_key", fn: () => tools.write_file.execute({ path: `${process.env.HOME}/.ssh/evil_key`, content: "hacked" }) },
  { label: "Fetch api.openai.com", fn: () => tools.fetch_url.execute({ url: "https://api.openai.com" }) },
  { label: "Fetch evil.com", fn: () => tools.fetch_url.execute({ url: "https://evil.com" }) },
];

async function runDryRun(): Promise<void> {
  console.log("=== Clawdstrike Security Demo (dry-run) ===\n");

  // Ensure the sandbox directory and test file exist
  fs.mkdirSync("/tmp/workspace", { recursive: true });
  fs.writeFileSync("/tmp/workspace/notes.txt", "Hello from the secure agent!\n");

  for (const { label, fn } of scenarios) {
    console.log(`Scenario: ${label}`);
    try {
      const result = await fn();
      const firstLine = result.split("\n")[0]?.slice(0, 80) ?? "";
      console.log(`  Result: ${firstLine}\n`);
    } catch (err) {
      console.log(`  Error: ${(err as Error).message}\n`);
    }
  }

  // Print session summary
  const summary = session.getSummary();
  console.log("=== Session Summary ===");
  console.log(`  Session ID:      ${summary.sessionId}`);
  console.log(`  Total checks:    ${summary.checkCount}`);
  console.log(`  Allowed:         ${summary.allowCount}`);
  console.log(`  Warnings:        ${summary.warnCount}`);
  console.log(`  Denied:          ${summary.denyCount}`);
  if (summary.blockedActions.length > 0) {
    console.log(`  Blocked actions: ${summary.blockedActions.join(", ")}`);
  }
}

async function runAgent(): Promise<void> {
  console.log("Agent mode requires an OPENAI_API_KEY. Use --dry-run to demo policy checks.");
  console.log("In a real integration you would pass these tools to the OpenAI Agents SDK.\n");
  await runDryRun();
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

if (dryRun) {
  await runDryRun();
} else {
  await runAgent();
}
