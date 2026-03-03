/**
 * ClawdStrike MCP Server
 *
 * Stdio-based MCP server exposing tools, resources, and prompts that shell
 * out to the `clawdstrike` CLI binary. Each tool builds a CLI arg list,
 * spawns the process, and returns the parsed output.
 */

import { McpServer, ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { homedir } from "node:os";
import { join } from "node:path";
import { readFile } from "node:fs/promises";

import {
  runCli,
  runCliRaw,
  runCliStdin,
  toToolResult,
  healthCheck,
} from "./cli-bridge.ts";

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

const server = new McpServer({
  name: "clawdstrike",
  version: "0.1.0",
});

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

// 1. clawdstrike_check ---------------------------------------------------
server.tool(
  "clawdstrike_check",
  "Check an action against ClawdStrike policy. Returns the enforcement decision (allow/deny) with evidence.",
  {
    action_type: z.string().describe("Action type (e.g. file, network, shell, mcp_tool)"),
    target: z.string().describe("Target of the action (path, URL, command, etc.)"),
    ruleset: z.string().optional().describe("Policy ruleset to evaluate against"),
    content: z.string().optional().describe("Optional content for file-write checks"),
  },
  async ({ action_type, target, ruleset, content }) => {
    const args = ["check", "--action-type", action_type];
    if (ruleset) args.push("--ruleset", ruleset);
    if (content) args.push("--content", content);
    args.push(target);
    return toToolResult(await runCli(args));
  },
);

// 2. clawdstrike_scan -----------------------------------------------------
server.tool(
  "clawdstrike_scan",
  "Scan MCP server configurations for security issues, policy violations, and suspicious tool definitions.",
  {
    targets: z.array(z.string()).optional().describe("Paths to MCP config files or directories to scan"),
    policy: z.string().optional().describe("Policy ruleset to apply during scan"),
  },
  async ({ targets, policy }) => {
    const args = ["hunt", "scan"];
    if (targets?.length) args.push(...targets);
    if (policy) args.push("--policy", policy);
    return toToolResult(await runCli(args));
  },
);

// 3. clawdstrike_query ----------------------------------------------------
server.tool(
  "clawdstrike_query",
  "Search security events by filters. Returns matching events from the audit log.",
  {
    query: z.string().optional().describe("Free-text search query"),
    source: z.string().optional().describe("Event source filter (tetragon, hubble, receipt, spine)"),
    verdict: z.string().optional().describe("Verdict filter (allow, deny, audit)"),
    kind: z.string().optional().describe("Event kind filter (process_exec, file_write, network_connect, etc.)"),
    since: z.string().optional().describe("Start time (ISO 8601 or relative like '1h', '30m')"),
    until: z.string().optional().describe("End time (ISO 8601 or relative)"),
    limit: z.number().optional().describe("Maximum number of results"),
  },
  async ({ query, source, verdict, kind, since, until, limit }) => {
    const args = ["hunt", "query"];
    if (query) args.push(query);
    if (source) args.push("--source", source);
    if (verdict) args.push("--verdict", verdict);
    if (kind) args.push("--kind", kind);
    if (since) args.push("--since", since);
    if (until) args.push("--until", until);
    if (limit !== undefined) args.push("--limit", String(Math.floor(limit)));
    return toToolResult(await runCli(args));
  },
);

// 4. clawdstrike_timeline -------------------------------------------------
server.tool(
  "clawdstrike_timeline",
  "View a chronological timeline of security events. Useful for understanding event sequences and investigating incidents.",
  {
    source: z.string().optional().describe("Event source filter"),
    verdict: z.string().optional().describe("Verdict filter (allow, deny, audit)"),
    since: z.string().optional().describe("Start time (ISO 8601 or relative)"),
    until: z.string().optional().describe("End time (ISO 8601 or relative)"),
    limit: z.number().optional().describe("Maximum number of events"),
  },
  async ({ source, verdict, since, until, limit }) => {
    const args = ["hunt", "timeline"];
    if (source) args.push("--source", source);
    if (verdict) args.push("--verdict", verdict);
    if (since) args.push("--since", since);
    if (until) args.push("--until", until);
    if (limit !== undefined) args.push("--limit", String(Math.floor(limit)));
    return toToolResult(await runCli(args));
  },
);

// 5. clawdstrike_correlate ------------------------------------------------
server.tool(
  "clawdstrike_correlate",
  "Run correlation rules against security events to detect attack patterns and suspicious behavior sequences.",
  {
    rules: z.array(z.string()).describe("Correlation rule names or paths to apply"),
    since: z.string().optional().describe("Start time (ISO 8601 or relative)"),
    until: z.string().optional().describe("End time (ISO 8601 or relative)"),
  },
  async ({ rules, since, until }) => {
    const args = ["hunt", "correlate"];
    for (const r of rules) args.push("--rules", r);
    if (since) args.push("--since", since);
    if (until) args.push("--until", until);
    return toToolResult(await runCli(args));
  },
);

// 6. clawdstrike_ioc ------------------------------------------------------
server.tool(
  "clawdstrike_ioc",
  "Match events against Indicator of Compromise (IOC) feeds. Detects known-malicious IPs, domains, hashes, and commands.",
  {
    feeds: z.array(z.string()).describe("IOC feed names or paths"),
    since: z.string().optional().describe("Start time (ISO 8601 or relative)"),
    until: z.string().optional().describe("End time (ISO 8601 or relative)"),
  },
  async ({ feeds, since, until }) => {
    const args = ["hunt", "ioc"];
    for (const f of feeds) args.push("--feed", f);
    if (since) args.push("--since", since);
    if (until) args.push("--until", until);
    return toToolResult(await runCli(args));
  },
);

// 7. clawdstrike_policy_show (Bug B: positional arg, raw YAML output) -----
server.tool(
  "clawdstrike_policy_show",
  "Display the active security policy configuration, including all guards, rules, and their settings. Returns YAML.",
  {
    ruleset: z.string().optional().describe("Ruleset name to show (default, strict, permissive, ai-agent, etc.)"),
    merged: z.boolean().optional().describe("Show the fully-merged policy with all inherited rules resolved"),
  },
  async ({ ruleset, merged }) => {
    const args = ["policy", "show"];
    if (ruleset) args.push(ruleset);
    if (merged) args.push("--merged");
    return toToolResult(await runCliRaw(args));
  },
);

// 8. clawdstrike_policy_eval (Bug C: pipe event_json via stdin) -----------
server.tool(
  "clawdstrike_policy_eval",
  "Evaluate a specific event against a policy reference. Returns the enforcement decision and matched rules.",
  {
    policy_ref: z.string().describe("Policy reference (ruleset name, file path, or URL)"),
    event_json: z.string().describe("JSON string of the event to evaluate"),
  },
  async ({ policy_ref, event_json }) => {
    // Validate that event_json is parseable JSON before sending to CLI
    try {
      JSON.parse(event_json);
    } catch {
      return {
        content: [{ type: "text" as const, text: "Invalid JSON in event_json parameter" }],
        isError: true,
      };
    }
    const args = ["policy", "eval", policy_ref, "-"];
    return toToolResult(await runCliStdin(args, event_json));
  },
);

// 9. clawdstrike_hunt_diff ------------------------------------------------
server.tool(
  "clawdstrike_hunt_diff",
  "Compare MCP scan results against a baseline to detect configuration drift: new servers, removed servers, or changed tool sets.",
  {
    baseline: z.string().describe("Path to baseline scan results"),
    current: z.string().optional().describe("Path to current scan results (runs a fresh scan if omitted)"),
  },
  async ({ baseline, current }) => {
    const args = ["hunt", "scan", "diff", "--baseline", baseline];
    if (current) args.push("--current", current);
    return toToolResult(await runCli(args));
  },
);

// 10. clawdstrike_report --------------------------------------------------
server.tool(
  "clawdstrike_report",
  "Generate a composite security report by running timeline analysis and correlation rules, then combining the results.",
  {
    rules: z.array(z.string()).describe("Correlation rule names or paths"),
    since: z.string().optional().describe("Start time (ISO 8601 or relative)"),
    until: z.string().optional().describe("End time (ISO 8601 or relative)"),
  },
  async ({ rules, since, until }) => {
    // Build shared time-range args
    const timeArgs: string[] = [];
    if (since) timeArgs.push("--since", since);
    if (until) timeArgs.push("--until", until);

    // Run timeline and correlate in parallel, with 60s timeout for reports
    const [timelineResult, correlateResult] = await Promise.all([
      runCli<unknown>(["hunt", "timeline", ...timeArgs], 60_000),
      (() => {
        const args = ["hunt", "correlate"];
        for (const r of rules) args.push("--rules", r);
        args.push(...timeArgs);
        return runCli<unknown>(args, 60_000);
      })(),
    ]);

    const report = {
      generated_at: new Date().toISOString(),
      timeline: timelineResult.ok
        ? timelineResult.data
        : { error: timelineResult.error },
      correlation: correlateResult.ok
        ? correlateResult.data
        : { error: correlateResult.error },
    };

    return {
      content: [{ type: "text" as const, text: JSON.stringify(report, null, 2) }],
    };
  },
);

// 11. clawdstrike_policy_lint ---------------------------------------------
server.tool(
  "clawdstrike_policy_lint",
  "Lint a policy file or ruleset reference for errors and warnings. Returns structured diagnostics.",
  {
    ref: z.string().describe("Policy reference to lint (ruleset name, file path, or URL)"),
    strict: z.boolean().optional().describe("Enable strict mode for additional warnings"),
  },
  async ({ ref, strict }) => {
    const args = ["policy", "lint", ref];
    if (strict) args.push("--strict");
    return toToolResult(await runCli(args));
  },
);

// 12. clawdstrike_policy_simulate -----------------------------------------
server.tool(
  "clawdstrike_policy_simulate",
  "Dry-run a batch of events against a policy reference. Returns per-event decisions without enforcing.",
  {
    ref: z.string().describe("Policy reference to simulate against"),
    events: z.string().describe("JSON array of events to simulate"),
  },
  async ({ ref, events }) => {
    try {
      JSON.parse(events);
    } catch {
      return {
        content: [{ type: "text" as const, text: "Invalid JSON in events parameter" }],
        isError: true,
      };
    }
    const args = ["policy", "simulate", ref, "-"];
    return toToolResult(await runCliStdin(args, events, 60_000));
  },
);

// 13. clawdstrike_verify_receipt ------------------------------------------
server.tool(
  "clawdstrike_verify_receipt",
  "Verify an Ed25519-signed enforcement receipt. Returns verification status and decoded payload.",
  {
    pubkey: z.string().describe("Ed25519 public key (hex or base64)"),
    receipt: z.string().describe("Receipt to verify (file path or JSON string)"),
  },
  async ({ pubkey, receipt }) => {
    const args = ["verify", "--pubkey", pubkey, receipt];
    return toToolResult(await runCli(args));
  },
);

// 14. clawdstrike_merkle_verify -------------------------------------------
server.tool(
  "clawdstrike_merkle_verify",
  "Verify a Merkle inclusion proof. Returns text confirmation of proof validity.",
  {
    root: z.string().describe("Merkle root hash (hex)"),
    leaf: z.string().describe("Leaf hash to verify (hex)"),
    proof: z.string().describe("Comma-separated sibling hashes forming the proof path"),
  },
  async ({ root, leaf, proof }) => {
    const args = ["merkle", "verify", "--root", root, "--leaf", leaf, "--proof", proof];
    return toToolResult(await runCliRaw(args));
  },
);

// 15. clawdstrike_guard_inspect -------------------------------------------
server.tool(
  "clawdstrike_guard_inspect",
  "Inspect a guard plugin's metadata, configuration schema, and capabilities.",
  {
    plugin_ref: z.string().describe("Guard plugin reference (built-in name or path to plugin)"),
  },
  async ({ plugin_ref }) => {
    const args = ["guard", "inspect", plugin_ref];
    return toToolResult(await runCliRaw(args));
  },
);

// ---------------------------------------------------------------------------
// Resources
// ---------------------------------------------------------------------------

// Static resource: current session receipts
server.resource(
  "session-receipts",
  "clawdstrike://session/receipts",
  { description: "Current session enforcement receipts (JSONL)" },
  async () => {
    const sessionId = process.env.CLAWDSTRIKE_SESSION_ID ?? "current";
    const receiptsPath = join(
      homedir(),
      ".clawdstrike",
      "receipts",
      `session-${sessionId}.jsonl`,
    );

    try {
      const data = await readFile(receiptsPath, "utf-8");
      return {
        contents: [
          {
            uri: "clawdstrike://session/receipts",
            mimeType: "application/jsonl",
            text: data,
          },
        ],
      };
    } catch {
      return {
        contents: [
          {
            uri: "clawdstrike://session/receipts",
            mimeType: "text/plain",
            text: "No receipts found for current session.",
          },
        ],
      };
    }
  },
);

// Template resource: policy by ruleset name
server.resource(
  "policy",
  new ResourceTemplate("clawdstrike://policy/{ruleset}", { list: undefined }),
  { description: "Security policy configuration (YAML) for a given ruleset" },
  async (uri, { ruleset }) => {
    const rulesetName = Array.isArray(ruleset) ? ruleset[0] : ruleset;
    const result = await runCliRaw(["policy", "show", String(rulesetName)]);

    if (!result.ok) {
      return {
        contents: [
          {
            uri: uri.href,
            mimeType: "text/plain",
            text: result.error ?? "Failed to load policy",
          },
        ],
      };
    }

    return {
      contents: [
        {
          uri: uri.href,
          mimeType: "text/yaml",
          text: result.data ?? "",
        },
      ],
    };
  },
);

// ---------------------------------------------------------------------------
// Prompts
// ---------------------------------------------------------------------------

server.prompt(
  "investigate-incident",
  "Structured 6-step threat hunt workflow for investigating security incidents within a time range.",
  {
    since: z.string().describe("Start of investigation window (ISO 8601 or relative like '1h')"),
    until: z.string().optional().describe("End of investigation window (ISO 8601 or relative)"),
    rules: z.string().optional().describe("Comma-separated correlation rule names to apply"),
  },
  ({ since, until, rules }) => {
    const timeRange = until ? `from ${since} to ${until}` : `since ${since}`;
    const rulesNote = rules
      ? `Focus on these correlation rules: ${rules}`
      : "Use all available correlation rules.";

    return {
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
            text: [
              `Investigate security incidents ${timeRange}. ${rulesNote}`,
              "",
              "Follow this 6-step threat hunt workflow:",
              "",
              "1. **Scope** — Use clawdstrike_timeline to get an overview of events in the time range. Identify event volume, sources, and anomalies.",
              "2. **Triage** — Use clawdstrike_query to filter for deny verdicts and high-severity events. Prioritize by impact.",
              "3. **Correlate** — Use clawdstrike_correlate to run correlation rules and detect multi-step attack patterns.",
              "4. **IOC Match** — Use clawdstrike_ioc to check events against known indicators of compromise.",
              "5. **Evidence** — Collect and verify enforcement receipts. Check Merkle proofs for tamper evidence.",
              "6. **Report** — Use clawdstrike_report to generate a composite summary. Include timeline, findings, and recommended actions.",
            ].join("\n"),
          },
        },
      ],
    };
  },
);

server.prompt(
  "assess-posture",
  "Security posture assessment workflow: evaluate current policy, scan for misconfigurations, and identify gaps.",
  {
    ruleset: z.string().optional().describe("Ruleset to assess (defaults to active policy)"),
  },
  ({ ruleset }) => {
    const target = ruleset ? `the "${ruleset}" ruleset` : "the active policy";

    return {
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
            text: [
              `Assess the security posture of ${target}.`,
              "",
              "Follow this workflow:",
              "",
              "1. **Policy Review** — Use clawdstrike_policy_show to display the current policy configuration. Identify enabled guards and their settings.",
              "2. **Lint** — Use clawdstrike_policy_lint with --strict to check for policy errors, warnings, and best-practice violations.",
              "3. **MCP Scan** — Use clawdstrike_scan to detect misconfigured or suspicious MCP server definitions.",
              "4. **Baseline Drift** — If a baseline exists, use clawdstrike_hunt_diff to detect configuration drift.",
              "5. **Gap Analysis** — Compare the policy against the strict ruleset. Identify missing guards and permissive rules.",
              "6. **Recommendations** — Summarize findings and provide prioritized remediation steps.",
            ].join("\n"),
          },
        },
      ],
    };
  },
);

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

// Health check: ensure CLI binary is available before accepting connections
await healthCheck();

const transport = new StdioServerTransport();
await server.connect(transport);
