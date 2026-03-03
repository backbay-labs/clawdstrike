/**
 * Hook script integration tests.
 *
 * Feeds mock JSON payloads via stdin to the shell scripts and verifies
 * exit codes and (where applicable) JSONL receipt output.
 */

import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm, readFile, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const SCRIPTS_DIR = join(import.meta.dir, "..", "scripts");
const PRE_TOOL = join(SCRIPTS_DIR, "pre-tool-check.sh");
const POST_TOOL = join(SCRIPTS_DIR, "post-tool-receipt.sh");
const SESSION_START = join(SCRIPTS_DIR, "session-start.sh");
const SESSION_END = join(SCRIPTS_DIR, "session-end.sh");

/** Run a hook script with the given stdin payload and environment overrides. */
async function runHook(
  script: string,
  stdinPayload: string,
  env: Record<string, string> = {},
): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  const proc = Bun.spawn(["bash", script], {
    stdin: "pipe",
    stdout: "pipe",
    stderr: "pipe",
    env: {
      ...process.env,
      ...env,
      // Disable fail-open by default so denials are real
      CLAWDSTRIKE_HOOK_FAIL_OPEN: env.CLAWDSTRIKE_HOOK_FAIL_OPEN ?? "0",
    },
  });

  proc.stdin.write(stdinPayload);
  proc.stdin.end();

  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ]);

  return { exitCode, stdout, stderr };
}

describe("pre-tool-check.sh", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "clawdstrike-test-"));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("exits 1 when token file is missing and fail-open is off", async () => {
    const payload = JSON.stringify({
      tool_name: "Bash",
      tool_input: { command: "echo hello" },
    });

    const result = await runHook(PRE_TOOL, payload, {
      CLAWDSTRIKE_TOKEN_FILE: join(tempDir, "nonexistent-token"),
      CLAWDSTRIKE_ENDPOINT: "http://127.0.0.1:1",
      CLAWDSTRIKE_HOOK_FAIL_OPEN: "0",
    });

    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain("token");
  });

  it("exits 0 when token file is missing but fail-open is on", async () => {
    const payload = JSON.stringify({
      tool_name: "Bash",
      tool_input: { command: "echo hello" },
    });

    const result = await runHook(PRE_TOOL, payload, {
      CLAWDSTRIKE_TOKEN_FILE: join(tempDir, "nonexistent-token"),
      CLAWDSTRIKE_ENDPOINT: "http://127.0.0.1:1",
      CLAWDSTRIKE_HOOK_FAIL_OPEN: "1",
    });

    expect(result.exitCode).toBe(0);
    expect(result.stderr).toContain("CLAWDSTRIKE_HOOK_FAIL_OPEN is set");
  });

  it("exits 1 when payload is missing tool_name and fail-open is off", async () => {
    const payload = JSON.stringify({ tool_input: {} });

    const result = await runHook(PRE_TOOL, payload, {
      CLAWDSTRIKE_TOKEN_FILE: join(tempDir, "nonexistent-token"),
      CLAWDSTRIKE_ENDPOINT: "http://127.0.0.1:1",
    });

    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain("tool_name");
  });

  it("exits 1 for Read tool with no target (fail-closed)", async () => {
    const payload = JSON.stringify({
      tool_name: "Read",
      tool_input: {},
    });

    const result = await runHook(PRE_TOOL, payload, {
      CLAWDSTRIKE_TOKEN_FILE: join(tempDir, "nonexistent-token"),
      CLAWDSTRIKE_ENDPOINT: "http://127.0.0.1:1",
    });

    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain("BLOCKED");
    expect(result.stderr).toContain("target");
  });

  it("writes denial receipt when session_id is set and target is empty", async () => {
    const receiptDir = join(tempDir, ".clawdstrike", "receipts");
    const sessionId = "test-session-001";

    const payload = JSON.stringify({
      tool_name: "Write",
      tool_input: {},
    });

    const result = await runHook(PRE_TOOL, payload, {
      HOME: tempDir,
      CLAWDSTRIKE_SESSION_ID: sessionId,
      CLAWDSTRIKE_TOKEN_FILE: join(tempDir, "nonexistent-token"),
      CLAWDSTRIKE_ENDPOINT: "http://127.0.0.1:1",
    });

    expect(result.exitCode).toBe(1);

    const receiptFile = join(receiptDir, `session-${sessionId}.jsonl`);
    const content = await readFile(receiptFile, "utf-8");
    const receipt = JSON.parse(content.trim());
    expect(receipt.outcome).toBe("deny");
    expect(receipt.guard).toBe("empty_target");
    expect(receipt.tool_name).toBe("Write");
  });

  it("exits 0 for Glob with no explicit target (allowed)", async () => {
    const payload = JSON.stringify({
      tool_name: "Glob",
      tool_input: {},
    });

    const result = await runHook(PRE_TOOL, payload, {
      CLAWDSTRIKE_TOKEN_FILE: join(tempDir, "nonexistent-token"),
      CLAWDSTRIKE_ENDPOINT: "http://127.0.0.1:1",
    });

    expect(result.exitCode).toBe(0);
  });
});

describe("post-tool-receipt.sh", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "clawdstrike-test-"));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("always exits 0 even with missing input", async () => {
    const result = await runHook(POST_TOOL, "", {
      HOME: tempDir,
      CLAWDSTRIKE_SESSION_ID: "test-post",
    });

    expect(result.exitCode).toBe(0);
  });

  it("writes a JSONL receipt for a successful tool call", async () => {
    const sessionId = "test-receipt-001";
    const payload = JSON.stringify({
      tool_name: "Read",
      tool_input: { file_path: "/etc/hosts" },
    });

    const result = await runHook(POST_TOOL, payload, {
      HOME: tempDir,
      CLAWDSTRIKE_SESSION_ID: sessionId,
    });

    expect(result.exitCode).toBe(0);

    const receiptFile = join(tempDir, ".clawdstrike", "receipts", `session-${sessionId}.jsonl`);
    const content = await readFile(receiptFile, "utf-8");
    const receipt = JSON.parse(content.trim());
    expect(receipt.tool_name).toBe("Read");
    expect(receipt.action_type).toBe("file_access");
    expect(receipt.target).toBe("/etc/hosts");
    expect(receipt.outcome).toBe("success");
    expect(receipt.session_id).toBe(sessionId);
  });

  it("records error outcome when tool reports isError", async () => {
    const sessionId = "test-error-001";
    const payload = JSON.stringify({
      tool_name: "Bash",
      tool_input: { command: "exit 1" },
      isError: true,
    });

    const result = await runHook(POST_TOOL, payload, {
      HOME: tempDir,
      CLAWDSTRIKE_SESSION_ID: sessionId,
    });

    expect(result.exitCode).toBe(0);

    const receiptFile = join(tempDir, ".clawdstrike", "receipts", `session-${sessionId}.jsonl`);
    const content = await readFile(receiptFile, "utf-8");
    const receipt = JSON.parse(content.trim());
    expect(receipt.outcome).toBe("error");
    expect(receipt.action_type).toBe("shell");
  });

  it("includes duration_ms when present", async () => {
    const sessionId = "test-duration-001";
    const payload = JSON.stringify({
      tool_name: "WebFetch",
      tool_input: { url: "https://example.com" },
      response_duration_ms: 42,
    });

    const result = await runHook(POST_TOOL, payload, {
      HOME: tempDir,
      CLAWDSTRIKE_SESSION_ID: sessionId,
    });

    expect(result.exitCode).toBe(0);

    const receiptFile = join(tempDir, ".clawdstrike", "receipts", `session-${sessionId}.jsonl`);
    const content = await readFile(receiptFile, "utf-8");
    const receipt = JSON.parse(content.trim());
    expect(receipt.duration_ms).toBe(42);
  });
});

describe("session-start.sh", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "clawdstrike-test-"));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("outputs hookSpecificOutput JSON on success", async () => {
    const result = await runHook(SESSION_START, "", {
      HOME: tempDir,
      CLAWDSTRIKE_ENDPOINT: "http://127.0.0.1:1",
      CLAWDSTRIKE_CLI: "false",
    });

    // session-start should exit 0 even if hushd is unreachable
    expect(result.exitCode).toBe(0);

    // stdout should contain hookSpecificOutput JSON
    const output = JSON.parse(result.stdout.trim());
    expect(output.hookSpecificOutput).toBeDefined();
    expect(output.hookSpecificOutput.additionalContext).toContain("ClawdStrike");
  });

  it("creates a receipt file with session_start event", async () => {
    const result = await runHook(SESSION_START, "", {
      HOME: tempDir,
      CLAWDSTRIKE_ENDPOINT: "http://127.0.0.1:1",
      CLAWDSTRIKE_CLI: "false",
    });

    expect(result.exitCode).toBe(0);

    // Find the receipt file (session ID is generated dynamically)
    const { readdir } = await import("node:fs/promises");
    const receiptsDir = join(tempDir, ".clawdstrike", "receipts");
    const files = await readdir(receiptsDir);
    const sessionFiles = files.filter((f) => f.startsWith("session-") && f.endsWith(".jsonl"));
    expect(sessionFiles.length).toBeGreaterThanOrEqual(1);

    const content = await readFile(join(receiptsDir, sessionFiles[0]), "utf-8");
    const receipt = JSON.parse(content.trim());
    expect(receipt.event).toBe("session_start");
    expect(receipt.hushd_status).toBe("disconnected");
  });
});

describe("session-end.sh", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "clawdstrike-test-"));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("exits 0 when no receipt file exists", async () => {
    const result = await runHook(SESSION_END, "", {
      HOME: tempDir,
      CLAWDSTRIKE_SESSION_ID: "nonexistent-session",
    });

    expect(result.exitCode).toBe(0);
  });

  it("writes session_end summary to existing receipt file", async () => {
    const sessionId = "test-end-001";
    const receiptDir = join(tempDir, ".clawdstrike", "receipts");
    await mkdir(receiptDir, { recursive: true });
    const receiptFile = join(receiptDir, `session-${sessionId}.jsonl`);

    // Seed with a tool call line
    await writeFile(
      receiptFile,
      JSON.stringify({
        timestamp: "2026-01-01T00:00:00Z",
        session_id: sessionId,
        tool_name: "Read",
        action_type: "file_access",
        target: "/etc/hosts",
        outcome: "success",
      }) + "\n",
    );

    const result = await runHook(SESSION_END, "", {
      HOME: tempDir,
      CLAWDSTRIKE_SESSION_ID: sessionId,
    });

    expect(result.exitCode).toBe(0);

    const content = await readFile(receiptFile, "utf-8");
    const lines = content.trim().split("\n");
    expect(lines.length).toBe(2);

    const summary = JSON.parse(lines[1]);
    expect(summary.event).toBe("session_end");
    expect(summary.total_tool_calls).toBe(1);
    expect(summary.denied_tool_calls).toBe(0);
  });
});
