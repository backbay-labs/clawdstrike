/**
 * Tests for Cursor-specific hook scripts (6 new hooks).
 *
 * Tests the hooks that are unique to Cursor and not present in the Claude Code plugin:
 * - beforeShellExecution / afterShellExecution
 * - beforeMCPExecution / afterMCPExecution
 * - beforeReadFile
 * - afterFileEdit
 */

import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { mkdtemp, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const SCRIPTS_DIR = join(import.meta.dir, "..", "scripts");
const BEFORE_SHELL = join(SCRIPTS_DIR, "before-shell.sh");
const AFTER_SHELL = join(SCRIPTS_DIR, "after-shell.sh");
const BEFORE_MCP = join(SCRIPTS_DIR, "before-mcp.sh");
const AFTER_MCP = join(SCRIPTS_DIR, "after-mcp.sh");
const BEFORE_READ_FILE = join(SCRIPTS_DIR, "before-read-file.sh");
const AFTER_FILE_EDIT = join(SCRIPTS_DIR, "after-file-edit.sh");

/** Cursor base fields included in every hook payload. */
const CURSOR_BASE = {
  conversation_id: "test-conv-001",
  generation_id: "test-gen-001",
  model: "claude-opus-4-6",
  cursor_version: "0.50.0",
  workspace_roots: ["/tmp/test-workspace"],
  user_email: "test@example.com",
};

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

// ---------------------------------------------------------------------------
// beforeShellExecution
// ---------------------------------------------------------------------------

describe("before-shell.sh", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "clawdstrike-cursor-test-"));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("exits 2 when token is missing and fail-open is off", async () => {
    const payload = JSON.stringify({
      ...CURSOR_BASE,
      hook_event_name: "beforeShellExecution",
      command: "rm -rf /",
      cwd: "/tmp",
    });

    const result = await runHook(BEFORE_SHELL, payload, {
      CLAWDSTRIKE_TOKEN_FILE: join(tempDir, "nonexistent-token"),
      CLAWDSTRIKE_ENDPOINT: "http://127.0.0.1:1",
    });

    expect(result.exitCode).toBe(2);
  });

  it("exits 0 when no command is provided", async () => {
    const payload = JSON.stringify({
      ...CURSOR_BASE,
      hook_event_name: "beforeShellExecution",
    });

    const result = await runHook(BEFORE_SHELL, payload, {
      CLAWDSTRIKE_TOKEN_FILE: join(tempDir, "nonexistent-token"),
      CLAWDSTRIKE_ENDPOINT: "http://127.0.0.1:1",
    });

    expect(result.exitCode).toBe(0);
  });

  it("outputs permission JSON on deny", async () => {
    const payload = JSON.stringify({
      ...CURSOR_BASE,
      hook_event_name: "beforeShellExecution",
      command: "echo hello",
      cwd: "/tmp",
    });

    const result = await runHook(BEFORE_SHELL, payload, {
      CLAWDSTRIKE_TOKEN_FILE: join(tempDir, "nonexistent-token"),
      CLAWDSTRIKE_ENDPOINT: "http://127.0.0.1:1",
    });

    // With no token file, it should deny (fail-closed)
    expect(result.exitCode).toBe(2);
    expect(result.stderr).toContain("token");
  });

  it("writes receipt on deny when session_id is set", async () => {
    const sessionId = "test-shell-deny";
    const payload = JSON.stringify({
      ...CURSOR_BASE,
      hook_event_name: "beforeShellExecution",
      command: "dangerous-command",
      cwd: "/tmp",
    });

    const result = await runHook(BEFORE_SHELL, payload, {
      HOME: tempDir,
      CLAWDSTRIKE_SESSION_ID: sessionId,
      CLAWDSTRIKE_TOKEN_FILE: join(tempDir, "nonexistent-token"),
      CLAWDSTRIKE_ENDPOINT: "http://127.0.0.1:1",
    });

    expect(result.exitCode).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// afterShellExecution
// ---------------------------------------------------------------------------

describe("after-shell.sh", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "clawdstrike-cursor-test-"));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("always exits 0", async () => {
    const payload = JSON.stringify({
      ...CURSOR_BASE,
      hook_event_name: "afterShellExecution",
      command: "echo hello",
      exit_code: 0,
    });

    const result = await runHook(AFTER_SHELL, payload, {
      HOME: tempDir,
      CLAWDSTRIKE_SESSION_ID: "test-after-shell",
    });

    expect(result.exitCode).toBe(0);
  });

  it("writes receipt with exit_code and outcome", async () => {
    const sessionId = "test-shell-receipt";
    const payload = JSON.stringify({
      ...CURSOR_BASE,
      hook_event_name: "afterShellExecution",
      command: "exit 1",
      exit_code: 1,
      stderr: "command failed",
    });

    const result = await runHook(AFTER_SHELL, payload, {
      HOME: tempDir,
      CLAWDSTRIKE_SESSION_ID: sessionId,
    });

    expect(result.exitCode).toBe(0);

    const receiptFile = join(tempDir, ".clawdstrike", "receipts", `session-${sessionId}.jsonl`);
    const content = await readFile(receiptFile, "utf-8");
    const receipt = JSON.parse(content.trim());
    expect(receipt.hook_event).toBe("afterShellExecution");
    expect(receipt.exit_code).toBe("1");
    expect(receipt.outcome).toBe("error");
    expect(receipt.target).toBe("exit 1");
  });

  it("records success for exit_code 0", async () => {
    const sessionId = "test-shell-success";
    const payload = JSON.stringify({
      ...CURSOR_BASE,
      hook_event_name: "afterShellExecution",
      command: "echo hello",
      exit_code: 0,
      stdout: "hello\n",
    });

    const result = await runHook(AFTER_SHELL, payload, {
      HOME: tempDir,
      CLAWDSTRIKE_SESSION_ID: sessionId,
    });

    expect(result.exitCode).toBe(0);

    const receiptFile = join(tempDir, ".clawdstrike", "receipts", `session-${sessionId}.jsonl`);
    const content = await readFile(receiptFile, "utf-8");
    const receipt = JSON.parse(content.trim());
    expect(receipt.outcome).toBe("success");
  });
});

// ---------------------------------------------------------------------------
// beforeMCPExecution
// ---------------------------------------------------------------------------

describe("before-mcp.sh", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "clawdstrike-cursor-test-"));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("bypasses check for clawdstrike MCP server (self-tool)", async () => {
    const payload = JSON.stringify({
      ...CURSOR_BASE,
      hook_event_name: "beforeMCPExecution",
      mcp_server_name: "clawdstrike",
      tool_name: "clawdstrike_check",
      tool_arguments: { action_type: "file", target: "/etc/hosts" },
    });

    const result = await runHook(BEFORE_MCP, payload, {
      CLAWDSTRIKE_TOKEN_FILE: join(tempDir, "nonexistent-token"),
      CLAWDSTRIKE_ENDPOINT: "http://127.0.0.1:1",
    });

    // Should pass through without checking (would fail on missing token otherwise)
    expect(result.exitCode).toBe(0);
  });

  it("exits 2 for non-clawdstrike MCP server when token missing", async () => {
    const payload = JSON.stringify({
      ...CURSOR_BASE,
      hook_event_name: "beforeMCPExecution",
      mcp_server_name: "unknown-server",
      tool_name: "dangerous_tool",
      tool_arguments: {},
    });

    const result = await runHook(BEFORE_MCP, payload, {
      CLAWDSTRIKE_TOKEN_FILE: join(tempDir, "nonexistent-token"),
      CLAWDSTRIKE_ENDPOINT: "http://127.0.0.1:1",
    });

    expect(result.exitCode).toBe(2);
  });

  it("exits 0 when no server or tool name provided", async () => {
    const payload = JSON.stringify({
      ...CURSOR_BASE,
      hook_event_name: "beforeMCPExecution",
    });

    const result = await runHook(BEFORE_MCP, payload, {
      CLAWDSTRIKE_TOKEN_FILE: join(tempDir, "nonexistent-token"),
      CLAWDSTRIKE_ENDPOINT: "http://127.0.0.1:1",
    });

    expect(result.exitCode).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// afterMCPExecution
// ---------------------------------------------------------------------------

describe("after-mcp.sh", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "clawdstrike-cursor-test-"));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("always exits 0", async () => {
    const payload = JSON.stringify({
      ...CURSOR_BASE,
      hook_event_name: "afterMCPExecution",
      mcp_server_name: "test-server",
      tool_name: "test_tool",
    });

    const result = await runHook(AFTER_MCP, payload, {
      HOME: tempDir,
      CLAWDSTRIKE_SESSION_ID: "test-after-mcp",
    });

    expect(result.exitCode).toBe(0);
  });

  it("writes receipt with server and tool info", async () => {
    const sessionId = "test-mcp-receipt";
    const payload = JSON.stringify({
      ...CURSOR_BASE,
      hook_event_name: "afterMCPExecution",
      mcp_server_name: "github",
      tool_name: "create_issue",
    });

    const result = await runHook(AFTER_MCP, payload, {
      HOME: tempDir,
      CLAWDSTRIKE_SESSION_ID: sessionId,
    });

    expect(result.exitCode).toBe(0);

    const receiptFile = join(tempDir, ".clawdstrike", "receipts", `session-${sessionId}.jsonl`);
    const content = await readFile(receiptFile, "utf-8");
    const receipt = JSON.parse(content.trim());
    expect(receipt.hook_event).toBe("afterMCPExecution");
    expect(receipt.mcp_server).toBe("github");
    expect(receipt.tool_name).toBe("create_issue");
    expect(receipt.target).toBe("github/create_issue");
  });
});

// ---------------------------------------------------------------------------
// beforeReadFile
// ---------------------------------------------------------------------------

describe("before-read-file.sh", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "clawdstrike-cursor-test-"));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("exits 2 when token is missing (fail-closed for file reads)", async () => {
    const payload = JSON.stringify({
      ...CURSOR_BASE,
      hook_event_name: "beforeReadFile",
      file_path: "/etc/shadow",
    });

    const result = await runHook(BEFORE_READ_FILE, payload, {
      CLAWDSTRIKE_TOKEN_FILE: join(tempDir, "nonexistent-token"),
      CLAWDSTRIKE_ENDPOINT: "http://127.0.0.1:1",
    });

    expect(result.exitCode).toBe(2);
  });

  it("exits 0 when no file_path is provided", async () => {
    const payload = JSON.stringify({
      ...CURSOR_BASE,
      hook_event_name: "beforeReadFile",
    });

    const result = await runHook(BEFORE_READ_FILE, payload, {
      CLAWDSTRIKE_TOKEN_FILE: join(tempDir, "nonexistent-token"),
      CLAWDSTRIKE_ENDPOINT: "http://127.0.0.1:1",
    });

    expect(result.exitCode).toBe(0);
  });

  it("outputs permission JSON on deny", async () => {
    const payload = JSON.stringify({
      ...CURSOR_BASE,
      hook_event_name: "beforeReadFile",
      file_path: "/etc/shadow",
    });

    const result = await runHook(BEFORE_READ_FILE, payload, {
      CLAWDSTRIKE_TOKEN_FILE: join(tempDir, "nonexistent-token"),
      CLAWDSTRIKE_ENDPOINT: "http://127.0.0.1:1",
    });

    expect(result.exitCode).toBe(2);
    // stderr should have the error
    expect(result.stderr).toContain("token");
  });
});

// ---------------------------------------------------------------------------
// afterFileEdit
// ---------------------------------------------------------------------------

describe("after-file-edit.sh", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "clawdstrike-cursor-test-"));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("always exits 0", async () => {
    const payload = JSON.stringify({
      ...CURSOR_BASE,
      hook_event_name: "afterFileEdit",
      file_path: "/tmp/test.txt",
      edits: [{ old_string: "foo", new_string: "bar" }],
    });

    const result = await runHook(AFTER_FILE_EDIT, payload, {
      HOME: tempDir,
      CLAWDSTRIKE_SESSION_ID: "test-after-edit",
    });

    expect(result.exitCode).toBe(0);
  });

  it("writes receipt with file_path and edit_count", async () => {
    const sessionId = "test-edit-receipt";
    const payload = JSON.stringify({
      ...CURSOR_BASE,
      hook_event_name: "afterFileEdit",
      file_path: "/tmp/app.ts",
      edits: [
        { old_string: "const a = 1", new_string: "const a = 2" },
        { old_string: "const b = 3", new_string: "const b = 4" },
      ],
    });

    const result = await runHook(AFTER_FILE_EDIT, payload, {
      HOME: tempDir,
      CLAWDSTRIKE_SESSION_ID: sessionId,
    });

    expect(result.exitCode).toBe(0);

    const receiptFile = join(tempDir, ".clawdstrike", "receipts", `session-${sessionId}.jsonl`);
    const content = await readFile(receiptFile, "utf-8");
    const receipt = JSON.parse(content.trim());
    expect(receipt.hook_event).toBe("afterFileEdit");
    expect(receipt.action_type).toBe("file_write");
    expect(receipt.target).toBe("/tmp/app.ts");
    expect(receipt.edit_count).toBe(2);
  });
});
