/**
 * CLI bridge — spawns the clawdstrike binary and returns structured results.
 *
 * Extracted from mcp-server.ts so it can be imported by both the server and tests.
 */

export const CLI = process.env.CLAWDSTRIKE_CLI ?? "clawdstrike";
export const DEFAULT_TIMEOUT = 30_000;

export interface CliResult<T> {
  ok: boolean;
  data?: T;
  error?: string;
}

/**
 * Run a CLI command, automatically appending `--json` for structured output.
 * Parses stdout as JSON on success.
 */
export async function runCli<T>(
  args: string[],
  timeout = DEFAULT_TIMEOUT,
): Promise<CliResult<T>> {
  const proc = Bun.spawn([CLI, ...args, "--json"], {
    stdout: "pipe",
    stderr: "pipe",
  });

  const timer =
    timeout > 0 ? setTimeout(() => proc.kill(), timeout) : undefined;

  try {
    const [stdout, stderr, exitCode] = await Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
      proc.exited,
    ]);
    if (timer) clearTimeout(timer);

    if (exitCode !== 0) {
      return { ok: false, error: stderr.trim() || `Exit code ${exitCode}` };
    }

    const trimmed = stdout.trim();
    if (!trimmed) return { ok: true, data: undefined };

    try {
      return { ok: true, data: JSON.parse(trimmed) as T };
    } catch {
      return {
        ok: false,
        error: `Failed to parse JSON: ${trimmed.slice(0, 200)}`,
      };
    }
  } catch (err) {
    if (timer) clearTimeout(timer);
    return {
      ok: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * Run a CLI command returning raw text output (no `--json` flag, no JSON parsing).
 * Use for commands that emit YAML, plain text, or other non-JSON formats.
 */
export async function runCliRaw(
  args: string[],
  timeout = DEFAULT_TIMEOUT,
): Promise<CliResult<string>> {
  const proc = Bun.spawn([CLI, ...args], {
    stdout: "pipe",
    stderr: "pipe",
  });

  const timer =
    timeout > 0 ? setTimeout(() => proc.kill(), timeout) : undefined;

  try {
    const [stdout, stderr, exitCode] = await Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
      proc.exited,
    ]);
    if (timer) clearTimeout(timer);

    if (exitCode !== 0) {
      return { ok: false, error: stderr.trim() || `Exit code ${exitCode}` };
    }

    return { ok: true, data: stdout.trimEnd() };
  } catch (err) {
    if (timer) clearTimeout(timer);
    return {
      ok: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * Run a CLI command with data piped to stdin. Appends `--json` for structured output.
 */
export async function runCliStdin<T>(
  args: string[],
  stdinData: string,
  timeout = DEFAULT_TIMEOUT,
): Promise<CliResult<T>> {
  const proc = Bun.spawn([CLI, ...args, "--json"], {
    stdout: "pipe",
    stderr: "pipe",
    stdin: "pipe",
  });

  const timer =
    timeout > 0 ? setTimeout(() => proc.kill(), timeout) : undefined;

  try {
    proc.stdin.write(stdinData);
    proc.stdin.end();

    const [stdout, stderr, exitCode] = await Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
      proc.exited,
    ]);
    if (timer) clearTimeout(timer);

    if (exitCode !== 0) {
      return { ok: false, error: stderr.trim() || `Exit code ${exitCode}` };
    }

    const trimmed = stdout.trim();
    if (!trimmed) return { ok: true, data: undefined };

    try {
      return { ok: true, data: JSON.parse(trimmed) as T };
    } catch {
      return {
        ok: false,
        error: `Failed to parse JSON: ${trimmed.slice(0, 200)}`,
      };
    }
  } catch (err) {
    if (timer) clearTimeout(timer);
    return {
      ok: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

/** Format a CliResult as an MCP CallToolResult. */
export function toToolResult(result: CliResult<unknown>) {
  if (!result.ok) {
    return {
      content: [{ type: "text" as const, text: result.error ?? "Unknown error" }],
      isError: true,
    };
  }

  const text =
    result.data !== undefined
      ? typeof result.data === "string"
        ? result.data
        : JSON.stringify(result.data, null, 2)
      : "OK (no output)";

  return { content: [{ type: "text" as const, text }] };
}

/** Check that the CLI binary is available. Throws if not. */
export async function healthCheck(): Promise<string> {
  const result = await runCliRaw(["--version"], 5_000);
  if (!result.ok) {
    throw new Error(
      `clawdstrike CLI not found or not executable (${CLI}): ${result.error}`,
    );
  }
  return result.data ?? "unknown";
}
