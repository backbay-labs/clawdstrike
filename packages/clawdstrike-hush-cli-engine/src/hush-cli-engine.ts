import { spawn } from 'node:child_process';

import type { Decision, PolicyEngineLike, PolicyEvent } from '@clawdstrike/adapter-core';

export interface HushCliEngineOptions {
  hushPath?: string;
  policyRef: string;
  resolve?: boolean;
  timeoutMs?: number;
}

type HushPolicyEvalResponseV1 = {
  version: 1;
  command: 'policy_eval';
  decision: Decision;
};

export function createHushCliEngine(options: HushCliEngineOptions): PolicyEngineLike {
  const hushPath = options.hushPath ?? 'hush';
  const timeoutMs = options.timeoutMs ?? 10_000;
  const policyRef = options.policyRef;
  const resolvePolicy = options.resolve === true;

  return {
    async evaluate(event: PolicyEvent): Promise<Decision> {
      const args = ['policy', 'eval', policyRef, '-', '--json'];
      if (resolvePolicy) {
        args.push('--resolve');
      }

      try {
        const output = await spawnJson(hushPath, args, event, timeoutMs);
        const response = parsePolicyEvalResponse(output);
        return response.decision;
      } catch (error) {
        return failClosed(error);
      }
    },
  };
}

async function spawnJson(
  command: string,
  args: string[],
  input: unknown,
  timeoutMs: number,
): Promise<string> {
  const child = spawn(command, args, { stdio: ['pipe', 'pipe', 'pipe'] });
  child.stdin.setDefaultEncoding('utf8');
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');

  const stdoutChunks: string[] = [];
  const stderrChunks: string[] = [];

  child.stdout.on('data', chunk => stdoutChunks.push(String(chunk)));
  child.stderr.on('data', chunk => stderrChunks.push(String(chunk)));

  let settled = false;
  const settleOnce = <T>(fn: () => T): T | undefined => {
    if (settled) {
      return undefined;
    }
    settled = true;
    return fn();
  };

  child.stdin.write(JSON.stringify(input));
  child.stdin.end();

  return await new Promise<string>((resolve, reject) => {
    const timeoutId = setTimeout(() => {
      settleOnce(() => {
        child.kill('SIGKILL');
        reject(
          new Error(
            `hush timed out after ${timeoutMs}ms${formatStderr(stderrChunks)}`,
          ),
        );
      });
    }, timeoutMs);

    timeoutId.unref?.();

    child.once('error', err => {
      settleOnce(() => {
        clearTimeout(timeoutId);
        reject(err);
      });
    });

    child.once('close', (code, signal) => {
      settleOnce(() => {
        clearTimeout(timeoutId);

        if (signal) {
          reject(
            new Error(
              `hush exited with signal ${signal}${formatStderr(stderrChunks)}`,
            ),
          );
          return;
        }

        // `hush policy eval` uses stable exit codes:
        // - 0: ok/allowed
        // - 1: warn
        // - 2: blocked
        // Treat 0-2 as non-fatal so we can still parse the JSON decision.
        const numericCode = typeof code === 'number' ? code : -1;
        if (numericCode < 0 || numericCode > 2) {
          reject(
            new Error(
              `hush exited with code ${String(code)}${formatStderr(stderrChunks)}`,
            ),
          );
          return;
        }

        resolve(stdoutChunks.join(''));
      });
    });
  });
}

function parsePolicyEvalResponse(raw: string): HushPolicyEvalResponseV1 {
  const parsed = JSON.parse(raw) as unknown;
  if (!isRecord(parsed)) {
    throw new Error('Invalid hush JSON: expected object');
  }

  if (parsed.version !== 1) {
    throw new Error(`Invalid hush JSON: expected version=1`);
  }

  if (parsed.command !== 'policy_eval') {
    throw new Error(`Invalid hush JSON: expected command="policy_eval"`);
  }

  const decision = parseDecision(parsed.decision);
  if (!decision) {
    throw new Error(`Invalid hush JSON: missing/invalid decision`);
  }

  return {
    version: 1,
    command: 'policy_eval',
    decision,
  };
}

function parseDecision(value: unknown): Decision | null {
  if (!isRecord(value)) {
    return null;
  }

  const status =
    value.status === 'allow' || value.status === 'warn' || value.status === 'deny'
      ? value.status
      : typeof value.allowed === 'boolean' && typeof value.denied === 'boolean' && typeof value.warn === 'boolean'
        ? value.denied
          ? 'deny'
          : value.warn
            ? 'warn'
            : 'allow'
        : null;

  if (!status) {
    return null;
  }

  const decision: Decision = { status };

  if (typeof value.reason === 'string') {
    decision.reason = value.reason;
  }

  if (typeof value.guard === 'string') {
    decision.guard = value.guard;
  }

  if (typeof value.message === 'string') {
    decision.message = value.message;
  }

  if (value.severity === 'low' || value.severity === 'medium' || value.severity === 'high' || value.severity === 'critical') {
    decision.severity = value.severity;
  }

  return decision;
}

function failClosed(error: unknown): Decision {
  const message = error instanceof Error ? error.message : String(error);
  return {
    status: 'deny',
    reason: 'engine_error',
    message,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function formatStderr(chunks: string[]): string {
  const stderr = chunks.join('').trim();
  if (!stderr) {
    return '';
  }
  const truncated = stderr.length > 2048 ? `${stderr.slice(0, 2048)}…` : stderr;
  return ` (stderr: ${truncated})`;
}
