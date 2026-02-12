import { spawn } from 'node:child_process';

import type { Decision, PolicyEngineLike, PolicyEvent } from '@clawdstrike/adapter-core';
import { failClosed, parsePolicyEvalResponse } from '@clawdstrike/adapter-core';

export interface StrikeCellOptions {
  hushPath?: string;
  policyRef: string;
  resolve?: boolean;
  timeoutMs?: number;
}

export function createStrikeCell(options: StrikeCellOptions): PolicyEngineLike {
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
        const response = parsePolicyEvalResponse(output, 'hush');
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

function formatStderr(chunks: string[]): string {
  const stderr = chunks.join('').trim();
  if (!stderr) {
    return '';
  }
  const truncated = stderr.length > 2048 ? `${stderr.slice(0, 2048)}…` : stderr;
  return ` (stderr: ${truncated})`;
}
