import { randomUUID } from 'node:crypto';

import { createHushCliEngine } from '@clawdstrike/hush-cli-engine';
import {
  GenericToolBoundary,
  GenericToolCallBlockedError,
  wrapGenericToolDispatcher,
} from '@clawdstrike/adapter-core';

type RequestLike = {
  headers?: Record<string, string | undefined>;
  body?: {
    runId?: string;
    toolName?: string;
    input?: Record<string, unknown>;
  };
};

type ResponseLike = {
  status(code: number): ResponseLike;
  json(payload: unknown): void;
};

const engine = createHushCliEngine({ policyRef: 'default' });
const boundary = new GenericToolBoundary({ engine });

const executeTool = wrapGenericToolDispatcher(
  boundary,
  async (toolName, input, runId) => ({
    ok: true,
    toolName,
    input,
    runId,
  }),
);

export async function toolHandler(req: RequestLike, res: ResponseLike): Promise<void> {
  const runId = req.headers?.['x-run-id'] ?? req.body?.runId ?? randomUUID();
  const toolName = req.body?.toolName ?? 'unknown_tool';
  const input = req.body?.input ?? {};

  try {
    const output = await executeTool(toolName, input, runId);
    res.status(200).json({ ok: true, output });
  } catch (error) {
    if (error instanceof GenericToolCallBlockedError) {
      res.status(403).json({
        ok: false,
        error: 'blocked_by_policy',
        toolName: error.toolName,
        decision: error.decision,
      });
      return;
    }

    res.status(500).json({
      ok: false,
      error: error instanceof Error ? error.message : 'tool_failed',
    });
  }
}
