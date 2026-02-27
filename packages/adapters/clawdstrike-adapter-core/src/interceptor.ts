import type { SecurityContext } from './context.js';
import type { RedactionInfo } from './sanitizer.js';
import type { Decision } from './types.js';

export interface InterceptResult {
  proceed: boolean;
  /** Optional rewritten tool input preserving original input shape. */
  modifiedInput?: unknown;
  /** Optional sanitized/rewritten parameters to dispatch instead of original input. */
  modifiedParameters?: Record<string, unknown>;
  /** Optional synthetic result to return without dispatching the tool. */
  replacementResult?: unknown;
  warning?: string;
  decision: Decision;
  duration: number;
}

export interface ProcessedOutput {
  output: unknown;
  modified: boolean;
  redactions?: RedactionInfo[];
  postDecision?: Decision;
}

export interface ToolInterceptor<TInput = unknown, TOutput = unknown> {
  beforeExecute(
    toolName: string,
    input: TInput,
    context: SecurityContext,
  ): Promise<InterceptResult>;

  afterExecute(
    toolName: string,
    input: TInput,
    output: TOutput,
    context: SecurityContext,
  ): Promise<ProcessedOutput>;

  onError(
    toolName: string,
    input: TInput,
    error: Error,
    context: SecurityContext,
  ): Promise<void>;
}
