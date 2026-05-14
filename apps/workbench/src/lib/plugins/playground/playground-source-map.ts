/**
 * Rewrites V8/Chrome stack traces referencing /__plugin-eval/ URLs
 * to show playground.ts:LINE:COL. Sucrase's type-only transform is
 * line-preserving so no offset correction is needed.
 */

const EVAL_FRAME_RE =
  /(\s*at\s+(?:.*?\s+)?\(?)[^\s]*\/__plugin-eval\/\d+\.js:(\d+):(\d+)\)?/g;

export function mapStackTrace(stack: string, _sourceLines: string[]): string {
  return stack.replace(
    EVAL_FRAME_RE,
    (_match, prefix: string, line: string, col: string) => {
      return `${prefix}playground.ts:${line}:${col})`;
    },
  );
}

export function extractErrorLocation(
  stack: string,
): { line: number; column: number } | null {
  const re =
    /\/__plugin-eval\/\d+\.js:(\d+):(\d+)/;
  const match = re.exec(stack);
  if (!match) return null;

  return {
    line: parseInt(match[1], 10),
    column: parseInt(match[2], 10),
  };
}
