/** Convert a camelCase string to snake_case. */
export function camelToSnake(s: string): string {
  return s.replace(/[A-Z]/g, (ch) => `_${ch.toLowerCase()}`);
}

/** Recursively convert all object keys from camelCase to snake_case. */
export function toSnakeCaseKeys(obj: unknown): unknown {
  if (Array.isArray(obj)) return obj.map(toSnakeCaseKeys);
  if (obj !== null && typeof obj === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
      out[camelToSnake(k)] = toSnakeCaseKeys(v);
    }
    return out;
  }
  return obj;
}
