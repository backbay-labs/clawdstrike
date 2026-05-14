const SENSITIVE_PATTERNS = [
  /x-apikey[:\s]+\S+/gi,
  /key[:\s]+\S+/gi,
  /authorization[:\s]+\S+/gi,
  /Bearer\s+\S+/gi,
  /apikey[=:]\S+/gi,
];

export function sanitizeErrorMessage(err: unknown): string {
  const raw = err instanceof Error ? err.message : String(err);
  let sanitized = raw;
  for (const pattern of SENSITIVE_PATTERNS) {
    sanitized = sanitized.replace(pattern, "[REDACTED]");
  }
  // Strip URLs that might contain keys in query params
  sanitized = sanitized.replace(
    /https?:\/\/[^\s]+key=[^\s&]+/gi,
    "[URL_REDACTED]",
  );
  return sanitized;
}
