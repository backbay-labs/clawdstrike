export function redactPII(value: string): string {
  let redacted = value;

  redacted = redacted.replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, "[REDACTED_EMAIL]");
  redacted = redacted.replace(/\b\d{3}-\d{2}-\d{4}\b/g, "[REDACTED_SSN]");
  redacted = redacted.replace(/\+?\d[\d\s().-]{8,}\d/g, "[REDACTED_PHONE]");

  return redacted;
}

export function sanitizeAuditText(
  value: string,
  redactSecrets: ((value: string) => string) | undefined,
  redactPii: boolean | undefined,
): string {
  const secretRedacted = redactSecrets ? redactSecrets(value) : value;
  return redactPii ? redactPII(secretRedacted) : secretRedacted;
}
