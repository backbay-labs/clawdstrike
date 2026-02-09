/**
 * Output sanitization (secrets + PII) for OpenClaw tool results.
 *
 * This is intentionally conservative and designed to be safe for logs/UI:
 * - Never returns raw match text
 * - Uses stable placeholder labels
 */

export type SanitizationFindingId =
  | 'pii_email'
  | 'pii_phone'
  | 'pii_ssn'
  | 'pii_credit_card';

export interface SanitizationResult {
  sanitized: string;
  redacted: boolean;
  findings: SanitizationFindingId[];
}

const EMAIL_RE = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
const PHONE_RE = /\b(?:\+?1[\s.-]?)?\(?(?:[2-9][0-9]{2})\)?[\s.-]?[0-9]{3}[\s.-]?[0-9]{4}\b/g;
const SSN_RE = /\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b/g;
const CREDIT_CARD_RE = /\b(?:[0-9][ -]*?){13,19}\b/g;

function redactAll(re: RegExp, input: string, replacement: string): { out: string; hit: boolean } {
  re.lastIndex = 0;
  const hit = re.test(input);
  re.lastIndex = 0;
  if (!hit) return { out: input, hit: false };
  const out = input.replace(re, replacement);
  re.lastIndex = 0;
  return { out, hit: true };
}

export function sanitizeOutputText(text: string): SanitizationResult {
  let out = text;
  const findings: SanitizationFindingId[] = [];

  const email = redactAll(EMAIL_RE, out, '[REDACTED:email]');
  out = email.out;
  if (email.hit) findings.push('pii_email');

  const phone = redactAll(PHONE_RE, out, '[REDACTED:phone]');
  out = phone.out;
  if (phone.hit) findings.push('pii_phone');

  const ssn = redactAll(SSN_RE, out, '[REDACTED:ssn]');
  out = ssn.out;
  if (ssn.hit) findings.push('pii_ssn');

  const cc = redactAll(CREDIT_CARD_RE, out, '[REDACTED:credit_card]');
  out = cc.out;
  if (cc.hit) findings.push('pii_credit_card');

  return {
    sanitized: out,
    redacted: findings.length > 0,
    findings,
  };
}

