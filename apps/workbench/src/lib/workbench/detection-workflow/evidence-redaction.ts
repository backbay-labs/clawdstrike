/**
 * Evidence redaction — strips sensitive fields from evidence items before
 * persistence, export, or swarm publication.
 *
 * This is separate from the existing storage-sanitizer.ts which handles
 * policy YAML sanitization. Evidence packs need their own registry since
 * sensitive data appears in different shapes (event payloads, byte samples,
 * OCSF fields, etc.).
 */

import type { EvidenceItem, EvidencePack, RedactionState } from "./shared-types";

// ---- Sensitive field patterns ----

const SENSITIVE_KEYS = new Set([
  "password",
  "passwd",
  "secret",
  "token",
  "api_key",
  "apikey",
  "api_secret",
  "access_token",
  "refresh_token",
  "private_key",
  "credential",
  "credentials",
  "auth",
  "authorization",
  "cookie",
  "session_id",
  "session_token",
  "bearer",
  "ssn",
  "social_security",
  "credit_card",
  "card_number",
  "cvv",
  "embedding_api_key",
]);

const SENSITIVE_KEY_PATTERN = /(?:password|secret|token|key|credential|auth|bearer|cookie|session)/i;

// ---- Size limits ----

/** Maximum inline size for structured event payloads (64 KiB). */
export const MAX_STRUCTURED_EVENT_SIZE = 64 * 1024;

/** Maximum inline size for byte sample payloads (256 KiB). */
export const MAX_BYTE_SAMPLE_SIZE = 256 * 1024;

// ---- Redaction ----

export interface RedactionResult {
  item: EvidenceItem;
  fieldsRedacted: string[];
  oversized: boolean;
}

export interface PackRedactionResult {
  pack: EvidencePack;
  totalFieldsRedacted: number;
  oversizedItems: string[];
  errors: Array<{ itemId: string; error: string }>;
}

function isSensitiveKey(key: string): boolean {
  return SENSITIVE_KEYS.has(key.toLowerCase()) || SENSITIVE_KEY_PATTERN.test(key);
}

function redactObject(
  obj: Record<string, unknown>,
  path: string,
  redactedPaths: string[],
): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj)) {
    const currentPath = path ? `${path}.${key}` : key;
    if (isSensitiveKey(key)) {
      result[key] = "[REDACTED]";
      redactedPaths.push(currentPath);
    } else if (value && typeof value === "object" && !Array.isArray(value)) {
      result[key] = redactObject(value as Record<string, unknown>, currentPath, redactedPaths);
    } else if (Array.isArray(value)) {
      result[key] = value.map((item, i) => {
        if (item && typeof item === "object" && !Array.isArray(item)) {
          return redactObject(item as Record<string, unknown>, `${currentPath}[${i}]`, redactedPaths);
        }
        return item;
      });
    } else {
      result[key] = value;
    }
  }
  return result;
}

function estimatePayloadSize(payload: unknown): number {
  try {
    return new TextEncoder().encode(JSON.stringify(payload)).length;
  } catch {
    return 0;
  }
}

export function redactEvidenceItem(item: EvidenceItem): RedactionResult {
  const fieldsRedacted: string[] = [];
  let oversized = false;

  switch (item.kind) {
    case "structured_event": {
      const size = estimatePayloadSize(item.payload);
      oversized = size > MAX_STRUCTURED_EVENT_SIZE;
      const redactedPayload = redactObject({ ...item.payload }, "", fieldsRedacted);
      return {
        item: { ...item, payload: redactedPayload },
        fieldsRedacted,
        oversized,
      };
    }

    case "ocsf_event": {
      const size = estimatePayloadSize(item.payload);
      oversized = size > MAX_STRUCTURED_EVENT_SIZE;
      const redactedPayload = redactObject({ ...item.payload }, "", fieldsRedacted);
      return {
        item: { ...item, payload: redactedPayload },
        fieldsRedacted,
        oversized,
      };
    }

    case "bytes": {
      const size = item.payload.length;
      oversized = size > MAX_BYTE_SAMPLE_SIZE;
      return { item, fieldsRedacted, oversized };
    }

    case "policy_scenario": {
      // Policy scenarios don't contain sensitive data in the same way
      return { item, fieldsRedacted, oversized };
    }
  }
}

export function redactEvidencePack(pack: EvidencePack): PackRedactionResult {
  let totalFieldsRedacted = 0;
  const oversizedItems: string[] = [];
  const errors: Array<{ itemId: string; error: string }> = [];
  const redactedDatasets = { ...pack.datasets };

  for (const [datasetKind, items] of Object.entries(redactedDatasets)) {
    redactedDatasets[datasetKind as keyof typeof redactedDatasets] = items.map((item) => {
      try {
        const result = redactEvidenceItem(item);
        totalFieldsRedacted += result.fieldsRedacted.length;
        if (result.oversized) {
          oversizedItems.push(item.id);
        }
        return result.item;
      } catch (err) {
        errors.push({
          itemId: item.id,
          error: err instanceof Error ? err.message : String(err),
        });
        return item;
      }
    });
  }

  const redactionState: RedactionState =
    totalFieldsRedacted > 0 ? "redacted" : pack.redactionState;

  return {
    pack: { ...pack, datasets: redactedDatasets, redactionState },
    totalFieldsRedacted,
    oversizedItems,
    errors,
  };
}
