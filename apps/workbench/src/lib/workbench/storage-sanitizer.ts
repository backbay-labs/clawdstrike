const SENSITIVE_GUARD_FIELDS = new Set(["embedding_api_key"]);

export interface SanitizedStorageYaml {
  yaml: string;
  sensitiveFieldsStripped: boolean;
}

export interface SanitizedStorageValue<T> {
  value: T;
  sensitiveFieldsStripped: boolean;
}

/**
 * Strip sensitive fields from YAML before writing it to browser storage.
 *
 * The implementation stays line-based so we preserve surrounding comments and
 * formatting instead of round-tripping the full document through a parser.
 */
export function sanitizeYamlForStorage(yaml: string): string {
  return sanitizeYamlForStorageWithMetadata(yaml).yaml;
}

export function sanitizeYamlForStorageWithMetadata(yaml: string): SanitizedStorageYaml {
  let hasSensitive = false;
  for (const field of SENSITIVE_GUARD_FIELDS) {
    if (yaml.includes(field)) {
      hasSensitive = true;
      break;
    }
  }
  if (!hasSensitive) {
    return {
      yaml,
      sensitiveFieldsStripped: false,
    };
  }

  const lines = yaml.split("\n");
  const sanitizedLines: string[] = [];

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    const sensitiveMatch = matchSensitiveField(line);
    if (!sensitiveMatch) {
      sanitizedLines.push(line);
      continue;
    }

    const value = sensitiveMatch.value.trimStart();
    if (value.length === 0 || value.startsWith("|") || value.startsWith(">")) {
      i = skipIndentedScalar(lines, i + 1, sensitiveMatch.keyIndent) - 1;
    }
  }

  const sanitizedYaml = sanitizedLines.join("\n");

  return {
    yaml: sanitizedYaml,
    sensitiveFieldsStripped: sanitizedYaml !== yaml,
  };
}

export function sanitizeObjectForStorage<T>(value: T): T {
  return sanitizeObjectForStorageWithMetadata(value).value;
}

export function sanitizeObjectForStorageWithMetadata<T>(value: T): SanitizedStorageValue<T> {
  const sanitized = sanitizeValue(value);
  return {
    value: sanitized.value as T,
    sensitiveFieldsStripped: sanitized.sensitiveFieldsStripped,
  };
}

function matchSensitiveField(line: string): { keyIndent: number; value: string } | null {
  for (const field of SENSITIVE_GUARD_FIELDS) {
    const escapedField = field.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const match = line.match(new RegExp(`^(\\s*)(-\\s*)?${escapedField}\\s*:(.*)$`));
    if (!match) {
      continue;
    }

    const indent = match[1]?.length ?? 0;
    const sequencePrefix = match[2]?.length ?? 0;
    return {
      keyIndent: indent + sequencePrefix,
      value: match[3] ?? "",
    };
  }
  return null;
}

function skipIndentedScalar(lines: string[], startIndex: number, keyIndent: number): number {
  let scalarIndent: number | null = null;
  let index = startIndex;

  while (index < lines.length) {
    const line = lines[index];
    if (line.trim().length === 0) {
      index += 1;
      continue;
    }

    const indent = line.length - line.trimStart().length;
    if (scalarIndent === null) {
      if (indent <= keyIndent) {
        break;
      }
      scalarIndent = indent;
      index += 1;
      continue;
    }

    if (indent < scalarIndent) {
      break;
    }
    index += 1;
  }

  return index;
}

function sanitizeValue(value: unknown): SanitizedStorageValue<unknown> {
  if (Array.isArray(value)) {
    let sensitiveFieldsStripped = false;
    const sanitizedItems = value.map((item) => {
      const sanitized = sanitizeValue(item);
      sensitiveFieldsStripped ||= sanitized.sensitiveFieldsStripped;
      return sanitized.value;
    });
    return {
      value: sanitizedItems,
      sensitiveFieldsStripped,
    };
  }

  if (typeof value !== "object" || value === null) {
    return {
      value,
      sensitiveFieldsStripped: false,
    };
  }

  let sensitiveFieldsStripped = false;
  const sanitizedObject: Record<string, unknown> = {};

  for (const [key, nestedValue] of Object.entries(value)) {
    if (SENSITIVE_GUARD_FIELDS.has(key)) {
      sensitiveFieldsStripped = true;
      continue;
    }

    const sanitized = sanitizeValue(nestedValue);
    sanitizedObject[key] = sanitized.value;
    sensitiveFieldsStripped ||= sanitized.sensitiveFieldsStripped;
  }

  return {
    value: sanitizedObject,
    sensitiveFieldsStripped,
  };
}
