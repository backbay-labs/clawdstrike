const SENSITIVE_GUARD_FIELDS = new Set(["embedding_api_key"]);

/**
 * Strip sensitive fields from YAML before writing it to browser storage.
 *
 * The implementation stays line-based so we preserve surrounding comments and
 * formatting instead of round-tripping the full document through a parser.
 */
export function sanitizeYamlForStorage(yaml: string): string {
  let hasSensitive = false;
  for (const field of SENSITIVE_GUARD_FIELDS) {
    if (yaml.includes(field)) {
      hasSensitive = true;
      break;
    }
  }
  if (!hasSensitive) {
    return yaml;
  }

  return yaml
    .split("\n")
    .filter((line) => {
      const trimmed = line.trimStart();
      for (const field of SENSITIVE_GUARD_FIELDS) {
        if (trimmed.startsWith(`${field}:`) || trimmed.startsWith(`${field} :`)) {
          return false;
        }
      }
      return true;
    })
    .join("\n");
}
