/**
 * CodeMirror lint source for ClawdStrike policy YAML.
 *
 * Validates policy documents against the v1.5.0 JSON Schema using Ajv,
 * then maps validation errors back to YAML source positions via the
 * `yaml` library's CST/AST node ranges.
 */
import { linter, type Diagnostic } from '@codemirror/lint';
import Ajv, { type ErrorObject } from 'ajv';
import { parseDocument, isMap, isSeq, isScalar, isPair, type YAMLMap, type YAMLSeq } from 'yaml';
import { policySchema } from './policy-schema';

// ---------------------------------------------------------------------------
// Ajv singleton
// ---------------------------------------------------------------------------

const ajv = new Ajv({ allErrors: true, verbose: true });
const validate = ajv.compile(policySchema);

// ---------------------------------------------------------------------------
// YAML position mapper
// ---------------------------------------------------------------------------

/**
 * Find the character range of a YAML node identified by a JSON Pointer path.
 *
 * Walks through YAML Map/Seq nodes following each segment of the JSON Pointer.
 * Returns `{ from, to }` character offsets suitable for CodeMirror diagnostics.
 *
 * @param yamlText - Raw YAML source text
 * @param jsonPath - JSON Pointer path (e.g. "/guards/forbidden_path")
 * @returns Character range `{ from, to }` in the source text
 */
export function findYamlPosition(
  yamlText: string,
  jsonPath: string,
): { from: number; to: number } {
  const fallbackTo = yamlText.indexOf('\n');
  const fallback = { from: 0, to: fallbackTo > 0 ? fallbackTo : yamlText.length };

  if (!jsonPath || jsonPath === '/') return fallback;

  try {
    const doc = parseDocument(yamlText);
    const segments = jsonPath.replace(/^\//, '').split('/');

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let node: any = doc.contents;

    for (const segment of segments) {
      if (!node) return fallback;

      if (isMap(node)) {
        // Walk the map's items to find the matching key
        const pair = (node as YAMLMap).items.find((item) => {
          if (isPair(item) && isScalar(item.key)) {
            return String(item.key.value) === segment;
          }
          return false;
        });
        if (pair && isPair(pair)) {
          // Move to the value node, but keep the key range for position reporting
          node = pair.value ?? pair.key;
        } else {
          return fallback;
        }
      } else if (isSeq(node)) {
        const index = parseInt(segment, 10);
        if (isNaN(index) || index < 0 || index >= (node as YAMLSeq).items.length) {
          return fallback;
        }
        node = (node as YAMLSeq).items[index];
      } else {
        return fallback;
      }
    }

    if (node && node.range) {
      const from = node.range[0];
      // Limit diagnostic range to a single line to avoid giant multi-line highlights.
      // Find the end of the line containing `from`.
      const lineEnd = yamlText.indexOf('\n', from);
      const to = lineEnd > from ? lineEnd : node.range[1];
      return { from, to: Math.min(to, node.range[1]) };
    }

    return fallback;
  } catch {
    return fallback;
  }
}

// ---------------------------------------------------------------------------
// Error formatter
// ---------------------------------------------------------------------------

/**
 * Format an Ajv validation error into a human-readable message.
 *
 * Special-cases common keywords for clearer guard-level messages:
 * - `additionalProperties`: "Unknown field ..."
 * - `enum`: "... must be one of ..."
 */
export function formatAjvError(error: ErrorObject): string {
  const field = error.instancePath || '/';

  switch (error.keyword) {
    case 'additionalProperties': {
      const extra = (error.params as { additionalProperty?: string }).additionalProperty ?? '?';
      return `Unknown field "${extra}" in ${field || '/'}`;
    }
    case 'enum': {
      const allowed = (error.params as { allowedValues?: string[] }).allowedValues ?? [];
      return `${field}: must be one of ${allowed.join(', ')}`;
    }
    default:
      return `${field}: ${error.message ?? 'validation error'}`;
  }
}

// ---------------------------------------------------------------------------
// CodeMirror linter
// ---------------------------------------------------------------------------

/**
 * CodeMirror lint source that validates policy YAML in real time.
 *
 * 1. Parses the editor text as YAML; surfaces parse errors as diagnostics.
 * 2. Validates the parsed object against the JSON Schema via Ajv.
 * 3. Maps each schema error back to the YAML source position.
 */
export const policyLinter = linter(
  (view) => {
    const text = view.state.doc.toString();
    if (!text.trim()) return [];

    return validatePolicyYaml(text);
  },
  { delay: 300 },
);

/**
 * Validate a YAML string against the policy schema.
 * Exported for direct use in tests without needing a CodeMirror EditorView.
 */
export function validatePolicyYaml(text: string): Diagnostic[] {
  const diagnostics: Diagnostic[] = [];

  // Step 1: Parse YAML
  let doc;
  try {
    doc = parseDocument(text);
  } catch (e) {
    // Fatal parse error (shouldn't normally happen -- parseDocument collects errors)
    diagnostics.push({
      from: 0,
      to: Math.min(text.length, text.indexOf('\n') > 0 ? text.indexOf('\n') : text.length),
      severity: 'error',
      message: `YAML parse error: ${e instanceof Error ? e.message : String(e)}`,
    });
    return diagnostics;
  }

  // Check for YAML parse errors collected by the parser
  if (doc.errors && doc.errors.length > 0) {
    for (const error of doc.errors) {
      const pos = error.pos ?? [0, 1];
      diagnostics.push({
        from: pos[0],
        to: pos[1] > pos[0] ? pos[1] : Math.min(pos[0] + 1, text.length),
        severity: 'error',
        message: `YAML parse error: ${error.message}`,
      });
    }
    return diagnostics;
  }

  // Step 2: Validate against schema
  const json = doc.toJSON();
  if (json === null || json === undefined) return [];

  const valid = validate(json);
  if (valid) return [];

  // Step 3: Map Ajv errors to YAML positions
  if (validate.errors) {
    for (const error of validate.errors) {
      const pos = findYamlPosition(text, error.instancePath);
      diagnostics.push({
        from: pos.from,
        to: pos.to,
        severity: 'error',
        message: formatAjvError(error),
      });
    }
  }

  return diagnostics;
}
