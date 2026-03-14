import type { CompletionContext, CompletionResult, CompletionSource } from "@codemirror/autocomplete";

// OCSF JSON autocomplete completion source for CodeMirror 6
// Provides field and enum completions for OCSF (Open Cybersecurity Schema Framework) events.

/** A completion option with label, insert text, and description. */
interface OcsfOption {
  label: string;
  /** Text to insert. Defaults to label. */
  apply?: string;
  /** Type hint for the completion widget. */
  type?: string;
  /** Description shown alongside the completion. */
  detail?: string;
}


// ---- Enum value options ----

const CLASS_UID_OPTIONS: OcsfOption[] = [
  { label: "1001", type: "enum", detail: "File Activity" },
  { label: "1007", type: "enum", detail: "Process Activity" },
  { label: "2004", type: "enum", detail: "Detection Finding" },
  { label: "4001", type: "enum", detail: "Network Activity" },
];

const SEVERITY_ID_OPTIONS: OcsfOption[] = [
  { label: "0", type: "enum", detail: "Unknown" },
  { label: "1", type: "enum", detail: "Informational" },
  { label: "2", type: "enum", detail: "Low" },
  { label: "3", type: "enum", detail: "Medium" },
  { label: "4", type: "enum", detail: "High" },
  { label: "5", type: "enum", detail: "Critical" },
  { label: "6", type: "enum", detail: "Fatal" },
];

const STATUS_ID_OPTIONS: OcsfOption[] = [
  { label: "0", type: "enum", detail: "Unknown" },
  { label: "1", type: "enum", detail: "Success" },
  { label: "2", type: "enum", detail: "Failure" },
];

const ACTION_ID_OPTIONS: OcsfOption[] = [
  { label: "0", type: "enum", detail: "Unknown" },
  { label: "1", type: "enum", detail: "Allowed" },
  { label: "2", type: "enum", detail: "Denied" },
];

const DISPOSITION_ID_OPTIONS: OcsfOption[] = [
  { label: "1", type: "enum", detail: "Allowed" },
  { label: "2", type: "enum", detail: "Blocked" },
  { label: "17", type: "enum", detail: "Logged" },
];

const ACTIVITY_ID_OPTIONS: OcsfOption[] = [
  { label: "1", type: "enum", detail: "Create" },
  { label: "2", type: "enum", detail: "Update" },
  { label: "3", type: "enum", detail: "Close" },
];


// ---- Field definition maps ----

/** Top-level OCSF fields offered when the cursor is inside the root `{}`. */
const TOP_LEVEL_FIELDS: OcsfOption[] = [
  { label: "class_uid", apply: '"class_uid"', type: "property", detail: "Event class identifier" },
  { label: "category_uid", apply: '"category_uid"', type: "property", detail: "Event category identifier" },
  { label: "activity_id", apply: '"activity_id"', type: "property", detail: "Activity type" },
  { label: "severity_id", apply: '"severity_id"', type: "property", detail: "Severity level" },
  { label: "status_id", apply: '"status_id"', type: "property", detail: "Event status" },
  { label: "time", apply: '"time"', type: "property", detail: "Event timestamp (epoch ms)" },
  { label: "message", apply: '"message"', type: "property", detail: "Event message" },
  { label: "metadata", apply: '"metadata"', type: "property", detail: "Event metadata object" },
  { label: "finding_info", apply: '"finding_info"', type: "property", detail: "Finding information" },
  { label: "actor", apply: '"actor"', type: "property", detail: "Actor object" },
  { label: "resources", apply: '"resources"', type: "property", detail: "Affected resources" },
  { label: "type_uid", apply: '"type_uid"', type: "property", detail: "Event type identifier" },
  { label: "action_id", apply: '"action_id"', type: "property", detail: "Action taken" },
  { label: "disposition_id", apply: '"disposition_id"', type: "property", detail: "Disposition of event" },
];

/** Fields inside the `metadata` object. */
const METADATA_FIELDS: OcsfOption[] = [
  { label: "version", apply: '"version"', type: "property", detail: "OCSF schema version" },
  { label: "product", apply: '"product"', type: "property", detail: "Product object" },
];

/** Fields inside `metadata.product`. */
const PRODUCT_FIELDS: OcsfOption[] = [
  { label: "name", apply: '"name"', type: "property", detail: "Product name" },
  { label: "uid", apply: '"uid"', type: "property", detail: "Product unique ID" },
  { label: "vendor_name", apply: '"vendor_name"', type: "property", detail: "Vendor name" },
  { label: "version", apply: '"version"', type: "property", detail: "Product version" },
];

/** Fields inside `finding_info`. */
const FINDING_INFO_FIELDS: OcsfOption[] = [
  { label: "uid", apply: '"uid"', type: "property", detail: "Finding unique ID" },
  { label: "title", apply: '"title"', type: "property", detail: "Finding title" },
  { label: "desc", apply: '"desc"', type: "property", detail: "Finding description" },
  { label: "analytic", apply: '"analytic"', type: "property", detail: "Analytic object" },
];

/** Fields inside `finding_info.analytic`. */
const ANALYTIC_FIELDS: OcsfOption[] = [
  { label: "name", apply: '"name"', type: "property", detail: "Analytic name" },
  { label: "type_id", apply: '"type_id"', type: "property", detail: "Analytic type ID" },
  { label: "type", apply: '"type"', type: "property", detail: "Analytic type name" },
];


// ---- Value map (key -> enum options) ----

const VALUE_MAP: Record<string, OcsfOption[]> = {
  class_uid: CLASS_UID_OPTIONS,
  category_uid: CLASS_UID_OPTIONS, // category is often derived from class_uid in practice
  severity_id: SEVERITY_ID_OPTIONS,
  status_id: STATUS_ID_OPTIONS,
  action_id: ACTION_ID_OPTIONS,
  disposition_id: DISPOSITION_ID_OPTIONS,
  activity_id: ACTIVITY_ID_OPTIONS,
};


// ---- JSON context analysis ----

/**
 * Determine the JSON object path at the cursor position by scanning backwards
 * through the document text. This is a heuristic approach — it counts braces
 * and looks for the nearest key before each `{` to build a path like
 * `["metadata", "product"]`.
 */
function getJsonPath(text: string, pos: number): { path: string[]; currentKey: string | null; isValuePos: boolean } {
  const before = text.slice(0, pos);

  // Determine if we're in a value position (after a colon) or key position
  // by scanning backward from cursor for the nearest structural character.
  let isValuePos = false;
  let currentKey: string | null = null;

  // Find the last unmatched colon or comma/brace
  let braceDepth = 0;
  let bracketDepth = 0;
  for (let i = before.length - 1; i >= 0; i--) {
    const ch = before[i];
    if (ch === "}") braceDepth++;
    else if (ch === "{") {
      if (braceDepth > 0) braceDepth--;
      else break; // opening brace of the current object
    } else if (ch === "]") bracketDepth++;
    else if (ch === "[") {
      if (bracketDepth > 0) bracketDepth--;
      else break;
    } else if (braceDepth === 0 && bracketDepth === 0) {
      if (ch === ":") {
        isValuePos = true;
        // Extract the key before this colon
        const keySlice = before.slice(0, i);
        const keyMatch = keySlice.match(/"([^"]+)"\s*$/);
        if (keyMatch) {
          currentKey = keyMatch[1];
        }
        break;
      } else if (ch === ",") {
        // After a comma — key position in current object
        isValuePos = false;
        break;
      }
    }
  }

  // Build the object path by scanning for nested `"key": {` patterns
  const path: string[] = [];
  let depth = 0;
  // Track the last key seen before each `{`
  const keyStack: (string | null)[] = [];

  for (let i = 0; i < before.length; i++) {
    const ch = before[i];
    if (ch === '"') {
      // Read the string
      let j = i + 1;
      while (j < before.length && before[j] !== '"') {
        if (before[j] === "\\") j++; // skip escaped chars
        j++;
      }
      const str = before.slice(i + 1, j);
      i = j; // advance past closing quote

      // Check if this is followed by a colon (it's a key)
      let k = i + 1;
      while (k < before.length && /\s/.test(before[k])) k++;
      if (k < before.length && before[k] === ":") {
        // This is a key; remember it for the current depth
        while (keyStack.length <= depth) keyStack.push(null);
        keyStack[depth] = str;
      }
    } else if (ch === "{") {
      // Push the key that preceded this brace into the path
      const key = keyStack[depth] ?? null;
      if (key) {
        path.push(key);
      }
      depth++;
    } else if (ch === "}") {
      depth--;
      if (path.length > depth) {
        path.length = depth;
      }
    }
  }

  return { path, currentKey, isValuePos };
}

/**
 * Find the start of the current token (word boundary) before the cursor,
 * for use as the `from` position of completions.
 */
function getTokenStart(text: string, pos: number): number {
  let i = pos - 1;
  while (i >= 0 && /[a-zA-Z0-9_"]/.test(text[i])) {
    i--;
  }
  return i + 1;
}


// ---- Completion source ----

/**
 * CodeMirror completion source for OCSF event JSON documents.
 *
 * Provides:
 * - Top-level field name completions
 * - Nested field completions for `metadata`, `metadata.product`, `finding_info`, `finding_info.analytic`
 * - Enum value completions for known numeric fields
 */
export const ocsfJsonCompletionSource: CompletionSource = (
  ctx: CompletionContext,
): CompletionResult | null => {
  if (!ctx.explicit && !ctx.matchBefore(/[\w"]/)) return null;

  const docText = ctx.state.doc.toString();
  const { path, currentKey, isValuePos } = getJsonPath(docText, ctx.pos);
  const from = getTokenStart(docText, ctx.pos);

  // Value position — suggest enum values for the current key
  if (isValuePos && currentKey) {
    const enumOptions = VALUE_MAP[currentKey];
    if (enumOptions) {
      return {
        from,
        options: enumOptions.map((o) => ({
          label: o.label,
          type: o.type ?? "enum",
          detail: o.detail,
        })),
        filter: true,
      };
    }
    return null;
  }

  // Key position — suggest field names based on the path
  const pathStr = path.join(".");

  let fields: OcsfOption[] | undefined;
  if (pathStr === "") {
    fields = TOP_LEVEL_FIELDS;
  } else if (pathStr === "metadata") {
    fields = METADATA_FIELDS;
  } else if (pathStr === "metadata.product") {
    fields = PRODUCT_FIELDS;
  } else if (pathStr === "finding_info") {
    fields = FINDING_INFO_FIELDS;
  } else if (pathStr === "finding_info.analytic") {
    fields = ANALYTIC_FIELDS;
  }

  if (fields) {
    return {
      from,
      options: fields.map((o) => ({
        label: o.label,
        apply: o.apply,
        type: o.type ?? "property",
        detail: o.detail,
        section: "OCSF",
      })),
      filter: true,
    };
  }

  return null;
};
