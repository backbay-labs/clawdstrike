import type { Completion, CompletionContext, CompletionResult, CompletionSource } from "@codemirror/autocomplete";

// Sigma YAML autocomplete completion source for CodeMirror 6
// Follows the same SchemaNode tree pattern as yaml-schema.ts (policyYamlCompletionSource)

/** A single completion option with label, insert text, type hint, and detail. */
interface SchemaOption {
  label: string;
  /** Text to insert. Defaults to label if not provided. */
  apply?: string;
  /** Short type hint displayed in the completion widget (e.g. "string", "enum"). */
  type?: string;
  /** Description shown alongside the completion. */
  detail?: string;
}

/** A node in the schema tree. Children are keyed by the parent YAML key. */
interface SchemaNode {
  /** Completions offered at this level. */
  options: SchemaOption[];
  /** Children keyed by YAML key (e.g. "logsource" -> logsource-level node). */
  children?: Record<string, SchemaNode>;
}


// ---- Enum options ----

const STATUS_OPTIONS: SchemaOption[] = [
  { label: "experimental", type: "enum", detail: "rule status" },
  { label: "test", type: "enum", detail: "rule status" },
  { label: "stable", type: "enum", detail: "rule status" },
  { label: "deprecated", type: "enum", detail: "rule status" },
  { label: "unsupported", type: "enum", detail: "rule status" },
];

const LEVEL_OPTIONS: SchemaOption[] = [
  { label: "informational", type: "enum", detail: "severity level" },
  { label: "low", type: "enum", detail: "severity level" },
  { label: "medium", type: "enum", detail: "severity level" },
  { label: "high", type: "enum", detail: "severity level" },
  { label: "critical", type: "enum", detail: "severity level" },
];

const CATEGORY_OPTIONS: SchemaOption[] = [
  { label: "process_creation", type: "text", detail: "process created" },
  { label: "file_event", type: "text", detail: "file system event" },
  { label: "file_change", type: "text", detail: "file modification" },
  { label: "file_rename", type: "text", detail: "file renamed" },
  { label: "file_delete", type: "text", detail: "file deleted" },
  { label: "network_connection", type: "text", detail: "network connection" },
  { label: "dns_query", type: "text", detail: "DNS query" },
  { label: "registry_add", type: "text", detail: "registry key added" },
  { label: "registry_set", type: "text", detail: "registry value set" },
  { label: "registry_delete", type: "text", detail: "registry key deleted" },
  { label: "registry_event", type: "text", detail: "generic registry event" },
  { label: "image_load", type: "text", detail: "image/DLL loaded" },
  { label: "driver_load", type: "text", detail: "driver loaded" },
  { label: "pipe_created", type: "text", detail: "named pipe created" },
  { label: "wmi_event", type: "text", detail: "WMI event" },
  { label: "clipboard_capture", type: "text", detail: "clipboard access" },
  { label: "process_access", type: "text", detail: "process accessed" },
  { label: "process_tampering", type: "text", detail: "process tampered" },
];

const PRODUCT_OPTIONS: SchemaOption[] = [
  { label: "windows", type: "text", detail: "Microsoft Windows" },
  { label: "linux", type: "text", detail: "Linux" },
  { label: "macos", type: "text", detail: "Apple macOS" },
  { label: "azure", type: "text", detail: "Microsoft Azure" },
  { label: "aws", type: "text", detail: "Amazon Web Services" },
  { label: "gcp", type: "text", detail: "Google Cloud Platform" },
  { label: "m365", type: "text", detail: "Microsoft 365" },
  { label: "okta", type: "text", detail: "Okta IAM" },
  { label: "github", type: "text", detail: "GitHub" },
  { label: "google_workspace", type: "text", detail: "Google Workspace" },
];

const SERVICE_OPTIONS: SchemaOption[] = [
  { label: "sysmon", type: "text", detail: "Sysmon" },
  { label: "security", type: "text", detail: "Windows Security" },
  { label: "system", type: "text", detail: "Windows System" },
  { label: "powershell", type: "text", detail: "PowerShell" },
  { label: "dns-server", type: "text", detail: "DNS Server" },
  { label: "firewall", type: "text", detail: "Windows Firewall" },
  { label: "application", type: "text", detail: "Application log" },
];

const CONDITION_OPERATORS: SchemaOption[] = [
  { label: "and", type: "keyword", detail: "logical AND" },
  { label: "or", type: "keyword", detail: "logical OR" },
  { label: "not", type: "keyword", detail: "logical NOT" },
  { label: "1 of", type: "keyword", detail: "any one matches" },
  { label: "all of", type: "keyword", detail: "all must match" },
  { label: "them", type: "keyword", detail: "all named selections" },
];

const ATTACK_TAGS: SchemaOption[] = [
  { label: "attack.initial_access", type: "text", detail: "TA0001" },
  { label: "attack.execution", type: "text", detail: "TA0002" },
  { label: "attack.persistence", type: "text", detail: "TA0003" },
  { label: "attack.privilege_escalation", type: "text", detail: "TA0004" },
  { label: "attack.defense_evasion", type: "text", detail: "TA0005" },
  { label: "attack.credential_access", type: "text", detail: "TA0006" },
  { label: "attack.discovery", type: "text", detail: "TA0007" },
  { label: "attack.lateral_movement", type: "text", detail: "TA0008" },
  { label: "attack.collection", type: "text", detail: "TA0009" },
  { label: "attack.exfiltration", type: "text", detail: "TA0010" },
  { label: "attack.command_and_control", type: "text", detail: "TA0011" },
  { label: "attack.impact", type: "text", detail: "TA0040" },
  { label: "attack.resource_development", type: "text", detail: "TA0042" },
  { label: "attack.reconnaissance", type: "text", detail: "TA0043" },
];

const MODIFIERS: SchemaOption[] = [
  { label: "contains", type: "keyword", detail: "substring match" },
  { label: "startswith", type: "keyword", detail: "prefix match" },
  { label: "endswith", type: "keyword", detail: "suffix match" },
  { label: "all", type: "keyword", detail: "all values must match" },
  { label: "base64", type: "keyword", detail: "base64-decode value" },
  { label: "base64offset", type: "keyword", detail: "base64 with offset" },
  { label: "re", type: "keyword", detail: "regular expression" },
  { label: "cidr", type: "keyword", detail: "CIDR notation match" },
  { label: "utf16le", type: "keyword", detail: "UTF-16 LE encoding" },
  { label: "utf16be", type: "keyword", detail: "UTF-16 BE encoding" },
  { label: "utf16", type: "keyword", detail: "UTF-16 encoding" },
  { label: "wide", type: "keyword", detail: "wide string match" },
  { label: "cased", type: "keyword", detail: "case-sensitive match" },
  { label: "windash", type: "keyword", detail: "normalize Windows dashes" },
  { label: "exists", type: "keyword", detail: "field existence check" },
  { label: "expand", type: "keyword", detail: "expand placeholders" },
];


// ---- Schema tree ----

const LOGSOURCE_NODE: SchemaNode = {
  options: [
    { label: "category", apply: "category: ", type: "property", detail: "log category" },
    { label: "product", apply: "product: ", type: "property", detail: "target product" },
    { label: "service", apply: "service: ", type: "property", detail: "log service" },
    { label: "definition", apply: "definition: ", type: "property", detail: "custom definition" },
  ],
  children: {
    category: { options: CATEGORY_OPTIONS },
    product: { options: PRODUCT_OPTIONS },
    service: { options: SERVICE_OPTIONS },
  },
};

const DETECTION_NODE: SchemaNode = {
  options: [
    { label: "selection", apply: "selection:", type: "property", detail: "selection block" },
    { label: "filter", apply: "filter:", type: "property", detail: "filter block" },
    { label: "condition", apply: "condition: ", type: "property", detail: "detection condition" },
  ],
  children: {
    condition: { options: CONDITION_OPERATORS },
  },
};

const TOP_LEVEL_NODE: SchemaNode = {
  options: [
    { label: "title", apply: "title: ", type: "property", detail: "rule title (required)" },
    { label: "id", apply: "id: ", type: "property", detail: "UUID identifier" },
    { label: "related", apply: "related:", type: "property", detail: "related rules" },
    { label: "status", apply: "status: ", type: "property", detail: "rule status" },
    { label: "description", apply: "description: ", type: "property", detail: "rule description" },
    { label: "references", apply: "references:", type: "property", detail: "reference URLs" },
    { label: "author", apply: "author: ", type: "property", detail: "rule author" },
    { label: "date", apply: "date: ", type: "property", detail: "creation date (YYYY/MM/DD)" },
    { label: "modified", apply: "modified: ", type: "property", detail: "last modified (YYYY/MM/DD)" },
    { label: "tags", apply: "tags:", type: "property", detail: "ATT&CK tags" },
    { label: "logsource", apply: "logsource:", type: "property", detail: "log source definition" },
    { label: "detection", apply: "detection:", type: "property", detail: "detection logic" },
    { label: "falsepositives", apply: "falsepositives:", type: "property", detail: "known false positives" },
    { label: "level", apply: "level: ", type: "property", detail: "severity level" },
    { label: "fields", apply: "fields:", type: "property", detail: "output fields" },
  ],
  children: {
    status: { options: STATUS_OPTIONS },
    level: { options: LEVEL_OPTIONS },
    logsource: LOGSOURCE_NODE,
    detection: DETECTION_NODE,
  },
};


// ---- Cursor context analysis ----

/**
 * Describes where the cursor sits in the YAML document, derived from
 * indentation and the content of surrounding lines.
 */
interface CursorContext {
  /** Indentation level (number of leading spaces) of the current line. */
  indent: number;
  /** The path of parent keys leading to the current cursor position. */
  path: string[];
  /** Whether the cursor is positioned after a colon (i.e. in value position). */
  isValuePosition: boolean;
  /** The key on the current line (if any), before the colon. */
  currentKey: string | null;
  /** The text the user has typed so far on this line (for filtering). */
  prefix: string;
  /** Start position of the prefix in the document. */
  prefixFrom: number;
  /** Whether the current line is a list item (starts with `- `). */
  isListItem: boolean;
  /** Whether the current token looks like a modifier (contains `|`). */
  isModifierPosition: boolean;
}

/**
 * Analyse the document text around the cursor to determine YAML context.
 *
 * Walks backwards from the cursor line to build a path of parent keys,
 * using indentation to determine nesting depth.
 */
function getCursorContext(ctx: CompletionContext): CursorContext {
  const { state, pos } = ctx;
  const line = state.doc.lineAt(pos);
  const lineText = line.text;
  const textBeforeCursor = lineText.slice(0, pos - line.from);

  // Calculate indentation
  const indentMatch = lineText.match(/^(\s*)/);
  const indent = indentMatch ? indentMatch[1].length : 0;

  // Detect list item
  const isListItem = /^\s*-\s/.test(lineText);

  // Detect if we are in value position (after a colon on this line)
  const colonIdx = textBeforeCursor.indexOf(":");
  const isValuePosition = colonIdx >= 0 && !isListItem;

  // Detect modifier position: user is typing a field name containing `|`
  const isModifierPosition = textBeforeCursor.includes("|");

  // Extract current key
  const keyMatch = lineText.match(/^\s*-?\s*([a-zA-Z_][a-zA-Z0-9_.-]*)(?:\|[a-zA-Z|]*)?(?:\s*:)?/);
  const currentKey = keyMatch ? keyMatch[1] : null;

  // Calculate prefix (what the user is typing)
  let prefix: string;
  let prefixFrom: number;

  if (isModifierPosition) {
    // After a pipe — modifier position
    const lastPipe = textBeforeCursor.lastIndexOf("|");
    const afterPipe = textBeforeCursor.slice(lastPipe + 1);
    prefix = afterPipe;
    prefixFrom = pos - afterPipe.length;
  } else if (isValuePosition) {
    // After the colon — value position
    const afterColon = textBeforeCursor.slice(colonIdx + 1);
    const trimmed = afterColon.replace(/^\s+/, "");
    prefix = trimmed;
    prefixFrom = pos - trimmed.length;
  } else if (isListItem) {
    // After "- " in a list item
    const dashMatch = textBeforeCursor.match(/^\s*-\s*(.*)/);
    const afterDash = dashMatch ? dashMatch[1] : "";
    prefix = afterDash;
    prefixFrom = pos - afterDash.length;
  } else {
    // Key position — everything after leading whitespace
    const afterIndent = textBeforeCursor.replace(/^\s+/, "");
    prefix = afterIndent;
    prefixFrom = line.from + indent;
  }

  // Walk backward to build the parent path
  const path: string[] = [];
  let currentIndent = indent;
  const lineNum = line.number;

  for (let i = lineNum - 1; i >= 1; i--) {
    const prevLine = state.doc.line(i);
    const prevText = prevLine.text;

    // Skip blank lines and comments
    if (/^\s*$/.test(prevText) || /^\s*#/.test(prevText)) continue;

    const prevIndentMatch = prevText.match(/^(\s*)/);
    const prevIndent = prevIndentMatch ? prevIndentMatch[1].length : 0;

    if (prevIndent < currentIndent) {
      const prevKeyMatch = prevText.match(/^\s*([a-zA-Z_][a-zA-Z0-9_.-]*)\s*:/);
      if (prevKeyMatch) {
        path.unshift(prevKeyMatch[1]);
        currentIndent = prevIndent;
        // Stop if we've reached the top level
        if (prevIndent === 0) break;
      }
    }
  }

  return { indent, path, isValuePosition, currentKey, prefix, prefixFrom, isListItem, isModifierPosition };
}


/**
 * Walk the schema tree using the resolved path and return the matching
 * SchemaNode, or null if no match exists.
 */
function resolveSchemaNode(path: string[]): SchemaNode | null {
  let node: SchemaNode = TOP_LEVEL_NODE;

  for (const segment of path) {
    if (!node.children) return null;

    // Direct match
    if (node.children[segment]) {
      node = node.children[segment];
      continue;
    }

    // Dynamic keys (e.g. user-defined selection names under detection)
    return null;
  }

  return node;
}


/** Convert a SchemaOption to a CodeMirror Completion object. */
function toCompletion(opt: SchemaOption, sectionLabel?: string): Completion {
  const c: Completion = {
    label: opt.label,
    type: opt.type ?? "text",
    detail: opt.detail,
    boost: 0,
  };
  if (opt.apply) {
    c.apply = opt.apply;
  }
  if (sectionLabel) {
    c.section = sectionLabel;
  }
  return c;
}


/**
 * CodeMirror completion source for Sigma rule YAML files.
 *
 * Uses indentation-based heuristics to determine what completions to
 * offer depending on cursor position: top-level keys, logsource fields,
 * detection blocks, value enums, ATT&CK tags, and value modifiers.
 */
export const sigmaYamlCompletionSource: CompletionSource = (
  ctx: CompletionContext,
): CompletionResult | null => {
  // Don't trigger on delete or if explicitly cancelled
  if (!ctx.explicit && !ctx.matchBefore(/\w+/)) return null;

  const cursor = getCursorContext(ctx);
  const { path, isValuePosition, currentKey, prefix, prefixFrom, isListItem, isModifierPosition } = cursor;

  // --- Modifier position: suggest value modifiers after `|` ---
  if (isModifierPosition) {
    return {
      from: prefixFrom,
      options: MODIFIERS.map((o) => toCompletion(o, "Modifiers")),
      filter: true,
    };
  }

  // --- List item context: suggest list values based on parent key ---
  if (isListItem) {
    // tags list items get ATT&CK tag completions
    const parentKey = path[path.length - 1];
    if (parentKey === "tags") {
      return {
        from: prefixFrom,
        options: ATTACK_TAGS.map((o) => toCompletion(o, "ATT&CK")),
        filter: true,
      };
    }
    return null;
  }

  // --- Value position: suggest values for the current key ---
  if (isValuePosition && currentKey) {
    const fullPath = [...path, currentKey];
    const node = resolveSchemaNode(fullPath);
    if (node && node.options.length > 0) {
      return {
        from: prefixFrom,
        options: node.options.map((o) => toCompletion(o)),
        filter: prefix.length > 0,
      };
    }
    return null;
  }

  // --- Key position: suggest keys at the current level ---
  const node = resolveSchemaNode(path);
  if (node) {
    // Determine section label based on path context
    let section: string | undefined;
    if (path.length === 0) {
      section = "Sigma Rule";
    } else if (path[0] === "logsource") {
      section = "Log Source";
    } else if (path[0] === "detection") {
      section = "Detection";
    }

    return {
      from: prefixFrom,
      options: node.options.map((o) => toCompletion(o, section)),
      filter: true,
    };
  }

  return null;
};
