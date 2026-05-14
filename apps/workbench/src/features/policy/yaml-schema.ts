import { GUARD_REGISTRY } from "@/lib/workbench/guard-registry";
import { BUILTIN_RULESETS } from "@/features/policy/builtin-rulesets";
import type { Completion, CompletionContext, CompletionResult, CompletionSource } from "@codemirror/autocomplete";


/** A single completion option with label, insert text, type hint, and detail. */
interface SchemaOption {
  label: string;
  /** Text to insert. Defaults to label if not provided. */
  apply?: string;
  /** Short type hint displayed in the completion widget (e.g. "string", "boolean"). */
  type?: string;
  /** Description shown alongside the completion. */
  detail?: string;
}

/** A node in the schema tree. Children are keyed by the parent YAML key. */
interface SchemaNode {
  /** Completions offered at this level. */
  options: SchemaOption[];
  /** Children keyed by YAML key (e.g. "guards" -> guard-level node). */
  children?: Record<string, SchemaNode>;
}


const BOOLEAN_OPTIONS: SchemaOption[] = [
  { label: "true", type: "keyword", detail: "boolean" },
  { label: "false", type: "keyword", detail: "boolean" },
];

const SCHEMA_VERSIONS: SchemaOption[] = [
  { label: '"1.4.0"', type: "text", detail: "latest (origins)" },
  { label: '"1.3.0"', type: "text", detail: "schema version" },
  { label: '"1.2.0"', type: "text", detail: "schema version" },
  { label: '"1.1.0"', type: "text", detail: "legacy" },
];

const EXTENDS_OPTIONS: SchemaOption[] = BUILTIN_RULESETS.map((r) => ({
  label: `"${r.id}"`,
  type: "text",
  detail: r.description.slice(0, 60),
}));


/** Map config field type to a value hint. */
function fieldTypeHint(field: { type: string; options?: { value: string; label: string }[] }): string {
  switch (field.type) {
    case "toggle":
      return "boolean";
    case "string_list":
    case "pattern_list":
    case "secret_pattern_list":
      return "list";
    case "number_slider":
    case "number_input":
      return "number";
    case "select":
      return "enum";
    default:
      return "value";
  }
}

/** Build value completions for a guard config field. */
function fieldValueOptions(field: {
  key: string;
  type: string;
  options?: { value: string; label: string }[];
  defaultValue?: unknown;
}): SchemaOption[] {
  switch (field.type) {
    case "toggle":
      return BOOLEAN_OPTIONS;
    case "select":
      if (field.options) {
        return field.options.map((o) => ({
          label: `"${o.value}"`,
          type: "text",
          detail: o.label,
        }));
      }
      return [];
    default:
      return [];
  }
}

function buildGuardChildren(): Record<string, SchemaNode> {
  const children: Record<string, SchemaNode> = {};

  for (const guard of GUARD_REGISTRY) {
    const fieldOptions: SchemaOption[] = guard.configFields.map((f) => ({
      label: f.key,
      apply: `${f.key}: `,
      type: "property",
      detail: f.description ?? fieldTypeHint(f),
    }));

    // Build per-field value completions as children
    const fieldChildren: Record<string, SchemaNode> = {};
    for (const f of guard.configFields) {
      const valueOpts = fieldValueOptions(f);
      if (valueOpts.length > 0) {
        fieldChildren[f.key] = { options: valueOpts };
      }
    }

    // Handle dot-notation keys (e.g. "detector.block_threshold" for jailbreak)
    // Group them under their parent key
    const dotFields = guard.configFields.filter((f) => f.key.includes("."));
    if (dotFields.length > 0) {
      const groups = new Map<string, typeof dotFields>();
      for (const f of dotFields) {
        const [parent] = f.key.split(".");
        const existing = groups.get(parent) ?? [];
        existing.push(f);
        groups.set(parent, existing);
      }

      for (const [parent, fields] of groups) {
        const subOptions: SchemaOption[] = fields.map((f) => {
          const subKey = f.key.split(".").slice(1).join(".");
          return {
            label: subKey,
            apply: `${subKey}: `,
            type: "property",
            detail: f.description ?? fieldTypeHint(f),
          };
        });
        // Build value completions for sub-fields
        const subChildren: Record<string, SchemaNode> = {};
        for (const f of fields) {
          const subKey = f.key.split(".").slice(1).join(".");
          const valueOpts = fieldValueOptions(f);
          if (valueOpts.length > 0) {
            subChildren[subKey] = { options: valueOpts };
          }
        }
        fieldChildren[parent] = { options: subOptions, children: subChildren };
      }
    }

    children[guard.id] = {
      options: fieldOptions,
      children: Object.keys(fieldChildren).length > 0 ? fieldChildren : undefined,
    };
  }

  return children;
}


const SETTINGS_NODE: SchemaNode = {
  options: [
    { label: "fail_fast", apply: "fail_fast: ", type: "property", detail: "Halt on first deny" },
    { label: "verbose_logging", apply: "verbose_logging: ", type: "property", detail: "Enable verbose logs" },
    { label: "session_timeout_secs", apply: "session_timeout_secs: ", type: "property", detail: "Session timeout in seconds" },
  ],
  children: {
    fail_fast: { options: BOOLEAN_OPTIONS },
    verbose_logging: { options: BOOLEAN_OPTIONS },
  },
};


const POSTURE_NODE: SchemaNode = {
  options: [
    { label: "initial", apply: "initial: ", type: "property", detail: "Initial posture state" },
    { label: "states", apply: "states:", type: "property", detail: "Posture state definitions" },
    { label: "transitions", apply: "transitions:", type: "property", detail: "State transition rules" },
  ],
  children: {
    states: {
      options: [
        { label: "description", apply: "description: ", type: "property", detail: "State description" },
        { label: "capabilities", apply: "capabilities:", type: "property", detail: "Allowed capabilities in this state" },
        { label: "budgets", apply: "budgets:", type: "property", detail: "Resource budgets" },
      ],
    },
    transitions: {
      options: [
        { label: "from", apply: "from: ", type: "property", detail: "Source state" },
        { label: "to", apply: "to: ", type: "property", detail: "Target state" },
        { label: "on", apply: "on: ", type: "property", detail: "Trigger event" },
        { label: "after", apply: "after: ", type: "property", detail: "Time-based trigger" },
      ],
    },
  },
};


const GUARDS_NODE: SchemaNode = {
  options: GUARD_REGISTRY.map((g) => ({
    label: g.id,
    apply: `${g.id}:`,
    type: "property",
    detail: g.name,
  })),
  children: buildGuardChildren(),
};


const TOP_LEVEL_NODE: SchemaNode = {
  options: [
    { label: "version", apply: "version: ", type: "property", detail: "Policy schema version" },
    { label: "name", apply: "name: ", type: "property", detail: "Policy name" },
    { label: "description", apply: "description: ", type: "property", detail: "Policy description" },
    { label: "schema_version", apply: "schema_version: ", type: "property", detail: "Alias for version" },
    { label: "extends", apply: "extends: ", type: "property", detail: "Base ruleset to inherit" },
    { label: "guards", apply: "guards:", type: "property", detail: "Guard configurations" },
    { label: "settings", apply: "settings:", type: "property", detail: "Engine settings" },
    { label: "posture", apply: "posture:", type: "property", detail: "Posture state machine" },
    { label: "origins", apply: "origins:", type: "property", detail: "Origin-aware enforcement (v1.4.0)" },
  ],
  children: {
    version: { options: SCHEMA_VERSIONS },
    schema_version: { options: SCHEMA_VERSIONS },
    extends: { options: EXTENDS_OPTIONS },
    guards: GUARDS_NODE,
    settings: SETTINGS_NODE,
    posture: POSTURE_NODE,
  },
};


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
}

/**
 * Analyse the document text around the cursor to determine YAML context.
 *
 * This is a heuristic approach based on indentation levels. It walks
 * backwards from the cursor line to build a path of parent keys. The
 * logic: any line with strictly less indentation than the current line
 * (and containing a colon) is considered a parent.
 */
function getCursorContext(ctx: CompletionContext): CursorContext {
  const { state, pos } = ctx;
  const line = state.doc.lineAt(pos);
  const lineText = line.text;
  const textBeforeCursor = lineText.slice(0, pos - line.from);

  // Calculate indentation
  const indentMatch = lineText.match(/^(\s*)/);
  const indent = indentMatch ? indentMatch[1].length : 0;

  // Detect if we are in value position (after a colon on this line)
  const colonIdx = textBeforeCursor.indexOf(":");
  const isValuePosition = colonIdx >= 0;

  // Extract current key
  const keyMatch = lineText.match(/^\s*([a-zA-Z_][a-zA-Z0-9_.-]*)(?:\s*:)?/);
  const currentKey = keyMatch ? keyMatch[1] : null;

  // Calculate prefix (what the user is typing)
  let prefix: string;
  let prefixFrom: number;

  if (isValuePosition) {
    // After the colon — value position
    const afterColon = textBeforeCursor.slice(colonIdx + 1);
    const trimmed = afterColon.replace(/^\s+/, "");
    prefix = trimmed;
    prefixFrom = pos - trimmed.length;
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

  return { indent, path, isValuePosition, currentKey, prefix, prefixFrom };
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

    // For dynamic keys (e.g. state names under posture.states),
    // check if the parent has a wildcard-like child
    // For guards, any key not in the registry means it's a custom guard section
    // For posture states, any key is a dynamic state name
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
 * CodeMirror completion source for ClawdStrike policy YAML files.
 *
 * The source uses a heuristic approach based on indentation and
 * surrounding line content to determine what completions to offer.
 * It does not fully parse the YAML — instead it walks backward from
 * the cursor to build a parent path and then looks up the schema tree.
 */
export const policyYamlCompletionSource: CompletionSource = (
  ctx: CompletionContext,
): CompletionResult | null => {
  // Don't trigger on delete or if explicitly cancelled
  if (!ctx.explicit && !ctx.matchBefore(/\w+/)) return null;

  const cursor = getCursorContext(ctx);
  const { path, isValuePosition, currentKey, prefix, prefixFrom } = cursor;

  // --- Value position: suggest values for the current key ---
  if (isValuePosition && currentKey) {
    // Build full key path including current key
    const fullPath = [...path, currentKey];

    // Try to resolve the node for value completions
    const node = resolveSchemaNode(fullPath);
    if (node && node.options.length > 0) {
      return {
        from: prefixFrom,
        options: node.options.map((o) => toCompletion(o)),
        filter: prefix.length > 0,
      };
    }

    // Special case: any key named "enabled" or ending in _enabled
    if (currentKey === "enabled" || currentKey.endsWith("_enabled")) {
      return {
        from: prefixFrom,
        options: BOOLEAN_OPTIONS.map((o) => toCompletion(o)),
        filter: prefix.length > 0,
      };
    }

    // Special case: keys that commonly hold booleans
    if (["require_balance", "enforce_forbidden_paths", "require_postcondition_probe", "session_aggregation", "fail_fast", "verbose_logging"].includes(currentKey)) {
      return {
        from: prefixFrom,
        options: BOOLEAN_OPTIONS.map((o) => toCompletion(o)),
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
      section = "Policy";
    } else if (path[0] === "guards" && path.length === 1) {
      section = "Guards";
    } else if (path[0] === "guards" && path.length === 2) {
      section = GUARD_REGISTRY.find((g) => g.id === path[1])?.name ?? path[1];
    } else if (path[0] === "settings") {
      section = "Settings";
    } else if (path[0] === "posture") {
      section = "Posture";
    }

    return {
      from: prefixFrom,
      options: node.options.map((o) => toCompletion(o, section)),
      filter: true,
    };
  }

  // If we're inside a guard section that wasn't resolved (e.g. under a
  // dynamic posture state), we may still want to offer the guard's child
  // options. Check if path looks like ["guards", "<guard_id>", "<sub_key>"].
  if (path.length >= 2 && path[0] === "guards") {
    const guardId = path[1];
    const guardNode = GUARDS_NODE.children?.[guardId];
    if (guardNode && path.length === 3) {
      // We're inside a nested object under a guard (e.g. guards.jailbreak.detector)
      const subKey = path[2];
      const subNode = guardNode.children?.[subKey];
      if (subNode) {
        return {
          from: prefixFrom,
          options: subNode.options.map((o) => toCompletion(o, subKey)),
          filter: true,
        };
      }
    }
  }

  // Fallback: if the path includes "posture" and we're at depth 3+,
  // offer posture state fields for dynamic state names
  if (path.length >= 2 && path[0] === "posture" && path[1] === "states") {
    const stateFieldsNode = POSTURE_NODE.children?.states;
    if (stateFieldsNode) {
      return {
        from: prefixFrom,
        options: stateFieldsNode.options.map((o) => toCompletion(o, "Posture State")),
        filter: true,
      };
    }
  }

  return null;
};
