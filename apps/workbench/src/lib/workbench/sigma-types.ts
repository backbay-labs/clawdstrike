import YAML from "yaml";

// ---- Sigma rule type definitions ----

export type SigmaStatus = "experimental" | "test" | "stable" | "deprecated" | "unsupported";
export type SigmaLevel = "informational" | "low" | "medium" | "high" | "critical";

export interface SigmaLogsource {
  category?: string;
  product?: string;
  service?: string;
  definition?: string;
}

export interface SigmaDetection {
  [key: string]: unknown; // selection blocks are dynamic
  condition: string;
}

export interface SigmaRule {
  title: string;
  id: string;
  status: SigmaStatus;
  description?: string;
  references?: string[];
  author?: string;
  date?: string;
  modified?: string;
  tags?: string[];
  logsource: SigmaLogsource;
  detection: SigmaDetection;
  falsepositives?: string[];
  level: SigmaLevel;
  fields?: string[];
}

// ---- Constants ----

const VALID_STATUSES: readonly string[] = ["experimental", "test", "stable", "deprecated", "unsupported"];
const VALID_LEVELS: readonly string[] = ["informational", "low", "medium", "high", "critical"];

// ---- Parser ----

/**
 * Parse a YAML string into a SigmaRule, collecting validation errors.
 *
 * Returns the parsed rule (if structurally valid enough) and any errors
 * found. A rule can be partially valid — callers should check the errors
 * array to determine whether the rule should be treated as usable.
 */
export function parseSigmaYaml(yamlText: string): { rule: SigmaRule | null; errors: string[] } {
  const errors: string[] = [];

  // Step 1 — parse the YAML
  let doc: unknown;
  try {
    doc = YAML.parse(yamlText);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    return { rule: null, errors: [`YAML parse error: ${msg}`] };
  }

  if (doc == null || typeof doc !== "object" || Array.isArray(doc)) {
    return { rule: null, errors: ["Document must be a YAML mapping"] };
  }

  const obj = doc as Record<string, unknown>;

  // Step 2 — validate required fields

  if (typeof obj.title !== "string" || obj.title.trim() === "") {
    errors.push("Missing required field: title");
  }

  if (typeof obj.id !== "string" || obj.id.trim() === "") {
    errors.push("Missing required field: id");
  }

  // status
  if (obj.status == null) {
    errors.push("Missing required field: status");
  } else if (typeof obj.status !== "string" || !VALID_STATUSES.includes(obj.status)) {
    errors.push(`Invalid status: "${String(obj.status)}" — expected one of: ${VALID_STATUSES.join(", ")}`);
  }

  // level
  if (obj.level == null) {
    errors.push("Missing required field: level");
  } else if (typeof obj.level !== "string" || !VALID_LEVELS.includes(obj.level)) {
    errors.push(`Invalid level: "${String(obj.level)}" — expected one of: ${VALID_LEVELS.join(", ")}`);
  }

  // logsource
  if (obj.logsource == null) {
    errors.push("Missing required field: logsource");
  } else if (typeof obj.logsource !== "object" || Array.isArray(obj.logsource)) {
    errors.push("logsource must be a mapping");
  }

  // detection
  if (obj.detection == null) {
    errors.push("Missing required field: detection");
  } else if (typeof obj.detection !== "object" || Array.isArray(obj.detection)) {
    errors.push("detection must be a mapping");
  } else {
    const det = obj.detection as Record<string, unknown>;
    if (typeof det.condition !== "string" || det.condition.trim() === "") {
      errors.push("detection.condition is required and must be a non-empty string");
    }
  }

  // Step 3 — validate optional fields with type checks

  if (obj.description != null && typeof obj.description !== "string") {
    errors.push("description must be a string");
  }

  if (obj.author != null && typeof obj.author !== "string") {
    errors.push("author must be a string");
  }

  if (obj.date != null && typeof obj.date !== "string") {
    errors.push("date must be a string");
  }

  if (obj.modified != null && typeof obj.modified !== "string") {
    errors.push("modified must be a string");
  }

  if (obj.references != null && !Array.isArray(obj.references)) {
    errors.push("references must be a list");
  }

  if (obj.tags != null && !Array.isArray(obj.tags)) {
    errors.push("tags must be a list");
  }

  if (obj.falsepositives != null && !Array.isArray(obj.falsepositives)) {
    errors.push("falsepositives must be a list");
  }

  if (obj.fields != null && !Array.isArray(obj.fields)) {
    errors.push("fields must be a list");
  }

  // Step 4 — build the rule if no critical errors prevent it
  if (errors.length > 0) {
    // Still attempt to build a partial rule if the basic structure is present
    const hasTitle = typeof obj.title === "string" && obj.title.trim() !== "";
    const hasDetection = obj.detection != null && typeof obj.detection === "object" && !Array.isArray(obj.detection);
    if (!hasTitle || !hasDetection) {
      return { rule: null, errors };
    }
  }

  const rule: SigmaRule = {
    title: String(obj.title ?? ""),
    id: String(obj.id ?? ""),
    status: (VALID_STATUSES.includes(String(obj.status)) ? obj.status : "experimental") as SigmaStatus,
    description: obj.description != null ? String(obj.description) : undefined,
    references: Array.isArray(obj.references) ? obj.references.map(String) : undefined,
    author: obj.author != null ? String(obj.author) : undefined,
    date: obj.date != null ? String(obj.date) : undefined,
    modified: obj.modified != null ? String(obj.modified) : undefined,
    tags: Array.isArray(obj.tags) ? obj.tags.map(String) : undefined,
    logsource: (typeof obj.logsource === "object" && obj.logsource != null
      ? obj.logsource
      : {}) as SigmaLogsource,
    detection: (typeof obj.detection === "object" && obj.detection != null
      ? obj.detection
      : { condition: "" }) as SigmaDetection,
    falsepositives: Array.isArray(obj.falsepositives) ? obj.falsepositives.map(String) : undefined,
    level: (VALID_LEVELS.includes(String(obj.level)) ? obj.level : "medium") as SigmaLevel,
    fields: Array.isArray(obj.fields) ? obj.fields.map(String) : undefined,
  };

  return { rule, errors };
}
