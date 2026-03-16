// ---- File Type Registry ----
// Central registry mapping detection-engineering file types to their
// language support, validation backend, icons, and colors.

/** Discriminated union of all supported file types. */
export type FileType = "clawdstrike_policy" | "sigma_rule" | "yara_rule" | "ocsf_event";

/** Descriptor for a registered file type. */
export interface FileTypeDescriptor {
  id: FileType;
  /** Human-readable label, e.g. "ClawdStrike Policy". */
  label: string;
  /** Short label for compact UI, e.g. "Policy". */
  shortLabel: string;
  /** Associated file extensions (lowercase, with leading dot). */
  extensions: string[];
  /** Hex color for tab dots and explorer icons. */
  iconColor: string;
  /** Template content for new file creation. */
  defaultContent: string;
  /** Whether this format supports the test runner. */
  testable: boolean;
  /** File types this format can be converted to. */
  convertibleTo: FileType[];
}

// ---- Default content templates ----

const POLICY_DEFAULT_CONTENT = `version: "1.2.0"
name: Untitled Policy
description: ""

guards:
  forbidden_path:
    enabled: true
  egress_allowlist:
    enabled: true
    default_action: block
  secret_leak:
    enabled: true
  shell_command:
    enabled: true

settings:
  fail_fast: false
  verbose_logging: false
`;

const SIGMA_DEFAULT_CONTENT = `title: Untitled Detection Rule
id: 00000000-0000-0000-0000-000000000000
status: experimental
description: |
    Detects ...
author: ""
date: 2026/03/14
tags:
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'suspicious'
    condition: selection
falsepositives:
    - Unknown
level: medium
`;

const YARA_DEFAULT_CONTENT = `rule untitled_rule {
    meta:
        author = ""
        description = ""
        date = "2026-03-14"

    strings:
        $s1 = "pattern"

    condition:
        any of them
}
`;

const OCSF_DEFAULT_CONTENT = JSON.stringify(
  {
    class_uid: 2004,
    category_uid: 2,
    activity_id: 1,
    severity_id: 1,
    status_id: 1,
    time: 0,
    message: "",
    metadata: {
      version: "1.4.0",
      product: {
        name: "ClawdStrike",
        uid: "clawdstrike",
        vendor_name: "Backbay Labs",
      },
    },
    finding_info: {
      uid: "",
      title: "",
    },
  },
  null,
  2,
) + "\n";

// ---- Registry ----

export const FILE_TYPE_REGISTRY: Record<FileType, FileTypeDescriptor> = {
  clawdstrike_policy: {
    id: "clawdstrike_policy",
    label: "ClawdStrike Policy",
    shortLabel: "Policy",
    extensions: [".yaml", ".yml"],
    iconColor: "#d4a84b",
    defaultContent: POLICY_DEFAULT_CONTENT,
    testable: true,
    convertibleTo: ["sigma_rule"],
  },
  sigma_rule: {
    id: "sigma_rule",
    label: "Sigma Rule",
    shortLabel: "Sigma",
    extensions: [".yaml", ".yml"],
    iconColor: "#7c9aef",
    defaultContent: SIGMA_DEFAULT_CONTENT,
    testable: true,
    convertibleTo: ["clawdstrike_policy", "yara_rule"],
  },
  yara_rule: {
    id: "yara_rule",
    label: "YARA Rule",
    shortLabel: "YARA",
    extensions: [".yar", ".yara"],
    iconColor: "#e0915c",
    defaultContent: YARA_DEFAULT_CONTENT,
    testable: true,
    convertibleTo: ["sigma_rule"],
  },
  ocsf_event: {
    id: "ocsf_event",
    label: "OCSF Event",
    shortLabel: "OCSF",
    extensions: [".json"],
    iconColor: "#5cc5c4",
    defaultContent: OCSF_DEFAULT_CONTENT,
    testable: false,
    convertibleTo: [],
  },
};

// ---- Detection helpers ----

export function isPolicyFileType(fileType: FileType): boolean {
  return fileType === "clawdstrike_policy";
}

export function getPrimaryExtension(fileType: FileType): string {
  const [primary] = FILE_TYPE_REGISTRY[fileType].extensions;
  return primary ?? ".yaml";
}

export function sanitizeFilenameStem(name: string, fallback: string): string {
  const cleaned = name
    .trim()
    .replace(/[<>:"/\\|?*\u0000-\u001f]/g, "_")
    .replace(/\s+/g, "_")
    .replace(/_+/g, "_")
    .replace(/^_+|_+$/g, "");

  return cleaned || fallback;
}

/**
 * Returns the file type based solely on file extension, or null if
 * the extension is ambiguous (e.g. `.yaml` could be policy or sigma,
 * `.json` could be an OCSF event or a policy export).
 */
export function getFileTypeByExtension(filename: string): FileType | null {
  const lower = filename.toLowerCase();

  if (lower.endsWith(".yar") || lower.endsWith(".yara")) {
    return "yara_rule";
  }
  // .yaml / .yml are ambiguous between policy and sigma.
  // .json is ambiguous between policy exports, OCSF events, and
  // arbitrary JSON files that should fall back to content heuristics.
  return null;
}

function parseJsonObject(content: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(content) as unknown;
    return parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

function isInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value);
}

function looksLikePolicyJson(content: string): boolean {
  const parsed = parseJsonObject(content);
  if (!parsed) {
    return false;
  }

  return typeof parsed.schema_version === "string" || typeof parsed.guards === "object";
}

function looksLikeOcsfJson(content: string): boolean {
  const parsed = parseJsonObject(content);
  if (!parsed || !isInteger(parsed.class_uid)) {
    return false;
  }

  return (
    isInteger(parsed.category_uid) ||
    (parsed.metadata !== null && typeof parsed.metadata === "object") ||
    (parsed.finding_info !== null && typeof parsed.finding_info === "object")
  );
}

/**
 * Detect the file type from a filename and its content.
 *
 * 1. Unambiguous extensions resolve immediately (.yar/.yara -> yara_rule).
 * 2. Content heuristics disambiguate JSON policy exports / OCSF events.
 * 3. YAML content heuristics disambiguate policy vs sigma.
 * 4. Unknown extensions fall back to clawdstrike_policy.
 */
export function detectFileType(filename: string, content: string): FileType {
  // Step 1 -- unambiguous extensions
  const byExt = getFileTypeByExtension(filename);
  if (byExt !== null) {
    return byExt;
  }

  // Step 2 -- JSON heuristics
  if (looksLikePolicyJson(content)) {
    return "clawdstrike_policy";
  }
  if (looksLikeOcsfJson(content)) {
    return "ocsf_event";
  }

  // Step 3 -- content heuristics (for YAML or unknown extensions)
  if (content.includes("guards:") || content.includes("schema_version:")) {
    return "clawdstrike_policy";
  }
  if (content.includes("detection:") && content.includes("logsource:")) {
    return "sigma_rule";
  }
  if (content.includes("title:") && content.includes("status:") && !content.includes("guards:")) {
    return "sigma_rule";
  }

  // Step 4 -- default fallback
  return "clawdstrike_policy";
}

/**
 * Returns the descriptor for a given FileType. Since the registry is
 * exhaustive over the FileType union this always succeeds.
 */
export function getDescriptor(fileType: FileType): FileTypeDescriptor {
  return FILE_TYPE_REGISTRY[fileType];
}

export function isRegisteredFileType(value: unknown): value is FileType {
  return typeof value === "string" && value in FILE_TYPE_REGISTRY;
}

export function coerceFileType(
  value: unknown,
  fallback: FileType = "clawdstrike_policy",
): FileType {
  return isRegisteredFileType(value) ? value : fallback;
}

/**
 * Extract the filename (basename) from a file path, normalizing
 * backslashes for cross-platform paths. Returns null for empty/null input.
 */
export function basenameFromPath(filePath: string | null | undefined): string | null {
  if (!filePath) return null;
  const normalized = filePath.replace(/\\/g, "/");
  const base = normalized.split("/").pop() ?? "";
  return base || null;
}
