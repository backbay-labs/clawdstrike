// ---- File Type Registry ----
// Central registry mapping detection-engineering file types to their
// language support, validation backend, icons, and colors.
// Supports dynamic registration of plugin file types at runtime.

export type FileType = string;

export const BUILTIN_FILE_TYPES = [
  "clawdstrike_policy",
  "sigma_rule",
  "yara_rule",
  "ocsf_event",
  "receipt",
  "swarm_bundle",
] as const;

export type BuiltinFileType = (typeof BUILTIN_FILE_TYPES)[number];

export interface FileTypeDescriptor {
  id: FileType;
  label: string;
  shortLabel: string;
  extensions: string[];
  iconColor: string;
  defaultContent: string;
  testable: boolean;
  convertibleTo: FileType[];
}

export interface FileTypeRegistrationOptions extends FileTypeDescriptor {
  detect?: (filename: string, content: string) => boolean;
}

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

const OCSF_DEFAULT_CONTENT =
  JSON.stringify(
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

const BUILTIN_FILE_TYPE_DESCRIPTORS: FileTypeDescriptor[] = [
  {
    id: "clawdstrike_policy",
    label: "ClawdStrike Policy",
    shortLabel: "Policy",
    extensions: [".yaml", ".yml"],
    iconColor: "#d4a84b",
    defaultContent: POLICY_DEFAULT_CONTENT,
    testable: true,
    convertibleTo: ["sigma_rule"],
  },
  {
    id: "sigma_rule",
    label: "Sigma Rule",
    shortLabel: "Sigma",
    extensions: [".yaml", ".yml"],
    iconColor: "#7c9aef",
    defaultContent: SIGMA_DEFAULT_CONTENT,
    testable: true,
    convertibleTo: ["clawdstrike_policy", "yara_rule"],
  },
  {
    id: "yara_rule",
    label: "YARA Rule",
    shortLabel: "YARA",
    extensions: [".yar", ".yara"],
    iconColor: "#e0915c",
    defaultContent: YARA_DEFAULT_CONTENT,
    testable: true,
    convertibleTo: ["sigma_rule"],
  },
  {
    id: "ocsf_event",
    label: "OCSF Event",
    shortLabel: "OCSF",
    extensions: [".json"],
    iconColor: "#5cc5c4",
    defaultContent: OCSF_DEFAULT_CONTENT,
    testable: false,
    convertibleTo: [],
  },
  {
    id: "swarm_bundle",
    label: "Swarm Bundle",
    shortLabel: "Swarm",
    extensions: [".swarm"],
    iconColor: "#8b5cf6",
    defaultContent: "",
    testable: false,
    convertibleTo: [],
  },
  {
    id: "receipt",
    label: "Receipt / Evidence",
    shortLabel: "Receipt",
    extensions: [".receipt", ".hush"],
    iconColor: "#7ee6f2",
    defaultContent: "",
    testable: false,
    convertibleTo: [],
  },
];

const fileTypeMap = new Map<string, FileTypeDescriptor>();
const customDetectors = new Map<string, (filename: string, content: string) => boolean>();

for (const descriptor of BUILTIN_FILE_TYPE_DESCRIPTORS) {
  fileTypeMap.set(descriptor.id, descriptor);
}

export function registerFileType(options: FileTypeRegistrationOptions): () => void {
  const { detect, ...descriptor } = options;
  if (fileTypeMap.has(descriptor.id)) {
    throw new Error(`File type "${descriptor.id}" is already registered`);
  }

  fileTypeMap.set(descriptor.id, descriptor);
  if (detect) {
    customDetectors.set(descriptor.id, detect);
  }

  return () => {
    fileTypeMap.delete(descriptor.id);
    customDetectors.delete(descriptor.id);
  };
}

export function unregisterFileType(id: string): void {
  fileTypeMap.delete(id);
  customDetectors.delete(id);
}

export function getAllFileTypes(): FileTypeDescriptor[] {
  return Array.from(fileTypeMap.values());
}

export const FILE_TYPE_REGISTRY: Record<string, FileTypeDescriptor> = new Proxy(
  {} as Record<string, FileTypeDescriptor>,
  {
    get(_target, prop: string) {
      if (typeof prop === "symbol") return undefined;
      return fileTypeMap.get(prop);
    },
    ownKeys() {
      return Array.from(fileTypeMap.keys());
    },
    getOwnPropertyDescriptor(_target, prop: string) {
      if (typeof prop === "symbol") return undefined;
      if (!fileTypeMap.has(prop)) return undefined;
      return {
        configurable: true,
        enumerable: true,
        value: fileTypeMap.get(prop),
      };
    },
    has(_target, prop: string) {
      if (typeof prop === "symbol") return false;
      return fileTypeMap.has(prop);
    },
  },
);

export function isPolicyFileType(fileType: FileType): boolean {
  return fileType === "clawdstrike_policy";
}

export function getPrimaryExtension(fileType: FileType): string {
  const descriptor = fileTypeMap.get(fileType);
  if (!descriptor) return ".yaml";
  return descriptor.extensions[0] ?? ".yaml";
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

export function getFileTypeByExtension(filename: string): FileType | null {
  const lower = filename.toLowerCase();

  if (lower.endsWith(".receipt") || lower.endsWith(".hush")) {
    return "receipt";
  }
  if (lower.endsWith(".yar") || lower.endsWith(".yara")) {
    return "yara_rule";
  }
  if (lower.endsWith(".swarm")) {
    return "swarm_bundle";
  }

  for (const [id, descriptor] of fileTypeMap) {
    if ((BUILTIN_FILE_TYPES as readonly string[]).includes(id)) continue;
    for (const extension of descriptor.extensions) {
      if (lower.endsWith(extension.toLowerCase())) {
        return id;
      }
    }
  }

  return null;
}

function parseJsonObject(content: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(content) as unknown;
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      return null;
    }
    return parsed as Record<string, unknown>;
  } catch {
    return null;
  }
}

function isInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value);
}

function looksLikePolicyJson(content: string): boolean {
  const parsed = parseJsonObject(content);
  if (!parsed) return false;

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

export function detectFileType(filename: string, content: string): FileType {
  const byExtension = getFileTypeByExtension(filename);
  if (byExtension !== null) {
    return byExtension;
  }

  if (looksLikePolicyJson(content)) {
    return "clawdstrike_policy";
  }
  if (looksLikeOcsfJson(content)) {
    return "ocsf_event";
  }

  if (content.includes("guards:") || content.includes("schema_version:")) {
    return "clawdstrike_policy";
  }
  if (content.includes("detection:") && content.includes("logsource:")) {
    return "sigma_rule";
  }
  if (content.includes("title:") && content.includes("status:") && !content.includes("guards:")) {
    return "sigma_rule";
  }

  for (const [id, detect] of customDetectors) {
    if (detect(filename, content)) {
      return id;
    }
  }

  return "clawdstrike_policy";
}

export function getDescriptor(fileType: FileType): FileTypeDescriptor {
  const descriptor = fileTypeMap.get(fileType);
  if (!descriptor) {
    throw new Error(`Unknown file type: ${fileType}`);
  }
  return descriptor;
}

export function isRegisteredFileType(value: unknown): value is FileType {
  return typeof value === "string" && fileTypeMap.has(value);
}

export function coerceFileType(
  value: unknown,
  fallback: FileType = "clawdstrike_policy",
): FileType {
  return isRegisteredFileType(value) ? value : fallback;
}

export function basenameFromPath(filePath: string | null | undefined): string | null {
  if (!filePath) return null;
  const normalized = filePath.replace(/\\/g, "/");
  const basename = normalized.split("/").pop() ?? "";
  return basename || null;
}
