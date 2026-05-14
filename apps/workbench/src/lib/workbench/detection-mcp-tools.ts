// ---- Detection MCP Tool Definitions ----
// MCP tool definitions for detection rule operations. These define the tools
// that the MCP sidecar server can expose to Claude Code for creating, validating,
// listing, and converting detection rules.

export interface McpToolDefinition {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

export const DETECTION_MCP_TOOLS: McpToolDefinition[] = [
  {
    name: "create_sigma_rule",
    description: "Create a new Sigma detection rule in the workbench editor",
    inputSchema: {
      type: "object",
      properties: {
        title: { type: "string", description: "Rule title" },
        logsource_category: {
          type: "string",
          description:
            "Sigma logsource category (e.g., process_creation, network_connection, dns_query, file_event, registry_set)",
        },
        logsource_product: {
          type: "string",
          description: "Sigma logsource product (e.g., windows, linux, aws, azure)",
        },
        detection_field: { type: "string", description: "Primary detection field name (e.g., CommandLine, Image, TargetFilename)" },
        detection_values: {
          type: "array",
          items: { type: "string" },
          description: "Values to match for the detection field",
        },
        level: {
          type: "string",
          enum: ["informational", "low", "medium", "high", "critical"],
          description: "Severity level of the detection rule",
        },
        description: { type: "string", description: "Rule description" },
        mitre_techniques: {
          type: "array",
          items: { type: "string" },
          description: "MITRE ATT&CK technique IDs (e.g., T1059.001, T1003.001)",
        },
      },
      required: ["title", "logsource_category", "detection_field", "detection_values", "level"],
    },
  },
  {
    name: "create_yara_rule",
    description: "Create a new YARA rule in the workbench editor",
    inputSchema: {
      type: "object",
      properties: {
        rule_name: {
          type: "string",
          description: "YARA rule name (no spaces, must be a valid identifier)",
        },
        description: { type: "string", description: "Rule description" },
        strings: {
          type: "array",
          items: {
            type: "object",
            properties: {
              name: { type: "string", description: "String variable name (e.g., s1, hex_pattern)" },
              value: { type: "string", description: "String value or pattern" },
              type: {
                type: "string",
                enum: ["text", "hex", "regex"],
                description: "String type: text for literal, hex for byte patterns, regex for regular expressions",
              },
            },
            required: ["name", "value", "type"],
          },
          description: "Array of string definitions for the YARA rule",
        },
        condition: {
          type: "string",
          description: "YARA condition expression (e.g., 'any of them', '$s1 and $s2', '2 of ($s*)')",
        },
      },
      required: ["rule_name", "strings", "condition"],
    },
  },
  {
    name: "validate_detection_rule",
    description: "Validate a detection rule (Sigma, YARA, or OCSF) and return diagnostics",
    inputSchema: {
      type: "object",
      properties: {
        format: {
          type: "string",
          enum: ["sigma", "yara", "ocsf"],
          description: "The detection rule format to validate against",
        },
        content: {
          type: "string",
          description: "Rule content to validate (full YAML for Sigma, source for YARA, JSON for OCSF)",
        },
      },
      required: ["format", "content"],
    },
  },
  {
    name: "list_detection_rules",
    description: "List all open detection rules in the workbench",
    inputSchema: {
      type: "object",
      properties: {
        format_filter: {
          type: "string",
          enum: ["sigma_rule", "yara_rule", "ocsf_event", "clawdstrike_policy"],
          description: "Optional filter to show only rules of a specific format",
        },
      },
    },
  },
  {
    name: "get_attack_coverage",
    description:
      "Get MITRE ATT&CK coverage summary from all open detection rules. Analyzes Sigma rules for ATT&CK tags and returns technique coverage by tactic.",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "convert_sigma_rule",
    description: "Convert a Sigma rule to another query language",
    inputSchema: {
      type: "object",
      properties: {
        sigma_yaml: {
          type: "string",
          description: "Sigma rule YAML content to convert",
        },
        target_format: {
          type: "string",
          enum: ["spl", "kql", "esql", "native"],
          description:
            "Target query language: spl (Splunk), kql (Microsoft Kusto/Sentinel), esql (Elasticsearch), native (ClawdStrike policy)",
        },
      },
      required: ["sigma_yaml", "target_format"],
    },
  },
];

// ---- Helper: generate a Sigma rule YAML from MCP tool inputs ----

function sanitizeYamlToken(value: string, fallback: string): string {
  const cleaned = value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_.-]+/g, "_")
    .replace(/_+/g, "_")
    .replace(/^_+|_+$/g, "");

  return cleaned || fallback;
}

function sanitizeSigmaField(value: string): string {
  const cleaned = value
    .trim()
    .replace(/[\r\n:]+/g, " ")
    .replace(/\s+/g, "_")
    .replace(/[^A-Za-z0-9_|.-]+/g, "");

  return cleaned || "CommandLine";
}

function yamlSingleQuoted(value: string): string {
  return `'${value.replace(/\r?\n+/g, " ").replace(/'/g, "''")}'`;
}

function yamlBlockScalar(value: string, indent: string = "    "): string[] {
  const normalized = value.replace(/\r\n?/g, "\n");
  const lines = normalized.split("\n");
  return ["|", ...lines.map((line) => `${indent}${line}`)];
}

function sanitizeYaraIdentifier(value: string, fallback: string): string {
  const cleaned = value.replace(/[^A-Za-z0-9_]/g, "_").replace(/_+/g, "_");
  if (/^[A-Za-z_]/.test(cleaned)) {
    return cleaned;
  }
  return fallback;
}

function escapeYaraText(value: string): string {
  return value
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/\r/g, "\\r")
    .replace(/\n/g, "\\n")
    .replace(/\t/g, "\\t");
}

function sanitizeYaraHex(value: string): string {
  const cleaned = value
    .replace(/[^0-9A-Fa-f?\[\]\-\s]/g, " ")
    .replace(/\s+/g, " ")
    .trim();

  return cleaned || "90 90";
}

function sanitizeYaraRegex(value: string): string {
  return value
    .replace(/\\/g, "\\\\")
    .replace(/\//g, "\\/")
    .replace(/\r/g, "\\r")
    .replace(/\n/g, "\\n");
}

/**
 * Generate valid Sigma YAML from MCP `create_sigma_rule` input parameters.
 */
export function generateSigmaFromMcpInput(input: Record<string, unknown>): string {
  const title = String(input.title ?? "Untitled Sigma Rule");
  const id = crypto.randomUUID();
  const description = input.description ? String(input.description) : `Detects ${title.toLowerCase()}.`;
  const category = sanitizeYamlToken(String(input.logsource_category ?? "process_creation"), "process_creation");
  const product = sanitizeYamlToken(
    input.logsource_product ? String(input.logsource_product) : "windows",
    "windows",
  );
  const field = sanitizeSigmaField(String(input.detection_field ?? "CommandLine"));
  const values = Array.isArray(input.detection_values)
    ? (input.detection_values as unknown[]).map(String)
    : ["suspicious"];
  const level = sanitizeYamlToken(String(input.level ?? "medium"), "medium");
  const techniques = Array.isArray(input.mitre_techniques)
    ? (input.mitre_techniques as unknown[]).map(String)
    : [];

  // Build tags
  const tags: string[] = [];
  for (const t of techniques) {
    const tid = sanitizeYamlToken(String(t), "execution");
    // Map common technique prefixes to tactics
    tags.push(`attack.${tid}`);
  }
  if (tags.length === 0) {
    tags.push("attack.execution");
  }

  // Build detection values (using `|contains` modifier for general matching)
  const valuesYaml = values.map((v) => `            - ${yamlSingleQuoted(v)}`).join("\n");
  const tagsYaml = tags.map((t) => `    - ${t}`).join("\n");

  const today = new Date();
  const dateStr = `${today.getFullYear()}/${String(today.getMonth() + 1).padStart(2, "0")}/${String(today.getDate()).padStart(2, "0")}`;

  // Determine the best field modifier based on field name heuristics
  let fieldModifier = "|contains";
  if (field.toLowerCase().includes("image") || field.toLowerCase().includes("path")) {
    fieldModifier = "|endswith";
  }

  const lines = [
    `title: ${yamlSingleQuoted(title)}`,
    `id: ${id}`,
    `status: experimental`,
    `description:`,
    ...yamlBlockScalar(description),
    `author: ClawdStrike Workbench`,
    `date: ${dateStr}`,
    `tags:`,
    tagsYaml,
    `logsource:`,
    `    category: ${category}`,
    `    product: ${product}`,
    `detection:`,
    `    selection:`,
    `        ${field}${fieldModifier}:`,
    valuesYaml,
    `    condition: selection`,
    `falsepositives:`,
    `    - Unknown`,
    `level: ${level}`,
    ``,
  ];

  return lines.join("\n");
}

// ---- Helper: generate a YARA rule from MCP tool inputs ----

/**
 * Generate valid YARA source from MCP `create_yara_rule` input parameters.
 */
export function generateYaraFromMcpInput(input: Record<string, unknown>): string {
  const ruleName = sanitizeYaraIdentifier(String(input.rule_name ?? "untitled_rule"), "untitled_rule");
  const description = input.description ? String(input.description) : "";
  // Sanitize condition to prevent YARA source injection (no newlines, no braces that close the rule)
  const rawCondition = String(input.condition ?? "any of them");
  const condition = rawCondition.replace(/[\n\r]+/g, " ").replace(/[{}]/g, "").trim() || "any of them";

  const today = new Date();
  const dateStr = `${today.getFullYear()}-${String(today.getMonth() + 1).padStart(2, "0")}-${String(today.getDate()).padStart(2, "0")}`;

  // Build string definitions
  interface StringDef {
    name?: unknown;
    value?: unknown;
    type?: unknown;
  }

  const strings: StringDef[] = Array.isArray(input.strings)
    ? (input.strings as StringDef[])
    : [];

  const stringLines: string[] = [];
  for (const s of strings) {
    const name = String(s.name ?? "s1");
    const value = String(s.value ?? "");
    const type = String(s.type ?? "text");

    const normalizedName = sanitizeYaraIdentifier(name.replace(/^\$/, ""), "s1");
    const varName = `$${normalizedName}`;

    switch (type) {
      case "hex":
        stringLines.push(`        ${varName} = { ${sanitizeYaraHex(value)} }`);
        break;
      case "regex":
        stringLines.push(`        ${varName} = /${sanitizeYaraRegex(value)}/`);
        break;
      case "text":
      default:
        stringLines.push(`        ${varName} = "${escapeYaraText(value)}"`);
        break;
    }
  }

  if (stringLines.length === 0) {
    stringLines.push('        $s1 = "pattern"');
  }

  const lines = [
    `rule ${ruleName} {`,
    `    meta:`,
    `        author = "ClawdStrike Workbench"`,
    `        description = "${escapeYaraText(description)}"`,
    `        date = "${dateStr}"`,
    ``,
    `    strings:`,
    ...stringLines,
    ``,
    `    condition:`,
    `        ${condition}`,
    `}`,
    ``,
  ];

  return lines.join("\n");
}
