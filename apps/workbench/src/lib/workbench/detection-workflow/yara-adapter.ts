/**
 * YARA workflow adapter — implements DetectionWorkflowAdapter for yara_rule.
 *
 * Generates YARA rule stubs from DraftSeeds that contain binary or artifact
 * evidence. Provides stub implementations for lab execution (requires the
 * yara-x backend) and publication.
 */

import type { DetectionWorkflowAdapter } from "./adapters";
import { registerAdapter } from "./adapters";
import type {
  DraftSeed,
  DetectionDocumentRef,
  EvidencePack,
  EvidenceItem,
  LabRun,
  ExplainabilityTrace,
} from "./shared-types";
import { createEmptyDatasets } from "./shared-types";
import type {
  DetectionExecutionRequest,
  DetectionExecutionResult,
  DraftBuildResult,
  PublicationRequest,
  PublicationBuildResult,
  ReportArtifact,
} from "./execution-types";

// ---- SHA-256 ----

async function sha256Hex(text: string): Promise<string> {
  const data = new TextEncoder().encode(text);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data.buffer as ArrayBuffer);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ---- Rule Name Sanitization ----

function sanitizeRuleName(id: string): string {
  // YARA rule names: alphanumeric + underscore, must start with letter or _
  return (
    "rule_" +
    id
      .replace(/[^a-zA-Z0-9_]/g, "_")
      .replace(/_+/g, "_")
      .slice(0, 48)
  );
}

// ---- String Pattern Extraction ----

interface YaraString {
  name: string;
  value: string;
  isHex: boolean;
}

interface ParsedYaraStringDefinition {
  name: string;
  bytes: Uint8Array;
  line: number;
}

interface ParsedYaraRule {
  strings: ParsedYaraStringDefinition[];
  condition: string;
  conditionLine: number;
}

function extractStrings(seed: DraftSeed): YaraString[] {
  const strings: YaraString[] = [];
  let idx = 1;

  const targets = seed.extractedFields["targets"] as string[] | undefined;
  const commands = seed.extractedFields["commands"] as string[] | undefined;
  const paths = seed.extractedFields["paths"] as string[] | undefined;
  const contents = seed.sourceEventIds
    .map((eventId) => seed.extractedFields[eventId] as Record<string, unknown> | undefined)
    .map((eventData) => (typeof eventData?.["content"] === "string" ? eventData.content : undefined))
    .filter((content): content is string => Boolean(content));

  // Extract string patterns from artifact content first, then telemetry fields.
  const candidates = [
    ...contents,
    ...(commands ?? []),
    ...(paths ?? []),
    ...(targets ?? []),
  ];

  const seen = new Set<string>();
  for (const candidate of candidates) {
    if (!candidate || seen.has(candidate) || candidate.length < 3) continue;
    seen.add(candidate);

    // Check if it looks like hex
    if (/^[0-9a-fA-F\s]+$/.test(candidate) && candidate.length >= 4) {
      strings.push({
        name: `$h${idx}`,
        value: normalizeHexPattern(candidate),
        isHex: true,
      });
    } else {
      strings.push({
        name: `$s${idx}`,
        value: candidate,
        isHex: false,
      });
    }
    idx++;

    // Limit to 10 strings
    if (idx > 10) break;
  }

  // If no strings were extracted, add a placeholder
  if (strings.length === 0) {
    strings.push({ name: "$s1", value: "pattern", isHex: false });
  }

  return strings;
}

// ---- Meta Builder ----

function buildMeta(seed: DraftSeed): string {
  const lines: string[] = [];
  const today = new Date().toISOString().slice(0, 10);

  lines.push(`        author = "Detection Lab"`);
  lines.push(
    `        description = "Auto-generated YARA rule from ${seed.kind} seed"`,
  );
  lines.push(`        date = "${today}"`);

  if (seed.techniqueHints.length > 0) {
    lines.push(
      `        technique = "${seed.techniqueHints.join(", ")}"`,
    );
  }

  return lines.join("\n");
}

function utf8Bytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function normalizeHexPattern(value: string): string {
  const cleaned = value.replace(/[^0-9a-fA-F]/g, "");
  if (cleaned.length < 2) {
    return value.trim().replace(/\s+/g, " ");
  }
  const evenLength = cleaned.length - (cleaned.length % 2);
  const evenCleaned = cleaned.slice(0, evenLength);
  return evenCleaned.match(/.{1,2}/g)?.join(" ") ?? value.trim().replace(/\s+/g, " ");
}

function decodeEscapedYaraString(value: string): string {
  try {
    return JSON.parse(`"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`) as string;
  } catch {
    return value;
  }
}

function parseHexString(value: string): Uint8Array {
  const cleaned = normalizeHexPattern(value)
    .trim()
    .split(/\s+/)
    .filter((token) => /^[0-9a-fA-F]{2}$/.test(token))
    .map((token) => Number.parseInt(token, 16));
  return Uint8Array.from(cleaned);
}

function parseYaraRule(source: string): ParsedYaraRule {
  const lines = source.split(/\r?\n/);
  const strings: ParsedYaraStringDefinition[] = [];
  let inStrings = false;
  let inCondition = false;
  let conditionLine = 0;
  const conditionLines: string[] = [];

  for (let index = 0; index < lines.length; index++) {
    const line = lines[index];
    const trimmed = line.trim();

    if (/^strings\s*:/i.test(trimmed)) {
      inStrings = true;
      inCondition = false;
      continue;
    }
    if (/^condition\s*:/i.test(trimmed)) {
      inStrings = false;
      inCondition = true;
      conditionLine = index + 1;
      const inlineCondition = trimmed.replace(/^condition\s*:/i, "").trim();
      if (inlineCondition.length > 0) {
        conditionLines.push(inlineCondition);
      }
      continue;
    }

    if (inStrings) {
      const textMatch = /^\s*(\$\w+)\s*=\s*"((?:\\.|[^"])*)"/.exec(line);
      if (textMatch) {
        strings.push({
          name: textMatch[1],
          bytes: utf8Bytes(decodeEscapedYaraString(textMatch[2])),
          line: index + 1,
        });
        continue;
      }

      const hexMatch = /^\s*(\$\w+)\s*=\s*\{([^}]+)\}/.exec(line);
      if (hexMatch) {
        strings.push({
          name: hexMatch[1],
          bytes: parseHexString(hexMatch[2]),
          line: index + 1,
        });
      }
      continue;
    }

    if (inCondition) {
      if (trimmed === "}") {
        break;
      }
      if (trimmed.length > 0) {
        conditionLines.push(trimmed);
      }
    }
  }

  return {
    strings,
    condition: conditionLines.join(" ").trim() || "any of them",
    conditionLine,
  };
}

function bytesFromEvidenceItem(item: EvidenceItem): Uint8Array {
  if (item.kind === "bytes") {
    if (item.encoding === "hex") {
      return parseHexString(item.payload);
    }
    if (item.encoding === "base64") {
      const normalized =
        typeof Buffer !== "undefined"
          ? Buffer.from(item.payload, "base64")
          : Uint8Array.from(atob(item.payload), (char) => char.charCodeAt(0));
      return normalized instanceof Uint8Array ? normalized : new Uint8Array(normalized);
    }
    return utf8Bytes(item.payload);
  }

  if (item.kind === "structured_event" || item.kind === "ocsf_event") {
    return utf8Bytes(JSON.stringify(item.payload));
  }

  if (item.kind === "policy_scenario") {
    return utf8Bytes(JSON.stringify(item.scenario));
  }

  return new Uint8Array();
}

function findMatches(
  haystack: Uint8Array,
  needle: Uint8Array,
): Array<{ offset: number; length: number }> {
  if (needle.length === 0 || haystack.length < needle.length) return [];
  const matches: Array<{ offset: number; length: number }> = [];

  for (let index = 0; index <= haystack.length - needle.length; index++) {
    let matched = true;
    for (let inner = 0; inner < needle.length; inner++) {
      if (haystack[index + inner] !== needle[inner]) {
        matched = false;
        break;
      }
    }
    if (matched) {
      matches.push({ offset: index, length: needle.length });
    }
  }

  return matches;
}

function resolveNameGroup(pattern: string, names: string[]): string[] {
  const trimmed = pattern.trim();
  if (trimmed === "them") {
    return names;
  }
  if (trimmed.startsWith("$") && trimmed.endsWith("*")) {
    const prefix = trimmed.slice(0, -1);
    return names.filter((name) => name.startsWith(prefix));
  }
  return trimmed
    .split(",")
    .map((part) => part.trim())
    .filter((part) => part.startsWith("$"))
    .flatMap((part) => resolveNameGroup(part, names));
}

function evaluateSimpleExpression(
  expression: string,
  matchedNames: Set<string>,
  availableNames: string[],
): boolean {
  let resolved = expression
    .replace(/\bany of them\b/gi, matchedNames.size > 0 ? "true" : "false")
    .replace(/\ball of them\b/gi, availableNames.every((name) => matchedNames.has(name)) ? "true" : "false")
    .replace(/(\d+)\s+of\s+them/gi, (_, count) =>
      matchedNames.size >= Number.parseInt(String(count), 10) ? "true" : "false",
    )
    .replace(/any of \(([^)]+)\)/gi, (_, group) =>
      resolveNameGroup(String(group), availableNames).some((name) => matchedNames.has(name))
        ? "true"
        : "false",
    )
    .replace(/all of \(([^)]+)\)/gi, (_, group) =>
      resolveNameGroup(String(group), availableNames).every((name) => matchedNames.has(name))
        ? "true"
        : "false",
    );

  for (const name of availableNames) {
    const escaped = name.replace(/\$/g, "\\$");
    resolved = resolved.replace(new RegExp(escaped, "g"), matchedNames.has(name) ? "true" : "false");
  }

  const normalized = resolved
    .replace(/\band\b/gi, "&&")
    .replace(/\bor\b/gi, "||")
    .replace(/\bnot\b/gi, "!");

  if (!/^[\s()!&|truefals]+$/i.test(normalized)) {
    return matchedNames.size > 0;
  }

  try {
    return Function(`"use strict"; return (${normalized});`)() === true;
  } catch {
    return matchedNames.size > 0;
  }
}

// ---- YARA Adapter ----

const yaraAdapter: DetectionWorkflowAdapter = {
  fileType: "yara_rule",

  canDraftFrom(seed: DraftSeed): boolean {
    // True ONLY when byte or artifact evidence exists
    const hints = seed.dataSourceHints;
    return (
      hints.includes("binary") ||
      hints.includes("artifact") ||
      (hints.includes("file") && hasByteContent(seed))
    );
  },

  buildDraft(seed: DraftSeed): DraftBuildResult {
    const ruleName = sanitizeRuleName(seed.id);
    const meta = buildMeta(seed);
    const strings = extractStrings(seed);

    // Build strings section
    const stringsSection = strings
      .map((s) => {
        if (s.isHex) {
          return `        ${s.name} = { ${s.value} }`;
        }
        // Escape quotes in string values
        const escaped = s.value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
        return `        ${s.name} = "${escaped}"`;
      })
      .join("\n");

    const source = `rule ${ruleName} {
    meta:
${meta}

    strings:
${stringsSection}

    condition:
        any of them
}
`;

    return {
      source,
      fileType: "yara_rule",
      name: ruleName,
      techniqueHints: seed.techniqueHints,
    };
  },

  buildStarterEvidence(seed: DraftSeed, document: DetectionDocumentRef): EvidencePack {
    const datasets = createEmptyDatasets();

    // Check if we have byte content in extracted fields
    const hasByteSources = seed.dataSourceHints.includes("binary") ||
      seed.dataSourceHints.includes("artifact");

    if (hasByteSources) {
      // Create bytes items from source events
      for (const eventId of seed.sourceEventIds) {
        const eventData = seed.extractedFields[eventId] as Record<string, unknown> | undefined;
        const content = eventData?.["content"] as string | undefined;

        if (content) {
          const normalizedHex = normalizeHexPattern(content);
          const isHexPayload = normalizedHex.length >= 2 && /^[0-9a-fA-F\s]+$/.test(normalizedHex);
          const item: EvidenceItem = {
            id: crypto.randomUUID(),
            kind: "bytes",
            encoding: isHexPayload ? "hex" : "utf8",
            payload: isHexPayload ? normalizedHex : content,
            expected: "match",
            sourceArtifactPath: eventData?.["target"] as string | undefined,
          };
          datasets.positive.push(item);
        }
      }
    }

    // If no byte items were created, fall back to structured events
    if (datasets.positive.length === 0) {
      for (const eventId of seed.sourceEventIds) {
        const eventData = seed.extractedFields[eventId] as Record<string, unknown> | undefined;
        const item: EvidenceItem = {
          id: crypto.randomUUID(),
          kind: "structured_event",
          format: "json",
          payload: eventData ?? { eventId, source: seed.kind },
          expected: "match",
          sourceEventId: eventId,
        };
        datasets.positive.push(item);
      }
    }

    return {
      id: crypto.randomUUID(),
      documentId: document.documentId,
      fileType: "yara_rule",
      title: `YARA starter pack from ${seed.kind}`,
      createdAt: new Date().toISOString(),
      derivedFromSeedId: seed.id,
      datasets,
      redactionState: "clean",
    };
  },

  async runLab(request: DetectionExecutionRequest): Promise<DetectionExecutionResult> {
    const startedAt = new Date().toISOString();
    const source = request.adapterRunConfig?.["yaraSource"] as string | undefined;
    const parsedRule = parseYaraRule(source ?? "");
    const allItems: Array<{ item: EvidenceItem; dataset: keyof EvidencePack["datasets"] }> = [];

    for (const [datasetKind, items] of Object.entries(request.evidencePack.datasets)) {
      for (const item of items) {
        allItems.push({
          item,
          dataset: datasetKind as keyof EvidencePack["datasets"],
        });
      }
    }

    const results: LabRun["results"] = [];
    const traces: ExplainabilityTrace[] = [];

    for (const { item, dataset } of allItems) {
      const haystack = bytesFromEvidenceItem(item);
      const caseId = item.id;
      const matchesByName = new Map<string, Array<{ offset: number; length: number }>>();

      for (const definition of parsedRule.strings) {
        const matches = findMatches(haystack, definition.bytes);
        if (matches.length > 0) {
          matchesByName.set(definition.name, matches);
        }
      }

      const matchedNames = new Set(matchesByName.keys());
      const didMatch = evaluateSimpleExpression(
        parsedRule.condition,
        matchedNames,
        parsedRule.strings.map((definition) => definition.name),
      );

      const expectedMatch = item.expected === "match";
      const passed = expectedMatch === didMatch;
      const traceId = crypto.randomUUID();

      results.push({
        caseId,
        dataset,
        status: passed ? "pass" : "fail",
        expected: expectedMatch ? "match" : "no_match",
        actual: didMatch ? "match" : "no_match",
        explanationRefIds: [traceId],
      });

      const matchedStrings = [...matchesByName.entries()].flatMap(([name, matches]) =>
        matches.map((match) => ({
          name,
          offset: match.offset,
          length: match.length,
        })),
      );
      const sourceLineHints = new Set<number>();
      for (const definition of parsedRule.strings) {
        if (matchedNames.has(definition.name)) {
          sourceLineHints.add(definition.line);
        }
      }
      if (parsedRule.conditionLine > 0) {
        sourceLineHints.add(parsedRule.conditionLine);
      }

      traces.push({
        id: traceId,
        kind: "yara_match",
        caseId,
        matchedStrings,
        conditionSummary: parsedRule.condition,
        sourceLineHints: [...sourceLineHints].sort((a, b) => a - b),
      });
    }

    const passedCount = results.filter((result) => result.status === "pass").length;
    const failedCount = results.filter((result) => result.status === "fail").length;
    const matchedCount = results.filter((result) => result.actual === "match").length;
    const missedCount = results.filter(
      (result) => result.expected === "match" && result.actual === "no_match",
    ).length;
    const falsePositives = results.filter(
      (result) => result.expected === "no_match" && result.actual === "match",
    ).length;
    const completedAt = new Date().toISOString();

    const run: LabRun = {
      id: crypto.randomUUID(),
      documentId: request.document.documentId,
      evidencePackId: request.evidencePack.id,
      fileType: "yara_rule",
      startedAt,
      completedAt,
      summary: {
        totalCases: results.length,
        passed: passedCount,
        failed: failedCount,
        matched: matchedCount,
        missed: missedCount,
        falsePositives,
        engine: "client",
      },
      results,
      explainability: traces,
    };

    const reportArtifacts: ReportArtifact[] = [
      {
        id: crypto.randomUUID(),
        kind: "summary",
        title: `YARA lab: ${passedCount}/${results.length} passed`,
        data: {
          matchedStrings: traces.reduce(
            (count, trace) => count + (trace.kind === "yara_match" ? trace.matchedStrings.length : 0),
            0,
          ),
        },
      },
    ];

    return { run, coverage: null, reportArtifacts };
  },

  buildExplainability(run: LabRun): ExplainabilityTrace[] {
    return run.explainability;
  },

  async buildPublication(request: PublicationRequest): Promise<PublicationBuildResult> {
    const outputContent =
      request.targetFormat === "json_export"
        ? JSON.stringify(
            {
              kind: "yara_rule",
              source: request.source,
            },
            null,
            2,
          )
        : request.source;
    const sourceHash = await sha256Hex(request.source);
    const outputHash = await sha256Hex(outputContent);

    return {
      manifest: {
        documentId: request.document.documentId,
        sourceFileType: "yara_rule",
        target: request.targetFormat,
        sourceHash,
        outputHash,
        validationSnapshot: {
          valid: true,
          diagnosticCount: 0,
        },
        runSnapshot:
          request.labRunId && request.evidencePackId
            ? {
                evidencePackId: request.evidencePackId,
                labRunId: request.labRunId,
                passed: true,
              }
            : null,
        coverageSnapshot: null,
        converter: {
          id: request.targetFormat === "json_export" ? "yara-to-json" : "yara-identity",
          version: "1.0.0",
        },
        signer: null,
        provenance: null,
      },
      outputContent,
      outputHash,
    };
  },
};

// ---- Helper ----

function hasByteContent(seed: DraftSeed): boolean {
  for (const eventId of seed.sourceEventIds) {
    const eventData = seed.extractedFields[eventId] as Record<string, unknown> | undefined;
    if (eventData?.["content"] && typeof eventData["content"] === "string") {
      const content = eventData["content"] as string;
      // Check for binary-looking content
      if (/^[0-9a-fA-F\s]+$/.test(content.slice(0, 200))) return true;
      // eslint-disable-next-line no-control-regex
      if (/[\x00-\x08\x0e-\x1f]/.test(content.slice(0, 200))) return true;
    }
  }
  return false;
}

// ---- Auto-register ----

registerAdapter(yaraAdapter);

export { yaraAdapter };
