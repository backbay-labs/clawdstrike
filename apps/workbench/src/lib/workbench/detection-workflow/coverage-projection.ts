import type { PolicyTab } from "../multi-policy-store";
import type { FileType } from "../file-type-registry";
import { parseSigmaYaml } from "../sigma-types";
import {
  extractPolicyTechniques,
  extractSigmaTechniques,
  extractYaraTechniques,
} from "../mitre-attack-data";
import type { PublicationManifest } from "./shared-types";
import type { DocumentCoverageEntry } from "./coverage-gap-engine";

const SIGMA_CATEGORY_TO_DATA_SOURCE: Record<string, string[]> = {
  process_creation: ["process", "command"],
  process_access: ["process"],
  file_event: ["file"],
  file_access: ["file"],
  network_connection: ["network"],
  dns_query: ["network"],
  dns: ["network"],
  firewall: ["network"],
};

export function extractDocumentCoverage(
  fileType: FileType,
  source: string,
): Pick<DocumentCoverageEntry, "techniques" | "dataSources"> {
  switch (fileType) {
    case "sigma_rule":
      return extractSigmaCoverage(source);
    case "yara_rule":
      return {
        techniques: extractYaraTechniques(source),
        dataSources: ["file", "artifact"],
      };
    case "clawdstrike_policy":
      return {
        techniques: extractPolicyTechniques(source),
        dataSources: extractPolicyDataSources(source),
      };
    case "ocsf_event":
      return extractOcsfCoverage(source);
    default:
      return {
        techniques: [],
        dataSources: [],
      };
  }
}

export function buildCoverageEntry(
  documentId: string,
  fileType: FileType,
  source: string,
): DocumentCoverageEntry {
  const coverage = extractDocumentCoverage(fileType, source);
  return {
    documentId,
    fileType,
    techniques: coverage.techniques,
    dataSources: coverage.dataSources,
  };
}

export function buildOpenDocumentCoverage(tabs: PolicyTab[]): DocumentCoverageEntry[] {
  return tabs.map((tab) => buildCoverageEntry(tab.documentId, tab.fileType, tab.yaml));
}

export function buildPublishedCoverage(
  manifests: PublicationManifest[],
): DocumentCoverageEntry[] {
  return manifests
    .filter((manifest) => manifest.coverageSnapshot != null)
    .map((manifest) => ({
      documentId: manifest.documentId,
      fileType: manifest.sourceFileType,
      techniques: manifest.coverageSnapshot?.techniques ?? [],
      dataSources: manifest.coverageSnapshot?.dataSources ?? [],
    }));
}

function extractSigmaCoverage(
  source: string,
): Pick<DocumentCoverageEntry, "techniques" | "dataSources"> {
  try {
    const { rule } = parseSigmaYaml(source);
    const tags = Array.isArray(rule?.tags) ? rule.tags : [];
    const techniques = extractSigmaTechniques(tags);
    const category = rule?.logsource?.category?.toLowerCase();
    const dataSources = category
      ? SIGMA_CATEGORY_TO_DATA_SOURCE[category] ?? []
      : [];

    return {
      techniques,
      dataSources,
    };
  } catch {
    return {
      techniques: [],
      dataSources: [],
    };
  }
}

function extractPolicyDataSources(source: string): string[] {
  const dataSources = new Set<string>();
  if (/shell_command:\s*\n\s*enabled:\s*true/m.test(source)) {
    dataSources.add("process");
    dataSources.add("command");
  }
  if (/forbidden_path:\s*\n\s*enabled:\s*true/m.test(source)) {
    dataSources.add("file");
  }
  if (/egress_allowlist:\s*\n\s*enabled:\s*true/m.test(source)) {
    dataSources.add("network");
  }
  if (/mcp_tool:\s*\n\s*enabled:\s*true/m.test(source)) {
    dataSources.add("tool");
  }
  if (/prompt_injection:\s*\n\s*enabled:\s*true/m.test(source)) {
    dataSources.add("prompt");
  }
  return [...dataSources];
}

function extractOcsfCoverage(
  source: string,
): Pick<DocumentCoverageEntry, "techniques" | "dataSources"> {
  try {
    const parsed = JSON.parse(source) as Record<string, unknown>;
    const techniques = new Set<string>();
    const dataSources = new Set<string>();

    const enrichments = parsed.enrichments;
    if (Array.isArray(enrichments)) {
      for (const enrichment of enrichments) {
        if (!enrichment || typeof enrichment !== "object" || Array.isArray(enrichment)) continue;
        const value = (enrichment as Record<string, unknown>).value;
        if (typeof value === "string" && /^T\d{4}(?:\.\d{3})?$/i.test(value)) {
          techniques.add(value.toUpperCase());
        }
      }
    }

    const classUid = parsed.class_uid;
    if (classUid === 1001) {
      dataSources.add("file");
    } else if (classUid === 1007) {
      dataSources.add("process");
      dataSources.add("command");
    } else if (classUid === 4001 || classUid === 4003) {
      dataSources.add("network");
    } else if (classUid === 6003) {
      dataSources.add("tool");
    }

    return {
      techniques: [...techniques],
      dataSources: [...dataSources],
    };
  } catch {
    return {
      techniques: [],
      dataSources: [],
    };
  }
}
