import { yamlToPolicy } from "@/features/policy/yaml-utils";
import {
  controlHeaders,
  isRecord,
  jsonFetch,
  preferredUrl,
  proxyUrl,
  readNumber,
  readString,
  readStringArray,
} from "./internal";
import type {
  CatalogCategoryInfo,
  CatalogTemplate,
  FleetConnection,
} from "./types";

function deriveCatalogDifficulty(tags: string[]): string {
  const value = tags.find((tag) => tag.startsWith("difficulty:"))?.slice("difficulty:".length);
  return value === "beginner" || value === "intermediate" || value === "advanced"
    ? value
    : "intermediate";
}

function deriveCatalogCompliance(tags: string[]): string[] {
  const normalized = new Set(tags.map((tag) => tag.toLowerCase()));
  const compliance: string[] = [];
  if (normalized.has("hipaa")) compliance.push("HIPAA");
  if (normalized.has("soc2")) compliance.push("SOC2");
  if (normalized.has("pci-dss") || normalized.has("pci_dss")) compliance.push("PCI-DSS");
  return compliance;
}

function deriveCatalogGuardSummary(policyYaml: string): string[] {
  const [policy] = yamlToPolicy(policyYaml);
  if (!policy) return [];

  return Object.entries(policy.guards)
    .filter(([, config]) => isRecord(config) && config.enabled !== false)
    .map(([guard]) => guard)
    .sort();
}

function normalizeCatalogTags(tags: string[], difficulty?: string): string[] {
  const base = tags.filter((tag) => !tag.startsWith("difficulty:"));
  if (difficulty) base.push(`difficulty:${difficulty}`);
  return Array.from(new Set(base));
}

function toCatalogTemplate(value: unknown): CatalogTemplate {
  if (!isRecord(value) || typeof value.id !== "string" || typeof value.name !== "string") {
    throw new Error("[fleet-client] catalog template response shape is invalid");
  }

  if (typeof value.yaml === "string") {
    const tags = readStringArray(value.tags);
    return {
      id: value.id,
      name: value.name,
      description: readString(value.description) ?? "",
      category: readString(value.category) ?? "general",
      tags,
      author: readString(value.author) ?? "Unknown",
      version: readString(value.version) ?? "1.0.0",
      yaml: value.yaml,
      guard_summary: readStringArray(value.guard_summary),
      use_cases: readStringArray(value.use_cases),
      compliance: readStringArray(value.compliance),
      difficulty: readString(value.difficulty) ?? deriveCatalogDifficulty(tags),
      downloads: readNumber(value.downloads) ?? 0,
      created_at: readString(value.created_at) ?? new Date(0).toISOString(),
      updated_at: readString(value.updated_at) ?? new Date(0).toISOString(),
      metadata: isRecord(value.metadata) ? value.metadata : undefined,
    };
  }

  if (typeof value.policy_yaml !== "string") {
    throw new Error("[fleet-client] catalog template response is missing policy_yaml");
  }

  const tags = readStringArray(value.tags);
  const policyYaml = value.policy_yaml;
  return {
    id: value.id,
    name: value.name,
    description: readString(value.description) ?? "",
    category: readString(value.category) ?? "general",
    tags,
    author: readString(value.author) ?? "Unknown",
    version: readString(value.version) ?? "1.0.0",
    yaml: policyYaml,
    guard_summary: deriveCatalogGuardSummary(policyYaml),
    use_cases: [],
    compliance: deriveCatalogCompliance(tags),
    difficulty: deriveCatalogDifficulty(tags),
    downloads: readNumber(value.downloads) ?? 0,
    created_at: readString(value.created_at) ?? new Date(0).toISOString(),
    updated_at: readString(value.updated_at) ?? new Date(0).toISOString(),
    metadata: isRecord(value.metadata) ? value.metadata : undefined,
  };
}

function toCatalogCategory(value: unknown): CatalogCategoryInfo {
  if (!isRecord(value) || typeof value.id !== "string") {
    throw new Error("[fleet-client] catalog category response shape is invalid");
  }

  const label = readString(value.label) ?? readString(value.name);
  if (!label) {
    throw new Error("[fleet-client] catalog category response is missing label/name");
  }

  return {
    id: value.id,
    label,
    color: readString(value.color) ?? "#6f7f9a",
    count: readNumber(value.count) ?? readNumber(value.template_count) ?? 0,
  };
}

function normalizeCatalogFetchError(error: unknown): Error {
  const message = error instanceof Error ? error.message : String(error);
  if (message.includes("HTTP 404")) {
    return new Error("Catalog endpoints are unavailable on the configured control API");
  }
  return error instanceof Error ? error : new Error(message);
}

export async function fetchCatalogTemplates(
  conn: FleetConnection,
  opts?: { category?: string; tag?: string },
): Promise<CatalogTemplate[]> {
  const { url, kind } = preferredUrl(conn);
  if (!url) return [];

  const params = new URLSearchParams();
  if (opts?.category) params.set("category", opts.category);
  if (opts?.tag) params.set("tag", opts.tag);
  const qs = params.toString();
  const endpoint = `${url}/api/v1/catalog/templates${qs ? `?${qs}` : ""}`;

  try {
    const res = await jsonFetch<unknown>(
      proxyUrl(endpoint, kind),
      { headers: controlHeaders(conn) },
    );

    // Handle wrapped or bare array responses
    let list: unknown[];
    if (Array.isArray(res)) {
      list = res;
    } else if (res && typeof res === "object" && "templates" in res) {
      const wrapped = res as { templates: unknown };
      if (!Array.isArray(wrapped.templates)) {
        throw new Error("[fleet-client] fetchCatalogTemplates: expected templates to be an array");
      }
      list = wrapped.templates;
    } else {
      throw new Error("[fleet-client] fetchCatalogTemplates: unexpected response shape");
    }

    return list.map(toCatalogTemplate);
  } catch (e) {
    throw normalizeCatalogFetchError(e);
  }
}

export async function fetchCatalogTemplate(
  conn: FleetConnection,
  id: string,
): Promise<CatalogTemplate | null> {
  const { url, kind } = preferredUrl(conn);
  if (!url) return null;

  try {
    const res = await jsonFetch<unknown>(
      proxyUrl(`${url}/api/v1/catalog/templates/${encodeURIComponent(id)}`, kind),
      { headers: controlHeaders(conn) },
    );

    if (isRecord(res) && "template" in res) {
      return toCatalogTemplate(res.template);
    }
    return toCatalogTemplate(res);
  } catch (e) {
    console.warn("[fleet-client] fetchCatalogTemplate failed:", e);
    return null;
  }
}

export async function publishCatalogTemplate(
  conn: FleetConnection,
  template: {
    name: string;
    description: string;
    category: string;
    tags: string[];
    yaml: string;
    difficulty?: string;
  },
): Promise<{ success: boolean; id?: string; error?: string }> {
  const { url, kind } = preferredUrl(conn);
  if (!url) return { success: false, error: "No API URL configured" };

  try {
    const [policy] = yamlToPolicy(template.yaml);
    const res = await jsonFetch<{ id?: string; success?: boolean }>(
      proxyUrl(`${url}/api/v1/catalog/templates`, kind),
      {
        method: "POST",
        headers: controlHeaders(conn),
        body: JSON.stringify({
          name: template.name,
          description: template.description,
          category: template.category,
          tags: normalizeCatalogTags(template.tags, template.difficulty),
          policy_yaml: template.yaml,
          version: policy?.version,
        }),
      },
    );
    return { success: true, id: res.id };
  } catch (err) {
    return {
      success: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

export async function forkCatalogTemplate(
  conn: FleetConnection,
  id: string,
): Promise<{ success: boolean; template?: CatalogTemplate; error?: string }> {
  const { url, kind } = preferredUrl(conn);
  if (!url) return { success: false, error: "No API URL configured" };

  try {
    const res = await jsonFetch<unknown>(
      proxyUrl(`${url}/api/v1/catalog/templates/${encodeURIComponent(id)}/fork`, kind),
      {
        method: "POST",
        headers: controlHeaders(conn),
      },
    );

    if (isRecord(res) && "template" in res) {
      return { success: true, template: toCatalogTemplate(res.template) };
    }
    return { success: true, template: toCatalogTemplate(res) };
  } catch (err) {
    return {
      success: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

export async function fetchCatalogCategories(
  conn: FleetConnection,
): Promise<CatalogCategoryInfo[]> {
  const { url, kind } = preferredUrl(conn);
  if (!url) return [];

  try {
    const res = await jsonFetch<unknown>(
      proxyUrl(`${url}/api/v1/catalog/categories`, kind),
      { headers: controlHeaders(conn) },
    );

    let list: unknown[];
    if (Array.isArray(res)) {
      list = res;
    } else if (res && typeof res === "object" && "categories" in res) {
      const wrapped = res as { categories: unknown };
      if (!Array.isArray(wrapped.categories)) {
        throw new Error("[fleet-client] fetchCatalogCategories: expected categories to be an array");
      }
      list = wrapped.categories;
    } else {
      throw new Error("[fleet-client] fetchCatalogCategories: unexpected response shape");
    }

    return list.map(toCatalogCategory);
  } catch (e) {
    throw normalizeCatalogFetchError(e);
  }
}
