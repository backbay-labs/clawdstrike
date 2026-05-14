import type {
  GuardConfigMap,
  PolicySettings,
  GuardId,
  ComplianceFramework,
} from "./types";
import frameworkData from "../../data/compliance-frameworks.json";

export interface ComplianceRequirementDef {
  id: string;
  framework: ComplianceFramework;
  title: string;
  citation: string;
  description: string;
  guardDeps: GuardId[];
  check: (guards: GuardConfigMap, settings: PolicySettings) => boolean;
}

// These cannot be serialised to JSON, so we keep them here and attach them
// when hydrating the framework data.

const checkFunctions: Record<
  string,
  (guards: GuardConfigMap, settings: PolicySettings) => boolean
> = {
  // ---- HIPAA ----
  "hipaa-1": (guards) =>
    !!guards.forbidden_path?.enabled &&
    !!guards.forbidden_path?.patterns &&
    guards.forbidden_path.patterns.length >= 3,
  "hipaa-2": (_guards, settings) => settings.verbose_logging === true,
  "hipaa-3": (guards) => !!guards.patch_integrity?.enabled,
  "hipaa-4": (guards) =>
    !!guards.egress_allowlist?.enabled &&
    guards.egress_allowlist?.default_action === "block",
  "hipaa-5": (guards) =>
    !!guards.secret_leak?.enabled &&
    !!guards.secret_leak?.patterns &&
    guards.secret_leak.patterns.length >= 1,
  "hipaa-6": (guards) =>
    !!guards.mcp_tool?.enabled &&
    guards.mcp_tool?.default_action === "block",
  "hipaa-7": (_guards, settings) =>
    settings.session_timeout_secs !== undefined &&
    settings.session_timeout_secs > 0,
  "hipaa-8": (_guards, settings) =>
    settings.session_timeout_secs !== undefined &&
    settings.session_timeout_secs <= 3600,
  "hipaa-9": (guards) =>
    !!guards.secret_leak?.enabled &&
    !!guards.secret_leak?.patterns &&
    guards.secret_leak.patterns.some(
      (p) =>
        p.name.toLowerCase().includes("key") ||
        p.name.toLowerCase().includes("private") ||
        p.pattern.includes("KEY")
    ),
  "hipaa-10": (guards) => !!guards.shell_command?.enabled,

  // ---- SOC2 ----
  "soc2-1": (guards) =>
    !!guards.forbidden_path?.enabled && !!guards.mcp_tool?.enabled,
  "soc2-2": (guards) =>
    !!guards.path_allowlist?.enabled || !!guards.forbidden_path?.enabled,
  "soc2-3": (_guards, settings) =>
    settings.session_timeout_secs !== undefined &&
    settings.session_timeout_secs > 0,
  "soc2-4": (guards) => !!guards.egress_allowlist?.enabled,
  "soc2-5": (guards) =>
    !!guards.egress_allowlist?.enabled &&
    guards.egress_allowlist?.default_action === "block",
  "soc2-6": (guards) =>
    !!guards.prompt_injection?.enabled || !!guards.jailbreak?.enabled,
  "soc2-7": (guards) => !!guards.secret_leak?.enabled,
  "soc2-8": (guards) => !!guards.patch_integrity?.enabled,

  // ---- PCI-DSS ----
  "pci-1": (guards) => !!guards.egress_allowlist?.enabled,
  "pci-2": (guards) =>
    !!guards.forbidden_path?.enabled &&
    !!guards.egress_allowlist?.enabled &&
    !!guards.secret_leak?.enabled,
  "pci-3": (guards) =>
    !!guards.secret_leak?.enabled &&
    !!guards.secret_leak?.patterns &&
    guards.secret_leak.patterns.length >= 1,
  "pci-4": (guards) =>
    !!guards.patch_integrity?.enabled && !!guards.shell_command?.enabled,
  "pci-5": (guards) =>
    !!guards.forbidden_path?.enabled &&
    !!guards.mcp_tool?.enabled &&
    guards.mcp_tool?.default_action === "block",
  "pci-6": (_guards, settings) =>
    settings.session_timeout_secs !== undefined &&
    settings.session_timeout_secs <= 1800,
  "pci-7": (_guards, settings) => settings.verbose_logging === true,
};


interface FrameworkJson {
  id: string;
  name: string;
  shortName: string;
  description: string;
  requirements: Array<{
    id: string;
    framework: string;
    title: string;
    citation: string;
    description: string;
    guardDeps: string[];
  }>;
}

function hydrateFrameworks(
  data: { frameworks: FrameworkJson[] }
): {
  id: ComplianceFramework;
  name: string;
  shortName: string;
  description: string;
  requirements: ComplianceRequirementDef[];
}[] {
  return data.frameworks.map((fw) => ({
    id: fw.id as ComplianceFramework,
    name: fw.name,
    shortName: fw.shortName,
    description: fw.description,
    requirements: fw.requirements.map((req) => ({
      id: req.id,
      framework: req.framework as ComplianceFramework,
      title: req.title,
      citation: req.citation,
      description: req.description,
      guardDeps: req.guardDeps as GuardId[],
      check: checkFunctions[req.id] ?? (() => false),
    })),
  }));
}

// ---- Exports ----

export const COMPLIANCE_FRAMEWORKS = hydrateFrameworks(frameworkData);

export function getFrameworkRequirements(
  framework: ComplianceFramework
): ComplianceRequirementDef[] {
  return (
    COMPLIANCE_FRAMEWORKS.find((f) => f.id === framework)?.requirements ?? []
  );
}

export function scoreFramework(
  framework: ComplianceFramework,
  guards: GuardConfigMap,
  settings: PolicySettings
): { score: number; met: ComplianceRequirementDef[]; gaps: ComplianceRequirementDef[] } {
  const reqs = getFrameworkRequirements(framework);
  const met: ComplianceRequirementDef[] = [];
  const gaps: ComplianceRequirementDef[] = [];

  for (const req of reqs) {
    if (req.check(guards, settings)) {
      met.push(req);
    } else {
      gaps.push(req);
    }
  }

  const score = reqs.length > 0 ? Math.round((met.length / reqs.length) * 100) : 0;
  return { score, met, gaps };
}
