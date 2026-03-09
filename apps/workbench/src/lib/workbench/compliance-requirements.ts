import type {
  GuardConfigMap,
  PolicySettings,
  GuardId,
  ComplianceFramework,
} from "./types";

export interface ComplianceRequirementDef {
  id: string;
  framework: ComplianceFramework;
  title: string;
  citation: string;
  description: string;
  guardDeps: GuardId[];
  check: (guards: GuardConfigMap, settings: PolicySettings) => boolean;
}

// ---- HIPAA ----

const hipaaRequirements: ComplianceRequirementDef[] = [
  {
    id: "hipaa-1",
    framework: "hipaa",
    title: "Access Control",
    citation: "164.312(a)(1)",
    description:
      "Implement technical policies to allow access only to authorized persons. Requires forbidden_path guard with patterns covering sensitive directories.",
    guardDeps: ["forbidden_path"],
    check: (guards) =>
      !!guards.forbidden_path?.enabled &&
      !!guards.forbidden_path?.patterns &&
      guards.forbidden_path.patterns.length >= 3,
  },
  {
    id: "hipaa-2",
    framework: "hipaa",
    title: "Audit Controls",
    citation: "164.312(b)",
    description:
      "Implement hardware, software, and procedural mechanisms for recording and examining access. Requires verbose logging enabled.",
    guardDeps: [],
    check: (_guards, settings) => settings.verbose_logging === true,
  },
  {
    id: "hipaa-3",
    framework: "hipaa",
    title: "Integrity Controls",
    citation: "164.312(c)(1)",
    description:
      "Protect ePHI from improper alteration or destruction. Requires patch_integrity guard enabled.",
    guardDeps: ["patch_integrity"],
    check: (guards) => !!guards.patch_integrity?.enabled,
  },
  {
    id: "hipaa-4",
    framework: "hipaa",
    title: "Transmission Security",
    citation: "164.312(e)(1)",
    description:
      "Guard against unauthorized access to ePHI transmitted over networks. Requires egress_allowlist with default_action: block.",
    guardDeps: ["egress_allowlist"],
    check: (guards) =>
      !!guards.egress_allowlist?.enabled &&
      guards.egress_allowlist?.default_action === "block",
  },
  {
    id: "hipaa-5",
    framework: "hipaa",
    title: "PHI Data Protection",
    citation: "HIPAA Privacy Rule",
    description:
      "Prevent leakage of protected health information. Requires secret_leak guard with medical/PHI-related patterns.",
    guardDeps: ["secret_leak"],
    check: (guards) =>
      !!guards.secret_leak?.enabled &&
      !!guards.secret_leak?.patterns &&
      guards.secret_leak.patterns.length >= 1,
  },
  {
    id: "hipaa-6",
    framework: "hipaa",
    title: "Authentication",
    citation: "164.312(d)",
    description:
      "Verify entity identity before granting access. Requires mcp_tool guard with restricted default action.",
    guardDeps: ["mcp_tool"],
    check: (guards) =>
      !!guards.mcp_tool?.enabled &&
      guards.mcp_tool?.default_action === "block",
  },
  {
    id: "hipaa-7",
    framework: "hipaa",
    title: "Emergency Access",
    citation: "164.312(a)(2)(ii)",
    description:
      "Establish procedures for obtaining ePHI during emergencies. Requires a reasonable session timeout configured.",
    guardDeps: [],
    check: (_guards, settings) =>
      settings.session_timeout_secs !== undefined &&
      settings.session_timeout_secs > 0,
  },
  {
    id: "hipaa-8",
    framework: "hipaa",
    title: "Automatic Logoff",
    citation: "164.312(a)(2)(iii)",
    description:
      "Implement electronic procedures that terminate sessions after inactivity. Requires session_timeout_secs <= 3600.",
    guardDeps: [],
    check: (_guards, settings) =>
      settings.session_timeout_secs !== undefined &&
      settings.session_timeout_secs <= 3600,
  },
  {
    id: "hipaa-9",
    framework: "hipaa",
    title: "Encryption",
    citation: "164.312(a)(2)(iv)",
    description:
      "Implement mechanisms to encrypt and decrypt ePHI. Requires secret_leak guard with key/credential patterns.",
    guardDeps: ["secret_leak"],
    check: (guards) =>
      !!guards.secret_leak?.enabled &&
      !!guards.secret_leak?.patterns &&
      guards.secret_leak.patterns.some(
        (p) =>
          p.name.toLowerCase().includes("key") ||
          p.name.toLowerCase().includes("private") ||
          p.pattern.includes("KEY")
      ),
  },
  {
    id: "hipaa-10",
    framework: "hipaa",
    title: "Command Restriction",
    citation: "164.312(a)(1)",
    description:
      "Restrict dangerous shell commands that could compromise systems containing ePHI. Requires shell_command guard enabled.",
    guardDeps: ["shell_command"],
    check: (guards) => !!guards.shell_command?.enabled,
  },
];

// ---- SOC2 ----

const soc2Requirements: ComplianceRequirementDef[] = [
  {
    id: "soc2-1",
    framework: "soc2",
    title: "Logical Access Controls",
    citation: "CC6.1",
    description:
      "Restrict logical access to information assets. Requires forbidden_path and mcp_tool guards.",
    guardDeps: ["forbidden_path", "mcp_tool"],
    check: (guards) =>
      !!guards.forbidden_path?.enabled && !!guards.mcp_tool?.enabled,
  },
  {
    id: "soc2-2",
    framework: "soc2",
    title: "Access Provisioning",
    citation: "CC6.2",
    description:
      "New access is provisioned based on authorization. Requires path_allowlist or forbidden_path guard.",
    guardDeps: ["forbidden_path", "path_allowlist"],
    check: (guards) =>
      !!guards.path_allowlist?.enabled || !!guards.forbidden_path?.enabled,
  },
  {
    id: "soc2-3",
    framework: "soc2",
    title: "Access Removal",
    citation: "CC6.3",
    description:
      "Access is removed when no longer needed. Requires session_timeout_secs configured.",
    guardDeps: [],
    check: (_guards, settings) =>
      settings.session_timeout_secs !== undefined &&
      settings.session_timeout_secs > 0,
  },
  {
    id: "soc2-4",
    framework: "soc2",
    title: "System Boundaries",
    citation: "CC6.6",
    description:
      "Restrict data transmission across system boundaries. Requires egress_allowlist guard.",
    guardDeps: ["egress_allowlist"],
    check: (guards) => !!guards.egress_allowlist?.enabled,
  },
  {
    id: "soc2-5",
    framework: "soc2",
    title: "Data Transmission Security",
    citation: "CC6.7",
    description:
      "Restrict data transmission to authorized channels. Requires egress_allowlist with default_action: block.",
    guardDeps: ["egress_allowlist"],
    check: (guards) =>
      !!guards.egress_allowlist?.enabled &&
      guards.egress_allowlist?.default_action === "block",
  },
  {
    id: "soc2-6",
    framework: "soc2",
    title: "Detection Monitoring",
    citation: "CC7.1",
    description:
      "Detection procedures are in place for anomalies. Requires prompt_injection or jailbreak guard.",
    guardDeps: ["prompt_injection", "jailbreak"],
    check: (guards) =>
      !!guards.prompt_injection?.enabled || !!guards.jailbreak?.enabled,
  },
  {
    id: "soc2-7",
    framework: "soc2",
    title: "Incident Detection",
    citation: "CC7.2",
    description:
      "Anomalies are monitored and incidents identified. Requires secret_leak guard enabled.",
    guardDeps: ["secret_leak"],
    check: (guards) => !!guards.secret_leak?.enabled,
  },
  {
    id: "soc2-8",
    framework: "soc2",
    title: "Change Management",
    citation: "CC8.1",
    description:
      "Changes to infrastructure and software are authorized. Requires patch_integrity guard enabled.",
    guardDeps: ["patch_integrity"],
    check: (guards) => !!guards.patch_integrity?.enabled,
  },
];

// ---- PCI-DSS ----

const pciDssRequirements: ComplianceRequirementDef[] = [
  {
    id: "pci-1",
    framework: "pci-dss",
    title: "Network Security",
    citation: "Requirement 1",
    description:
      "Install and maintain network security controls. Requires egress_allowlist guard enabled.",
    guardDeps: ["egress_allowlist"],
    check: (guards) => !!guards.egress_allowlist?.enabled,
  },
  {
    id: "pci-2",
    framework: "pci-dss",
    title: "Secure Defaults",
    citation: "Requirement 2",
    description:
      "Apply secure configurations to all system components. Requires extending strict ruleset or equivalent guard coverage.",
    guardDeps: ["forbidden_path", "egress_allowlist", "secret_leak"],
    check: (guards) =>
      !!guards.forbidden_path?.enabled &&
      !!guards.egress_allowlist?.enabled &&
      !!guards.secret_leak?.enabled,
  },
  {
    id: "pci-3",
    framework: "pci-dss",
    title: "Protect Stored Data",
    citation: "Requirement 3",
    description:
      "Protect stored account data. Requires secret_leak guard with card number patterns.",
    guardDeps: ["secret_leak"],
    check: (guards) =>
      !!guards.secret_leak?.enabled &&
      !!guards.secret_leak?.patterns &&
      guards.secret_leak.patterns.length >= 1,
  },
  {
    id: "pci-4",
    framework: "pci-dss",
    title: "Secure Development",
    citation: "Requirement 6",
    description:
      "Develop and maintain secure systems. Requires patch_integrity and shell_command guards.",
    guardDeps: ["patch_integrity", "shell_command"],
    check: (guards) =>
      !!guards.patch_integrity?.enabled && !!guards.shell_command?.enabled,
  },
  {
    id: "pci-5",
    framework: "pci-dss",
    title: "Restrict Access",
    citation: "Requirement 7",
    description:
      "Restrict access by business need-to-know. Requires forbidden_path and mcp_tool with block default.",
    guardDeps: ["forbidden_path", "mcp_tool"],
    check: (guards) =>
      !!guards.forbidden_path?.enabled &&
      !!guards.mcp_tool?.enabled &&
      guards.mcp_tool?.default_action === "block",
  },
  {
    id: "pci-6",
    framework: "pci-dss",
    title: "Authentication",
    citation: "Requirement 8",
    description:
      "Identify users and authenticate access. Requires session_timeout_secs <= 1800 (30 minutes).",
    guardDeps: [],
    check: (_guards, settings) =>
      settings.session_timeout_secs !== undefined &&
      settings.session_timeout_secs <= 1800,
  },
  {
    id: "pci-7",
    framework: "pci-dss",
    title: "Logging & Monitoring",
    citation: "Requirement 10",
    description:
      "Log and monitor all access to system components and cardholder data. Requires verbose_logging enabled.",
    guardDeps: [],
    check: (_guards, settings) => settings.verbose_logging === true,
  },
];

// ---- Exports ----

export const COMPLIANCE_FRAMEWORKS: {
  id: ComplianceFramework;
  name: string;
  shortName: string;
  description: string;
  requirements: ComplianceRequirementDef[];
}[] = [
  {
    id: "hipaa",
    name: "HIPAA",
    shortName: "HIPAA",
    description: "Health Insurance Portability and Accountability Act",
    requirements: hipaaRequirements,
  },
  {
    id: "soc2",
    name: "SOC 2",
    shortName: "SOC2",
    description: "Service Organization Control 2 (Trust Services Criteria)",
    requirements: soc2Requirements,
  },
  {
    id: "pci-dss",
    name: "PCI-DSS",
    shortName: "PCI",
    description: "Payment Card Industry Data Security Standard",
    requirements: pciDssRequirements,
  },
];

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
