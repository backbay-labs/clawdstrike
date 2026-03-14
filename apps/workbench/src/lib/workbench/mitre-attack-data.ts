// ---- MITRE ATT&CK Technique Data ----
// Static subset of ATT&CK techniques for the coverage heatmap.
// Organized by tactic column for matrix visualization.

import type { FileType } from "./file-type-registry";

/** A single MITRE ATT&CK technique. */
export interface MitreTechnique {
  /** ATT&CK ID, e.g. "T1059" or "T1059.001". */
  id: string;
  /** Human-readable technique name. */
  name: string;
  /** Tactic slug (underscore-separated). */
  tactic: MitreTactic;
}

/** Coverage data for a single technique across all open rules. */
export interface TechniqueCoverage {
  technique: MitreTechnique;
  ruleCount: number;
  rules: { name: string; fileType: FileType }[];
}

/** Tactic identifiers matching ATT&CK naming. */
export type MitreTactic =
  | "initial_access"
  | "execution"
  | "persistence"
  | "privilege_escalation"
  | "defense_evasion"
  | "credential_access"
  | "discovery"
  | "lateral_movement"
  | "collection"
  | "exfiltration"
  | "command_and_control"
  | "impact";

/** Display metadata for each tactic column. */
export interface TacticMeta {
  id: MitreTactic;
  label: string;
  shortLabel: string;
}

/** Ordered tactic columns for the heatmap. */
export const MITRE_TACTICS: TacticMeta[] = [
  { id: "initial_access", label: "Initial Access", shortLabel: "Init Access" },
  { id: "execution", label: "Execution", shortLabel: "Execution" },
  { id: "persistence", label: "Persistence", shortLabel: "Persist" },
  { id: "privilege_escalation", label: "Privilege Escalation", shortLabel: "Priv Esc" },
  { id: "defense_evasion", label: "Defense Evasion", shortLabel: "Def Evasion" },
  { id: "credential_access", label: "Credential Access", shortLabel: "Cred Access" },
  { id: "discovery", label: "Discovery", shortLabel: "Discovery" },
  { id: "lateral_movement", label: "Lateral Movement", shortLabel: "Lat Move" },
  { id: "collection", label: "Collection", shortLabel: "Collection" },
  { id: "exfiltration", label: "Exfiltration", shortLabel: "Exfil" },
  { id: "command_and_control", label: "Command and Control", shortLabel: "C2" },
  { id: "impact", label: "Impact", shortLabel: "Impact" },
];

/** Static subset of common ATT&CK techniques (~3-5 per tactic). */
export const MITRE_TECHNIQUES: MitreTechnique[] = [
  // Initial Access
  { id: "T1566", name: "Phishing", tactic: "initial_access" },
  { id: "T1190", name: "Exploit Public-Facing Application", tactic: "initial_access" },
  { id: "T1078", name: "Valid Accounts", tactic: "initial_access" },
  { id: "T1195", name: "Supply Chain Compromise", tactic: "initial_access" },

  // Execution
  { id: "T1059", name: "Command & Scripting", tactic: "execution" },
  { id: "T1059.001", name: "PowerShell", tactic: "execution" },
  { id: "T1059.003", name: "Windows Cmd", tactic: "execution" },
  { id: "T1059.004", name: "Unix Shell", tactic: "execution" },
  { id: "T1203", name: "Exploitation for Client Execution", tactic: "execution" },

  // Persistence
  { id: "T1547", name: "Boot/Logon Autostart", tactic: "persistence" },
  { id: "T1053", name: "Scheduled Task/Job", tactic: "persistence" },
  { id: "T1136", name: "Create Account", tactic: "persistence" },
  { id: "T1098", name: "Account Manipulation", tactic: "persistence" },

  // Privilege Escalation
  { id: "T1548", name: "Abuse Elevation Control", tactic: "privilege_escalation" },
  { id: "T1134", name: "Access Token Manipulation", tactic: "privilege_escalation" },
  { id: "T1068", name: "Exploitation for Privilege Escalation", tactic: "privilege_escalation" },

  // Defense Evasion
  { id: "T1562", name: "Impair Defenses", tactic: "defense_evasion" },
  { id: "T1070", name: "Indicator Removal", tactic: "defense_evasion" },
  { id: "T1027", name: "Obfuscated Files or Information", tactic: "defense_evasion" },
  { id: "T1036", name: "Masquerading", tactic: "defense_evasion" },

  // Credential Access
  { id: "T1003", name: "OS Credential Dumping", tactic: "credential_access" },
  { id: "T1110", name: "Brute Force", tactic: "credential_access" },
  { id: "T1555", name: "Credentials from Password Stores", tactic: "credential_access" },
  { id: "T1552", name: "Unsecured Credentials", tactic: "credential_access" },

  // Discovery
  { id: "T1018", name: "Remote System Discovery", tactic: "discovery" },
  { id: "T1046", name: "Network Service Scan", tactic: "discovery" },
  { id: "T1082", name: "System Information Discovery", tactic: "discovery" },
  { id: "T1083", name: "File and Directory Discovery", tactic: "discovery" },

  // Lateral Movement
  { id: "T1021", name: "Remote Services", tactic: "lateral_movement" },
  { id: "T1021.001", name: "Remote Desktop Protocol", tactic: "lateral_movement" },
  { id: "T1021.004", name: "SSH", tactic: "lateral_movement" },

  // Collection
  { id: "T1005", name: "Data from Local System", tactic: "collection" },
  { id: "T1039", name: "Data from Network Shared Drive", tactic: "collection" },
  { id: "T1074", name: "Data Staged", tactic: "collection" },

  // Exfiltration
  { id: "T1041", name: "Exfiltration Over C2 Channel", tactic: "exfiltration" },
  { id: "T1048", name: "Exfiltration Over Alternative Protocol", tactic: "exfiltration" },
  { id: "T1567", name: "Exfiltration Over Web Service", tactic: "exfiltration" },

  // Command and Control
  { id: "T1071", name: "Application Layer Protocol", tactic: "command_and_control" },
  { id: "T1105", name: "Ingress Tool Transfer", tactic: "command_and_control" },
  { id: "T1572", name: "Protocol Tunneling", tactic: "command_and_control" },
  { id: "T1573", name: "Encrypted Channel", tactic: "command_and_control" },

  // Impact
  { id: "T1486", name: "Data Encrypted for Impact", tactic: "impact" },
  { id: "T1489", name: "Service Stop", tactic: "impact" },
  { id: "T1485", name: "Data Destruction", tactic: "impact" },
  { id: "T1499", name: "Endpoint Denial of Service", tactic: "impact" },
];

// ---- Guard-to-technique mapping (for policy files) ----

/** Maps ClawdStrike guard IDs to the ATT&CK techniques they help detect or mitigate. */
export const GUARD_TECHNIQUE_MAP: Record<string, string[]> = {
  forbidden_path: ["T1005", "T1083", "T1552"],
  path_allowlist: ["T1005", "T1083", "T1074"],
  egress_allowlist: ["T1041", "T1048", "T1071", "T1105", "T1567", "T1572", "T1573"],
  secret_leak: ["T1552", "T1555"],
  patch_integrity: ["T1195"],
  shell_command: ["T1059", "T1059.001", "T1059.003", "T1059.004"],
  mcp_tool: ["T1203"],
  prompt_injection: ["T1566"],
  jailbreak: ["T1566"],
  computer_use: ["T1021", "T1021.001"],
  remote_desktop_side_channel: ["T1021.001", "T1039"],
  input_injection_capability: ["T1021.001"],
  spider_sense: ["T1566", "T1027"],
};

// ---- Extraction helpers ----

/**
 * Extract ATT&CK technique IDs from Sigma rule tags.
 * Sigma convention: `attack.tXXXX` or `attack.tXXXX.YYY`.
 */
export function extractSigmaTechniques(tags: string[]): string[] {
  const result: string[] = [];
  const techniqueRe = /^attack\.(t\d{4}(?:\.\d{3})?)$/i;
  for (const tag of tags) {
    const match = techniqueRe.exec(tag.trim());
    if (match) {
      result.push(match[1].toUpperCase());
    }
  }
  return result;
}

/**
 * Extract ATT&CK technique IDs from YARA rule content.
 * Looks for `mitre_attack` or `technique` fields in the meta section.
 */
export function extractYaraTechniques(content: string): string[] {
  const result: string[] = [];
  const techniqueRe = /T\d{4}(?:\.\d{3})?/g;

  // Look within the meta section for mitre_attack or technique references
  const metaMatch = /meta\s*:([\s\S]*?)(?:strings\s*:|condition\s*:|$)/.exec(content);
  if (metaMatch) {
    const metaBlock = metaMatch[1];
    // Only scan lines that mention mitre or technique
    const lines = metaBlock.split("\n");
    for (const line of lines) {
      const lower = line.toLowerCase();
      if (lower.includes("mitre") || lower.includes("technique") || lower.includes("attack")) {
        let m: RegExpExecArray | null;
        while ((m = techniqueRe.exec(line)) !== null) {
          result.push(m[0]);
        }
      }
    }
  }
  return [...new Set(result)];
}

/**
 * Extract ATT&CK technique IDs from a ClawdStrike policy YAML string.
 * Maps enabled guards to their corresponding techniques.
 */
export function extractPolicyTechniques(yamlContent: string): string[] {
  const result: string[] = [];
  for (const [guardId, techniques] of Object.entries(GUARD_TECHNIQUE_MAP)) {
    // Simple heuristic: guard is referenced and enabled
    const guardRe = new RegExp(`${guardId}:\\s*\\n\\s*enabled:\\s*true`, "m");
    if (guardRe.test(yamlContent)) {
      result.push(...techniques);
    }
  }
  return [...new Set(result)];
}
