/**
 * Compliance framework-to-plugin mappings vendored from promptfoo's
 * frameworks.ts, adapted for the ClawdStrike policy builder workbench.
 *
 * Each mapping records which promptfoo red-team plugins exercise the
 * requirements of a given compliance framework entry.
 */

import type { GuardId } from "../types.ts";
import { PLUGIN_TO_GUARDS } from "./plugin-registry.ts";

// ---------------------------------------------------------------------------
// Shared mapping entry type
// ---------------------------------------------------------------------------

export interface FrameworkMappingEntry {
  plugins: string[];
  description: string;
}

// ---------------------------------------------------------------------------
// OWASP LLM Top 10 (2025)
// ---------------------------------------------------------------------------

export const OWASP_LLM_TOP_10: Record<string, FrameworkMappingEntry> = {
  "owasp:llm:01": {
    plugins: ["ascii-smuggling", "indirect-prompt-injection", "prompt-extraction"],
    description: "Prompt Injection",
  },
  "owasp:llm:02": {
    plugins: ["pii:api-db", "pii:direct", "pii:session", "pii:social", "harmful:privacy", "prompt-extraction"],
    description: "Sensitive Information Disclosure",
  },
  "owasp:llm:03": {
    plugins: [],
    description: "Supply Chain",
  },
  "owasp:llm:04": {
    plugins: [
      "harmful:misinformation-disinformation",
      "harmful:hate",
      "bias:age",
      "bias:disability",
      "bias:gender",
      "bias:race",
      "harmful:radicalization",
      "harmful:specialized-advice",
    ],
    description: "Data and Model Poisoning",
  },
  "owasp:llm:05": {
    plugins: ["shell-injection", "sql-injection", "ssrf"],
    description: "Improper Output Handling",
  },
  "owasp:llm:06": {
    plugins: ["excessive-agency", "rbac", "bfla", "bola", "shell-injection", "sql-injection", "ssrf"],
    description: "Excessive Agency",
  },
  "owasp:llm:07": {
    plugins: ["prompt-extraction", "rbac", "harmful:privacy", "pii:api-db", "pii:direct", "pii:session", "pii:social"],
    description: "System Prompt Leakage",
  },
  "owasp:llm:08": {
    plugins: ["harmful:privacy", "pii:api-db", "pii:direct", "pii:session", "pii:social"],
    description: "Vector and Embedding Weaknesses",
  },
  "owasp:llm:09": {
    plugins: ["hallucination", "overreliance", "harmful:misinformation-disinformation", "harmful:specialized-advice"],
    description: "Misinformation",
  },
  "owasp:llm:10": {
    plugins: ["divergent-repetition", "reasoning-dos"],
    description: "Unbounded Consumption",
  },
};

// ---------------------------------------------------------------------------
// OWASP Agentic Security Top 10 (December 2025)
// ---------------------------------------------------------------------------

export const OWASP_AGENTIC: Record<string, FrameworkMappingEntry> = {
  "owasp:agentic:asi01": {
    plugins: ["hijacking", "system-prompt-override", "indirect-prompt-injection"],
    description: "ASI01: Agent Goal Hijack",
  },
  "owasp:agentic:asi02": {
    plugins: ["excessive-agency", "mcp"],
    description: "ASI02: Tool Misuse and Exploitation",
  },
  "owasp:agentic:asi03": {
    plugins: ["rbac", "bfla", "bola"],
    description: "ASI03: Identity and Privilege Abuse",
  },
  "owasp:agentic:asi04": {
    plugins: ["indirect-prompt-injection", "mcp"],
    description: "ASI04: Agentic Supply Chain Vulnerabilities",
  },
  "owasp:agentic:asi05": {
    plugins: ["shell-injection", "sql-injection", "harmful:cybercrime:malicious-code", "ssrf"],
    description: "ASI05: Unexpected Code Execution",
  },
  "owasp:agentic:asi06": {
    plugins: ["agentic:memory-poisoning", "indirect-prompt-injection"],
    description: "ASI06: Memory and Context Poisoning",
  },
  "owasp:agentic:asi07": {
    plugins: ["indirect-prompt-injection", "hijacking"],
    description: "ASI07: Insecure Inter-Agent Communication",
  },
  "owasp:agentic:asi08": {
    plugins: ["hallucination", "harmful:misinformation-disinformation"],
    description: "ASI08: Cascading Failures",
  },
  "owasp:agentic:asi09": {
    plugins: ["overreliance", "harmful:misinformation-disinformation"],
    description: "ASI09: Human Agent Trust Exploitation",
  },
  "owasp:agentic:asi10": {
    plugins: ["excessive-agency", "hijacking", "rbac"],
    description: "ASI10: Rogue Agents",
  },
};

// ---------------------------------------------------------------------------
// MITRE ATLAS
// ---------------------------------------------------------------------------

export const MITRE_ATLAS: Record<string, FrameworkMappingEntry> = {
  "mitre:atlas:exfiltration": {
    plugins: [
      "ascii-smuggling",
      "harmful:privacy",
      "indirect-prompt-injection",
      "pii:api-db",
      "pii:direct",
      "pii:session",
      "pii:social",
      "prompt-extraction",
    ],
    description: "Data exfiltration from AI systems",
  },
  "mitre:atlas:impact": {
    plugins: ["excessive-agency", "hijacking"],
    description: "Impact on availability, integrity, or confidentiality",
  },
  "mitre:atlas:initial-access": {
    plugins: ["harmful:cybercrime", "shell-injection", "sql-injection", "ssrf"],
    description: "Initial access to AI system components",
  },
  "mitre:atlas:ml-attack-staging": {
    plugins: ["ascii-smuggling", "excessive-agency", "hallucination", "indirect-prompt-injection"],
    description: "Machine learning attack staging and preparation",
  },
  "mitre:atlas:reconnaissance": {
    plugins: ["prompt-extraction", "rbac"],
    description: "Reconnaissance of AI system capabilities and boundaries",
  },
  "mitre:atlas:resource-development": {
    plugins: ["harmful:cybercrime", "harmful:illegal-drugs", "harmful:indiscriminate-weapons"],
    description: "Resource development for AI attacks",
  },
};

// ---------------------------------------------------------------------------
// NIST AI RMF
// ---------------------------------------------------------------------------

export const NIST_AI_RMF: Record<string, FrameworkMappingEntry> = {
  "nist:ai:measure:1.1": {
    plugins: ["excessive-agency", "harmful:misinformation-disinformation"],
    description: "Identify and characterize risks",
  },
  "nist:ai:measure:1.2": {
    plugins: ["excessive-agency", "harmful:misinformation-disinformation"],
    description: "Anticipate risks",
  },
  "nist:ai:measure:2.1": {
    plugins: ["harmful:privacy", "pii:api-db", "pii:direct", "pii:session", "pii:social"],
    description: "Privacy risk measurement",
  },
  "nist:ai:measure:2.2": {
    plugins: ["harmful:privacy", "pii:api-db", "pii:direct", "pii:session", "pii:social"],
    description: "Privacy risk assessment",
  },
  "nist:ai:measure:2.3": {
    plugins: ["excessive-agency"],
    description: "Agency and autonomy risks",
  },
  "nist:ai:measure:2.4": {
    plugins: ["excessive-agency", "harmful:misinformation-disinformation"],
    description: "Trustworthiness measurement",
  },
  "nist:ai:measure:2.5": {
    plugins: ["excessive-agency"],
    description: "Controllability assessment",
  },
  "nist:ai:measure:2.6": {
    plugins: ["harmful:chemical-biological-weapons", "harmful:indiscriminate-weapons", "harmful:unsafe-practices"],
    description: "Safety and physical harm risks",
  },
  "nist:ai:measure:2.7": {
    plugins: ["harmful:cybercrime", "shell-injection", "sql-injection"],
    description: "Cybersecurity risks",
  },
  "nist:ai:measure:2.8": {
    plugins: ["bfla", "bola", "rbac"],
    description: "Access control measurement",
  },
  "nist:ai:measure:2.9": {
    plugins: ["excessive-agency"],
    description: "Autonomy boundaries",
  },
  "nist:ai:measure:2.10": {
    plugins: ["harmful:privacy", "pii:api-db", "pii:direct", "pii:session", "pii:social"],
    description: "Data governance risks",
  },
  "nist:ai:measure:2.11": {
    plugins: ["harmful:harassment-bullying", "harmful:hate", "harmful:insults"],
    description: "Harmful bias and discrimination",
  },
  "nist:ai:measure:2.12": {
    plugins: [],
    description: "Environmental impact risks",
  },
  "nist:ai:measure:2.13": {
    plugins: ["excessive-agency"],
    description: "Explainability and interpretability",
  },
  "nist:ai:measure:3.1": {
    plugins: ["excessive-agency", "harmful:misinformation-disinformation"],
    description: "Risk monitoring and management",
  },
  "nist:ai:measure:3.2": {
    plugins: ["excessive-agency"],
    description: "Continuous monitoring",
  },
  "nist:ai:measure:3.3": {
    plugins: ["excessive-agency"],
    description: "Incident response planning",
  },
  "nist:ai:measure:4.1": {
    plugins: ["excessive-agency"],
    description: "Governance and oversight",
  },
  "nist:ai:measure:4.2": {
    plugins: ["excessive-agency", "harmful:misinformation-disinformation"],
    description: "Documentation and accountability",
  },
  "nist:ai:measure:4.3": {
    plugins: ["excessive-agency"],
    description: "Stakeholder engagement",
  },
};

// ---------------------------------------------------------------------------
// EU AI Act
// ---------------------------------------------------------------------------

export const EU_AI_ACT: Record<string, FrameworkMappingEntry> = {
  "eu:ai-act:art5:subliminal-manipulation": {
    plugins: ["hijacking", "excessive-agency"],
    description: "Prohibition on subliminal manipulation techniques",
  },
  "eu:ai-act:art5:exploitation-of-vulnerabilities": {
    plugins: ["hijacking", "harmful:misinformation-disinformation"],
    description: "Prohibition on exploitation of vulnerable groups",
  },
  "eu:ai-act:art5:social-scoring": {
    plugins: ["harmful:misinformation-disinformation", "overreliance"],
    description: "Prohibition on social scoring",
  },
  "eu:ai-act:art5:biometric-categorisation": {
    plugins: ["pii:direct", "pii:session", "harmful:privacy"],
    description: "Prohibition on biometric categorisation",
  },
  "eu:ai-act:art5:remote-biometric-id-live": {
    plugins: ["pii:session", "pii:direct", "harmful:privacy"],
    description: "Prohibition on real-time remote biometric identification",
  },
  "eu:ai-act:art5:remote-biometric-id-post": {
    plugins: ["pii:api-db", "pii:direct", "harmful:privacy"],
    description: "Restrictions on post-remote biometric identification",
  },
  "eu:ai-act:annex3:biometric-id": {
    plugins: ["pii:direct", "pii:session", "harmful:privacy"],
    description: "High-risk: Biometric identification systems",
  },
  "eu:ai-act:annex3:critical-infrastructure": {
    plugins: ["shell-injection", "sql-injection", "ssrf", "excessive-agency"],
    description: "High-risk: Critical infrastructure management",
  },
  "eu:ai-act:annex3:education": {
    plugins: ["harmful:misinformation-disinformation", "hallucination", "overreliance"],
    description: "High-risk: Education and vocational training",
  },
  "eu:ai-act:annex3:employment": {
    plugins: ["pii:direct", "overreliance"],
    description: "High-risk: Employment, worker management, self-employment",
  },
  "eu:ai-act:annex3:essential-services": {
    plugins: ["pii:direct", "pii:session", "excessive-agency"],
    description: "High-risk: Access to essential services",
  },
  "eu:ai-act:annex3:law-enforcement": {
    plugins: ["pii:direct", "pii:api-db", "harmful:privacy"],
    description: "High-risk: Law enforcement applications",
  },
  "eu:ai-act:annex3:migration-border": {
    plugins: ["pii:direct", "harmful:hate", "harmful:privacy"],
    description: "High-risk: Migration, asylum, border control",
  },
  "eu:ai-act:annex3:justice-democracy": {
    plugins: ["hallucination", "harmful:misinformation-disinformation", "pii:direct"],
    description: "High-risk: Administration of justice and democratic processes",
  },
};

// ---------------------------------------------------------------------------
// Framework registry — convenience lookup by framework ID
// ---------------------------------------------------------------------------

export const FRAMEWORK_REGISTRY: Record<string, Record<string, FrameworkMappingEntry>> = {
  "owasp:llm": OWASP_LLM_TOP_10,
  "owasp:agentic": OWASP_AGENTIC,
  "mitre:atlas": MITRE_ATLAS,
  "nist:ai:measure": NIST_AI_RMF,
  "eu:ai-act": EU_AI_ACT,
};

// ---------------------------------------------------------------------------
// frameworkPluginsToGuards
// ---------------------------------------------------------------------------

/**
 * Given a framework ID and its mapping, collect all ClawdStrike guards that
 * are exercised by the framework's plugin set.
 *
 * Returns a de-duplicated array of GuardIds.
 */
export function frameworkPluginsToGuards(
  _frameworkId: string,
  mapping: Record<string, FrameworkMappingEntry>,
): GuardId[] {
  const guardSet = new Set<GuardId>();

  for (const entry of Object.values(mapping)) {
    for (const pluginId of entry.plugins) {
      const guards = PLUGIN_TO_GUARDS[pluginId];
      if (guards) {
        for (const g of guards) {
          guardSet.add(g);
        }
      }
    }
  }

  return [...guardSet];
}
