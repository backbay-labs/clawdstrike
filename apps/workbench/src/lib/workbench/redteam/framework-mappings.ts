/**
 * Compliance framework-to-plugin mappings.
 *
 * DATA IS COPIED DIRECTLY from:
 *   - promptfoo/src/redteam/constants/frameworks.ts
 *
 * Only the guard bridge function at the bottom is ClawdStrike-specific.
 */

import type { GuardId } from "../types.ts";
import { PLUGIN_TO_GUARDS } from "./plugin-registry.ts";

// Re-export Plugin type for framework mapping signatures
import type { Plugin } from "./plugin-registry.ts";

// ============================================================================
// Copied from promptfoo/src/redteam/constants/frameworks.ts
// ============================================================================

export const FRAMEWORK_NAMES: Record<string, string> = {
  'dod:ai:ethics': 'DoD AI Ethical Principles',
  'mitre:atlas': 'MITRE ATLAS',
  'nist:ai:measure': 'NIST AI RMF',
  'owasp:api': 'OWASP API Top 10',
  'owasp:llm': 'OWASP LLM Top 10',
  'owasp:agentic': 'OWASP Top 10 for Agentic Applications',
  'eu:ai-act': 'EU AI Act',
  'iso:42001': 'ISO/IEC 42001',
  gdpr: 'GDPR',
};

export const OWASP_LLM_TOP_10_NAMES = [
  'Prompt Injection',
  'Sensitive Information Disclosure',
  'Supply Chain',
  'Data and Model Poisoning',
  'Improper Output Handling',
  'Excessive Agency',
  'System Prompt Leakage',
  'Vector and Embedding Weaknesses',
  'Misinformation',
  'Unbounded Consumption',
];

export const OWASP_API_TOP_10_NAMES = [
  'Broken Object Level Authorization',
  'Broken Authentication',
  'Broken Object Property Level Authorization',
  'Unrestricted Resource Consumption',
  'Broken Function Level Authorization',
  'Unrestricted Access to Sensitive Business Flows',
  'Server Side Request Forgery',
  'Security Misconfiguration',
  'Improper Inventory Management',
  'Unsafe Consumption of APIs',
];

export const OWASP_AGENTIC_NAMES = [
  'ASI01: Agent Goal Hijack',
  'ASI02: Tool Misuse and Exploitation',
  'ASI03: Identity and Privilege Abuse',
  'ASI04: Agentic Supply Chain Vulnerabilities',
  'ASI05: Unexpected Code Execution',
  'ASI06: Memory and Context Poisoning',
  'ASI07: Insecure Inter-Agent Communication',
  'ASI08: Cascading Failures',
  'ASI09: Human Agent Trust Exploitation',
  'ASI10: Rogue Agents',
];

export const GDPR_ARTICLE_NAMES = [
  'Principles of Processing Personal Data',
  'Special Categories of Personal Data',
  'Right of Access',
  'Right to Erasure',
  'Automated Decision-Making',
  'Data Protection by Design',
  'Security of Processing',
];

export const DOD_AI_ETHICS_PRINCIPLE_NAMES = [
  'Responsible',
  'Equitable',
  'Traceable',
  'Reliable',
  'Governable',
];

// Copied from promptfoo/src/redteam/constants/frameworks.ts — OWASP_LLM_TOP_10_MAPPING
export const OWASP_LLM_TOP_10_MAPPING: Record<
  string,
  { plugins: string[]; strategies: string[] }
> = {
  'owasp:llm:01': {
    plugins: ['ascii-smuggling', 'indirect-prompt-injection', 'prompt-extraction', 'harmful'],
    strategies: ['jailbreak', 'jailbreak-templates', 'jailbreak:composite'],
  },
  'owasp:llm:02': {
    plugins: [
      'pii:api-db',
      'pii:direct',
      'pii:session',
      'pii:social',
      'harmful:privacy',
      'cross-session-leak',
      'prompt-extraction',
    ],
    strategies: ['jailbreak', 'jailbreak-templates', 'jailbreak:composite'],
  },
  'owasp:llm:03': {
    plugins: [],
    strategies: [],
  },
  'owasp:llm:04': {
    plugins: [
      'harmful:misinformation-disinformation',
      'harmful:hate',
      'bias:age',
      'bias:disability',
      'bias:gender',
      'bias:race',
      'harmful:radicalization',
      'harmful:specialized-advice',
    ],
    strategies: ['jailbreak', 'jailbreak-templates', 'jailbreak:composite'],
  },
  'owasp:llm:05': {
    plugins: ['shell-injection', 'sql-injection', 'ssrf', 'debug-access'],
    strategies: ['jailbreak', 'jailbreak-templates'],
  },
  'owasp:llm:06': {
    plugins: [
      'excessive-agency',
      'rbac',
      'bfla',
      'bola',
      'shell-injection',
      'sql-injection',
      'ssrf',
    ],
    strategies: ['jailbreak', 'jailbreak-templates', 'jailbreak:composite'],
  },
  'owasp:llm:07': {
    plugins: [
      'prompt-extraction',
      'rbac',
      'harmful:privacy',
      'pii:api-db',
      'pii:direct',
      'pii:session',
      'pii:social',
    ],
    strategies: ['jailbreak', 'jailbreak-templates', 'jailbreak:composite'],
  },
  'owasp:llm:08': {
    plugins: [
      'cross-session-leak',
      'harmful:privacy',
      'pii:api-db',
      'pii:direct',
      'pii:session',
      'pii:social',
    ],
    strategies: ['jailbreak', 'jailbreak-templates', 'jailbreak:composite'],
  },
  'owasp:llm:09': {
    plugins: [
      'hallucination',
      'overreliance',
      'harmful:misinformation-disinformation',
      'harmful:specialized-advice',
    ],
    strategies: ['jailbreak', 'jailbreak-templates', 'jailbreak:composite'],
  },
  'owasp:llm:10': {
    plugins: ['divergent-repetition', 'reasoning-dos'],
    strategies: [],
  },
};

// Copied from promptfoo/src/redteam/constants/frameworks.ts — OWASP_API_TOP_10_MAPPING
export const OWASP_API_TOP_10_MAPPING: Record<
  string,
  { plugins: string[]; strategies: string[] }
> = {
  'owasp:api:01': {
    plugins: ['bola', 'rbac'],
    strategies: [],
  },
  'owasp:api:02': {
    plugins: ['bfla', 'rbac'],
    strategies: [],
  },
  'owasp:api:03': {
    plugins: ['excessive-agency', 'overreliance'],
    strategies: [],
  },
  'owasp:api:04': {
    plugins: ['harmful:privacy', 'pii:api-db', 'pii:session'],
    strategies: [],
  },
  'owasp:api:05': {
    plugins: ['bfla', 'bola', 'rbac'],
    strategies: [],
  },
  'owasp:api:06': {
    plugins: ['harmful:misinformation-disinformation', 'overreliance'],
    strategies: [],
  },
  'owasp:api:07': {
    plugins: ['shell-injection', 'sql-injection'],
    strategies: [],
  },
  'owasp:api:08': {
    plugins: ['harmful:privacy', 'pii:api-db', 'pii:session'],
    strategies: [],
  },
  'owasp:api:09': {
    plugins: ['harmful:specialized-advice', 'overreliance'],
    strategies: [],
  },
  'owasp:api:10': {
    plugins: ['debug-access', 'harmful:privacy'],
    strategies: [],
  },
};

// Copied from promptfoo/src/redteam/constants/frameworks.ts — OWASP_AGENTIC_TOP_10_MAPPING
export const OWASP_AGENTIC_TOP_10_MAPPING: Record<
  string,
  { plugins: string[]; strategies: string[] }
> = {
  'owasp:agentic:asi01': {
    plugins: ['hijacking', 'system-prompt-override', 'indirect-prompt-injection', 'intent'],
    strategies: ['jailbreak', 'jailbreak-templates', 'jailbreak:composite'],
  },
  'owasp:agentic:asi02': {
    plugins: ['excessive-agency', 'mcp', 'tool-discovery'],
    strategies: ['jailbreak', 'jailbreak-templates'],
  },
  'owasp:agentic:asi03': {
    plugins: ['rbac', 'bfla', 'bola', 'imitation'],
    strategies: ['jailbreak', 'jailbreak-templates'],
  },
  'owasp:agentic:asi04': {
    plugins: ['indirect-prompt-injection', 'mcp'],
    strategies: ['jailbreak-templates'],
  },
  'owasp:agentic:asi05': {
    plugins: ['shell-injection', 'sql-injection', 'harmful:cybercrime:malicious-code', 'ssrf'],
    strategies: ['jailbreak', 'jailbreak-templates'],
  },
  'owasp:agentic:asi06': {
    plugins: ['agentic:memory-poisoning', 'cross-session-leak', 'indirect-prompt-injection'],
    strategies: ['jailbreak', 'crescendo'],
  },
  'owasp:agentic:asi07': {
    plugins: ['indirect-prompt-injection', 'hijacking', 'imitation'],
    strategies: ['jailbreak-templates'],
  },
  'owasp:agentic:asi08': {
    plugins: ['hallucination', 'harmful:misinformation-disinformation', 'divergent-repetition'],
    strategies: ['jailbreak', 'jailbreak-templates'],
  },
  'owasp:agentic:asi09': {
    plugins: ['overreliance', 'imitation', 'harmful:misinformation-disinformation'],
    strategies: ['crescendo'],
  },
  'owasp:agentic:asi10': {
    plugins: ['excessive-agency', 'hijacking', 'rbac', 'goal-misalignment'],
    strategies: ['jailbreak', 'crescendo'],
  },
};

// Copied from promptfoo/src/redteam/constants/frameworks.ts — OWASP_LLM_RED_TEAM_MAPPING
export const OWASP_LLM_RED_TEAM_MAPPING: Record<
  string,
  { plugins: string[]; strategies: string[] }
> = {
  'owasp:llm:redteam:model': {
    plugins: [
      'ascii-smuggling', 'beavertails', 'bias:age', 'bias:disability', 'bias:gender',
      'bias:race', 'contracts', 'cyberseceval', 'donotanswer', 'divergent-repetition',
      'excessive-agency', 'hallucination', 'harmful:chemical-biological-weapons',
      'harmful:child-exploitation', 'harmful:copyright-violations', 'harmful:cybercrime',
      'harmful:cybercrime:malicious-code', 'harmful:graphic-content', 'harmful:harassment-bullying',
      'harmful:hate', 'harmful:illegal-activities', 'harmful:illegal-drugs',
      'harmful:illegal-drugs:meth', 'harmful:indiscriminate-weapons', 'harmful:insults',
      'harmful:intellectual-property', 'harmful:misinformation-disinformation',
      'harmful:non-violent-crime', 'harmful:profanity', 'harmful:radicalization',
      'harmful:self-harm', 'harmful:sex-crime', 'harmful:sexual-content',
      'harmful:specialized-advice', 'harmful:unsafe-practices', 'harmful:violent-crime',
      'harmful:weapons:ied', 'hijacking', 'imitation', 'overreliance', 'pii:direct',
      'pliny', 'politics', 'religion',
    ],
    strategies: [
      'jailbreak', 'jailbreak:tree', 'jailbreak:composite', 'crescendo',
      'goat', 'jailbreak-templates', 'best-of-n',
    ],
  },
  'owasp:llm:redteam:implementation': {
    plugins: [
      'pii:api-db', 'pii:direct', 'pii:session', 'pii:social',
      'prompt-extraction', 'harmful:privacy', 'rbac', 'bfla', 'bola', 'ascii-smuggling',
    ],
    strategies: [
      'jailbreak', 'jailbreak:tree', 'jailbreak:composite', 'jailbreak-templates',
      'hex', 'base64', 'homoglyph', 'leetspeak', 'morse', 'piglatin', 'rot13',
    ],
  },
  'owasp:llm:redteam:system': {
    plugins: [
      'shell-injection', 'sql-injection', 'ssrf', 'debug-access', 'tool-discovery',
      'indirect-prompt-injection', 'hijacking',
    ],
    strategies: ['jailbreak', 'jailbreak:tree', 'jailbreak:composite', 'crescendo', 'goat', 'gcg'],
  },
  'owasp:llm:redteam:runtime': {
    plugins: [
      'excessive-agency', 'overreliance', 'pliny', 'competitors', 'imitation',
      'politics', 'religion', 'harmful:radicalization', 'harmful:self-harm', 'harmful:hate',
    ],
    strategies: [
      'crescendo', 'goat', 'jailbreak:tree', 'jailbreak:composite', 'jailbreak-templates',
    ],
  },
};

// Copied from promptfoo/src/redteam/constants/frameworks.ts — NIST_AI_RMF_MAPPING
export const NIST_AI_RMF_MAPPING: Record<string, { plugins: string[]; strategies: string[] }> = {
  'nist:ai:measure:1.1': {
    plugins: ['excessive-agency', 'harmful:misinformation-disinformation'],
    strategies: ['jailbreak', 'jailbreak-templates'],
  },
  'nist:ai:measure:1.2': {
    plugins: ['excessive-agency', 'harmful:misinformation-disinformation'],
    strategies: ['jailbreak', 'jailbreak-templates'],
  },
  'nist:ai:measure:2.1': {
    plugins: ['harmful:privacy', 'pii:api-db', 'pii:direct', 'pii:session', 'pii:social'],
    strategies: [],
  },
  'nist:ai:measure:2.2': {
    plugins: ['harmful:privacy', 'pii:api-db', 'pii:direct', 'pii:session', 'pii:social'],
    strategies: [],
  },
  'nist:ai:measure:2.3': {
    plugins: ['excessive-agency'],
    strategies: [],
  },
  'nist:ai:measure:2.4': {
    plugins: ['excessive-agency', 'harmful:misinformation-disinformation'],
    strategies: ['jailbreak', 'jailbreak-templates'],
  },
  'nist:ai:measure:2.5': {
    plugins: ['excessive-agency'],
    strategies: [],
  },
  'nist:ai:measure:2.6': {
    plugins: [
      'harmful:chemical-biological-weapons',
      'harmful:indiscriminate-weapons',
      'harmful:unsafe-practices',
    ],
    strategies: [],
  },
  'nist:ai:measure:2.7': {
    plugins: ['harmful:cybercrime', 'shell-injection', 'sql-injection'],
    strategies: ['jailbreak', 'jailbreak-templates'],
  },
  'nist:ai:measure:2.8': {
    plugins: ['bfla', 'bola', 'rbac'],
    strategies: [],
  },
  'nist:ai:measure:2.9': {
    plugins: ['excessive-agency'],
    strategies: [],
  },
  'nist:ai:measure:2.10': {
    plugins: ['harmful:privacy', 'pii:api-db', 'pii:direct', 'pii:session', 'pii:social'],
    strategies: [],
  },
  'nist:ai:measure:2.11': {
    plugins: ['harmful:harassment-bullying', 'harmful:hate', 'harmful:insults'],
    strategies: [],
  },
  'nist:ai:measure:2.12': {
    plugins: [],
    strategies: [],
  },
  'nist:ai:measure:2.13': {
    plugins: ['excessive-agency'],
    strategies: [],
  },
  'nist:ai:measure:3.1': {
    plugins: ['excessive-agency', 'harmful:misinformation-disinformation'],
    strategies: ['jailbreak', 'jailbreak-templates'],
  },
  'nist:ai:measure:3.2': {
    plugins: ['excessive-agency'],
    strategies: [],
  },
  'nist:ai:measure:3.3': {
    plugins: ['excessive-agency'],
    strategies: [],
  },
  'nist:ai:measure:4.1': {
    plugins: ['excessive-agency'],
    strategies: [],
  },
  'nist:ai:measure:4.2': {
    plugins: ['excessive-agency', 'harmful:misinformation-disinformation'],
    strategies: [],
  },
  'nist:ai:measure:4.3': {
    plugins: ['excessive-agency'],
    strategies: [],
  },
};

// Copied from promptfoo/src/redteam/constants/frameworks.ts — MITRE_ATLAS_MAPPING
export const MITRE_ATLAS_MAPPING: Record<string, { plugins: string[]; strategies: string[] }> = {
  'mitre:atlas:exfiltration': {
    plugins: [
      'ascii-smuggling', 'harmful:privacy', 'indirect-prompt-injection',
      'pii:api-db', 'pii:direct', 'pii:session', 'pii:social', 'prompt-extraction',
    ],
    strategies: [],
  },
  'mitre:atlas:impact': {
    plugins: ['excessive-agency', 'harmful', 'hijacking', 'imitation'],
    strategies: ['crescendo'],
  },
  'mitre:atlas:initial-access': {
    plugins: ['debug-access', 'harmful:cybercrime', 'shell-injection', 'sql-injection', 'ssrf'],
    strategies: ['base64', 'jailbreak', 'leetspeak', 'jailbreak-templates', 'rot13'],
  },
  'mitre:atlas:ml-attack-staging': {
    plugins: ['ascii-smuggling', 'excessive-agency', 'hallucination', 'indirect-prompt-injection'],
    strategies: ['jailbreak', 'jailbreak:tree'],
  },
  'mitre:atlas:reconnaissance': {
    plugins: ['competitors', 'policy', 'prompt-extraction', 'rbac'],
    strategies: [],
  },
  'mitre:atlas:resource-development': {
    plugins: ['harmful:cybercrime', 'harmful:illegal-drugs', 'harmful:indiscriminate-weapons'],
    strategies: [],
  },
};

// Copied from promptfoo/src/redteam/constants/frameworks.ts — EU_AI_ACT_MAPPING
export const EU_AI_ACT_MAPPING: Record<string, { plugins: string[]; strategies: string[] }> = {
  'eu:ai-act:art5:subliminal-manipulation': {
    plugins: ['hijacking', 'intent', 'excessive-agency'],
    strategies: ['jailbreak', 'jailbreak:tree', 'jailbreak:composite', 'jailbreak-templates'],
  },
  'eu:ai-act:art5:exploitation-of-vulnerabilities': {
    plugins: ['hijacking', 'imitation', 'harmful:misinformation-disinformation'],
    strategies: [],
  },
  'eu:ai-act:art5:social-scoring': {
    plugins: ['harmful:misinformation-disinformation', 'overreliance'],
    strategies: [],
  },
  'eu:ai-act:art5:biometric-categorisation': {
    plugins: ['pii:direct', 'pii:session', 'harmful:privacy'],
    strategies: [],
  },
  'eu:ai-act:art5:remote-biometric-id-live': {
    plugins: ['pii:session', 'pii:direct', 'harmful:privacy'],
    strategies: [],
  },
  'eu:ai-act:art5:remote-biometric-id-post': {
    plugins: ['pii:api-db', 'pii:direct', 'harmful:privacy'],
    strategies: [],
  },
  'eu:ai-act:annex3:biometric-id': {
    plugins: ['pii:direct', 'pii:session', 'harmful:privacy'],
    strategies: [],
  },
  'eu:ai-act:annex3:critical-infrastructure': {
    plugins: ['shell-injection', 'sql-injection', 'ssrf', 'excessive-agency'],
    strategies: ['jailbreak', 'jailbreak-templates'],
  },
  'eu:ai-act:annex3:education': {
    plugins: ['harmful:misinformation-disinformation', 'hallucination', 'overreliance'],
    strategies: [],
  },
  'eu:ai-act:annex3:employment': {
    plugins: ['imitation', 'pii:direct', 'overreliance'],
    strategies: [],
  },
  'eu:ai-act:annex3:essential-services': {
    plugins: ['pii:direct', 'pii:session', 'excessive-agency'],
    strategies: [],
  },
  'eu:ai-act:annex3:law-enforcement': {
    plugins: ['pii:direct', 'pii:api-db', 'harmful:privacy'],
    strategies: [],
  },
  'eu:ai-act:annex3:migration-border': {
    plugins: ['pii:direct', 'harmful:hate', 'harmful:privacy'],
    strategies: [],
  },
  'eu:ai-act:annex3:justice-democracy': {
    plugins: ['hallucination', 'harmful:misinformation-disinformation', 'pii:direct'],
    strategies: [],
  },
};

// Copied from promptfoo/src/redteam/constants/frameworks.ts — ISO_42001_MAPPING
export const ISO_42001_MAPPING: Record<string, { plugins: string[]; strategies: string[] }> = {
  'iso:42001:accountability': {
    plugins: ['excessive-agency', 'overreliance', 'hijacking'],
    strategies: [],
  },
  'iso:42001:fairness': {
    plugins: ['bias:age', 'bias:disability', 'bias:gender', 'bias:race', 'harmful:hate'],
    strategies: [],
  },
  'iso:42001:privacy': {
    plugins: ['harmful:privacy', 'pii:api-db', 'pii:direct', 'pii:session', 'pii:social'],
    strategies: [],
  },
  'iso:42001:robustness': {
    plugins: ['ascii-smuggling', 'prompt-extraction'],
    strategies: ['jailbreak', 'jailbreak:composite', 'jailbreak:tree'],
  },
  'iso:42001:security': {
    plugins: ['shell-injection', 'sql-injection', 'ssrf', 'debug-access'],
    strategies: ['jailbreak', 'jailbreak:composite', 'base64', 'rot13'],
  },
  'iso:42001:safety': {
    plugins: [
      'harmful:chemical-biological-weapons',
      'harmful:child-exploitation',
      'harmful:violent-crime',
      'harmful:cybercrime',
      'harmful:cybercrime:malicious-code',
    ],
    strategies: ['jailbreak', 'jailbreak:composite', 'jailbreak:tree'],
  },
  'iso:42001:transparency': {
    plugins: [
      'harmful:misinformation-disinformation',
      'hallucination',
      'imitation',
      'unverifiable-claims',
      'politics',
      'religion',
    ],
    strategies: [],
  },
};

// Copied from promptfoo/src/redteam/constants/frameworks.ts — GDPR_MAPPING
export const GDPR_MAPPING: Record<string, { plugins: string[]; strategies: string[] }> = {
  'gdpr:art5': {
    plugins: [
      'harmful:privacy', 'pii:api-db', 'pii:direct', 'pii:session', 'pii:social',
      'hallucination', 'harmful:misinformation-disinformation',
    ],
    strategies: [],
  },
  'gdpr:art9': {
    plugins: [
      'pii:direct', 'pii:social', 'harmful:privacy',
      'bias:age', 'bias:disability', 'bias:gender', 'bias:race',
    ],
    strategies: [],
  },
  'gdpr:art15': {
    plugins: ['pii:api-db', 'pii:session', 'rbac', 'bola', 'bfla'],
    strategies: [],
  },
  'gdpr:art17': {
    plugins: ['pii:api-db', 'pii:direct', 'pii:session', 'harmful:privacy', 'cross-session-leak'],
    strategies: [],
  },
  'gdpr:art22': {
    plugins: [
      'bias:age', 'bias:disability', 'bias:gender', 'bias:race',
      'harmful:hate', 'overreliance', 'hallucination',
    ],
    strategies: [],
  },
  'gdpr:art25': {
    plugins: [
      'harmful:privacy', 'pii:api-db', 'pii:direct', 'pii:session', 'pii:social',
      'prompt-extraction',
    ],
    strategies: [],
  },
  'gdpr:art32': {
    plugins: [
      'shell-injection', 'sql-injection', 'ssrf', 'debug-access',
      'harmful:cybercrime', 'rbac', 'bfla', 'bola',
    ],
    strategies: [],
  },
};

// Copied from promptfoo/src/redteam/constants/frameworks.ts — DOD_AI_ETHICS_MAPPING
export const DOD_AI_ETHICS_MAPPING: Record<string, { plugins: string[]; strategies: string[] }> =
  {
    'dod:ai:ethics:01': {
      plugins: ['excessive-agency', 'goal-misalignment', 'overreliance', 'hijacking'],
      strategies: ['jailbreak', 'jailbreak-templates'],
    },
    'dod:ai:ethics:02': {
      plugins: ['bias:age', 'bias:disability', 'bias:gender', 'bias:race', 'harmful:hate'],
      strategies: [],
    },
    'dod:ai:ethics:03': {
      plugins: [
        'hallucination', 'harmful:misinformation-disinformation',
        'rag-source-attribution', 'unverifiable-claims',
      ],
      strategies: [],
    },
    'dod:ai:ethics:04': {
      plugins: [
        'harmful:misinformation-disinformation', 'harmful:unsafe-practices',
        'shell-injection', 'sql-injection', 'ssrf', 'debug-access', 'reasoning-dos',
      ],
      strategies: ['jailbreak', 'jailbreak-templates'],
    },
    'dod:ai:ethics:05': {
      plugins: [
        'excessive-agency', 'hijacking', 'indirect-prompt-injection',
        'system-prompt-override', 'rbac', 'bfla', 'bola', 'tool-discovery',
      ],
      strategies: ['jailbreak', 'jailbreak-templates', 'jailbreak:composite'],
    },
  };

// Copied from promptfoo/src/redteam/constants/frameworks.ts — ALIASED_PLUGINS
export const ALIASED_PLUGINS = [
  'dod:ai:ethics',
  'mitre:atlas',
  'nist:ai',
  'nist:ai:measure',
  'owasp:api',
  'owasp:llm',
  'owasp:llm:redteam:model',
  'owasp:llm:redteam:implementation',
  'owasp:llm:redteam:system',
  'owasp:llm:redteam:runtime',
  'owasp:agentic',
  'toxicity',
  'bias',
  'misinformation',
  'illegal-activity',
  'personal-safety',
  'tool-discovery:multi-turn',
  'eu:ai-act',
  'iso:42001',
  'gdpr',
  ...Object.keys(MITRE_ATLAS_MAPPING),
  ...Object.keys(NIST_AI_RMF_MAPPING),
  ...Object.keys(OWASP_API_TOP_10_MAPPING),
  ...Object.keys(OWASP_LLM_TOP_10_MAPPING),
  ...Object.keys(OWASP_AGENTIC_TOP_10_MAPPING),
  ...Object.keys(EU_AI_ACT_MAPPING),
  ...Object.keys(ISO_42001_MAPPING),
  ...Object.keys(GDPR_MAPPING),
  ...Object.keys(DOD_AI_ETHICS_MAPPING),
] as const;

export const ALIASED_PLUGIN_MAPPINGS: Record<
  string,
  Record<string, { plugins: string[]; strategies: string[] }>
> = {
  'dod:ai:ethics': DOD_AI_ETHICS_MAPPING,
  'mitre:atlas': MITRE_ATLAS_MAPPING,
  'nist:ai:measure': NIST_AI_RMF_MAPPING,
  'owasp:api': OWASP_API_TOP_10_MAPPING,
  'owasp:llm': OWASP_LLM_TOP_10_MAPPING,
  'owasp:llm:redteam': OWASP_LLM_RED_TEAM_MAPPING,
  'owasp:agentic': OWASP_AGENTIC_TOP_10_MAPPING,
  'eu:ai-act': EU_AI_ACT_MAPPING,
  'iso:42001': ISO_42001_MAPPING,
  gdpr: GDPR_MAPPING,
  'tool-discovery:multi-turn': {
    'tool-discovery:multi-turn': {
      plugins: ['tool-discovery'],
      strategies: [],
    },
  },
  toxicity: {
    toxicity: {
      plugins: [
        'harmful:hate', 'harmful:harassment-bullying', 'harmful:insults',
        'harmful:profanity', 'harmful:graphic-content', 'harmful:sexual-content',
      ],
      strategies: [],
    },
  },
  bias: {
    bias: {
      plugins: ['politics', 'religion', 'bias:age', 'bias:disability', 'bias:gender', 'bias:race'],
      strategies: [],
    },
  },
  misinformation: {
    misinformation: {
      plugins: [
        'harmful:misinformation-disinformation', 'hallucination',
        'harmful:radicalization', 'imitation',
      ],
      strategies: [],
    },
  },
  'illegal-activity': {
    'illegal-activity': {
      plugins: [
        'harmful:violent-crime', 'harmful:non-violent-crime', 'harmful:sex-crime',
        'harmful:cybercrime', 'harmful:illegal-activities', 'harmful:illegal-drugs',
        'harmful:illegal-drugs:meth', 'harmful:chemical-biological-weapons',
        'harmful:indiscriminate-weapons', 'harmful:weapons:ied',
      ],
      strategies: [],
    },
  },
};

// ============================================================================
// ClawdStrike guard bridge (NOT from promptfoo)
// ============================================================================

// Shared mapping entry type for the simplified guard-bridge view
export interface FrameworkMappingEntry {
  plugins: string[];
  description: string;
}

// Simplified guard-bridge views (description-only, no strategies)
// These are derived from the full mappings above for the policy builder UI

export const OWASP_LLM_TOP_10: Record<string, FrameworkMappingEntry> = Object.fromEntries(
  Object.entries(OWASP_LLM_TOP_10_MAPPING).map(([key, val], i) => [
    key,
    { plugins: val.plugins, description: OWASP_LLM_TOP_10_NAMES[i] ?? key },
  ]),
);

export const OWASP_AGENTIC: Record<string, FrameworkMappingEntry> = Object.fromEntries(
  Object.entries(OWASP_AGENTIC_TOP_10_MAPPING).map(([key, val], i) => [
    key,
    { plugins: val.plugins, description: OWASP_AGENTIC_NAMES[i] ?? key },
  ]),
);

export const MITRE_ATLAS: Record<string, FrameworkMappingEntry> = {
  "mitre:atlas:exfiltration": {
    plugins: MITRE_ATLAS_MAPPING["mitre:atlas:exfiltration"].plugins,
    description: "Data exfiltration from AI systems",
  },
  "mitre:atlas:impact": {
    plugins: MITRE_ATLAS_MAPPING["mitre:atlas:impact"].plugins,
    description: "Impact on availability, integrity, or confidentiality",
  },
  "mitre:atlas:initial-access": {
    plugins: MITRE_ATLAS_MAPPING["mitre:atlas:initial-access"].plugins,
    description: "Initial access to AI system components",
  },
  "mitre:atlas:ml-attack-staging": {
    plugins: MITRE_ATLAS_MAPPING["mitre:atlas:ml-attack-staging"].plugins,
    description: "Machine learning attack staging and preparation",
  },
  "mitre:atlas:reconnaissance": {
    plugins: MITRE_ATLAS_MAPPING["mitre:atlas:reconnaissance"].plugins,
    description: "Reconnaissance of AI system capabilities and boundaries",
  },
  "mitre:atlas:resource-development": {
    plugins: MITRE_ATLAS_MAPPING["mitre:atlas:resource-development"].plugins,
    description: "Resource development for AI attacks",
  },
};

export const NIST_AI_RMF: Record<string, FrameworkMappingEntry> = Object.fromEntries(
  Object.entries(NIST_AI_RMF_MAPPING).map(([key, val]) => {
    const descriptions: Record<string, string> = {
      "nist:ai:measure:1.1": "Identify and characterize risks",
      "nist:ai:measure:1.2": "Anticipate risks",
      "nist:ai:measure:2.1": "Privacy risk measurement",
      "nist:ai:measure:2.2": "Privacy risk assessment",
      "nist:ai:measure:2.3": "Agency and autonomy risks",
      "nist:ai:measure:2.4": "Trustworthiness measurement",
      "nist:ai:measure:2.5": "Controllability assessment",
      "nist:ai:measure:2.6": "Safety and physical harm risks",
      "nist:ai:measure:2.7": "Cybersecurity risks",
      "nist:ai:measure:2.8": "Access control measurement",
      "nist:ai:measure:2.9": "Autonomy boundaries",
      "nist:ai:measure:2.10": "Data governance risks",
      "nist:ai:measure:2.11": "Harmful bias and discrimination",
      "nist:ai:measure:2.12": "Environmental impact risks",
      "nist:ai:measure:2.13": "Explainability and interpretability",
      "nist:ai:measure:3.1": "Risk monitoring and management",
      "nist:ai:measure:3.2": "Continuous monitoring",
      "nist:ai:measure:3.3": "Incident response planning",
      "nist:ai:measure:4.1": "Governance and oversight",
      "nist:ai:measure:4.2": "Documentation and accountability",
      "nist:ai:measure:4.3": "Stakeholder engagement",
    };
    return [key, { plugins: val.plugins, description: descriptions[key] ?? key }];
  }),
);

export const EU_AI_ACT: Record<string, FrameworkMappingEntry> = Object.fromEntries(
  Object.entries(EU_AI_ACT_MAPPING).map(([key, val]) => {
    const descriptions: Record<string, string> = {
      "eu:ai-act:art5:subliminal-manipulation": "Prohibition on subliminal manipulation techniques",
      "eu:ai-act:art5:exploitation-of-vulnerabilities": "Prohibition on exploitation of vulnerable groups",
      "eu:ai-act:art5:social-scoring": "Prohibition on social scoring",
      "eu:ai-act:art5:biometric-categorisation": "Prohibition on biometric categorisation",
      "eu:ai-act:art5:remote-biometric-id-live": "Prohibition on real-time remote biometric identification",
      "eu:ai-act:art5:remote-biometric-id-post": "Restrictions on post-remote biometric identification",
      "eu:ai-act:annex3:biometric-id": "High-risk: Biometric identification systems",
      "eu:ai-act:annex3:critical-infrastructure": "High-risk: Critical infrastructure management",
      "eu:ai-act:annex3:education": "High-risk: Education and vocational training",
      "eu:ai-act:annex3:employment": "High-risk: Employment, worker management, self-employment",
      "eu:ai-act:annex3:essential-services": "High-risk: Access to essential services",
      "eu:ai-act:annex3:law-enforcement": "High-risk: Law enforcement applications",
      "eu:ai-act:annex3:migration-border": "High-risk: Migration, asylum, border control",
      "eu:ai-act:annex3:justice-democracy": "High-risk: Administration of justice and democratic processes",
    };
    return [key, { plugins: val.plugins, description: descriptions[key] ?? key }];
  }),
);

// Framework registry for convenience lookup
export const FRAMEWORK_REGISTRY: Record<string, Record<string, FrameworkMappingEntry>> = {
  "owasp:llm": OWASP_LLM_TOP_10,
  "owasp:agentic": OWASP_AGENTIC,
  "mitre:atlas": MITRE_ATLAS,
  "nist:ai:measure": NIST_AI_RMF,
  "eu:ai-act": EU_AI_ACT,
};

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
