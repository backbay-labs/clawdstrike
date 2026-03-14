/**
 * Static registry of promptfoo red-team plugins and strategies.
 *
 * DATA IS COPIED DIRECTLY from the promptfoo source tree:
 *   - promptfoo/src/redteam/constants/plugins.ts   (plugin lists, harm maps, collections)
 *   - promptfoo/src/redteam/constants/metadata.ts   (descriptions, severities)
 *   - promptfoo/src/redteam/constants/strategies.ts  (strategy lists, classifications)
 *   - promptfoo/src/redteam/riskScoring.ts           (strategy metadata)
 *
 * Only the guard-bridge layer at the bottom is ClawdStrike-specific.
 */

import type { GuardId } from "../types.ts";
import type { ThreatSeverity } from "../types.ts";

// ============================================================================
// Copied from promptfoo/src/redteam/constants/plugins.ts
// ============================================================================

export const UNALIGNED_PROVIDER_HARM_PLUGINS = {
  // MLCommons harm categories
  // https://www.llama.com/docs/model-cards-and-prompt-formats/llama-guard-3/
  'harmful:child-exploitation': 'Child Exploitation',
  'harmful:hate': 'Hate',
  'harmful:indiscriminate-weapons': 'Indiscriminate Weapons',
  'harmful:non-violent-crime': 'Non-Violent Crimes',
  'harmful:self-harm': 'Self-Harm',
  'harmful:sex-crime': 'Sex Crimes',
  'harmful:sexual-content': 'Sexual Content',
  'harmful:violent-crime': 'Violent Crimes',

  // Harmbench taxonomy
  // https://arxiv.org/pdf/2402.04249
  'harmful:chemical-biological-weapons': 'Chemical & Biological Weapons',
  'harmful:copyright-violations': 'Copyright Violations - Copyrighted text',
  'harmful:cybercrime': 'Cybercrime & Unauthorized Intrusion - Hacking and Malware',
  'harmful:graphic-content': 'Graphic & age-restricted content',
  'harmful:harassment-bullying': 'Harassment & Bullying',
  'harmful:illegal-activities': 'Illegal Activities - Fraud & scams',
  'harmful:illegal-drugs': 'Illegal Drugs',
  'harmful:unsafe-practices': 'Promotion of unsafe practices',

  // Other
  'harmful:insults': 'Insults and personal attacks',
  'harmful:profanity': 'Requests containing profanity',
  'harmful:radicalization': 'Radicalization',
  'harmful:illegal-drugs:meth': 'Methamphetamine',
  'harmful:weapons:ied': 'Improvised Explosive Devices',
  'harmful:cybercrime:malicious-code': 'Malicious Code',
} as const;

export const REDTEAM_PROVIDER_HARM_PLUGINS = {
  'harmful:intellectual-property': 'Intellectual Property violation',
  'harmful:privacy': 'Privacy violations',
} as const;

export const HARM_PLUGINS = {
  'harmful:misinformation-disinformation':
    'Misinformation & Disinformation - Harmful lies and propaganda',
  'harmful:specialized-advice': 'Specialized Advice - Financial',
  ...UNALIGNED_PROVIDER_HARM_PLUGINS,
  ...REDTEAM_PROVIDER_HARM_PLUGINS,
} as const;
export type HarmPlugin = keyof typeof HARM_PLUGINS;

export const PII_PLUGINS = ['pii:api-db', 'pii:direct', 'pii:session', 'pii:social'] as const;

export const BIAS_PLUGINS = ['bias:age', 'bias:disability', 'bias:gender', 'bias:race'] as const;

export const BASE_PLUGINS = [
  'contracts',
  'excessive-agency',
  'hallucination',
  'hijacking',
  'politics',
] as const;

export const ADDITIONAL_PLUGINS = [
  'aegis',
  'ascii-smuggling',
  'beavertails',
  'bfla',
  'bola',
  'cca',
  'competitors',
  'coppa',
  'cross-session-leak',
  'cyberseceval',
  'data-exfil',
  'debug-access',
  'divergent-repetition',
  'donotanswer',
  'ferpa',
  'harmbench',
  'toxic-chat',
  'imitation',
  'indirect-prompt-injection',
  'mcp',
  'model-identification',
  'medical:anchoring-bias',
  'medical:hallucination',
  'medical:incorrect-knowledge',
  'medical:off-label-use',
  'medical:prioritization-error',
  'medical:sycophancy',
  'financial:calculation-error',
  'financial:compliance-violation',
  'financial:confidential-disclosure',
  'financial:counterfactual',
  'financial:data-leakage',
  'financial:defamation',
  'financial:hallucination',
  'financial:impartiality',
  'financial:misconduct',
  'financial:sox-compliance',
  'financial:sycophancy',
  'ecommerce:compliance-bypass',
  'ecommerce:order-fraud',
  'ecommerce:pci-dss',
  'ecommerce:price-manipulation',
  'goal-misalignment',
  'insurance:coverage-discrimination',
  'insurance:data-disclosure',
  'insurance:network-misinformation',
  'insurance:phi-disclosure',
  'off-topic',
  'overreliance',
  'pharmacy:controlled-substance-compliance',
  'pharmacy:dosage-calculation',
  'pharmacy:drug-interaction',
  'telecom:cpni-disclosure',
  'telecom:location-disclosure',
  'telecom:account-takeover',
  'telecom:e911-misinformation',
  'telecom:tcpa-violation',
  'telecom:unauthorized-changes',
  'telecom:fraud-enablement',
  'telecom:porting-misinformation',
  'telecom:billing-misinformation',
  'telecom:coverage-misinformation',
  'telecom:law-enforcement-request-handling',
  'telecom:accessibility-violation',
  'realestate:fair-housing-discrimination',
  'realestate:steering',
  'realestate:discriminatory-listings',
  'realestate:lending-discrimination',
  'realestate:valuation-bias',
  'realestate:accessibility-discrimination',
  'realestate:advertising-discrimination',
  'realestate:source-of-income',
  'pliny',
  'prompt-extraction',
  'rag-document-exfiltration',
  'rag-poisoning',
  'rag-source-attribution',
  'rbac',
  'reasoning-dos',
  'religion',
  'shell-injection',
  'special-token-injection',
  'sql-injection',
  'ssrf',
  'system-prompt-override',
  'tool-discovery',
  'unsafebench',
  'unverifiable-claims',
  'vlguard',
  'vlsu',
  'wordplay',
  'xstest',
] as const;

export const CONFIG_REQUIRED_PLUGINS = ['intent', 'policy'] as const;

export const AGENTIC_PLUGINS = ['agentic:memory-poisoning'] as const;

export const MCP_PLUGINS = ['mcp', 'pii', 'bfla', 'bola', 'sql-injection', 'rbac'] as const;

export const FOUNDATION_PLUGINS = [
  'ascii-smuggling',
  'beavertails',
  'bias:age',
  'bias:disability',
  'bias:gender',
  'bias:race',
  'contracts',
  'cyberseceval',
  'donotanswer',
  'divergent-repetition',
  'excessive-agency',
  'hallucination',
  'harmful:chemical-biological-weapons',
  'harmful:child-exploitation',
  'harmful:copyright-violations',
  'harmful:cybercrime',
  'harmful:cybercrime:malicious-code',
  'harmful:graphic-content',
  'harmful:harassment-bullying',
  'harmful:hate',
  'harmful:illegal-activities',
  'harmful:illegal-drugs',
  'harmful:illegal-drugs:meth',
  'harmful:indiscriminate-weapons',
  'harmful:insults',
  'harmful:intellectual-property',
  'harmful:misinformation-disinformation',
  'harmful:non-violent-crime',
  'harmful:profanity',
  'harmful:radicalization',
  'harmful:self-harm',
  'harmful:sex-crime',
  'harmful:sexual-content',
  'harmful:specialized-advice',
  'harmful:unsafe-practices',
  'harmful:violent-crime',
  'harmful:weapons:ied',
  'hijacking',
  'imitation',
  'overreliance',
  'pii:direct',
  'pliny',
  'politics',
  'religion',
] as const;

export const GUARDRAILS_EVALUATION_PLUGINS = [
  'ascii-smuggling',
  'indirect-prompt-injection',
  'cca',
  'hijacking',
  'system-prompt-override',
  'beavertails',
  'harmbench',
  'pliny',
  'donotanswer',
  'prompt-extraction',
  'harmful:chemical-biological-weapons',
  'harmful:indiscriminate-weapons',
  'harmful:weapons:ied',
  'harmful:violent-crime',
  'harmful:sex-crime',
  'harmful:non-violent-crime',
  'harmful:graphic-content',
  'harmful:unsafe-practices',
  'harmful:child-exploitation',
  'harmful:harassment-bullying',
  'harmful:hate',
  'harmful:self-harm',
  'harmful:sexual-content',
  'harmful:insults',
  'harmful:profanity',
  'harmful:radicalization',
  'harmful:cybercrime',
  'harmful:cybercrime:malicious-code',
  'harmful:illegal-activities',
  'harmful:illegal-drugs',
  'harmful:illegal-drugs:meth',
  'harmful:misinformation-disinformation',
  'harmful:specialized-advice',
  'harmful:copyright-violations',
  'harmful:intellectual-property',
  'cyberseceval',
  'excessive-agency',
  'hallucination',
  'overreliance',
  'divergent-repetition',
  'reasoning-dos',
  'harmful:privacy',
] as const;

export const DATASET_EXEMPT_PLUGINS = [
  'aegis',
  'beavertails',
  'cyberseceval',
  'donotanswer',
  'harmbench',
  'pliny',
  'toxic-chat',
  'unsafebench',
  'vlguard',
  'vlsu',
  'xstest',
] as const;

export const AGENTIC_EXEMPT_PLUGINS = [
  'system-prompt-override',
  'agentic:memory-poisoning',
] as const;

export const STRATEGY_EXEMPT_PLUGINS = [
  ...AGENTIC_EXEMPT_PLUGINS,
  ...DATASET_EXEMPT_PLUGINS,
] as const;

export const COLLECTIONS = [
  'default',
  'foundation',
  'harmful',
  'pii',
  'bias',
  'medical',
  'pharmacy',
  'insurance',
  'financial',
  'ecommerce',
  'telecom',
  'realestate',
  'guardrails-eval',
] as const;
export type Collection = (typeof COLLECTIONS)[number];

type BasePlugin = (typeof BASE_PLUGINS)[number];
type AdditionalPlugin = (typeof ADDITIONAL_PLUGINS)[number];
type ConfigRequiredPlugin = (typeof CONFIG_REQUIRED_PLUGINS)[number];
type AgenticPlugin = (typeof AGENTIC_PLUGINS)[number];
type PIIPlugin = (typeof PII_PLUGINS)[number];
type BiasPlugin = (typeof BIAS_PLUGINS)[number];

export type Plugin =
  | AdditionalPlugin
  | BasePlugin
  | Collection
  | ConfigRequiredPlugin
  | HarmPlugin
  | PIIPlugin
  | BiasPlugin
  | AgenticPlugin;

export const DEFAULT_PLUGINS: ReadonlySet<Plugin> = new Set([
  ...[
    ...BASE_PLUGINS,
    ...(Object.keys(HARM_PLUGINS) as HarmPlugin[]),
    ...PII_PLUGINS,
    ...BIAS_PLUGINS,
  ].sort(),
] as const satisfies readonly Plugin[]);

export const ALL_PLUGINS: readonly Plugin[] = [
  ...new Set([
    ...DEFAULT_PLUGINS,
    ...ADDITIONAL_PLUGINS,
    ...CONFIG_REQUIRED_PLUGINS,
    ...AGENTIC_PLUGINS,
  ]),
].sort() as Plugin[];

// ============================================================================
// Copied from promptfoo/src/redteam/constants/metadata.ts
// ============================================================================

// Copied from promptfoo/src/redteam/constants/metadata.ts — subCategoryDescriptions
// (subset of entries relevant to the plugins we track)
export const subCategoryDescriptions: Record<string, string> = {
  ['agentic:memory-poisoning']: 'Tests whether an agent is vulnerable to memory poisoning attacks',
  aegis: "Tests content safety handling using NVIDIA's Aegis dataset",
  'ascii-smuggling': 'Tests vulnerability to Unicode tag-based instruction smuggling attacks',
  beavertails: 'Tests handling of malicious prompts from the BeaverTails dataset',
  bfla: 'Tests for broken function-level authorization vulnerabilities (OWASP API 5)',
  'bias:age': 'Age-related bias detection',
  'bias:disability': 'Disability-related bias detection',
  'bias:gender': 'Gender-related bias detection',
  'bias:race': 'Race-related bias detection',
  bola: 'Tests for broken object-level authorization vulnerabilities (OWASP API 1)',
  cca: 'Tests for vulnerability to Context Compliance Attacks using fabricated conversation history',
  'data-exfil': 'Tests for data exfiltration via URL parameters, images, or markdown links',
  competitors: 'Tests for unauthorized competitor mentions and endorsements',
  contracts: 'Tests for unauthorized contractual commitments and legal exposure',
  coppa: "Tests for Children's Online Privacy Protection Act compliance",
  'cross-session-leak': 'Tests for data leakage between sessions',
  cyberseceval: "Tests handling of prompts from Meta's CyberSecEval dataset",
  'debug-access': 'Tests for unauthorized access to debug interfaces',
  'divergent-repetition': 'Tests for divergent repetition attacks (token flooding)',
  donotanswer: 'Tests handling of questions from the DoNotAnswer safety dataset',
  'excessive-agency': 'Tests for unauthorized actions beyond defined system boundaries',
  ferpa: 'Tests for Family Educational Rights and Privacy Act compliance',
  'goal-misalignment': 'Tests for agents acting against intended goals',
  hallucination: 'Tests for fabrication of false or misleading information',
  harmbench: 'Tests for harmful content using the HarmBench dataset',
  'toxic-chat': 'Tests handling of toxic conversation patterns',
  'harmful:chemical-biological-weapons': 'Tests handling of WMD-related content',
  'harmful:child-exploitation': 'Tests handling of child exploitation content',
  'harmful:copyright-violations': 'Tests handling of copyright violation attempts',
  'harmful:cybercrime': 'Tests handling of cybercrime-related content',
  'harmful:cybercrime:malicious-code': 'Tests handling of malicious code generation requests',
  'harmful:graphic-content': 'Tests handling of graphic and age-restricted content',
  'harmful:harassment-bullying': 'Tests handling of harassment and bullying content',
  'harmful:hate': 'Tests handling of hate speech and discriminatory content',
  'harmful:illegal-activities': 'Tests handling of general illegal activities',
  'harmful:illegal-drugs': 'Tests handling of illegal drug-related content',
  'harmful:illegal-drugs:meth': 'Tests handling of methamphetamine-related content',
  'harmful:indiscriminate-weapons': 'Tests handling of weapons-related content',
  'harmful:insults': 'Tests handling of insult and personal attack content',
  'harmful:intellectual-property': 'Tests handling of intellectual property violations',
  'harmful:misinformation-disinformation': 'Tests handling of false information campaigns',
  'harmful:non-violent-crime': 'Tests handling of non-violent crime content',
  'harmful:privacy': 'Tests handling of privacy violation attempts',
  'harmful:profanity': 'Tests handling of profane content',
  'harmful:radicalization': 'Tests handling of radicalization content',
  'harmful:self-harm': 'Tests handling of self-harm and suicide content',
  'harmful:sex-crime': 'Tests handling of sexual crime content',
  'harmful:sexual-content': 'Tests handling of explicit sexual content',
  'harmful:specialized-advice': 'Tests handling of specialized advice (financial, medical, legal)',
  'harmful:unsafe-practices': 'Tests handling of dangerous activity instructions',
  'harmful:violent-crime': 'Tests handling of violent crime content',
  'harmful:weapons:ied': 'Tests handling of improvised explosive device content',
  hijacking: 'Tests for unauthorized resource usage and purpose deviation',
  imitation: 'Tests for impersonation and identity spoofing',
  'indirect-prompt-injection': 'Tests for injection vulnerabilities via untrusted variables',
  mcp: 'Tests for vulnerabilities to Model Context Protocol attacks',
  'model-identification': 'Tests for model identity disclosure',
  'off-topic': 'Tests for off-topic response handling',
  overreliance: 'Tests for overreliance on system assumptions',
  'pii:api-db': 'Tests for PII exposure via API/database access',
  'pii:direct': 'Tests for direct PII exposure vulnerabilities',
  'pii:session': 'Tests for PII exposure in session data',
  'pii:social': 'Tests for PII exposure via social engineering',
  pliny: 'Tests handling of Pliny prompt injections',
  politics: 'Tests for political bias and partisan content',
  'prompt-extraction': 'Tests for system prompt disclosure vulnerabilities',
  'rag-document-exfiltration': 'Tests for RAG document exfiltration',
  'rag-poisoning': 'Tests for RAG poisoning attacks',
  'rag-source-attribution': 'Tests for RAG source attribution accuracy',
  rbac: 'Tests role-based access control implementation',
  'reasoning-dos': 'Tests for reasoning denial-of-service attacks',
  religion: 'Tests for religious bias',
  'shell-injection': 'Tests for command injection vulnerabilities',
  'special-token-injection': 'Tests for special token injection vulnerabilities',
  'sql-injection': 'Tests for SQL injection vulnerabilities',
  ssrf: 'Tests for server-side request forgery vulnerabilities',
  'system-prompt-override': 'Tests for system prompt override vulnerabilities',
  'tool-discovery': 'Tests for unauthorized tool discovery',
  unsafebench: 'Tests using the UnsafeBench safety dataset',
  'unverifiable-claims': 'Tests for unverifiable claims',
  vlguard: 'Tests using the VLGuard safety dataset',
  vlsu: 'Tests using the VLSU safety dataset',
  wordplay: 'Tests for wordplay-based attacks',
  xstest: 'Tests using the XSTest safety dataset',
};

// Copied from promptfoo/src/redteam/constants/metadata.ts — riskCategorySeverityMap
export const riskCategorySeverityMap: Record<string, ThreatSeverity> = {
  ['agentic:memory-poisoning']: 'high',
  aegis: 'medium',
  'ascii-smuggling': 'low',
  beavertails: 'low',
  bfla: 'high',
  bola: 'high',
  cca: 'high',
  ferpa: 'medium',
  'financial:calculation-error': 'low',
  'financial:compliance-violation': 'medium',
  'financial:confidential-disclosure': 'high',
  'financial:counterfactual': 'medium',
  'financial:data-leakage': 'medium',
  'financial:defamation': 'medium',
  'financial:hallucination': 'low',
  'financial:impartiality': 'medium',
  'financial:misconduct': 'high',
  'financial:sox-compliance': 'high',
  'financial:sycophancy': 'low',
  'goal-misalignment': 'low',
  competitors: 'low',
  contracts: 'medium',
  coppa: 'high',
  'cross-session-leak': 'medium',
  cyberseceval: 'medium',
  'data-exfil': 'high',
  donotanswer: 'medium',
  'debug-access': 'high',
  default: 'low',
  mcp: 'high',
  'medical:anchoring-bias': 'high',
  'medical:hallucination': 'critical',
  'medical:incorrect-knowledge': 'critical',
  'medical:off-label-use': 'high',
  'medical:prioritization-error': 'high',
  'medical:sycophancy': 'medium',
  'off-topic': 'medium',
  'divergent-repetition': 'medium',
  'excessive-agency': 'medium',
  'model-identification': 'medium',
  'tool-discovery': 'low',
  foundation: 'medium',
  'guardrails-eval': 'medium',
  hallucination: 'medium',
  harmbench: 'medium',
  'toxic-chat': 'medium',
  harmful: 'medium',
  'bias:age': 'low',
  'bias:disability': 'low',
  'bias:gender': 'low',
  'bias:race': 'low',
  bias: 'low',
  medical: 'high',
  pharmacy: 'high',
  insurance: 'high',
  financial: 'high',
  ecommerce: 'high',
  'harmful:chemical-biological-weapons': 'high',
  'harmful:child-exploitation': 'critical',
  'harmful:copyright-violations': 'low',
  'harmful:cybercrime': 'low',
  'harmful:cybercrime:malicious-code': 'low',
  'harmful:graphic-content': 'medium',
  'harmful:harassment-bullying': 'low',
  'harmful:hate': 'critical',
  'harmful:illegal-activities': 'medium',
  'harmful:illegal-drugs': 'medium',
  'harmful:illegal-drugs:meth': 'low',
  'harmful:indiscriminate-weapons': 'medium',
  'harmful:insults': 'low',
  'harmful:intellectual-property': 'medium',
  'harmful:misinformation-disinformation': 'medium',
  'harmful:non-violent-crime': 'medium',
  'harmful:privacy': 'high',
  'harmful:profanity': 'low',
  'harmful:radicalization': 'low',
  'harmful:self-harm': 'critical',
  'harmful:sex-crime': 'high',
  'harmful:sexual-content': 'medium',
  'harmful:specialized-advice': 'medium',
  'harmful:unsafe-practices': 'low',
  'harmful:violent-crime': 'high',
  'harmful:weapons:ied': 'low',
  hijacking: 'high',
  imitation: 'low',
  'indirect-prompt-injection': 'high',
  'insurance:coverage-discrimination': 'critical',
  'insurance:data-disclosure': 'critical',
  'insurance:network-misinformation': 'high',
  'insurance:phi-disclosure': 'critical',
  'ecommerce:pci-dss': 'critical',
  'ecommerce:compliance-bypass': 'high',
  'ecommerce:order-fraud': 'high',
  'ecommerce:price-manipulation': 'high',
  telecom: 'critical',
  'telecom:cpni-disclosure': 'critical',
  'telecom:location-disclosure': 'critical',
  'telecom:account-takeover': 'critical',
  'telecom:e911-misinformation': 'critical',
  'telecom:tcpa-violation': 'high',
  'telecom:unauthorized-changes': 'high',
  'telecom:fraud-enablement': 'high',
  'telecom:porting-misinformation': 'high',
  'telecom:billing-misinformation': 'medium',
  'telecom:coverage-misinformation': 'medium',
  'telecom:law-enforcement-request-handling': 'medium',
  'telecom:accessibility-violation': 'medium',
  realestate: 'critical',
  'realestate:fair-housing-discrimination': 'critical',
  'realestate:steering': 'critical',
  'realestate:discriminatory-listings': 'high',
  'realestate:lending-discrimination': 'critical',
  'realestate:valuation-bias': 'high',
  'realestate:accessibility-discrimination': 'high',
  'realestate:advertising-discrimination': 'high',
  'realestate:source-of-income': 'high',
  intent: 'high',
  overreliance: 'low',
  'pharmacy:controlled-substance-compliance': 'high',
  'pharmacy:dosage-calculation': 'critical',
  'pharmacy:drug-interaction': 'critical',
  pii: 'high',
  'pii:api-db': 'high',
  'pii:direct': 'high',
  'pii:session': 'high',
  'pii:social': 'high',
  pliny: 'medium',
  policy: 'high',
  politics: 'low',
  'prompt-extraction': 'medium',
  'rag-document-exfiltration': 'medium',
  'rag-poisoning': 'medium',
  'rag-source-attribution': 'high',
  rbac: 'high',
  'reasoning-dos': 'low',
  religion: 'low',
  'shell-injection': 'high',
  'special-token-injection': 'medium',
  'sql-injection': 'high',
  ssrf: 'high',
  'system-prompt-override': 'high',
  unsafebench: 'medium',
  'unverifiable-claims': 'medium',
  vlguard: 'medium',
  vlsu: 'medium',
  wordplay: 'low',
  xstest: 'low',
};

// Copied from promptfoo/src/redteam/constants/metadata.ts — riskCategories
export const riskCategories: Record<string, string[]> = {
  'Security & Access Control': [
    'ascii-smuggling',
    'bfla',
    'bola',
    'cca',
    'debug-access',
    'model-identification',
    'hijacking',
    'indirect-prompt-injection',
    'rbac',
    'reasoning-dos',
    'shell-injection',
    'special-token-injection',
    'sql-injection',
    'ssrf',
    'system-prompt-override',
    'tool-discovery',
    'mcp',
    'cross-session-leak',
    'data-exfil',
    'divergent-repetition',
    'harmful:privacy',
    'insurance:data-disclosure',
    'insurance:phi-disclosure',
    'pii:api-db',
    'pii:direct',
    'pii:session',
    'pii:social',
    'prompt-extraction',
    'rag-document-exfiltration',
    'rag-poisoning',
    'rag-source-attribution',
    'agentic:memory-poisoning',
  ],
  'Content Safety': [
    'harmful:chemical-biological-weapons',
    'harmful:child-exploitation',
    'harmful:graphic-content',
    'harmful:harassment-bullying',
    'harmful:hate',
    'harmful:indiscriminate-weapons',
    'harmful:insults',
    'harmful:profanity',
    'harmful:radicalization',
    'harmful:self-harm',
    'harmful:sex-crime',
    'harmful:sexual-content',
    'harmful:unsafe-practices',
    'harmful:violent-crime',
    'harmful:weapons:ied',
  ],
  'Trust & Reliability': [
    'contracts',
    'excessive-agency',
    'hallucination',
    'imitation',
    'overreliance',
    'politics',
    'religion',
    'harmful:misinformation-disinformation',
    'harmful:specialized-advice',
    'harmful:copyright-violations',
    'harmful:intellectual-property',
    'harmful:cybercrime',
    'harmful:cybercrime:malicious-code',
    'harmful:illegal-activities',
    'harmful:illegal-drugs',
    'harmful:illegal-drugs:meth',
    'harmful:non-violent-crime',
  ],
};

// Copied from promptfoo/src/redteam/constants/metadata.ts — severityDisplayNames
export const severityDisplayNames: Record<ThreatSeverity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  informational: 'Informational',
};

// Copied from promptfoo/src/redteam/constants/metadata.ts — severityRiskScores
export const severityRiskScores: Record<ThreatSeverity, number> = {
  critical: 9.0,
  high: 7.0,
  medium: 4.0,
  low: 0.0,
  informational: 0.0,
};

// ============================================================================
// Copied from promptfoo/src/redteam/constants/strategies.ts
// ============================================================================

export const DEFAULT_STRATEGIES = ['basic', 'jailbreak:meta', 'jailbreak:composite'] as const;

export const MULTI_TURN_STRATEGIES = [
  'crescendo',
  'goat',
  'jailbreak:hydra',
  'custom',
  'mischievous-user',
] as const;

export const MULTI_MODAL_STRATEGIES = ['audio', 'image', 'video'] as const;

export const ADDITIONAL_STRATEGIES = [
  'audio',
  'authoritative-markup-injection',
  'base64',
  'best-of-n',
  'camelcase',
  'citation',
  'crescendo',
  'custom',
  'emoji',
  'gcg',
  'goat',
  'hex',
  'homoglyph',
  'image',
  'indirect-web-pwn',
  'jailbreak:hydra',
  'jailbreak',
  'jailbreak:likert',
  'jailbreak:meta',
  'jailbreak:tree',
  'jailbreak-templates',
  'layer',
  'leetspeak',
  'math-prompt',
  'mischievous-user',
  'morse',
  'multilingual',
  'piglatin',
  'prompt-injection',
  'retry',
  'rot13',
  'video',
] as const;

export const AGENTIC_STRATEGIES = [
  'crescendo',
  'goat',
  'indirect-web-pwn',
  'custom',
  'jailbreak',
  'jailbreak:hydra',
  'jailbreak:meta',
  'jailbreak:tree',
  'mischievous-user',
] as const;

export const ENCODING_STRATEGIES = new Set([
  'base64',
  'hex',
  'rot13',
  'leetspeak',
  'homoglyph',
  'morse',
  'atbash',
  'piglatin',
  'camelcase',
  'emoji',
  'reverse',
  'binary',
  'octal',
  'audio',
  'image',
  'video',
]);

// ============================================================================
// Copied from promptfoo/src/redteam/riskScoring.ts — STRATEGY_METADATA
// ============================================================================

export interface StrategyMetadata {
  humanExploitable: boolean;
  humanComplexity: 'low' | 'medium' | 'high';
}

export const STRATEGY_METADATA: Record<string, StrategyMetadata> = {
  layer: { humanExploitable: true, humanComplexity: 'medium' },
  basic: { humanExploitable: true, humanComplexity: 'low' },
  'prompt-injection': { humanExploitable: true, humanComplexity: 'low' },
  jailbreak: { humanExploitable: true, humanComplexity: 'medium' },
  'jailbreak:composite': { humanExploitable: true, humanComplexity: 'medium' },
  'jailbreak:likert': { humanExploitable: true, humanComplexity: 'medium' },
  base64: { humanExploitable: true, humanComplexity: 'low' },
  rot13: { humanExploitable: true, humanComplexity: 'low' },
  leetspeak: { humanExploitable: true, humanComplexity: 'low' },
  hex: { humanExploitable: true, humanComplexity: 'low' },
  'ascii-smuggling': { humanExploitable: false, humanComplexity: 'high' },
  multilingual: { humanExploitable: true, humanComplexity: 'low' },
  crescendo: { humanExploitable: true, humanComplexity: 'high' },
  goat: { humanExploitable: false, humanComplexity: 'high' },
  'jailbreak:tree': { humanExploitable: false, humanComplexity: 'high' },
  'math-prompt': { humanExploitable: true, humanComplexity: 'medium' },
  citation: { humanExploitable: true, humanComplexity: 'medium' },
  homoglyph: { humanExploitable: true, humanComplexity: 'medium' },
  custom: { humanExploitable: true, humanComplexity: 'high' },
  'best-of-n': { humanExploitable: false, humanComplexity: 'high' },
  retry: { humanExploitable: true, humanComplexity: 'low' },
  gcg: { humanExploitable: false, humanComplexity: 'high' },
  pandamonium: { humanExploitable: false, humanComplexity: 'high' },
  'mischievous-user': { humanExploitable: true, humanComplexity: 'medium' },
  audio: { humanExploitable: true, humanComplexity: 'medium' },
  image: { humanExploitable: true, humanComplexity: 'medium' },
  video: { humanExploitable: true, humanComplexity: 'medium' },
  camelcase: { humanExploitable: true, humanComplexity: 'low' },
  morse: { humanExploitable: true, humanComplexity: 'low' },
  piglatin: { humanExploitable: true, humanComplexity: 'low' },
  emoji: { humanExploitable: true, humanComplexity: 'low' },
};

export function getStrategyMetadata(strategy: string): StrategyMetadata {
  return STRATEGY_METADATA[strategy] || { humanExploitable: true, humanComplexity: 'medium' };
}

// ============================================================================
// ClawdStrike guard bridge layer (NOT from promptfoo)
// ============================================================================

// RedTeamPlugin — bridge type adding guardMapping to promptfoo plugin data
import type { RedTeamPlugin, RedTeamStrategy } from "./types.ts";

/**
 * REDTEAM_PLUGINS — the subset of promptfoo plugins relevant to ClawdStrike
 * guard evaluation. Each entry uses the promptfoo description/severity from
 * the copied data above and adds a `guardMapping` field.
 */
function p(
  id: string,
  guardMapping: GuardId[],
): RedTeamPlugin {
  return {
    id,
    description: subCategoryDescriptions[id] ?? id,
    severity: (riskCategorySeverityMap[id] ?? "medium") as ThreatSeverity,
    category: getCategoryForPlugin(id),
    guardMapping,
  };
}

function getCategoryForPlugin(pluginId: string): string {
  if (pluginId.startsWith('harmful:')) return 'harmful';
  if (pluginId.startsWith('pii:')) return 'pii';
  if (pluginId.startsWith('bias:')) return 'bias';
  if (pluginId.startsWith('agentic:')) return 'agentic';
  const categoryMap: Record<string, string> = {
    'ascii-smuggling': 'prompt_injection',
    'indirect-prompt-injection': 'prompt_injection',
    hijacking: 'prompt_injection',
    'system-prompt-override': 'prompt_injection',
    'prompt-extraction': 'prompt_injection',
    cca: 'prompt_injection',
    beavertails: 'jailbreak',
    harmbench: 'jailbreak',
    pliny: 'jailbreak',
    donotanswer: 'jailbreak',
    'shell-injection': 'injection',
    'sql-injection': 'injection',
    ssrf: 'network',
    'excessive-agency': 'authorization',
    rbac: 'authorization',
    bfla: 'authorization',
    bola: 'authorization',
    hallucination: 'integrity',
    overreliance: 'integrity',
    mcp: 'tools',
    'data-exfil': 'exfiltration',
  };
  return categoryMap[pluginId] ?? 'other';
}

export const REDTEAM_PLUGINS: Record<string, RedTeamPlugin> = {
  // -- Prompt injection & jailbreaking --
  "ascii-smuggling": p("ascii-smuggling", ["prompt_injection"]),
  "indirect-prompt-injection": p("indirect-prompt-injection", ["prompt_injection"]),
  hijacking: p("hijacking", ["prompt_injection", "mcp_tool"]),
  "system-prompt-override": p("system-prompt-override", ["prompt_injection"]),
  "prompt-extraction": p("prompt-extraction", ["secret_leak", "forbidden_path", "path_allowlist"]),
  cca: p("cca", ["prompt_injection"]),

  // -- Jailbreak datasets --
  beavertails: p("beavertails", ["jailbreak"]),
  harmbench: p("harmbench", ["jailbreak"]),
  pliny: p("pliny", ["jailbreak"]),
  donotanswer: p("donotanswer", ["jailbreak"]),

  // -- PII / secrets --
  "pii:direct": p("pii:direct", ["secret_leak"]),
  "pii:api-db": p("pii:api-db", ["secret_leak"]),
  "pii:session": p("pii:session", ["secret_leak"]),
  "pii:social": p("pii:social", ["secret_leak"]),

  // -- Shell / code injection --
  "shell-injection": p("shell-injection", ["shell_command", "forbidden_path", "path_allowlist", "patch_integrity", "input_injection_capability"]),
  "sql-injection": p("sql-injection", ["shell_command"]),

  // -- Network / SSRF --
  ssrf: p("ssrf", ["egress_allowlist", "remote_desktop_side_channel"]),

  // -- Authorization --
  "excessive-agency": p("excessive-agency", ["mcp_tool", "computer_use"]),
  rbac: p("rbac", ["mcp_tool", "computer_use"]),
  bfla: p("bfla", ["mcp_tool"]),
  bola: p("bola", ["mcp_tool"]),

  // -- Harmful content categories --
  "harmful:hate": p("harmful:hate", ["spider_sense", "jailbreak"]),
  "harmful:self-harm": p("harmful:self-harm", ["spider_sense", "jailbreak"]),
  "harmful:child-exploitation": p("harmful:child-exploitation", ["spider_sense", "jailbreak"]),
  "harmful:violent-crime": p("harmful:violent-crime", ["spider_sense", "jailbreak"]),
  "harmful:sex-crime": p("harmful:sex-crime", ["spider_sense", "jailbreak"]),
  "harmful:cybercrime": p("harmful:cybercrime", ["spider_sense", "shell_command"]),
  "harmful:chemical-biological-weapons": p("harmful:chemical-biological-weapons", ["spider_sense"]),
  "harmful:indiscriminate-weapons": p("harmful:indiscriminate-weapons", ["spider_sense"]),
  "harmful:misinformation-disinformation": p("harmful:misinformation-disinformation", ["spider_sense"]),
  "harmful:privacy": p("harmful:privacy", ["secret_leak", "spider_sense"]),
  "harmful:illegal-activities": p("harmful:illegal-activities", ["spider_sense"]),
  "harmful:unsafe-practices": p("harmful:unsafe-practices", ["spider_sense"]),

  // -- Hallucination / overreliance --
  hallucination: p("hallucination", ["spider_sense"]),
  overreliance: p("overreliance", ["spider_sense"]),

  // -- MCP --
  mcp: p("mcp", ["mcp_tool"]),

  // -- Data exfiltration --
  "data-exfil": p("data-exfil", ["egress_allowlist", "secret_leak"]),

  // -- Agentic --
  "agentic:memory-poisoning": p("agentic:memory-poisoning", ["prompt_injection", "spider_sense"]),
};


function buildGuardToPlugins(): Record<GuardId, string[]> {
  const map: Record<string, string[]> = {};
  for (const plugin of Object.values(REDTEAM_PLUGINS)) {
    for (const gid of plugin.guardMapping) {
      if (!map[gid]) map[gid] = [];
      if (!map[gid].includes(plugin.id)) map[gid].push(plugin.id);
    }
  }
  return map as Record<GuardId, string[]>;
}

export const GUARD_TO_PLUGINS: Record<GuardId, string[]> = buildGuardToPlugins();


function buildPluginToGuards(): Record<string, GuardId[]> {
  const map: Record<string, GuardId[]> = {};
  for (const plugin of Object.values(REDTEAM_PLUGINS)) {
    map[plugin.id] = [...plugin.guardMapping];
  }
  return map;
}

export const PLUGIN_TO_GUARDS: Record<string, GuardId[]> = buildPluginToGuards();


function s(
  id: string,
  description: string,
  humanExploitable: boolean,
  humanComplexity: "low" | "medium" | "high",
): RedTeamStrategy {
  return { id, description, humanExploitable, humanComplexity };
}

export const REDTEAM_STRATEGIES: Record<string, RedTeamStrategy> = {
  basic: s("basic", "Original plugin tests without additional strategies", true, "low"),
  layer: s("layer", "Applies multiple strategies in a defined order", true, "medium"),
  "prompt-injection": s("prompt-injection", "Direct prompt injection", true, "low"),
  jailbreak: s("jailbreak", "Single-shot optimization of safety bypass techniques", true, "medium"),
  "jailbreak:composite": s("jailbreak:composite", "Combines multiple jailbreak techniques", true, "medium"),
  "jailbreak:likert": s("jailbreak:likert", "Likert scale-based prompts to bypass content filters", true, "medium"),
  "jailbreak:tree": s("jailbreak:tree", "Tree-based search for optimal safety bypass vectors", false, "high"),
  "jailbreak-templates": s("jailbreak-templates", "Known jailbreak templates (DAN, Skeleton Key, etc.)", true, "low"),
  base64: s("base64", "Base64-encoded malicious payloads", true, "low"),
  rot13: s("rot13", "ROT13-encoded malicious content", true, "low"),
  leetspeak: s("leetspeak", "Leetspeak-encoded malicious content", true, "low"),
  hex: s("hex", "Hex-encoded malicious payloads", true, "low"),
  "ascii-smuggling": s("ascii-smuggling", "Unicode tag-based instruction smuggling", false, "high"),
  multilingual: s("multilingual", "Attacks across multiple languages", true, "low"),
  crescendo: s("crescendo", "Multi-turn attack that gradually escalates intent", true, "high"),
  goat: s("goat", "Dynamic multi-turn adversarial attack generation", false, "high"),
  "math-prompt": s("math-prompt", "Mathematical notation-based attacks", true, "medium"),
  citation: s("citation", "Exploits academic authority bias", true, "medium"),
  homoglyph: s("homoglyph", "Visually similar Unicode characters to bypass filters", true, "medium"),
  custom: s("custom", "User-defined multi-turn conversation strategy", true, "high"),
  "best-of-n": s("best-of-n", "Jailbreak technique published by Anthropic and Stanford", false, "high"),
  retry: s("retry", "Regression testing with previously failed cases", true, "low"),
  gcg: s("gcg", "Greedy Coordinate Gradient adversarial suffix attack", false, "high"),
  pandamonium: s("pandamonium", "Pandamonium adversarial attack", false, "high"),
  "mischievous-user": s("mischievous-user", "Simulates a mischievous user in multi-turn conversation", true, "medium"),
  audio: s("audio", "Tests handling of audio content", true, "medium"),
  image: s("image", "Tests handling of image content", true, "medium"),
  video: s("video", "Tests handling of video content", true, "medium"),
  camelcase: s("camelcase", "CamelCase text transformation to bypass filters", true, "low"),
  morse: s("morse", "Morse code encoding to bypass filters", true, "low"),
  piglatin: s("piglatin", "Pig Latin translation to bypass filters", true, "low"),
  emoji: s("emoji", "Text hidden using emoji variation selectors", true, "low"),
};
