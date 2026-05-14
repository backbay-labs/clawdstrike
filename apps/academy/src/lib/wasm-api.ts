import { getWasm } from './wasm';

// --- Types ---

export interface PromptInjectionResult {
  level: 'safe' | 'low' | 'medium' | 'high' | 'critical';
  score: number;
  indicators: string[];
}

export interface JailbreakResult {
  riskScore: number;
  severity: 'safe' | 'low' | 'medium' | 'high' | 'critical';
  blocked: boolean;
  layerResults: Record<string, unknown>;
  session?: Record<string, unknown>;
}

export interface SanitizeResult {
  wasRedacted: boolean;
  redactedText: string;
  stats: { findingsCount: number };
}

export interface SpiderSenseResult {
  verdict: 'allow' | 'deny';
  topScore: number;
  topMatches: Array<{ id: string; category: string; score: number }>;
}

export interface InstructionHierarchyResult {
  allowed: boolean;
  violations: string[];
}

// --- API Functions ---

export async function detectPromptInjection(
  text: string,
  maxScanBytes?: number
): Promise<PromptInjectionResult> {
  const wasm = await getWasm();
  const json = wasm.detect_prompt_injection(text, maxScanBytes ?? null);
  return JSON.parse(json) as PromptInjectionResult;
}

export async function detectJailbreak(
  text: string,
  sessionId?: string
): Promise<JailbreakResult> {
  const wasm = await getWasm();
  const detector = new wasm.WasmJailbreakDetector(null);
  try {
    const json = detector.detect(text, sessionId ?? null);
    return JSON.parse(json) as JailbreakResult;
  } finally {
    detector.free();
  }
}

export async function sanitizeOutput(
  text: string
): Promise<SanitizeResult> {
  const wasm = await getWasm();
  const sanitizer = new wasm.WasmOutputSanitizer(null);
  try {
    const json = sanitizer.sanitize(text);
    return JSON.parse(json) as SanitizeResult;
  } finally {
    sanitizer.free();
  }
}

export async function screenSpiderSense(
  embeddingJson: string,
  patternsJson?: string
): Promise<SpiderSenseResult> {
  const wasm = await getWasm();
  const detector = new wasm.WasmSpiderSenseDetector(null);
  try {
    if (patternsJson) {
      detector.load_patterns(patternsJson);
    }
    const json = detector.screen(embeddingJson);
    return JSON.parse(json) as SpiderSenseResult;
  } finally {
    detector.free();
  }
}

export async function enforceInstructionHierarchy(
  messagesJson: string
): Promise<InstructionHierarchyResult> {
  const wasm = await getWasm();
  const enforcer = new wasm.WasmInstructionHierarchyEnforcer(null);
  try {
    const json = enforcer.enforce(messagesJson);
    return JSON.parse(json) as InstructionHierarchyResult;
  } finally {
    enforcer.free();
  }
}
