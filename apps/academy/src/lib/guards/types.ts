/**
 * Unified guard evaluation types and dispatcher.
 *
 * The guard simulation layer provides browser-side evaluation of all 14
 * ClawdStrike guards. Five guards (prompt injection, jailbreak, output
 * sanitizer, spider sense, instruction hierarchy) run via WASM. The
 * remaining nine are implemented as TypeScript simulations using the same
 * patterns and thresholds from rulesets/default.yaml.
 */

// ---------------------------------------------------------------------------
// Guard Result
// ---------------------------------------------------------------------------

export interface GuardResult {
  allowed: boolean;
  guard: string;
  severity: 'info' | 'warning' | 'error' | 'critical';
  message: string;
  details?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// VerdictData (matches verdict-display.tsx)
// ---------------------------------------------------------------------------

export interface VerdictData {
  level: string;
  score: number;
  indicators: string[];
  guardName: string;
}

/**
 * Convert a GuardResult to VerdictData for the verdict display component.
 *
 * Mapping:
 *   severity -> level  (e.g. "critical" -> "critical", "info" -> "safe")
 *   allowed  -> score  (true = 0, false = 1.0)
 *   message  -> first indicator; details keys contribute additional indicators
 */
export function guardResultToVerdict(result: GuardResult): VerdictData {
  const levelMap: Record<string, string> = {
    info: 'safe',
    warning: 'low',
    error: 'high',
    critical: 'critical',
  };

  const indicators: string[] = [];
  if (result.message) {
    indicators.push(result.message);
  }
  if (result.details) {
    for (const [key, value] of Object.entries(result.details)) {
      if (Array.isArray(value)) {
        for (const item of value) {
          indicators.push(`${key}: ${String(item)}`);
        }
      } else if (value !== undefined && value !== null) {
        indicators.push(`${key}: ${String(value)}`);
      }
    }
  }

  return {
    level: levelMap[result.severity] ?? result.severity,
    score: result.allowed ? 0 : 1.0,
    indicators,
    guardName: result.guard,
  };
}

// ---------------------------------------------------------------------------
// Guard Action (discriminated union)
// ---------------------------------------------------------------------------

export type GuardAction =
  | { type: 'file_access'; path: string }
  | { type: 'file_write'; path: string; content: string }
  | { type: 'network_egress'; host: string; port?: number }
  | { type: 'shell_command'; command: string }
  | { type: 'mcp_tool'; tool: string; args?: Record<string, unknown> }
  | { type: 'patch'; path: string; diff: string }
  | { type: 'text'; text: string }
  | { type: 'custom'; action_type: string; data?: Record<string, unknown> };

// ---------------------------------------------------------------------------
// Guard Names
// ---------------------------------------------------------------------------

/** All 14 built-in guard names. */
export type GuardName =
  // TS-simulated guards (9)
  | 'forbidden_path'
  | 'path_allowlist'
  | 'egress_allowlist'
  | 'secret_leak'
  | 'shell_command'
  | 'mcp_tool'
  | 'patch_integrity'
  | 'computer_use'
  | 'remote_desktop_side_channel'
  // WASM guards (5)
  | 'prompt_injection'
  | 'jailbreak'
  | 'output_sanitizer'
  | 'spider_sense'
  | 'instruction_hierarchy';

/** Guards evaluated via WASM. */
export const WASM_GUARDS = new Set<GuardName>([
  'prompt_injection',
  'jailbreak',
  'output_sanitizer',
  'spider_sense',
  'instruction_hierarchy',
]);

/** Guards evaluated via TypeScript simulation. */
export const TS_GUARDS = new Set<GuardName>([
  'forbidden_path',
  'path_allowlist',
  'egress_allowlist',
  'secret_leak',
  'shell_command',
  'mcp_tool',
  'patch_integrity',
  'computer_use',
  'remote_desktop_side_channel',
]);

// ---------------------------------------------------------------------------
// TS Guard Module Registry (lazy imports)
// ---------------------------------------------------------------------------

type TSGuardFn = (
  config: Record<string, unknown>,
  action: GuardAction,
) => GuardResult;

const tsGuardImporters: Record<string, () => Promise<{ default: TSGuardFn } | Record<string, TSGuardFn>>> = {
  forbidden_path: () => import('./forbidden-path'),
  path_allowlist: () => import('./path-allowlist'),
  egress_allowlist: () => import('./egress-allowlist'),
  secret_leak: () => import('./secret-leak'),
  shell_command: () => import('./shell-command'),
  mcp_tool: () => import('./mcp-tool'),
  patch_integrity: () => import('./patch-integrity'),
  computer_use: () => import('./computer-use'),
  remote_desktop_side_channel: () => import('./remote-desktop'),
};

// Map guard name -> exported function name
const tsGuardFnNames: Record<string, string> = {
  forbidden_path: 'evaluateForbiddenPath',
  path_allowlist: 'evaluatePathAllowlist',
  egress_allowlist: 'evaluateEgressAllowlist',
  secret_leak: 'evaluateSecretLeak',
  shell_command: 'evaluateShellCommand',
  mcp_tool: 'evaluateMcpTool',
  patch_integrity: 'evaluatePatchIntegrity',
  computer_use: 'evaluateComputerUse',
  remote_desktop_side_channel: 'evaluateRemoteDesktop',
};

// ---------------------------------------------------------------------------
// WASM Bridge
// ---------------------------------------------------------------------------

async function evaluateWasmGuard(
  name: GuardName,
  _config: Record<string, unknown>,
  action: GuardAction,
): Promise<GuardResult> {
  // Extract text from the action
  const text = action.type === 'text' ? action.text : '';
  if (!text) {
    return {
      allowed: true,
      guard: name,
      severity: 'info',
      message: 'No text content to evaluate',
    };
  }

  switch (name) {
    case 'prompt_injection': {
      const { detectPromptInjection } = await import('@/lib/wasm-api');
      const result = await detectPromptInjection(text);
      return {
        allowed: result.level === 'safe',
        guard: name,
        severity: result.level === 'safe' ? 'info' : 'critical',
        message:
          result.level === 'safe'
            ? 'No prompt injection detected'
            : `Prompt injection detected (score: ${result.score.toFixed(2)})`,
        details: {
          score: result.score,
          indicators: result.indicators,
        },
      };
    }

    case 'jailbreak': {
      const { detectJailbreak } = await import('@/lib/wasm-api');
      const result = await detectJailbreak(text);
      return {
        allowed: !result.blocked,
        guard: name,
        severity: result.severity === 'safe' ? 'info' : 'critical',
        message: result.blocked
          ? `Jailbreak attempt detected (risk: ${result.riskScore.toFixed(2)})`
          : 'No jailbreak detected',
        details: {
          riskScore: result.riskScore,
          severity: result.severity,
          layers: result.layerResults,
        },
      };
    }

    case 'output_sanitizer': {
      const { sanitizeOutput } = await import('@/lib/wasm-api');
      const result = await sanitizeOutput(text);
      return {
        allowed: !result.wasRedacted,
        guard: name,
        severity: result.wasRedacted ? 'warning' : 'info',
        message: result.wasRedacted
          ? `Content redacted (${result.stats.findingsCount} findings)`
          : 'Output clean',
        details: {
          redacted: result.wasRedacted,
          findingsCount: result.stats.findingsCount,
        },
      };
    }

    case 'spider_sense': {
      const { screenSpiderSense } = await import('@/lib/wasm-api');
      // screenSpiderSense expects a JSON-encoded embedding vector, not raw text.
      // For the academy playground, we pass a demo 3-dim embedding derived from text length.
      const demoEmbedding = [
        Math.sin(text.length * 0.1),
        Math.cos(text.length * 0.2),
        Math.sin(text.length * 0.3),
      ];
      const result = await screenSpiderSense(JSON.stringify(demoEmbedding));
      return {
        allowed: result.verdict === 'allow',
        guard: name,
        severity: result.verdict === 'deny' ? 'critical' : 'info',
        message:
          result.verdict === 'deny'
            ? `Threat pattern matched (score: ${result.topScore.toFixed(2)})`
            : 'No threat patterns detected',
        details: {
          topScore: result.topScore,
          matches: result.topMatches,
        },
      };
    }

    case 'instruction_hierarchy': {
      const { enforceInstructionHierarchy } = await import('@/lib/wasm-api');
      // enforceInstructionHierarchy expects a JSON array of message objects, not raw text.
      const messages = [{ role: 'user', content: text }];
      const result = await enforceInstructionHierarchy(JSON.stringify(messages));
      return {
        allowed: result.allowed,
        guard: name,
        severity: result.allowed ? 'info' : 'error',
        message: result.allowed
          ? 'Instruction hierarchy valid'
          : `Hierarchy violations: ${result.violations.join(', ')}`,
        details: {
          violations: result.violations,
        },
      };
    }

    default:
      return {
        allowed: false,
        guard: name,
        severity: 'critical',
        message: `Unknown WASM guard: ${name}`,
      };
  }
}

// ---------------------------------------------------------------------------
// Unified Dispatcher
// ---------------------------------------------------------------------------

/**
 * Evaluate a guard by name, dispatching to WASM or TS simulation.
 *
 * WASM guards require a `text` action type and load the WASM binary.
 * TS guards dynamically import their simulation module.
 */
export async function evaluateGuard(
  name: GuardName,
  config: Record<string, unknown>,
  action: GuardAction,
): Promise<GuardResult> {
  // Dispatch WASM guards
  if (WASM_GUARDS.has(name)) {
    return evaluateWasmGuard(name, config, action);
  }

  // Dispatch TS guards
  if (TS_GUARDS.has(name)) {
    const importer = tsGuardImporters[name];
    const fnName = tsGuardFnNames[name];
    if (!importer || !fnName) {
      return {
        allowed: false,
        guard: name,
        severity: 'critical',
        message: `Guard module not registered: ${name}`,
      };
    }

    const mod = await importer();
    const fn = (mod as Record<string, TSGuardFn>)[fnName];
    if (typeof fn !== 'function') {
      return {
        allowed: false,
        guard: name,
        severity: 'critical',
        message: `Guard function ${fnName} not found in module for ${name}`,
      };
    }

    return fn(config, action);
  }

  // Unknown guard
  return {
    allowed: false,
    guard: name,
    severity: 'critical',
    message: `Unknown guard: ${name}`,
  };
}
