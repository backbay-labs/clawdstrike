/**
 * @hushclaw/openclaw - Agent Bootstrap Hook Handler
 *
 * Injects a SECURITY.md file into the agent bootstrap context.
 */

import type { AgentBootstrapEvent, HookEvent, HookHandler, HushClawConfig } from '../../types.js';
import { PolicyEngine } from '../../policy/engine.js';
import { generateSecurityPrompt } from '../../security-prompt.js';

let engine: PolicyEngine | null = null;

export function initialize(config: HushClawConfig): void {
  engine = new PolicyEngine(config);
}

function getEngine(config?: HushClawConfig): PolicyEngine {
  if (!engine) {
    engine = new PolicyEngine(config ?? {});
  }
  return engine;
}

const handler: HookHandler = async (event: HookEvent): Promise<void> => {
  if (event.type !== 'agent:bootstrap') return;

  const bootstrap = event as AgentBootstrapEvent;
  const cfg = bootstrap.context.cfg;
  const policyEngine = getEngine(cfg);

  const policy = policyEngine.getPolicy();
  const enabledGuards = policyEngine.enabledGuards();

  const securityPrompt =
    generateSecurityPrompt(policy) +
    `\n\n## Enabled Guards\n` +
    enabledGuards.map((g) => `- ${g}`).join('\n');

  bootstrap.context.bootstrapFiles.push({
    path: 'SECURITY.md',
    content: securityPrompt,
  });
};

export default handler;
