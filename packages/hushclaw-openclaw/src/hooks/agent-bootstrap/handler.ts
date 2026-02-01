import { generateSecurityPrompt } from '../../security-prompt.js';
import type { PolicyConfig } from '../../policy/types.js';

interface BootstrapFile {
  path: string;
  content: string;
}

interface BootstrapEvent {
  type: string;
  context: {
    bootstrapFiles: BootstrapFile[];
    cfg: {
      hushclaw?: PolicyConfig;
    };
  };
}

const handler = async (event: BootstrapEvent): Promise<void> => {
  if (event.type !== 'agent:bootstrap') return;

  const config = event.context.cfg.hushclaw || {};
  const securityPrompt = generateSecurityPrompt(config);

  event.context.bootstrapFiles.push({
    path: 'SECURITY.md',
    content: securityPrompt,
  });
};

export default handler;
