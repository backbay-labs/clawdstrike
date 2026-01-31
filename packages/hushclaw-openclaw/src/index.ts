/**
 * @hushclaw/openclaw - OpenClaw Security Plugin
 *
 * Multi-model security enforcement for OpenClaw agents.
 *
 * @example
 * ```json
 * {
 *   "plugins": {
 *     "entries": {
 *       "@hushclaw/openclaw": {
 *         "enabled": true,
 *         "config": {
 *           "policy": "hushclaw:ai-agent-minimal",
 *           "mode": "deterministic"
 *         }
 *       }
 *     }
 *   }
 * }
 * ```
 */

import type { PluginAPI, HushClawConfig } from './types.js';
import { PolicyEngine } from './policy/engine.js';
import { policyCheckTool } from './tools/policy-check.js';
import { mergeConfig, validateConfig } from './config.js';

// Re-export types
export * from './types.js';

// Re-export modules
export { PolicyEngine, loadPolicy, validatePolicy } from './policy/index.js';
export {
  ForbiddenPathGuard,
  EgressGuard,
  SecretLeakGuard,
  PatchIntegrityGuard,
} from './guards/index.js';
export { policyCheckTool, checkPolicy } from './tools/policy-check.js';

/**
 * Plugin registration function
 *
 * This is the main entry point called by OpenClaw when loading the plugin.
 */
export default function register(api: PluginAPI): void {
  const rawConfig = api.getConfig<HushClawConfig>();
  const logger = api.getLogger?.() ?? console;

  // Validate configuration
  const configErrors = validateConfig(rawConfig);
  if (configErrors.length > 0) {
    logger.error('[hushclaw] Configuration errors:', configErrors);
  }

  // Merge with defaults
  const config = mergeConfig(rawConfig);

  // Create policy engine
  const engine = new PolicyEngine(config, logger);

  logger.info('[hushclaw] Plugin initialized', {
    mode: config.mode,
    policy: config.policy,
    guards: engine.enabledGuards(),
  });

  // Register policy_check tool
  api.registerTool(policyCheckTool(engine));

  // Register CLI commands
  api.registerCli(({ program }) => {
    const hushclaw = program
      .command('hushclaw')
      .description('Hushclaw security management');

    // Policy subcommand
    const policy = hushclaw
      .command('policy')
      .description('Policy management commands');

    policy
      .command('lint')
      .description('Validate a policy file')
      .argument('<file>', 'Policy file to validate')
      .action(async (...args: unknown[]) => {
        const file = args[0] as string;
        const result = await engine.lintPolicy(file);
        if (result.valid) {
          console.log('Policy is valid');
          if (result.warnings.length > 0) {
            console.log('Warnings:');
            for (const warning of result.warnings) {
              console.log(`  - ${warning}`);
            }
          }
        } else {
          console.error('Policy validation failed:');
          for (const error of result.errors) {
            console.error(`  - ${error}`);
          }
          process.exit(1);
        }
      });

    policy
      .command('show')
      .description('Show current policy')
      .action(() => {
        const currentPolicy = engine.getPolicy();
        console.log(JSON.stringify(currentPolicy, null, 2));
      });

    policy
      .command('reload')
      .description('Reload policy from file')
      .action(() => {
        engine.reloadPolicy();
        console.log('Policy reloaded');
      });

    // Guards subcommand
    hushclaw
      .command('guards')
      .description('List enabled security guards')
      .action(() => {
        const guards = engine.enabledGuards();
        console.log('Enabled guards:');
        for (const guard of guards) {
          console.log(`  - ${guard}`);
        }
      });

    // Check subcommand (CLI version of policy_check)
    hushclaw
      .command('check')
      .description('Check if an action is allowed')
      .argument('<action>', 'Action type (file_read, file_write, network, command)')
      .argument('<resource>', 'Resource to check')
      .action(async (...args: unknown[]) => {
        const action = args[0] as string;
        const resource = args[1] as string;
        const { checkPolicy } = await import('./tools/policy-check.js');
        const result = await checkPolicy(config, action, resource);

        if (result.allowed) {
          console.log('ALLOWED:', result.message);
        } else {
          console.log('DENIED:', result.message);
          process.exit(1);
        }
      });
  });

  // Register background service for policy hot-reload
  api.registerService({
    id: 'hushclaw-policy-watcher',
    start: async () => {
      await engine.watchPolicy(config.policy);
      logger.debug('[hushclaw] Policy watcher started');
    },
    stop: async () => {
      engine.stopWatching();
      logger.debug('[hushclaw] Policy watcher stopped');
    },
  });
}
