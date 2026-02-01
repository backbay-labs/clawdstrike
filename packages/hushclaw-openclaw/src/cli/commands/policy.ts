import { readFileSync } from 'fs';
import { loadPolicy, loadPolicyFromString } from '../../policy/loader.js';
import { validatePolicy } from '../../policy/validator.js';
import { PolicyEngine } from '../../policy/engine.js';
import type { PolicyEvent } from '../../policy/types.js';

export const policyCommands = {
  async lint(file: string): Promise<void> {
    try {
      const content = readFileSync(file, 'utf-8');
      const policy = loadPolicyFromString(content);
      const result = validatePolicy(policy);

      if (result.valid) {
        console.log('Policy is valid');
        console.log(`   Version: ${policy.version || 'unspecified'}`);
        const guards = Object.keys(policy).filter(k => !['version', 'on_violation', 'extends'].includes(k));
        console.log(`   Guards: ${guards.join(', ') || 'none'}`);

        if (result.warnings.length > 0) {
          console.log('\nWarnings:');
          result.warnings.forEach(w => console.log(`   - ${w}`));
        }
      } else {
        console.log('Policy validation failed:');
        result.errors.forEach(err => console.log(`   - ${err}`));
        process.exit(1);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.log(`Failed to read policy file: ${message}`);
      process.exit(1);
    }
  },

  async show(options: { policy?: string } = {}): Promise<void> {
    try {
      const policyPath = options.policy || '.hush/policy.yaml';
      const policy = await loadPolicy(policyPath);
      console.log('Current policy:');
      console.log(JSON.stringify(policy, null, 2));
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.log(`Failed to load policy: ${message}`);
      process.exit(1);
    }
  },

  async test(eventFile: string, options: { policy?: string } = {}): Promise<void> {
    try {
      const policyPath = options.policy || '.hush/policy.yaml';
      const policy = await loadPolicy(policyPath);
      const event: PolicyEvent = JSON.parse(readFileSync(eventFile, 'utf-8'));

      const engine = new PolicyEngine(policy);
      const decision = await engine.evaluate(event);

      console.log('Decision:', decision.allowed ? 'ALLOWED' : 'DENIED');
      if (decision.reason) console.log('Reason:', decision.reason);
      if (decision.guard) console.log('Guard:', decision.guard);
      if (decision.severity) console.log('Severity:', decision.severity);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.log(`Failed to test event: ${message}`);
      process.exit(1);
    }
  },

  async diff(file1: string, file2: string): Promise<void> {
    try {
      const p1 = await loadPolicy(file1);
      const p2 = await loadPolicy(file2);

      console.log('Policy Diff:');
      console.log('============');

      // Compare egress
      if (JSON.stringify(p1.egress) !== JSON.stringify(p2.egress)) {
        console.log('\nEgress:');
        console.log('  File 1:', JSON.stringify(p1.egress || {}));
        console.log('  File 2:', JSON.stringify(p2.egress || {}));
      }

      // Compare filesystem
      if (JSON.stringify(p1.filesystem) !== JSON.stringify(p2.filesystem)) {
        console.log('\nFilesystem:');
        console.log('  File 1:', JSON.stringify(p1.filesystem || {}));
        console.log('  File 2:', JSON.stringify(p2.filesystem || {}));
      }

      // Compare on_violation
      if (p1.on_violation !== p2.on_violation) {
        console.log('\nOn Violation:');
        console.log('  File 1:', p1.on_violation || 'default');
        console.log('  File 2:', p2.on_violation || 'default');
      }

      if (JSON.stringify(p1) === JSON.stringify(p2)) {
        console.log('Policies are identical');
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.log(`Failed to diff policies: ${message}`);
      process.exit(1);
    }
  },
};
