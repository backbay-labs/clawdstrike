import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { policyCommands } from './policy.js';
import { writeFileSync, mkdirSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

describe('policyCommands', () => {
  const testDir = join(tmpdir(), 'hushclaw-cli-test-' + Date.now());
  let consoleLog: ReturnType<typeof vi.spyOn>;
  let processExit: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    mkdirSync(testDir, { recursive: true });
    consoleLog = vi.spyOn(console, 'log').mockImplementation(() => {});
    processExit = vi.spyOn(process, 'exit').mockImplementation(() => undefined as never);
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
    consoleLog.mockRestore();
    processExit.mockRestore();
  });

  describe('lint', () => {
    it('validates a correct policy file', async () => {
      const policyPath = join(testDir, 'valid.yaml');
      writeFileSync(policyPath, `
version: hushclaw-v1.0
egress:
  mode: allowlist
  allowed_domains:
    - api.github.com
`);
      await policyCommands.lint(policyPath);
      expect(consoleLog).toHaveBeenCalledWith(expect.stringContaining('valid'));
    });

    it('reports invalid policy file', async () => {
      const policyPath = join(testDir, 'invalid.yaml');
      writeFileSync(policyPath, `
egress:
  mode: invalid_mode
`);
      await policyCommands.lint(policyPath);
      expect(consoleLog).toHaveBeenCalledWith(expect.stringContaining('failed'));
      expect(processExit).toHaveBeenCalledWith(1);
    });

    it('handles missing file', async () => {
      await policyCommands.lint('/nonexistent/policy.yaml');
      expect(consoleLog).toHaveBeenCalledWith(expect.stringContaining('Failed'));
      expect(processExit).toHaveBeenCalledWith(1);
    });
  });

  describe('test', () => {
    it('tests event against policy', async () => {
      const policyPath = join(testDir, 'policy.yaml');
      const eventPath = join(testDir, 'event.json');

      writeFileSync(policyPath, `
filesystem:
  forbidden_paths:
    - ~/.ssh
`);
      writeFileSync(eventPath, JSON.stringify({
        type: 'file_read',
        resource: '~/.ssh/id_rsa',
      }));

      await policyCommands.test(eventPath, { policy: policyPath });
      expect(consoleLog).toHaveBeenCalledWith('Decision:', 'DENIED');
    });
  });
});
