import { describe, it, expect } from 'vitest';
import { evaluateForbiddenPath } from '../forbidden-path';
import type { GuardAction, GuardResult } from '../types';

const defaultConfig = {};

describe('evaluateForbiddenPath', () => {
  it('denies access to SSH key paths', () => {
    const action: GuardAction = { type: 'file_access', path: '~/.ssh/id_rsa' };
    const result = evaluateForbiddenPath(defaultConfig, action);
    expect(result.allowed).toBe(false);
    expect(result.severity).toBe('critical');
    expect(result.guard).toBe('forbidden_path');
  });

  it('denies access to AWS credentials', () => {
    const action: GuardAction = { type: 'file_access', path: '~/.aws/credentials' };
    const result = evaluateForbiddenPath(defaultConfig, action);
    expect(result.allowed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('denies access to /etc/shadow', () => {
    const action: GuardAction = { type: 'file_access', path: '/etc/shadow' };
    const result = evaluateForbiddenPath(defaultConfig, action);
    expect(result.allowed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('allows access to safe project files', () => {
    const action: GuardAction = { type: 'file_access', path: '/home/user/project/src/main.rs' };
    const result = evaluateForbiddenPath(defaultConfig, action);
    expect(result.allowed).toBe(true);
    expect(result.severity).toBe('info');
  });

  it('allows access when exception pattern overrides forbidden match', () => {
    const config = {
      patterns: ['**/.env'],
      exceptions: ['**/project/.env'],
    };
    const action: GuardAction = { type: 'file_access', path: '/home/user/project/.env' };
    const result = evaluateForbiddenPath(config, action);
    expect(result.allowed).toBe(true);
  });

  it('allows non-file actions (passthrough)', () => {
    const action: GuardAction = { type: 'shell_command', command: 'ls -la' };
    const result = evaluateForbiddenPath(defaultConfig, action);
    expect(result.allowed).toBe(true);
    expect(result.severity).toBe('info');
  });

  it('denies file_write to forbidden paths', () => {
    const action: GuardAction = { type: 'file_write', path: '~/.ssh/id_rsa', content: 'secret' };
    const result = evaluateForbiddenPath(defaultConfig, action);
    expect(result.allowed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('denies access to .env files', () => {
    const action: GuardAction = { type: 'file_access', path: '/app/.env' };
    const result = evaluateForbiddenPath(defaultConfig, action);
    expect(result.allowed).toBe(false);
  });

  it('denies access to .gnupg directory', () => {
    const action: GuardAction = { type: 'file_access', path: '/home/user/.gnupg/pubring.kbx' };
    const result = evaluateForbiddenPath(defaultConfig, action);
    expect(result.allowed).toBe(false);
  });

  it('accepts custom patterns config', () => {
    const config = { patterns: ['**/secret.txt'] };
    const action: GuardAction = { type: 'file_access', path: '/tmp/secret.txt' };
    const result = evaluateForbiddenPath(config, action);
    expect(result.allowed).toBe(false);
  });
});
