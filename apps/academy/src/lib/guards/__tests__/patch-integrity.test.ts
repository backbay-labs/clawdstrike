import { describe, it, expect } from 'vitest';
import { evaluatePatchIntegrity } from '../patch-integrity';
import type { GuardAction } from '../types';

const defaultConfig = {};

function makeDiff(additions: number, deletions: number): string {
  const lines: string[] = ['--- a/file.ts', '+++ b/file.ts', '@@ -1,10 +1,10 @@'];
  for (let i = 0; i < additions; i++) {
    lines.push(`+added line ${i}`);
  }
  for (let i = 0; i < deletions; i++) {
    lines.push(`-removed line ${i}`);
  }
  return lines.join('\n');
}

describe('evaluatePatchIntegrity', () => {
  it('denies diff with 1500 additions exceeding max_additions 1000', () => {
    const diff = makeDiff(1500, 0);
    const action: GuardAction = { type: 'patch', path: 'src/main.ts', diff };
    const result = evaluatePatchIntegrity(defaultConfig, action);
    expect(result.allowed).toBe(false);
    expect(result.severity).toBe('error');
    expect(result.guard).toBe('patch_integrity');
  });

  it('denies diff with disable_security in added lines', () => {
    const diff = [
      '--- a/config.ts',
      '+++ b/config.ts',
      '@@ -1,5 +1,6 @@',
      ' const config = {',
      '+  disable_security: true,',
      '   port: 3000,',
      ' };',
    ].join('\n');
    const action: GuardAction = { type: 'patch', path: 'config.ts', diff };
    const result = evaluatePatchIntegrity(defaultConfig, action);
    expect(result.allowed).toBe(false);
  });

  it('allows small clean diff under thresholds', () => {
    const diff = makeDiff(10, 5);
    const action: GuardAction = { type: 'patch', path: 'src/main.ts', diff };
    const result = evaluatePatchIntegrity(defaultConfig, action);
    expect(result.allowed).toBe(true);
    expect(result.severity).toBe('info');
  });

  it('denies diff with chmod 777 in added lines', () => {
    const diff = [
      '--- a/setup.sh',
      '+++ b/setup.sh',
      '@@ -1,3 +1,4 @@',
      ' #!/bin/bash',
      '+chmod 777 /var/data',
      ' echo done',
    ].join('\n');
    const action: GuardAction = { type: 'patch', path: 'setup.sh', diff };
    const result = evaluatePatchIntegrity(defaultConfig, action);
    expect(result.allowed).toBe(false);
  });

  it('denies diff with skip_verify in added lines', () => {
    const diff = [
      '--- a/auth.ts',
      '+++ b/auth.ts',
      '@@ -1,3 +1,4 @@',
      '+const skip_verify = true;',
      ' export default {};',
    ].join('\n');
    const action: GuardAction = { type: 'patch', path: 'auth.ts', diff };
    const result = evaluatePatchIntegrity(defaultConfig, action);
    expect(result.allowed).toBe(false);
  });

  it('denies diff with rm -rf / in added lines', () => {
    const diff = [
      '--- a/clean.sh',
      '+++ b/clean.sh',
      '@@ -1,2 +1,3 @@',
      ' #!/bin/bash',
      '+rm -rf /',
    ].join('\n');
    const action: GuardAction = { type: 'patch', path: 'clean.sh', diff };
    const result = evaluatePatchIntegrity(defaultConfig, action);
    expect(result.allowed).toBe(false);
  });

  it('allows non-patch actions (passthrough)', () => {
    const action: GuardAction = { type: 'text', text: 'some text' };
    const result = evaluatePatchIntegrity(defaultConfig, action);
    expect(result.allowed).toBe(true);
    expect(result.severity).toBe('info');
  });

  it('denies diff exceeding max_deletions 500', () => {
    const diff = makeDiff(0, 600);
    const action: GuardAction = { type: 'patch', path: 'src/main.ts', diff };
    const result = evaluatePatchIntegrity(defaultConfig, action);
    expect(result.allowed).toBe(false);
  });
});
