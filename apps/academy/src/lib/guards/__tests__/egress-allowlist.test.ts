import { describe, it, expect } from 'vitest';
import { evaluateEgressAllowlist } from '../egress-allowlist';
import type { GuardAction } from '../types';

const defaultConfig = {};

describe('evaluateEgressAllowlist', () => {
  it('allows api.openai.com via *.openai.com pattern', () => {
    const action: GuardAction = { type: 'network_egress', host: 'api.openai.com' };
    const result = evaluateEgressAllowlist(defaultConfig, action);
    expect(result.allowed).toBe(true);
    expect(result.guard).toBe('egress_allowlist');
  });

  it('denies evil.example.com not in allow list with default_action block', () => {
    const action: GuardAction = { type: 'network_egress', host: 'evil.example.com' };
    const result = evaluateEgressAllowlist(defaultConfig, action);
    expect(result.allowed).toBe(false);
    expect(result.severity).toBe('error');
  });

  it('allows api.github.com exact match', () => {
    const action: GuardAction = { type: 'network_egress', host: 'api.github.com' };
    const result = evaluateEgressAllowlist(defaultConfig, action);
    expect(result.allowed).toBe(true);
  });

  it('block list takes precedence over allow list', () => {
    const config = {
      allow: ['*.example.com'],
      block: ['evil.example.com'],
      default_action: 'block',
    };
    const action: GuardAction = { type: 'network_egress', host: 'evil.example.com' };
    const result = evaluateEgressAllowlist(config, action);
    expect(result.allowed).toBe(false);
  });

  it('allows non-network actions (passthrough)', () => {
    const action: GuardAction = { type: 'file_access', path: '/tmp/test.txt' };
    const result = evaluateEgressAllowlist(defaultConfig, action);
    expect(result.allowed).toBe(true);
    expect(result.severity).toBe('info');
  });

  it('allows anthropic.com via *.anthropic.com wildcard', () => {
    const action: GuardAction = { type: 'network_egress', host: 'api.anthropic.com' };
    const result = evaluateEgressAllowlist(defaultConfig, action);
    expect(result.allowed).toBe(true);
  });

  it('allows registry.npmjs.org exact match', () => {
    const action: GuardAction = { type: 'network_egress', host: 'registry.npmjs.org' };
    const result = evaluateEgressAllowlist(defaultConfig, action);
    expect(result.allowed).toBe(true);
  });

  it('denies unknown domains when default_action is block', () => {
    const action: GuardAction = { type: 'network_egress', host: 'malware.io' };
    const result = evaluateEgressAllowlist(defaultConfig, action);
    expect(result.allowed).toBe(false);
  });
});
