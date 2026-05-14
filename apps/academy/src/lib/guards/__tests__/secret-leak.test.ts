import { describe, it, expect } from 'vitest';
import { evaluateSecretLeak } from '../secret-leak';
import type { GuardAction } from '../types';

const defaultConfig = {};

describe('evaluateSecretLeak', () => {
  it('denies content with AWS access key', () => {
    const action: GuardAction = {
      type: 'file_write',
      path: '/tmp/config.json',
      content: 'AWS_KEY=AKIAIOSFODNN7EXAMPLE',
    };
    const result = evaluateSecretLeak(defaultConfig, action);
    expect(result.allowed).toBe(false);
    expect(result.severity).toBe('critical');
    expect(result.guard).toBe('secret_leak');
  });

  it('denies content with GitHub token', () => {
    const action: GuardAction = {
      type: 'file_write',
      path: '/tmp/env',
      content: 'TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij',
    };
    const result = evaluateSecretLeak(defaultConfig, action);
    expect(result.allowed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('denies content with RSA private key header', () => {
    const action: GuardAction = {
      type: 'file_write',
      path: '/tmp/key.pem',
      content: '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK...',
    };
    const result = evaluateSecretLeak(defaultConfig, action);
    expect(result.allowed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('denies content with generic private key header', () => {
    const action: GuardAction = {
      type: 'file_write',
      path: '/tmp/key.pem',
      content: '-----BEGIN PRIVATE KEY-----\nMIIEowIBAAK...',
    };
    const result = evaluateSecretLeak(defaultConfig, action);
    expect(result.allowed).toBe(false);
  });

  it('allows clean content with no secrets', () => {
    const action: GuardAction = {
      type: 'file_write',
      path: '/tmp/readme.md',
      content: '# Hello World\nThis is a safe document.',
    };
    const result = evaluateSecretLeak(defaultConfig, action);
    expect(result.allowed).toBe(true);
    expect(result.severity).toBe('info');
  });

  it('allows non-file_write actions (passthrough)', () => {
    const action: GuardAction = { type: 'file_access', path: '/tmp/secret.key' };
    const result = evaluateSecretLeak(defaultConfig, action);
    expect(result.allowed).toBe(true);
    expect(result.severity).toBe('info');
  });

  it('detects OpenAI API key pattern', () => {
    const action: GuardAction = {
      type: 'file_write',
      path: '/tmp/.env',
      content: 'OPENAI_KEY=sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv',
    };
    const result = evaluateSecretLeak(defaultConfig, action);
    expect(result.allowed).toBe(false);
  });

  it('includes matched pattern names in details', () => {
    const action: GuardAction = {
      type: 'file_write',
      path: '/tmp/config',
      content: 'key=AKIAIOSFODNN7EXAMPLE',
    };
    const result = evaluateSecretLeak(defaultConfig, action);
    expect(result.details).toBeDefined();
    expect(result.details?.matched_patterns).toBeDefined();
    expect(result.details?.matched_patterns).toContain('aws_access_key');
  });
});
