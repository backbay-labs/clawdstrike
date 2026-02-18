import { describe, it, expect } from 'vitest';
import { validatePolicy } from './validator.js';

describe('validatePolicy', () => {
  it('validates a minimal valid policy', () => {
    const policy = { version: 'clawdstrike-v1.0' };
    const result = validatePolicy(policy);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('validates a full policy', () => {
    const policy = {
      version: 'clawdstrike-v1.0',
      egress: {
        mode: 'allowlist',
        allowed_domains: ['api.github.com'],
      },
      filesystem: {
        forbidden_paths: ['~/.ssh'],
      },
      guards: {
        computer_use: {
          mode: 'guardrail',
          allowed_actions: ['remote.session.connect', 'input.inject'],
        },
        remote_desktop_side_channel: {
          clipboard_enabled: false,
          file_transfer_enabled: true,
          audio_enabled: false,
          drive_mapping_enabled: false,
          printing_enabled: false,
          session_share_enabled: false,
          max_transfer_size_bytes: 1024,
        },
        input_injection_capability: {
          allowed_input_types: ['keyboard', 'mouse'],
          require_postcondition_probe: false,
        },
      },
      on_violation: 'cancel',
    };
    const result = validatePolicy(policy);
    expect(result.valid).toBe(true);
  });

  it('rejects invalid egress mode', () => {
    const policy = {
      version: 'clawdstrike-v1.0',
      egress: { mode: 'invalid' },
    };
    const result = validatePolicy(policy as any);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('egress.mode'))).toBe(true);
  });

  it('rejects invalid on_violation', () => {
    const policy = {
      version: 'clawdstrike-v1.0',
      on_violation: 'explode',
    };
    const result = validatePolicy(policy as any);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('on_violation'))).toBe(true);
  });

  it('warns on empty forbidden_paths', () => {
    const policy = {
      version: 'clawdstrike-v1.0',
      filesystem: { forbidden_paths: [] },
    };
    const result = validatePolicy(policy);
    expect(result.valid).toBe(true);
    expect(result.warnings[0]).toContain('empty');
  });

  it('fails closed when a required env placeholder is missing (custom guards)', () => {
    const policy = {
      version: 'clawdstrike-v1.0',
      guards: {
        custom: [
          { package: 'clawdstrike-virustotal', config: { api_key: '${VT_API_KEY}' } },
        ],
      },
    };
    const result = validatePolicy(policy as any);
    expect(result.valid).toBe(false);
    expect(result.errors.join('\n')).toMatch(/missing environment variable/i);
  });

  it('accepts canonical schema policies', () => {
    const policy = {
      version: '1.2.0',
      guards: {
        forbidden_path: {
          patterns: ['~/.ssh'],
        },
      },
    };
    const result = validatePolicy(policy as any);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('rejects invalid computer_use mode', () => {
    const policy = {
      version: 'clawdstrike-v1.0',
      guards: {
        computer_use: {
          mode: 'block_everything',
        },
      },
    };
    const result = validatePolicy(policy as any);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('guards.computer_use.mode'))).toBe(true);
  });

  it('rejects unknown fields in remote_desktop_side_channel config', () => {
    const policy = {
      version: 'clawdstrike-v1.0',
      guards: {
        remote_desktop_side_channel: {
          clipboard_enabled: true,
          unsupported_field: true,
        },
      },
    };
    const result = validatePolicy(policy as any);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('unsupported_field'))).toBe(true);
  });
});
