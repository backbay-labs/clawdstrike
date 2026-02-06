import { describe, expect, it } from 'vitest';

import { validatePolicy } from './validator.js';

describe('policy validator posture/version gating', () => {
  it('accepts policy v1.2.0 with posture and path_allowlist', () => {
    const lint = validatePolicy({
      version: '1.2.0',
      name: 'test',
      guards: {
        path_allowlist: {
          enabled: true,
          file_access_allow: ['**/repo/**'],
          file_write_allow: ['**/repo/**'],
        },
      },
      posture: {
        initial: 'work',
        states: {
          work: {
            capabilities: ['file_access', 'file_write'],
            budgets: {
              file_writes: 10,
            },
          },
        },
      },
    });

    expect(lint.valid).toBe(true);
    expect(lint.errors).toEqual([]);
  });

  it('rejects posture for policy v1.1.0', () => {
    const lint = validatePolicy({
      version: '1.1.0',
      posture: {
        initial: 'work',
        states: {
          work: {
            capabilities: ['file_access'],
          },
        },
      },
    });

    expect(lint.valid).toBe(false);
    expect(lint.errors).toContain('posture requires policy version 1.2.0');
  });

  it('rejects path_allowlist for policy v1.1.0', () => {
    const lint = validatePolicy({
      version: '1.1.0',
      guards: {
        path_allowlist: {
          enabled: true,
          file_access_allow: ['**/repo/**'],
        },
      },
    });

    expect(lint.valid).toBe(false);
    expect(lint.errors).toContain('path_allowlist requires policy version 1.2.0');
  });
});
