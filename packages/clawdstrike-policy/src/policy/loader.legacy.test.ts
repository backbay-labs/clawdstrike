import { loadPolicyFromString } from './loader.js';

describe('policy loader legacy translation', () => {
  it('translates OpenClaw legacy schema (clawdstrike-v1.0) to canonical', () => {
    const warnings: string[] = [];
    const legacyYaml = `
version: "clawdstrike-v1.0"
filesystem:
  forbidden_paths:
    - "~/.ssh"
egress:
  mode: allowlist
  allowed_domains:
    - "api.github.com"
tools:
  denied:
    - "shell_exec"
`;

    const policy = loadPolicyFromString(legacyYaml, { resolve: false, onWarning: (m) => warnings.push(m) });

    expect(policy.version).toBe('1.1.0');
    expect(warnings.join('\n')).toMatch(/legacy OpenClaw policy/i);
    expect((policy as any).legacy_openclaw).toBeTruthy();
    expect((policy.guards as any)?.forbidden_path?.patterns).toEqual(['~/.ssh']);
    expect((policy.guards as any)?.egress_allowlist?.default_action).toBe('block');
    expect((policy.guards as any)?.mcp_tool?.block).toEqual(['shell_exec']);
  });
});
