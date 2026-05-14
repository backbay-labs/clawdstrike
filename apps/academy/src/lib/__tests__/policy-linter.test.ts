import { describe, it, expect } from 'vitest';
import { validatePolicyYaml, findYamlPosition, formatAjvError } from '../policy-linter';

describe('policy-linter', () => {
  // ---------- Test 1 ----------
  it('valid minimal policy passes validation with zero diagnostics', () => {
    const yaml = `version: "1.5.0"\nname: test-policy\n`;
    const diagnostics = validatePolicyYaml(yaml);
    expect(diagnostics).toHaveLength(0);
  });

  // ---------- Test 2 ----------
  it('unknown top-level field returns diagnostic with "Unknown field" message', () => {
    const yaml = `version: "1.5.0"\nname: test\nfoobar: true\n`;
    const diagnostics = validatePolicyYaml(yaml);
    expect(diagnostics.length).toBeGreaterThanOrEqual(1);
    const fooErr = diagnostics.find((d) => d.message.includes('Unknown field'));
    expect(fooErr).toBeDefined();
    expect(fooErr!.message).toContain('foobar');
  });

  // ---------- Test 3 ----------
  it('invalid guard config field returns diagnostic mentioning guard name', () => {
    const yaml = [
      'version: "1.5.0"',
      'name: test',
      'guards:',
      '  forbidden_path:',
      '    nonexistent: true',
    ].join('\n');
    const diagnostics = validatePolicyYaml(yaml);
    expect(diagnostics.length).toBeGreaterThanOrEqual(1);
    const guardErr = diagnostics.find(
      (d) => d.message.includes('forbidden_path') || d.message.includes('nonexistent'),
    );
    expect(guardErr).toBeDefined();
  });

  // ---------- Test 4 ----------
  it('invalid version string returns diagnostic mentioning "version"', () => {
    const yaml = `version: "9.9.9"\nname: test\n`;
    const diagnostics = validatePolicyYaml(yaml);
    expect(diagnostics.length).toBeGreaterThanOrEqual(1);
    const verErr = diagnostics.find((d) => d.message.includes('version'));
    expect(verErr).toBeDefined();
  });

  // ---------- Test 5 ----------
  it('findYamlPosition maps "/guards/forbidden_path" to correct offset', () => {
    const yaml = [
      'version: "1.5.0"',
      'name: test',
      'guards:',
      '  forbidden_path:',
      '    patterns: []',
    ].join('\n');
    const pos = findYamlPosition(yaml, '/guards/forbidden_path');
    // The position should point somewhere inside the "forbidden_path:" block
    // (at the value, which is the nested object starting with "patterns")
    expect(pos.from).toBeGreaterThan(0);
    expect(pos.to).toBeGreaterThan(pos.from);
    // The offset should land within the YAML text
    const slice = yaml.slice(pos.from, pos.to);
    // The value node of forbidden_path is the mapping containing "patterns: []"
    expect(slice).toContain('patterns');
  });

  // ---------- Test 6 ----------
  it('findYamlPosition returns fallback for nonexistent path', () => {
    const yaml = 'version: "1.5.0"\nname: test\n';
    const pos = findYamlPosition(yaml, '/nonexistent/deep/path');
    expect(pos.from).toBe(0);
    // Fallback to is the first newline position
    expect(pos.to).toBe(yaml.indexOf('\n'));
  });

  // ---------- Test 7 ----------
  it('formatAjvError for additionalProperties returns "Unknown field" message', () => {
    const error = {
      keyword: 'additionalProperties',
      instancePath: '/guards',
      schemaPath: '#/$defs/GuardConfigs/additionalProperties',
      params: { additionalProperty: 'bogus_guard' },
      message: 'must NOT have additional properties',
    } as const;
    const msg = formatAjvError(error as any);
    expect(msg).toContain('Unknown field');
    expect(msg).toContain('bogus_guard');
    expect(msg).toContain('/guards');
  });

  // ---------- Test 8 ----------
  it('malformed YAML (unclosed quote) returns a YAML parse error diagnostic', () => {
    const yaml = 'version: "1.5.0\nname: test\n';
    const diagnostics = validatePolicyYaml(yaml);
    expect(diagnostics.length).toBeGreaterThanOrEqual(1);
    const parseErr = diagnostics.find((d) => d.message.includes('YAML parse error'));
    expect(parseErr).toBeDefined();
  });
});
