import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { extractFromFile, runExtraction } from '../extract';
import type { TaggedRegion } from '../extract';

function createTempFile(content: string, ext: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'extract-test-'));
  const filePath = path.join(dir, `test${ext}`);
  fs.writeFileSync(filePath, content, 'utf8');
  return filePath;
}

function cleanupPath(filePath: string): void {
  const dir = path.dirname(filePath);
  fs.rmSync(dir, { recursive: true, force: true });
}

describe('extractFromFile', () => {
  it('finds tagged regions between @academy:start and @academy:end markers', () => {
    const content = [
      'fn main() {',
      '    // @academy:start my-tag',
      '    let x = 42;',
      '    println!("{}", x);',
      '    // @academy:end my-tag',
      '}',
    ].join('\n');

    const filePath = createTempFile(content, '.rs');
    try {
      const regions = extractFromFile(filePath);
      expect(regions).toHaveLength(1);
      expect(regions[0].tag).toBe('my-tag');
      expect(regions[0].code).toContain('let x = 42;');
      expect(regions[0].code).toContain('println!');
    } finally {
      cleanupPath(filePath);
    }
  });

  it('returns correct tag name, code content, line numbers, and language for Rust', () => {
    const content = [
      '// preamble',
      '// @academy:start guard-check',
      'fn is_forbidden(path: &str) -> bool {',
      '    path.starts_with("/etc")',
      '}',
      '// @academy:end guard-check',
      '// postamble',
    ].join('\n');

    const filePath = createTempFile(content, '.rs');
    try {
      const regions = extractFromFile(filePath);
      expect(regions).toHaveLength(1);
      const region = regions[0];
      expect(region.tag).toBe('guard-check');
      expect(region.startLine).toBe(3);
      expect(region.endLine).toBe(5);
      expect(region.language).toBe('rust');
      expect(region.code).toBe(
        'fn is_forbidden(path: &str) -> bool {\n    path.starts_with("/etc")\n}'
      );
    } finally {
      cleanupPath(filePath);
    }
  });

  it('returns correct language for TypeScript files', () => {
    const content = [
      '// @academy:start ts-example',
      'export function hello(): string {',
      '  return "hello";',
      '}',
      '// @academy:end ts-example',
    ].join('\n');

    const filePath = createTempFile(content, '.ts');
    try {
      const regions = extractFromFile(filePath);
      expect(regions[0].language).toBe('typescript');
    } finally {
      cleanupPath(filePath);
    }
  });

  it('throws Error for unclosed @academy:start tags', () => {
    const content = [
      '// @academy:start unclosed-tag',
      'fn foo() {}',
      '// no end marker',
    ].join('\n');

    const filePath = createTempFile(content, '.rs');
    try {
      expect(() => extractFromFile(filePath)).toThrow(/unclosed/i);
    } finally {
      cleanupPath(filePath);
    }
  });

  it('returns empty array for files with no tags', () => {
    const content = [
      'fn main() {',
      '    println!("no tags here");',
      '}',
    ].join('\n');

    const filePath = createTempFile(content, '.rs');
    try {
      const regions = extractFromFile(filePath);
      expect(regions).toHaveLength(0);
    } finally {
      cleanupPath(filePath);
    }
  });

  it('handles hash-style markers for Python files', () => {
    const content = [
      'import os',
      '# @academy:start py-example',
      'def hello():',
      '    return "hello"',
      '# @academy:end py-example',
      'print("done")',
    ].join('\n');

    const filePath = createTempFile(content, '.py');
    try {
      const regions = extractFromFile(filePath);
      expect(regions).toHaveLength(1);
      expect(regions[0].tag).toBe('py-example');
      expect(regions[0].language).toBe('python');
      expect(regions[0].code).toContain('def hello():');
    } finally {
      cleanupPath(filePath);
    }
  });

  it('handles hash-style markers for YAML files', () => {
    const content = [
      'version: "1.0"',
      '# @academy:start yaml-config',
      'guards:',
      '  forbidden_path:',
      '    enabled: true',
      '# @academy:end yaml-config',
    ].join('\n');

    const filePath = createTempFile(content, '.yaml');
    try {
      const regions = extractFromFile(filePath);
      expect(regions).toHaveLength(1);
      expect(regions[0].tag).toBe('yaml-config');
      expect(regions[0].language).toBe('yaml');
    } finally {
      cleanupPath(filePath);
    }
  });

  it('extracts multiple tagged regions from one file', () => {
    const content = [
      '// @academy:start first',
      'let a = 1;',
      '// @academy:end first',
      '',
      '// @academy:start second',
      'let b = 2;',
      '// @academy:end second',
    ].join('\n');

    const filePath = createTempFile(content, '.ts');
    try {
      const regions = extractFromFile(filePath);
      expect(regions).toHaveLength(2);
      expect(regions[0].tag).toBe('first');
      expect(regions[1].tag).toBe('second');
    } finally {
      cleanupPath(filePath);
    }
  });
});

describe('runExtraction', () => {
  let outDir: string;

  beforeEach(() => {
    outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'extract-out-'));
  });

  afterEach(() => {
    fs.rmSync(outDir, { recursive: true, force: true });
  });

  it('writes JSON files to output directory', () => {
    const content = [
      '// @academy:start demo-tag',
      'const x = 1;',
      '// @academy:end demo-tag',
    ].join('\n');

    const filePath = createTempFile(content, '.ts');
    try {
      const manifest = [{ file: filePath, expectedTags: ['demo-tag'] }];
      runExtraction(manifest, outDir);

      const outputFile = path.join(outDir, 'demo-tag.json');
      expect(fs.existsSync(outputFile)).toBe(true);

      const data = JSON.parse(fs.readFileSync(outputFile, 'utf8')) as TaggedRegion & { extractedAt: string };
      expect(data.tag).toBe('demo-tag');
      expect(data.code).toContain('const x = 1;');
      expect(data.language).toBe('typescript');
      expect(data.extractedAt).toBeDefined();
    } finally {
      cleanupPath(filePath);
    }
  });

  it('throws Error when manifest tag is missing from source files', () => {
    const content = [
      '// @academy:start existing-tag',
      'const x = 1;',
      '// @academy:end existing-tag',
    ].join('\n');

    const filePath = createTempFile(content, '.ts');
    try {
      const manifest = [
        { file: filePath, expectedTags: ['existing-tag', 'nonexistent-tag'] },
      ];
      expect(() => runExtraction(manifest, outDir)).toThrow(/nonexistent-tag/);
    } finally {
      cleanupPath(filePath);
    }
  });
});
