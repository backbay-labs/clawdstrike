import { describe, it, expect } from 'vitest';
import { normalize, sep } from 'path';
import { FilePluginMap } from '../src/file-plugin-map';

describe('FilePluginMap', () => {
  describe('register()', () => {
    it('stores directory-to-pluginId mapping', () => {
      const map = new FilePluginMap();
      map.register('clawdstrike.my-guard', '/workspace/plugins/my-guard');

      const result = map.resolve('/workspace/plugins/my-guard/src/index.ts');
      expect(result).toBe('clawdstrike.my-guard');
    });

    it('uses default entry path src/index.ts when entry is omitted', () => {
      const map = new FilePluginMap();
      map.register('clawdstrike.my-guard', '/workspace/plugins/my-guard');

      const entry = map.getEntry('clawdstrike.my-guard');
      expect(entry).toBe('/workspace/plugins/my-guard/src/index.ts');
    });

    it('uses custom entry path when provided', () => {
      const map = new FilePluginMap();
      map.register('clawdstrike.my-guard', '/workspace/plugins/my-guard', 'lib/main.ts');

      const entry = map.getEntry('clawdstrike.my-guard');
      expect(entry).toBe('/workspace/plugins/my-guard/lib/main.ts');
    });
  });

  describe('resolve()', () => {
    it('returns correct pluginId for files within a registered directory', () => {
      const map = new FilePluginMap();
      map.register('clawdstrike.guard-a', '/workspace/plugins/guard-a');
      map.register('clawdstrike.guard-b', '/workspace/plugins/guard-b');

      expect(map.resolve('/workspace/plugins/guard-a/src/index.ts')).toBe('clawdstrike.guard-a');
      expect(map.resolve('/workspace/plugins/guard-b/src/helper.ts')).toBe('clawdstrike.guard-b');
    });

    it('returns correct pluginId for newly created files in a registered directory', () => {
      const map = new FilePluginMap();
      map.register('clawdstrike.my-guard', '/workspace/plugins/my-guard');

      // New file that wasn't registered individually
      expect(map.resolve('/workspace/plugins/my-guard/src/new-file.ts')).toBe('clawdstrike.my-guard');
      // Deeply nested new file
      expect(map.resolve('/workspace/plugins/my-guard/src/utils/deep/nested.ts')).toBe('clawdstrike.my-guard');
    });

    it('returns undefined for files outside any registered directory', () => {
      const map = new FilePluginMap();
      map.register('clawdstrike.my-guard', '/workspace/plugins/my-guard');

      expect(map.resolve('/workspace/other/file.ts')).toBeUndefined();
      expect(map.resolve('/different/path/file.ts')).toBeUndefined();
    });

    it('handles nested directories with longest prefix wins', () => {
      const map = new FilePluginMap();
      map.register('clawdstrike.parent', '/workspace/plugins');
      map.register('clawdstrike.child', '/workspace/plugins/child');

      // File in child directory should match child plugin (longer prefix)
      expect(map.resolve('/workspace/plugins/child/src/index.ts')).toBe('clawdstrike.child');
      // File in parent but not child should match parent
      expect(map.resolve('/workspace/plugins/other/src/index.ts')).toBe('clawdstrike.parent');
    });

    it('does not match partial directory names', () => {
      const map = new FilePluginMap();
      map.register('clawdstrike.guard', '/workspace/plugins/guard');

      // "guard-extra" starts with "guard" but is a different directory
      expect(map.resolve('/workspace/plugins/guard-extra/file.ts')).toBeUndefined();
    });
  });

  describe('getEntry()', () => {
    it('returns the entry path for a registered plugin', () => {
      const map = new FilePluginMap();
      map.register('clawdstrike.my-guard', '/workspace/plugins/my-guard', 'src/main.ts');

      expect(map.getEntry('clawdstrike.my-guard')).toBe('/workspace/plugins/my-guard/src/main.ts');
    });

    it('returns undefined for unregistered plugin', () => {
      const map = new FilePluginMap();
      expect(map.getEntry('nonexistent')).toBeUndefined();
    });
  });

  describe('getPluginDir()', () => {
    it('returns the directory for a registered plugin', () => {
      const map = new FilePluginMap();
      map.register('clawdstrike.my-guard', '/workspace/plugins/my-guard');

      const dir = map.getPluginDir('clawdstrike.my-guard');
      expect(dir).toBe(`${normalize('/workspace/plugins/my-guard')}${sep}`);
    });

    it('returns undefined for unregistered plugin', () => {
      const map = new FilePluginMap();
      expect(map.getPluginDir('nonexistent')).toBeUndefined();
    });

    it('normalizes Windows-style separators consistently', () => {
      const map = new FilePluginMap();
      map.register('clawdstrike.win-guard', 'C:\\workspace\\plugins\\win-guard');

      expect(
        map.resolve('C:\\workspace\\plugins\\win-guard\\src\\index.ts'),
      ).toBe('clawdstrike.win-guard');
      expect(map.getPluginDir('clawdstrike.win-guard')).toBe(
        `${normalize('C:/workspace/plugins/win-guard')}${sep}`,
      );
    });
  });
});
