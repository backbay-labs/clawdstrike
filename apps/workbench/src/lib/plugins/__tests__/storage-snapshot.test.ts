import { describe, it, expect, beforeEach } from 'vitest';
import {
  trackStorageWrite,
  getSnapshot,
  restoreToApi,
  clearSnapshot,
} from '../dev/storage-snapshot';

describe('storage-snapshot', () => {
  // Clear all snapshots between tests by clearing each known plugin
  beforeEach(() => {
    clearSnapshot('plugin-a');
    clearSnapshot('plugin-b');
    clearSnapshot('plugin-c');
  });

  describe('trackStorageWrite()', () => {
    it('stores entries in devStorageCache', () => {
      trackStorageWrite('plugin-a', 'theme', 'dark');
      trackStorageWrite('plugin-a', 'count', 42);

      const snapshot = getSnapshot('plugin-a');
      expect(snapshot.get('theme')).toBe('dark');
      expect(snapshot.get('count')).toBe(42);
    });

    it('overwrites existing keys', () => {
      trackStorageWrite('plugin-a', 'value', 'first');
      trackStorageWrite('plugin-a', 'value', 'second');

      const snapshot = getSnapshot('plugin-a');
      expect(snapshot.get('value')).toBe('second');
    });
  });

  describe('getSnapshot()', () => {
    it('returns a copy of stored entries', () => {
      trackStorageWrite('plugin-a', 'key1', 'val1');

      const snapshot1 = getSnapshot('plugin-a');
      const snapshot2 = getSnapshot('plugin-a');

      // Should be separate Map instances
      expect(snapshot1).not.toBe(snapshot2);
      expect(snapshot1.get('key1')).toBe('val1');
      expect(snapshot2.get('key1')).toBe('val1');
    });

    it('returns empty map for unknown plugin', () => {
      const snapshot = getSnapshot('nonexistent');
      expect(snapshot.size).toBe(0);
    });

    it('mutations to returned map do not affect the cache', () => {
      trackStorageWrite('plugin-a', 'key1', 'val1');

      const snapshot = getSnapshot('plugin-a');
      snapshot.set('key2', 'injected');

      const fresh = getSnapshot('plugin-a');
      expect(fresh.has('key2')).toBe(false);
    });
  });

  describe('restoreToApi()', () => {
    it('calls set() on provided API for each stored entry', () => {
      trackStorageWrite('plugin-a', 'theme', 'dark');
      trackStorageWrite('plugin-a', 'count', 42);

      const mockApi = {
        set: vi.fn(),
      };

      restoreToApi('plugin-a', mockApi);

      expect(mockApi.set).toHaveBeenCalledTimes(2);
      expect(mockApi.set).toHaveBeenCalledWith('theme', 'dark');
      expect(mockApi.set).toHaveBeenCalledWith('count', 42);
    });

    it('does nothing for unknown plugin', () => {
      const mockApi = { set: vi.fn() };
      restoreToApi('nonexistent', mockApi);
      expect(mockApi.set).not.toHaveBeenCalled();
    });
  });

  describe('clearSnapshot()', () => {
    it('removes entries for a pluginId', () => {
      trackStorageWrite('plugin-a', 'key1', 'val1');
      clearSnapshot('plugin-a');

      const snapshot = getSnapshot('plugin-a');
      expect(snapshot.size).toBe(0);
    });

    it('does not throw for unknown plugin', () => {
      expect(() => clearSnapshot('nonexistent')).not.toThrow();
    });
  });

  describe('isolation', () => {
    it('snapshots are isolated per pluginId', () => {
      trackStorageWrite('plugin-a', 'key', 'value-a');
      trackStorageWrite('plugin-b', 'key', 'value-b');

      expect(getSnapshot('plugin-a').get('key')).toBe('value-a');
      expect(getSnapshot('plugin-b').get('key')).toBe('value-b');
    });

    it('clearing one plugin does not affect another', () => {
      trackStorageWrite('plugin-a', 'key', 'value-a');
      trackStorageWrite('plugin-b', 'key', 'value-b');

      clearSnapshot('plugin-a');

      expect(getSnapshot('plugin-a').size).toBe(0);
      expect(getSnapshot('plugin-b').get('key')).toBe('value-b');
    });
  });
});
