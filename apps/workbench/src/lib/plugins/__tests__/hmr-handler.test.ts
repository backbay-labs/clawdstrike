import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { PluginManifest, RegisteredPlugin } from '../types';

// Mock the plugin-loader and plugin-registry modules
vi.mock('../plugin-loader', () => ({
  pluginLoader: {
    deactivatePlugin: vi.fn().mockResolvedValue(undefined),
    loadPlugin: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock('../plugin-registry', () => ({
  pluginRegistry: {
    get: vi.fn(),
    unregister: vi.fn(),
    register: vi.fn(),
  },
}));

// Must import after mocks are set up
import { handlePluginUpdate, onDevLifecycleEvent } from '../dev/hmr-handler';
import { pluginLoader } from '../plugin-loader';
import { pluginRegistry } from '../plugin-registry';
import type { PluginUpdateEvent, DevLifecycleEvent } from '../dev/types';

const mockManifest: PluginManifest = {
  id: 'clawdstrike.test-guard',
  name: 'test-guard',
  displayName: 'Test Guard',
  description: 'A test guard plugin',
  version: '1.0.0',
  publisher: 'test',
  categories: ['guards'],
  trust: 'internal',
  activationEvents: ['onStartup'],
  main: './dist/index.js',
};

const mockRegistered: RegisteredPlugin = {
  manifest: mockManifest,
  state: 'activated',
  installedAt: Date.now(),
};

describe('hmr-handler', () => {
  const updateEvent: PluginUpdateEvent = {
    pluginId: 'clawdstrike.test-guard',
    entryPath: '/workspace/plugins/test-guard/src/index.ts',
    timestamp: 1700000000000,
  };

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(pluginRegistry.get).mockReturnValue(mockRegistered);
  });

  describe('handlePluginUpdate()', () => {
    it('calls deactivatePlugin, unregister, register, loadPlugin in correct order', async () => {
      const callOrder: string[] = [];

      vi.mocked(pluginLoader.deactivatePlugin).mockImplementation(async () => {
        callOrder.push('deactivate');
      });
      vi.mocked(pluginRegistry.unregister).mockImplementation(() => {
        callOrder.push('unregister');
      });
      vi.mocked(pluginRegistry.register).mockImplementation(() => {
        callOrder.push('register');
      });
      vi.mocked(pluginLoader.loadPlugin).mockImplementation(async () => {
        callOrder.push('loadPlugin');
      });

      await handlePluginUpdate(updateEvent);

      expect(callOrder).toEqual([
        'deactivate',
        'unregister',
        'register',
        'loadPlugin',
      ]);
    });

    it('calls deactivatePlugin with the correct pluginId', async () => {
      await handlePluginUpdate(updateEvent);

      expect(pluginLoader.deactivatePlugin).toHaveBeenCalledWith(
        'clawdstrike.test-guard',
      );
    });

    it('unregisters the plugin from the registry', async () => {
      await handlePluginUpdate(updateEvent);

      expect(pluginRegistry.unregister).toHaveBeenCalledWith(
        'clawdstrike.test-guard',
      );
    });

    it('re-registers manifest with cache-bust query param on main', async () => {
      await handlePluginUpdate(updateEvent);

      expect(pluginRegistry.register).toHaveBeenCalledWith(
        expect.objectContaining({
          main: '/workspace/plugins/test-guard/src/index.ts?t=1700000000000',
        }),
      );
    });

    it('re-loads the plugin after re-registration', async () => {
      await handlePluginUpdate(updateEvent);

      expect(pluginLoader.loadPlugin).toHaveBeenCalledWith(
        'clawdstrike.test-guard',
      );
    });

    it('does not reload other plugins', async () => {
      await handlePluginUpdate(updateEvent);

      // loadPlugin should only be called once with the specific plugin
      expect(pluginLoader.loadPlugin).toHaveBeenCalledTimes(1);
      expect(pluginLoader.deactivatePlugin).toHaveBeenCalledTimes(1);
    });

    it('throws and emits hmr:error if plugin not found in registry', async () => {
      vi.mocked(pluginRegistry.get).mockReturnValue(undefined);

      const events: DevLifecycleEvent[] = [];
      const dispose = onDevLifecycleEvent((e) => events.push(e));

      await handlePluginUpdate(updateEvent);

      const errorEvent = events.find((e) => e.type === 'hmr:error');
      expect(errorEvent).toBeDefined();
      expect(errorEvent!.message).toContain('not found in registry');

      dispose();
    });
  });

  describe('lifecycle events', () => {
    it('emits hmr:start, deactivated, registered, hmr:complete events', async () => {
      const events: DevLifecycleEvent[] = [];
      const dispose = onDevLifecycleEvent((e) => events.push(e));

      await handlePluginUpdate(updateEvent);

      const types = events.map((e) => e.type);
      expect(types).toContain('hmr:start');
      expect(types).toContain('deactivated');
      expect(types).toContain('registered');
      expect(types).toContain('hmr:complete');

      dispose();
    });

    it('emits hmr:complete with durationMs', async () => {
      const events: DevLifecycleEvent[] = [];
      const dispose = onDevLifecycleEvent((e) => events.push(e));

      await handlePluginUpdate(updateEvent);

      const complete = events.find((e) => e.type === 'hmr:complete');
      expect(complete).toBeDefined();
      expect(complete!.durationMs).toBeGreaterThanOrEqual(0);

      dispose();
    });

    it('emits hmr:error event on error', async () => {
      vi.mocked(pluginLoader.deactivatePlugin).mockRejectedValue(
        new Error('Deactivation failed'),
      );

      const events: DevLifecycleEvent[] = [];
      const dispose = onDevLifecycleEvent((e) => events.push(e));

      await handlePluginUpdate(updateEvent);

      const errorEvent = events.find((e) => e.type === 'hmr:error');
      expect(errorEvent).toBeDefined();
      expect(errorEvent!.message).toContain('Deactivation failed');

      dispose();
    });

    it('all events contain the correct pluginId', async () => {
      const events: DevLifecycleEvent[] = [];
      const dispose = onDevLifecycleEvent((e) => events.push(e));

      await handlePluginUpdate(updateEvent);

      for (const event of events) {
        expect(event.pluginId).toBe('clawdstrike.test-guard');
      }

      dispose();
    });
  });

  describe('onDevLifecycleEvent()', () => {
    it('supports multiple listeners', async () => {
      const events1: DevLifecycleEvent[] = [];
      const events2: DevLifecycleEvent[] = [];

      const dispose1 = onDevLifecycleEvent((e) => events1.push(e));
      const dispose2 = onDevLifecycleEvent((e) => events2.push(e));

      await handlePluginUpdate(updateEvent);

      expect(events1.length).toBeGreaterThan(0);
      expect(events2.length).toBeGreaterThan(0);
      expect(events1.length).toBe(events2.length);

      dispose1();
      dispose2();
    });

    it('dispose function removes the listener', async () => {
      const events: DevLifecycleEvent[] = [];
      const dispose = onDevLifecycleEvent((e) => events.push(e));

      dispose();

      await handlePluginUpdate(updateEvent);

      expect(events.length).toBe(0);
    });

    it('listener errors do not prevent other listeners from firing', async () => {
      const events: DevLifecycleEvent[] = [];

      const dispose1 = onDevLifecycleEvent(() => {
        throw new Error('listener error');
      });
      const dispose2 = onDevLifecycleEvent((e) => events.push(e));

      await handlePluginUpdate(updateEvent);

      expect(events.length).toBeGreaterThan(0);

      dispose1();
      dispose2();
    });
  });
});
