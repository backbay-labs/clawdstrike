import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { setupPluginWatcher } from '../src/watcher';
import { FilePluginMap } from '../src/file-plugin-map';
import type { ClawdstrikePluginOptions } from '../src/types';
import { PLUGIN_UPDATE_EVENT } from '../src/types';

// Mock ViteDevServer
function createMockServer() {
  const eventHandlers = new Map<string, Array<(path: string) => void>>();

  return {
    ws: {
      send: vi.fn(),
    },
    watcher: {
      add: vi.fn(),
      on: vi.fn((event: string, handler: (path: string) => void) => {
        const handlers = eventHandlers.get(event) ?? [];
        handlers.push(handler);
        eventHandlers.set(event, handlers);
      }),
    },
    // Helper to simulate file events
    _emit(event: string, filePath: string) {
      const handlers = eventHandlers.get(event) ?? [];
      for (const handler of handlers) {
        handler(filePath);
      }
    },
  };
}

describe('setupPluginWatcher', () => {
  let mockServer: ReturnType<typeof createMockServer>;
  let fileMap: FilePluginMap;
  let options: ClawdstrikePluginOptions;

  beforeEach(() => {
    mockServer = createMockServer();
    fileMap = new FilePluginMap();
    options = {
      plugins: [
        {
          dir: '/workspace/plugins/guard-a',
          pluginId: 'clawdstrike.guard-a',
          entry: 'src/index.ts',
        },
        {
          dir: '/workspace/plugins/guard-b',
          pluginId: 'clawdstrike.guard-b',
        },
      ],
    };
  });

  it('calls server.watcher.add() for each plugin directory', () => {
    setupPluginWatcher(mockServer as any, fileMap, options);

    expect(mockServer.watcher.add).toHaveBeenCalledTimes(2);
    expect(mockServer.watcher.add).toHaveBeenCalledWith('/workspace/plugins/guard-a');
    expect(mockServer.watcher.add).toHaveBeenCalledWith('/workspace/plugins/guard-b');
  });

  it('registers change and add event listeners on the watcher', () => {
    setupPluginWatcher(mockServer as any, fileMap, options);

    expect(mockServer.watcher.on).toHaveBeenCalledWith('change', expect.any(Function));
    expect(mockServer.watcher.on).toHaveBeenCalledWith('add', expect.any(Function));
  });

  it('sends HMR event on file change within a plugin directory', () => {
    setupPluginWatcher(mockServer as any, fileMap, options);

    mockServer._emit('change', '/workspace/plugins/guard-a/src/helper.ts');

    expect(mockServer.ws.send).toHaveBeenCalledTimes(1);
    expect(mockServer.ws.send).toHaveBeenCalledWith(
      PLUGIN_UPDATE_EVENT,
      expect.objectContaining({
        pluginId: 'clawdstrike.guard-a',
        entryPath: '/workspace/plugins/guard-a/src/index.ts',
        timestamp: expect.any(Number),
      }),
    );
  });

  it('sends HMR event on new file (add event) within a plugin directory', () => {
    setupPluginWatcher(mockServer as any, fileMap, options);

    mockServer._emit('add', '/workspace/plugins/guard-b/src/new-file.ts');

    expect(mockServer.ws.send).toHaveBeenCalledTimes(1);
    expect(mockServer.ws.send).toHaveBeenCalledWith(
      PLUGIN_UPDATE_EVENT,
      expect.objectContaining({
        pluginId: 'clawdstrike.guard-b',
      }),
    );
  });

  it('does NOT send event for files outside any plugin directory', () => {
    setupPluginWatcher(mockServer as any, fileMap, options);

    mockServer._emit('change', '/workspace/other/file.ts');

    expect(mockServer.ws.send).not.toHaveBeenCalled();
  });

  it('sends event with correct plugin ID for the specific plugin that owns the changed file', () => {
    setupPluginWatcher(mockServer as any, fileMap, options);

    // Change a file in guard-a
    mockServer._emit('change', '/workspace/plugins/guard-a/src/utils/shared.ts');

    expect(mockServer.ws.send).toHaveBeenCalledTimes(1);
    const call = mockServer.ws.send.mock.calls[0]!;
    expect(call[1]).toMatchObject({ pluginId: 'clawdstrike.guard-a' });

    // Change a file in guard-b
    mockServer._emit('change', '/workspace/plugins/guard-b/src/index.ts');

    expect(mockServer.ws.send).toHaveBeenCalledTimes(2);
    const call2 = mockServer.ws.send.mock.calls[1]!;
    expect(call2[1]).toMatchObject({ pluginId: 'clawdstrike.guard-b' });
  });

  it('uses default entry path when no entry is specified', () => {
    setupPluginWatcher(mockServer as any, fileMap, options);

    mockServer._emit('change', '/workspace/plugins/guard-b/src/something.ts');

    expect(mockServer.ws.send).toHaveBeenCalledWith(
      PLUGIN_UPDATE_EVENT,
      expect.objectContaining({
        pluginId: 'clawdstrike.guard-b',
        entryPath: '/workspace/plugins/guard-b/src/index.ts', // default
      }),
    );
  });

  describe('error handling in file change handler', () => {
    let consoleErrorSpy: ReturnType<typeof vi.spyOn>;

    beforeEach(() => {
      consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    });

    afterEach(() => {
      consoleErrorSpy.mockRestore();
    });

    it('catches and logs the error when fileMap.resolve throws', () => {
      const throwingFileMap = new FilePluginMap();
      vi.spyOn(throwingFileMap, 'resolve').mockImplementation(() => {
        throw new Error('resolve boom');
      });

      setupPluginWatcher(mockServer as any, throwingFileMap, options);

      mockServer._emit('change', '/workspace/plugins/guard-a/src/helper.ts');

      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining('[clawdstrike]'),
        expect.any(Error),
      );
      expect(mockServer.ws.send).not.toHaveBeenCalled();
    });

    it('subsequent file changes still trigger after an error (watcher not broken)', () => {
      let callCount = 0;
      const flakyFileMap = new FilePluginMap();
      vi.spyOn(flakyFileMap, 'resolve').mockImplementation((filePath: string) => {
        callCount++;
        if (callCount === 1) {
          throw new Error('transient error');
        }
        // Fall through to real resolution for subsequent calls
        if (filePath.startsWith('/workspace/plugins/guard-a/')) {
          return 'clawdstrike.guard-a';
        }
        return undefined;
      });
      vi.spyOn(flakyFileMap, 'getEntry').mockReturnValue('/workspace/plugins/guard-a/src/index.ts');

      setupPluginWatcher(mockServer as any, flakyFileMap, options);

      // First change: throws
      const errorCountBefore = consoleErrorSpy.mock.calls.length;
      mockServer._emit('change', '/workspace/plugins/guard-a/src/foo.ts');
      expect(consoleErrorSpy.mock.calls.length - errorCountBefore).toBe(1);
      expect(mockServer.ws.send).not.toHaveBeenCalled();

      // Second change: should succeed, watcher is not broken
      mockServer._emit('change', '/workspace/plugins/guard-a/src/bar.ts');
      expect(mockServer.ws.send).toHaveBeenCalledTimes(1);
      expect(mockServer.ws.send).toHaveBeenCalledWith(
        PLUGIN_UPDATE_EVENT,
        expect.objectContaining({
          pluginId: 'clawdstrike.guard-a',
          entryPath: '/workspace/plugins/guard-a/src/index.ts',
        }),
      );
    });
  });
});
