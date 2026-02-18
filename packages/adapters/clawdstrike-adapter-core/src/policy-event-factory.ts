import type { CuaEventData, EventType, PolicyEvent } from './types.js';
import { parseNetworkTarget } from './network-target.js';

function coerceValidPort(value: unknown): number | null {
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) return null;
    const port = Math.trunc(value);
    if (port > 0 && port <= 65535) return port;
    return null;
  }

  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!/^[0-9]+$/.test(trimmed)) return null;
    const port = Number.parseInt(trimmed, 10);
    if (Number.isFinite(port) && port > 0 && port <= 65535) return port;
  }

  return null;
}

export class PolicyEventFactory {
  private readonly toolTypeMapping: Map<RegExp, EventType> = new Map([
    [/read|cat|get_file|load/i, 'file_read'],
    [/write|save|create_file|store/i, 'file_write'],
    [/exec|shell|bash|command|run/i, 'command_exec'],
    [/fetch|http|request|curl|wget|browse/i, 'network_egress'],
    [/patch|diff|apply/i, 'patch_apply'],
  ]);

  create(
    toolName: string,
    parameters: Record<string, unknown>,
    sessionId?: string,
  ): PolicyEvent {
    const eventType = this.inferEventType(toolName, parameters);
    const eventId = this.generateEventId();

    return {
      eventId,
      eventType,
      timestamp: new Date().toISOString(),
      sessionId,
      data: this.createEventData(eventType, toolName, parameters),
      metadata: {
        source: 'adapter-core',
        toolName,
      },
    };
  }

  inferEventType(toolName: string, parameters: Record<string, unknown>): EventType {
    for (const [pattern, eventType] of this.toolTypeMapping) {
      if (pattern.test(toolName)) {
        return eventType;
      }
    }

    const params = parameters as Record<string, unknown> & {
      path?: unknown;
      file?: unknown;
      filepath?: unknown;
      filename?: unknown;
      content?: unknown;
      data?: unknown;
      url?: unknown;
      endpoint?: unknown;
      host?: unknown;
      command?: unknown;
      cmd?: unknown;
    };

    if (params.path ?? params.file ?? params.filepath ?? params.filename) {
      if (params.content ?? params.data) {
        return 'file_write';
      }
      return 'file_read';
    }

    if (params.url ?? params.endpoint ?? params.host) {
      return 'network_egress';
    }

    if (params.command ?? params.cmd) {
      return 'command_exec';
    }

    return 'tool_call';
  }

  registerMapping(pattern: RegExp, eventType: EventType): void {
    this.toolTypeMapping.set(pattern, eventType);
  }

  createCuaConnectEvent(
    sessionId: string,
    data?: Partial<Omit<CuaEventData, 'type' | 'cuaAction'>>,
  ): PolicyEvent {
    return this.buildCuaEvent('remote.session.connect', 'session.connect', sessionId, data);
  }

  createCuaDisconnectEvent(
    sessionId: string,
    data?: Partial<Omit<CuaEventData, 'type' | 'cuaAction'>>,
  ): PolicyEvent {
    return this.buildCuaEvent('remote.session.disconnect', 'session.disconnect', sessionId, data);
  }

  createCuaReconnectEvent(
    sessionId: string,
    data?: Partial<Omit<CuaEventData, 'type' | 'cuaAction'>>,
  ): PolicyEvent {
    return this.buildCuaEvent('remote.session.reconnect', 'session.reconnect', sessionId, data);
  }

  createCuaInputInjectEvent(
    sessionId: string,
    data?: Partial<Omit<CuaEventData, 'type' | 'cuaAction'>>,
  ): PolicyEvent {
    return this.buildCuaEvent('input.inject', 'input.inject', sessionId, data);
  }

  createCuaClipboardEvent(
    sessionId: string,
    direction: CuaEventData['direction'],
    data?: Partial<Omit<CuaEventData, 'type' | 'cuaAction' | 'direction'>>,
  ): PolicyEvent {
    return this.buildCuaEvent('remote.clipboard', 'clipboard', sessionId, { ...data, direction });
  }

  createCuaFileTransferEvent(
    sessionId: string,
    direction: CuaEventData['direction'],
    data?: Partial<Omit<CuaEventData, 'type' | 'cuaAction' | 'direction'>>,
  ): PolicyEvent {
    return this.buildCuaEvent('remote.file_transfer', 'file_transfer', sessionId, { ...data, direction });
  }

  createCuaAudioEvent(
    sessionId: string,
    data?: Partial<Omit<CuaEventData, 'type' | 'cuaAction'>>,
  ): PolicyEvent {
    return this.buildCuaEvent('remote.audio', 'audio', sessionId, data);
  }

  createCuaDriveMappingEvent(
    sessionId: string,
    data?: Partial<Omit<CuaEventData, 'type' | 'cuaAction'>>,
  ): PolicyEvent {
    return this.buildCuaEvent('remote.drive_mapping', 'drive_mapping', sessionId, data);
  }

  createCuaPrintingEvent(
    sessionId: string,
    data?: Partial<Omit<CuaEventData, 'type' | 'cuaAction'>>,
  ): PolicyEvent {
    return this.buildCuaEvent('remote.printing', 'printing', sessionId, data);
  }

  createCuaSessionShareEvent(
    sessionId: string,
    data?: Partial<Omit<CuaEventData, 'type' | 'cuaAction'>>,
  ): PolicyEvent {
    return this.buildCuaEvent('remote.session_share', 'session_share', sessionId, data);
  }

  private buildCuaEvent(
    eventType: EventType,
    cuaAction: string,
    sessionId: string,
    data?: Partial<Omit<CuaEventData, 'type' | 'cuaAction'>>,
  ): PolicyEvent {
    const raw = data ?? {};
    const direction = raw.direction as CuaEventData['direction'];
    const continuityPrevSessionHash = raw.continuityPrevSessionHash as string | undefined;
    const postconditionProbeHash = raw.postconditionProbeHash as string | undefined;
    const { direction: _d, continuityPrevSessionHash: _c, postconditionProbeHash: _p, ...extra } = raw;
    const eventData: CuaEventData = {
      type: 'cua',
      cuaAction,
      ...(direction !== undefined && { direction }),
      ...(continuityPrevSessionHash !== undefined && { continuityPrevSessionHash }),
      ...(postconditionProbeHash !== undefined && { postconditionProbeHash }),
      ...extra,
    };

    return {
      eventId: this.generateEventId(),
      eventType,
      timestamp: new Date().toISOString(),
      sessionId,
      data: eventData,
      metadata: {
        source: 'adapter-core',
        cuaAction,
      },
    };
  }

  private createEventData(
    eventType: EventType,
    toolName: string,
    parameters: Record<string, unknown>,
  ): PolicyEvent['data'] {
    switch (eventType) {
      case 'file_read':
      case 'file_write':
        return {
          type: 'file',
          path: String(
            parameters.path ??
              parameters.file ??
              parameters.filepath ??
              parameters.filename ??
              '',
          ),
          operation: eventType === 'file_read' ? 'read' : 'write',
        };

      case 'command_exec': {
        const cmdStr = String(parameters.command ?? parameters.cmd ?? '');
        const parts = cmdStr.split(/\s+/);
        return {
          type: 'command',
          command: parts[0] ?? '',
          args: parts.slice(1),
          workingDir: parameters.cwd as string | undefined,
        };
      }

      case 'network_egress': {
        const url = String(
          parameters.url ?? parameters.endpoint ?? parameters.href ?? '',
        );
        const explicitHost = parameters.host;
        const explicitPort = parameters.port;

        const parsedTarget = parseNetworkTarget(url, { emptyPort: 'default' });
        const host = typeof explicitHost === 'string' && explicitHost.length > 0
          ? explicitHost
          : parsedTarget.host;

        const port = coerceValidPort(explicitPort) ?? parsedTarget.port;

        return {
          type: 'network',
          host,
          port,
          url,
        };
      }

      case 'patch_apply':
        return {
          type: 'patch',
          filePath: String(parameters.path ?? parameters.file ?? ''),
          patchContent: String(
            parameters.patch ?? parameters.diff ?? parameters.content ?? '',
          ),
        };

      default:
        return {
          type: 'tool',
          toolName,
          parameters,
        };
    }
  }

  private generateEventId(): string {
    return `evt-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
  }
}
