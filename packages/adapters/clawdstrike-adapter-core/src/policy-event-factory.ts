import type { EventType, PolicyEvent } from './types.js';

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
        try {
          const parsed = new URL(url.includes('://') ? url : `https://${url}`);
          return {
            type: 'network',
            host: parsed.hostname,
            port: parseInt(parsed.port) || (parsed.protocol === 'https:' ? 443 : 80),
            url,
          };
        } catch {
          return {
            type: 'network',
            host: String(parameters.host ?? url),
            port: Number(parameters.port ?? 443),
            url,
          };
        }
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

