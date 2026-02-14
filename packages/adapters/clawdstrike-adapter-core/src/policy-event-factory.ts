import type { EventType, PolicyEvent } from './types.js';

function parseNetworkTarget(target: string): { host: string; port: number } {
  const trimmed = target.trim();
  if (!trimmed) return { host: '', port: 443 };

  const lower = trimmed.toLowerCase();
  const defaultPort = lower.startsWith('http://') ? 80 : 443;

  const schemeSep = trimmed.indexOf('://');
  const withoutScheme = schemeSep === -1 ? trimmed : trimmed.slice(schemeSep + 3);
  const end = withoutScheme.search(/[/?#]/);
  const hostPortRaw = end === -1 ? withoutScheme : withoutScheme.slice(0, end);

  // Drop userinfo if present.
  if (schemeSep === -1 && hostPortRaw.includes('@')) {
    return { host: '', port: defaultPort };
  }

  const atIndex = hostPortRaw.lastIndexOf('@');
  const hostPort = atIndex === -1 ? hostPortRaw : hostPortRaw.slice(atIndex + 1);

  // IPv6: [::1]:443
  if (hostPort.startsWith('[')) {
    const close = hostPort.indexOf(']');
    if (close !== -1) {
      const host = hostPort.slice(1, close);
      const rest = hostPort.slice(close + 1);
      if (rest.startsWith(':')) {
        const parsedPort = Number.parseInt(rest.slice(1), 10);
        if (Number.isFinite(parsedPort) && parsedPort > 0 && parsedPort <= 65535) {
          return { host, port: parsedPort };
        }
      }
      return { host, port: defaultPort };
    }
  }

  const lastColon = hostPort.lastIndexOf(':');
  const hasSingleColon = lastColon > 0 && hostPort.indexOf(':') === lastColon;
  if (hasSingleColon) {
    const host = hostPort.slice(0, lastColon);
    const portText = hostPort.slice(lastColon + 1);
    if (/^[0-9]+$/.test(portText)) {
      const parsedPort = Number.parseInt(portText, 10);
      if (Number.isFinite(parsedPort) && parsedPort > 0 && parsedPort <= 65535) {
        return { host, port: parsedPort };
      }

      // Drop invalid numeric port suffix before returning host.
      return { host, port: defaultPort };
    }

    // Single-colon but non-numeric port suffix (e.g. `mailto:user@example.com`): fail closed.
    return { host: '', port: defaultPort };
  }

  return { host: hostPort, port: defaultPort };
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

        const parsedTarget = parseNetworkTarget(url);
        const host = typeof explicitHost === 'string' && explicitHost.length > 0
          ? explicitHost
          : parsedTarget.host;

        let port = parsedTarget.port;
        if (typeof explicitPort === 'number' && Number.isFinite(explicitPort)) {
          port = explicitPort;
        } else if (typeof explicitPort === 'string') {
          const parsedPort = Number.parseInt(explicitPort, 10);
          if (Number.isFinite(parsedPort)) {
            port = parsedPort;
          }
        }

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
