import {
  parseNetworkTarget,
  PolicyEventFactory,
  type CuaEventData,
  type PolicyEvent,
  type ToolCallTranslationInput,
  type ToolCallTranslator,
} from '@clawdstrike/adapter-core';

const factory = new PolicyEventFactory();

const CLAUDE_CUA_TOOLS = new Set([
  'computer',
  'computer_use',
  'computer.use',
  'computer-use',
]);

const INPUT_ACTIONS = new Set([
  'mouse_click',
  'click',
  'key_type',
  'type',
  'key_press',
  'keypress',
  'key_chord',
  'scroll',
  'drag',
  'move_mouse',
]);

function isClaudeCuaTool(toolName: string): boolean {
  const lower = toolName.toLowerCase();
  if (CLAUDE_CUA_TOOLS.has(lower)) return true;
  return lower.startsWith('computer_') || lower.startsWith('computer.');
}

function ensureSessionId(sessionId: string | undefined): string {
  if (typeof sessionId !== 'string' || sessionId.trim().length === 0) {
    throw new Error('Claude CUA translator requires a sessionId');
  }
  return sessionId;
}

function normalizeAction(action: string): string {
  const lower = action.toLowerCase();
  switch (lower) {
    case 'mouse_click':
      return 'click';
    case 'key_type':
      return 'type';
    case 'key_press':
    case 'keypress':
      return 'key';
    default:
      return lower;
  }
}

function extractAction(input: ToolCallTranslationInput): string | null {
  const explicit = input.parameters.action;
  if (typeof explicit === 'string' && explicit.trim().length > 0) {
    return normalizeAction(explicit.trim());
  }

  const lowerTool = input.toolName.toLowerCase();
  if (lowerTool.startsWith('computer_')) {
    return normalizeAction(lowerTool.slice('computer_'.length));
  }
  if (lowerTool.startsWith('computer.')) {
    return normalizeAction(lowerTool.slice('computer.'.length));
  }

  return null;
}

function withAction(event: PolicyEvent, cuaAction: string, extra?: Partial<CuaEventData>): PolicyEvent {
  if (event.data.type !== 'cua') {
    throw new Error('Claude CUA translator produced non-CUA event data');
  }
  event.data.cuaAction = cuaAction;
  if (extra) {
    Object.assign(event.data, extra);
  }
  return event;
}

function deriveInputType(action: string, parameters: Record<string, unknown>): string | undefined {
  if (typeof parameters.input_type === 'string' && parameters.input_type.trim().length > 0) {
    return parameters.input_type.trim().toLowerCase();
  }

  if (action === 'type' || action === 'key' || action === 'key_chord') {
    return 'keyboard';
  }
  if (action === 'click' || action === 'scroll' || action === 'drag' || action === 'move_mouse') {
    return 'mouse';
  }
  return undefined;
}

function maybeTransferSize(parameters: Record<string, unknown>): number | undefined {
  const value = parameters.transfer_size ?? parameters.transferSize ?? parameters.size_bytes ?? parameters.sizeBytes;
  if (typeof value === 'number' && Number.isFinite(value) && value >= 0) {
    return Math.trunc(value);
  }
  if (typeof value === 'string') {
    const parsed = Number.parseInt(value, 10);
    if (Number.isFinite(parsed) && parsed >= 0) {
      return parsed;
    }
  }
  return undefined;
}

function maybePort(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) {
    const port = Math.trunc(value);
    if (port > 0 && port <= 65535) return port;
  }
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (/^[0-9]+$/.test(trimmed)) {
      const parsed = Number.parseInt(trimmed, 10);
      if (Number.isFinite(parsed) && parsed > 0 && parsed <= 65535) {
        return parsed;
      }
    }
  }
  return undefined;
}

function firstNonEmptyString(values: unknown[]): string | undefined {
  for (const value of values) {
    if (typeof value !== 'string') continue;
    const trimmed = value.trim();
    if (trimmed.length > 0) return trimmed;
  }
  return undefined;
}

function deriveConnectMetadata(parameters: Record<string, unknown>): Partial<CuaEventData> {
  const url = firstNonEmptyString([
    parameters.url,
    parameters.endpoint,
    parameters.href,
    parameters.target_url,
    parameters.targetUrl,
  ]);
  const parsed = parseNetworkTarget(url ?? '', { emptyPort: 'default' });
  const host = firstNonEmptyString([
    parameters.host,
    parameters.hostname,
    parameters.remote_host,
    parameters.remoteHost,
    parameters.destination_host,
    parameters.destinationHost,
    parsed.host,
  ])?.toLowerCase();
  const explicitPort = maybePort(
    parameters.port
      ?? parameters.remote_port
      ?? parameters.remotePort
      ?? parameters.destination_port
      ?? parameters.destinationPort,
  );
  const protocol = firstNonEmptyString([parameters.protocol, parameters.scheme])?.toLowerCase();

  const extra: Partial<CuaEventData> = { direction: 'outbound' };
  if (host) (extra as Record<string, unknown>).host = host;
  if (explicitPort !== undefined) {
    (extra as Record<string, unknown>).port = explicitPort;
  } else if (parsed.host) {
    (extra as Record<string, unknown>).port = parsed.port;
  }
  if (url) (extra as Record<string, unknown>).url = url;
  if (protocol) (extra as Record<string, unknown>).protocol = protocol;
  return extra;
}

function failUnknownAction(action: string): never {
  throw new Error(`Claude CUA translator does not support action '${action}'`);
}

export const claudeCuaTranslator: ToolCallTranslator = (input) => {
  if (!isClaudeCuaTool(input.toolName)) {
    return null;
  }

  const action = extractAction(input);
  if (!action) {
    throw new Error(`Claude CUA translator could not resolve action for tool '${input.toolName}'`);
  }

  if (!INPUT_ACTIONS.has(action)
    && action !== 'navigate'
    && action !== 'connect'
    && action !== 'disconnect'
    && action !== 'reconnect'
    && action !== 'screenshot'
    && action !== 'clipboard_read'
    && action !== 'clipboard_write'
    && action !== 'file_transfer'
    && action !== 'file_upload'
    && action !== 'upload'
    && action !== 'file_download'
    && action !== 'download'
    && action !== 'session_share'
    && action !== 'share_session'
    && action !== 'audio'
    && action !== 'audio_stream'
    && action !== 'drive_mapping'
    && action !== 'map_drive'
    && action !== 'printing'
    && action !== 'print') {
    return failUnknownAction(action);
  }

  const sessionId = ensureSessionId(input.sessionId);
  const params = input.parameters;

  if (INPUT_ACTIONS.has(action)) {
    const inputType = deriveInputType(action, params);
    const extra: Partial<CuaEventData> = {
      ...(inputType ? { input_type: inputType } : {}),
    };
    return withAction(factory.createCuaInputInjectEvent(sessionId, extra), action);
  }

  if (action === 'navigate' || action === 'connect') {
    const connectMeta = deriveConnectMetadata(params);
    return withAction(factory.createCuaConnectEvent(sessionId, connectMeta), 'navigate', connectMeta);
  }

  switch (action) {
    case 'disconnect':
      return withAction(factory.createCuaDisconnectEvent(sessionId), 'disconnect');
    case 'reconnect':
      return withAction(factory.createCuaReconnectEvent(sessionId), 'reconnect');
    case 'screenshot':
      return withAction(factory.createCuaClipboardEvent(sessionId, 'read'), 'screenshot', { direction: 'read' });
    case 'clipboard_read':
      return withAction(factory.createCuaClipboardEvent(sessionId, 'read'), 'clipboard_read', { direction: 'read' });
    case 'clipboard_write':
      return withAction(factory.createCuaClipboardEvent(sessionId, 'write'), 'clipboard_write', { direction: 'write' });
    case 'file_transfer':
    case 'file_upload':
    case 'upload': {
      const transferSize = maybeTransferSize(params);
      return withAction(factory.createCuaFileTransferEvent(sessionId, 'upload', {
        ...(transferSize !== undefined ? { transfer_size: transferSize } : {}),
      }), 'file_transfer', {
        direction: 'upload',
        ...(transferSize !== undefined ? { transfer_size: transferSize } : {}),
      });
    }
    case 'file_download':
    case 'download': {
      const transferSize = maybeTransferSize(params);
      return withAction(factory.createCuaFileTransferEvent(sessionId, 'download', {
        ...(transferSize !== undefined ? { transfer_size: transferSize } : {}),
      }), 'file_transfer', {
        direction: 'download',
        ...(transferSize !== undefined ? { transfer_size: transferSize } : {}),
      });
    }
    case 'session_share':
    case 'share_session':
      return withAction(factory.createCuaSessionShareEvent(sessionId), 'session_share');
    case 'audio':
    case 'audio_stream':
      return withAction(factory.createCuaAudioEvent(sessionId), 'audio');
    case 'drive_mapping':
    case 'map_drive':
      return withAction(factory.createCuaDriveMappingEvent(sessionId), 'drive_mapping');
    case 'printing':
    case 'print':
      return withAction(factory.createCuaPrintingEvent(sessionId), 'printing');
    default:
      return failUnknownAction(action);
  }
};
