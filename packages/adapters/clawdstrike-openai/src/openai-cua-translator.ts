import {
  parseNetworkTarget,
  PolicyEventFactory,
  type CuaEventData,
  type PolicyEvent,
  type ToolCallTranslationInput,
  type ToolCallTranslator,
} from '@clawdstrike/adapter-core';

const factory = new PolicyEventFactory();

const OPENAI_CUA_TOOLS = new Set([
  'computer_use',
  'computer.use',
  'computer-use',
  'computer',
]);

const INPUT_ACTIONS = new Set(['click', 'type', 'key', 'key_chord', 'scroll', 'drag', 'move_mouse']);
const CONNECT_ACTIONS = new Set(['navigate', 'open_url', 'go_to', 'connect']);

function isOpenAiCuaTool(toolName: string): boolean {
  const lower = toolName.toLowerCase();
  if (OPENAI_CUA_TOOLS.has(lower)) return true;
  return lower.startsWith('computer_use_') || lower.startsWith('computer_use.');
}

function extractAction(input: ToolCallTranslationInput): string | null {
  const { toolName, parameters } = input;
  const explicit = parameters.action;
  if (typeof explicit === 'string' && explicit.trim().length > 0) {
    return explicit.trim().toLowerCase();
  }

  const lowerTool = toolName.toLowerCase();
  if (lowerTool.startsWith('computer_use_')) {
    return lowerTool.slice('computer_use_'.length);
  }
  if (lowerTool.startsWith('computer_use.')) {
    return lowerTool.slice('computer_use.'.length);
  }

  return null;
}

function ensureSessionId(sessionId: string | undefined): string {
  if (typeof sessionId !== 'string' || sessionId.trim().length === 0) {
    throw new Error('OpenAI CUA translator requires a sessionId');
  }
  return sessionId;
}

function withAction(event: PolicyEvent, cuaAction: string, extra?: Partial<CuaEventData>): PolicyEvent {
  if (event.data.type !== 'cua') {
    throw new Error('OpenAI CUA translator produced non-CUA event data');
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
  throw new Error(`OpenAI CUA translator does not support action '${action}'`);
}

export const openAICuaTranslator: ToolCallTranslator = (input) => {
  if (!isOpenAiCuaTool(input.toolName)) {
    return null;
  }

  const action = extractAction(input);
  if (!action) {
    throw new Error(`OpenAI CUA translator could not resolve action for tool '${input.toolName}'`);
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

  if (CONNECT_ACTIONS.has(action)) {
    const connectMeta = deriveConnectMetadata(params);
    return withAction(factory.createCuaConnectEvent(sessionId, connectMeta), action, connectMeta);
  }

  switch (action) {
    case 'disconnect':
      return withAction(factory.createCuaDisconnectEvent(sessionId), action);
    case 'reconnect':
      return withAction(factory.createCuaReconnectEvent(sessionId), action);
    case 'screenshot':
      return withAction(factory.createCuaClipboardEvent(sessionId, 'read'), action, { direction: 'read' });
    case 'clipboard_read':
    case 'read_clipboard':
      return withAction(factory.createCuaClipboardEvent(sessionId, 'read'), 'clipboard_read', { direction: 'read' });
    case 'clipboard_write':
    case 'write_clipboard':
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
