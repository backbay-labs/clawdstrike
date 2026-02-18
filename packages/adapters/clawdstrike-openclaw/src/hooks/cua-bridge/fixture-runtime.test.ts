import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, it, expect, beforeAll } from 'vitest';
import { PolicyEventFactory } from '@clawdstrike/adapter-core';

import handler, {
  initialize,
  isCuaToolCall,
  extractActionToken,
  classifyCuaAction,
  buildCuaEvent,
  CUA_ERROR_CODES,
  type CuaActionKind,
} from './handler.js';
import type { ToolCallEvent } from '../../types.js';

type BridgeCaseDoc = {
  cases: Array<{
    id: string;
    query: Record<string, any>;
    expected: Record<string, any>;
  }>;
};

const THIS_DIR = fileURLToPath(new URL('.', import.meta.url));
const CASES_PATH = resolve(THIS_DIR, '../../../../../../fixtures/policy-events/openclaw-bridge/v1/cases.json');
const CASES = JSON.parse(readFileSync(CASES_PATH, 'utf8')) as BridgeCaseDoc;

function makeToolCallEvent(
  toolName: string,
  params: Record<string, unknown>,
  sessionId: string,
): ToolCallEvent {
  return {
    type: 'tool_call',
    timestamp: new Date().toISOString(),
    context: {
      sessionId,
      toolCall: {
        toolName,
        params,
      },
    },
    preventDefault: false,
    messages: [],
  };
}

function expectedErrorCodeForCase(caseId: string): string {
  if (caseId.includes('unknown_cua_action')) return CUA_ERROR_CODES.UNKNOWN_ACTION;
  if (caseId.includes('missing_cua_metadata')) return CUA_ERROR_CODES.MISSING_METADATA;
  if (caseId.includes('missing_session')) return CUA_ERROR_CODES.SESSION_MISSING;
  return '';
}

function directFactoryEventForKind(
  factory: PolicyEventFactory,
  kind: CuaActionKind,
  sessionId: string,
  params: Record<string, unknown>,
) {
  switch (kind) {
    case 'connect':
      return factory.createCuaConnectEvent(sessionId);
    case 'disconnect':
      return factory.createCuaDisconnectEvent(sessionId);
    case 'reconnect':
      return factory.createCuaReconnectEvent(sessionId, {
        continuityPrevSessionHash: params.continuityPrevSessionHash as string | undefined,
      });
    case 'input_inject':
      return factory.createCuaInputInjectEvent(sessionId, {
        input_type: (params.input_type ?? params.inputType) as string | undefined,
      });
    case 'clipboard_read':
      return factory.createCuaClipboardEvent(sessionId, 'read');
    case 'clipboard_write':
      return factory.createCuaClipboardEvent(sessionId, 'write');
    case 'file_upload':
      return factory.createCuaFileTransferEvent(sessionId, 'upload');
    case 'file_download':
      return factory.createCuaFileTransferEvent(sessionId, 'download');
    case 'session_share':
      return factory.createCuaSessionShareEvent(sessionId);
    case 'audio':
      return factory.createCuaAudioEvent(sessionId);
    case 'drive_mapping':
      return factory.createCuaDriveMappingEvent(sessionId);
    case 'printing':
      return factory.createCuaPrintingEvent(sessionId);
  }
}

describe('openclaw bridge runtime fixtures', () => {
  beforeAll(() => {
    const tempRoot = mkdtempSync(join(tmpdir(), 'clawdstrike-openclaw-bridge-fixtures-'));
    const policyPath = join(tempRoot, 'fixture-policy.yaml');
    writeFileSync(policyPath, `
version: "1.2.0"
guards:
  egress_allowlist:
    enabled: true
    default_action: allow
    allow:
      - "*"
  computer_use:
    enabled: true
    mode: guardrail
    allowed_actions:
      - "remote.session.connect"
      - "remote.session.disconnect"
      - "remote.session.reconnect"
      - "input.inject"
      - "remote.clipboard"
      - "remote.file_transfer"
      - "remote.audio"
      - "remote.drive_mapping"
      - "remote.printing"
      - "remote.session_share"
  remote_desktop_side_channel:
    enabled: true
    clipboard_enabled: true
    file_transfer_enabled: true
    audio_enabled: true
    drive_mapping_enabled: true
    printing_enabled: true
    session_share_enabled: true
  input_injection_capability:
    enabled: true
    require_postcondition_probe: false
`);

    initialize({ policy: policyPath });
  });

  const factory = new PolicyEventFactory();

  for (const fixtureCase of CASES.cases) {
    it(fixtureCase.id, async () => {
      const { query, expected, id } = fixtureCase;

      if (query.source === 'parity') {
        const sessionId = String(query.session_id ?? 'sess-parity');
        const params = (query.params ?? {}) as Record<string, unknown>;
        const toolName = String(query.tool_name ?? '');

        const actionToken = extractActionToken(toolName, params);
        expect(actionToken).not.toBeNull();

        const kind = classifyCuaAction(actionToken as string);
        expect(kind).not.toBeNull();

        const openClawEvent = buildCuaEvent(sessionId, kind as CuaActionKind, params);
        const directEvent = directFactoryEventForKind(factory, kind as CuaActionKind, sessionId, params);

        for (const parityField of query.parity_fields as string[]) {
          if (parityField === 'eventType') {
            expect(openClawEvent.eventType).toBe(directEvent.eventType);
          } else if (parityField === 'data.type') {
            expect(openClawEvent.data.type).toBe(directEvent.data.type);
          } else if (parityField === 'data.cuaAction') {
            if (openClawEvent.data.type === 'cua' && directEvent.data.type === 'cua') {
              expect(openClawEvent.data.cuaAction).toBe(directEvent.data.cuaAction);
            } else {
              throw new Error('Expected CUA data types for parity comparison');
            }
          }
        }

        expect(expected.result).toBe('pass');
        return;
      }

      const toolName = String(query.tool_name ?? '');
      const params = (query.params ?? {}) as Record<string, unknown>;
      const sessionId = String(query.session_id ?? '');
      const event = makeToolCallEvent(toolName, params, sessionId);

      if (expected.result === 'fail') {
        await handler(event);
        expect(event.preventDefault).toBe(true);

        const errorCode = expected.error_code as string;
        const inferredCode = expectedErrorCodeForCase(id);
        if (errorCode && inferredCode) {
          expect(errorCode).toBe(inferredCode);
        }
        expect(event.messages.join('\n')).toContain(errorCode);
        return;
      }

      // Pass case
      expect(isCuaToolCall(toolName, params)).toBe(true);

      const actionToken = extractActionToken(toolName, params);
      expect(actionToken).not.toBeNull();
      const kind = classifyCuaAction(actionToken as string);
      expect(kind).not.toBeNull();

      const canonicalEvent = buildCuaEvent(sessionId, kind as CuaActionKind, params);

      await handler(event);
      expect(event.preventDefault).toBe(false);
      expect(event.messages.some((m) => m.includes('allowed'))).toBe(true);

      expect(canonicalEvent.eventType).toBe(query.expected_event_type);
      if (canonicalEvent.data.type === 'cua') {
        expect(canonicalEvent.data.cuaAction).toBe(query.expected_cua_action);

        if (query.expected_direction !== undefined) {
          expect(canonicalEvent.data.direction).toBe(query.expected_direction);
        }

        if (query.expected_host !== undefined) {
          expect(canonicalEvent.data.host).toBe(query.expected_host);
        }

        if (query.expected_port !== undefined) {
          expect(canonicalEvent.data.port).toBe(query.expected_port);
        }

        if (query.expected_url !== undefined) {
          expect(canonicalEvent.data.url).toBe(query.expected_url);
        }

        if (query.expected_continuity_hash !== undefined) {
          expect(canonicalEvent.data.continuityPrevSessionHash).toBe(query.expected_continuity_hash);
        }
      } else {
        throw new Error('Expected canonical CUA event data');
      }
    });
  }
});
