import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import type { EventType, PolicyEvent } from './types.js';

const THIS_DIR = fileURLToPath(new URL('.', import.meta.url));
const FIXTURES_PATH = resolve(THIS_DIR, '../../../fixtures/policy-events/v1/events.jsonl');

const KNOWN_EVENT_TYPES: EventType[] = [
  'file_read',
  'file_write',
  'network_egress',
  'command_exec',
  'patch_apply',
  'tool_call',
  'secret_access',
  'custom',
];

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function assertPolicyEventShape(value: unknown): asserts value is PolicyEvent {
  expect(isRecord(value)).toBe(true);

  expect(typeof value.eventId).toBe('string');
  expect(value.eventId.length).toBeGreaterThan(0);

  expect(KNOWN_EVENT_TYPES).toContain(value.eventType as EventType);
  expect(typeof value.timestamp).toBe('string');

  expect(isRecord(value.data)).toBe(true);
  expect(typeof value.data.type).toBe('string');

  // Validate canonical eventType <-> data.type pairing where possible.
  const eventType = value.eventType as EventType;
  const dataType = value.data.type as string;

  if (eventType === 'file_read' || eventType === 'file_write') {
    expect(dataType).toBe('file');
  } else if (eventType === 'network_egress') {
    expect(dataType).toBe('network');
  } else if (eventType === 'command_exec') {
    expect(dataType).toBe('command');
  } else if (eventType === 'patch_apply') {
    expect(dataType).toBe('patch');
  } else if (eventType === 'tool_call') {
    expect(dataType).toBe('tool');
  } else if (eventType === 'secret_access') {
    expect(dataType).toBe('secret');
  } else if (eventType === 'custom') {
    expect(dataType).toBe('custom');
  }
}

describe('fixtures/policy-events/v1', () => {
  it('parses and validates PolicyEvent JSONL fixtures', () => {
    const text = readFileSync(FIXTURES_PATH, 'utf8');
    const lines = text.split('\n').filter(line => line.trim().length > 0);

    for (const [idx, line] of lines.entries()) {
      const parsed = JSON.parse(line) as unknown;
      expect(() => assertPolicyEventShape(parsed)).not.toThrow(`line ${idx + 1}`);
    }
  });
});
