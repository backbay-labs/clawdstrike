import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { claudeCuaTranslator } from '../../clawdstrike-claude/src/claude-cua-translator.js';
import { openAICuaTranslator } from './openai-cua-translator.js';

type Provider = 'openai' | 'claude';

type CanonicalLike = {
  eventType?: unknown;
  data?: {
    cuaAction?: unknown;
    direction?: unknown;
    [key: string]: unknown;
  };
  [key: string]: unknown;
};

type CaseDoc = {
  cases: Array<{
    id: string;
    query: Record<string, any>;
    expected: Record<string, any>;
  }>;
};

const THIS_DIR = fileURLToPath(new URL('.', import.meta.url));
const CASES_PATH = resolve(THIS_DIR, '../../../../fixtures/policy-events/provider-conformance/v1/cases.json');
const CASES = JSON.parse(readFileSync(CASES_PATH, 'utf8')) as CaseDoc;

const KNOWN_INTENTS = new Set([
  'connect',
  'input',
  'clipboard_read',
  'clipboard_write',
  'file_transfer_upload',
  'file_transfer_download',
  'session_share',
  'reconnect',
  'disconnect',
]);

function normalizeCanonical(value: CanonicalLike): { eventType: unknown; data: { cuaAction: unknown; direction: unknown } } {
  return {
    eventType: value.eventType,
    data: {
      cuaAction: value.data?.cuaAction,
      direction: value.data?.direction ?? null,
    },
  };
}

function translate(provider: Provider, providerInput: Record<string, unknown>, sessionId: string): CanonicalLike {
  const input = {
    framework: provider,
    toolName: String(providerInput.tool ?? ''),
    parameters: providerInput,
    rawInput: providerInput,
    sessionId,
    contextMetadata: {},
  };

  const event = provider === 'openai'
    ? openAICuaTranslator(input)
    : claudeCuaTranslator(input);

  if (!event) {
    throw new Error(`Translator returned null for provider '${provider}'`);
  }

  return normalizeCanonical(event as unknown as CanonicalLike);
}

function evaluateSingle(query: Record<string, any>): Record<string, any> {
  const provider = query.provider;
  const intent = query.intent;

  if (provider !== 'openai' && provider !== 'claude') {
    return { result: 'fail', error_code: 'PRV_PROVIDER_UNKNOWN' };
  }

  if (!KNOWN_INTENTS.has(String(intent ?? ''))) {
    return { result: 'fail', error_code: 'PRV_INTENT_UNKNOWN' };
  }

  let canonical = translate(provider, query.provider_input ?? {}, `sess-${provider}`);
  if (query.override_canonical) {
    canonical = normalizeCanonical(query.override_canonical as CanonicalLike);
  }

  if (!canonical.eventType || canonical.data.cuaAction === undefined) {
    return { result: 'fail', error_code: 'PRV_MISSING_REQUIRED_FIELD' };
  }

  return { result: 'pass', canonical };
}

function evaluateParity(query: Record<string, any>): Record<string, any> {
  const providerA = query.provider_a?.provider;
  const providerB = query.provider_b?.provider;
  const intent = query.intent;

  if ((providerA !== 'openai' && providerA !== 'claude') || (providerB !== 'openai' && providerB !== 'claude')) {
    return { result: 'fail', error_code: 'PRV_PROVIDER_UNKNOWN' };
  }

  if (!KNOWN_INTENTS.has(String(intent ?? ''))) {
    return { result: 'fail', error_code: 'PRV_INTENT_UNKNOWN' };
  }

  const canonicalA = translate(providerA, query.provider_a?.provider_input ?? {}, `sess-${providerA}`);
  const canonicalB = query.override_canonical_b
    ? normalizeCanonical(query.override_canonical_b as CanonicalLike)
    : translate(providerB, query.provider_b?.provider_input ?? {}, `sess-${providerB}`);

  if (
    canonicalA.eventType !== canonicalB.eventType
    || canonicalA.data.cuaAction !== canonicalB.data.cuaAction
    || canonicalA.data.direction !== canonicalB.data.direction
  ) {
    return { result: 'fail', error_code: 'PRV_PARITY_VIOLATION' };
  }

  return { result: 'pass', parity: true };
}

describe('provider-conformance runtime fixture checks', () => {
  for (const testCase of CASES.cases) {
    it(testCase.id, () => {
      const query = testCase.query;
      const expected = testCase.expected;

      const actual = query.type === 'parity_check'
        ? evaluateParity(query)
        : evaluateSingle(query);

      expect(actual.result).toBe(expected.result);
      if (expected.error_code !== undefined) {
        expect(actual.error_code ?? null).toBe(expected.error_code);
      }

      if (expected.canonical) {
        expect(actual.canonical).toEqual(expected.canonical);
      }

      if (expected.parity !== undefined) {
        expect(actual.parity).toBe(expected.parity);
      }
    });
  }
});
