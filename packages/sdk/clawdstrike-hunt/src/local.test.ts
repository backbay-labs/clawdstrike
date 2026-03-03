import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { canonicalize, generateKeypair, sha256, signMessage, toHex } from '@clawdstrike/sdk';
import { queryLocalFiles, hunt } from './local.js';
import { createHuntQuery } from './query.js';

function makeEnvelope(
  schema: string,
  ts: string,
  decision: string,
  summaryText: string,
): Record<string, unknown> {
  return {
    issued_at: ts,
    fact: {
      schema,
      decision,
      guard: 'TestGuard',
      action_type: 'file_open',
      severity: 'info',
      event_type: 'PROCESS_EXEC',
      process: { binary: '/usr/bin/cat' },
      verdict: decision.toUpperCase(),
      traffic_direction: 'EGRESS',
      summary: summaryText,
      scan_type: 'vulnerability',
      status: decision,
      source: {
        namespace: 'default',
        pod_name: 'test-pod',
      },
    },
  };
}

async function makeSignedEnvelope(
  envelope: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const issuedAt = envelope.issued_at;
  const fact = envelope.fact;
  if (typeof issuedAt !== 'string' || typeof fact !== 'object' || fact === null) {
    throw new Error('invalid envelope fixture');
  }

  const { privateKey, publicKey } = await generateKeypair();
  const unsigned: Record<string, unknown> = {
    schema: 'aegis.spine.envelope.v1',
    issuer: `aegis:ed25519:${toHex(publicKey)}`,
    seq: 1,
    prev_envelope_hash: null,
    issued_at: issuedAt,
    capability_token: null,
    fact,
  };

  const canonical = canonicalize(unsigned as Parameters<typeof canonicalize>[0]);
  const message = new TextEncoder().encode(canonical);
  const signature = await signMessage(message, privateKey);

  return {
    ...unsigned,
    envelope_hash: `0x${toHex(sha256(message))}`,
    signature: `0x${toHex(signature)}`,
  };
}

describe('queryLocalFiles', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'hunt-local-test-'));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it('reads a single JSON envelope', async () => {
    const envelope = makeEnvelope(
      'clawdstrike.sdr.fact.tetragon_event.v1',
      '2025-01-15T10:00:00Z',
      'allow',
      'file_open /etc/passwd',
    );
    await writeFile(
      join(tempDir, 'envelope.json'),
      JSON.stringify(envelope),
    );

    const query = createHuntQuery();
    const events = await queryLocalFiles(query, [tempDir]);
    expect(events).toHaveLength(1);
    expect(events[0].summary).toContain('process_exec');
  });

  it('reads an array of JSON envelopes', async () => {
    const envelopes = [
      makeEnvelope(
        'clawdstrike.sdr.fact.receipt.v1',
        '2025-01-15T10:00:00Z',
        'deny',
        'blocked',
      ),
      makeEnvelope(
        'clawdstrike.sdr.fact.receipt.v1',
        '2025-01-15T10:01:00Z',
        'allow',
        'allowed',
      ),
    ];
    await writeFile(
      join(tempDir, 'envelopes.json'),
      JSON.stringify(envelopes),
    );

    const query = createHuntQuery();
    const events = await queryLocalFiles(query, [tempDir]);
    expect(events).toHaveLength(2);
  });

  it('reads JSONL files', async () => {
    const e1 = makeEnvelope(
      'clawdstrike.sdr.fact.tetragon_event.v1',
      '2025-01-15T10:00:00Z',
      'allow',
      'open /etc/hosts',
    );
    const e2 = makeEnvelope(
      'clawdstrike.sdr.fact.tetragon_event.v1',
      '2025-01-15T10:01:00Z',
      'deny',
      'egress to evil.com',
    );

    const lines = [
      JSON.stringify(e1),
      '', // blank line should be skipped
      JSON.stringify(e2),
    ];
    await writeFile(join(tempDir, 'events.jsonl'), lines.join('\n'));

    const query = createHuntQuery();
    const events = await queryLocalFiles(query, [tempDir]);
    expect(events).toHaveLength(2);
  });

  it('skips invalid JSONL lines', async () => {
    const e1 = makeEnvelope(
      'clawdstrike.sdr.fact.receipt.v1',
      '2025-01-15T10:00:00Z',
      'allow',
      'read /tmp/data',
    );
    const e2 = makeEnvelope(
      'clawdstrike.sdr.fact.receipt.v1',
      '2025-01-15T10:02:00Z',
      'allow',
      'echo hello',
    );

    const lines = [
      JSON.stringify(e1),
      'not valid json {{{',
      JSON.stringify(e2),
    ];
    await writeFile(join(tempDir, 'mixed.jsonl'), lines.join('\n'));

    const query = createHuntQuery();
    const events = await queryLocalFiles(query, [tempDir]);
    expect(events).toHaveLength(2);
  });

  it('skips non-JSON/JSONL files', async () => {
    await writeFile(join(tempDir, 'notes.txt'), 'not an envelope');
    const envelope = makeEnvelope(
      'clawdstrike.sdr.fact.receipt.v1',
      '2025-01-15T10:00:00Z',
      'allow',
      'test',
    );
    await writeFile(
      join(tempDir, 'envelope.json'),
      JSON.stringify(envelope),
    );

    const query = createHuntQuery();
    const events = await queryLocalFiles(query, [tempDir]);
    expect(events).toHaveLength(1);
  });

  it('skips corrupt JSON files', async () => {
    const envelope = makeEnvelope(
      'clawdstrike.sdr.fact.receipt.v1',
      '2025-01-15T10:00:00Z',
      'allow',
      'test',
    );
    await writeFile(
      join(tempDir, 'valid.json'),
      JSON.stringify(envelope),
    );
    await writeFile(join(tempDir, 'corrupt.json'), '{not valid json');

    const query = createHuntQuery();
    const events = await queryLocalFiles(query, [tempDir]);
    expect(events).toHaveLength(1);
  });

  it('skips nonexistent directories', async () => {
    const query = createHuntQuery();
    const events = await queryLocalFiles(query, [
      '/nonexistent/path/that/does/not/exist',
    ]);
    expect(events).toHaveLength(0);
  });

  it('respects limit keeping newest events', async () => {
    const lines = [
      JSON.stringify(
        makeEnvelope(
          'clawdstrike.sdr.fact.receipt.v1',
          '2025-01-15T10:00:00Z',
          'allow',
          'event-1',
        ),
      ),
      JSON.stringify(
        makeEnvelope(
          'clawdstrike.sdr.fact.receipt.v1',
          '2025-01-15T10:01:00Z',
          'allow',
          'event-2',
        ),
      ),
      JSON.stringify(
        makeEnvelope(
          'clawdstrike.sdr.fact.receipt.v1',
          '2025-01-15T10:02:00Z',
          'allow',
          'event-3',
        ),
      ),
    ];
    await writeFile(join(tempDir, 'events.jsonl'), lines.join('\n'));

    const query = createHuntQuery({ limit: 2 });
    const events = await queryLocalFiles(query, [tempDir]);

    expect(events).toHaveLength(2);
    expect(events[0].timestamp.toISOString()).toBe(
      '2025-01-15T10:01:00.000Z',
    );
    expect(events[1].timestamp.toISOString()).toBe(
      '2025-01-15T10:02:00.000Z',
    );
  });

  it('limit 0 returns no events', async () => {
    const lines = [
      JSON.stringify(
        makeEnvelope(
          'clawdstrike.sdr.fact.receipt.v1',
          '2025-01-15T10:00:00Z',
          'allow',
          'event-1',
        ),
      ),
    ];
    await writeFile(join(tempDir, 'events.jsonl'), lines.join('\n'));

    const query = createHuntQuery({ limit: 0 });
    const events = await queryLocalFiles(query, [tempDir]);
    expect(events).toHaveLength(0);
  });

  it('populates signatureValid when verify=true', async () => {
    const signedEnvelope = await makeSignedEnvelope(
      makeEnvelope(
        'clawdstrike.sdr.fact.receipt.v1',
        '2025-01-15T10:00:00Z',
        'allow',
        'verified',
      ),
    );
    await writeFile(join(tempDir, 'signed.json'), JSON.stringify(signedEnvelope));

    const query = createHuntQuery();
    const events = await queryLocalFiles(query, [tempDir], true);
    expect(events).toHaveLength(1);
    expect(events[0].signatureValid).toBe(true);
  });

  it('marks tampered signed envelopes as invalid when verify=true', async () => {
    const signedEnvelope = await makeSignedEnvelope(
      makeEnvelope(
        'clawdstrike.sdr.fact.receipt.v1',
        '2025-01-15T10:00:00Z',
        'allow',
        'verified',
      ),
    );

    const fact = signedEnvelope.fact as Record<string, unknown>;
    fact.decision = 'deny';
    await writeFile(join(tempDir, 'tampered.json'), JSON.stringify(signedEnvelope));

    const query = createHuntQuery();
    const events = await queryLocalFiles(query, [tempDir], true);
    expect(events).toHaveLength(1);
    expect(events[0].signatureValid).toBe(false);
  });
});

describe('hunt', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'hunt-fn-test-'));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it('queries with explicit dirs', async () => {
    const envelope = makeEnvelope(
      'clawdstrike.sdr.fact.receipt.v1',
      '2025-01-15T10:00:00Z',
      'deny',
      'blocked',
    );
    await writeFile(
      join(tempDir, 'test.json'),
      JSON.stringify(envelope),
    );

    const events = await hunt({ dirs: [tempDir] });
    expect(events).toHaveLength(1);
  });

  it('accepts duration string for start', async () => {
    const envelope = makeEnvelope(
      'clawdstrike.sdr.fact.receipt.v1',
      new Date().toISOString(),
      'allow',
      'recent event',
    );
    await writeFile(
      join(tempDir, 'recent.json'),
      JSON.stringify(envelope),
    );

    const events = await hunt({ start: '1h', dirs: [tempDir] });
    expect(events).toHaveLength(1);
  });

  it('forwards verify to local file parsing', async () => {
    const signedEnvelope = await makeSignedEnvelope(
      makeEnvelope(
        'clawdstrike.sdr.fact.receipt.v1',
        '2025-01-15T10:00:00Z',
        'allow',
        'verified',
      ),
    );
    await writeFile(join(tempDir, 'verified.json'), JSON.stringify(signedEnvelope));

    const events = await hunt({ dirs: [tempDir], verify: true });
    expect(events).toHaveLength(1);
    expect(events[0].signatureValid).toBe(true);
  });
});
