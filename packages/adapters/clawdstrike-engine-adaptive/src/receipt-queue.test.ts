import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createReceiptQueue } from './receipt-queue.js';
import type { QueuedReceipt } from './types.js';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

function makeReceipt(id: string): QueuedReceipt {
  return {
    event: { id },
    decision: { status: 'allow' },
    provenance: {
      mode: 'degraded',
      engine: 'local',
      timestamp: new Date().toISOString(),
    },
    enqueuedAt: new Date().toISOString(),
  };
}

describe('ReceiptQueue', () => {
  it('enqueues and drains receipts', () => {
    const queue = createReceiptQueue();
    queue.enqueue(makeReceipt('1'));
    queue.enqueue(makeReceipt('2'));
    expect(queue.size()).toBe(2);

    const drained = queue.drain();
    expect(drained).toHaveLength(2);
    expect(queue.size()).toBe(0);
  });

  it('respects maxSize with FIFO eviction', () => {
    const queue = createReceiptQueue({ maxSize: 3 });
    queue.enqueue(makeReceipt('a'));
    queue.enqueue(makeReceipt('b'));
    queue.enqueue(makeReceipt('c'));
    queue.enqueue(makeReceipt('d'));

    expect(queue.size()).toBe(3);
    const drained = queue.drain();
    // Oldest ('a') should have been evicted.
    expect((drained[0].event as { id: string }).id).toBe('b');
    expect((drained[2].event as { id: string }).id).toBe('d');
  });

  it('drain returns empty array when queue is empty', () => {
    const queue = createReceiptQueue();
    expect(queue.drain()).toEqual([]);
  });

  describe('JSONL persistence', () => {
    let tempDir: string;

    beforeEach(() => {
      tempDir = mkdtempSync(join(tmpdir(), 'receipt-queue-'));
    });

    afterEach(() => {
      rmSync(tempDir, { recursive: true, force: true });
    });

    it('persists on enqueue and truncates on drain', () => {
      const filePath = join(tempDir, 'queue.jsonl');
      const queue = createReceiptQueue({ persistPath: filePath });

      queue.enqueue(makeReceipt('1'));
      queue.enqueue(makeReceipt('2'));

      const content = readFileSync(filePath, 'utf-8');
      const lines = content.split('\n').filter((l) => l.trim().length > 0);
      expect(lines).toHaveLength(2);

      queue.drain();
      const afterDrain = readFileSync(filePath, 'utf-8');
      expect(afterDrain).toBe('');
    });

    it('compacts persisted queue when maxSize eviction occurs', () => {
      const filePath = join(tempDir, 'queue.jsonl');
      const queue = createReceiptQueue({ persistPath: filePath, maxSize: 2 });

      queue.enqueue(makeReceipt('a'));
      queue.enqueue(makeReceipt('b'));
      queue.enqueue(makeReceipt('c'));

      const lines = readFileSync(filePath, 'utf-8')
        .split('\n')
        .filter((l) => l.trim().length > 0)
        .map((l) => JSON.parse(l) as QueuedReceipt);
      expect(lines).toHaveLength(2);
      expect((lines[0].event as { id: string }).id).toBe('b');
      expect((lines[1].event as { id: string }).id).toBe('c');
    });

    it('round-trips through loadFromDisk and persistToDisk', () => {
      const filePath = join(tempDir, 'queue.jsonl');
      const q1 = createReceiptQueue({ persistPath: filePath });
      q1.enqueue(makeReceipt('x'));
      q1.enqueue(makeReceipt('y'));
      q1.persistToDisk(filePath);

      const q2 = createReceiptQueue();
      q2.loadFromDisk(filePath);
      expect(q2.size()).toBe(2);
      const drained = q2.drain();
      expect((drained[0].event as { id: string }).id).toBe('x');
      expect((drained[1].event as { id: string }).id).toBe('y');
    });

    it('loadFromDisk handles missing file gracefully', () => {
      const queue = createReceiptQueue();
      queue.loadFromDisk(join(tempDir, 'does-not-exist.jsonl'));
      expect(queue.size()).toBe(0);
    });

    it('loadFromDisk trims to maxSize and compacts persisted file', () => {
      const filePath = join(tempDir, 'queue.jsonl');
      const lines = [makeReceipt('a'), makeReceipt('b'), makeReceipt('c')]
        .map((r) => JSON.stringify(r))
        .join('\n') + '\n';
      writeFileSync(filePath, lines, 'utf-8');

      const queue = createReceiptQueue({ maxSize: 2 });
      queue.loadFromDisk(filePath);
      expect(queue.size()).toBe(2);

      const compacted = readFileSync(filePath, 'utf-8')
        .split('\n')
        .filter((l) => l.trim().length > 0)
        .map((l) => JSON.parse(l) as QueuedReceipt);
      expect(compacted).toHaveLength(2);
      expect((compacted[0].event as { id: string }).id).toBe('b');
      expect((compacted[1].event as { id: string }).id).toBe('c');
    });
  });
});
