import { readFileSync, writeFileSync, appendFileSync } from 'node:fs';
import type { QueuedReceipt } from './types.js';

export interface ReceiptQueue {
  enqueue(receipt: QueuedReceipt): void;
  drain(): QueuedReceipt[];
  size(): number;
  loadFromDisk(path: string): void;
  persistToDisk(path: string): void;
}

export function createReceiptQueue(options?: {
  maxSize?: number;
  persistPath?: string;
}): ReceiptQueue {
  const maxSize = options?.maxSize ?? 1000;
  const persistPath = options?.persistPath;
  const items: QueuedReceipt[] = [];

  return {
    enqueue(receipt: QueuedReceipt): void {
      items.push(receipt);

      // Evict oldest entries when over capacity.
      while (items.length > maxSize) {
        items.shift();
      }

      if (persistPath) {
        try {
          appendFileSync(persistPath, JSON.stringify(receipt) + '\n', 'utf-8');
        } catch {
          // Persistence is best-effort; failures must not break evaluation.
        }
      }
    },

    drain(): QueuedReceipt[] {
      const drained = items.splice(0, items.length);

      if (persistPath) {
        try {
          writeFileSync(persistPath, '', 'utf-8');
        } catch {
          // Best-effort truncation.
        }
      }

      return drained;
    },

    size(): number {
      return items.length;
    },

    loadFromDisk(path: string): void {
      try {
        const content = readFileSync(path, 'utf-8');
        const lines = content.split('\n').filter((line) => line.trim().length > 0);
        for (const line of lines) {
          const receipt = JSON.parse(line) as QueuedReceipt;
          items.push(receipt);
        }

        // Trim to maxSize after load.
        while (items.length > maxSize) {
          items.shift();
        }
      } catch {
        // File may not exist yet; that is fine.
      }
    },

    persistToDisk(path: string): void {
      try {
        const content = items.map((r) => JSON.stringify(r)).join('\n') + (items.length > 0 ? '\n' : '');
        writeFileSync(path, content, 'utf-8');
      } catch {
        // Best-effort persistence.
      }
    },
  };
}
