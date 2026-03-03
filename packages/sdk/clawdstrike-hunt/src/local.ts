import { readdir, readFile, stat } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join, extname } from 'node:path';

import type { HuntQuery, NormalizedVerdict, TimelineEvent, EventSourceType } from './types.js';
import { matchesQuery } from './query.js';
import { mergeTimeline, parseEnvelope } from './timeline.js';
import { parseHumanDuration } from './duration.js';

/**
 * Default directories to search for local envelopes.
 * Returns only directories that actually exist.
 */
export async function defaultLocalDirs(): Promise<string[]> {
  const home = homedir();
  const candidates = [
    join(home, '.clawdstrike', 'receipts'),
    join(home, '.clawdstrike', 'scans'),
    join(home, '.hush', 'receipts'),
  ];

  const result: string[] = [];
  for (const dir of candidates) {
    try {
      const s = await stat(dir);
      if (s.isDirectory()) {
        result.push(dir);
      }
    } catch {
      // Directory does not exist, skip
    }
  }
  return result;
}

function truncateToNewest(
  events: TimelineEvent[],
  limit: number,
): TimelineEvent[] {
  if (limit === 0) {
    return [];
  }
  if (events.length <= limit) {
    return events;
  }
  return events.slice(events.length - limit);
}

/**
 * Query envelopes from local JSON/JSONL files.
 *
 * Reads files from the given search directories. `.json` files may contain
 * a single envelope or an array. `.jsonl` files contain one envelope per line.
 * Corrupt files/lines are skipped.
 * When `verify` is true, each parsed envelope gets `signatureValid` populated.
 *
 * Results are filtered by the query, merged by timestamp, and truncated
 * to the newest `query.limit` events.
 */
export async function queryLocalFiles(
  query: HuntQuery,
  searchDirs?: string[],
  verify: boolean = false,
): Promise<TimelineEvent[]> {
  const dirs = searchDirs ?? await defaultLocalDirs();
  const allEvents: TimelineEvent[] = [];

  for (const dir of dirs) {
    let isDir: boolean;
    try {
      const s = await stat(dir);
      isDir = s.isDirectory();
    } catch {
      isDir = false;
    }
    if (!isDir) {
      continue;
    }

    let entries: string[];
    try {
      entries = await readdir(dir);
    } catch {
      continue;
    }

    for (const entry of entries) {
      const filePath = join(dir, entry);
      let fileStat;
      try {
        fileStat = await stat(filePath);
      } catch {
        continue;
      }

      if (!fileStat.isFile()) {
        continue;
      }

      const ext = extname(entry).toLowerCase();
      let events: TimelineEvent[];

      if (ext === '.json') {
        try {
          events = await readJsonFile(filePath, verify);
        } catch {
          continue;
        }
      } else if (ext === '.jsonl') {
        try {
          events = await readJsonlFile(filePath, verify);
        } catch {
          continue;
        }
      } else {
        continue;
      }

      for (const event of events) {
        if (matchesQuery(query, event)) {
          allEvents.push(event);
        }
      }
    }
  }

  const merged = mergeTimeline(allEvents);
  return truncateToNewest(merged, query.limit);
}

/**
 * Options for the high-level `hunt()` convenience function.
 */
export interface HuntOptions {
  sources?: EventSourceType[];
  verdict?: NormalizedVerdict;
  /** Accepts a Date or a human-duration string like "1h", "30m". */
  start?: Date | string;
  end?: Date;
  actionType?: string;
  process?: string;
  namespace?: string;
  pod?: string;
  entity?: string;
  limit?: number;
  dirs?: string[];
  /** Verify envelope signatures and populate `event.signatureValid`. */
  verify?: boolean;
}

/**
 * High-level convenience function for querying local events.
 *
 * Parses duration strings for `start`, applies defaults, builds a query,
 * and calls `queryLocalFiles`.
 */
export async function hunt(options?: HuntOptions): Promise<TimelineEvent[]> {
  const opts = options ?? {};

  let startDate: Date | undefined;
  if (typeof opts.start === 'string') {
    const ms = parseHumanDuration(opts.start);
    if (ms !== undefined) {
      startDate = new Date(Date.now() - ms);
    }
  } else {
    startDate = opts.start;
  }

  const query: HuntQuery = {
    sources: opts.sources ?? [],
    verdict: opts.verdict,
    start: startDate,
    end: opts.end,
    actionType: opts.actionType,
    process: opts.process,
    namespace: opts.namespace,
    pod: opts.pod,
    entity: opts.entity,
    limit: opts.limit ?? 100,
  };

  return queryLocalFiles(query, opts.dirs, opts.verify ?? false);
}

async function readJsonFile(path: string, verify: boolean): Promise<TimelineEvent[]> {
  const content = await readFile(path, 'utf-8');
  const value: unknown = JSON.parse(content);

  if (Array.isArray(value)) {
    return value
      .map((v) => parseEnvelope(v, verify))
      .filter((e): e is TimelineEvent => e !== undefined);
  }

  const event = parseEnvelope(value, verify);
  return event !== undefined ? [event] : [];
}

async function readJsonlFile(path: string, verify: boolean): Promise<TimelineEvent[]> {
  const content = await readFile(path, 'utf-8');
  const events: TimelineEvent[] = [];

  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (trimmed.length === 0) {
      continue;
    }
    try {
      const value: unknown = JSON.parse(trimmed);
      const event = parseEnvelope(value, verify);
      if (event !== undefined) {
        events.push(event);
      }
    } catch {
      // Skip invalid JSON lines
    }
  }

  return events;
}
