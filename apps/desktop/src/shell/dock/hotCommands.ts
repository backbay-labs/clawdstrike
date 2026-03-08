export type HotCommandScope = "global" | "nexus" | "operations";

export interface HotCommand {
  id: string;
  title: string;
  description?: string;
  command: string;
  scope: HotCommandScope;
  pinned: boolean;
  createdAt: number;
  updatedAt: number;
  lastUsedAt?: number;
}

export interface HotCommandInput {
  id?: string;
  title: string;
  description?: string;
  command: string;
  scope?: HotCommandScope;
  pinned?: boolean;
}

export const HOT_COMMANDS_STORAGE_KEY = "sdr:hot-commands:v1";

const KNOWN_SCOPES = new Set<HotCommandScope>(["global", "nexus", "operations"]);

const DEFAULT_COMMANDS: HotCommand[] = [
  {
    id: "cmd_ops_fleet",
    title: "Open Fleet",
    description: "Jump to Operations fleet management",
    command: "/operations?tab=fleet",
    scope: "operations",
    pinned: true,
    createdAt: 0,
    updatedAt: 0,
  },
  {
    id: "cmd_ops_connection",
    title: "Connection Settings",
    description: "Open daemon connection controls",
    command: "/operations?tab=connection",
    scope: "operations",
    pinned: true,
    createdAt: 0,
    updatedAt: 0,
  },
  {
    id: "cmd_open_policies",
    title: "Open Policies",
    description: "Jump to policy viewer",
    command: "/policies",
    scope: "nexus",
    pinned: false,
    createdAt: 0,
    updatedAt: 0,
  },
  {
    id: "cmd_palette",
    title: "Open Command Palette",
    description: "Open the global command palette",
    command: "palette",
    scope: "global",
    pinned: false,
    createdAt: 0,
    updatedAt: 0,
  },
];

function now(): number {
  return Date.now();
}

function generateId(): string {
  return `cmd_${now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
}

function asString(value: unknown): string | null {
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : null;
}

function asScope(value: unknown): HotCommandScope {
  return typeof value === "string" && KNOWN_SCOPES.has(value as HotCommandScope)
    ? (value as HotCommandScope)
    : "global";
}

function asNumber(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function normalizeHotCommand(raw: unknown): HotCommand | null {
  if (!raw || typeof raw !== "object") return null;
  const record = raw as Record<string, unknown>;
  const id = asString(record.id);
  const title = asString(record.title);
  const command = asString(record.command);
  if (!id || !title || !command) return null;

  const createdAt = asNumber(record.createdAt, now());
  const updatedAt = asNumber(record.updatedAt, createdAt);

  return {
    id,
    title,
    description: asString(record.description) ?? undefined,
    command,
    scope: asScope(record.scope),
    pinned: Boolean(record.pinned),
    createdAt,
    updatedAt,
    lastUsedAt: asNumber(record.lastUsedAt, updatedAt),
  };
}

function withDefaultTimestamps(commands: HotCommand[]): HotCommand[] {
  const seededAt = now();
  return commands.map((command, index) => ({
    ...command,
    createdAt: command.createdAt || seededAt - (commands.length - index) * 1000,
    updatedAt: command.updatedAt || seededAt - (commands.length - index) * 1000,
  }));
}

export function sortHotCommands(commands: HotCommand[]): HotCommand[] {
  return [...commands].sort((a, b) => {
    if (a.pinned !== b.pinned) return a.pinned ? -1 : 1;
    const aRef = a.lastUsedAt ?? a.updatedAt;
    const bRef = b.lastUsedAt ?? b.updatedAt;
    if (aRef !== bRef) return bRef - aRef;
    return a.title.localeCompare(b.title);
  });
}

function readStoredHotCommands(): HotCommand[] {
  try {
    const raw = localStorage.getItem(HOT_COMMANDS_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return [];
    return parsed
      .map((entry) => normalizeHotCommand(entry))
      .filter((entry): entry is HotCommand => entry !== null);
  } catch {
    return [];
  }
}

export function loadHotCommands(): HotCommand[] {
  const stored = readStoredHotCommands();
  if (stored.length > 0) return sortHotCommands(stored);
  return sortHotCommands(withDefaultTimestamps(DEFAULT_COMMANDS));
}

export function saveHotCommands(commands: HotCommand[]): void {
  try {
    localStorage.setItem(HOT_COMMANDS_STORAGE_KEY, JSON.stringify(sortHotCommands(commands)));
  } catch {
    // ignore storage write failures
  }
}

export function upsertHotCommand(commands: HotCommand[], input: HotCommandInput): HotCommand[] {
  const ts = now();
  const title = input.title.trim();
  const command = input.command.trim();
  if (!title || !command) return commands;

  const id = input.id ?? generateId();
  const existing = commands.find((entry) => entry.id === id);
  const next: HotCommand = {
    id,
    title,
    description: input.description?.trim() || undefined,
    command,
    scope: input.scope ?? existing?.scope ?? "global",
    pinned: input.pinned ?? existing?.pinned ?? false,
    createdAt: existing?.createdAt ?? ts,
    updatedAt: ts,
    lastUsedAt: existing?.lastUsedAt,
  };

  const withoutExisting = commands.filter((entry) => entry.id !== id);
  return sortHotCommands([...withoutExisting, next]);
}

export function removeHotCommand(commands: HotCommand[], id: string): HotCommand[] {
  return sortHotCommands(commands.filter((entry) => entry.id !== id));
}

export function markHotCommandUsed(commands: HotCommand[], id: string): HotCommand[] {
  const ts = now();
  return sortHotCommands(
    commands.map((entry) =>
      entry.id === id ? { ...entry, lastUsedAt: ts, updatedAt: ts } : entry,
    ),
  );
}

export type HotCommandAction =
  | { kind: "navigate"; path: string }
  | { kind: "palette" }
  | { kind: "event"; payload: string }
  | { kind: "invalid"; reason: string };

function ensurePath(value: string): string {
  return value.startsWith("/") ? value : `/${value}`;
}

function normalizeLegacyPath(path: string): string {
  return path.startsWith("/nexus-labs") ? path.replace("/nexus-labs", "/nexus") : path;
}

export function resolveHotCommandAction(rawCommand: string): HotCommandAction {
  const trimmed = rawCommand.trim();
  if (!trimmed) return { kind: "invalid", reason: "Command is empty" };

  const lower = trimmed.toLowerCase();
  if (lower === "palette" || lower === "command-palette" || lower === "cmd+k") {
    return { kind: "palette" };
  }

  if (trimmed.startsWith("#/")) {
    return { kind: "navigate", path: normalizeLegacyPath(trimmed.slice(1)) };
  }

  if (trimmed.startsWith("/")) {
    return { kind: "navigate", path: normalizeLegacyPath(trimmed) };
  }

  if (lower.startsWith("open ") || lower.startsWith("goto ")) {
    const parts = trimmed.split(/\s+/, 2);
    const target = parts[1]?.trim();
    if (!target) return { kind: "invalid", reason: "Target route is missing" };
    return { kind: "navigate", path: normalizeLegacyPath(ensurePath(target)) };
  }

  return { kind: "event", payload: trimmed };
}
