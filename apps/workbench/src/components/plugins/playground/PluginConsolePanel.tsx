import { useState, useRef, useEffect } from "react";
import {
  Info,
  AlertTriangle,
  XCircle,
  MessageSquare,
  Terminal,
  Trash2,
} from "lucide-react";
import {
  usePlaygroundConsole,
  clearConsole,
} from "@/lib/plugins/playground/playground-store";
import { formatConsoleTimestamp } from "@/lib/plugins/console/format-console-timestamp";
import type { ConsoleEntry } from "@/lib/plugins/playground/playground-store";

type LogLevel = ConsoleEntry["level"];

interface LevelConfig {
  level: LogLevel;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  color: string;
  textClass: string;
}

const LEVEL_CONFIGS: LevelConfig[] = [
  {
    level: "log",
    label: "Log",
    icon: MessageSquare,
    color: "#c8d1e0",
    textClass: "text-[#c8d1e0]",
  },
  {
    level: "info",
    label: "Info",
    icon: Info,
    color: "#60a5fa",
    textClass: "text-[#60a5fa]",
  },
  {
    level: "warn",
    label: "Warn",
    icon: AlertTriangle,
    color: "#fbbf24",
    textClass: "text-[#fbbf24]",
  },
  {
    level: "error",
    label: "Error",
    icon: XCircle,
    color: "#f87171",
    textClass: "text-[#f87171]",
  },
];

function stringifyArg(arg: unknown): string {
  if (typeof arg === "string") return arg;
  if (arg === null) return "null";
  if (arg === undefined) return "undefined";
  try {
    return JSON.stringify(arg, null, 2);
  } catch {
    return String(arg);
  }
}

function stringifyArgs(args: unknown[]): string {
  return args.map(stringifyArg).join(" ");
}

function getLevelConfig(level: LogLevel): LevelConfig {
  return LEVEL_CONFIGS.find((c) => c.level === level) ?? LEVEL_CONFIGS[0];
}

function FilterToggle({
  config,
  count,
  isActive,
  onToggle,
}: {
  config: LevelConfig;
  count: number;
  isActive: boolean;
  onToggle: () => void;
}) {
  const Icon = config.icon;

  return (
    <button
      onClick={onToggle}
      className={`flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium transition-colors border ${
        isActive
          ? "border-current bg-current/10"
          : "border-[#2a3142] text-[#6f7f9a] opacity-50 hover:opacity-75"
      }`}
      style={isActive ? { color: config.color } : undefined}
      title={`${isActive ? "Hide" : "Show"} ${config.label} entries`}
    >
      <Icon className="w-3 h-3" />
      <span>
        {config.label} ({count})
      </span>
    </button>
  );
}

function ConsoleEntryRow({ entry }: { entry: ConsoleEntry }) {
  const config = getLevelConfig(entry.level);
  const Icon = config.icon;

  return (
    <div
      className={`flex items-start gap-2 px-2 py-1 border-b border-[#2a3142]/50 font-mono text-xs ${config.textClass}`}
    >
      <Icon className={`w-3.5 h-3.5 shrink-0 mt-0.5 ${config.textClass}`} />
      <span className="text-[#6f7f9a] shrink-0 tabular-nums">
        {formatConsoleTimestamp(entry.timestamp)}
      </span>
      <span className="whitespace-pre-wrap break-all">
        {stringifyArgs(entry.args)}
      </span>
    </div>
  );
}

export function PluginConsolePanel() {
  const entries = usePlaygroundConsole();
  const [activeFilters, setActiveFilters] = useState<Set<string>>(
    () => new Set(["log", "info", "warn", "error"]),
  );

  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = scrollRef.current;
    if (el) {
      el.scrollTo({ top: el.scrollHeight, behavior: "smooth" });
    }
  }, [entries]);

  const toggleFilter = (level: string) => {
    setActiveFilters((prev) => {
      const next = new Set(prev);
      if (next.has(level)) {
        next.delete(level);
      } else {
        next.add(level);
      }
      return next;
    });
  };

  const counts: Record<string, number> = { log: 0, info: 0, warn: 0, error: 0 };
  for (const entry of entries) {
    counts[entry.level] = (counts[entry.level] ?? 0) + 1;
  }

  const filteredEntries = entries.filter((e) => activeFilters.has(e.level));

  if (entries.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-[#6f7f9a] text-xs p-4 gap-3 bg-[#0d1117]">
        <Terminal className="w-8 h-8 opacity-50" />
        <span>No console output yet</span>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full bg-[#0d1117]">
      <div className="flex items-center gap-1.5 px-2 py-1 border-b border-[#2a3142] shrink-0">
        {LEVEL_CONFIGS.map((config) => (
          <FilterToggle
            key={config.level}
            config={config}
            count={counts[config.level] ?? 0}
            isActive={activeFilters.has(config.level)}
            onToggle={() => toggleFilter(config.level)}
          />
        ))}

        <div className="flex-1" />

        <button
          onClick={() => clearConsole()}
          className="flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium
            text-[#6f7f9a] hover:text-[#c8d1e0] hover:bg-[#2a3142] transition-colors"
          title="Clear console"
        >
          <Trash2 className="w-3 h-3" />
          Clear
        </button>
      </div>

      <div ref={scrollRef} className="flex-1 overflow-y-auto min-h-0">
        {filteredEntries.length === 0 ? (
          <div className="flex items-center justify-center h-full text-[#6f7f9a] text-xs p-4">
            No entries match current filters
          </div>
        ) : (
          filteredEntries.map((entry, i) => (
            <ConsoleEntryRow key={i} entry={entry} />
          ))
        )}
      </div>
    </div>
  );
}

export default PluginConsolePanel;
