import { useState, useRef, useEffect, useCallback } from "react";
import {
  Shield,
  Terminal,
  FileCode,
  LayoutPanelTop,
  PanelBottom,
  PanelRight,
  RectangleHorizontal,
  Puzzle,
  ChevronRight,
  ChevronDown,
  AlertCircle,
} from "lucide-react";
import {
  usePlaygroundContributions,
  usePlaygroundErrors,
} from "@/lib/plugins/playground/playground-store";
import type { ContributionSnapshot } from "@/lib/plugins/playground/playground-store";

interface SectionConfig {
  key: keyof ContributionSnapshot;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
}

const SECTIONS: SectionConfig[] = [
  { key: "guards", label: "Guards", icon: Shield },
  { key: "commands", label: "Commands", icon: Terminal },
  { key: "fileTypes", label: "File Types", icon: FileCode },
  { key: "editorTabs", label: "Editor Tabs", icon: LayoutPanelTop },
  { key: "bottomPanelTabs", label: "Bottom Panel Tabs", icon: PanelBottom },
  { key: "rightSidebarPanels", label: "Right Sidebar Panels", icon: PanelRight },
  { key: "statusBarItems", label: "Status Bar Items", icon: RectangleHorizontal },
];

interface DiffHighlights {
  added: Set<string>;
  removed: Map<string, keyof ContributionSnapshot>;
}

function computeDiff(
  prev: ContributionSnapshot | null,
  current: ContributionSnapshot | null,
): DiffHighlights {
  const added = new Set<string>();
  const removed = new Map<string, keyof ContributionSnapshot>();

  if (!current) return { added, removed };

  for (const section of SECTIONS) {
    const prevItems = prev ? prev[section.key] : [];
    const currItems = current[section.key];
    const prevSet = new Set(prevItems);
    const currSet = new Set(currItems);

    for (const item of currItems) {
      if (!prevSet.has(item)) {
        added.add(`${section.key}::${item}`);
      }
    }
    for (const item of prevItems) {
      if (!currSet.has(item)) {
        removed.set(`${section.key}::${item}`, section.key);
      }
    }
  }

  return { added, removed };
}

function ContributionSection({
  config,
  items,
  isExpanded,
  onToggle,
  highlights,
}: {
  config: SectionConfig;
  items: string[];
  isExpanded: boolean;
  onToggle: () => void;
  highlights: DiffHighlights;
}) {
  const Icon = config.icon;

  return (
    <div className="mb-1">
      <button
        onClick={onToggle}
        className="flex items-center gap-1.5 w-full px-2 py-1 rounded text-xs font-medium
          hover:bg-[#1a1f2e] transition-colors text-[#c8d1e0]"
      >
        {isExpanded ? (
          <ChevronDown className="w-3 h-3 text-[#6f7f9a] shrink-0" />
        ) : (
          <ChevronRight className="w-3 h-3 text-[#6f7f9a] shrink-0" />
        )}
        <Icon className="w-3.5 h-3.5 text-[#6f7f9a] shrink-0" />
        <span>{config.label}</span>
        <span className="text-[#6f7f9a] ml-auto">({items.length})</span>
      </button>

      {isExpanded && (
        <ul className="ml-5 mt-0.5 space-y-0.5">
          {items.map((item) => {
            const itemKey = `${config.key}::${item}`;
            const isAdded = highlights.added.has(itemKey);

            return (
              <li
                key={item}
                className="flex items-center gap-1.5 text-xs text-[#c8d1e0] px-2 py-0.5 rounded bg-[#1a1f2e]/50"
              >
                {isAdded && (
                  <span className="w-1.5 h-1.5 rounded-full bg-[#4ade80] shrink-0" />
                )}
                <span className="truncate">{item}</span>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

function RemovedItemsList({
  highlights,
}: {
  highlights: DiffHighlights;
}) {
  if (highlights.removed.size === 0) return null;

  return (
    <div className="mb-2 px-2">
      <h4 className="text-[10px] font-semibold uppercase tracking-wider text-[#6f7f9a] mb-1">
        Removed
      </h4>
      <ul className="space-y-0.5">
        {Array.from(highlights.removed.entries()).map(([key, sectionKey]) => {
          const itemName = key.split("::")[1];
          return (
            <li
              key={key}
              className="flex items-center gap-1.5 text-xs text-[#c8d1e0]/50 px-2 py-0.5 rounded bg-[#1a0000]/30 line-through"
            >
              <span className="w-1.5 h-1.5 rounded-full bg-[#f87171] shrink-0" />
              <span className="truncate">{itemName}</span>
              <span className="text-[10px] text-[#6f7f9a] ml-auto">{sectionKey}</span>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

export function ContributionInspector() {
  const contributions = usePlaygroundContributions();
  const errors = usePlaygroundErrors();

  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());

  const prevContributionsRef = useRef<ContributionSnapshot | null>(null);
  const [highlights, setHighlights] = useState<DiffHighlights>({
    added: new Set(),
    removed: new Map(),
  });
  const highlightTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    const diff = computeDiff(prevContributionsRef.current, contributions);
    if (diff.added.size > 0 || diff.removed.size > 0) {
      setHighlights(diff);

      // Clear highlights after 2 seconds
      if (highlightTimerRef.current) {
        clearTimeout(highlightTimerRef.current);
      }
      highlightTimerRef.current = setTimeout(() => {
        setHighlights({ added: new Set(), removed: new Map() });
        highlightTimerRef.current = null;
      }, 2000);
    }

    prevContributionsRef.current = contributions;

    return () => {
      if (highlightTimerRef.current) {
        clearTimeout(highlightTimerRef.current);
      }
    };
  }, [contributions]);

  const toggleSection = useCallback((key: string) => {
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(key)) {
        next.delete(key);
      } else {
        next.add(key);
      }
      return next;
    });
  }, []);

  if (!contributions) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-[#6f7f9a] text-xs p-4 gap-3">
        <Puzzle className="w-8 h-8 opacity-50" />
        <span>Click Run to see contributions</span>
      </div>
    );
  }

  const activeSections = SECTIONS.filter(
    (s) => contributions[s.key].length > 0,
  );

  return (
    <div className="flex flex-col h-full overflow-y-auto bg-[#0f1219] text-[#c8d1e0]">
      {errors.length > 0 && (
        <div className="flex items-center gap-1.5 px-3 py-2 bg-[#1a0000]/60 border-b border-[#f87171]/20 text-xs text-[#f87171]">
          <AlertCircle className="w-3.5 h-3.5 shrink-0" />
          <span>
            {errors.length} error{errors.length !== 1 ? "s" : ""} during last
            run
          </span>
        </div>
      )}

      <div className="p-2">
        <h3 className="text-xs font-semibold mb-2 px-2 text-[#d4a84b]">
          Plugin Contributions
        </h3>

        <RemovedItemsList highlights={highlights} />

        {activeSections.length === 0 ? (
          <div className="text-xs text-[#6f7f9a] px-2 py-4 text-center">
            Plugin registered no contributions
          </div>
        ) : (
          activeSections.map((config) => (
            <ContributionSection
              key={config.key}
              config={config}
              items={contributions[config.key]}
              isExpanded={!collapsed.has(config.key)}
              onToggle={() => toggleSection(config.key)}
              highlights={highlights}
            />
          ))
        )}
      </div>
    </div>
  );
}

export default ContributionInspector;
