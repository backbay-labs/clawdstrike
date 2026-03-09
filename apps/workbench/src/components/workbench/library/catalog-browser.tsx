import { useState, useMemo, useCallback } from "react";
import { useWorkbench } from "@/lib/workbench/multi-policy-store";
import { yamlToPolicy } from "@/lib/workbench/yaml-utils";
import {
  POLICY_CATALOG,
  CATALOG_CATEGORIES,
  getCategoryColor,
  type CatalogEntry,
  type CatalogCategory,
  type CatalogDifficulty,
} from "@/lib/workbench/policy-catalog";
import { cn } from "@/lib/utils";
import {
  IconSearch,
  IconEye,
  IconDownload,
  IconGitFork,
  IconShieldCheck,
  IconLock,
  IconWorld,
  IconKey,
  IconFile,
  IconTerminal,
  IconPlugConnected,
  IconBrain,
  IconDeviceDesktop,
  IconAdjustments,
  IconSpider,
  IconStar,
  IconClock,
  IconFlame,
} from "@tabler/icons-react";
import { YamlViewDialog } from "./yaml-view-dialog";

// ---- Guard icon mapping ----

const GUARD_ICONS: Record<string, typeof IconShieldCheck> = {
  forbidden_path: IconLock,
  path_allowlist: IconFile,
  egress_allowlist: IconWorld,
  secret_leak: IconKey,
  shell_command: IconTerminal,
  patch_integrity: IconShieldCheck,
  mcp_tool: IconPlugConnected,
  prompt_injection: IconBrain,
  jailbreak: IconBrain,
  computer_use: IconDeviceDesktop,
  remote_desktop_side_channel: IconDeviceDesktop,
  input_injection_capability: IconAdjustments,
  spider_sense: IconSpider,
};

// ---- Sort options ----

type SortOption = "popularity" | "newest" | "difficulty";

function sortEntries(entries: CatalogEntry[], sort: SortOption): CatalogEntry[] {
  const sorted = [...entries];
  switch (sort) {
    case "popularity":
      sorted.sort((a, b) => b.popularity - a.popularity);
      break;
    case "newest":
      sorted.sort((a, b) => new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime());
      break;
    case "difficulty": {
      const order: Record<CatalogDifficulty, number> = { beginner: 0, intermediate: 1, advanced: 2 };
      sorted.sort((a, b) => order[a.difficulty] - order[b.difficulty]);
      break;
    }
  }
  return sorted;
}

// ---- Difficulty badge ----

function DifficultyBadge({ difficulty }: { difficulty: CatalogDifficulty }) {
  const config: Record<CatalogDifficulty, { label: string; bg: string; text: string; border: string }> = {
    beginner: {
      label: "Beginner",
      bg: "bg-[#3dbf84]/10",
      text: "text-[#3dbf84]",
      border: "border-[#3dbf84]/20",
    },
    intermediate: {
      label: "Intermediate",
      bg: "bg-[#d4a84b]/10",
      text: "text-[#d4a84b]",
      border: "border-[#d4a84b]/20",
    },
    advanced: {
      label: "Advanced",
      bg: "bg-[#c45c5c]/10",
      text: "text-[#c45c5c]",
      border: "border-[#c45c5c]/20",
    },
  };
  const c = config[difficulty];
  return (
    <span
      className={cn(
        "inline-flex items-center px-1.5 py-0.5 text-[9px] font-mono border rounded",
        c.bg,
        c.text,
        c.border,
      )}
    >
      {c.label}
    </span>
  );
}

// ---- Catalog card ----

interface CatalogCardProps {
  entry: CatalogEntry;
  onViewYaml: () => void;
  onUseTemplate: () => void;
  onFork: () => void;
}

function CatalogCard({ entry, onViewYaml, onUseTemplate, onFork }: CatalogCardProps) {
  const catColor = getCategoryColor(entry.category);
  const catLabel = CATALOG_CATEGORIES.find((c) => c.id === entry.category)?.label ?? entry.category;

  return (
    <div className="group flex flex-col justify-between rounded-xl border border-[#2d3240]/60 bg-[#0b0d13] p-4 min-h-[220px] hover:border-[#2d3240] hover:bg-[#0b0d13]/80 transition-all duration-200">
      {/* Top section */}
      <div>
        {/* Name + badges row */}
        <div className="flex items-start justify-between gap-2 mb-2">
          <h3 className="font-syne font-bold text-sm text-[#ece7dc] leading-tight">
            {entry.name}
          </h3>
          <div className="flex items-center gap-1 shrink-0">
            <span className="inline-flex items-center px-1.5 py-0.5 text-[9px] font-mono bg-[#131721] text-[#6f7f9a] border border-[#2d3240] rounded">
              v{entry.version}
            </span>
          </div>
        </div>

        {/* Category pill + difficulty */}
        <div className="flex items-center gap-1.5 mb-2.5">
          <span
            className="inline-flex items-center px-1.5 py-0.5 text-[9px] font-mono rounded border"
            style={{
              backgroundColor: `${catColor}10`,
              color: catColor,
              borderColor: `${catColor}33`,
            }}
          >
            {catLabel}
          </span>
          <DifficultyBadge difficulty={entry.difficulty} />
        </div>

        {/* Description */}
        <p className="text-xs text-[#6f7f9a] line-clamp-2 mb-3 leading-relaxed">
          {entry.description}
        </p>

        {/* Guard icons */}
        <div className="flex items-center gap-1 mb-2 flex-wrap">
          {entry.guardSummary.slice(0, 6).map((guard) => {
            const Icon = GUARD_ICONS[guard] ?? IconShieldCheck;
            return (
              <span
                key={guard}
                title={guard.replace(/_/g, " ")}
                className="inline-flex items-center justify-center w-5 h-5 rounded bg-[#131721] border border-[#2d3240]/50"
              >
                <Icon size={11} className="text-[#6f7f9a]" stroke={1.5} />
              </span>
            );
          })}
          {entry.guardSummary.length > 6 && (
            <span className="text-[9px] text-[#6f7f9a] ml-0.5">
              +{entry.guardSummary.length - 6}
            </span>
          )}
        </div>

        {/* Compliance badges */}
        {entry.compliance.length > 0 && (
          <div className="flex items-center gap-1 mb-2">
            {entry.compliance.map((c) => (
              <span
                key={c}
                className="inline-flex items-center px-1.5 py-0.5 text-[8px] font-mono font-bold bg-[#5b8def]/10 text-[#5b8def] border border-[#5b8def]/20 rounded uppercase tracking-wider"
              >
                {c}
              </span>
            ))}
          </div>
        )}

        {/* Use case tags */}
        <div className="flex items-center gap-1 flex-wrap">
          {entry.useCases.slice(0, 3).map((uc) => (
            <span
              key={uc}
              className="inline-flex items-center px-1.5 py-0.5 text-[9px] text-[#6f7f9a]/80 bg-[#131721]/50 rounded"
            >
              {uc}
            </span>
          ))}
        </div>
      </div>

      {/* Bottom section — author + actions */}
      <div className="mt-3 pt-3 border-t border-[#2d3240]/30">
        <div className="flex items-center justify-between">
          <span className="text-[10px] text-[#6f7f9a]/60">{entry.author}</span>
          <div className="flex items-center gap-1.5">
            <button
              onClick={onViewYaml}
              title="View YAML"
              className="flex items-center gap-1 px-2 py-1 rounded-md bg-[#131721] text-[#6f7f9a] text-[10px] font-medium hover:text-[#ece7dc] transition-colors"
            >
              <IconEye size={11} stroke={1.5} />
              YAML
            </button>
            <button
              onClick={onFork}
              title="Fork & Customize"
              className="flex items-center gap-1 px-2 py-1 rounded-md bg-[#131721] text-[#6f7f9a] text-[10px] font-medium hover:text-[#ece7dc] transition-colors"
            >
              <IconGitFork size={11} stroke={1.5} />
              Fork
            </button>
            <button
              onClick={onUseTemplate}
              title="Use Template"
              className="flex items-center gap-1 px-2 py-1 rounded-md bg-[#d4a84b]/10 text-[#d4a84b] text-[10px] font-medium hover:bg-[#d4a84b]/20 transition-colors"
            >
              <IconDownload size={11} stroke={1.5} />
              Use
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ---- Main catalog browser ----

export function CatalogBrowser() {
  const { loadPolicy } = useWorkbench();
  const [search, setSearch] = useState("");
  const [activeCategory, setActiveCategory] = useState<CatalogCategory | "all">("all");
  const [sort, setSort] = useState<SortOption>("popularity");
  const [viewYaml, setViewYaml] = useState<{ name: string; yaml: string } | null>(null);

  // Filter + sort entries
  const filteredEntries = useMemo(() => {
    let entries = POLICY_CATALOG;

    // Category filter
    if (activeCategory !== "all") {
      entries = entries.filter((e) => e.category === activeCategory);
    }

    // Search filter
    if (search.trim()) {
      const q = search.toLowerCase().trim();
      entries = entries.filter(
        (e) =>
          e.name.toLowerCase().includes(q) ||
          e.description.toLowerCase().includes(q) ||
          e.tags.some((t) => t.includes(q)) ||
          e.guardSummary.some((g) => g.includes(q)) ||
          e.useCases.some((u) => u.toLowerCase().includes(q)) ||
          e.compliance.some((c) => c.toLowerCase().includes(q)),
      );
    }

    return sortEntries(entries, sort);
  }, [activeCategory, search, sort]);

  const handleUseTemplate = useCallback(
    (entry: CatalogEntry) => {
      const [policy] = yamlToPolicy(entry.yaml);
      if (policy) {
        loadPolicy(policy);
      }
    },
    [loadPolicy],
  );

  const handleFork = useCallback(
    (entry: CatalogEntry) => {
      const [policy] = yamlToPolicy(entry.yaml);
      if (policy) {
        loadPolicy({
          ...policy,
          name: `${policy.name}-custom`,
          description: `Forked from "${entry.name}" template. ${policy.description}`,
        });
      }
    },
    [loadPolicy],
  );

  // Categories with counts
  const categoryCounts = useMemo(() => {
    const counts: Record<string, number> = { all: POLICY_CATALOG.length };
    for (const entry of POLICY_CATALOG) {
      counts[entry.category] = (counts[entry.category] ?? 0) + 1;
    }
    return counts;
  }, []);

  return (
    <div>
      {/* Search + Sort bar */}
      <div className="flex items-center gap-3 mb-5 flex-wrap">
        {/* Search */}
        <div className="relative flex-1 min-w-[200px]">
          <IconSearch
            size={14}
            className="absolute left-3 top-1/2 -translate-y-1/2 text-[#6f7f9a]"
            stroke={1.5}
          />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search templates by name, tag, guard, or compliance..."
            className="w-full pl-8 pr-3 py-2 rounded-lg bg-[#131721] border border-[#2d3240] text-[#ece7dc] text-xs placeholder:text-[#6f7f9a]/50 focus:outline-none focus:border-[#d4a84b]/40 transition-colors"
          />
        </div>

        {/* Sort selector */}
        <div className="flex items-center gap-1.5">
          {(
            [
              { value: "popularity", label: "Popular", icon: IconFlame },
              { value: "newest", label: "Newest", icon: IconClock },
              { value: "difficulty", label: "Difficulty", icon: IconStar },
            ] as const
          ).map(({ value, label, icon: SortIcon }) => (
            <button
              key={value}
              onClick={() => setSort(value)}
              className={cn(
                "flex items-center gap-1 px-2.5 py-1.5 rounded-md text-[10px] font-medium transition-colors",
                sort === value
                  ? "bg-[#d4a84b]/10 text-[#d4a84b] border border-[#d4a84b]/20"
                  : "bg-[#131721] text-[#6f7f9a] border border-[#2d3240] hover:text-[#ece7dc]",
              )}
            >
              <SortIcon size={11} stroke={1.5} />
              {label}
            </button>
          ))}
        </div>
      </div>

      {/* Category tabs */}
      <div className="flex items-center gap-1 mb-5 overflow-x-auto pb-1 scrollbar-thin">
        <button
          onClick={() => setActiveCategory("all")}
          className={cn(
            "flex items-center gap-1.5 px-3 py-1.5 rounded-md text-[11px] font-medium whitespace-nowrap transition-colors",
            activeCategory === "all"
              ? "bg-[#ece7dc]/10 text-[#ece7dc] border border-[#ece7dc]/20"
              : "bg-[#131721] text-[#6f7f9a] border border-[#2d3240] hover:text-[#ece7dc]",
          )}
        >
          All
          <span className="text-[9px] opacity-60">{categoryCounts.all}</span>
        </button>
        {CATALOG_CATEGORIES.map((cat) => {
          const count = categoryCounts[cat.id] ?? 0;
          if (count === 0) return null;
          return (
            <button
              key={cat.id}
              onClick={() => setActiveCategory(cat.id)}
              className={cn(
                "flex items-center gap-1.5 px-3 py-1.5 rounded-md text-[11px] font-medium whitespace-nowrap transition-colors",
                activeCategory === cat.id
                  ? "border"
                  : "bg-[#131721] text-[#6f7f9a] border border-[#2d3240] hover:text-[#ece7dc]",
              )}
              style={
                activeCategory === cat.id
                  ? {
                      backgroundColor: `${cat.color}15`,
                      color: cat.color,
                      borderColor: `${cat.color}33`,
                    }
                  : undefined
              }
            >
              {cat.label}
              <span className="text-[9px] opacity-60">{count}</span>
            </button>
          );
        })}
      </div>

      {/* Results grid */}
      {filteredEntries.length === 0 ? (
        <div className="rounded-xl border border-dashed border-[#2d3240]/60 bg-[#0b0d13]/30 px-8 py-14 text-center flex flex-col items-center">
          <div className="w-12 h-12 rounded-2xl bg-[#131721] border border-[#2d3240]/50 flex items-center justify-center mb-4">
            <IconSearch size={20} className="text-[#6f7f9a]" />
          </div>
          <p className="text-[13px] font-medium text-[#6f7f9a] mb-1">
            No templates found
          </p>
          <p className="text-[11px] text-[#6f7f9a]/60 max-w-[300px] leading-relaxed">
            Try adjusting your search terms or category filter
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {filteredEntries.map((entry) => (
            <CatalogCard
              key={entry.id}
              entry={entry}
              onViewYaml={() => setViewYaml({ name: entry.name, yaml: entry.yaml })}
              onUseTemplate={() => handleUseTemplate(entry)}
              onFork={() => handleFork(entry)}
            />
          ))}
        </div>
      )}

      {/* Results count */}
      {filteredEntries.length > 0 && (
        <p className="text-[10px] text-[#6f7f9a]/50 mt-4 text-center">
          Showing {filteredEntries.length} of {POLICY_CATALOG.length} templates
        </p>
      )}

      {/* YAML view dialog */}
      <YamlViewDialog
        open={viewYaml !== null}
        onClose={() => setViewYaml(null)}
        name={viewYaml?.name ?? ""}
        yaml={viewYaml?.yaml ?? ""}
      />
    </div>
  );
}
