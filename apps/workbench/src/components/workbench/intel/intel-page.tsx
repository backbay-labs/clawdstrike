import { useState, useMemo, useCallback } from "react";

import {
  IconSearch,
  IconFilter,
  IconPlus,
  IconLayoutGrid,
  IconList,
  IconShieldCheck,
  IconVectorTriangle,
  IconBug,
  IconSpeakerphone,
  IconFileDescription,
  IconGitPullRequest,
  IconLock,
  IconUsers,
  IconWorld,
  IconDiamond,
  IconMoon,
  IconStar,
  IconKey,
  IconCrown,
  IconSpiral,
  IconWaveSine,
  IconEyeCheck,
  IconCheck,
  IconAlertTriangle,
  IconCircleDot,
  IconClock,
  IconTag,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import type {
  Intel,
  IntelType,
  IntelShareability,
} from "@/lib/workbench/sentinel-types";
import type { SigilType } from "@/lib/workbench/sentinel-manager";
import {
  INTEL_TYPE_LABELS,
  INTEL_TYPES,
  SHAREABILITY_LABELS,
} from "@/lib/workbench/intel-forge";

const TYPE_ICONS: Record<IntelType, typeof IconShieldCheck> = {
  detection_rule: IconShieldCheck,
  pattern: IconVectorTriangle,
  ioc: IconBug,
  campaign: IconSpeakerphone,
  advisory: IconFileDescription,
  policy_patch: IconGitPullRequest,
};

const TYPE_COLORS: Record<IntelType, string> = {
  detection_rule: "#5b8def",
  pattern: "#d4784b",
  ioc: "#c45c5c",
  campaign: "#8b5cf6",
  advisory: "#d4a84b",
  policy_patch: "#3dbf84",
};

const SHAREABILITY_ICONS: Record<IntelShareability, typeof IconLock> = {
  private: IconLock,
  swarm: IconUsers,
  public: IconWorld,
};

const SHAREABILITY_COLORS: Record<IntelShareability, string> = {
  private: "#6f7f9a",
  swarm: "#d4a84b",
  public: "#3dbf84",
};

const SIGIL_ICONS: Record<SigilType, typeof IconDiamond> = {
  diamond: IconDiamond,
  eye: IconEyeCheck,
  wave: IconWaveSine,
  crown: IconCrown,
  spiral: IconSpiral,
  key: IconKey,
  star: IconStar,
  moon: IconMoon,
};

type IntelTab = "local" | "swarm";
type ViewMode = "grid" | "list";
type TypeFilter = "all" | IntelType;

export interface IntelPageProps {
  localIntel: Intel[];
  swarmIntel?: Intel[];
  onCreateFromFinding?: () => void;
  onSelectIntel?: (intelId: string) => void;
}

function formatRelativeTime(timestamp: number): string {
  const delta = Date.now() - timestamp;
  const seconds = Math.floor(delta / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function truncateFingerprint(fp: string): string {
  if (fp.length <= 8) return fp;
  return `${fp.slice(0, 4)}...${fp.slice(-4)}`;
}

function ConfidenceMeter({ value }: { value: number }) {
  const pct = Math.round(value * 100);
  const color =
    pct >= 90
      ? "#3dbf84"
      : pct >= 70
        ? "#d4a84b"
        : pct >= 40
          ? "#d4784b"
          : "#c45c5c";

  return (
    <div className="flex items-center gap-1.5">
      <div className="w-16 h-1.5 rounded-full bg-[#2d3240] overflow-hidden">
        <div
          className="h-full rounded-full transition-all"
          style={{ width: `${pct}%`, backgroundColor: color }}
        />
      </div>
      <span className="text-[9px] font-mono" style={{ color }}>
        {pct}%
      </span>
    </div>
  );
}

function IntelTypeBadge({ type }: { type: IntelType }) {
  const Icon = TYPE_ICONS[type];
  const color = TYPE_COLORS[type];

  return (
    <span
      className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-mono font-medium"
      style={{
        color,
        backgroundColor: `${color}15`,
        border: `1px solid ${color}30`,
      }}
    >
      <Icon size={10} stroke={1.5} />
      {INTEL_TYPE_LABELS[type]}
    </span>
  );
}

function ShareabilityBadge({
  shareability,
}: {
  shareability: IntelShareability;
}) {
  const Icon = SHAREABILITY_ICONS[shareability];
  const color = SHAREABILITY_COLORS[shareability];

  return (
    <span
      className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-mono"
      style={{ color, backgroundColor: `${color}10` }}
    >
      <Icon size={9} stroke={1.5} />
      {SHAREABILITY_LABELS[shareability]}
    </span>
  );
}

function SignatureStatus({ intel }: { intel: Intel }) {
  const hasSignature = intel.signature.length > 0;
  return hasSignature ? (
    <span className="inline-flex items-center gap-1 text-[9px] font-mono text-[#3dbf84]">
      <IconCheck size={9} stroke={2} />
      Signed
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 text-[9px] font-mono text-[#d4a84b]">
      <IconAlertTriangle size={9} stroke={2} />
      Unsigned
    </span>
  );
}

function AuthorSigil({
  author,
  sigil,
}: {
  author: string;
  sigil?: SigilType;
}) {
  const SigilIcon = sigil ? SIGIL_ICONS[sigil] : IconCircleDot;
  return (
    <span className="inline-flex items-center gap-1 text-[9px] font-mono text-[#6f7f9a]">
      <SigilIcon size={10} stroke={1.5} className="text-[#d4a84b]" />
      {truncateFingerprint(author)}
    </span>
  );
}

function IntelCard({
  intel,
  onClick,
}: {
  intel: Intel;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className="w-full text-left rounded-xl border border-[#2d3240]/60 bg-[#0b0d13]/50 hover:border-[#d4a84b]/30 hover:bg-[#131721]/40 transition-colors p-4 group"
    >
      {/* Header: type badge + shareability */}
      <div className="flex items-start justify-between gap-2 mb-2">
        <IntelTypeBadge type={intel.type} />
        <ShareabilityBadge shareability={intel.shareability} />
      </div>

      {/* Title */}
      <h3 className="text-[13px] font-medium text-[#ece7dc] mb-1 line-clamp-2 group-hover:text-[#d4a84b] transition-colors">
        {intel.title}
      </h3>

      {/* Description */}
      <p className="text-[10px] text-[#6f7f9a] mb-3 line-clamp-2 leading-relaxed">
        {intel.description}
      </p>

      {/* Confidence */}
      <div className="mb-2">
        <ConfidenceMeter value={intel.confidence} />
      </div>

      {/* MITRE tags */}
      {intel.mitre.length > 0 && (
        <div className="flex flex-wrap gap-1 mb-2">
          {intel.mitre.slice(0, 3).map((m) => (
            <span
              key={m.techniqueId}
              className="px-1.5 py-0.5 rounded text-[8px] font-mono text-[#8b5cf6] bg-[#8b5cf6]/10 border border-[#8b5cf6]/20"
            >
              {m.techniqueId}
            </span>
          ))}
          {intel.mitre.length > 3 && (
            <span className="px-1.5 py-0.5 text-[8px] font-mono text-[#6f7f9a]">
              +{intel.mitre.length - 3}
            </span>
          )}
        </div>
      )}

      {/* Tags */}
      {intel.tags.length > 0 && (
        <div className="flex flex-wrap gap-1 mb-3">
          {intel.tags.slice(0, 4).map((tag) => (
            <span
              key={tag}
              className="px-1.5 py-0.5 rounded text-[8px] font-mono text-[#6f7f9a] bg-[#2d3240]/40"
            >
              {tag}
            </span>
          ))}
          {intel.tags.length > 4 && (
            <span className="px-1.5 py-0.5 text-[8px] font-mono text-[#6f7f9a]">
              +{intel.tags.length - 4}
            </span>
          )}
        </div>
      )}

      {/* Footer: author + signature + date */}
      <div className="flex items-center justify-between pt-2 border-t border-[#2d3240]/30">
        <AuthorSigil author={intel.author} />
        <div className="flex items-center gap-2">
          <SignatureStatus intel={intel} />
          <span className="text-[9px] font-mono text-[#6f7f9a]/60 flex items-center gap-1">
            <IconClock size={9} stroke={1.5} />
            {formatRelativeTime(intel.createdAt)}
          </span>
        </div>
      </div>
    </button>
  );
}

function IntelRow({
  intel,
  onClick,
}: {
  intel: Intel;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className="w-full flex items-center gap-3 px-4 py-3 rounded-lg border border-transparent hover:border-[#2d3240]/60 hover:bg-[#131721]/30 transition-colors group text-left"
    >
      {/* Type icon */}
      <div
        className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0"
        style={{
          backgroundColor: `${TYPE_COLORS[intel.type]}10`,
          border: `1px solid ${TYPE_COLORS[intel.type]}20`,
        }}
      >
        {(() => {
          const Icon = TYPE_ICONS[intel.type];
          return (
            <Icon
              size={14}
              stroke={1.5}
              style={{ color: TYPE_COLORS[intel.type] }}
            />
          );
        })()}
      </div>

      {/* Title + description */}
      <div className="flex-1 min-w-0">
        <p className="text-[12px] font-medium text-[#ece7dc] truncate group-hover:text-[#d4a84b] transition-colors">
          {intel.title}
        </p>
        <p className="text-[10px] text-[#6f7f9a] truncate">
          {intel.description}
        </p>
      </div>

      {/* Confidence */}
      <div className="shrink-0 hidden sm:block">
        <ConfidenceMeter value={intel.confidence} />
      </div>

      {/* Tags preview */}
      <div className="shrink-0 hidden md:flex items-center gap-1">
        {intel.tags.slice(0, 2).map((tag) => (
          <span
            key={tag}
            className="px-1.5 py-0.5 rounded text-[8px] font-mono text-[#6f7f9a] bg-[#2d3240]/40"
          >
            {tag}
          </span>
        ))}
      </div>

      {/* Shareability */}
      <div className="shrink-0">
        <ShareabilityBadge shareability={intel.shareability} />
      </div>

      {/* Signature + date */}
      <div className="shrink-0 flex items-center gap-2">
        <SignatureStatus intel={intel} />
        <span className="text-[9px] font-mono text-[#6f7f9a]/60 hidden lg:inline">
          {formatRelativeTime(intel.createdAt)}
        </span>
      </div>
    </button>
  );
}

function EmptyState({
  tab,
  onCreateFromFinding,
}: {
  tab: IntelTab;
  onCreateFromFinding?: () => void;
}) {
  return (
    <div className="rounded-xl border border-dashed border-[#2d3240]/60 bg-[#0b0d13]/30 px-8 py-14 text-center flex flex-col items-center">
      <div className="w-12 h-12 rounded-2xl bg-[#131721] border border-[#2d3240]/50 flex items-center justify-center mb-4">
        {tab === "local" ? (
          <IconShieldCheck
            size={20}
            className="text-[#6f7f9a]"
            stroke={1.5}
          />
        ) : (
          <IconUsers size={20} className="text-[#6f7f9a]" stroke={1.5} />
        )}
      </div>
      <p className="text-[13px] font-medium text-[#6f7f9a] mb-1">
        {tab === "local"
          ? "No local intel yet"
          : "No swarm intel received"}
      </p>
      <p className="text-[11px] text-[#6f7f9a]/60 max-w-[360px] leading-relaxed mb-4">
        {tab === "local"
          ? "Promote confirmed findings to create portable, signed intel artifacts that can be shared with your swarm."
          : "Join a swarm and configure your sentinels to receive shared detections, patterns, and IOC bundles from peers. This feature is coming in Phase 2."}
      </p>
      {tab === "local" && onCreateFromFinding && (
        <button
          onClick={onCreateFromFinding}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-[#d4a84b] bg-[#d4a84b]/10 border border-[#d4a84b]/20 rounded-md hover:bg-[#d4a84b]/20 transition-colors"
        >
          <IconPlus size={12} stroke={1.5} />
          Create from Finding
        </button>
      )}
    </div>
  );
}

export function IntelPage({
  localIntel,
  swarmIntel = [],
  onCreateFromFinding,
  onSelectIntel,
}: IntelPageProps) {
  const [activeTab, setActiveTab] = useState<IntelTab>("local");
  const [viewMode, setViewMode] = useState<ViewMode>("grid");
  const [typeFilter, setTypeFilter] = useState<TypeFilter>("all");
  const [tagFilter, setTagFilter] = useState("");
  const [search, setSearch] = useState("");

  // Compute unique tags from all intel
  const allTags = useMemo(() => {
    const tagSet = new Set<string>();
    const allItems = [...localIntel, ...swarmIntel];
    for (const item of allItems) {
      for (const tag of item.tags) {
        tagSet.add(tag);
      }
    }
    return Array.from(tagSet).sort();
  }, [localIntel, swarmIntel]);

  // Select items based on active tab
  const tabItems = activeTab === "local" ? localIntel : swarmIntel;

  // Apply filters
  const filteredIntel = useMemo(() => {
    return tabItems.filter((intel) => {
      // Type filter
      if (typeFilter !== "all" && intel.type !== typeFilter) return false;

      // Tag filter
      if (tagFilter && !intel.tags.includes(tagFilter)) return false;

      // Search
      if (search) {
        const q = search.toLowerCase();
        const haystack =
          `${intel.title} ${intel.description} ${intel.tags.join(" ")} ${intel.mitre.map((m) => `${m.techniqueId} ${m.techniqueName}`).join(" ")}`.toLowerCase();
        if (!haystack.includes(q)) return false;
      }

      return true;
    });
  }, [tabItems, typeFilter, tagFilter, search]);

  const handleSelectIntel = useCallback(
    (intelId: string) => {
      onSelectIntel?.(intelId);
    },
    [onSelectIntel],
  );

  return (
    <div className="p-6 max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 mb-6 flex-wrap">
        <div>
          <h1 className="font-syne font-bold text-xl text-[#ece7dc] mb-1">
            Intel Library
          </h1>
          <p className="text-sm text-[#6f7f9a]">
            Browse, create, and share signed intelligence artifacts.
          </p>
        </div>
        {onCreateFromFinding && (
          <button
            onClick={onCreateFromFinding}
            className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-[#ece7dc] bg-[#d4a84b]/20 border border-[#d4a84b]/30 rounded-md hover:bg-[#d4a84b]/30 transition-colors"
          >
            <IconPlus size={14} stroke={1.5} />
            Create from Finding
          </button>
        )}
      </div>

      {/* Tab switcher */}
      <div className="flex items-center justify-between gap-4 mb-6 border-b border-[#2d3240]/40 pb-px">
        <div className="flex items-center gap-1">
          <button
            onClick={() => setActiveTab("local")}
            className={cn(
              "flex items-center gap-1.5 px-4 py-2 text-sm font-medium rounded-t-md transition-colors -mb-px border-b-2",
              activeTab === "local"
                ? "text-[#ece7dc] border-[#d4a84b] bg-[#131721]/30"
                : "text-[#6f7f9a] border-transparent hover:text-[#ece7dc] hover:bg-[#131721]/20",
            )}
          >
            <IconShieldCheck size={15} stroke={1.5} />
            Local
            {localIntel.length > 0 && (
              <span className="ml-1 text-[10px] font-mono text-[#6f7f9a]">
                ({localIntel.length})
              </span>
            )}
          </button>
          <button
            onClick={() => setActiveTab("swarm")}
            className={cn(
              "flex items-center gap-1.5 px-4 py-2 text-sm font-medium rounded-t-md transition-colors -mb-px border-b-2",
              activeTab === "swarm"
                ? "text-[#ece7dc] border-[#d4a84b] bg-[#131721]/30"
                : "text-[#6f7f9a] border-transparent hover:text-[#ece7dc] hover:bg-[#131721]/20",
            )}
          >
            <IconUsers size={15} stroke={1.5} />
            Swarm
            {swarmIntel.length > 0 && (
              <span className="ml-1 text-[10px] font-mono text-[#6f7f9a]">
                ({swarmIntel.length})
              </span>
            )}
          </button>
        </div>

        {/* View mode toggle */}
        <div className="flex items-center gap-1">
          <button
            onClick={() => setViewMode("grid")}
            className={cn(
              "p-1.5 rounded-md transition-colors",
              viewMode === "grid"
                ? "text-[#ece7dc] bg-[#131721]"
                : "text-[#6f7f9a] hover:text-[#ece7dc]",
            )}
            title="Grid view"
          >
            <IconLayoutGrid size={14} stroke={1.5} />
          </button>
          <button
            onClick={() => setViewMode("list")}
            className={cn(
              "p-1.5 rounded-md transition-colors",
              viewMode === "list"
                ? "text-[#ece7dc] bg-[#131721]"
                : "text-[#6f7f9a] hover:text-[#ece7dc]",
            )}
            title="List view"
          >
            <IconList size={14} stroke={1.5} />
          </button>
        </div>
      </div>

      {/* Filter bar */}
      <div className="flex items-center gap-3 mb-6 flex-wrap">
        {/* Type filter */}
        <div className="flex items-center gap-1">
          <IconFilter size={12} stroke={1.5} className="text-[#6f7f9a]" />
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value as TypeFilter)}
            className="h-7 rounded-md border border-[#2d3240] bg-[#131721] px-2 text-[10px] font-mono text-[#ece7dc] outline-none focus:border-[#d4a84b]/50 transition-colors appearance-none cursor-pointer"
          >
            <option value="all">All Types</option>
            {INTEL_TYPES.map((t) => (
              <option key={t} value={t}>
                {INTEL_TYPE_LABELS[t]}
              </option>
            ))}
          </select>
        </div>

        {/* Tag filter */}
        {allTags.length > 0 && (
          <div className="flex items-center gap-1">
            <IconTag size={12} stroke={1.5} className="text-[#6f7f9a]" />
            <select
              value={tagFilter}
              onChange={(e) => setTagFilter(e.target.value)}
              className="h-7 rounded-md border border-[#2d3240] bg-[#131721] px-2 text-[10px] font-mono text-[#ece7dc] outline-none focus:border-[#d4a84b]/50 transition-colors appearance-none cursor-pointer"
            >
              <option value="">All Tags</option>
              {allTags.map((tag) => (
                <option key={tag} value={tag}>
                  {tag}
                </option>
              ))}
            </select>
          </div>
        )}

        {/* Search */}
        <div className="flex-1 min-w-[180px]">
          <div className="relative">
            <IconSearch
              size={12}
              stroke={1.5}
              className="absolute left-2.5 top-1/2 -translate-y-1/2 text-[#6f7f9a]"
            />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search intel..."
              className="h-7 w-full max-w-[280px] rounded-md border border-[#2d3240] bg-[#131721] pl-7 pr-2.5 text-[10px] font-mono text-[#ece7dc] placeholder:text-[#6f7f9a]/50 outline-none focus:border-[#d4a84b]/50 transition-colors"
            />
          </div>
        </div>

        {/* Count */}
        <span className="text-[10px] font-mono text-[#6f7f9a] shrink-0">
          {filteredIntel.length} artifact
          {filteredIntel.length !== 1 ? "s" : ""}
        </span>
      </div>

      {/* Content */}
      {filteredIntel.length === 0 ? (
        <EmptyState tab={activeTab} onCreateFromFinding={onCreateFromFinding} />
      ) : viewMode === "grid" ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filteredIntel.map((intel) => (
            <IntelCard
              key={intel.id}
              intel={intel}
              onClick={() => handleSelectIntel(intel.id)}
            />
          ))}
        </div>
      ) : (
        <div className="space-y-1">
          {filteredIntel.map((intel) => (
            <IntelRow
              key={intel.id}
              intel={intel}
              onClick={() => handleSelectIntel(intel.id)}
            />
          ))}
        </div>
      )}
    </div>
  );
}
