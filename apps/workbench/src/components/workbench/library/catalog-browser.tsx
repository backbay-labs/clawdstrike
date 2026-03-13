import { useState, useEffect, useMemo, useCallback, useRef } from "react";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useWorkbench } from "@/lib/workbench/multi-policy-store";
import { yamlToPolicy, policyToYaml } from "@/lib/workbench/yaml-utils";
import { useFleetConnection } from "@/lib/workbench/use-fleet-connection";
import {
  POLICY_CATALOG,
  CATALOG_CATEGORIES,
  getCategoryColor,
  type CatalogEntry,
  type CatalogCategory,
  type CatalogDifficulty,
} from "@/lib/workbench/policy-catalog";
import {
  fetchCatalogTemplates,
  fetchCatalogCategories,
  publishCatalogTemplate,
  forkCatalogTemplate,
  type CatalogTemplate,
  type CatalogCategoryInfo,
} from "@/lib/workbench/fleet-client";
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
  IconCloud,
  IconCloudUpload,
  IconRefresh,
  IconLoader2,
  IconCheck,
  IconX,
  IconUser,
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

// ---- Unified entry type (local + remote) ----

interface UnifiedCatalogEntry extends CatalogEntry {
  /** Whether this entry came from the live fleet catalog. */
  source: "local" | "catalog";
  /** Remote catalog ID (only set for catalog entries). */
  catalogId?: string;
  /** Download count from the catalog backend. */
  downloads?: number;
}

/**
 * Adapt a backend CatalogTemplate to the unified entry shape.
 */
function templateToEntry(t: CatalogTemplate): UnifiedCatalogEntry {
  return {
    id: `catalog-${t.id}`,
    catalogId: t.id,
    name: t.name,
    description: t.description,
    category: (t.category || "general") as CatalogCategory,
    tags: t.tags ?? [],
    author: t.author ?? "Unknown",
    version: t.version ?? "1.0.0",
    yaml: t.yaml,
    guardSummary: t.guard_summary ?? [],
    useCases: t.use_cases ?? [],
    compliance: t.compliance ?? [],
    difficulty: (t.difficulty || "intermediate") as CatalogDifficulty,
    popularity: t.downloads ?? 0,
    downloads: t.downloads ?? 0,
    createdAt: t.created_at ?? new Date().toISOString(),
    updatedAt: t.updated_at ?? new Date().toISOString(),
    source: "catalog",
  };
}

/**
 * Wrap a local CatalogEntry as a UnifiedCatalogEntry.
 */
function localToEntry(e: CatalogEntry): UnifiedCatalogEntry {
  return { ...e, source: "local" };
}

function sortEntries(entries: UnifiedCatalogEntry[], sort: SortOption): UnifiedCatalogEntry[] {
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

// ---- Source badge ----

function SourceBadge({ source }: { source: "local" | "catalog" }) {
  if (source === "catalog") {
    return (
      <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 text-[9px] font-mono bg-[#5b8def]/10 text-[#5b8def] border border-[#5b8def]/20 rounded">
        <IconCloud size={9} stroke={1.5} />
        Catalog
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 text-[9px] font-mono bg-[#6f7f9a]/10 text-[#6f7f9a] border border-[#6f7f9a]/20 rounded">
      <IconFile size={9} stroke={1.5} />
      Local
    </span>
  );
}

// ---- Catalog card ----

interface CatalogCardProps {
  entry: UnifiedCatalogEntry;
  onViewYaml: () => void;
  onUseTemplate: () => void;
  onFork: () => void;
  forkingId?: string | null;
}

function CatalogCard({ entry, onViewYaml, onUseTemplate, onFork, forkingId }: CatalogCardProps) {
  const catColor = getCategoryColor(entry.category);
  const catLabel = CATALOG_CATEGORIES.find((c) => c.id === entry.category)?.label ?? entry.category;
  const isForking = forkingId === entry.catalogId;

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
            <SourceBadge source={entry.source} />
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

      {/* Bottom section -- author + metadata + actions */}
      <div className="mt-3 pt-3 border-t border-[#2d3240]/30">
        {/* Author + downloads row (catalog entries show extra metadata) */}
        <div className="flex items-center justify-between mb-2">
          <span className="flex items-center gap-1 text-[10px] text-[#6f7f9a]/60">
            <IconUser size={10} stroke={1.5} />
            {entry.author}
          </span>
          {entry.source === "catalog" && entry.downloads != null && (
            <span className="flex items-center gap-1 text-[10px] text-[#6f7f9a]/50">
              <IconDownload size={10} stroke={1.5} />
              {entry.downloads.toLocaleString()}
            </span>
          )}
        </div>
        {/* Actions */}
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
            disabled={isForking}
            title={entry.source === "catalog" ? "Fork from catalog" : "Fork & Customize"}
            className={cn(
              "flex items-center gap-1 px-2 py-1 rounded-md text-[10px] font-medium transition-colors",
              isForking
                ? "bg-[#131721] text-[#6f7f9a]/50 cursor-wait"
                : "bg-[#131721] text-[#6f7f9a] hover:text-[#ece7dc]",
            )}
          >
            {isForking ? (
              <IconLoader2 size={11} stroke={1.5} className="animate-spin" />
            ) : (
              <IconGitFork size={11} stroke={1.5} />
            )}
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
  );
}

// ---- Publish dialog ----

interface PublishDialogProps {
  open: boolean;
  onClose: () => void;
  onPublish: (meta: { name: string; description: string; category: string; tags: string[]; difficulty: string }) => void;
  publishing: boolean;
  publishError: string | null;
  publishSuccess: boolean;
  defaultName: string;
  defaultDescription: string;
}

function PublishDialog({
  open,
  onClose,
  onPublish,
  publishing,
  publishError,
  publishSuccess,
  defaultName,
  defaultDescription,
}: PublishDialogProps) {
  const [name, setName] = useState(defaultName);
  const [description, setDescription] = useState(defaultDescription);
  const [category, setCategory] = useState("general");
  const [tagsInput, setTagsInput] = useState("");
  const [difficulty, setDifficulty] = useState("intermediate");

  // Reset when dialog opens
  useEffect(() => {
    if (open) {
      setName(defaultName);
      setDescription(defaultDescription);
      setCategory("general");
      setTagsInput("");
      setDifficulty("intermediate");
    }
  }, [open, defaultName, defaultDescription]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="relative w-full max-w-md rounded-xl border border-[#2d3240] bg-[#0f1117] p-6 shadow-xl">
        <button
          onClick={onClose}
          className="absolute top-3 right-3 text-[#6f7f9a] hover:text-[#ece7dc] transition-colors"
        >
          <IconX size={16} stroke={1.5} />
        </button>

        <h3 className="font-syne font-bold text-base text-[#ece7dc] mb-1">
          Publish to Catalog
        </h3>
        <p className="text-[11px] text-[#6f7f9a] mb-5">
          Share your policy template with the fleet catalog.
        </p>

        {publishSuccess ? (
          <div className="flex flex-col items-center py-8">
            <div className="w-10 h-10 rounded-full bg-[#3dbf84]/10 flex items-center justify-center mb-3">
              <IconCheck size={20} className="text-[#3dbf84]" />
            </div>
            <p className="text-sm text-[#ece7dc] font-medium mb-1">Published successfully</p>
            <p className="text-[11px] text-[#6f7f9a]">Your template is now available in the catalog.</p>
            <button
              onClick={onClose}
              className="mt-4 px-4 py-1.5 text-xs rounded-md bg-[#131721] text-[#6f7f9a] hover:text-[#ece7dc] transition-colors"
            >
              Close
            </button>
          </div>
        ) : (
          <div className="space-y-3">
            <div>
              <label className="text-[10px] font-mono text-[#6f7f9a] mb-1 block">Name</label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="w-full px-3 py-1.5 rounded-md bg-[#131721] border border-[#2d3240] text-xs text-[#ece7dc] focus:outline-none focus:border-[#d4a84b]/40"
              />
            </div>
            <div>
              <label className="text-[10px] font-mono text-[#6f7f9a] mb-1 block">Description</label>
              <textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                rows={2}
                className="w-full px-3 py-1.5 rounded-md bg-[#131721] border border-[#2d3240] text-xs text-[#ece7dc] focus:outline-none focus:border-[#d4a84b]/40 resize-none"
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-[10px] font-mono text-[#6f7f9a] mb-1 block">Category</label>
                <Select
                  value={category}
                  onValueChange={(val) => setCategory(val as string)}
                >
                  <SelectTrigger className="w-full h-7 text-xs bg-[#131721] border-[#2d3240] text-[#ece7dc]">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-[#131721] border-[#2d3240]">
                    {CATALOG_CATEGORIES.map((c) => (
                      <SelectItem
                        key={c.id}
                        value={c.id}
                        className="text-xs text-[#ece7dc] focus:bg-[#2d3240] focus:text-[#ece7dc]"
                      >
                        {c.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <label className="text-[10px] font-mono text-[#6f7f9a] mb-1 block">Difficulty</label>
                <Select
                  value={difficulty}
                  onValueChange={(val) => setDifficulty(val as string)}
                >
                  <SelectTrigger className="w-full h-7 text-xs bg-[#131721] border-[#2d3240] text-[#ece7dc]">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-[#131721] border-[#2d3240]">
                    <SelectItem value="beginner" className="text-xs text-[#ece7dc] focus:bg-[#2d3240] focus:text-[#ece7dc]">Beginner</SelectItem>
                    <SelectItem value="intermediate" className="text-xs text-[#ece7dc] focus:bg-[#2d3240] focus:text-[#ece7dc]">Intermediate</SelectItem>
                    <SelectItem value="advanced" className="text-xs text-[#ece7dc] focus:bg-[#2d3240] focus:text-[#ece7dc]">Advanced</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div>
              <label className="text-[10px] font-mono text-[#6f7f9a] mb-1 block">Tags (comma-separated)</label>
              <input
                type="text"
                value={tagsInput}
                onChange={(e) => setTagsInput(e.target.value)}
                placeholder="security, agent, production"
                className="w-full px-3 py-1.5 rounded-md bg-[#131721] border border-[#2d3240] text-xs text-[#ece7dc] placeholder:text-[#6f7f9a]/40 focus:outline-none focus:border-[#d4a84b]/40"
              />
            </div>

            {publishError && (
              <div className="rounded-md bg-[#c45c5c]/10 border border-[#c45c5c]/20 px-3 py-2 text-[11px] text-[#c45c5c]">
                {publishError}
              </div>
            )}

            <div className="flex items-center gap-2 pt-1">
              <button
                onClick={onClose}
                className="px-3 py-1.5 text-xs rounded-md bg-[#131721] text-[#6f7f9a] hover:text-[#ece7dc] transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  const tags = tagsInput
                    .split(",")
                    .map((t) => t.trim())
                    .filter(Boolean);
                  onPublish({ name, description, category, tags, difficulty });
                }}
                disabled={publishing || !name.trim()}
                className={cn(
                  "flex items-center gap-1.5 px-4 py-1.5 text-xs font-medium rounded-md transition-colors",
                  publishing || !name.trim()
                    ? "bg-[#d4a84b]/5 text-[#d4a84b]/40 cursor-not-allowed"
                    : "bg-[#d4a84b]/10 text-[#d4a84b] hover:bg-[#d4a84b]/20",
                )}
              >
                {publishing ? (
                  <IconLoader2 size={12} stroke={1.5} className="animate-spin" />
                ) : (
                  <IconCloudUpload size={12} stroke={1.5} />
                )}
                {publishing ? "Publishing..." : "Publish"}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ---- Main catalog browser ----

export function CatalogBrowser() {
  const { state, loadPolicy } = useWorkbench();
  const { connection } = useFleetConnection();
  const isConnected = connection.connected;

  const [search, setSearch] = useState("");
  const [activeCategory, setActiveCategory] = useState<string>("all");
  const [sort, setSort] = useState<SortOption>("popularity");
  const [viewYaml, setViewYaml] = useState<{ name: string; yaml: string } | null>(null);

  // ---- Live catalog state ----
  const [catalogTemplates, setCatalogTemplates] = useState<CatalogTemplate[]>([]);
  const [catalogCategories, setCatalogCategories] = useState<CatalogCategoryInfo[]>([]);
  const [catalogLoading, setCatalogLoading] = useState(false);
  const [catalogError, setCatalogError] = useState<string | null>(null);
  const fetchIdRef = useRef(0);

  // ---- Publish state ----
  const [publishOpen, setPublishOpen] = useState(false);
  const [publishing, setPublishing] = useState(false);
  const [publishError, setPublishError] = useState<string | null>(null);
  const [publishSuccess, setPublishSuccess] = useState(false);

  // ---- Fork state ----
  const [forkingId, setForkingId] = useState<string | null>(null);

  // ---- Fetch live catalog when connected ----
  const loadCatalog = useCallback(async () => {
    if (!isConnected) return;
    const id = ++fetchIdRef.current;
    setCatalogLoading(true);
    setCatalogError(null);

    try {
      const [templates, categories] = await Promise.all([
        fetchCatalogTemplates(connection),
        fetchCatalogCategories(connection),
      ]);
      if (id !== fetchIdRef.current) return; // stale
      setCatalogTemplates(templates);
      setCatalogCategories(categories);
    } catch (e) {
      if (id !== fetchIdRef.current) return;
      setCatalogError(e instanceof Error ? e.message : "Failed to load catalog");
    } finally {
      if (id === fetchIdRef.current) {
        setCatalogLoading(false);
      }
    }
  }, [isConnected, connection]);

  useEffect(() => {
    loadCatalog();
  }, [loadCatalog]);

  // Clear remote state when disconnected
  useEffect(() => {
    if (!isConnected) {
      setCatalogTemplates([]);
      setCatalogCategories([]);
      setCatalogError(null);
    }
  }, [isConnected]);

  // ---- Build unified entries ----
  const allEntries = useMemo(() => {
    const local: UnifiedCatalogEntry[] = POLICY_CATALOG.map(localToEntry);
    const remote: UnifiedCatalogEntry[] = catalogTemplates.map(templateToEntry);

    // Deduplicate: if a remote template has the same name as a local one,
    // prefer the remote version but keep both accessible by prefixing IDs
    const localNames = new Set(local.map((e) => e.name.toLowerCase()));
    const deduped = remote.filter((r) => !localNames.has(r.name.toLowerCase()));

    return [...local, ...deduped];
  }, [catalogTemplates]);

  // ---- Merge categories (local static + remote live) ----
  const mergedCategories = useMemo(() => {
    // Start with the local static categories
    const cats = [...CATALOG_CATEGORIES];

    // Add any remote-only categories
    for (const rc of catalogCategories) {
      if (!cats.find((c) => c.id === rc.id)) {
        cats.push({ id: rc.id as CatalogCategory, label: rc.label, color: rc.color });
      }
    }
    return cats;
  }, [catalogCategories]);

  // ---- Category counts ----
  const categoryCounts = useMemo(() => {
    const counts: Record<string, number> = { all: allEntries.length };
    for (const entry of allEntries) {
      counts[entry.category] = (counts[entry.category] ?? 0) + 1;
    }
    return counts;
  }, [allEntries]);

  // ---- Filter + sort entries ----
  const filteredEntries = useMemo(() => {
    let entries = allEntries;

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
          e.compliance.some((c) => c.toLowerCase().includes(q)) ||
          e.author.toLowerCase().includes(q),
      );
    }

    return sortEntries(entries, sort);
  }, [allEntries, activeCategory, search, sort]);

  const handleUseTemplate = useCallback(
    (entry: UnifiedCatalogEntry) => {
      const [policy] = yamlToPolicy(entry.yaml);
      if (policy) {
        loadPolicy(policy);
      }
    },
    [loadPolicy],
  );

  const handleFork = useCallback(
    async (entry: UnifiedCatalogEntry) => {
      // For catalog entries, try server-side fork first
      if (entry.source === "catalog" && entry.catalogId && isConnected) {
        setForkingId(entry.catalogId);
        try {
          const result = await forkCatalogTemplate(connection, entry.catalogId);
          if (result.success && result.template) {
            const [policy] = yamlToPolicy(result.template.yaml);
            if (policy) {
              loadPolicy(policy);
              // Refresh catalog to show the new forked template
              loadCatalog();
              return;
            }
          }
        } catch {
          // Fall through to client-side fork
        } finally {
          setForkingId(null);
        }
      }

      // Client-side fork fallback
      const [policy] = yamlToPolicy(entry.yaml);
      if (policy) {
        loadPolicy({
          ...policy,
          name: `${policy.name}-custom`,
          description: `Forked from "${entry.name}" template. ${policy.description}`,
        });
      }
    },
    [isConnected, connection, loadPolicy, loadCatalog],
  );

  // ---- Publish handler ----
  const handlePublish = useCallback(
    async (meta: { name: string; description: string; category: string; tags: string[]; difficulty: string }) => {
      if (!isConnected) return;
      setPublishing(true);
      setPublishError(null);
      setPublishSuccess(false);

      try {
        const yaml = policyToYaml(state.activePolicy);
        const result = await publishCatalogTemplate(connection, {
          name: meta.name,
          description: meta.description,
          category: meta.category,
          tags: meta.tags,
          yaml,
          difficulty: meta.difficulty,
        });

        if (result.success) {
          setPublishSuccess(true);
          // Refresh catalog to show the new template
          loadCatalog();
        } else {
          setPublishError(result.error ?? "Publishing failed");
        }
      } catch (e) {
        setPublishError(e instanceof Error ? e.message : "Publishing failed");
      } finally {
        setPublishing(false);
      }
    },
    [isConnected, connection, state.activePolicy, loadCatalog],
  );

  const totalLocal = POLICY_CATALOG.length;
  const totalRemote = catalogTemplates.length;
  const liveCatalogReady = isConnected && !catalogError;

  return (
    <div>
      {/* Fleet connection status bar + Publish button */}
      <div className="flex items-center justify-between gap-3 mb-4 flex-wrap">
        <div className="flex items-center gap-2">
          {liveCatalogReady ? (
            <span className="flex items-center gap-1.5 text-[10px] font-mono text-[#3dbf84]">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#3dbf84] opacity-40" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-[#3dbf84]" />
              </span>
              Live catalog connected
              {totalRemote > 0 && (
                <span className="text-[#6f7f9a]">
                  ({totalRemote} remote template{totalRemote !== 1 ? "s" : ""})
                </span>
              )}
            </span>
          ) : isConnected ? (
            <span className="flex items-center gap-1.5 text-[10px] font-mono text-[#d4a84b]">
              <span className="inline-flex rounded-full h-2 w-2 bg-[#d4a84b]" />
              Live catalog unavailable
            </span>
          ) : (
            <span className="flex items-center gap-1.5 text-[10px] font-mono text-[#6f7f9a]">
              <span className="inline-flex rounded-full h-2 w-2 bg-[#6f7f9a]/40" />
              Showing local templates only
            </span>
          )}
          {catalogLoading && (
            <IconLoader2 size={12} className="text-[#d4a84b] animate-spin" stroke={1.5} />
          )}
          {catalogError && (
            <span className="text-[10px] text-[#c45c5c]" title={catalogError}>
              Catalog fetch failed
            </span>
          )}
        </div>

        <div className="flex items-center gap-2">
          {isConnected && (
            <>
              <button
                onClick={loadCatalog}
                disabled={catalogLoading}
                title="Refresh catalog"
                className="flex items-center gap-1 px-2 py-1 rounded-md bg-[#131721] text-[#6f7f9a] text-[10px] font-medium hover:text-[#ece7dc] transition-colors disabled:opacity-50"
              >
                <IconRefresh size={11} stroke={1.5} className={catalogLoading ? "animate-spin" : ""} />
                Refresh
              </button>
              <button
                onClick={() => {
                  setPublishOpen(true);
                  setPublishError(null);
                  setPublishSuccess(false);
                }}
                className="flex items-center gap-1 px-3 py-1 rounded-md bg-[#d4a84b]/10 text-[#d4a84b] text-[10px] font-medium hover:bg-[#d4a84b]/20 transition-colors"
              >
                <IconCloudUpload size={11} stroke={1.5} />
                Publish to Catalog
              </button>
            </>
          )}
        </div>
      </div>

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
            placeholder="Search templates by name, tag, guard, author, or compliance..."
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
        {mergedCategories.map((cat) => {
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
              forkingId={forkingId}
            />
          ))}
        </div>
      )}

      {/* Results count */}
      {filteredEntries.length > 0 && (
        <p className="text-[10px] text-[#6f7f9a]/50 mt-4 text-center">
          Showing {filteredEntries.length} of {allEntries.length} templates
          {isConnected && totalRemote > 0 && (
            <span> ({totalLocal} local + {totalRemote} catalog)</span>
          )}
        </p>
      )}

      {/* Publish dialog */}
      <PublishDialog
        open={publishOpen}
        onClose={() => setPublishOpen(false)}
        onPublish={handlePublish}
        publishing={publishing}
        publishError={publishError}
        publishSuccess={publishSuccess}
        defaultName={state.activePolicy.name}
        defaultDescription={state.activePolicy.description}
      />

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
