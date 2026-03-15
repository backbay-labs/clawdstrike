import { useState, useCallback, useMemo, useEffect } from "react";
import { motion } from "motion/react";
import {
  Collapsible,
  CollapsibleTrigger,
  CollapsibleContent,
} from "@/components/ui/collapsible";
import { Switch } from "@/components/ui/switch";
import { VerdictBadge } from "@/components/workbench/shared/verdict-badge";
import { GuardConfigFields } from "@/components/workbench/editor/guard-config-fields";
import { TrustprintThresholdTuner } from "@/components/workbench/editor/trustprint-threshold-tuner";
import { TrustprintPatternExplorer } from "@/components/workbench/editor/trustprint-pattern-explorer";
import { TrustprintProviderWizard } from "@/components/workbench/editor/trustprint-provider-wizard";
import {
  S2BENCH_PATTERNS,
  type PatternEntry,
  computeCoverageStats,
} from "@/lib/workbench/trustprint-patterns";
import { useGuardProvenance } from "@/components/workbench/editor/inheritance-chain";
import { useWorkbench } from "@/lib/workbench/multi-policy-store";
import { GUARD_REGISTRY } from "@/lib/workbench/guard-registry";
import { useGuardTestStatus, useTestRunnerOptional } from "@/lib/workbench/test-store";
import { generateScenariosFromPolicy } from "@/lib/workbench/scenario-generator";
import type { SuiteScenario } from "@/lib/workbench/suite-parser";
import type { GuardId, GuardConfigMap, TestScenario } from "@/lib/workbench/types";
import { cn } from "@/lib/utils";
import {
  IconLock,
  IconShieldCheck,
  IconNetwork,
  IconEye,
  IconFileCheck,
  IconTerminal,
  IconTool,
  IconBrain,
  IconSkull,
  IconDeviceDesktop,
  IconPlugConnected,
  IconKeyboard,
  IconSpider,
  IconFingerprint,
  IconChevronDown,
  IconChevronUp,
  IconAlertTriangle,
  IconGripVertical,
  IconDatabase,
  IconCircleCheck,
} from "@tabler/icons-react";

/** Keys handled by custom spider_sense UI — excluded from the generic Advanced section. */
const SPIDER_SENSE_HANDLED_KEYS = new Set([
  "similarity_threshold",
  "ambiguity_band",
  "pattern_db_path",
  "embedding_model",
  "embedding_api_url",
  "embedding_api_key",
]);


function TrustprintProfileCard({
  patterns,
  profilePath,
}: {
  patterns: PatternEntry[];
  profilePath: string;
}) {
  const stats = useMemo(() => computeCoverageStats(patterns), [patterns]);
  const dims = patterns[0]?.embedding.length ?? 0;
  const isBuiltin = profilePath.startsWith("builtin:");

  return (
    <div className="border border-[#2d3240] rounded-lg overflow-hidden">
      {/* Selected profile */}
      <div className="flex items-start gap-2.5 px-3 py-2.5 bg-[#131721]/40">
        <IconDatabase size={14} stroke={1.5} className="text-[#d4a84b] shrink-0 mt-0.5" />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-[11px] font-mono font-medium text-[#ece7dc]">
              {isBuiltin ? "S2Bench v1 Baseline" : profilePath}
            </span>
            {isBuiltin && (
              <span className="px-1.5 py-0 text-[8px] font-mono text-[#6f7f9a] bg-[#6f7f9a]/10 border border-[#6f7f9a]/20 rounded">
                built-in
              </span>
            )}
          </div>
          {isBuiltin ? (
            <p className="text-[9px] text-[#6f7f9a]/70 mt-0.5 leading-relaxed">
              Research baseline covering 9 attack categories across 4 agent lifecycle stages.
              Based on the S2Bench threat taxonomy (Yu et al. 2026).
            </p>
          ) : (
            <p className="text-[9px] text-[#6f7f9a]/70 mt-0.5 leading-relaxed">
              Custom pattern database loaded from local path.
            </p>
          )}
        </div>
      </div>

      {/* Stats row */}
      <div className="flex items-center gap-3 px-3 py-2 border-t border-[#2d3240]/50 bg-[#0b0d13]/50">
        <span className="text-[9px] font-mono text-[#6f7f9a]">
          {patterns.length} patterns
        </span>
        <span className="text-[9px] font-mono text-[#6f7f9a]/30">|</span>
        <span className="text-[9px] font-mono text-[#6f7f9a]">
          {dims}-dim embeddings
        </span>
        <span className="text-[9px] font-mono text-[#6f7f9a]/30">|</span>
        {stats.gapCount === 0 ? (
          <span className="inline-flex items-center gap-1 text-[9px] font-mono text-[#3dbf84]">
            <IconCircleCheck size={10} stroke={1.5} />
            Full coverage
          </span>
        ) : (
          <span className="inline-flex items-center gap-1 text-[9px] font-mono text-[#c45c5c]">
            <IconAlertTriangle size={10} stroke={1.5} />
            {stats.gapCount} gap{stats.gapCount !== 1 ? "s" : ""}
          </span>
        )}
      </div>

      {/* Custom profile note */}
      <div className="px-3 py-2 border-t border-[#2d3240]/50 bg-[#0b0d13]/30">
        <p className="text-[8px] font-mono text-[#6f7f9a]/40 leading-relaxed">
          Custom profiles: set <code className="text-[#6f7f9a]/60">pattern_db_path</code> to a JSON
          file path containing pattern entries with embeddings matching your embedding model's dimensions.
        </p>
      </div>
    </div>
  );
}

const ICON_MAP: Record<string, typeof IconLock> = {
  IconLock,
  IconShieldCheck,
  IconNetwork,
  IconEye,
  IconFileCheck,
  IconTerminal,
  IconTool,
  IconBrain,
  IconSkull,
  IconDeviceDesktop,
  IconPlugConnected,
  IconKeyboard,
  IconSpider,
  IconFingerprint,
};


const TEST_STATUS_DOT: Record<string, { color: string; tip: string } | null> = {
  pass: { color: "#3dbf84", tip: "All tests pass" },
  fail: { color: "#c45c5c", tip: "Tests failing" },
  warn: { color: "#d4a84b", tip: "Tests have warnings" },
  none: null,
};


function extractTarget(s: TestScenario): string {
  const p = s.payload;
  if (typeof p.path === "string") return p.path;
  if (typeof p.host === "string") return p.host;
  if (typeof p.command === "string") return p.command;
  if (typeof p.tool === "string") return p.tool;
  if (typeof p.text === "string") return p.text.slice(0, 120);
  return JSON.stringify(p).slice(0, 120);
}

function testScenarioToSuite(s: TestScenario): SuiteScenario {
  const suite: SuiteScenario = {
    id: s.id,
    name: s.name,
    action: s.actionType,
    target: extractTarget(s),
    description: s.description,
  };
  if (s.expectedVerdict) suite.expect = s.expectedVerdict;
  if (typeof s.payload.content === "string") suite.content = s.payload.content;
  if (s.category) suite.tags = [s.category];
  return suite;
}

/** Fields that contain secrets and should be masked in summaries and displays. */
const SENSITIVE_CONFIG_KEYS = new Set(["embedding_api_key"]);

function maskSensitiveValue(value: string): string {
  if (value.length <= 4) return "****";
  return `${value.slice(0, 4)}${"*".repeat(Math.min(value.length - 4, 12))}`;
}

function getGuardSummary(guardId: GuardId, config: Record<string, unknown>): string {
  const parts: string[] = [];

  // Count list-type fields
  for (const [key, val] of Object.entries(config)) {
    if (key === "enabled") continue;
    if (Array.isArray(val)) {
      parts.push(`${val.length} ${key.replace(/_/g, " ")}`);
    } else if (typeof val === "object" && val !== null) {
      // Nested config like detector
      const nested = val as Record<string, unknown>;
      for (const [nk, nv] of Object.entries(nested)) {
        if (typeof nv === "number") {
          parts.push(`${nk.replace(/_/g, " ")}: ${nv}`);
        }
      }
    } else if (typeof val === "number") {
      parts.push(`${key.replace(/_/g, " ")}: ${val}`);
    } else if (typeof val === "string" && key !== "enabled") {
      // Mask sensitive values like API keys
      const displayVal = SENSITIVE_CONFIG_KEYS.has(key) ? maskSensitiveValue(val) : val;
      parts.push(`${key.replace(/_/g, " ")}: ${displayVal}`);
    }
  }

  return parts.length > 0 ? parts.join(", ") : "default configuration";
}

interface GuardCardProps {
  guardId: GuardId;
  /** Enable reorder controls (up/down buttons, drag handle). Only shown in custom view. */
  reorderable?: boolean;
  /** Whether this is the first item (disables move-up). */
  isFirst?: boolean;
  /** Whether this is the last item (disables move-down). */
  isLast?: boolean;
  onMoveUp?: () => void;
  onMoveDown?: () => void;
  /** HTML5 drag-and-drop handlers for reordering. */
  onDragStart?: (e: React.DragEvent<HTMLDivElement>) => void;
  onDragOver?: (e: React.DragEvent<HTMLDivElement>) => void;
  onDragEnd?: (e: React.DragEvent<HTMLDivElement>) => void;
  onDrop?: (e: React.DragEvent<HTMLDivElement>) => void;
  onDragLeave?: (e: React.DragEvent<HTMLDivElement>) => void;
  /** Whether this card is currently being dragged. */
  isDragging?: boolean;
  /** Drop position indicator: "above" or "below". */
  dropIndicator?: "above" | "below" | null;
}

const PROVENANCE_BADGE_STYLES: Record<string, string> = {
  inherited: "bg-[#6f7f9a]/10 text-[#6f7f9a] border-[#6f7f9a]/20",
  overridden: "bg-[#d4a84b]/10 text-[#d4a84b] border-[#d4a84b]/20",
  added: "bg-[#3dbf84]/10 text-[#3dbf84] border-[#3dbf84]/20",
  removed: "bg-[#c45c5c]/10 text-[#c45c5c] border-[#c45c5c]/20",
};

export function GuardCard({
  guardId,
  reorderable,
  isFirst,
  isLast,
  onMoveUp,
  onMoveDown,
  onDragStart,
  onDragOver,
  onDragEnd,
  onDrop,
  onDragLeave,
  isDragging,
  dropIndicator,
}: GuardCardProps) {
  const { state, dispatch } = useWorkbench();
  const [open, setOpen] = useState(false);
  const provenanceInfo = useGuardProvenance(guardId);

  // Regression dot
  const testStatus = useGuardTestStatus(guardId);
  const dotInfo = TEST_STATUS_DOT[testStatus];

  // Coverage-based "untested" badge (Gap 4)
  const testRunner = useTestRunnerOptional();
  const isUntested = useMemo(() => {
    if (!testRunner?.state.coverageReport) return false;
    const guardCoverage = testRunner.state.coverageReport.guards.find(
      (g) => g.guardId === guardId,
    );
    return guardCoverage?.status === "uncovered";
  }, [testRunner?.state.coverageReport, guardId]);

  // Context menu
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number } | null>(null);

  useEffect(() => {
    if (!contextMenu) return;
    const close = () => setContextMenu(null);
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") close();
    };
    window.addEventListener("click", close);
    window.addEventListener("keydown", onKeyDown);
    window.addEventListener("scroll", close, true);
    return () => {
      window.removeEventListener("click", close);
      window.removeEventListener("keydown", onKeyDown);
      window.removeEventListener("scroll", close, true);
    };
  }, [contextMenu]);

  const meta = GUARD_REGISTRY.find((g) => g.id === guardId);
  if (!meta) return null;

  const guardConfig = (state.activePolicy.guards[guardId] ?? {}) as Record<string, unknown>;
  const enabled = (guardConfig.enabled as boolean | undefined) ?? false;

  const Icon = ICON_MAP[meta.icon] ?? IconLock;

  // Per-guard native validation errors from the Rust engine
  const nativeErrors = state.nativeValidation.guardErrors[guardId] ?? [];
  const hasNativeErrors = nativeErrors.length > 0;

  const summary = useMemo(
    () => getGuardSummary(guardId, guardConfig),
    [guardId, guardConfig]
  );

  const handleToggle = useCallback(
    (checked: boolean | React.FormEvent<HTMLButtonElement>) => {
      const isEnabled = typeof checked === "boolean" ? checked : !enabled;
      dispatch({ type: "TOGGLE_GUARD", guardId, enabled: isEnabled });
    },
    [dispatch, guardId, enabled]
  );

  const handleConfigChange = useCallback(
    (key: string, value: unknown) => {
      // Handle nested keys like "detector.block_threshold" or "detector.layers.heuristic"
      const parts = key.split(".");
      if (parts.length === 1) {
        dispatch({
          type: "UPDATE_GUARD",
          guardId,
          config: { [key]: value } as Partial<GuardConfigMap[GuardId]>,
        });
      } else {
        // Build nested update — supports 2 or 3 levels of nesting
        const [topKey, ...rest] = parts;
        const existing =
          (guardConfig[topKey] as Record<string, unknown> | undefined) ?? {};
        const nested: Record<string, unknown> = { ...existing };
        if (rest.length === 1) {
          nested[rest[0]] = value;
        } else if (rest.length === 2) {
          const subExisting =
            (nested[rest[0]] as Record<string, unknown> | undefined) ?? {};
          nested[rest[0]] = { ...subExisting, [rest[1]]: value };
        }
        dispatch({
          type: "UPDATE_GUARD",
          guardId,
          config: { [topKey]: nested } as Partial<GuardConfigMap[GuardId]>,
        });
      }
    },
    [dispatch, guardId, guardConfig]
  );

  const handleGenerateTests = useCallback(() => {
    if (!testRunner) return;
    const result = generateScenariosFromPolicy(state.activePolicy);
    // Filter to only scenarios for this guard (scenario IDs start with "auto-{guardId}-")
    const prefix = `auto-${guardId}-`;
    const guardScenarios = result.scenarios.filter((s) => s.id.startsWith(prefix));
    if (guardScenarios.length === 0) return;

    const suiteScenarios: SuiteScenario[] = guardScenarios.map(testScenarioToSuite);
    testRunner.dispatch({ type: "IMPORT_SCENARIOS", scenarios: suiteScenarios });
    setContextMenu(null);
  }, [testRunner, state.activePolicy, guardId]);

  const handleViewResults = useCallback(() => {
    // Scroll to any test result element that references this guard
    const el = document.querySelector(`[data-guard-result="${guardId}"]`);
    if (el) {
      el.scrollIntoView({ behavior: "smooth", block: "center" });
      // Flash the element briefly
      el.classList.add("ring-2", "ring-[#d4a84b]");
      setTimeout(() => el.classList.remove("ring-2", "ring-[#d4a84b]"), 1500);
    }
    setContextMenu(null);
  }, [guardId]);

  const handleContextMenu = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    setContextMenu({ x: e.clientX, y: e.clientY });
  }, []);

  return (
    <div
      className="relative"
      draggable={reorderable ? true : undefined}
      onDragStart={reorderable ? onDragStart : undefined}
      onDragOver={reorderable ? onDragOver : undefined}
      onDragEnd={reorderable ? onDragEnd : undefined}
      onDrop={reorderable ? onDrop : undefined}
      onDragLeave={reorderable ? onDragLeave : undefined}
      onContextMenu={handleContextMenu}
    >
      {/* Drop indicator line — above */}
      {dropIndicator === "above" && (
        <div className="absolute top-0 left-0 right-0 h-0.5 bg-[#d4a84b] rounded-full z-10 -translate-y-1" />
      )}
    <Collapsible open={open} onOpenChange={setOpen}>
      <div
        className={cn(
          "rounded-lg border bg-[#0b0d13] guard-card-hover",
          hasNativeErrors
            ? "border-l-2 border-l-[#c45c5c] border-t-[#c45c5c]/20 border-r-[#c45c5c]/20 border-b-[#c45c5c]/20"
            : enabled
              ? "border-l-2 border-l-[#d4a84b] border-t-[#2d3240]/80 border-r-[#2d3240]/80 border-b-[#2d3240]/80"
              : "border-[#2d3240]/60 hover:border-[#2d3240]",
          isDragging && "opacity-40",
        )}
      >
        {/* Header */}
        <CollapsibleTrigger
          aria-expanded={open}
          aria-label={`${open ? 'Collapse' : 'Expand'} ${meta.name} configuration`}
          className="flex items-center gap-3 w-full px-3 py-3 text-left cursor-pointer hover:bg-[#131721]/50 transition-colors rounded-t-lg"
          render={<div role="button" tabIndex={0} />}
          nativeButton={false}
        >
          {/* Drag handle — only in custom reorder mode */}
          {reorderable && (
            <div
              className="shrink-0 cursor-grab active:cursor-grabbing text-[#6f7f9a] hover:text-[#d4a84b] transition-colors"
              onMouseDown={(e) => e.stopPropagation()}
            >
              <IconGripVertical size={14} stroke={1.5} />
            </div>
          )}
          <Icon
            size={16}
            stroke={1.5}
            className={cn(
              "shrink-0",
              hasNativeErrors ? "text-[#c45c5c]" : enabled ? "text-[#d4a84b]" : "text-[#6f7f9a]"
            )}
          />
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <span
                className={cn(
                  "text-xs font-mono font-medium truncate",
                  enabled ? "text-[#ece7dc]" : "text-[#6f7f9a]"
                )}
              >
                {meta.name}
              </span>
              {dotInfo && (
                <span
                  className="w-1.5 h-1.5 rounded-full shrink-0"
                  style={{ backgroundColor: dotInfo.color }}
                  title={dotInfo.tip}
                />
              )}
              {enabled && isUntested && (
                <span className="text-[8px] font-mono text-[#c45c5c]/60 border border-dashed border-[#c45c5c]/30 rounded px-1">
                  untested
                </span>
              )}
              <VerdictBadge verdict={meta.defaultVerdict} />
              {provenanceInfo && (
                <span
                  className={cn(
                    "inline-flex items-center gap-1 px-1.5 py-0 text-[9px] font-mono border rounded select-none whitespace-nowrap",
                    PROVENANCE_BADGE_STYLES[provenanceInfo.provenance] ?? "",
                  )}
                  title={
                    provenanceInfo.source
                      ? `${provenanceInfo.provenance} ${provenanceInfo.provenance === "added" ? "" : `from ${provenanceInfo.source}`}`
                      : provenanceInfo.provenance
                  }
                >
                  {provenanceInfo.provenance === "inherited" && provenanceInfo.source
                    ? `from ${provenanceInfo.source}`
                    : provenanceInfo.provenance === "overridden" && provenanceInfo.source
                      ? "local override"
                      : provenanceInfo.provenance}
                </span>
              )}
              {hasNativeErrors && (
                <span className="inline-flex items-center gap-1 px-1.5 py-0 text-[9px] font-mono text-[#c45c5c] bg-[#c45c5c]/10 border border-[#c45c5c]/20 rounded">
                  <IconAlertTriangle size={10} stroke={1.5} />
                  {nativeErrors.length}
                </span>
              )}
            </div>
            {!open && (
              <p className="text-[10px] text-[#6f7f9a] truncate mt-0.5">
                {enabled ? summary : meta.description}
              </p>
            )}
          </div>
          <div
            className="shrink-0"
            onClick={(e) => e.stopPropagation()}
          >
            <Switch
              checked={enabled}
              onCheckedChange={handleToggle}
              size="sm"
              className="data-checked:bg-[#d4a84b]"
            />
          </div>
          {/* Move up/down buttons — only in custom reorder mode */}
          {reorderable && (
            <div
              className="shrink-0 flex flex-col gap-0"
              onClick={(e) => e.stopPropagation()}
            >
              <button
                type="button"
                disabled={isFirst}
                onClick={onMoveUp}
                className={cn(
                  "p-0.5 rounded transition-colors",
                  isFirst
                    ? "text-[#6f7f9a]/30 cursor-not-allowed"
                    : "text-[#6f7f9a] hover:text-[#d4a84b] hover:bg-[#d4a84b]/10"
                )}
                title="Move up"
                aria-label="Move guard up"
              >
                <IconChevronUp size={12} stroke={1.5} />
              </button>
              <button
                type="button"
                disabled={isLast}
                onClick={onMoveDown}
                className={cn(
                  "p-0.5 rounded transition-colors",
                  isLast
                    ? "text-[#6f7f9a]/30 cursor-not-allowed"
                    : "text-[#6f7f9a] hover:text-[#d4a84b] hover:bg-[#d4a84b]/10"
                )}
                title="Move down"
                aria-label="Move guard down"
              >
                <IconChevronDown size={12} stroke={1.5} />
              </button>
            </div>
          )}
          <IconChevronDown
            size={14}
            stroke={1.5}
            className={cn(
              "shrink-0 text-[#6f7f9a] transition-transform duration-150",
              open && "rotate-180"
            )}
          />
        </CollapsibleTrigger>

        {/* Native validation errors (shown below header, always visible when present) */}
        {hasNativeErrors && (
          <div className="px-3 pb-2 flex flex-col gap-1">
            {nativeErrors.map((msg, i) => (
              <div
                key={i}
                className="flex items-start gap-1.5 text-[10px] font-mono text-[#c45c5c]/90 bg-[#c45c5c]/5 border border-[#c45c5c]/10 rounded px-2 py-1"
              >
                <IconAlertTriangle size={10} stroke={1.5} className="shrink-0 mt-0.5" />
                <span>{msg}</span>
              </div>
            ))}
          </div>
        )}

        {/* Body */}
        <CollapsibleContent>
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
          <div className="px-3 pb-3 border-t border-[#2d3240]/50">
            <p className="text-[10px] text-[#6f7f9a] pt-2 pb-1">
              {meta.description}
            </p>
            {guardId === "spider_sense" ? (
              <div className="flex flex-col gap-5 pt-2">
                {/* --- Trustprint Profile --- */}
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-[10px] font-mono font-medium text-[#ece7dc]" title="Embedding-based threat screening using vector similarity against known patterns">Trustprint Profile</span>
                  </div>
                  <p className="text-[9px] text-[#6f7f9a]/60 mb-2.5 leading-relaxed">
                    A Trustprint profile is the threat pattern database that this guard screens actions against.
                    It defines what attack behaviors the guard can recognize.
                  </p>
                  <TrustprintProfileCard
                    patterns={S2BENCH_PATTERNS}
                    profilePath={(guardConfig.pattern_db_path as string) ?? "builtin:s2bench-v1"}
                  />
                </div>

                {/* --- Threat Coverage (connected to profile) --- */}
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-[10px] font-mono font-medium text-[#ece7dc]">Threat Coverage</span>
                  </div>
                  <p className="text-[9px] text-[#6f7f9a]/60 mb-2 leading-relaxed">
                    Click any cell to inspect the patterns it contains. Dashed cells are coverage gaps.
                  </p>
                  <TrustprintPatternExplorer
                    patterns={S2BENCH_PATTERNS}
                    compact
                  />
                </div>

                {/* --- Decision Zones --- */}
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-[10px] font-mono font-medium text-[#ece7dc]">Decision Zones</span>
                    <span className="text-[9px] font-mono text-[#6f7f9a]/50">Drag handles to tune</span>
                  </div>
                  <p className="text-[9px] text-[#6f7f9a]/60 mb-2 leading-relaxed">
                    Actions with similarity above the threshold are denied. The ambiguity band flags borderline cases for review.
                  </p>
                  <TrustprintThresholdTuner
                    threshold={(guardConfig.similarity_threshold as number) ?? 0.85}
                    ambiguityBand={(guardConfig.ambiguity_band as number) ?? 0.1}
                    onThresholdChange={(v) => handleConfigChange("similarity_threshold", v)}
                    onAmbiguityBandChange={(v) => handleConfigChange("ambiguity_band", v)}
                  />
                </div>

                {/* --- Embedding Provider --- */}
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-[10px] font-mono font-medium text-[#ece7dc]">Embedding Provider</span>
                  </div>
                  <p className="text-[9px] text-[#6f7f9a]/60 mb-2 leading-relaxed">
                    Connect an embedding API to convert actions into vectors for similarity screening.
                  </p>
                  <TrustprintProviderWizard
                    config={{
                      embedding_api_url: guardConfig.embedding_api_url as string | undefined,
                      embedding_api_key: guardConfig.embedding_api_key as string | undefined,
                      embedding_model: guardConfig.embedding_model as string | undefined,
                    }}
                    onChange={(updates) => {
                      for (const [k, v] of Object.entries(updates)) {
                        handleConfigChange(k, v);
                      }
                    }}
                    compact
                  />

                </div>

                {/* --- Advanced Config (filtered) --- */}
                <div>
                  <span className="text-[10px] font-mono font-medium text-[#ece7dc] block mb-1.5">Advanced</span>
                  <GuardConfigFields
                    guardId={guardId}
                    config={guardConfig}
                    onChange={handleConfigChange}
                    excludeKeys={SPIDER_SENSE_HANDLED_KEYS}
                  />
                </div>
              </div>
            ) : (
              <GuardConfigFields
                guardId={guardId}
                config={guardConfig}
                onChange={handleConfigChange}
              />
            )}
          </div>
          </motion.div>
        </CollapsibleContent>
      </div>
    </Collapsible>
      {/* Drop indicator line — below */}
      {dropIndicator === "below" && (
        <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-[#d4a84b] rounded-full z-10 translate-y-1" />
      )}

      {/* Context menu */}
      {contextMenu && (
        <div
          role="menu"
          className="fixed z-50 min-w-[180px] rounded-md border border-[#2d3240] bg-[#131721] py-1 shadow-lg shadow-black/40"
          style={{ left: contextMenu.x, top: contextMenu.y }}
        >
          <button
            type="button"
            role="menuitem"
            className="flex w-full items-center gap-2 px-3 py-1.5 text-[10px] font-mono text-[#ece7dc] hover:bg-[#2d3240] transition-colors text-left"
            onClick={handleGenerateTests}
            disabled={!testRunner}
          >
            <span className={!testRunner ? "opacity-40" : ""}>
              Generate tests for this guard
            </span>
          </button>
          <button
            type="button"
            role="menuitem"
            className="flex w-full items-center gap-2 px-3 py-1.5 text-[10px] font-mono text-[#ece7dc] hover:bg-[#2d3240] transition-colors text-left"
            onClick={handleViewResults}
            disabled={testStatus === "none"}
          >
            <span className={testStatus === "none" ? "opacity-40" : ""}>
              View test results
            </span>
          </button>
        </div>
      )}
    </div>
  );
}
