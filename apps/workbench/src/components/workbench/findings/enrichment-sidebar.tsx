import { useState } from "react";
import { formatRelativeTime } from "@/lib/workbench/format-utils";
import {
  IconChevronDown,
  IconChevronRight,
  IconTarget,
  IconBug,
  IconSpider,
  IconRss,
  IconUsers,
  IconWorld,
  IconMapPin,
  IconInfoCircle,
  IconFlask,
  IconShieldCheck,
} from "@tabler/icons-react";
import type { Enrichment } from "@/lib/workbench/finding-engine";

interface EnrichmentSidebarProps {
  enrichments: Enrichment[];
  onRunEnrichment?: () => void;
}

const ENRICHMENT_TYPE_CONFIG: Record<
  string,
  { icon: typeof IconTarget; color: string; label: string }
> = {
  mitre_attack: { icon: IconTarget, color: "#c45c5c", label: "MITRE ATT&CK" },
  ioc_extraction: { icon: IconBug, color: "#d4784b", label: "IOC Extraction" },
  spider_sense: { icon: IconSpider, color: "#d4a84b", label: "Spider Sense" },
  external_feed: { icon: IconRss, color: "#6ea8d9", label: "External Feed" },
  swarm_corroboration: { icon: IconUsers, color: "#3dbf84", label: "Swarm Corroboration" },
  reputation: { icon: IconShieldCheck, color: "#6b9b8b", label: "Reputation" },
  geolocation: { icon: IconMapPin, color: "#a78bfa", label: "Geolocation" },
  whois: { icon: IconWorld, color: "#8b9dc3", label: "WHOIS" },
  custom: { icon: IconInfoCircle, color: "#6f7f9a", label: "Custom" },
};

const IOC_TYPE_COLORS: Record<string, string> = {
  sha256: "#c45c5c",
  sha1: "#c45c5c",
  md5: "#c45c5c",
  domain: "#6ea8d9",
  ip: "#d4784b",
  url: "#d4a84b",
  email: "#a78bfa",
  filepath: "#6b9b8b",
};

const SPIDER_SENSE_VERDICT_CONFIG: Record<
  string,
  { color: string; bg: string; label: string }
> = {
  deny: { color: "#c45c5c", bg: "#c45c5c20", label: "DENY" },
  ambiguous: { color: "#d4a84b", bg: "#d4a84b20", label: "AMBIGUOUS" },
  allow: { color: "#3dbf84", bg: "#3dbf8420", label: "ALLOW" },
};

const KILL_CHAIN_DEPTH_LABELS: Record<number, { label: string; color: string }> = {
  1: { label: "Initial", color: "#6b9b8b" },
  2: { label: "Establishing", color: "#d4a84b" },
  3: { label: "Expanding", color: "#d4784b" },
  4: { label: "Deep", color: "#c45c5c" },
  5: { label: "Full Chain", color: "#c45c5c" },
};

export function EnrichmentSidebar({
  enrichments,
  onRunEnrichment,
}: EnrichmentSidebarProps) {
  const grouped = groupByType(enrichments);

  return (
    <div className="flex flex-col h-full">
      <div className="shrink-0 px-4 py-3 border-b border-[#2d3240]/60">
        <div className="flex items-center justify-between">
          <h2 className="text-[10px] font-semibold uppercase tracking-[0.08em] text-[#6f7f9a]/50">
            Enrichment
          </h2>
          {onRunEnrichment && (
            <button
              onClick={onRunEnrichment}
              className="flex items-center gap-1 rounded-md px-2.5 py-1 text-[10px] font-medium text-[#d4a84b] bg-[#d4a84b]/10 border border-[#d4a84b]/20 hover:bg-[#d4a84b]/20 transition-colors"
            >
              <IconFlask size={11} stroke={1.5} />
              Run Enrichment
            </button>
          )}
        </div>
        {enrichments.length > 0 && (
          <span className="text-[9px] font-mono text-[#6f7f9a]/30 mt-0.5 block">
            {enrichments.length} enrichment{enrichments.length !== 1 ? "s" : ""} applied
          </span>
        )}
      </div>

      <div className="flex-1 overflow-y-auto">
        {enrichments.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-48 px-4">
            <IconFlask size={24} className="text-[#6f7f9a]/15 mb-2" stroke={1.5} />
            <span className="text-[11px] text-[#6f7f9a]/30 text-center">
              No enrichments applied yet.
              {onRunEnrichment && " Click \"Run Enrichment\" to analyze this finding."}
            </span>
          </div>
        ) : (
          <div className="flex flex-col">
            {Object.entries(grouped).map(([type, items]) => (
              <EnrichmentSection key={type} type={type} enrichments={items} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function groupByType(enrichments: Enrichment[]): Record<string, Enrichment[]> {
  const groups: Record<string, Enrichment[]> = {};
  for (const e of enrichments) {
    if (!groups[e.type]) groups[e.type] = [];
    groups[e.type].push(e);
  }
  return groups;
}

function EnrichmentSection({
  type,
  enrichments,
}: {
  type: string;
  enrichments: Enrichment[];
}) {
  const [collapsed, setCollapsed] = useState(false);
  const config = ENRICHMENT_TYPE_CONFIG[type] ?? ENRICHMENT_TYPE_CONFIG.custom;
  const SectionIcon = config.icon;

  return (
    <div className="border-b border-[#2d3240]/40">
      <button
        onClick={() => setCollapsed(!collapsed)}
        className="flex items-center gap-2 w-full px-4 py-2.5 text-left hover:bg-[#131721]/40 transition-colors"
      >
        {collapsed ? (
          <IconChevronRight size={11} className="text-[#6f7f9a]/40 shrink-0" />
        ) : (
          <IconChevronDown size={11} className="text-[#6f7f9a]/40 shrink-0" />
        )}
        <SectionIcon
          size={13}
          stroke={1.5}
          style={{ color: config.color }}
          className="shrink-0"
        />
        <span
          className="text-[10px] font-semibold uppercase tracking-[0.04em]"
          style={{ color: config.color }}
        >
          {config.label}
        </span>
        <span className="text-[9px] font-mono text-[#6f7f9a]/30 ml-auto">
          {enrichments.length}
        </span>
      </button>

      {!collapsed && (
        <div className="px-4 pb-3">
          {enrichments.map((enrichment) => (
            <div key={enrichment.id} className="mb-2 last:mb-0">
              <EnrichmentContent enrichment={enrichment} />
              <div className="mt-1 flex items-center gap-2">
                <span className="text-[8px] text-[#6f7f9a]/30">
                  {formatRelativeTime(enrichment.addedAt)}
                </span>
                <span className="text-[8px] text-[#6f7f9a]/20">via {enrichment.source}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function EnrichmentContent({ enrichment }: { enrichment: Enrichment }) {
  switch (enrichment.type) {
    case "mitre_attack":
      return <MitreAttackContent data={enrichment.data} />;
    case "ioc_extraction":
      return <IocExtractionContent data={enrichment.data} />;
    case "spider_sense":
      return <SpiderSenseContent data={enrichment.data} />;
    case "external_feed":
      return <ExternalFeedContent data={enrichment.data} label={enrichment.label} />;
    case "swarm_corroboration":
      return <SwarmCorroborationContent data={enrichment.data} />;
    default:
      return <GenericContent data={enrichment.data} label={enrichment.label} />;
  }
}

function MitreAttackContent({ data }: { data: Record<string, unknown> }) {
  const techniques = (data.techniques ?? []) as Array<{
    id: string;
    name: string;
    tactic: string;
    subTechnique?: string;
  }>;
  const killChainDepth = (data.killChainDepth ?? 0) as number;
  const tactics = (data.tactics ?? []) as string[];
  const depthConfig = KILL_CHAIN_DEPTH_LABELS[Math.min(killChainDepth, 5)] ??
    KILL_CHAIN_DEPTH_LABELS[1];

  return (
    <div className="rounded-lg border border-[#2d3240]/40 bg-[#131721] p-3">
      {killChainDepth > 0 && (
        <div className="flex items-center gap-2 mb-2">
          <span className="text-[9px] text-[#6f7f9a]/40">Kill-chain depth:</span>
          <span
            className="rounded px-1.5 py-0.5 text-[9px] font-semibold uppercase border"
            style={{
              color: depthConfig?.color,
              borderColor: (depthConfig?.color ?? "#6f7f9a") + "30",
              backgroundColor: (depthConfig?.color ?? "#6f7f9a") + "10",
            }}
          >
            {killChainDepth} — {depthConfig?.label}
          </span>
        </div>
      )}

      <div className="flex flex-col gap-1.5">
        {techniques.map((tech) => (
          <div
            key={tech.id}
            className="flex items-start gap-2 rounded border border-[#2d3240]/30 bg-[#05060a] px-2.5 py-1.5"
          >
            <span className="font-mono text-[10px] text-[#c45c5c] font-semibold shrink-0">
              {tech.id}
            </span>
            <div className="flex-1 min-w-0">
              <span className="text-[10px] text-[#ece7dc]/70 block truncate">
                {tech.name}
              </span>
              <span className="text-[9px] text-[#6f7f9a]/50">
                {tech.tactic}
                {tech.subTechnique && ` / ${tech.subTechnique}`}
              </span>
            </div>
          </div>
        ))}
      </div>

      {tactics.length > 0 && (
        <div className="flex flex-wrap gap-1 mt-2 pt-2 border-t border-[#2d3240]/30">
          {tactics.map((tactic) => (
            <span
              key={tactic}
              className="rounded bg-[#c45c5c]/10 px-1.5 py-0.5 text-[8px] font-medium text-[#c45c5c]/70 border border-[#c45c5c]/15"
            >
              {tactic}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function IocExtractionContent({ data }: { data: Record<string, unknown> }) {
  const indicators = (data.indicators ?? []) as Array<{
    indicator: string;
    iocType: string;
    source?: string;
  }>;

  return (
    <div className="rounded-lg border border-[#2d3240]/40 bg-[#131721] p-3">
      <div className="flex flex-col gap-1.5">
        {indicators.map((ioc, idx) => {
          const typeColor = IOC_TYPE_COLORS[ioc.iocType] ?? "#6f7f9a";
          return (
            <div
              key={`${ioc.indicator}-${idx}`}
              className="flex items-center gap-2"
            >
              <span
                className="shrink-0 rounded px-1.5 py-0.5 text-[8px] font-semibold uppercase border"
                style={{
                  color: typeColor,
                  borderColor: typeColor + "30",
                  backgroundColor: typeColor + "10",
                }}
              >
                {ioc.iocType}
              </span>

              <span className="font-mono text-[10px] text-[#ece7dc]/60 truncate flex-1 min-w-0">
                {ioc.indicator}
              </span>
            </div>
          );
        })}
      </div>
      {indicators.length > 0 && (
        <div className="mt-2 pt-2 border-t border-[#2d3240]/30">
          <span className="text-[9px] font-mono text-[#6f7f9a]/30">
            {indicators.length} indicator{indicators.length !== 1 ? "s" : ""} extracted
          </span>
        </div>
      )}
    </div>
  );
}

function SpiderSenseContent({ data }: { data: Record<string, unknown> }) {
  const verdict = (data.verdict ?? "allow") as string;
  const topScore = (data.topScore ?? 0) as number;
  const threshold = (data.threshold ?? 0) as number;
  const topMatches = (data.topMatches ?? []) as Array<{
    category: string;
    label: string;
    score: number;
  }>;

  const verdictConfig = SPIDER_SENSE_VERDICT_CONFIG[verdict] ??
    SPIDER_SENSE_VERDICT_CONFIG.allow;

  return (
    <div className="rounded-lg border border-[#2d3240]/40 bg-[#131721] p-3">
      <div className="flex items-center gap-2 mb-2">
        <span
          className="rounded px-1.5 py-0.5 text-[9px] font-semibold uppercase border"
          style={{
            color: verdictConfig.color,
            borderColor: verdictConfig.color + "30",
            backgroundColor: verdictConfig.bg,
          }}
        >
          {verdictConfig.label}
        </span>
        <span className="font-mono text-[10px] text-[#ece7dc]/60">
          Top score: {topScore.toFixed(3)}
        </span>
        <span className="text-[9px] text-[#6f7f9a]/30 ml-auto">
          threshold: {threshold.toFixed(3)}
        </span>
      </div>

      <div className="mb-2.5">
        <div className="w-full h-2 rounded-full bg-[#2d3240]/30 overflow-hidden relative">
          <div
            className="absolute top-0 bottom-0 w-px bg-[#6f7f9a]/40"
            style={{ left: `${threshold * 100}%` }}
          />
          <div
            className="h-full rounded-full transition-all duration-300"
            style={{
              width: `${Math.min(topScore * 100, 100)}%`,
              backgroundColor: verdictConfig.color,
            }}
          />
        </div>
      </div>

      {topMatches.length > 0 && (
        <div className="flex flex-col gap-1">
          <span className="text-[9px] text-[#6f7f9a]/40 mb-0.5">
            Top matches:
          </span>
          {topMatches.map((match, idx) => (
            <div
              key={`${match.label}-${idx}`}
              className="flex items-center gap-2 rounded border border-[#2d3240]/20 bg-[#05060a] px-2 py-1"
            >
              <span className="text-[9px] text-[#d4a84b]/60 shrink-0">
                {match.category}
              </span>
              <span className="text-[10px] text-[#ece7dc]/60 flex-1 min-w-0 truncate">
                {match.label}
              </span>
              <span className="font-mono text-[9px] text-[#ece7dc]/40 shrink-0">
                {match.score.toFixed(3)}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function ExternalFeedContent({
  data,
  label,
}: {
  data: Record<string, unknown>;
  label: string;
}) {
  const feedName = (data.feedName ?? data.feed_name ?? "Unknown Feed") as string;
  const matchDetails = (data.matchDetails ?? data.match_details ?? data.details ?? null) as
    | string
    | null;

  return (
    <div className="rounded-lg border border-[#2d3240]/40 bg-[#131721] p-3">
      <div className="flex items-center gap-2 mb-1.5">
        <IconRss size={12} className="text-[#6ea8d9] shrink-0" stroke={1.5} />
        <span className="text-[10px] font-medium text-[#ece7dc]/70">
          {feedName}
        </span>
      </div>
      {matchDetails && (
        <p className="text-[10px] text-[#ece7dc]/50 leading-relaxed">
          {matchDetails}
        </p>
      )}
      {!matchDetails && label && (
        <p className="text-[10px] text-[#ece7dc]/50 leading-relaxed">
          {label}
        </p>
      )}
    </div>
  );
}

function SwarmCorroborationContent({ data }: { data: Record<string, unknown> }) {
  const peerFingerprint = (data.peerFingerprint ?? "") as string;
  const peerFindingId = (data.peerFindingId ?? "") as string;
  const peerConfidence = (data.peerConfidence ?? 0) as number;

  return (
    <div className="rounded-lg border border-[#3dbf84]/15 bg-[#3dbf84]/5 p-3">
      <div className="flex items-center gap-2 mb-2">
        <IconUsers size={12} className="text-[#3dbf84] shrink-0" stroke={1.5} />
        <span className="text-[10px] font-medium text-[#3dbf84]">
          Peer Corroboration
        </span>
      </div>
      <div className="flex flex-col gap-1.5">
        <div className="flex items-baseline gap-2 text-[10px]">
          <span className="text-[#6f7f9a]/50 shrink-0 w-[70px]">Peer</span>
          <span className="font-mono text-[#ece7dc]/60 truncate">
            {peerFingerprint ? `${peerFingerprint.slice(0, 12)}...` : "unknown"}
          </span>
        </div>
        <div className="flex items-baseline gap-2 text-[10px]">
          <span className="text-[#6f7f9a]/50 shrink-0 w-[70px]">Finding</span>
          <span className="font-mono text-[#ece7dc]/60 truncate">
            {peerFindingId || "unknown"}
          </span>
        </div>
        <div className="flex items-baseline gap-2 text-[10px]">
          <span className="text-[#6f7f9a]/50 shrink-0 w-[70px]">Confidence</span>
          <span className="font-mono text-[#3dbf84]">
            {Math.round(peerConfidence * 100)}%
          </span>
        </div>
      </div>
    </div>
  );
}

function GenericContent({
  data,
  label,
}: {
  data: Record<string, unknown>;
  label: string;
}) {
  const entries = Object.entries(data).filter(
    ([key]) => key !== "kind",
  );

  return (
    <div className="rounded-lg border border-[#2d3240]/40 bg-[#131721] p-3">
      {label && (
        <p className="text-[10px] text-[#ece7dc]/60 mb-2">{label}</p>
      )}
      <div className="flex flex-col gap-1">
        {entries.map(([key, value]) => (
          <div
            key={key}
            className="flex items-baseline gap-2 text-[10px]"
          >
            <span className="text-[#6f7f9a]/50 shrink-0 min-w-[60px]">
              {key}
            </span>
            <span className="font-mono text-[#ece7dc]/50 break-all">
              {formatValue(value)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

function formatValue(value: unknown): string {
  if (value === null || value === undefined) return "-";
  if (typeof value === "string") return value;
  if (typeof value === "number") return value.toLocaleString();
  if (typeof value === "boolean") return value ? "true" : "false";
  if (Array.isArray(value)) return `[${value.length} items]`;
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}
