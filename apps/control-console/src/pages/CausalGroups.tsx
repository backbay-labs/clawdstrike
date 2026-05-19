import { useCallback, useEffect, useMemo, useState } from "react";
import {
  type FindingGroup,
  type FindingGroupsResponse,
  fetchFindingGroups,
  type SignedReceiptJson,
} from "../api/client";
import { GlassButton, NoiseGrain, Plate } from "../components/ui";
import { exportAsJSON } from "../utils/exportData";

const DEFAULT_LIMIT = 25;
const DEFAULT_MAX_DEPTH = 3;

export function CausalGroups(_props: { windowId?: string }) {
  const [limit, setLimit] = useState(DEFAULT_LIMIT);
  const [maxDepth, setMaxDepth] = useState(DEFAULT_MAX_DEPTH);
  const [groups, setGroups] = useState<FindingGroupsResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadGroups = useCallback(async () => {
    setLoading(true);
    try {
      const response = await fetchFindingGroups({ limit, maxDepth });
      setGroups(response);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load causal groups");
    } finally {
      setLoading(false);
    }
  }, [limit, maxDepth]);

  useEffect(() => {
    loadGroups();
  }, [loadGroups]);

  return (
    <div
      className="space-y-5"
      style={{ padding: 20, color: "var(--text)", overflow: "auto", height: "100%" }}
    >
      <header className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <p
            className="font-mono"
            style={{
              color: "rgba(214,177,90,0.72)",
              fontSize: "0.68rem",
              letterSpacing: "0.16em",
              textTransform: "uppercase",
            }}
          >
            Local causal graph
          </p>
          <h1
            className="font-display"
            style={{ fontSize: "1.85rem", fontWeight: 700, letterSpacing: 0, marginTop: 2 }}
          >
            Causal Groups
          </h1>
        </div>

        <div className="flex flex-wrap items-end gap-2">
          <NumberField label="Limit" value={limit} min={1} max={100} onChange={setLimit} />
          <NumberField label="Max Depth" value={maxDepth} min={1} max={8} onChange={setMaxDepth} />
          <GlassButton variant="primary" onClick={loadGroups} disabled={loading}>
            {loading ? "Loading..." : "Refresh Groups"}
          </GlassButton>
        </div>
      </header>

      {error && <StatusBanner message={error} />}

      <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
        <SummaryMetric label="Groups" value={`Groups: ${groups?.groupCount ?? 0}`} />
        <SummaryMetric label="Findings" value={`Findings: ${groups?.findingCount ?? 0}`} />
        <SummaryMetric label="Depth" value={`Depth: ${maxDepth}`} />
      </div>

      <section className="space-y-3">
        {!groups || groups.groups.length === 0 ? (
          <Plate className="p-6">
            <EmptyState text={loading ? "Loading causal groups" : "No causal groups"} />
          </Plate>
        ) : (
          groups.groups.map((group) => <GroupPanel key={group.groupId} group={group} />)
        )}
      </section>
    </div>
  );
}

function GroupPanel({ group }: { group: FindingGroup }) {
  const nodeKinds = useMemo(() => graphNodeKinds(group), [group]);
  const affectedIdentityItems = useMemo(() => findingGroupIdentityLabels(group), [group]);
  const affectedToolItems = useMemo(() => findingGroupToolLabels(group), [group]);
  const receiptFamily = receiptFamilyText(group.receipt) ?? "-";

  return (
    <Plate className="p-4" goldEdge>
      <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
        <PanelTitle eyebrow={group.groupId} title={group.rootLabel || group.rootNodeId} />
        <div className="flex flex-wrap gap-2">
          <GlassButton
            onClick={() => exportAsJSON([group], `causal-group-${safeFilenameId(group.groupId)}`)}
          >
            Export Group
          </GlassButton>
        </div>
      </div>

      <div className="mt-4 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <SmallFact label="Root" value={group.rootNodeId} mono />
        <SmallFact label="Findings" value={String(group.findingCount)} />
        <SmallFact label="Nodes" value={String(group.nodeCount)} />
        <SmallFact label="Receipt" value={receiptFamily} />
        <SmallFact label="Identities" value={String(group.affectedIdentityCount ?? 0)} />
        <SmallFact label="Tools" value={String(group.affectedToolCount ?? 0)} />
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-[1fr_1fr_0.9fr]">
        <FactList title="Rules" items={group.ruleIds} />
        <FactList title="Findings" items={group.findingIds} />
        <FactList title="Graph Kinds" items={nodeKinds} />
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <FactList title="Responsible Identities" items={affectedIdentityItems} />
        <FactList title="Responsible Tools" items={affectedToolItems} />
      </div>
    </Plate>
  );
}

function NumberField({
  label,
  value,
  min,
  max,
  onChange,
}: {
  label: string;
  value: number;
  min: number;
  max: number;
  onChange: (value: number) => void;
}) {
  return (
    <label className="flex flex-col gap-1">
      <span className="font-mono uppercase tracking-[0.12em] text-[0.65rem] text-[rgba(154,167,181,0.62)]">
        {label}
      </span>
      <input
        type="number"
        min={min}
        max={max}
        value={value}
        onChange={(event) => onChange(clampNumber(event.target.value, min, max, value))}
        className="glass-input font-mono rounded-md px-3 py-2 text-sm outline-none"
        style={{ color: "var(--text)", width: 112 }}
      />
    </label>
  );
}

function SummaryMetric({ label, value }: { label: string; value: string }) {
  return (
    <Plate className="p-4">
      <p
        className="font-mono"
        style={{
          position: "relative",
          color: "rgba(154,167,181,0.58)",
          fontSize: "0.62rem",
          letterSpacing: "0.13em",
          textTransform: "uppercase",
        }}
      >
        {label}
      </p>
      <p
        className="font-display mt-2 truncate"
        style={{ position: "relative", color: "var(--text)", fontSize: "1.25rem", fontWeight: 700 }}
      >
        {value}
      </p>
    </Plate>
  );
}

function PanelTitle({ eyebrow, title }: { eyebrow: string; title: string }) {
  return (
    <div style={{ position: "relative" }}>
      <p
        className="font-mono"
        style={{
          color: "rgba(214,177,90,0.66)",
          fontSize: "0.62rem",
          letterSpacing: "0.14em",
          textTransform: "uppercase",
        }}
      >
        {eyebrow}
      </p>
      <h2
        className="font-display mt-1"
        style={{ color: "var(--text)", fontSize: "1.05rem", fontWeight: 700 }}
      >
        {title}
      </h2>
    </div>
  );
}

function SmallFact({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div>
      <p
        className="font-mono"
        style={{
          color: "rgba(154,167,181,0.54)",
          fontSize: "0.62rem",
          letterSpacing: "0.12em",
          textTransform: "uppercase",
        }}
      >
        {label}
      </p>
      <p
        className={mono ? "font-mono mt-1 truncate" : "font-body mt-1 truncate"}
        style={{ color: "var(--text)", fontSize: mono ? "0.72rem" : "0.88rem" }}
      >
        {value}
      </p>
    </div>
  );
}

function FactList({ title, items }: { title: string; items: string[] }) {
  return (
    <div>
      <p
        className="font-mono"
        style={{
          color: "rgba(154,167,181,0.54)",
          fontSize: "0.62rem",
          letterSpacing: "0.12em",
          textTransform: "uppercase",
        }}
      >
        {title}
      </p>
      <div className="mt-2 flex flex-wrap gap-2">
        {items.length === 0 ? (
          <span className="font-mono text-xs" style={{ color: "rgba(154,167,181,0.45)" }}>
            -
          </span>
        ) : (
          items.map((item, index) => (
            <span
              key={`${item}:${index}`}
              className="font-mono rounded-md px-2 py-1"
              style={{
                border: "1px solid rgba(27,34,48,0.82)",
                background: "rgba(0,0,0,0.22)",
                color: "var(--text)",
                fontSize: "0.66rem",
              }}
            >
              {item}
            </span>
          ))
        )}
      </div>
    </div>
  );
}

function findingGroupIdentityLabels(group: FindingGroup): string[] {
  const identities = group.affectedIdentities;
  if (!identities) {
    return [];
  }
  return [
    ...identities.hosts.map((identity) => `host:${identity.id}`),
    ...identities.users.map((identity) => `user:${identity.id}`),
    ...identities.sessions.map((identity) => `session:${identity.id}`),
    ...identities.agents.map((identity) => `agent:${identity.id}`),
    ...identities.workloads.map((identity) => `workload:${identity.id}`),
    ...identities.approvals.map((identity) => `approval:${identity.id}`),
  ];
}

function findingGroupToolLabels(group: FindingGroup): string[] {
  return (group.affectedTools ?? []).map((tool) => tool.toolName);
}

function StatusBanner({ message }: { message: string }) {
  return (
    <div
      className="glass-panel"
      style={{
        background: "rgba(194,59,59,0.08)",
        border: "1px solid rgba(194,59,59,0.3)",
        padding: "0.7rem 1rem",
      }}
    >
      <NoiseGrain />
      <p
        className="font-mono"
        style={{ position: "relative", color: "var(--crimson)", fontSize: "0.78rem" }}
      >
        {message}
      </p>
    </div>
  );
}

function EmptyState({ text }: { text: string }) {
  return (
    <p
      className="font-mono"
      style={{
        position: "relative",
        color: "rgba(154,167,181,0.5)",
        fontSize: "0.78rem",
        letterSpacing: "0.06em",
      }}
    >
      {text}
    </p>
  );
}

function graphNodeKinds(group: FindingGroup): string[] {
  const nodes = group.graph.nodes ?? {};
  return Array.from(
    new Set(
      Object.values(nodes)
        .map((node) => node.kind)
        .filter(isString),
    ),
  ).sort();
}

function receiptFamilyText(receipt: SignedReceiptJson): string | null {
  const receiptValue = isRecord(receipt.receipt) ? receipt.receipt : null;
  const metadata = isRecord(receiptValue?.metadata) ? receiptValue.metadata : null;
  const decision = isRecord(metadata?.endpointDecision) ? metadata.endpointDecision : null;
  const family = decision?.receiptFamily;
  return typeof family === "string" && family.trim() ? family : null;
}

function clampNumber(raw: string, min: number, max: number, fallback: number): number {
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

function safeFilenameId(value: string): string {
  return value.trim().replace(/[^A-Za-z0-9_.-]+/g, "-") || "unknown";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}
