import { useMemo, useState } from "react";
import {
  type AgentSecretTouchesFleetPublishResponse,
  type AgentSecretTouchesInput,
  type AgentSecretTouchesResponse,
  fetchAgentSecretTouches,
  publishAgentSecretTouchesToFleet,
  type SignedReceiptJson,
} from "../api/client";
import { GlassButton, NoiseGrain, Plate } from "../components/ui";
import { exportAsJSON } from "../utils/exportData";

const DEFAULT_UPSTREAM_DEPTH = 3;
const DEFAULT_DOWNSTREAM_DEPTH = 1;
const DEFAULT_LIMIT = 10;

export function AgentSecretTouches(_props: { windowId?: string }) {
  const [sessionId, setSessionId] = useState("");
  const [credentialKind, setCredentialKind] = useState("api_token");
  const [requireAgentContext, setRequireAgentContext] = useState(true);
  const [upstreamDepth, setUpstreamDepth] = useState(DEFAULT_UPSTREAM_DEPTH);
  const [downstreamDepth, setDownstreamDepth] = useState(DEFAULT_DOWNSTREAM_DEPTH);
  const [limit, setLimit] = useState(DEFAULT_LIMIT);
  const [touches, setTouches] = useState<AgentSecretTouchesResponse | null>(null);
  const [publish, setPublish] = useState<AgentSecretTouchesFleetPublishResponse | null>(null);
  const [loading, setLoading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const query = useMemo(
    () =>
      buildQuery({
        sessionId,
        credentialKind,
        requireAgentContext,
        upstreamDepth,
        downstreamDepth,
        limit,
      }),
    [sessionId, credentialKind, requireAgentContext, upstreamDepth, downstreamDepth, limit],
  );
  const receiptFamily = useMemo(() => receiptFamilyText(touches?.touches[0]?.receipt), [touches]);
  const agentCount = useMemo(
    () => new Set((touches?.touches ?? []).flatMap((touch) => touch.agentNodeIds)).size,
    [touches],
  );
  const processCount = useMemo(
    () => new Set((touches?.touches ?? []).flatMap((touch) => touch.processNodeIds)).size,
    [touches],
  );
  const exportPayload = useMemo(() => [touches, publish].filter(Boolean), [touches, publish]);

  async function queryTouches() {
    setLoading("query");
    try {
      const response = await fetchAgentSecretTouches(query);
      setTouches(response);
      setPublish(null);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to query agent-secret touches");
    } finally {
      setLoading(null);
    }
  }

  async function publishTouches() {
    setLoading("publish");
    try {
      const response = await publishAgentSecretTouchesToFleet(query);
      setPublish(response);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to publish agent-secret touches");
    } finally {
      setLoading(null);
    }
  }

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
            Agent credential graph slices
          </p>
          <h1
            className="font-display"
            style={{ fontSize: "1.85rem", fontWeight: 700, letterSpacing: 0, marginTop: 2 }}
          >
            Agent Secret Touches
          </h1>
        </div>

        <div className="flex flex-wrap gap-2">
          <GlassButton variant="primary" onClick={queryTouches} disabled={loading != null}>
            {loading === "query" ? "Querying..." : "Query Touches"}
          </GlassButton>
          <GlassButton onClick={publishTouches} disabled={loading != null}>
            {loading === "publish" ? "Publishing..." : "Publish to Fleet"}
          </GlassButton>
          <GlassButton
            onClick={() =>
              exportAsJSON(exportPayload, `agent-secret-touches-${safeFilenameId(sessionId)}`)
            }
            disabled={exportPayload.length === 0}
          >
            Export JSON
          </GlassButton>
        </div>
      </header>

      {error && <StatusBanner message={error} />}

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-[minmax(320px,0.74fr)_minmax(0,1.26fr)]">
        <Plate className="p-4">
          <PanelTitle eyebrow="Filter" title="Credential Touch Query" />
          <div className="mt-4 space-y-3">
            <TextField label="Session ID" value={sessionId} onChange={setSessionId} />
            <TextField
              label="Credential Kind"
              value={credentialKind}
              onChange={setCredentialKind}
            />
            <CheckboxField
              label="Require Agent Context"
              checked={requireAgentContext}
              onChange={setRequireAgentContext}
            />
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
              <NumberField
                label="Upstream Depth"
                value={upstreamDepth}
                min={0}
                max={8}
                onChange={setUpstreamDepth}
              />
              <NumberField
                label="Downstream Depth"
                value={downstreamDepth}
                min={0}
                max={8}
                onChange={setDownstreamDepth}
              />
              <NumberField label="Limit" value={limit} min={1} max={100} onChange={setLimit} />
            </div>
          </div>
        </Plate>

        <section className="space-y-5">
          <div className="grid grid-cols-1 gap-3 md:grid-cols-4">
            <Metric label="Touches" value={numberText(touches?.touchCount)} />
            <Metric label="Agents" value={numberText(agentCount)} />
            <Metric label="Processes" value={numberText(processCount)} />
            <Metric label="Receipt" value={receiptFamily ?? "-"} />
          </div>

          <Plate className="p-4" goldEdge>
            <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
              <PanelTitle
                eyebrow={touches ? "Credential Evidence" : "No query"}
                title={
                  touches
                    ? `${touches.touchCount} touch${touches.touchCount === 1 ? "" : "es"}`
                    : "Agent Secrets"
                }
              />
              <StatusPill
                value={query.requireAgentContext ? "Agent context required" : "Any credential"}
              />
            </div>

            <div className="mt-4 space-y-3">
              {!touches || touches.touches.length === 0 ? (
                <EmptyState text="No agent-secret touches loaded" />
              ) : (
                touches.touches.map((touch) => (
                  <TouchRow
                    key={touch.credentialNodeId}
                    touch={touch}
                    receiptFamily={receiptFamilyText(touch.receipt)}
                  />
                ))
              )}
            </div>
          </Plate>

          <Plate className="p-4">
            <PanelTitle
              eyebrow={publish ? "Fleet Hunt" : "Not published"}
              title={publish ? `${publish.publishedCount} published` : "Fleet Publish"}
            />
            <div className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-3">
              <SmallFact label="Touch Count" value={numberText(publish?.touchCount)} />
              <SmallFact label="Published" value={numberText(publish?.publishedCount)} />
              <SmallFact label="Events" value={numberText(publish?.events.length)} />
            </div>
            <div className="mt-4 space-y-2">
              {!publish || publish.events.length === 0 ? (
                <EmptyState text="No fleet hunt events published" />
              ) : (
                publish.events.map((event) => (
                  <div
                    key={event.eventId}
                    className="rounded-md px-3 py-2"
                    style={{
                      border: "1px solid rgba(27,34,48,0.78)",
                      background: "rgba(0,0,0,0.18)",
                    }}
                  >
                    <p
                      className="font-mono break-all"
                      style={{ color: "var(--text)", fontSize: "0.76rem" }}
                    >
                      {event.eventId}
                    </p>
                    <p
                      className="font-mono mt-1 break-all"
                      style={{ color: "rgba(154,167,181,0.62)", fontSize: "0.66rem" }}
                    >
                      {event.rawRef}
                    </p>
                  </div>
                ))
              )}
            </div>
          </Plate>
        </section>
      </div>
    </div>
  );
}

function TouchRow({
  touch,
  receiptFamily,
}: {
  touch: NonNullable<AgentSecretTouchesResponse["touches"][number]>;
  receiptFamily: string | null;
}) {
  const graphNodeCount = Object.keys(touch.graph.nodes ?? {}).length;
  const graphEdgeCount = touch.graph.edges?.length ?? 0;
  return (
    <div
      className="rounded-md p-3"
      style={{ border: "1px solid rgba(27,34,48,0.78)", background: "rgba(0,0,0,0.18)" }}
    >
      <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <p
            className="font-display"
            style={{ color: "var(--text)", fontSize: "1rem", fontWeight: 700 }}
          >
            {touch.name || touch.credentialLabel}
          </p>
          <p
            className="font-mono mt-1 break-all"
            style={{ color: "rgba(154,167,181,0.62)", fontSize: "0.66rem" }}
          >
            {touch.credentialNodeId}
          </p>
        </div>
        <StatusPill value={touch.credentialKind || "credential"} />
      </div>

      <div className="mt-4 grid grid-cols-1 gap-3 lg:grid-cols-4">
        <SmallFact label="Path" value={touch.path || "-"} mono />
        <SmallFact label="Receipt" value={receiptFamily ?? "-"} />
        <SmallFact label="Graph Nodes" value={numberText(graphNodeCount)} />
        <SmallFact label="Graph Edges" value={numberText(graphEdgeCount)} />
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <TagList title="Agent Labels" values={touch.agentLabels} />
        <TagList title="Process Nodes" values={touch.processNodeIds} />
      </div>
    </div>
  );
}

function TextField({
  label,
  value,
  onChange,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
}) {
  return (
    <label className="flex flex-col gap-1">
      <span className="font-mono uppercase tracking-[0.12em] text-[0.65rem] text-[rgba(154,167,181,0.62)]">
        {label}
      </span>
      <input
        aria-label={label}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="glass-input font-mono rounded-md px-3 py-2 text-sm outline-none"
        style={{ color: "var(--text)", minWidth: 0 }}
      />
    </label>
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
        aria-label={label}
        type="number"
        min={min}
        max={max}
        value={value}
        onChange={(event) => onChange(clampNumber(event.target.value, min, max, value))}
        className="glass-input font-mono rounded-md px-3 py-2 text-sm outline-none"
        style={{ color: "var(--text)" }}
      />
    </label>
  );
}

function CheckboxField({
  label,
  checked,
  onChange,
}: {
  label: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
}) {
  return (
    <label
      className="flex items-center justify-between gap-3 rounded-md px-3 py-2"
      style={{ border: "1px solid rgba(27,34,48,0.78)", background: "rgba(0,0,0,0.16)" }}
    >
      <span className="font-mono uppercase tracking-[0.12em] text-[0.65rem] text-[rgba(154,167,181,0.62)]">
        {label}
      </span>
      <input
        aria-label={label}
        type="checkbox"
        checked={checked}
        onChange={(event) => onChange(event.target.checked)}
      />
    </label>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
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
        style={{ position: "relative", color: "var(--text)", fontSize: "1.08rem", fontWeight: 700 }}
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
        className={mono ? "font-mono mt-1 break-all" : "font-body mt-1 truncate"}
        style={{ color: "var(--text)", fontSize: mono ? "0.72rem" : "0.88rem" }}
      >
        {value}
      </p>
    </div>
  );
}

function StatusPill({ value }: { value: string }) {
  return (
    <span
      className="font-mono rounded-md px-3 py-1"
      style={{
        border: "1px solid rgba(214,177,90,0.36)",
        background: "rgba(214,177,90,0.08)",
        color: "var(--gold)",
        fontSize: "0.72rem",
        alignSelf: "flex-start",
      }}
    >
      {value}
    </span>
  );
}

function TagList({ title, values }: { title: string; values: string[] }) {
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
        {values.length === 0 ? (
          <EmptyState text="None" />
        ) : (
          values.map((value) => <Tag key={value}>{value}</Tag>)
        )}
      </div>
    </div>
  );
}

function Tag({ children }: { children: string }) {
  return (
    <span
      className="font-mono rounded-md px-2 py-1"
      style={{
        border: "1px solid rgba(27,34,48,0.82)",
        background: "rgba(0,0,0,0.22)",
        color: "var(--text)",
        fontSize: "0.66rem",
      }}
    >
      {children}
    </span>
  );
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

function buildQuery(input: {
  sessionId: string;
  credentialKind: string;
  requireAgentContext: boolean;
  upstreamDepth: number;
  downstreamDepth: number;
  limit: number;
}): AgentSecretTouchesInput {
  return {
    ...(input.sessionId.trim() && { sessionId: input.sessionId.trim() }),
    ...(input.credentialKind.trim() && { credentialKind: input.credentialKind.trim() }),
    requireAgentContext: input.requireAgentContext,
    upstreamDepth: input.upstreamDepth,
    downstreamDepth: input.downstreamDepth,
    limit: input.limit,
  };
}

function receiptFamilyText(receipt: SignedReceiptJson | undefined): string | null {
  const receiptValue = isRecord(receipt?.receipt) ? receipt.receipt : null;
  const metadata = isRecord(receiptValue?.metadata) ? receiptValue.metadata : null;
  const decision = isRecord(metadata?.endpointDecision) ? metadata.endpointDecision : null;
  const family = decision?.receiptFamily;
  return typeof family === "string" && family.trim() ? family : null;
}

function numberText(value: number | undefined): string {
  return typeof value === "number" ? String(value) : "-";
}

function clampNumber(raw: string, min: number, max: number, fallback: number): number {
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

function safeFilenameId(value: string): string {
  return value.trim().replace(/[^A-Za-z0-9_.-]+/g, "-") || "all";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
