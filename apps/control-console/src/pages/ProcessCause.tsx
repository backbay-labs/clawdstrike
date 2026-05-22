import { useMemo, useState } from "react";
import {
  type CausalContextResponse,
  type CausalGraphEdge,
  type CausalGraphJson,
  type CausalGraphNode,
  type CausalSliceAffectedIdentities,
  type CausalSliceAffectedTool,
  type CausalSubgraphResponse,
  createCausalContext,
  createCausalSubgraph,
  exportGraphSlice,
  type GraphSliceExportResponse,
  type GraphSliceKind,
  type SignedReceiptJson,
} from "../api/client";
import { GlassButton, NoiseGrain, Plate } from "../components/ui";
import { exportAsJSON } from "../utils/exportData";

const DEFAULT_MAX_DEPTH = 3;
const DEFAULT_UPSTREAM_DEPTH = 3;
const DEFAULT_DOWNSTREAM_DEPTH = 1;
const DEFAULT_REASON = "operator graph-slice export";

type SliceMode = "causal_subgraph" | "causal_context";

interface ActiveSlice {
  mode: SliceMode;
  rootNodeId: string;
  depthLabel: string;
  nodeCount: number;
  edgeCount: number;
  graph: CausalGraphJson;
  affectedIdentityCount: number;
  affectedToolCount: number;
  affectedIdentities?: CausalSliceAffectedIdentities;
  affectedTools?: CausalSliceAffectedTool[];
  receipt: SignedReceiptJson;
}

export function ProcessCause(_props: { windowId?: string }) {
  const [rootNodeId, setRootNodeId] = useState("");
  const [processGuid, setProcessGuid] = useState("");
  const [maxDepth, setMaxDepth] = useState(DEFAULT_MAX_DEPTH);
  const [upstreamDepth, setUpstreamDepth] = useState(DEFAULT_UPSTREAM_DEPTH);
  const [downstreamDepth, setDownstreamDepth] = useState(DEFAULT_DOWNSTREAM_DEPTH);
  const [sliceKind, setSliceKind] = useState<GraphSliceKind>("causal_subgraph");
  const [reason, setReason] = useState(DEFAULT_REASON);
  const [slice, setSlice] = useState<ActiveSlice | null>(null);
  const [exportedSlice, setExportedSlice] = useState<GraphSliceExportResponse | null>(null);
  const [loading, setLoading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const graphNodes = useMemo(() => graphNodeRows(slice?.graph), [slice]);
  const graphEdges = slice?.graph.edges ?? [];
  const receiptFamily = useMemo(() => receiptFamilyText(slice?.receipt), [slice]);
  const graphSliceId = useMemo(() => graphSliceIdText(slice?.receipt), [slice]);
  const affectedIdentityItems = useMemo(() => causalSliceIdentityLabels(slice), [slice]);
  const affectedToolItems = useMemo(() => causalSliceToolLabels(slice), [slice]);

  async function showEffects() {
    const target = buildTargetInput(rootNodeId, processGuid);
    if (!target) {
      setError("Root Node ID or Process GUID is required");
      return;
    }

    setLoading("subgraph");
    try {
      const response = await createCausalSubgraph({ ...target, maxDepth });
      setSlice(fromSubgraphResponse(response));
      setSliceKind("causal_subgraph");
      setExportedSlice(null);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load process effects");
    } finally {
      setLoading(null);
    }
  }

  async function showContext() {
    const target = buildTargetInput(rootNodeId, processGuid);
    if (!target) {
      setError("Root Node ID or Process GUID is required");
      return;
    }

    setLoading("context");
    try {
      const response = await createCausalContext({
        ...target,
        upstreamDepth,
        downstreamDepth,
      });
      setSlice(fromContextResponse(response));
      setSliceKind("causal_context");
      setExportedSlice(null);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load causal context");
    } finally {
      setLoading(null);
    }
  }

  async function persistGraphSlice() {
    const target = slice
      ? { rootNodeId: slice.rootNodeId }
      : buildTargetInput(rootNodeId, processGuid);
    if (!target) {
      setError("Root Node ID or Process GUID is required");
      return;
    }

    setLoading("export");
    try {
      const response = await exportGraphSlice({
        ...target,
        sliceKind,
        ...(sliceKind === "causal_context" ? { upstreamDepth, downstreamDepth } : { maxDepth }),
        ...(reason.trim() && { reason: reason.trim() }),
      });
      setExportedSlice(response);
      setSlice(fromExportResponse(response));
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to export graph slice");
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
            Local causal graph
          </p>
          <h1
            className="font-display"
            style={{ fontSize: "1.85rem", fontWeight: 700, letterSpacing: 0, marginTop: 2 }}
          >
            Process Cause
          </h1>
        </div>

        <div className="flex flex-wrap gap-2">
          <GlassButton variant="primary" onClick={showEffects} disabled={loading !== null}>
            {loading === "subgraph" ? "Loading..." : "Show Effects"}
          </GlassButton>
          <GlassButton onClick={showContext} disabled={loading !== null}>
            {loading === "context" ? "Loading..." : "Show Context"}
          </GlassButton>
          <GlassButton onClick={persistGraphSlice} disabled={loading !== null}>
            {loading === "export" ? "Exporting..." : "Export Slice"}
          </GlassButton>
        </div>
      </header>

      {error && <StatusBanner message={error} />}

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-[minmax(320px,0.78fr)_minmax(0,1.22fr)]">
        <Plate className="p-4">
          <PanelTitle eyebrow="Target" title="Process or Root Node" />
          <div className="mt-4 space-y-3">
            <TextField label="Root Node ID" value={rootNodeId} onChange={setRootNodeId} />
            <TextField label="Process GUID" value={processGuid} onChange={setProcessGuid} />
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
              <NumberField
                label="Max Depth"
                value={maxDepth}
                min={1}
                max={8}
                onChange={setMaxDepth}
              />
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
            </div>
            <label className="flex flex-col gap-1">
              <span className="font-mono uppercase tracking-[0.12em] text-[0.65rem] text-[rgba(154,167,181,0.62)]">
                Slice Kind
              </span>
              <select
                value={sliceKind}
                onChange={(event) => setSliceKind(event.target.value as GraphSliceKind)}
                className="glass-input font-mono rounded-md px-3 py-2 text-sm outline-none"
                style={{ color: "var(--text)", background: "rgba(7,8,10,0.72)" }}
              >
                <option value="causal_subgraph">causal_subgraph</option>
                <option value="causal_context">causal_context</option>
              </select>
            </label>
            <TextField label="Export Reason" value={reason} onChange={setReason} />
          </div>
        </Plate>

        <section className="space-y-5">
          <div className="grid grid-cols-1 gap-3 md:grid-cols-4">
            <Metric label="Root" value={slice?.rootNodeId ?? "-"} mono />
            <Metric label="Nodes" value={numberText(slice?.nodeCount)} />
            <Metric label="Edges" value={numberText(slice?.edgeCount)} />
            <Metric label="Receipt" value={receiptFamily ?? "-"} />
          </div>

          <Plate className="p-4" goldEdge>
            <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
              <PanelTitle eyebrow={slice?.depthLabel ?? "No slice"} title={sliceTitle(slice)} />
              <GlassButton
                onClick={() =>
                  exportedSlice && exportAsJSON([exportedSlice], graphExportFilename(exportedSlice))
                }
                disabled={!exportedSlice}
              >
                Export JSON
              </GlassButton>
            </div>
            <div className="mt-4 grid grid-cols-1 gap-3 lg:grid-cols-5">
              <SmallFact label="Context" value={slice ? `Context: ${slice.mode}` : "-"} />
              <SmallFact
                label="Graph Slice"
                value={graphSliceId ?? exportedSlice?.bundle.graphSliceId ?? "-"}
                mono
              />
              <SmallFact label="Bundle" value={exportedSlice?.bundle.bundleId ?? "-"} mono />
              <SmallFact label="Identities" value={numberText(slice?.affectedIdentityCount)} />
              <SmallFact label="Tools" value={numberText(slice?.affectedToolCount)} />
            </div>
            {exportedSlice && (
              <div className="mt-4 grid grid-cols-1 gap-3 lg:grid-cols-3">
                <SmallFact label="Artifact Path" value={exportedSlice.artifact.path ?? "-"} mono />
                <SmallFact label="Content Hash" value={exportedSlice.bundle.contentHash} mono />
                <SmallFact label="Bytes" value={String(exportedSlice.artifact.byteCount)} />
              </div>
            )}
            <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
              <FactList title="Responsible Identities" items={affectedIdentityItems} />
              <FactList title="Responsible Tools" items={affectedToolItems} />
            </div>
          </Plate>

          <div className="grid grid-cols-1 gap-5 xl:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)]">
            <Plate className="p-4">
              <PanelTitle eyebrow="Graph" title="Nodes" />
              <div className="mt-4 max-h-[420px] space-y-2 overflow-y-auto pr-1">
                {graphNodes.length === 0 ? (
                  <EmptyState text="No graph nodes" />
                ) : (
                  graphNodes.map((node) => (
                    <GraphNodeRow key={node.id} nodeId={node.id} node={node.node} />
                  ))
                )}
              </div>
            </Plate>

            <Plate className="p-4">
              <PanelTitle eyebrow="Graph" title="Edges" />
              <div className="mt-4 max-h-[420px] space-y-2 overflow-y-auto pr-1">
                {graphEdges.length === 0 ? (
                  <EmptyState text="No graph edges" />
                ) : (
                  graphEdges.map((edge, index) => (
                    <GraphEdgeRow key={`${edge.from}:${edge.to}:${index}`} edge={edge} />
                  ))
                )}
              </div>
            </Plate>
          </div>
        </section>
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

function Metric({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
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
        className={mono ? "font-mono mt-2 truncate" : "font-display mt-2 truncate"}
        style={{ position: "relative", color: "var(--text)", fontSize: "1rem", fontWeight: 700 }}
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

function GraphNodeRow({ nodeId, node }: { nodeId: string; node: CausalGraphNode }) {
  return (
    <div
      className="rounded-md px-3 py-2"
      style={{ border: "1px solid rgba(27,34,48,0.78)", background: "rgba(0,0,0,0.18)" }}
    >
      <div className="flex min-w-0 items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="font-body truncate" style={{ color: "var(--text)", fontSize: "0.88rem" }}>
            {node.label ?? nodeId}
          </p>
          <p
            className="font-mono mt-1 break-all"
            style={{ color: "rgba(154,167,181,0.58)", fontSize: "0.66rem" }}
          >
            {nodeId}
          </p>
        </div>
        <Tag>{node.kind ?? "unknown"}</Tag>
      </div>
    </div>
  );
}

function GraphEdgeRow({ edge }: { edge: CausalGraphEdge }) {
  return (
    <div
      className="rounded-md px-3 py-2"
      style={{ border: "1px solid rgba(27,34,48,0.78)", background: "rgba(0,0,0,0.18)" }}
    >
      <div className="flex flex-wrap items-center gap-2">
        <Tag>{edge.kind ?? "edge"}</Tag>
        <span className="font-mono break-all text-xs" style={{ color: "var(--text)" }}>
          {edge.from ?? "-"} {"->"} {edge.to ?? "-"}
        </span>
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

function fromSubgraphResponse(response: CausalSubgraphResponse): ActiveSlice {
  return {
    mode: "causal_subgraph",
    rootNodeId: response.root_node_id,
    depthLabel: `Depth ${response.max_depth}`,
    nodeCount: response.node_count,
    edgeCount: response.edge_count,
    graph: response.graph,
    affectedIdentityCount: response.affected_identity_count ?? 0,
    affectedToolCount: response.affected_tool_count ?? 0,
    affectedIdentities: response.affected_identities,
    affectedTools: response.affected_tools,
    receipt: response.receipt,
  };
}

function fromContextResponse(response: CausalContextResponse): ActiveSlice {
  return {
    mode: "causal_context",
    rootNodeId: response.root_node_id,
    depthLabel: `Up ${response.upstream_depth} / Down ${response.downstream_depth}`,
    nodeCount: response.node_count,
    edgeCount: response.edge_count,
    graph: response.graph,
    affectedIdentityCount: response.affected_identity_count ?? 0,
    affectedToolCount: response.affected_tool_count ?? 0,
    affectedIdentities: response.affected_identities,
    affectedTools: response.affected_tools,
    receipt: response.receipt,
  };
}

function fromExportResponse(response: GraphSliceExportResponse): ActiveSlice {
  return {
    mode: response.sliceKind,
    rootNodeId: response.rootNodeId,
    depthLabel:
      response.sliceKind === "causal_context"
        ? "Persisted cause/effect context"
        : "Persisted downstream effects",
    nodeCount: response.nodeCount,
    edgeCount: response.edgeCount,
    graph: response.graph,
    affectedIdentityCount: response.affectedIdentityCount ?? 0,
    affectedToolCount: response.affectedToolCount ?? 0,
    affectedIdentities: response.affectedIdentities,
    affectedTools: response.affectedTools,
    receipt: response.receipt,
  };
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

function causalSliceIdentityLabels(slice: ActiveSlice | null): string[] {
  const identities = slice?.affectedIdentities;
  if (!identities) {
    return [];
  }
  return [
    ...(identities.hosts ?? []).map((identity) => `host:${identity.id}`),
    ...(identities.users ?? []).map((identity) => `user:${identity.id}`),
    ...(identities.sessions ?? []).map((identity) => `session:${identity.id}`),
    ...(identities.agents ?? []).map((identity) => `agent:${identity.id}`),
    ...(identities.workloads ?? []).map((identity) => `workload:${identity.id}`),
    ...(identities.approvals ?? []).map((identity) => `approval:${identity.id}`),
  ];
}

function causalSliceToolLabels(slice: ActiveSlice | null): string[] {
  return (slice?.affectedTools ?? []).map((tool) => tool.toolName);
}

function buildTargetInput(rootNodeId: string, processGuid: string) {
  const root = rootNodeId.trim();
  if (root) return { rootNodeId: root };
  const guid = processGuid.trim();
  if (guid) return { process: { processGuid: guid } };
  return null;
}

function graphNodeRows(graph: CausalGraphJson | undefined) {
  return Object.entries(graph?.nodes ?? {})
    .map(([id, node]) => ({ id, node }))
    .sort((left, right) => {
      const leftKind = left.node.kind ?? "";
      const rightKind = right.node.kind ?? "";
      return leftKind.localeCompare(rightKind) || left.id.localeCompare(right.id);
    });
}

function receiptFamilyText(receipt: SignedReceiptJson | undefined): string | null {
  const decision = endpointDecision(receipt);
  const family = decision?.receiptFamily;
  return typeof family === "string" && family.trim() ? family : null;
}

function graphSliceIdText(receipt: SignedReceiptJson | undefined): string | null {
  const decision = endpointDecision(receipt);
  const graph = isRecord(decision?.graph) ? decision.graph : null;
  const graphSliceId = graph?.graphSliceId;
  return typeof graphSliceId === "string" && graphSliceId.trim() ? graphSliceId : null;
}

function endpointDecision(receipt: SignedReceiptJson | undefined): Record<string, unknown> | null {
  const receiptValue = isRecord(receipt?.receipt) ? receipt.receipt : null;
  const metadata = isRecord(receiptValue?.metadata) ? receiptValue.metadata : null;
  return isRecord(metadata?.endpointDecision) ? metadata.endpointDecision : null;
}

function sliceTitle(slice: ActiveSlice | null): string {
  if (!slice) return "Process Effects";
  return slice.mode === "causal_context"
    ? "Cause and Effect Context"
    : "Downstream Process Effects";
}

function numberText(value: number | undefined): string {
  return typeof value === "number" ? String(value) : "-";
}

function clampNumber(raw: string, min: number, max: number, fallback: number): number {
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

function graphExportFilename(exportedSlice: GraphSliceExportResponse): string {
  return `graph-slice-${safeFilenameId(exportedSlice.bundle.bundleId)}`;
}

function safeFilenameId(value: string): string {
  return value.trim().replace(/[^A-Za-z0-9_.-]+/g, "-") || "unknown";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
