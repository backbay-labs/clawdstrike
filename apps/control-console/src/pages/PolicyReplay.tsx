import { useMemo, useState } from "react";
import {
  createPolicyReplay,
  type EndpointDecisionAction,
  type PolicyReplayResponse,
  type SignedReceiptJson,
} from "../api/client";
import { GlassButton, NoiseGrain, Plate } from "../components/ui";
import { exportAsJSON } from "../utils/exportData";

const DEFAULT_MAX_DEPTH = 8;
const REPLAY_ACTIONS: EndpointDecisionAction[] = [
  "block",
  "warn",
  "observe",
  "restrict_egress",
  "suspend_process_tree",
  "collect_evidence",
];

export function PolicyReplay(_props: { windowId?: string }) {
  const [rootNodeId, setRootNodeId] = useState("");
  const [processGuid, setProcessGuid] = useState("");
  const [action, setAction] = useState<EndpointDecisionAction>("block");
  const [maxDepth, setMaxDepth] = useState(DEFAULT_MAX_DEPTH);
  const [ruleId, setRuleId] = useState("");
  const [description, setDescription] = useState("");
  const [replay, setReplay] = useState<PolicyReplayResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const receiptFamily = useMemo(() => receiptFamilyText(replay?.receipt), [replay]);
  const policyEpoch = replay?.replay.policy.policyEpoch;
  const nodeKinds = useMemo(() => graphNodeKinds(replay), [replay]);
  const affectedIdentities = replay?.simulation.affectedIdentities ?? [];
  const affectedTools = replay?.simulation.affectedTools ?? [];

  async function runReplay() {
    const target = buildTargetInput(rootNodeId, processGuid);
    if (!target) {
      setError("Root Node ID or Process GUID is required");
      return;
    }

    setLoading(true);
    try {
      const response = await createPolicyReplay({
        ...target,
        action,
        maxDepth,
        ...(ruleId.trim() && { ruleId: ruleId.trim() }),
        ...(description.trim() && { description: description.trim() }),
      });
      setReplay(response);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to replay policy");
    } finally {
      setLoading(false);
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
            Current policy graph replay
          </p>
          <h1
            className="font-display"
            style={{ fontSize: "1.85rem", fontWeight: 700, letterSpacing: 0, marginTop: 2 }}
          >
            Policy Replay
          </h1>
        </div>

        <div className="flex flex-wrap gap-2">
          <GlassButton variant="primary" onClick={runReplay} disabled={loading}>
            {loading ? "Replaying..." : "Replay Policy"}
          </GlassButton>
          <GlassButton
            onClick={() =>
              replay &&
              exportAsJSON([replay], `policy-replay-${safeFilenameId(replay.replay.replayId)}`)
            }
            disabled={!replay}
          >
            Export JSON
          </GlassButton>
        </div>
      </header>

      {error && <StatusBanner message={error} />}

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-[minmax(320px,0.78fr)_minmax(0,1.22fr)]">
        <Plate className="p-4">
          <PanelTitle eyebrow="Target" title="Incident Graph" />
          <div className="mt-4 space-y-3">
            <TextField label="Root Node ID" value={rootNodeId} onChange={setRootNodeId} />
            <TextField label="Process GUID" value={processGuid} onChange={setProcessGuid} />
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <label className="flex flex-col gap-1">
                <span className="font-mono uppercase tracking-[0.12em] text-[0.65rem] text-[rgba(154,167,181,0.62)]">
                  Action
                </span>
                <select
                  value={action}
                  onChange={(event) => setAction(event.target.value as EndpointDecisionAction)}
                  className="glass-input font-mono rounded-md px-3 py-2 text-sm outline-none"
                  style={{ color: "var(--text)", background: "rgba(7,8,10,0.72)" }}
                >
                  {REPLAY_ACTIONS.map((item) => (
                    <option key={item} value={item}>
                      {item}
                    </option>
                  ))}
                </select>
              </label>
              <NumberField
                label="Max Depth"
                value={maxDepth}
                min={1}
                max={8}
                onChange={setMaxDepth}
              />
            </div>
            <TextField label="Rule ID" value={ruleId} onChange={setRuleId} />
            <TextField label="Description" value={description} onChange={setDescription} />
          </div>
        </Plate>

        <section className="space-y-5">
          <div className="grid grid-cols-1 gap-3 md:grid-cols-4">
            <Metric label="Policy" value={replay?.replay.policy.policyVersion ?? "-"} />
            <Metric label="Epoch" value={policyEpoch == null ? "-" : `Epoch ${policyEpoch}`} />
            <Metric
              label="Breakage"
              value={replay ? `${replay.replay.developerBreakageScore}/100` : "-"}
            />
            <Metric label="Impact" value={replay?.replay.impactLevel ?? "-"} />
          </div>

          <Plate className="p-4" goldEdge>
            <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
              <PanelTitle
                eyebrow={replay ? "Replay Result" : "No replay"}
                title={replay?.replay.rootLabel ?? "Replay Result"}
              />
              <StatusPill
                value={replay ? `Would enforce: ${replay.replay.wouldEnforce ? "yes" : "no"}` : "-"}
              />
            </div>
            <div className="mt-4 grid grid-cols-1 gap-3 lg:grid-cols-3">
              <SmallFact label="Mode" value={replay?.replay.mode ?? "-"} />
              <SmallFact label="Graph Slice" value={replay?.replay.graphSliceId ?? "-"} mono />
              <SmallFact label="Receipt" value={receiptFamily ?? "-"} />
              <SmallFact label="Root" value={replay?.replay.rootNodeId ?? "-"} mono />
              <SmallFact label="Observations" value={numberText(replay?.replay.observationCount)} />
              <SmallFact
                label="Flight Recorder"
                value={numberText(replay?.replay.flightRecorderObservationCount)}
              />
            </div>
            {replay && (
              <p
                className="font-body mt-4"
                style={{ color: "rgba(229,231,235,0.78)", fontSize: "0.88rem" }}
              >
                {replay.replay.summary}
              </p>
            )}
          </Plate>

          <div className="grid grid-cols-1 gap-5 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
            <Plate className="p-4">
              <PanelTitle eyebrow="Simulation" title="Affected Nodes" />
              <div className="mt-4 space-y-2">
                {!replay || replay.simulation.affectedNodes.length === 0 ? (
                  <EmptyState text="No affected nodes" />
                ) : (
                  replay.simulation.affectedNodes.map((node) => (
                    <AffectedNodeRow key={node.nodeId} node={node} />
                  ))
                )}
              </div>
            </Plate>

            <Plate className="p-4">
              <PanelTitle eyebrow="Evidence" title="Policy + Graph Binding" />
              <div className="mt-4 space-y-4">
                <SmallFact label="Rule ID" value={replay?.simulation.ruleId ?? "-"} mono />
                <SmallFact label="Simulation" value={replay?.simulation.simulationId ?? "-"} mono />
                <SmallFact
                  label="Would Block"
                  value={replay ? String(replay.simulation.wouldBlock) : "-"}
                />
                <SmallFact
                  label="Policy Hash"
                  value={replay?.replay.policy.policyHash ?? "-"}
                  mono
                />
                <FactList title="Graph Node Kinds" items={nodeKinds} />
              </div>
            </Plate>
          </div>

          <Plate className="p-4">
            <PanelTitle eyebrow="Attribution" title="Affected Identities and Tools" />
            <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
              <div className="space-y-2">
                {!replay || affectedIdentities.length === 0 ? (
                  <EmptyState text="No affected identities" />
                ) : (
                  affectedIdentities.map((identity) => (
                    <IdentityContextRow
                      key={`${identity.identityKind}:${identity.value}:${identity.sourceNodeId}`}
                      identity={identity}
                    />
                  ))
                )}
              </div>
              <div className="space-y-2">
                {!replay || affectedTools.length === 0 ? (
                  <EmptyState text="No affected tools" />
                ) : (
                  affectedTools.map((tool) => (
                    <ToolContextRow
                      key={`${tool.toolName}:${tool.toolCallId ?? ""}:${tool.sourceNodeId}`}
                      tool={tool}
                    />
                  ))
                )}
              </div>
            </div>
          </Plate>
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
      }}
    >
      {value}
    </span>
  );
}

function AffectedNodeRow({
  node,
}: {
  node: PolicyReplayResponse["simulation"]["affectedNodes"][number];
}) {
  return (
    <div
      className="rounded-md px-3 py-2"
      style={{ border: "1px solid rgba(27,34,48,0.78)", background: "rgba(0,0,0,0.18)" }}
    >
      <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <p className="font-body truncate" style={{ color: "var(--text)", fontSize: "0.88rem" }}>
            {node.label}
          </p>
          <p
            className="font-mono mt-1 break-all"
            style={{ color: "rgba(154,167,181,0.58)", fontSize: "0.66rem" }}
          >
            {node.nodeId}
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Tag>{node.kind}</Tag>
          <Tag>{`${node.breakageScore}/100`}</Tag>
        </div>
      </div>
      <p
        className="font-body mt-2"
        style={{ color: "rgba(229,231,235,0.66)", fontSize: "0.78rem" }}
      >
        {node.reason}
      </p>
    </div>
  );
}

function IdentityContextRow({
  identity,
}: {
  identity: NonNullable<PolicyReplayResponse["simulation"]["affectedIdentities"]>[number];
}) {
  return (
    <ContextRow
      primary={identity.value}
      secondary={identity.sourceNodeId}
      tags={[identity.identityKind, identity.sourceNodeKind]}
    />
  );
}

function ToolContextRow({
  tool,
}: {
  tool: NonNullable<PolicyReplayResponse["simulation"]["affectedTools"]>[number];
}) {
  return (
    <ContextRow
      primary={tool.toolName}
      secondary={tool.toolCallId ? `${tool.sourceNodeId} / ${tool.toolCallId}` : tool.sourceNodeId}
      tags={tool.toolCallId ? ["tool", "tool call"] : ["tool"]}
    />
  );
}

function ContextRow({
  primary,
  secondary,
  tags,
}: {
  primary: string;
  secondary: string;
  tags: string[];
}) {
  return (
    <div
      className="rounded-md px-3 py-2"
      style={{ border: "1px solid rgba(27,34,48,0.78)", background: "rgba(0,0,0,0.18)" }}
    >
      <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <p className="font-body truncate" style={{ color: "var(--text)", fontSize: "0.88rem" }}>
            {primary}
          </p>
          <p
            className="font-mono mt-1 break-all"
            style={{ color: "rgba(154,167,181,0.58)", fontSize: "0.66rem" }}
          >
            {secondary}
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          {tags.map((tag) => (
            <Tag key={tag}>{tag}</Tag>
          ))}
        </div>
      </div>
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
          <EmptyState text="No graph node kinds" />
        ) : (
          items.map((item) => <Tag key={item}>{item}</Tag>)
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

function buildTargetInput(rootNodeId: string, processGuid: string) {
  const root = rootNodeId.trim();
  if (root) return { rootNodeId: root };
  const guid = processGuid.trim();
  if (guid) return { process: { processGuid: guid } };
  return null;
}

function receiptFamilyText(receipt: SignedReceiptJson | undefined): string | null {
  const receiptValue = isRecord(receipt?.receipt) ? receipt.receipt : null;
  const metadata = isRecord(receiptValue?.metadata) ? receiptValue.metadata : null;
  const decision = isRecord(metadata?.endpointDecision) ? metadata.endpointDecision : null;
  const family = decision?.receiptFamily;
  return typeof family === "string" && family.trim() ? family : null;
}

function graphNodeKinds(replay: PolicyReplayResponse | null): string[] {
  const nodes = replay?.graph.nodes ?? {};
  return Array.from(
    new Set(
      Object.values(nodes)
        .map((node) => node.kind)
        .filter(isString),
    ),
  ).sort();
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
  return value.trim().replace(/[^A-Za-z0-9_.-]+/g, "-") || "unknown";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}
