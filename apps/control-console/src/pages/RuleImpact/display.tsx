import {
  type PolicySimulationAffectedNode,
  type PolicySimulationIdentityContext,
  type PolicySimulationToolContext,
} from "../../api/client";
import { NoiseGrain, Plate } from "../../components/ui";

export function Metric({ label, value }: { label: string; value: string }) {
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

export function PanelTitle({ eyebrow, title }: { eyebrow: string; title: string }) {
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

export function SmallFact({
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

export function StatusPill({ value }: { value: string }) {
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

export function StageRow({
  stage,
  action,
  gate,
  recommended,
}: {
  stage: string;
  action: string;
  gate: string;
  recommended: boolean;
}) {
  return (
    <div
      className="rounded-md px-3 py-2"
      style={{ border: "1px solid rgba(27,34,48,0.78)", background: "rgba(0,0,0,0.18)" }}
    >
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div className="min-w-0">
          <p className="font-body truncate" style={{ color: "var(--text)", fontSize: "0.88rem" }}>
            {stage}
          </p>
          <p
            className="font-body mt-1"
            style={{ color: "rgba(229,231,235,0.66)", fontSize: "0.78rem" }}
          >
            {gate}
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Tag>{action}</Tag>
          {recommended && <Tag>recommended</Tag>}
        </div>
      </div>
    </div>
  );
}

export function AffectedNodeRow({ node }: { node: PolicySimulationAffectedNode }) {
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

export function IdentityContextRow({ identity }: { identity: PolicySimulationIdentityContext }) {
  return (
    <ContextRow
      primary={identity.value}
      secondary={identity.sourceNodeId}
      tags={[identity.identityKind, identity.sourceNodeKind]}
    />
  );
}

export function ToolContextRow({ tool }: { tool: PolicySimulationToolContext }) {
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
          {tags.map((tag, index) => (
            <Tag key={`${tag}:${index}`}>{tag}</Tag>
          ))}
        </div>
      </div>
    </div>
  );
}

export function Tag({ children }: { children: string }) {
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

export function StatusBanner({ message }: { message: string }) {
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

export function EmptyState({ text }: { text: string }) {
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
