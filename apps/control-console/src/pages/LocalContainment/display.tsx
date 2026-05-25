import { type ResponseExecutionRecord } from "../../api/client";
import { NoiseGrain, Plate } from "../../components/ui";
import {
  attributionIdentityLabels,
  attributionToolLabels,
  numberText,
} from "./utils";

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

export function ExecutionSummary({ record }: { record?: ResponseExecutionRecord }) {
  if (!record) return <EmptyState text="No response execution selected" />;
  const affectedIdentityLabels = attributionIdentityLabels(record);
  const affectedToolLabels = attributionToolLabels(record);
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 gap-3 md:grid-cols-4">
        <SmallFact label="Execution ID" value={record.execution.executionId} mono />
        <SmallFact label="Action" value={record.execution.action ?? "-"} />
        <SmallFact label="Status" value={record.execution.status ?? "-"} />
        <SmallFact label="Expires" value={record.expiresAt ?? "-"} />
        <SmallFact label="Expired" value={String(record.expired)} />
        <SmallFact label="Effects" value={numberText(record.execution.effects?.length)} />
        <SmallFact label="Identities" value={numberText(record.affectedIdentityCount)} />
        <SmallFact label="Tools" value={numberText(record.affectedToolCount)} />
      </div>
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <LabelList
          label="Responsible Identities"
          items={affectedIdentityLabels}
          emptyText="No identity context loaded"
        />
        <LabelList
          label="Responsible Tools"
          items={affectedToolLabels}
          emptyText="No tool-call context loaded"
        />
      </div>
    </div>
  );
}

export function EffectRow({ effect }: { effect: { effectType?: string; target?: string } }) {
  return (
    <div
      className="rounded-md px-3 py-2"
      style={{ border: "1px solid rgba(27,34,48,0.78)", background: "rgba(0,0,0,0.18)" }}
    >
      <p className="font-body" style={{ color: "var(--text)", fontSize: "0.88rem" }}>
        {effect.effectType ?? "-"}
      </p>
      <p
        className="font-mono mt-1 break-all"
        style={{ color: "rgba(154,167,181,0.58)", fontSize: "0.66rem" }}
      >
        {effect.target ?? "-"}
      </p>
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

export function LabelList({
  label,
  items,
  emptyText,
}: {
  label: string;
  items: string[];
  emptyText: string;
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
      <div className="mt-2 flex flex-wrap gap-2">
        {items.length === 0 ? (
          <EmptyState text={emptyText} />
        ) : (
          items.map((item) => <Tag key={item}>{item}</Tag>)
        )}
      </div>
    </div>
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
