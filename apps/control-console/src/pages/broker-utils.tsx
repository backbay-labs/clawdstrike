import type { ReactNode } from "react";
import type {
  BrokerCapabilityState,
  BrokerCapabilityStatus,
  BrokerExecutionOutcome,
  BrokerExecutionPhase,
  BrokerFrozenProviderStatus,
  BrokerProvider,
  BrokerReplayResponse,
} from "../api/client";
import { NoiseGrain, Stamp } from "../components/ui";

export type StampVariant = "allowed" | "blocked" | "warn";

export const KNOWN_PROVIDERS: BrokerProvider[] = ["openai", "github", "slack", "generic_https"];

export function formatCost(value?: number): string {
  if (value == null) return "-";
  return `$${(value / 1_000_000).toFixed(4)}`;
}

export function shortValue(value?: string, edge = 12): string {
  if (!value) return "-";
  if (value.length <= edge * 2 + 3) return value;
  return `${value.slice(0, edge)}...${value.slice(-edge)}`;
}

export function statusVariant(state: BrokerCapabilityState): StampVariant {
  if (state === "active") return "allowed";
  if (state === "frozen") return "warn";
  return "blocked";
}

export function executionVariant(phase: BrokerExecutionPhase, outcome?: BrokerExecutionOutcome): StampVariant {
  if (phase === "started") return "warn";
  return outcome === "success" ? "allowed" : "blocked";
}

export function replayVariant(result: BrokerReplayResponse | null): StampVariant {
  if (!result) return "warn";
  return result.would_allow ? "allowed" : "blocked";
}

export function formatDateTime(value?: string): string {
  if (!value) return "-";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

export function formatRelative(value?: string): string {
  if (!value) return "-";
  const deltaMs = new Date(value).getTime() - Date.now();
  const deltaMin = Math.round(deltaMs / 60_000);
  if (Math.abs(deltaMin) < 1) return "now";
  if (deltaMin > 0) return `in ${deltaMin}m`;
  return `${Math.abs(deltaMin)}m ago`;
}

export function uniqueProviders(
  capabilities: BrokerCapabilityStatus[],
  frozenProviders: BrokerFrozenProviderStatus[],
  extraProviders: { provider: BrokerProvider }[] = [],
): BrokerProvider[] {
  return Array.from(
    new Set<BrokerProvider>([
      ...KNOWN_PROVIDERS,
      ...capabilities.map((capability) => capability.provider),
      ...frozenProviders.map((provider) => provider.provider),
      ...extraProviders.map((item) => item.provider),
    ]),
  );
}

export function DetailItem({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <div className="font-mono text-[11px]" style={{ color: "rgba(154,167,181,0.7)" }}>
        {label}
      </div>
      <div className="mt-1">{children}</div>
    </div>
  );
}

export function HintBlock({ children }: { children: ReactNode }) {
  return (
    <div className="font-mono" style={{ padding: 16, color: "rgba(154,167,181,0.65)" }}>
      {children}
    </div>
  );
}

export function PanelHeader({ title, meta }: { title: string; meta: string }) {
  return (
    <div
      className="flex items-center justify-between"
      style={{ padding: "16px 16px 12px 16px", borderBottom: "1px solid rgba(27,34,48,0.8)" }}
    >
      <div className="font-mono text-xs uppercase" style={{ letterSpacing: "0.08em" }}>
        {title}
      </div>
      <div className="font-mono text-xs" style={{ color: "rgba(154,167,181,0.72)" }}>
        {meta}
      </div>
    </div>
  );
}

const TAG_STYLE = {
  border: "1px solid rgba(27,34,48,0.8)",
  background: "rgba(8,10,14,0.92)",
  color: "rgba(154,167,181,0.86)",
} as const;

export function Tag({ children }: { children: ReactNode }) {
  return (
    <span
      className="inline-flex items-center rounded-full px-2.5 py-1 font-mono text-[11px]"
      style={TAG_STYLE}
    >
      {children}
    </span>
  );
}

export function Stack({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <div className="font-mono text-[11px]" style={{ color: "rgba(154,167,181,0.72)" }}>
        {label}
      </div>
      <div className="mt-2 flex flex-wrap gap-2">{children}</div>
    </div>
  );
}

export function Banner({
  children,
  variant,
}: {
  children: ReactNode;
  variant: "allowed" | "blocked";
}) {
  const color = variant === "allowed" ? "var(--stamp-allowed)" : "var(--crimson)";
  const border = variant === "allowed" ? "rgba(63,160,112,0.3)" : "rgba(194,59,59,0.35)";
  return (
    <div
      className="glass-panel font-mono text-sm"
      style={{ padding: 12, color, borderColor: border }}
    >
      {children}
    </div>
  );
}

export function MetricCard({
  label,
  value,
  variant,
}: {
  label: string;
  value: number;
  variant: StampVariant;
}) {
  return (
    <div className="glass-panel" style={{ padding: 16 }}>
      <NoiseGrain />
      <div className="font-mono text-[11px]" style={{ color: "rgba(154,167,181,0.72)" }}>
        {label}
      </div>
      <div className="mt-2 flex items-center justify-between gap-3">
        <div className="font-display text-3xl">{value}</div>
        <Stamp variant={variant}>{label}</Stamp>
      </div>
    </div>
  );
}
