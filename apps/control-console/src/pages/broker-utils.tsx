import type { ReactNode } from "react";
import type {
  BrokerCapabilityState,
  BrokerCapabilityStatus,
  BrokerFrozenProviderStatus,
  BrokerProvider,
  BrokerReplayResponse,
} from "../api/client";

export const KNOWN_PROVIDERS: BrokerProvider[] = ["openai", "github", "slack", "generic_https"];

export function statusVariant(state: BrokerCapabilityState): "allowed" | "blocked" | "warn" {
  if (state === "active") return "allowed";
  if (state === "frozen") return "warn";
  return "blocked";
}

export function replayVariant(result: BrokerReplayResponse | null): "allowed" | "blocked" | "warn" {
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

export function DetailItem({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  return (
    <div>
      <div className="font-mono text-[11px]" style={{ color: "rgba(154,167,181,0.7)" }}>
        {label}
      </div>
      <div className="mt-1">{children}</div>
    </div>
  );
}
