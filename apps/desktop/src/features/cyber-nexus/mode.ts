import type { NexusOperationMode } from "./types";

export const NEXUS_MODE_STORAGE_KEY = "sdr:cyber-nexus:operation-mode";
export const CYBER_NEXUS_MODE_EVENT = "cyber-nexus:operation-mode";

export interface NexusModeDescriptor {
  id: NexusOperationMode;
  label: string;
  description: string;
  tone: "gold" | "amber" | "crimson";
}

export const NEXUS_MODES: readonly NexusModeDescriptor[] = [
  {
    id: "observe",
    label: "Observe",
    description: "Passive posture with minimal intervention.",
    tone: "gold",
  },
  {
    id: "trace",
    label: "Trace",
    description: "Increase telemetry and follow active paths.",
    tone: "gold",
  },
  {
    id: "contain",
    label: "Contain",
    description: "Constrain movement and tighten guardrails.",
    tone: "amber",
  },
  {
    id: "execute",
    label: "Execute",
    description: "Run direct response actions.",
    tone: "crimson",
  },
] as const;

export function isNexusOperationMode(value: string): value is NexusOperationMode {
  return NEXUS_MODES.some((mode) => mode.id === value);
}

export function getNexusModeDescriptor(mode: NexusOperationMode): NexusModeDescriptor {
  return NEXUS_MODES.find((entry) => entry.id === mode) ?? NEXUS_MODES[0];
}

export function getNexusOperationMode(): NexusOperationMode {
  if (typeof window === "undefined") {
    return "observe";
  }

  try {
    const stored = window.localStorage.getItem(NEXUS_MODE_STORAGE_KEY);
    if (stored && isNexusOperationMode(stored)) {
      return stored;
    }
  } catch {
    // Ignore storage access errors.
  }

  return "observe";
}

export function cycleNexusOperationMode(current: NexusOperationMode): NexusOperationMode {
  const index = NEXUS_MODES.findIndex((mode) => mode.id === current);
  const next = index < 0 ? 0 : (index + 1) % NEXUS_MODES.length;
  return NEXUS_MODES[next].id;
}

export function setNexusOperationMode(mode: NexusOperationMode) {
  if (typeof window === "undefined") return;

  try {
    window.localStorage.setItem(NEXUS_MODE_STORAGE_KEY, mode);
  } catch {
    // Ignore storage access errors.
  }

  window.dispatchEvent(
    new CustomEvent<NexusOperationMode>(CYBER_NEXUS_MODE_EVENT, { detail: mode }),
  );
}
