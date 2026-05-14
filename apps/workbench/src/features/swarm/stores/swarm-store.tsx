// Swarm Store — Zustand store for swarm CRUD & coordination
//
// Converted from Context+useReducer to Zustand with createSelectors.
// Preserves localStorage persistence with debounced writes.
import { useLayoutEffect } from "react";
import { create } from "zustand";
import { createSelectors } from "@/lib/create-selectors";
import type {
  Swarm,
  SwarmType,
  SwarmMember,
  SwarmPolicy,
  SwarmStats,
  TrustEdge,
  IntelRef,
  DetectionRef,
  SpeakeasyRef,
} from "@/lib/workbench/sentinel-types";
import { generateId } from "@/lib/workbench/sentinel-types";


export interface SwarmState {
  swarms: Swarm[];
  activeSwarmId: string | null;
  loading: boolean;
  invitationTracking: Record<string, { active: string[]; used: string[]; revoked: string[] }>;
}


function recomputeStats(swarm: Swarm): SwarmStats {
  const sentinelCount = swarm.members.filter((m) => m.type === "sentinel").length;
  const operatorCount = swarm.members.filter((m) => m.type === "operator").length;
  const totalRep = swarm.members.reduce((sum, m) => sum + m.reputation.overall, 0);
  const avgReputation = swarm.members.length > 0 ? totalRep / swarm.members.length : 0;

  return {
    memberCount: swarm.members.length,
    sentinelCount,
    operatorCount,
    intelShared: swarm.sharedIntel.length,
    activeDetections: swarm.sharedDetections.length,
    speakeasyCount: swarm.speakeasies.length,
    avgReputation,
  };
}


const STORAGE_KEY = "clawdstrike_workbench_swarms";
let lastSwarmStorageSnapshot =
  typeof window === "undefined" ? null : readSwarmStorageSnapshot();

function readSwarmStorageSnapshot(): string | null {
  try {
    return localStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
}

function persistSwarms(state: SwarmState): void {
  try {
    const persisted = {
      swarms: state.swarms,
      activeSwarmId: state.activeSwarmId,
      invitationTracking: state.invitationTracking,
    };
    const raw = JSON.stringify(persisted);
    localStorage.setItem(STORAGE_KEY, raw);
    lastSwarmStorageSnapshot = raw;
  } catch (e) {
    console.error("[swarm-store] persistSwarms failed:", e);
  }
}

function loadPersistedSwarms(): SwarmState | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || !Array.isArray(parsed.swarms)) {
      console.warn("[swarm-store] Invalid persisted swarm data, using defaults");
      return null;
    }

    // Validate each entry has required fields
    const validSwarms: Swarm[] = parsed.swarms.filter(
      (s: unknown): s is Swarm =>
        typeof s === "object" &&
        s !== null &&
        typeof (s as Record<string, unknown>).id === "string" &&
        typeof (s as Record<string, unknown>).name === "string" &&
        typeof (s as Record<string, unknown>).type === "string" &&
        Array.isArray((s as Record<string, unknown>).members),
    );

    if (validSwarms.length === 0) return null;

    const activeSwarmId =
      typeof parsed.activeSwarmId === "string" &&
      validSwarms.some((s) => s.id === parsed.activeSwarmId)
        ? parsed.activeSwarmId
        : validSwarms[0].id;

    const rawTracking =
      parsed.invitationTracking &&
      typeof parsed.invitationTracking === "object"
        ? (parsed.invitationTracking as Record<string, { active?: string[]; used: string[]; revoked: string[] }>)
        : {};
    // Migrate old entries that lack `active`
    const invitationTracking: Record<string, { active: string[]; used: string[]; revoked: string[] }> = {};
    for (const [key, val] of Object.entries(rawTracking)) {
      invitationTracking[key] = {
        active: val.active ?? [],
        used: val.used ?? [],
        revoked: val.revoked ?? [],
      };
    }

    return {
      swarms: validSwarms,
      activeSwarmId,
      loading: false,
      invitationTracking,
    };
  } catch (e) {
    console.warn("[swarm-store] loadPersistedSwarms failed:", e);
    return null;
  }
}


function getInitialState(): SwarmState {
  const restored = loadPersistedSwarms();
  if (restored) return restored;

  return {
    swarms: [],
    activeSwarmId: null,
    loading: false,
    invitationTracking: {},
  };
}

function syncSwarmStoreWithStorage(): void {
  const snapshot = readSwarmStorageSnapshot();
  if (snapshot === lastSwarmStorageSnapshot) {
    return;
  }

  const restored = loadPersistedSwarms() ?? getInitialState();
  lastSwarmStorageSnapshot = snapshot;
  useSwarmStoreBase.setState({
    swarms: restored.swarms,
    activeSwarmId: restored.activeSwarmId,
    activeSwarm: deriveActiveSwarm(restored.swarms, restored.activeSwarmId),
    loading: restored.loading,
    invitationTracking: restored.invitationTracking,
  });
}


export interface CreateSwarmConfig {
  name: string;
  type: SwarmType;
  description?: string;
  policies?: Partial<SwarmPolicy>;
}

const DEFAULT_POLICY: SwarmPolicy = {
  minReputationToPublish: null,
  requireSignatures: true,
  autoShareDetections: false,
  compartmentalized: false,
  requiredCapabilities: [],
  maxMembers: null,
};

const DEFAULT_STATS: SwarmStats = {
  memberCount: 0,
  sentinelCount: 0,
  operatorCount: 0,
  intelShared: 0,
  activeDetections: 0,
  speakeasyCount: 0,
  avgReputation: 0,
};

export function createSwarm(config: CreateSwarmConfig): Swarm {
  const id = generateId("swm");
  const now = Date.now();

  // Trusted/federated default to compartmentalized
  const compartmentalized =
    config.policies?.compartmentalized ??
    (config.type === "trusted" || config.type === "federated");

  return {
    id,
    name: config.name,
    type: config.type,
    description: config.description ?? "",
    members: [],
    sharedIntel: [],
    sharedDetections: [],
    trustGraph: [],
    policies: {
      ...DEFAULT_POLICY,
      ...config.policies,
      compartmentalized,
    },
    speakeasies: [],
    stats: { ...DEFAULT_STATS },
    topicPrefix: `/baychat/v1/swarm/${id}/`,
    createdAt: now,
    lastActivityAt: now,
  };
}


// ---------------------------------------------------------------------------
// Debounced localStorage persistence
// ---------------------------------------------------------------------------

let _persistTimer: ReturnType<typeof setTimeout> | null = null;

function schedulePersist(state: SwarmState): void {
  if (_persistTimer) clearTimeout(_persistTimer);
  _persistTimer = setTimeout(() => {
    persistSwarms(state);
    _persistTimer = null;
  }, 500);
}


// ---------------------------------------------------------------------------
// Zustand store
// ---------------------------------------------------------------------------

interface SwarmStoreState extends SwarmState {
  /** Derived: the currently active swarm, or undefined. */
  activeSwarm: Swarm | undefined;
  actions: {
    createSwarm: (config: CreateSwarmConfig) => Swarm;
    updateSwarm: (swarmId: string, patch: Partial<Pick<Swarm, "name" | "description" | "type">>) => void;
    deleteSwarm: (swarmId: string) => void;
    setActiveSwarm: (swarmId: string | null) => void;
    addMember: (swarmId: string, member: SwarmMember) => void;
    removeMember: (swarmId: string, fingerprint: string) => void;
    updateMember: (swarmId: string, fingerprint: string, patch: Partial<Pick<SwarmMember, "role" | "reputation">>) => void;
    updatePolicy: (swarmId: string, policies: Partial<SwarmPolicy>) => void;
    addIntelRef: (swarmId: string, ref: IntelRef) => void;
    removeIntelRef: (swarmId: string, intelId: string) => void;
    addDetectionRef: (swarmId: string, ref: DetectionRef) => void;
    removeDetectionRef: (swarmId: string, intelId: string) => void;
    addSpeakeasyRef: (swarmId: string, ref: SpeakeasyRef) => void;
    removeSpeakeasyRef: (swarmId: string, speakeasyId: string) => void;
    addTrustEdge: (swarmId: string, edge: TrustEdge) => void;
    removeTrustEdge: (swarmId: string, from: string, to: string) => void;
    updateStats: (swarmId: string, stats: Partial<SwarmStats>) => void;
    addInvitation: (swarmId: string, jti: string) => void;
    revokeInvitation: (swarmId: string, jti: string) => void;
    markInvitationUsed: (swarmId: string, jti: string) => void;
    load: (swarms: Swarm[]) => void;
  };
}

/** Helper: map over swarms array, replacing the target swarm via a transform fn. */
function mapSwarm(
  swarms: Swarm[],
  swarmId: string,
  transform: (swarm: Swarm) => Swarm,
): Swarm[] {
  return swarms.map((s) => (s.id === swarmId ? transform(s) : s));
}

function deriveActiveSwarm(swarms: Swarm[], activeSwarmId: string | null): Swarm | undefined {
  return swarms.find((s) => s.id === activeSwarmId);
}

const initialState = getInitialState();

const useSwarmStoreBase = create<SwarmStoreState>()((set, get) => ({
  ...initialState,
  activeSwarm: deriveActiveSwarm(initialState.swarms, initialState.activeSwarmId),

  actions: {
    createSwarm: (config: CreateSwarmConfig): Swarm => {
      const swarm = createSwarm(config);
      const swarmWithStats = { ...swarm, stats: recomputeStats(swarm) };
      const swarms = [...get().swarms, swarmWithStats];
      const next = {
        swarms,
        activeSwarmId: swarmWithStats.id,
        activeSwarm: swarmWithStats,
      };
      set(next);
      schedulePersist({ ...get() });
      return swarmWithStats;
    },

    updateSwarm: (swarmId: string, patch: Partial<Pick<Swarm, "name" | "description" | "type">>) => {
      const swarms = mapSwarm(get().swarms, swarmId, (s) => ({
        ...s,
        ...patch,
        lastActivityAt: Date.now(),
      }));
      set({ swarms, activeSwarm: deriveActiveSwarm(swarms, get().activeSwarmId) });
      schedulePersist({ ...get() });
    },

    deleteSwarm: (swarmId: string) => {
      const remaining = get().swarms.filter((s) => s.id !== swarmId);
      const needNewActive = get().activeSwarmId === swarmId;
      const activeSwarmId = needNewActive
        ? (remaining.length > 0 ? remaining[0].id : null)
        : get().activeSwarmId;
      set({
        swarms: remaining,
        activeSwarmId,
        activeSwarm: deriveActiveSwarm(remaining, activeSwarmId),
      });
      schedulePersist({ ...get() });
    },

    setActiveSwarm: (swarmId: string | null) => {
      if (swarmId !== null && !get().swarms.some((s) => s.id === swarmId)) {
        return;
      }
      set({
        activeSwarmId: swarmId,
        activeSwarm: deriveActiveSwarm(get().swarms, swarmId),
      });
      schedulePersist({ ...get() });
    },

    addMember: (swarmId: string, member: SwarmMember) => {
      const swarms = mapSwarm(get().swarms, swarmId, (s) => {
        if (s.members.some((m) => m.fingerprint === member.fingerprint)) return s;
        const updated = { ...s, members: [...s.members, member], lastActivityAt: Date.now() };
        return { ...updated, stats: recomputeStats(updated) };
      });
      set({ swarms, activeSwarm: deriveActiveSwarm(swarms, get().activeSwarmId) });
      schedulePersist({ ...get() });
    },

    removeMember: (swarmId: string, fingerprint: string) => {
      const swarms = mapSwarm(get().swarms, swarmId, (s) => {
        const updated = {
          ...s,
          members: s.members.filter((m) => m.fingerprint !== fingerprint),
          trustGraph: s.trustGraph.filter(
            (e) => e.from !== fingerprint && e.to !== fingerprint,
          ),
          lastActivityAt: Date.now(),
        };
        return { ...updated, stats: recomputeStats(updated) };
      });
      set({ swarms, activeSwarm: deriveActiveSwarm(swarms, get().activeSwarmId) });
      schedulePersist({ ...get() });
    },

    updateMember: (swarmId: string, fingerprint: string, patch: Partial<Pick<SwarmMember, "role" | "reputation">>) => {
      const swarms = mapSwarm(get().swarms, swarmId, (s) => {
        const updated = {
          ...s,
          members: s.members.map((m) =>
            m.fingerprint === fingerprint ? { ...m, ...patch } : m,
          ),
          lastActivityAt: Date.now(),
        };
        return { ...updated, stats: recomputeStats(updated) };
      });
      set({ swarms, activeSwarm: deriveActiveSwarm(swarms, get().activeSwarmId) });
      schedulePersist({ ...get() });
    },

    updatePolicy: (swarmId: string, policies: Partial<SwarmPolicy>) => {
      const swarms = mapSwarm(get().swarms, swarmId, (s) => ({
        ...s,
        policies: { ...s.policies, ...policies },
        lastActivityAt: Date.now(),
      }));
      set({ swarms, activeSwarm: deriveActiveSwarm(swarms, get().activeSwarmId) });
      schedulePersist({ ...get() });
    },

    addIntelRef: (swarmId: string, ref: IntelRef) => {
      const swarms = mapSwarm(get().swarms, swarmId, (s) => {
        if (s.sharedIntel.some((r) => r.intelId === ref.intelId)) return s;
        const updated = { ...s, sharedIntel: [...s.sharedIntel, ref], lastActivityAt: Date.now() };
        return { ...updated, stats: recomputeStats(updated) };
      });
      set({ swarms, activeSwarm: deriveActiveSwarm(swarms, get().activeSwarmId) });
      schedulePersist({ ...get() });
    },

    removeIntelRef: (swarmId: string, intelId: string) => {
      const swarms = mapSwarm(get().swarms, swarmId, (s) => {
        const updated = {
          ...s,
          sharedIntel: s.sharedIntel.filter((r) => r.intelId !== intelId),
          lastActivityAt: Date.now(),
        };
        return { ...updated, stats: recomputeStats(updated) };
      });
      set({ swarms, activeSwarm: deriveActiveSwarm(swarms, get().activeSwarmId) });
      schedulePersist({ ...get() });
    },

    addDetectionRef: (swarmId: string, ref: DetectionRef) => {
      const swarms = mapSwarm(get().swarms, swarmId, (s) => {
        if (s.sharedDetections.some((r) => r.intelId === ref.intelId)) return s;
        const updated = {
          ...s,
          sharedDetections: [...s.sharedDetections, ref],
          lastActivityAt: Date.now(),
        };
        return { ...updated, stats: recomputeStats(updated) };
      });
      set({ swarms, activeSwarm: deriveActiveSwarm(swarms, get().activeSwarmId) });
      schedulePersist({ ...get() });
    },

    removeDetectionRef: (swarmId: string, intelId: string) => {
      const swarms = mapSwarm(get().swarms, swarmId, (s) => {
        const updated = {
          ...s,
          sharedDetections: s.sharedDetections.filter((r) => r.intelId !== intelId),
          lastActivityAt: Date.now(),
        };
        return { ...updated, stats: recomputeStats(updated) };
      });
      set({ swarms, activeSwarm: deriveActiveSwarm(swarms, get().activeSwarmId) });
      schedulePersist({ ...get() });
    },

    addSpeakeasyRef: (swarmId: string, ref: SpeakeasyRef) => {
      const swarms = mapSwarm(get().swarms, swarmId, (s) => {
        if (s.speakeasies.some((r) => r.speakeasyId === ref.speakeasyId)) return s;
        const updated = {
          ...s,
          speakeasies: [...s.speakeasies, ref],
          lastActivityAt: Date.now(),
        };
        return { ...updated, stats: recomputeStats(updated) };
      });
      set({ swarms, activeSwarm: deriveActiveSwarm(swarms, get().activeSwarmId) });
      schedulePersist({ ...get() });
    },

    removeSpeakeasyRef: (swarmId: string, speakeasyId: string) => {
      const swarms = mapSwarm(get().swarms, swarmId, (s) => {
        const updated = {
          ...s,
          speakeasies: s.speakeasies.filter((r) => r.speakeasyId !== speakeasyId),
          lastActivityAt: Date.now(),
        };
        return { ...updated, stats: recomputeStats(updated) };
      });
      set({ swarms, activeSwarm: deriveActiveSwarm(swarms, get().activeSwarmId) });
      schedulePersist({ ...get() });
    },

    addTrustEdge: (swarmId: string, edge: TrustEdge) => {
      const swarms = mapSwarm(get().swarms, swarmId, (s) => {
        // Replace existing edge between same pair
        const filtered = s.trustGraph.filter(
          (e) => !(e.from === edge.from && e.to === edge.to),
        );
        return {
          ...s,
          trustGraph: [...filtered, edge],
          lastActivityAt: Date.now(),
        };
      });
      set({ swarms, activeSwarm: deriveActiveSwarm(swarms, get().activeSwarmId) });
      schedulePersist({ ...get() });
    },

    removeTrustEdge: (swarmId: string, from: string, to: string) => {
      const swarms = mapSwarm(get().swarms, swarmId, (s) => ({
        ...s,
        trustGraph: s.trustGraph.filter(
          (e) => !(e.from === from && e.to === to),
        ),
        lastActivityAt: Date.now(),
      }));
      set({ swarms, activeSwarm: deriveActiveSwarm(swarms, get().activeSwarmId) });
      schedulePersist({ ...get() });
    },

    updateStats: (swarmId: string, stats: Partial<SwarmStats>) => {
      const swarms = mapSwarm(get().swarms, swarmId, (s) => ({
        ...s,
        stats: { ...s.stats, ...stats },
      }));
      set({ swarms, activeSwarm: deriveActiveSwarm(swarms, get().activeSwarmId) });
      schedulePersist({ ...get() });
    },

    addInvitation: (swarmId: string, jti: string) => {
      const tracking = get().invitationTracking[swarmId] ?? { active: [], used: [], revoked: [] };
      if (tracking.active.includes(jti) || tracking.used.includes(jti) || tracking.revoked.includes(jti)) {
        return;
      }
      set({
        invitationTracking: {
          ...get().invitationTracking,
          [swarmId]: {
            ...tracking,
            active: [...tracking.active, jti],
          },
        },
      });
      schedulePersist({ ...get() });
    },

    revokeInvitation: (swarmId: string, jti: string) => {
      const tracking = get().invitationTracking[swarmId] ?? { active: [], used: [], revoked: [] };
      if (tracking.revoked.includes(jti)) return;
      set({
        invitationTracking: {
          ...get().invitationTracking,
          [swarmId]: {
            ...tracking,
            active: tracking.active.filter((j) => j !== jti),
            revoked: [...tracking.revoked, jti],
          },
        },
      });
      schedulePersist({ ...get() });
    },

    markInvitationUsed: (swarmId: string, jti: string) => {
      const tracking = get().invitationTracking[swarmId] ?? { active: [], used: [], revoked: [] };
      if (tracking.used.includes(jti)) return;
      set({
        invitationTracking: {
          ...get().invitationTracking,
          [swarmId]: {
            ...tracking,
            active: tracking.active.filter((j) => j !== jti),
            used: [...tracking.used, jti],
          },
        },
      });
      schedulePersist({ ...get() });
    },

    load: (swarms: Swarm[]) => {
      const currentActiveId = get().activeSwarmId;
      const activeId =
        currentActiveId && swarms.some((s) => s.id === currentActiveId)
          ? currentActiveId
          : swarms.length > 0 ? swarms[0].id : null;
      set({
        swarms,
        activeSwarmId: activeId,
        activeSwarm: deriveActiveSwarm(swarms, activeId),
        loading: false,
      });
      schedulePersist({ ...get() });
    },
  },
}));

export const useSwarmStore = createSelectors(useSwarmStoreBase);

// ---------------------------------------------------------------------------
// Backward-compatible hook
// ---------------------------------------------------------------------------

interface SwarmContextValue {
  swarms: Swarm[];
  activeSwarm: Swarm | undefined;
  loading: boolean;
  createSwarm: (config: CreateSwarmConfig) => Swarm;
  updateSwarm: (swarmId: string, patch: Partial<Pick<Swarm, "name" | "description" | "type">>) => void;
  deleteSwarm: (swarmId: string) => void;
  setActiveSwarm: (swarmId: string | null) => void;
  addMember: (swarmId: string, member: SwarmMember) => void;
  removeMember: (swarmId: string, fingerprint: string) => void;
  updateMember: (swarmId: string, fingerprint: string, patch: Partial<Pick<SwarmMember, "role" | "reputation">>) => void;
  updatePolicy: (swarmId: string, policies: Partial<SwarmPolicy>) => void;
  addIntelRef: (swarmId: string, ref: IntelRef) => void;
  removeIntelRef: (swarmId: string, intelId: string) => void;
  addDetectionRef: (swarmId: string, ref: DetectionRef) => void;
  removeDetectionRef: (swarmId: string, intelId: string) => void;
  addSpeakeasyRef: (swarmId: string, ref: SpeakeasyRef) => void;
  removeSpeakeasyRef: (swarmId: string, speakeasyId: string) => void;
  addTrustEdge: (swarmId: string, edge: TrustEdge) => void;
  removeTrustEdge: (swarmId: string, from: string, to: string) => void;
  updateStats: (swarmId: string, stats: Partial<SwarmStats>) => void;
  addInvitation: (swarmId: string, jti: string) => void;
  revokeInvitation: (swarmId: string, jti: string) => void;
  markInvitationUsed: (swarmId: string, jti: string) => void;
  invitationTracking: Record<string, { active: string[]; used: string[]; revoked: string[] }>;
}

/** @deprecated Use useSwarmStore directly */
export function useSwarms(): SwarmContextValue {
  useLayoutEffect(() => {
    syncSwarmStoreWithStorage();
  }, []);

  const swarms = useSwarmStore((s) => s.swarms);
  const activeSwarm = useSwarmStore((s) => s.activeSwarm);
  const loading = useSwarmStore((s) => s.loading);
  const invitationTracking = useSwarmStore((s) => s.invitationTracking);
  const actions = useSwarmStore((s) => s.actions);

  return {
    swarms,
    activeSwarm,
    loading,
    invitationTracking,
    createSwarm: actions.createSwarm,
    updateSwarm: actions.updateSwarm,
    deleteSwarm: actions.deleteSwarm,
    setActiveSwarm: actions.setActiveSwarm,
    addMember: actions.addMember,
    removeMember: actions.removeMember,
    updateMember: actions.updateMember,
    updatePolicy: actions.updatePolicy,
    addIntelRef: actions.addIntelRef,
    removeIntelRef: actions.removeIntelRef,
    addDetectionRef: actions.addDetectionRef,
    removeDetectionRef: actions.removeDetectionRef,
    addSpeakeasyRef: actions.addSpeakeasyRef,
    removeSpeakeasyRef: actions.removeSpeakeasyRef,
    addTrustEdge: actions.addTrustEdge,
    removeTrustEdge: actions.removeTrustEdge,
    updateStats: actions.updateStats,
    addInvitation: actions.addInvitation,
    revokeInvitation: actions.revokeInvitation,
    markInvitationUsed: actions.markInvitationUsed,
  };
}
