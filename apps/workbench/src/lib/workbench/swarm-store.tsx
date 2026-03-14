// Swarm Store — React Context + useReducer for swarm CRUD & coordination
//
// Follows the sentinel-store.tsx pattern: State, Action union, reducer,
// Provider with localStorage persistence, and a typed hook.
import React, {
  createContext,
  useContext,
  useReducer,
  useCallback,
  useEffect,
  useRef,
  type ReactNode,
} from "react";
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
} from "./sentinel-types";
import { generateId } from "./sentinel-types";


export interface SwarmState {
  swarms: Swarm[];
  activeSwarmId: string | null;
  loading: boolean;
  invitationTracking: Record<string, { active: string[]; used: string[]; revoked: string[] }>;
}


export type SwarmAction =
  | { type: "CREATE"; swarm: Swarm }
  | { type: "UPDATE"; swarmId: string; patch: Partial<Pick<Swarm, "name" | "description" | "type">> }
  | { type: "DELETE"; swarmId: string }
  | { type: "SET_ACTIVE"; swarmId: string | null }
  | { type: "ADD_MEMBER"; swarmId: string; member: SwarmMember }
  | { type: "REMOVE_MEMBER"; swarmId: string; fingerprint: string }
  | { type: "UPDATE_MEMBER"; swarmId: string; fingerprint: string; patch: Partial<Pick<SwarmMember, "role" | "reputation">> }
  | { type: "UPDATE_POLICY"; swarmId: string; policies: Partial<SwarmPolicy> }
  | { type: "ADD_INTEL_REF"; swarmId: string; ref: IntelRef }
  | { type: "REMOVE_INTEL_REF"; swarmId: string; intelId: string }
  | { type: "ADD_DETECTION_REF"; swarmId: string; ref: DetectionRef }
  | { type: "REMOVE_DETECTION_REF"; swarmId: string; intelId: string }
  | { type: "ADD_SPEAKEASY_REF"; swarmId: string; ref: SpeakeasyRef }
  | { type: "REMOVE_SPEAKEASY_REF"; swarmId: string; speakeasyId: string }
  | { type: "ADD_TRUST_EDGE"; swarmId: string; edge: TrustEdge }
  | { type: "REMOVE_TRUST_EDGE"; swarmId: string; from: string; to: string }
  | { type: "UPDATE_STATS"; swarmId: string; stats: Partial<SwarmStats> }
  | { type: "ADD_INVITATION"; swarmId: string; jti: string }
  | { type: "REVOKE_INVITATION"; swarmId: string; jti: string }
  | { type: "MARK_INVITATION_USED"; swarmId: string; jti: string }
  | { type: "LOAD"; swarms: Swarm[] };


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


function swarmReducer(state: SwarmState, action: SwarmAction): SwarmState {
  switch (action.type) {
    case "CREATE": {
      const swarm = { ...action.swarm, stats: recomputeStats(action.swarm) };
      return {
        ...state,
        swarms: [...state.swarms, swarm],
        activeSwarmId: swarm.id,
      };
    }

    case "UPDATE": {
      return {
        ...state,
        swarms: state.swarms.map((s) =>
          s.id === action.swarmId
            ? { ...s, ...action.patch, lastActivityAt: Date.now() }
            : s,
        ),
      };
    }

    case "DELETE": {
      const remaining = state.swarms.filter((s) => s.id !== action.swarmId);
      const needNewActive = state.activeSwarmId === action.swarmId;
      return {
        ...state,
        swarms: remaining,
        activeSwarmId: needNewActive
          ? (remaining.length > 0 ? remaining[0].id : null)
          : state.activeSwarmId,
      };
    }

    case "SET_ACTIVE": {
      if (action.swarmId !== null && !state.swarms.some((s) => s.id === action.swarmId)) {
        return state;
      }
      return { ...state, activeSwarmId: action.swarmId };
    }

    case "ADD_MEMBER": {
      return {
        ...state,
        swarms: state.swarms.map((s) => {
          if (s.id !== action.swarmId) return s;
          // Prevent duplicates
          if (s.members.some((m) => m.fingerprint === action.member.fingerprint)) return s;
          const updated = { ...s, members: [...s.members, action.member], lastActivityAt: Date.now() };
          return { ...updated, stats: recomputeStats(updated) };
        }),
      };
    }

    case "REMOVE_MEMBER": {
      return {
        ...state,
        swarms: state.swarms.map((s) => {
          if (s.id !== action.swarmId) return s;
          const updated = {
            ...s,
            members: s.members.filter((m) => m.fingerprint !== action.fingerprint),
            // Also remove trust edges involving this member
            trustGraph: s.trustGraph.filter(
              (e) => e.from !== action.fingerprint && e.to !== action.fingerprint,
            ),
            lastActivityAt: Date.now(),
          };
          return { ...updated, stats: recomputeStats(updated) };
        }),
      };
    }

    case "UPDATE_MEMBER": {
      return {
        ...state,
        swarms: state.swarms.map((s) => {
          if (s.id !== action.swarmId) return s;
          const updated = {
            ...s,
            members: s.members.map((m) =>
              m.fingerprint === action.fingerprint
                ? { ...m, ...action.patch }
                : m,
            ),
            lastActivityAt: Date.now(),
          };
          return { ...updated, stats: recomputeStats(updated) };
        }),
      };
    }

    case "UPDATE_POLICY": {
      return {
        ...state,
        swarms: state.swarms.map((s) =>
          s.id === action.swarmId
            ? { ...s, policies: { ...s.policies, ...action.policies }, lastActivityAt: Date.now() }
            : s,
        ),
      };
    }

    case "ADD_INTEL_REF": {
      return {
        ...state,
        swarms: state.swarms.map((s) => {
          if (s.id !== action.swarmId) return s;
          if (s.sharedIntel.some((r) => r.intelId === action.ref.intelId)) return s;
          const updated = { ...s, sharedIntel: [...s.sharedIntel, action.ref], lastActivityAt: Date.now() };
          return { ...updated, stats: recomputeStats(updated) };
        }),
      };
    }

    case "REMOVE_INTEL_REF": {
      return {
        ...state,
        swarms: state.swarms.map((s) => {
          if (s.id !== action.swarmId) return s;
          const updated = {
            ...s,
            sharedIntel: s.sharedIntel.filter((r) => r.intelId !== action.intelId),
            lastActivityAt: Date.now(),
          };
          return { ...updated, stats: recomputeStats(updated) };
        }),
      };
    }

    case "ADD_DETECTION_REF": {
      return {
        ...state,
        swarms: state.swarms.map((s) => {
          if (s.id !== action.swarmId) return s;
          if (s.sharedDetections.some((r) => r.intelId === action.ref.intelId)) return s;
          const updated = {
            ...s,
            sharedDetections: [...s.sharedDetections, action.ref],
            lastActivityAt: Date.now(),
          };
          return { ...updated, stats: recomputeStats(updated) };
        }),
      };
    }

    case "REMOVE_DETECTION_REF": {
      return {
        ...state,
        swarms: state.swarms.map((s) => {
          if (s.id !== action.swarmId) return s;
          const updated = {
            ...s,
            sharedDetections: s.sharedDetections.filter((r) => r.intelId !== action.intelId),
            lastActivityAt: Date.now(),
          };
          return { ...updated, stats: recomputeStats(updated) };
        }),
      };
    }

    case "ADD_SPEAKEASY_REF": {
      return {
        ...state,
        swarms: state.swarms.map((s) => {
          if (s.id !== action.swarmId) return s;
          if (s.speakeasies.some((r) => r.speakeasyId === action.ref.speakeasyId)) return s;
          const updated = {
            ...s,
            speakeasies: [...s.speakeasies, action.ref],
            lastActivityAt: Date.now(),
          };
          return { ...updated, stats: recomputeStats(updated) };
        }),
      };
    }

    case "REMOVE_SPEAKEASY_REF": {
      return {
        ...state,
        swarms: state.swarms.map((s) => {
          if (s.id !== action.swarmId) return s;
          const updated = {
            ...s,
            speakeasies: s.speakeasies.filter((r) => r.speakeasyId !== action.speakeasyId),
            lastActivityAt: Date.now(),
          };
          return { ...updated, stats: recomputeStats(updated) };
        }),
      };
    }

    case "ADD_TRUST_EDGE": {
      return {
        ...state,
        swarms: state.swarms.map((s) => {
          if (s.id !== action.swarmId) return s;
          // Replace existing edge between same pair
          const filtered = s.trustGraph.filter(
            (e) => !(e.from === action.edge.from && e.to === action.edge.to),
          );
          return {
            ...s,
            trustGraph: [...filtered, action.edge],
            lastActivityAt: Date.now(),
          };
        }),
      };
    }

    case "REMOVE_TRUST_EDGE": {
      return {
        ...state,
        swarms: state.swarms.map((s) => {
          if (s.id !== action.swarmId) return s;
          return {
            ...s,
            trustGraph: s.trustGraph.filter(
              (e) => !(e.from === action.from && e.to === action.to),
            ),
            lastActivityAt: Date.now(),
          };
        }),
      };
    }

    case "UPDATE_STATS": {
      return {
        ...state,
        swarms: state.swarms.map((s) =>
          s.id === action.swarmId
            ? { ...s, stats: { ...s.stats, ...action.stats } }
            : s,
        ),
      };
    }

    case "ADD_INVITATION": {
      const tracking = state.invitationTracking[action.swarmId] ?? { active: [], used: [], revoked: [] };
      if (tracking.active.includes(action.jti) || tracking.used.includes(action.jti) || tracking.revoked.includes(action.jti)) {
        return state;
      }
      return {
        ...state,
        invitationTracking: {
          ...state.invitationTracking,
          [action.swarmId]: {
            ...tracking,
            active: [...tracking.active, action.jti],
          },
        },
      };
    }

    case "REVOKE_INVITATION": {
      const tracking = state.invitationTracking[action.swarmId] ?? { active: [], used: [], revoked: [] };
      if (tracking.revoked.includes(action.jti)) return state;
      return {
        ...state,
        invitationTracking: {
          ...state.invitationTracking,
          [action.swarmId]: {
            ...tracking,
            active: tracking.active.filter((j) => j !== action.jti),
            revoked: [...tracking.revoked, action.jti],
          },
        },
      };
    }

    case "MARK_INVITATION_USED": {
      const tracking = state.invitationTracking[action.swarmId] ?? { active: [], used: [], revoked: [] };
      if (tracking.used.includes(action.jti)) return state;
      return {
        ...state,
        invitationTracking: {
          ...state.invitationTracking,
          [action.swarmId]: {
            ...tracking,
            active: tracking.active.filter((j) => j !== action.jti),
            used: [...tracking.used, action.jti],
          },
        },
      };
    }

    case "LOAD": {
      const activeId =
        state.activeSwarmId && action.swarms.some((s) => s.id === state.activeSwarmId)
          ? state.activeSwarmId
          : action.swarms.length > 0 ? action.swarms[0].id : null;
      return {
        ...state,
        swarms: action.swarms,
        activeSwarmId: activeId,
        loading: false,
      };
    }

    default:
      return state;
  }
}


const STORAGE_KEY = "clawdstrike_workbench_swarms";

function persistSwarms(state: SwarmState): void {
  try {
    const persisted = {
      swarms: state.swarms,
      activeSwarmId: state.activeSwarmId,
      invitationTracking: state.invitationTracking,
    };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(persisted));
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

const SwarmContext = createContext<SwarmContextValue | null>(null);


export function useSwarms(): SwarmContextValue {
  const ctx = useContext(SwarmContext);
  if (!ctx) throw new Error("useSwarms must be used within SwarmProvider");
  return ctx;
}


export function SwarmProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(swarmReducer, undefined, getInitialState);

    const persistRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => {
    if (persistRef.current) clearTimeout(persistRef.current);
    persistRef.current = setTimeout(() => {
      persistSwarms(state);
    }, 500);
    return () => {
      if (persistRef.current) clearTimeout(persistRef.current);
    };
  }, [state.swarms, state.activeSwarmId, state.invitationTracking]);

    const activeSwarm = state.swarms.find((s) => s.id === state.activeSwarmId);

  
  const createSwarmAction = useCallback(
    (config: CreateSwarmConfig): Swarm => {
      const swarm = createSwarm(config);
      dispatch({ type: "CREATE", swarm });
      return swarm;
    },
    [],
  );

  const updateSwarmAction = useCallback(
    (swarmId: string, patch: Partial<Pick<Swarm, "name" | "description" | "type">>) => {
      dispatch({ type: "UPDATE", swarmId, patch });
    },
    [],
  );

  const deleteSwarmAction = useCallback((swarmId: string) => {
    dispatch({ type: "DELETE", swarmId });
  }, []);

  const setActiveSwarm = useCallback((swarmId: string | null) => {
    dispatch({ type: "SET_ACTIVE", swarmId });
  }, []);

  const addMember = useCallback(
    (swarmId: string, member: SwarmMember) => {
      dispatch({ type: "ADD_MEMBER", swarmId, member });
    },
    [],
  );

  const removeMember = useCallback(
    (swarmId: string, fingerprint: string) => {
      dispatch({ type: "REMOVE_MEMBER", swarmId, fingerprint });
    },
    [],
  );

  const updateMember = useCallback(
    (swarmId: string, fingerprint: string, patch: Partial<Pick<SwarmMember, "role" | "reputation">>) => {
      dispatch({ type: "UPDATE_MEMBER", swarmId, fingerprint, patch });
    },
    [],
  );

  const updatePolicy = useCallback(
    (swarmId: string, policies: Partial<SwarmPolicy>) => {
      dispatch({ type: "UPDATE_POLICY", swarmId, policies });
    },
    [],
  );

  const addIntelRef = useCallback(
    (swarmId: string, ref: IntelRef) => {
      dispatch({ type: "ADD_INTEL_REF", swarmId, ref });
    },
    [],
  );

  const removeIntelRef = useCallback(
    (swarmId: string, intelId: string) => {
      dispatch({ type: "REMOVE_INTEL_REF", swarmId, intelId });
    },
    [],
  );

  const addDetectionRef = useCallback(
    (swarmId: string, ref: DetectionRef) => {
      dispatch({ type: "ADD_DETECTION_REF", swarmId, ref });
    },
    [],
  );

  const removeDetectionRef = useCallback(
    (swarmId: string, intelId: string) => {
      dispatch({ type: "REMOVE_DETECTION_REF", swarmId, intelId });
    },
    [],
  );

  const addSpeakeasyRef = useCallback(
    (swarmId: string, ref: SpeakeasyRef) => {
      dispatch({ type: "ADD_SPEAKEASY_REF", swarmId, ref });
    },
    [],
  );

  const removeSpeakeasyRef = useCallback(
    (swarmId: string, speakeasyId: string) => {
      dispatch({ type: "REMOVE_SPEAKEASY_REF", swarmId, speakeasyId });
    },
    [],
  );

  const addTrustEdge = useCallback(
    (swarmId: string, edge: TrustEdge) => {
      dispatch({ type: "ADD_TRUST_EDGE", swarmId, edge });
    },
    [],
  );

  const removeTrustEdge = useCallback(
    (swarmId: string, from: string, to: string) => {
      dispatch({ type: "REMOVE_TRUST_EDGE", swarmId, from, to });
    },
    [],
  );

  const updateStatsAction = useCallback(
    (swarmId: string, stats: Partial<SwarmStats>) => {
      dispatch({ type: "UPDATE_STATS", swarmId, stats });
    },
    [],
  );

  const addInvitation = useCallback(
    (swarmId: string, jti: string) => {
      dispatch({ type: "ADD_INVITATION", swarmId, jti });
    },
    [],
  );

  const revokeInvitation = useCallback(
    (swarmId: string, jti: string) => {
      dispatch({ type: "REVOKE_INVITATION", swarmId, jti });
    },
    [],
  );

  const markInvitationUsed = useCallback(
    (swarmId: string, jti: string) => {
      dispatch({ type: "MARK_INVITATION_USED", swarmId, jti });
    },
    [],
  );

  const value: SwarmContextValue = {
    swarms: state.swarms,
    activeSwarm,
    loading: state.loading,
    createSwarm: createSwarmAction,
    updateSwarm: updateSwarmAction,
    deleteSwarm: deleteSwarmAction,
    setActiveSwarm,
    addMember,
    removeMember,
    updateMember,
    updatePolicy,
    addIntelRef,
    removeIntelRef,
    addDetectionRef,
    removeDetectionRef,
    addSpeakeasyRef,
    removeSpeakeasyRef,
    addTrustEdge,
    removeTrustEdge,
    updateStats: updateStatsAction,
    addInvitation,
    revokeInvitation,
    markInvitationUsed,
    invitationTracking: state.invitationTracking,
  };

  return (
    <SwarmContext.Provider value={value}>
      {children}
    </SwarmContext.Provider>
  );
}
