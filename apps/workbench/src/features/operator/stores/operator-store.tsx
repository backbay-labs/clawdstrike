// Operator Store — Zustand + immer for operator identity management.
//
// Migrated from React Context + useReducer. Preserves all crypto operations,
// secure store integration, and localStorage persistence with debounced writes.
import { useLayoutEffect, type ReactElement, type ReactNode } from "react";
import { create } from "zustand";
import { immer } from "zustand/middleware/immer";
import { createSelectors } from "@/lib/create-selectors";
import type { OperatorIdentity, IdpClaims } from "@/lib/workbench/operator-types";
import {
  createOperatorIdentity,
  signData,
  deriveFingerprint,
  deriveSigil,
  exportKey as cryptoExportKey,
  importKey as cryptoImportKey,
} from "@/lib/workbench/operator-crypto";
import { signDetachedPayload } from "@/lib/workbench/signature-adapter";
import { secureStore } from "@/features/settings/secure-store";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface OperatorState {
  currentOperator: OperatorIdentity | null;
  initialized: boolean;
  loading: boolean;
}

export type OperatorAction =
  | { type: "INIT"; operator: OperatorIdentity | null }
  | { type: "CREATE"; operator: OperatorIdentity }
  | { type: "UPDATE_DISPLAY_NAME"; displayName: string }
  | { type: "LINK_IDP"; claims: IdpClaims }
  | { type: "UNLINK_IDP" }
  | { type: "ADD_DEVICE"; device: { deviceId: string; deviceName: string } }
  | { type: "REVOKE"; revokedAt: number; revocationReason: string }
  | { type: "SIGN_OUT" };

/**
 * Pure reducer function — kept exported for unit testing.
 */
export function operatorReducer(state: OperatorState, action: OperatorAction): OperatorState {
  switch (action.type) {
    case "INIT": {
      return {
        ...state,
        currentOperator: action.operator,
        initialized: true,
        loading: false,
      };
    }

    case "CREATE": {
      return {
        ...state,
        currentOperator: action.operator,
        loading: false,
      };
    }

    case "UPDATE_DISPLAY_NAME": {
      if (!state.currentOperator) return state;
      return {
        ...state,
        currentOperator: {
          ...state.currentOperator,
          displayName: action.displayName,
        },
      };
    }

    case "LINK_IDP": {
      if (!state.currentOperator) return state;
      return {
        ...state,
        currentOperator: {
          ...state.currentOperator,
          idpClaims: action.claims,
        },
      };
    }

    case "UNLINK_IDP": {
      if (!state.currentOperator) return state;
      return {
        ...state,
        currentOperator: {
          ...state.currentOperator,
          idpClaims: null,
        },
      };
    }

    case "ADD_DEVICE": {
      if (!state.currentOperator) return state;
      const now = Date.now();
      return {
        ...state,
        currentOperator: {
          ...state.currentOperator,
          devices: [
            ...state.currentOperator.devices,
            {
              deviceId: action.device.deviceId,
              deviceName: action.device.deviceName,
              addedAt: now,
              lastSeenAt: now,
            },
          ],
        },
      };
    }

    case "REVOKE": {
      if (!state.currentOperator) return state;
      return {
        ...state,
        currentOperator: {
          ...state.currentOperator,
          revokedAt: action.revokedAt,
          revocationReason: action.revocationReason,
        },
      };
    }

    case "SIGN_OUT": {
      return {
        ...state,
        currentOperator: null,
      };
    }

    default:
      return state;
  }
}

// ---------------------------------------------------------------------------
// localStorage persistence helpers
// ---------------------------------------------------------------------------

const STORAGE_KEY = "clawdstrike_workbench_operator";
const SECRET_KEY_STORE_KEY = "operator_secret_key";

let persistTimer: ReturnType<typeof setTimeout> | null = null;
let lastOperatorStorageSnapshot =
  typeof window === "undefined" ? null : readOperatorStorageSnapshot();

function readOperatorStorageSnapshot(): string | null {
  try {
    return localStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
}

function schedulePersist(operator: OperatorIdentity | null): void {
  if (persistTimer) clearTimeout(persistTimer);
  persistTimer = setTimeout(() => {
    try {
      if (operator) {
        const raw = JSON.stringify(operator);
        localStorage.setItem(STORAGE_KEY, raw);
        lastOperatorStorageSnapshot = raw;
      } else {
        localStorage.removeItem(STORAGE_KEY);
        lastOperatorStorageSnapshot = null;
      }
    } catch (e) {
      console.error("[operator-store] persistOperator failed:", e);
    }
    persistTimer = null;
  }, 500);
}

function persistOperatorSync(operator: OperatorIdentity | null): void {
  try {
    if (operator) {
      const raw = JSON.stringify(operator);
      localStorage.setItem(STORAGE_KEY, raw);
      lastOperatorStorageSnapshot = raw;
    } else {
      localStorage.removeItem(STORAGE_KEY);
      lastOperatorStorageSnapshot = null;
    }
  } catch (e) {
    console.error("[operator-store] persistOperator failed:", e);
  }
}

function loadPersistedOperator(): OperatorIdentity | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (
      !parsed ||
      typeof parsed !== "object" ||
      typeof parsed.publicKey !== "string" ||
      typeof parsed.fingerprint !== "string"
    ) {
      console.warn("[operator-store] Invalid persisted operator data, ignoring");
      return null;
    }
    return parsed as OperatorIdentity;
  } catch (e) {
    console.warn("[operator-store] loadPersistedOperator failed:", e);
    return null;
  }
}

function syncOperatorStoreWithStorage(): void {
  const snapshot = readOperatorStorageSnapshot();
  if (snapshot === lastOperatorStorageSnapshot) {
    return;
  }

  lastOperatorStorageSnapshot = snapshot;
  useOperatorStoreBase.setState({
    currentOperator: loadPersistedOperator(),
    initialized: true,
    loading: false,
  });
}

// ---------------------------------------------------------------------------
// Zustand store
// ---------------------------------------------------------------------------

export interface OperatorStoreState {
  currentOperator: OperatorIdentity | null;
  initialized: boolean;
  loading: boolean;
  actions: OperatorActions;
}

interface OperatorActions {
  _init: () => void;
  createIdentity: (displayName: string) => Promise<OperatorIdentity>;
  updateDisplayName: (displayName: string) => void;
  linkIdp: (claims: IdpClaims) => void;
  unlinkIdp: () => void;
  /** @deprecated Callers should migrate to signPayload to avoid exposing the raw secret key. */
  getSecretKey: () => Promise<string | null>;
  signPayload: (data: Uint8Array) => Promise<string>;
  signData: (data: Uint8Array) => Promise<string | null>;
  exportKey: (passphrase: string) => Promise<string | null>;
  importKey: (encoded: string, passphrase: string) => Promise<boolean>;
  revokeIdentity: (reason: string) => void;
  signOut: () => Promise<void>;
}

const useOperatorStoreBase = create<OperatorStoreState>()(
  immer((set, get) => {
    return {
      currentOperator: null,
      initialized: false,
      loading: true,

      actions: {
        _init: () => {
          const operator = loadPersistedOperator();
          set((state) => {
            state.currentOperator = operator as any;
            state.initialized = true;
            state.loading = false;
          });
        },

        createIdentity: async (displayName: string): Promise<OperatorIdentity> => {
          const { identity, secretKeyHex } = await createOperatorIdentity(displayName);
          await secureStore.set(SECRET_KEY_STORE_KEY, secretKeyHex);
          set((state) => {
            state.currentOperator = identity as any;
            state.loading = false;
          });
          schedulePersist(identity);
          return identity;
        },

        updateDisplayName: (displayName: string) => {
          set((state) => {
            if (state.currentOperator) {
              state.currentOperator.displayName = displayName;
            }
          });
          schedulePersist(get().currentOperator);
        },

        linkIdp: (claims: IdpClaims) => {
          set((state) => {
            if (state.currentOperator) {
              state.currentOperator.idpClaims = claims as any;
            }
          });
          schedulePersist(get().currentOperator);
        },

        unlinkIdp: () => {
          set((state) => {
            if (state.currentOperator) {
              state.currentOperator.idpClaims = null;
            }
          });
          schedulePersist(get().currentOperator);
        },

        getSecretKey: async (): Promise<string | null> => {
          return secureStore.get(SECRET_KEY_STORE_KEY);
        },

        signData: async (data: Uint8Array): Promise<string | null> => {
          const secretKey = await secureStore.get(SECRET_KEY_STORE_KEY);
          if (!secretKey) return null;
          return signData(data, secretKey);
        },

        signPayload: async (data: Uint8Array): Promise<string> => {
          const secretKey = await secureStore.get(SECRET_KEY_STORE_KEY);
          if (!secretKey) {
            throw new Error("No secret key available — create or import an identity first");
          }
          return signDetachedPayload(data, secretKey);
        },

        revokeIdentity: (reason: string): void => {
          set((state) => {
            if (state.currentOperator) {
              state.currentOperator.revokedAt = Date.now();
              state.currentOperator.revocationReason = reason;
            }
          });
          schedulePersist(get().currentOperator);
        },

        exportKey: async (passphrase: string): Promise<string | null> => {
          const secretKey = await secureStore.get(SECRET_KEY_STORE_KEY);
          if (!secretKey) return null;
          const publicKey = get().currentOperator?.publicKey;
          if (!publicKey) return null;
          return cryptoExportKey(secretKey, publicKey, passphrase);
        },

        importKey: async (encoded: string, passphrase: string): Promise<boolean> => {
          try {
            const { publicKeyHex, secretKeyHex } = await cryptoImportKey(encoded, passphrase);
            await secureStore.set(SECRET_KEY_STORE_KEY, secretKeyHex);
            // Reconstruct identity from the imported public key
            const fingerprint = await deriveFingerprint(publicKeyHex);
            const sigil = deriveSigil(fingerprint);
            const now = Date.now();
            const deviceId = publicKeyHex.slice(0, 16);
            const currentOp = get().currentOperator;
            const identity: OperatorIdentity = {
              publicKey: publicKeyHex,
              fingerprint,
              sigil,
              nickname: currentOp?.nickname ?? fingerprint.slice(0, 8),
              displayName: currentOp?.displayName ?? "Imported Identity",
              idpClaims: null,
              createdAt: now,
              originDeviceId: deviceId,
              devices: [{ deviceId, deviceName: "imported", addedAt: now, lastSeenAt: now }],
            };
            set((state) => {
              state.currentOperator = identity as any;
              state.loading = false;
            });
            schedulePersist(identity);
            return true;
          } catch {
            return false;
          }
        },

        signOut: async () => {
          // Flush any pending persist timer
          if (persistTimer) {
            clearTimeout(persistTimer);
            persistTimer = null;
          }
          await secureStore.delete(SECRET_KEY_STORE_KEY);
          persistOperatorSync(null);
          set((state) => {
            state.currentOperator = null;
          });
        },
      },
    };
  }),
);

// Auto-initialize from localStorage on store creation
useOperatorStoreBase.getState().actions._init();

export const useOperatorStore = createSelectors(useOperatorStoreBase);

// ---------------------------------------------------------------------------
// Backward-compatible hook — same shape the old Context-based hook returned
// ---------------------------------------------------------------------------

interface OperatorContextValue {
  currentOperator: OperatorIdentity | null;
  initialized: boolean;
  loading: boolean;
  createIdentity: (displayName: string) => Promise<OperatorIdentity>;
  updateDisplayName: (displayName: string) => void;
  linkIdp: (claims: IdpClaims) => void;
  unlinkIdp: () => void;
  /** @deprecated Callers should migrate to signPayload */
  getSecretKey: () => Promise<string | null>;
  signPayload: (data: Uint8Array) => Promise<string>;
  signData: (data: Uint8Array) => Promise<string | null>;
  exportKey: (passphrase: string) => Promise<string | null>;
  importKey: (encoded: string, passphrase: string) => Promise<boolean>;
  revokeIdentity: (reason: string) => void;
  signOut: () => Promise<void>;
}

/** @deprecated Use useOperatorStore directly */
export function useOperator(): OperatorContextValue {
  useLayoutEffect(() => {
    syncOperatorStoreWithStorage();
  }, []);

  const currentOperator = useOperatorStore((s) => s.currentOperator);
  const initialized = useOperatorStore((s) => s.initialized);
  const loading = useOperatorStore((s) => s.loading);
  const actions = useOperatorStore((s) => s.actions);

  return {
    currentOperator,
    initialized,
    loading,
    createIdentity: actions.createIdentity,
    updateDisplayName: actions.updateDisplayName,
    linkIdp: actions.linkIdp,
    unlinkIdp: actions.unlinkIdp,
    getSecretKey: actions.getSecretKey,
    signPayload: actions.signPayload,
    signData: actions.signData,
    exportKey: actions.exportKey,
    importKey: actions.importKey,
    revokeIdentity: actions.revokeIdentity,
    signOut: actions.signOut,
  };
}

/**
 * @deprecated Provider is no longer needed — Operator is now a Zustand store.
 * Kept as a pass-through wrapper for backward compatibility.
 */
export function OperatorProvider({ children }: { children: ReactNode }) {
  useLayoutEffect(() => {
    syncOperatorStoreWithStorage();
  }, []);

  return children as ReactElement;
}
