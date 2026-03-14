import React, {
  createContext,
  useContext,
  useReducer,
  useCallback,
  useEffect,
  useRef,
  type ReactNode,
} from "react";
import type { OperatorIdentity, IdpClaims } from "./operator-types";
import {
  createOperatorIdentity,
  signData,
  deriveFingerprint,
  deriveSigil,
  exportKey as cryptoExportKey,
  importKey as cryptoImportKey,
} from "./operator-crypto";
import { signDetachedPayload } from "./signature-adapter";
import { secureStore } from "./secure-store";

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

const STORAGE_KEY = "clawdstrike_workbench_operator";
const SECRET_KEY_STORE_KEY = "operator_secret_key";

function persistOperator(operator: OperatorIdentity | null): void {
  try {
    if (operator) {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(operator));
    } else {
      localStorage.removeItem(STORAGE_KEY);
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

const INITIAL_STATE: OperatorState = {
  currentOperator: null,
  initialized: false,
  loading: true,
};

interface OperatorContextValue {
  currentOperator: OperatorIdentity | null;
  initialized: boolean;
  loading: boolean;
  createIdentity: (displayName: string) => Promise<OperatorIdentity>;
  updateDisplayName: (displayName: string) => void;
  linkIdp: (claims: IdpClaims) => void;
  unlinkIdp: () => void;
  /**
   * @deprecated Callers should migrate to {@link signPayload} to avoid
   * exposing the raw secret key outside the operator store.
   */
  getSecretKey: () => Promise<string | null>;
  signPayload: (data: Uint8Array) => Promise<string>;
  signData: (data: Uint8Array) => Promise<string | null>;
  exportKey: (passphrase: string) => Promise<string | null>;
  importKey: (encoded: string, passphrase: string) => Promise<boolean>;
  revokeIdentity: (reason: string) => void;
  signOut: () => Promise<void>;
}

const OperatorContext = createContext<OperatorContextValue | null>(null);

export function useOperator(): OperatorContextValue {
  const ctx = useContext(OperatorContext);
  if (!ctx) throw new Error("useOperator must be used within OperatorProvider");
  return ctx;
}

export function OperatorProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(operatorReducer, INITIAL_STATE);

  // Load from localStorage on mount
  useEffect(() => {
    const operator = loadPersistedOperator();
    dispatch({ type: "INIT", operator });
  }, []);

    const persistRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => {
    if (!state.initialized) return;
    if (persistRef.current) clearTimeout(persistRef.current);
    persistRef.current = setTimeout(() => {
      persistOperator(state.currentOperator);
    }, 500);
    return () => {
      if (persistRef.current) clearTimeout(persistRef.current);
    };
  }, [state.currentOperator, state.initialized]);

  
  const createIdentity = useCallback(
    async (displayName: string): Promise<OperatorIdentity> => {
      const { identity, secretKeyHex } = await createOperatorIdentity(displayName);
      await secureStore.set(SECRET_KEY_STORE_KEY, secretKeyHex);
      dispatch({ type: "CREATE", operator: identity });
      return identity;
    },
    [],
  );

  const updateDisplayName = useCallback((displayName: string) => {
    dispatch({ type: "UPDATE_DISPLAY_NAME", displayName });
  }, []);

  const linkIdp = useCallback((claims: IdpClaims) => {
    dispatch({ type: "LINK_IDP", claims });
  }, []);

  const unlinkIdp = useCallback(() => {
    dispatch({ type: "UNLINK_IDP" });
  }, []);

  const getSecretKey = useCallback(async (): Promise<string | null> => {
    return secureStore.get(SECRET_KEY_STORE_KEY);
  }, []);

  const signDataAction = useCallback(
    async (data: Uint8Array): Promise<string | null> => {
      const secretKey = await secureStore.get(SECRET_KEY_STORE_KEY);
      if (!secretKey) return null;
      return signData(data, secretKey);
    },
    [],
  );

  const signPayloadAction = useCallback(
    async (data: Uint8Array): Promise<string> => {
      const secretKey = await secureStore.get(SECRET_KEY_STORE_KEY);
      if (!secretKey) {
        throw new Error("No secret key available — create or import an identity first");
      }
      return signDetachedPayload(data, secretKey);
    },
    [],
  );

  const revokeIdentityAction = useCallback(
    (reason: string): void => {
      dispatch({ type: "REVOKE", revokedAt: Date.now(), revocationReason: reason });
    },
    [],
  );

  const exportKeyAction = useCallback(
    async (passphrase: string): Promise<string | null> => {
      const secretKey = await secureStore.get(SECRET_KEY_STORE_KEY);
      if (!secretKey) return null;
      const publicKey = state.currentOperator?.publicKey;
      if (!publicKey) return null;
      return cryptoExportKey(secretKey, publicKey, passphrase);
    },
    [state.currentOperator],
  );

  const importKeyAction = useCallback(
    async (encoded: string, passphrase: string): Promise<boolean> => {
      try {
        const { publicKeyHex, secretKeyHex } = await cryptoImportKey(encoded, passphrase);
        await secureStore.set(SECRET_KEY_STORE_KEY, secretKeyHex);
        // Reconstruct identity from the imported public key
        const fingerprint = await deriveFingerprint(publicKeyHex);
        const sigil = deriveSigil(fingerprint);
        const now = Date.now();
        const deviceId = publicKeyHex.slice(0, 16);
        dispatch({
          type: "CREATE",
          operator: {
            publicKey: publicKeyHex,
            fingerprint,
            sigil,
            nickname: state.currentOperator?.nickname ?? fingerprint.slice(0, 8),
            displayName: state.currentOperator?.displayName ?? "Imported Identity",
            idpClaims: null,
            createdAt: now,
            originDeviceId: deviceId,
            devices: [{ deviceId, deviceName: "imported", addedAt: now, lastSeenAt: now }],
          },
        });
        return true;
      } catch {
        return false;
      }
    },
    [state.currentOperator],
  );

  const signOutAction = useCallback(async () => {
    if (persistRef.current) clearTimeout(persistRef.current);
    await secureStore.delete(SECRET_KEY_STORE_KEY);
    persistOperator(null);
    dispatch({ type: "SIGN_OUT" });
  }, []);

  const value: OperatorContextValue = {
    currentOperator: state.currentOperator,
    initialized: state.initialized,
    loading: state.loading,
    createIdentity,
    updateDisplayName,
    linkIdp,
    unlinkIdp,
    getSecretKey,
    signPayload: signPayloadAction,
    signData: signDataAction,
    exportKey: exportKeyAction,
    importKey: importKeyAction,
    revokeIdentity: revokeIdentityAction,
    signOut: signOutAction,
  };

  return (
    <OperatorContext.Provider value={value}>
      {children}
    </OperatorContext.Provider>
  );
}
