/**
 * PolicyContext - Policy state management
 */
import { createContext, type ReactNode, useCallback, useContext, useEffect, useState } from "react";
import { HushdClient } from "@/services/hushdClient";
import type { Policy, PolicyBundle, ValidationResult } from "@/types/policies";
import { useConnection } from "./ConnectionContext";

interface PolicyState {
  currentPolicy?: Policy;
  policyBundle?: PolicyBundle;
  isLoading: boolean;
  error?: string;
  lastFetched?: number;
}

interface PolicyContextValue extends PolicyState {
  fetchPolicy: () => Promise<void>;
  validatePolicy: (yaml: string) => Promise<ValidationResult>;
  reloadPolicy: () => Promise<void>;
}

const PolicyContext = createContext<PolicyContextValue | null>(null);

export function PolicyProvider({ children }: { children: ReactNode }) {
  const { status, daemonUrl } = useConnection();

  const [state, setState] = useState<PolicyState>({
    isLoading: false,
  });

  const fetchPolicy = useCallback(async () => {
    if (status !== "connected") return;

    setState((s) => ({ ...s, isLoading: true, error: undefined }));
    try {
      const client = new HushdClient(daemonUrl);
      const data = await client.getPolicy();
      const normalizedPolicy: Policy = {
        version: data.version,
        name: data.name,
        description: data.description,
        guards: {},
      };
      setState((s) => ({
        ...s,
        currentPolicy: normalizedPolicy,
        policyBundle: {
          policy: normalizedPolicy,
          policy_hash: data.policy_hash,
        },
        isLoading: false,
        lastFetched: Date.now(),
      }));
    } catch (e) {
      const message = e instanceof Error ? e.message : "Failed to fetch policy";
      setState((s) => ({ ...s, isLoading: false, error: message }));
    }
  }, [status, daemonUrl]);

  const validatePolicy = useCallback(
    async (yaml: string): Promise<ValidationResult> => {
      const client = new HushdClient(daemonUrl);
      return client.validatePolicy(yaml);
    },
    [daemonUrl],
  );

  const reloadPolicy = useCallback(async () => {
    const client = new HushdClient(daemonUrl);
    await client.reloadPolicy();
    await fetchPolicy();
  }, [daemonUrl, fetchPolicy]);

  // Fetch policy when connected
  useEffect(() => {
    if (status === "connected") {
      fetchPolicy();
    } else {
      setState((s) => ({ ...s, currentPolicy: undefined, policyBundle: undefined }));
    }
  }, [status, fetchPolicy]);

  const value: PolicyContextValue = {
    ...state,
    fetchPolicy,
    validatePolicy,
    reloadPolicy,
  };

  return <PolicyContext.Provider value={value}>{children}</PolicyContext.Provider>;
}

export function usePolicy(): PolicyContextValue {
  const context = useContext(PolicyContext);
  if (!context) {
    throw new Error("usePolicy must be used within PolicyProvider");
  }
  return context;
}

export function useCurrentPolicy(): Policy | undefined {
  return usePolicy().currentPolicy;
}
