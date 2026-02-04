/**
 * PolicyContext - Policy state management
 */
import { createContext, useContext, useCallback, useState, useEffect, type ReactNode } from "react";
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
      const response = await fetch(`${daemonUrl}/api/v1/policy`);
      if (!response.ok) {
        throw new Error(`Failed to fetch policy: ${response.status}`);
      }
      const data = await response.json();
      setState((s) => ({
        ...s,
        currentPolicy: data.data?.policy ?? data.policy,
        policyBundle: data.data,
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
      const response = await fetch(`${daemonUrl}/api/v1/policy/validate`, {
        method: "POST",
        headers: { "Content-Type": "application/x-yaml" },
        body: yaml,
      });
      const data = await response.json();
      return data.data ?? data;
    },
    [daemonUrl]
  );

  const reloadPolicy = useCallback(async () => {
    const response = await fetch(`${daemonUrl}/api/v1/policy/reload`, {
      method: "POST",
    });
    if (!response.ok) {
      throw new Error(`Failed to reload policy: ${response.status}`);
    }
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
