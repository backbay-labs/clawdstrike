/**
 * React hook for managing lab execution through the adapter layer.
 *
 * Wraps the DetectionWorkflowAdapter pattern to provide a format-aware
 * execution interface. For policy files, this delegates to the policy
 * adapter (which uses the existing simulation engine). For non-policy
 * formats, it checks adapter availability and provides appropriate
 * status information.
 */

import { useState, useCallback, useEffect, useRef } from "react";
import type { FileType } from "../file-type-registry";
import type { EvidencePack, LabRun } from "./shared-types";
import type {
  DetectionExecutionRequest,
  DetectionExecutionResult,
} from "./execution-types";
import { getAdapter, hasAdapter } from "./adapters";
import { getLabRunStore } from "./lab-run-store";

export interface UseLabExecutionReturn {
  /** Whether an adapter exists for the current file type. */
  canExecute: boolean;
  /** Whether a lab run is currently in progress. */
  isRunning: boolean;
  /** The most recent lab run for this document, or null. */
  lastRun: LabRun | null;
  /** History of lab runs for this document. */
  runHistory: LabRun[];
  /** Execute a lab run against the given evidence pack. */
  executeRun(
    evidencePack: EvidencePack,
    source: string,
  ): Promise<DetectionExecutionResult | null>;
  /** Load run history from the store. */
  loadRunHistory(): void;
  /** Delete a specific run from history. */
  deleteRun(runId: string): Promise<void>;
}

export function useLabExecution(
  documentId: string | undefined,
  fileType: FileType | undefined,
): UseLabExecutionReturn {
  const [isRunning, setIsRunning] = useState(false);
  const [lastRun, setLastRun] = useState<LabRun | null>(null);
  const [runHistory, setRunHistory] = useState<LabRun[]>([]);
  const storeInitialized = useRef(false);

  const canExecute = fileType != null && hasAdapter(fileType);

  // Initialize the store and load history on mount / documentId change
  const loadRunHistory = useCallback(() => {
    if (!documentId) return;

    const store = getLabRunStore();
    const doLoad = async () => {
      try {
        if (!storeInitialized.current) {
          await store.init();
          storeInitialized.current = true;
        }
        const runs = await store.getRunsForDocument(documentId, 20);
        setRunHistory(runs);
        if (runs.length > 0) {
          setLastRun(runs[0]);
        }
      } catch (err) {
        console.warn("[use-lab-execution] Failed to load run history:", err);
      }
    };

    void doLoad();
  }, [documentId]);

  // Load history when documentId changes
  useEffect(() => {
    if (documentId) {
      loadRunHistory();
    } else {
      setRunHistory([]);
      setLastRun(null);
    }
  }, [documentId, loadRunHistory]);

  const buildAdapterRunConfig = useCallback(
    (source: string): Record<string, unknown> => {
      switch (fileType) {
        case "clawdstrike_policy":
          return { policySource: source };
        case "sigma_rule":
          return { sigmaSource: source };
        case "yara_rule":
          return { yaraSource: source };
        case "ocsf_event":
          return { ocsfSource: source };
        default:
          return { source };
      }
    },
    [fileType],
  );

  const executeRun = useCallback(
    async (
      evidencePack: EvidencePack,
      source: string,
    ): Promise<DetectionExecutionResult | null> => {
      if (!documentId || !fileType) return null;

      const adapter = getAdapter(fileType);
      if (!adapter) return null;

      setIsRunning(true);
      try {
        const request: DetectionExecutionRequest = {
          document: {
            documentId,
            fileType,
            filePath: null,
            name: documentId,
            sourceHash: "",
          },
          evidencePack,
          adapterRunConfig: buildAdapterRunConfig(source),
        };

        const result = await adapter.runLab(request);

        // Persist the run to the store
        const store = getLabRunStore();
        try {
          if (!storeInitialized.current) {
            await store.init();
            storeInitialized.current = true;
          }
          await store.saveRun(result.run);
        } catch (err) {
          console.warn("[use-lab-execution] Failed to save run:", err);
        }

        setLastRun(result.run);
        setRunHistory((prev) => [result.run, ...prev].slice(0, 20));

        return result;
      } catch (err) {
        console.error("[use-lab-execution] Adapter execution failed:", err);
        return null;
      } finally {
        setIsRunning(false);
      }
    },
    [buildAdapterRunConfig, documentId, fileType],
  );

  const deleteRun = useCallback(
    async (runId: string) => {
      const store = getLabRunStore();
      try {
        if (!storeInitialized.current) {
          await store.init();
          storeInitialized.current = true;
        }
        await store.deleteRun(runId);
        setRunHistory((prev) => {
          const remaining = prev.filter((r) => r.id !== runId);
          // Update lastRun based on the new remaining list
          setLastRun((prevLast) => {
            if (prevLast?.id === runId) {
              return remaining.length > 0 ? remaining[0] : null;
            }
            return prevLast;
          });
          return remaining;
        });
      } catch (err) {
        console.warn("[use-lab-execution] Failed to delete run:", err);
      }
    },
    [],
  );

  return {
    canExecute,
    isRunning,
    lastRun,
    runHistory,
    executeRun,
    loadRunHistory,
    deleteRun,
  };
}
