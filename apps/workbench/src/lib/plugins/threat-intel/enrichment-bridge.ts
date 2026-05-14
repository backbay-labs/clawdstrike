import { useState, useCallback, useRef } from "react";
import type { EnrichmentResult, ThreatIntelSource } from "@clawdstrike/plugin-sdk";
import type { Finding } from "@/lib/workbench/finding-engine";
import { extractIndicators } from "@/lib/workbench/indicator-extractor";
import { getAllThreatIntelSources } from "@/lib/workbench/threat-intel-registry";

export type EnrichmentSourceStatusState = "idle" | "loading" | "done" | "error";

export interface EnrichmentSourceStatus {
  sourceId: string;
  sourceName: string;
  status: EnrichmentSourceStatusState;
  result?: EnrichmentResult;
  error?: string;
}

interface EnrichmentOrchestratorLike {
  enrich(
    indicator: unknown,
    options?: {
      sourceIds?: string[];
      signal?: AbortSignal;
      onResult?: (result: EnrichmentResult) => void;
    },
  ): Promise<EnrichmentResult[]>;
}

export interface UseEnrichmentBridgeReturn {
  runEnrichment: (finding: Pick<Finding, "id">) => void;
  sourceStatuses: EnrichmentSourceStatus[];
  isEnriching: boolean;
  results: EnrichmentResult[];
  cancel: () => void;
}

export function useEnrichmentBridge(
  orchestrator: EnrichmentOrchestratorLike,
): UseEnrichmentBridgeReturn {
  const [sourceStatuses, setSourceStatuses] = useState<EnrichmentSourceStatus[]>([]);
  const [isEnriching, setIsEnriching] = useState(false);
  const [results, setResults] = useState<EnrichmentResult[]>([]);
  const abortControllerRef = useRef<AbortController | null>(null);

  const cancel = useCallback(() => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
    }
    setIsEnriching(false);
  }, []);

  const runEnrichment = useCallback(
    (finding: Pick<Finding, "id">) => {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }

      const controller = new AbortController();
      abortControllerRef.current = controller;
      const { signal } = controller;

      // so we pass undefined -- the extractor falls back to finding-only extraction)
      const indicators = extractIndicators(finding, undefined as never);

      const sources: ThreatIntelSource[] = getAllThreatIntelSources();

      const initialStatuses: EnrichmentSourceStatus[] = sources.map((source) => ({
        sourceId: source.id,
        sourceName: source.name,
        status: "loading" as const,
      }));

      setSourceStatuses(initialStatuses);
      setResults([]);
      setIsEnriching(true);

      if (indicators.length === 0) {
        setIsEnriching(false);
        setSourceStatuses(
          sources.map((source) => ({
            sourceId: source.id,
            sourceName: source.name,
            status: "done" as const,
          })),
        );
        return;
      }

      // to avoid the race condition of manual counter tracking.
      const promises = indicators.map((indicator) =>
        orchestrator.enrich(indicator, {
          signal,
          onResult: (result: EnrichmentResult) => {
            setSourceStatuses((prev) =>
              prev.map((s) =>
                s.sourceId === result.sourceId
                  ? { ...s, status: "done" as const, result }
                  : s,
              ),
            );
            setResults((prev) => [...prev, result]);
          },
        }),
      );

      Promise.allSettled(promises).then((settled) => {
        const errors = settled
          .filter(
            (r): r is PromiseRejectedResult => r.status === "rejected",
          )
          .map((r) =>
            r.reason instanceof Error
              ? r.reason.message
              : "Enrichment failed",
          );

        setSourceStatuses((prev) =>
          prev.map((s) => {
            if (s.status === "loading") {
              if (errors.length > 0) {
                return { ...s, status: "error" as const, error: errors[0] };
              }
              return { ...s, status: "done" as const };
            }
            return s;
          }),
        );
        setIsEnriching(false);
      });
    },
    [orchestrator, cancel],
  );

  return {
    runEnrichment,
    sourceStatuses,
    isEnriching,
    results,
    cancel,
  };
}
