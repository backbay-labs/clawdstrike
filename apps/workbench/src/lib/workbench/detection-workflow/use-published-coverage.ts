import { useCallback, useEffect, useState } from "react";
import type { DocumentCoverageEntry } from "./coverage-gap-engine";
import { buildPublishedCoverage } from "./coverage-projection";
import { getPublicationStore } from "./publication-store";
import { logger } from "@/lib/logger";

export function usePublishedCoverage(): DocumentCoverageEntry[] {
  const [coverage, setCoverage] = useState<DocumentCoverageEntry[]>([]);

  const loadCoverage = useCallback(async () => {
    const store = getPublicationStore();
    try {
      await store.init();
      const manifests = await store.getAllManifests();
      setCoverage(buildPublishedCoverage(manifests));
    } catch (error) {
      logger.warn("[use-published-coverage] Failed to load publication coverage:", error);
      setCoverage([]);
    }
  }, []);

  useEffect(() => {
    void loadCoverage();
  }, [loadCoverage]);

  return coverage;
}
