/**
 * React hook for orchestrating the publication pipeline.
 *
 * Coordinates validation gates, lab run gates, adapter publication builds,
 * SHA-256 hashing, and manifest persistence. Format-aware: delegates to
 * the appropriate DetectionWorkflowAdapter for each file type.
 */

import { useState, useCallback, useEffect, useRef, useMemo } from "react";
import type { FileType } from "../file-type-registry";
import type { PublicationManifest, PublishTarget, LabRun } from "./shared-types";
import type { PublicationRequest } from "./execution-types";
import { getAdapter, hasAdapter } from "./adapters";
import { getPublicationStore } from "./publication-store";
import { extractDocumentCoverage } from "./coverage-projection";
import { signPublicationOutput } from "./publication-provenance";

// ---- SHA-256 ----

async function sha256Hex(text: string): Promise<string> {
  const data = new TextEncoder().encode(text);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data.buffer as ArrayBuffer);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ---- Public Types ----

export interface PublishRequest {
  source: string;
  targetFormat: PublishTarget;
  evidencePackId?: string;
  labRunId?: string;
  skipLabGate?: boolean;
}

export interface PublishResult {
  success: boolean;
  manifest?: PublicationManifest;
  outputContent?: string;
  error?: string;
}

export interface PublishGateStatus {
  validationPassed: boolean;
  labRunPassed: boolean | null; // null = no run exists
  sourceHashChanged: boolean; // vs latest manifest
  gateOpen: boolean; // all required gates pass
  reasons: string[];
}

export interface UsePublicationReturn {
  /** All manifests for this document, newest first. */
  manifests: PublicationManifest[];
  /** The most recent manifest, or null. */
  latestManifest: PublicationManifest | null;
  /** Whether manifests are loading from the store. */
  loading: boolean;
  /** Execute a publication build, gate-check, and persist manifest. */
  publish(request: PublishRequest): Promise<PublishResult>;
  /** Whether this document/fileType can be published. */
  canPublish: boolean;
  /** Current gate status. */
  publishGateStatus: PublishGateStatus;
  /** Refresh manifests from the store. */
  refreshManifests(): void;
}

// ---- Available targets per file type ----

export function getAvailableTargets(fileType: FileType): PublishTarget[] {
  switch (fileType) {
    case "clawdstrike_policy":
      return ["native_policy", "fleet_deploy"];
    case "sigma_rule":
      return ["native_policy", "fleet_deploy", "json_export", "spl", "kql", "esql"];
    case "yara_rule":
      return ["json_export"];
    case "ocsf_event":
      return ["json_export"];
    default:
      return [];
  }
}

// ---- Hook ----

export function usePublication(
  documentId: string | undefined,
  fileType: FileType | undefined,
  options?: {
    /** Current validation state for the document. */
    validationValid?: boolean;
    /** Current source content for hash comparison. */
    currentSource?: string;
    /** Latest lab run for this document. */
    lastLabRun?: LabRun | null;
  },
): UsePublicationReturn {
  const [manifests, setManifests] = useState<PublicationManifest[]>([]);
  const [loading, setLoading] = useState(false);
  const [currentSourceHash, setCurrentSourceHash] = useState<string | null>(null);
  const storeInitialized = useRef(false);

  const canPublish = fileType != null && hasAdapter(fileType);

  // ---- Load manifests ----

  const refreshManifests = useCallback(() => {
    if (!documentId) return;

    const store = getPublicationStore();
    const doLoad = async () => {
      setLoading(true);
      try {
        if (!storeInitialized.current) {
          await store.init();
          storeInitialized.current = true;
        }
        const loaded = await store.getManifestsForDocument(documentId);
        setManifests(loaded);
      } catch (err) {
        console.warn("[use-publication] Failed to load manifests:", err);
      } finally {
        setLoading(false);
      }
    };

    void doLoad();
  }, [documentId]);

  useEffect(() => {
    if (documentId) {
      refreshManifests();
    } else {
      setManifests([]);
    }
  }, [documentId, refreshManifests]);

  useEffect(() => {
    if (!options?.currentSource) {
      setCurrentSourceHash(null);
      return;
    }

    let cancelled = false;
    void sha256Hex(options.currentSource).then((hash) => {
      if (!cancelled) {
        setCurrentSourceHash(hash);
      }
    });

    return () => {
      cancelled = true;
    };
  }, [options?.currentSource]);

  // ---- Derived state ----

  const latestManifest = manifests.length > 0 ? manifests[0] : null;

  const publishGateStatus = useMemo<PublishGateStatus>(() => {
    const validationPassed = options?.validationValid ?? false;
    const lastRun = options?.lastLabRun;
    const labRunPassed =
      lastRun === undefined ? null : lastRun === null ? null : lastRun.summary.failed === 0;

    // Source hash changed check
    const sourceHashChanged =
      latestManifest != null &&
      currentSourceHash != null &&
      latestManifest.sourceHash !== currentSourceHash;

    const reasons: string[] = [];
    if (!validationPassed) reasons.push("Validation has errors");
    if (labRunPassed === false) reasons.push("Latest lab run has failures");

    const gateOpen = validationPassed && labRunPassed !== false;

    return {
      validationPassed,
      labRunPassed,
      sourceHashChanged,
      gateOpen,
      reasons,
    };
  }, [currentSourceHash, latestManifest, options?.lastLabRun, options?.validationValid]);

  // ---- Publish ----

  const publish = useCallback(
    async (request: PublishRequest): Promise<PublishResult> => {
      if (!documentId || !fileType) {
        return { success: false, error: "No active document" };
      }

      const adapter = getAdapter(fileType);
      if (!adapter) {
        return { success: false, error: `No adapter registered for ${fileType}` };
      }

      // Gate 1: Validation
      const validationOk = options?.validationValid ?? false;
      if (!validationOk) {
        return { success: false, error: "Publication blocked: document has validation errors" };
      }

      // Gate 2: Lab run (unless explicitly skipped)
      if (!request.skipLabGate) {
        const lastRun = options?.lastLabRun;
        if (lastRun && lastRun.summary.failed > 0) {
          return {
            success: false,
            error: `Publication blocked: latest lab run has ${lastRun.summary.failed} failure(s)`,
          };
        }
      }

      try {
        // Build publication via adapter
        const computedSourceHash = await sha256Hex(request.source);
        const pubRequest: PublicationRequest = {
          document: {
            documentId,
            fileType,
            filePath: null,
            name: documentId,
            sourceHash: computedSourceHash,
          },
          source: request.source,
          targetFormat: request.targetFormat,
          evidencePackId: request.evidencePackId,
          labRunId: request.labRunId,
        };

        const buildResult = await adapter.buildPublication(pubRequest);

        // Verify source hash matches what was provided
        if (buildResult.manifest.sourceHash !== computedSourceHash) {
          return {
            success: false,
            error: "Source hash mismatch: document may have changed during publication",
          };
        }

        const provenance = await signPublicationOutput(
          buildResult.outputHash,
          documentId,
          request.targetFormat,
        );
        const coverageSnapshot = extractDocumentCoverage(fileType, request.source);

        // Build the full manifest
        const manifest: PublicationManifest = {
          ...buildResult.manifest,
          id: crypto.randomUUID(),
          createdAt: new Date().toISOString(),
          coverageSnapshot,
          signer: provenance.signer,
          provenance: provenance.provenance,
          receiptId: provenance.receiptId,
        };

        // Persist to store
        const store = getPublicationStore();
        if (!storeInitialized.current) {
          await store.init();
          storeInitialized.current = true;
        }
        await store.savePublication(manifest, buildResult.outputContent);

        // Update local state
        setManifests((prev) => [manifest, ...prev]);

        return { success: true, manifest, outputContent: buildResult.outputContent };
      } catch (err) {
        const msg = err instanceof Error ? err.message : "Publication build failed";
        return { success: false, error: msg };
      }
    },
    [documentId, fileType, options?.validationValid, options?.lastLabRun],
  );

  return {
    manifests,
    latestManifest,
    loading,
    publish,
    canPublish,
    publishGateStatus,
    refreshManifests,
  };
}
