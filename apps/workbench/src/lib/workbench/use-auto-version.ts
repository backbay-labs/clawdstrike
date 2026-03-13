import { useEffect, useRef } from "react";
import { getVersionStore } from "./version-store";
import type { WorkbenchPolicy } from "./types";

/**
 * Auto-versioning hook: creates a version snapshot whenever the policy
 * transitions from dirty to clean (i.e., the user explicitly saves).
 *
 * This does NOT create versions for auto-saves (the 2s debounced localStorage backup).
 * It relies on the `dirty` flag transitioning from true -> false, which only happens
 * on explicit save (MARK_CLEAN action).
 *
 * Dedup: if the YAML hash matches the latest version, the store silently skips.
 * Pruning: keeps at most 200 versions per policy (auto-prunes oldest untagged).
 */
export function useAutoVersion(
  policyId: string | undefined,
  yaml: string,
  policy: WorkbenchPolicy,
  dirty: boolean,
) {
  const wasDirtyRef = useRef(dirty);
  const initRef = useRef(false);
  const storeRef = useRef(getVersionStore());

  // Initialize the store once
  useEffect(() => {
    if (initRef.current) return;
    initRef.current = true;
    storeRef.current.init().catch((err) => {
      console.error("[auto-version] Failed to init store:", err);
    });
  }, []);

  useEffect(() => {
    // Detect transition from dirty -> clean (explicit save happened)
    if (wasDirtyRef.current && !dirty && policyId) {
      // Fire-and-forget: don't block the UI
      storeRef.current
        .saveVersion(policyId, yaml, policy)
        .then(() => storeRef.current.deleteOldVersions(policyId, 200))
        .catch((err) => {
          console.error("[auto-version] Failed to auto-save version:", err);
        });
    }
    wasDirtyRef.current = dirty;
  }, [dirty, policyId, yaml, policy]);
}
