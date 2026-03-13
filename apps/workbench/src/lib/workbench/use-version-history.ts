import { useState, useEffect, useCallback, useRef, useMemo } from "react";
import { getVersionStore, type PolicyVersion } from "./version-store";
import { diffVersions, type VersionDiff } from "./version-diff";
import type { WorkbenchPolicy } from "./types";

const PAGE_SIZE = 20;
const MAX_VERSIONS = 200;

export function useVersionHistory(policyId: string | undefined) {
  const [versions, setVersions] = useState<PolicyVersion[]>([]);
  const [loading, setLoading] = useState(false);
  const [hasMore, setHasMore] = useState(false);
  const [totalCount, setTotalCount] = useState(0);
  const [initialized, setInitialized] = useState(false);
  const offsetRef = useRef(0);
  const storeRef = useRef(getVersionStore());

  // Initialize the store once
  useEffect(() => {
    let cancelled = false;
    storeRef.current.init().then(() => {
      if (!cancelled) setInitialized(true);
    }).catch((err) => {
      console.error("[use-version-history] Failed to init store:", err);
      if (!cancelled) setInitialized(true); // still mark initialized to avoid hanging
    });
    return () => { cancelled = true; };
  }, []);

  // Load initial versions when policyId changes
  useEffect(() => {
    if (!policyId || !initialized) return;
    let cancelled = false;
    const store = storeRef.current;

    setLoading(true);
    offsetRef.current = 0;

    Promise.all([
      store.getVersions(policyId, PAGE_SIZE, 0),
      store.getVersionCount(policyId),
    ])
      .then(([versionList, count]) => {
        if (cancelled) return;
        setVersions(versionList);
        setTotalCount(count);
        setHasMore(versionList.length < count);
        offsetRef.current = versionList.length;
      })
      .catch((err) => {
        console.error("[use-version-history] Failed to load versions:", err);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => { cancelled = true; };
  }, [policyId, initialized]);

  const loadMore = useCallback(() => {
    if (!policyId || loading || !hasMore || !initialized) return;

    setLoading(true);
    const store = storeRef.current;
    const currentOffset = offsetRef.current;

    store
      .getVersions(policyId, PAGE_SIZE, currentOffset)
      .then((moreVersions) => {
        setVersions((prev) => [...prev, ...moreVersions]);
        offsetRef.current = currentOffset + moreVersions.length;
        setHasMore(currentOffset + moreVersions.length < totalCount);
      })
      .catch((err) => {
        console.error("[use-version-history] Failed to load more:", err);
      })
      .finally(() => {
        setLoading(false);
      });
  }, [policyId, loading, hasMore, totalCount, initialized]);

  const saveVersion = useCallback(
    async (yaml: string, policy: WorkbenchPolicy, message?: string): Promise<PolicyVersion | null> => {
      if (!policyId || !initialized) return null;
      const store = storeRef.current;

      try {
        const version = await store.saveVersion(policyId, yaml, policy, message);

        // Auto-prune
        await store.deleteOldVersions(policyId, MAX_VERSIONS);

        // Refresh the version list
        const [updatedVersions, count] = await Promise.all([
          store.getVersions(policyId, PAGE_SIZE, 0),
          store.getVersionCount(policyId),
        ]);
        setVersions(updatedVersions);
        setTotalCount(count);
        setHasMore(updatedVersions.length < count);
        offsetRef.current = updatedVersions.length;

        return version;
      } catch (err) {
        console.error("[use-version-history] Failed to save version:", err);
        return null;
      }
    },
    [policyId, initialized],
  );

  const addTag = useCallback(
    async (versionId: string, tag: string, color?: string): Promise<void> => {
      if (!initialized) return;
      const store = storeRef.current;

      await store.addTag(versionId, tag, color);

      // Update the local state
      setVersions((prev) =>
        prev.map((v) =>
          v.id === versionId
            ? { ...v, tags: v.tags.includes(tag) ? v.tags : [...v.tags, tag] }
            : v,
        ),
      );
    },
    [initialized],
  );

  const removeTag = useCallback(
    async (versionId: string, tag: string): Promise<void> => {
      if (!initialized) return;
      const store = storeRef.current;

      await store.removeTag(versionId, tag);

      // Update the local state
      setVersions((prev) =>
        prev.map((v) =>
          v.id === versionId
            ? { ...v, tags: v.tags.filter((t) => t !== tag) }
            : v,
        ),
      );
    },
    [initialized],
  );

  const compareVersions = useCallback(
    (fromVersion: PolicyVersion, toVersion: PolicyVersion): VersionDiff => {
      return diffVersions(fromVersion.policy, toVersion.policy, fromVersion.version, toVersion.version);
    },
    [],
  );

  const exportChangelog = useCallback(async (): Promise<string> => {
    if (!policyId || !initialized) return "";
    const store = storeRef.current;
    return store.exportChangelog(policyId);
  }, [policyId, initialized]);

  const getVersion = useCallback(
    async (versionId: string): Promise<PolicyVersion | null> => {
      if (!initialized) return null;
      const store = storeRef.current;
      return store.getVersion(versionId);
    },
    [initialized],
  );

  return {
    versions,
    loading,
    hasMore,
    totalCount,
    initialized,
    loadMore,
    saveVersion,
    addTag,
    removeTag,
    compareVersions,
    exportChangelog,
    getVersion,
  };
}
