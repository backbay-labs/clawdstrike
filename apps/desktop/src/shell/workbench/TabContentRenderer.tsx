/**
 * TabContentRenderer - Resolves tab kind to a lazy component and manages a keep-alive pool.
 *
 * - Active tab is always visible.
 * - Recently-used tabs stay mounted but hidden (display: none) for fast switching.
 * - Pool size defaults to 3. 3D-heavy kinds (keepAlive: false) are never pooled.
 * - Zero-tab state shows a shell-appropriate hint.
 */
import { Suspense, useEffect, useMemo, useRef } from "react";
import { useTabGroup, useShell } from "./WorkbenchStateProvider";
import { getTabRegistryEntry } from "./tabRegistry";
import type { TabState, ShellMode } from "./workbenchState";

interface TabContentRendererProps {
  groupId: string;
  poolSize?: number;
}

interface PoolEntry {
  tabId: string;
  kind: string;
  lastActive: number;
}

const EMPTY_HINT: Record<ShellMode, string> = {
  wire: "Select a signal thread from the Scopes lens.",
  hunt: "Launch a hunt from the command palette.",
  lab: "Open a folder from the Files lens.",
  case: "Create a case from the Notes lens.",
};

export function TabContentRenderer({ groupId, poolSize = 3 }: TabContentRendererProps) {
  const group = useTabGroup(groupId);
  const shell = useShell();
  const poolRef = useRef<PoolEntry[]>([]);

  const tabs = group?.tabs ?? [];
  const activeTabId = group?.activeTabId ?? null;
  const activeTab = activeTabId ? tabs.find((t) => t.id === activeTabId) ?? null : null;

  // Update pool ref in an effect (safe for concurrent mode, mutations only during commit)
  useEffect(() => {
    const pool = poolRef.current;

    if (activeTab) {
      const entry = getTabRegistryEntry(activeTab.kind);
      const canPool = entry?.keepAlive !== false;

      // Update pool: move active tab to front
      const existingIndex = pool.findIndex((p) => p.tabId === activeTab.id);
      if (existingIndex >= 0) {
        pool[existingIndex].lastActive = Date.now();
      } else if (canPool) {
        pool.push({ tabId: activeTab.id, kind: activeTab.kind, lastActive: Date.now() });
      }

      // Evict LRU entries beyond pool size
      pool.sort((a, b) => b.lastActive - a.lastActive);
      while (pool.length > poolSize) {
        pool.pop();
      }
    }

    // Remove pool entries for tabs that no longer exist
    for (let i = pool.length - 1; i >= 0; i--) {
      if (!tabs.find((t) => t.id === pool[i].tabId)) {
        pool.splice(i, 1);
      }
    }
  }, [activeTab, tabs, poolSize]);

  // Derive mounted tabs from pool (read-only during render)
  const mountedTabs = useMemo(() => {
    const pool = poolRef.current;
    const mounted = new Map<string, TabState>();

    // Always mount the active tab
    if (activeTab) {
      mounted.set(activeTab.id, activeTab);
    }

    // Add pooled tabs
    for (const p of pool) {
      const tab = tabs.find((t) => t.id === p.tabId);
      if (tab && !mounted.has(tab.id)) {
        const entry = getTabRegistryEntry(tab.kind);
        if (entry?.keepAlive !== false) {
          mounted.set(tab.id, tab);
        }
      }
    }

    return Array.from(mounted.values());
  }, [activeTab, tabs]);

  // Zero-tab hint (the full welcome screen lives at the WorkbenchShell level)
  if (tabs.length === 0 || !activeTab) {
    return (
      <div className="flex flex-1 items-center justify-center">
        <p className="text-[12px] text-[rgba(182,183,193,0.4)]">{EMPTY_HINT[shell]}</p>
      </div>
    );
  }

  return (
    <div className="relative flex-1 overflow-hidden">
      {mountedTabs.map((tab) => {
        const isActive = tab.id === activeTabId;
        const entry = getTabRegistryEntry(tab.kind);
        if (!entry) return null;

        const Component = entry.component;

        return (
          <div
            key={tab.id}
            className="absolute inset-0"
            style={{ display: isActive ? "flex" : "none", flexDirection: "column" }}
            role="tabpanel"
            aria-hidden={!isActive}
          >
            <Suspense
              fallback={
                <div className="flex flex-1 items-center justify-center text-sdr-text-muted text-xs">
                  Loading...
                </div>
              }
            >
              <Component tab={tab} isActive={isActive} />
            </Suspense>
          </div>
        );
      })}
    </div>
  );
}
