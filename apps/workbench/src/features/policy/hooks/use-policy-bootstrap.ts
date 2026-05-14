/**
 * Bootstrap hook for the policy stores.
 *
 * Extracted from multi-policy-store.tsx — handles store initialization,
 * hydration, and persistence side-effects on mount.
 */
import { useEffect, useRef, type ReactNode } from "react";
import React from "react";
import { usePolicyTabsStore } from "@/features/policy/stores/policy-tabs-store";
import { usePolicyEditStore } from "@/features/policy/stores/policy-edit-store";
import { useWorkbenchUIStore } from "@/features/policy/stores/workbench-ui-store";
import { sanitizeYamlForStorageWithMetadata } from "@/lib/workbench/storage-sanitizer";

export function usePolicyBootstrap(): void {
  // Reset stores on mount — ensures clean state in tests where localStorage
  // is cleared between renders.  In production this runs once.
  const initialized = useRef(false);
  if (!initialized.current) {
    initialized.current = true;
    // Reset all three Zustand stores from current localStorage
    useWorkbenchUIStore.getState()._reset();
    usePolicyTabsStore.getState()._reset();
    usePolicyTabsStore.getState().hydrateSavedPolicies();
  }

  // Persist saved policies when they change
  const savedPolicies = usePolicyTabsStore((s) => s.savedPolicies);
  const savedPoliciesInitialized = useRef(false);
  useEffect(() => {
    // Skip the initial render — hydrateSavedPolicies handles that
    if (!savedPoliciesInitialized.current) {
      savedPoliciesInitialized.current = true;
      return;
    }
    try {
      localStorage.setItem(
        "clawdstrike_workbench_policies",
        JSON.stringify(savedPolicies),
      );
    } catch (e) {
      console.error(
        "[policy-bootstrap] persist saved policies failed:",
        e,
      );
    }
  }, [savedPolicies]);

  // Debounced tab persistence — directly writes to localStorage after 500ms.
  const tabs = usePolicyTabsStore((s) => s.tabs);
  const activeTabId = usePolicyTabsStore((s) => s.activeTabId);
  const editStates = usePolicyEditStore((s) => s.editStates);
  const persistRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => {
    if (persistRef.current) clearTimeout(persistRef.current);
    persistRef.current = setTimeout(() => {
      // Persist directly (matching original behavior), not via schedulePersist
      // which adds an additional debounce layer.
      try {
        const currentTabs = usePolicyTabsStore.getState().tabs;
        const currentActiveTabId = usePolicyTabsStore.getState().activeTabId;
        const currentEditStates = usePolicyEditStore.getState().editStates;
        const persisted = {
          tabs: currentTabs.map((t) => {
            const editState = currentEditStates.get(t.id);
            const yaml = editState?.yaml ?? "";
            const sanitized = sanitizeYamlForStorageWithMetadata(yaml);
            const sensitiveFieldsStripped = sanitized.sensitiveFieldsStripped;
            return {
              id: t.id,
              documentId: t.documentId,
              name: t.name,
              filePath: sensitiveFieldsStripped ? null : t.filePath,
              yaml: sanitized.yaml,
              sensitiveFieldsStripped: sensitiveFieldsStripped || undefined,
              fileType: t.fileType,
            };
          }),
          activeTabId: currentActiveTabId,
        };
        localStorage.setItem(
          "clawdstrike_workbench_tabs",
          JSON.stringify(persisted),
        );
      } catch (e) {
        console.error(
          "[policy-bootstrap] persistTabs failed:",
          e,
        );
      }
    }, 500);
    return () => {
      if (persistRef.current) clearTimeout(persistRef.current);
    };
  }, [tabs, activeTabId, editStates]);
}

export function PolicyBootstrapProvider({
  children,
}: {
  children: React.ReactNode;
}) {
  usePolicyBootstrap();
  return React.createElement(React.Fragment, null, children);
}
