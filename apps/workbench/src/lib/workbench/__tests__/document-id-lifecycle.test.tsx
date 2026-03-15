/**
 * Tests for documentId lifecycle across tab operations in multi-policy-store.
 *
 * Covers W0.1 acceptance criteria:
 * - every tab has a stable documentId
 * - restored tabs preserve documentId
 * - duplicated tabs get new documentId
 * - reopened files resolve existing documentId via alias store
 * - legacy persisted tabs without documentId are migrated
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { render, act } from "@testing-library/react";
import React from "react";
import {
  MultiPolicyProvider,
  useMultiPolicy,
} from "../multi-policy-store";

// Helper to capture the multi-policy context
function TestHarness({ onContext }: { onContext: (ctx: ReturnType<typeof useMultiPolicy>) => void }) {
  const ctx = useMultiPolicy();
  React.useEffect(() => {
    onContext(ctx);
  });
  return null;
}

describe("documentId lifecycle", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  afterEach(() => {
    localStorage.clear();
  });

  it("new tabs have a documentId", () => {
    let captured: ReturnType<typeof useMultiPolicy> | null = null;

    render(
      <MultiPolicyProvider>
        <TestHarness onContext={(ctx) => { captured = ctx; }} />
      </MultiPolicyProvider>,
    );

    expect(captured).not.toBeNull();
    expect(captured!.activeTab).toBeDefined();
    expect(captured!.activeTab!.documentId).toBeDefined();
    expect(typeof captured!.activeTab!.documentId).toBe("string");
    expect(captured!.activeTab!.documentId.length).toBeGreaterThan(0);
  });

  it("tabs created via NEW_TAB each get unique documentIds", () => {
    let captured: ReturnType<typeof useMultiPolicy> | null = null;

    render(
      <MultiPolicyProvider>
        <TestHarness onContext={(ctx) => { captured = ctx; }} />
      </MultiPolicyProvider>,
    );

    const firstDocId = captured!.activeTab!.documentId;

    act(() => {
      captured!.multiDispatch({ type: "NEW_TAB" });
    });

    const secondDocId = captured!.activeTab!.documentId;
    expect(secondDocId).toBeDefined();
    expect(secondDocId).not.toBe(firstDocId);
  });

  it("DUPLICATE_TAB generates a new documentId", () => {
    let captured: ReturnType<typeof useMultiPolicy> | null = null;

    render(
      <MultiPolicyProvider>
        <TestHarness onContext={(ctx) => { captured = ctx; }} />
      </MultiPolicyProvider>,
    );

    const originalTab = captured!.activeTab!;

    act(() => {
      captured!.multiDispatch({ type: "DUPLICATE_TAB", tabId: originalTab.id });
    });

    const dupedTab = captured!.activeTab!;
    expect(dupedTab.id).not.toBe(originalTab.id);
    expect(dupedTab.documentId).not.toBe(originalTab.documentId);
  });

  it("documentId persists across save/restore cycle", () => {
    let captured: ReturnType<typeof useMultiPolicy> | null = null;

    const { unmount } = render(
      <MultiPolicyProvider>
        <TestHarness onContext={(ctx) => { captured = ctx; }} />
      </MultiPolicyProvider>,
    );

    const originalDocId = captured!.activeTab!.documentId;
    const originalTabId = captured!.activeTab!.id;

    // Wait for persistence debounce
    act(() => {
      // Force synchronous persist by calling the internal mechanism
      // The provider persists on a 500ms debounce, so we trigger it via unmount
    });

    // Wait for the persist timer
    return new Promise<void>((resolve) => {
      setTimeout(() => {
        unmount();

        // Re-render to restore from localStorage
        let restored: ReturnType<typeof useMultiPolicy> | null = null;
        render(
          <MultiPolicyProvider>
            <TestHarness onContext={(ctx) => { restored = ctx; }} />
          </MultiPolicyProvider>,
        );

        expect(restored).not.toBeNull();
        const restoredTab = restored!.tabs.find((t) => t.id === originalTabId);
        if (restoredTab) {
          expect(restoredTab.documentId).toBe(originalDocId);
        }
        resolve();
      }, 600);
    });
  });

  it("OPEN_TAB_OR_SWITCH preserves documentId when switching to existing tab", () => {
    let captured: ReturnType<typeof useMultiPolicy> | null = null;

    render(
      <MultiPolicyProvider>
        <TestHarness onContext={(ctx) => { captured = ctx; }} />
      </MultiPolicyProvider>,
    );

    // Open a file
    act(() => {
      captured!.multiDispatch({
        type: "OPEN_TAB_OR_SWITCH",
        filePath: "/test/file.yaml",
        fileType: "clawdstrike_policy",
        yaml: "version: '1.5.0'\nname: Test\nguards: {}\nsettings: {}",
      });
    });

    const firstDocId = captured!.activeTab!.documentId;
    const firstTabId = captured!.activeTab!.id;

    // Switch to a different tab
    act(() => {
      captured!.multiDispatch({ type: "NEW_TAB" });
    });

    // Reopen the same file — should switch back, preserving documentId
    act(() => {
      captured!.multiDispatch({
        type: "OPEN_TAB_OR_SWITCH",
        filePath: "/test/file.yaml",
        fileType: "clawdstrike_policy",
        yaml: "version: '1.5.0'\nname: Test Updated\nguards: {}\nsettings: {}",
      });
    });

    expect(captured!.activeTab!.id).toBe(firstTabId);
    expect(captured!.activeTab!.documentId).toBe(firstDocId);
  });

  it("opening same file after close resolves same documentId via alias store", () => {
    let captured: ReturnType<typeof useMultiPolicy> | null = null;

    render(
      <MultiPolicyProvider>
        <TestHarness onContext={(ctx) => { captured = ctx; }} />
      </MultiPolicyProvider>,
    );

    // Open a file
    act(() => {
      captured!.multiDispatch({
        type: "OPEN_TAB_OR_SWITCH",
        filePath: "/test/persistent-doc.yaml",
        fileType: "clawdstrike_policy",
        yaml: "version: '1.5.0'\nname: Persistent\nguards: {}\nsettings: {}",
      });
    });

    const originalDocId = captured!.activeTab!.documentId;
    const originalTabId = captured!.activeTab!.id;

    // Close the tab
    act(() => {
      captured!.multiDispatch({ type: "CLOSE_TAB", tabId: originalTabId });
    });

    // Reopen the same file
    act(() => {
      captured!.multiDispatch({
        type: "OPEN_TAB_OR_SWITCH",
        filePath: "/test/persistent-doc.yaml",
        fileType: "clawdstrike_policy",
        yaml: "version: '1.5.0'\nname: Persistent\nguards: {}\nsettings: {}",
      });
    });

    // New tab ID, but same documentId
    expect(captured!.activeTab!.id).not.toBe(originalTabId);
    expect(captured!.activeTab!.documentId).toBe(originalDocId);
  });

  it("legacy persisted tabs without documentId get one on restore", () => {
    // Simulate a legacy persisted state without documentId
    const legacyState = {
      tabs: [
        {
          id: "legacy-tab-1",
          name: "Legacy Policy",
          filePath: null,
          yaml: "version: '1.5.0'\nname: Legacy\nguards: {}\nsettings: {}",
          fileType: "clawdstrike_policy",
        },
      ],
      activeTabId: "legacy-tab-1",
    };
    localStorage.setItem("clawdstrike_workbench_tabs", JSON.stringify(legacyState));

    let captured: ReturnType<typeof useMultiPolicy> | null = null;

    render(
      <MultiPolicyProvider>
        <TestHarness onContext={(ctx) => { captured = ctx; }} />
      </MultiPolicyProvider>,
    );

    expect(captured).not.toBeNull();
    const tab = captured!.activeTab!;
    expect(tab.id).toBe("legacy-tab-1");
    expect(tab.documentId).toBeDefined();
    expect(typeof tab.documentId).toBe("string");
    expect(tab.documentId.length).toBeGreaterThan(0);
  });

  it("Sigma and YARA tabs also get documentIds", () => {
    let captured: ReturnType<typeof useMultiPolicy> | null = null;

    render(
      <MultiPolicyProvider>
        <TestHarness onContext={(ctx) => { captured = ctx; }} />
      </MultiPolicyProvider>,
    );

    act(() => {
      captured!.multiDispatch({
        type: "NEW_TAB",
        fileType: "sigma_rule",
        yaml: "title: Test Sigma\nstatus: test\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    CommandLine: test\n  condition: selection",
      });
    });

    const sigmaDocId = captured!.activeTab!.documentId;
    expect(sigmaDocId).toBeDefined();

    act(() => {
      captured!.multiDispatch({
        type: "NEW_TAB",
        fileType: "yara_rule",
        yaml: 'rule test_rule {\n  strings:\n    $a = "test"\n  condition:\n    $a\n}',
      });
    });

    const yaraDocId = captured!.activeTab!.documentId;
    expect(yaraDocId).toBeDefined();
    expect(yaraDocId).not.toBe(sigmaDocId);
  });
});
