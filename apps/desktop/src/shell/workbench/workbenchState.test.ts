import { describe, expect, it } from "vitest";
import { createInitialWorkbenchState, workbenchReducer } from "./workbenchState";

describe("workbenchReducer", () => {
  it("sets sidebar collapsed explicitly", () => {
    const initial = createInitialWorkbenchState();
    const collapsed = workbenchReducer(initial, {
      type: "SET_SIDEBAR_COLLAPSED",
      payload: true,
    });

    expect(collapsed.sidebarCollapsed).toBe(true);

    const reopened = workbenchReducer(collapsed, {
      type: "SET_SIDEBAR_COLLAPSED",
      payload: false,
    });

    expect(reopened.sidebarCollapsed).toBe(false);
  });

  it("opens compare-mode tabs into a secondary group when needed", () => {
    const initial = createInitialWorkbenchState();
    const withReceipt = workbenchReducer(initial, {
      type: "OPEN_TAB",
      payload: {
        groupId: "main",
        tab: {
          kind: "receipt",
          title: "Receipt A",
          sourceUri: "receipts://a",
          isPreview: false,
          isPinned: false,
          isDirty: false,
        },
      },
    });

    const compared = workbenchReducer(withReceipt, {
      type: "OPEN_TAB",
      payload: {
        groupId: "main",
        openMode: "compare",
        tab: {
          kind: "receipt",
          title: "Receipt B",
          sourceUri: "receipts://b",
          isPreview: false,
          isPinned: false,
          isDirty: false,
        },
      },
    });

    expect(compared.tabGroups).toHaveLength(2);
    expect(compared.tabGroups[1]?.tabs[0]?.sourceUri).toBe("receipts://b");
  });

  it("opens a note from a case as a new tab instead of replacing the case tab", () => {
    const initial = createInitialWorkbenchState();
    const withCase = workbenchReducer(initial, {
      type: "OPEN_TAB",
      payload: {
        groupId: "main",
        tab: {
          kind: "case",
          title: "Case 26",
          sourceUri: "case://26",
          isPreview: false,
          isPinned: false,
          isDirty: false,
        },
      },
    });

    const withNote = workbenchReducer(withCase, {
      type: "OPEN_TAB",
      payload: {
        groupId: "main",
        tab: {
          kind: "note",
          title: "Case note",
          sourceUri: "notes://26/1",
          isPreview: false,
          isPinned: false,
          isDirty: false,
        },
      },
    });

    expect(withNote.tabGroups).toHaveLength(2);
    expect(withNote.tabGroups[0]?.tabs).toHaveLength(1);
    expect(withNote.tabGroups[1]?.tabs[0]?.kind).toBe("note");
    expect(withNote.tabGroups[1]?.activeTabId).toBe(withNote.tabGroups[1]?.tabs[0]?.id ?? null);
  });
});
