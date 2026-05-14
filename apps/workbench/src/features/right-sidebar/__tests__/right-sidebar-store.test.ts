// apps/workbench/src/features/right-sidebar/__tests__/right-sidebar-store.test.ts
import { describe, it, expect, beforeEach } from "vitest";
import { useRightSidebarStore } from "../stores/right-sidebar-store";

describe("RightSidebarStore — spirit panel support", () => {
  beforeEach(() => {
    // Reset to default state
    useRightSidebarStore.getState().actions.setActivePanel("speakeasy");
    useRightSidebarStore.getState().actions.hide();
  });

  it("accepts 'spirit' as a valid panel value for setActivePanel", () => {
    useRightSidebarStore.getState().actions.setActivePanel("spirit");
    expect(useRightSidebarStore.getState().activePanel).toBe("spirit");
  });

  it("switches back from spirit to speakeasy", () => {
    useRightSidebarStore.getState().actions.setActivePanel("spirit");
    useRightSidebarStore.getState().actions.setActivePanel("speakeasy");
    expect(useRightSidebarStore.getState().activePanel).toBe("speakeasy");
  });
});
