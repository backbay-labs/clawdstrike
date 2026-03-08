import { describe, expect, it } from "vitest";

import { appIdFromPath, shouldBlockDirtyPolicyDraftExit } from "./policyDraftGuard";

describe("policyDraftGuard", () => {
  it("parses app id from pathname", () => {
    expect(appIdFromPath("/nexus/session-1")).toBe("nexus");
    expect(appIdFromPath("/operations?tab=fleet")).toBe("operations");
    expect(appIdFromPath("/")).toBe("");
  });

  it("blocks dirty exits away from nexus", () => {
    expect(
      shouldBlockDirtyPolicyDraftExit({
        hasDirtyDraft: true,
        currentPathname: "/nexus",
        nextPathname: "/operations",
      }),
    ).toBe(true);
  });

  it("does not block navigation when there is no dirty draft", () => {
    expect(
      shouldBlockDirtyPolicyDraftExit({
        hasDirtyDraft: false,
        currentPathname: "/nexus",
        nextPathname: "/operations",
      }),
    ).toBe(false);
  });

  it("does not block navigation inside nexus", () => {
    expect(
      shouldBlockDirtyPolicyDraftExit({
        hasDirtyDraft: true,
        currentPathname: "/nexus",
        nextPathname: "/nexus/session-2",
      }),
    ).toBe(false);
  });

  it("does not block transitions from other apps", () => {
    expect(
      shouldBlockDirtyPolicyDraftExit({
        hasDirtyDraft: true,
        currentPathname: "/operations",
        nextPathname: "/operations",
      }),
    ).toBe(false);
  });
});
