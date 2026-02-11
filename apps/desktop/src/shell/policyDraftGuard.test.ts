import { describe, expect, it } from "vitest";

import { appIdFromPath, shouldBlockDirtyPolicyDraftExit } from "./policyDraftGuard";

describe("policyDraftGuard", () => {
  it("parses app id from pathname", () => {
    expect(appIdFromPath("/forensics-river/session-1")).toBe("forensics-river");
    expect(appIdFromPath("/cyber-nexus?strikecell=foo")).toBe("cyber-nexus");
    expect(appIdFromPath("/")).toBe("");
  });

  it("blocks dirty exits away from forensics-river", () => {
    expect(
      shouldBlockDirtyPolicyDraftExit({
        hasDirtyDraft: true,
        currentPathname: "/forensics-river",
        nextPathname: "/cyber-nexus",
      })
    ).toBe(true);
  });

  it("does not block navigation when there is no dirty draft", () => {
    expect(
      shouldBlockDirtyPolicyDraftExit({
        hasDirtyDraft: false,
        currentPathname: "/forensics-river",
        nextPathname: "/cyber-nexus",
      })
    ).toBe(false);
  });

  it("does not block navigation inside forensics-river", () => {
    expect(
      shouldBlockDirtyPolicyDraftExit({
        hasDirtyDraft: true,
        currentPathname: "/forensics-river",
        nextPathname: "/forensics-river/session-2",
      })
    ).toBe(false);
  });

  it("does not block transitions from other apps", () => {
    expect(
      shouldBlockDirtyPolicyDraftExit({
        hasDirtyDraft: true,
        currentPathname: "/cyber-nexus",
        nextPathname: "/settings",
      })
    ).toBe(false);
  });
});
