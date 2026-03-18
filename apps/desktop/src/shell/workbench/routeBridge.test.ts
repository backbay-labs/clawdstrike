import { describe, expect, it } from "vitest";

import { getWorkbenchAppBridgeTarget } from "./routeBridge";

describe("getWorkbenchAppBridgeTarget", () => {
  const appIds = ["nexus", "workspace", "operations"] as const;

  it("bridges top-level app routes", () => {
    expect(getWorkbenchAppBridgeTarget("/nexus", appIds)).toBe("nexus");
    expect(getWorkbenchAppBridgeTarget("/workspace", appIds)).toBe("workspace");
  });

  it("preserves nested plugin routes", () => {
    expect(getWorkbenchAppBridgeTarget("/nexus/scene", appIds)).toBeNull();
    expect(getWorkbenchAppBridgeTarget("/workspace/editor/file.ts", appIds)).toBeNull();
  });

  it("ignores root and unknown paths", () => {
    expect(getWorkbenchAppBridgeTarget("/", appIds)).toBeNull();
    expect(getWorkbenchAppBridgeTarget("/unknown", appIds)).toBeNull();
  });
});
