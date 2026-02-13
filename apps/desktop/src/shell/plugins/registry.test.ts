import { describe, expect, it } from "vitest";

import { getPlugin, getPlugins, getVisiblePlugins } from "./registry";

describe("plugin registry", () => {
  it("keeps nexus as default landing plugin", () => {
    const plugins = getPlugins();
    expect(plugins[0]?.id).toBe("nexus");
  });

  it("does not register the legacy nexus-labs route", () => {
    const all = getPlugins();
    const visible = getVisiblePlugins();
    const allIds = all.map((plugin) => String(plugin.id));
    const visibleIds = visible.map((plugin) => String(plugin.id));

    expect(allIds).not.toContain("nexus-labs");
    expect(visibleIds).not.toContain("nexus-labs");
  });

  it("registers nexus session route param", () => {
    const nexus = getPlugin("nexus");
    const paths = nexus?.routes.filter((route) => !route.index).map((route) => route.path);
    expect(paths).toContain(":sessionId");
  });
});
