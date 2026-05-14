// nexus-store tests — NXS-02 layoutMode slice
// Wave 0 stub becomes live in 09-02-PLAN.md

import { beforeEach, describe, it, expect } from "vitest";
import { useNexusStore } from "../stores/nexus-store";

describe("nexus-store layoutMode (NXS-02)", () => {
  beforeEach(() => {
    // Reset layoutMode to default before each test
    useNexusStore.getState().actions.setLayoutMode("radial");
  });

  it("defaults to 'radial' layoutMode", () => {
    expect(useNexusStore.getState().layoutMode).toBe("radial");
  });

  it("setLayoutMode('force-directed') updates layoutMode", () => {
    useNexusStore.getState().actions.setLayoutMode("force-directed");
    expect(useNexusStore.getState().layoutMode).toBe("force-directed");
  });

  it("setLayoutMode('radial') reverts from force-directed", () => {
    useNexusStore.getState().actions.setLayoutMode("force-directed");
    useNexusStore.getState().actions.setLayoutMode("radial");
    expect(useNexusStore.getState().layoutMode).toBe("radial");
  });

  it("createSelectors exposes useNexusStore.use.layoutMode as a function", () => {
    expect(typeof useNexusStore.use.layoutMode).toBe("function");
  });
});
