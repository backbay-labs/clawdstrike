import { describe, expect, it } from "vitest";
import { desktopIcons, pinnedAppIds, processes } from "./processRegistry";

describe("processRegistry", () => {
  it("every process has a unique id", () => {
    const ids = processes.map((p) => p.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("every process has required fields", () => {
    for (const p of processes) {
      expect(p.id).toBeTruthy();
      expect(p.name).toBeTruthy();
      expect(p.component).toBeDefined();
      expect(p.defaultSize).toBeDefined();
    }
  });

  it("pinnedAppIds is a subset of process ids", () => {
    const processIds = new Set(processes.map((p) => p.id));
    for (const id of pinnedAppIds) {
      expect(processIds.has(id)).toBe(true);
    }
  });

  it("desktopIcons reference valid process ids", () => {
    const processIds = new Set(processes.map((p) => p.id));
    for (const icon of desktopIcons) {
      expect(processIds.has(icon.processId)).toBe(true);
    }
  });

  it("desktop icon ids are unique", () => {
    const ids = desktopIcons.map((i) => i.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});
