import { describe, expect, it } from "vitest";
import {
  desktopIconGroups,
  desktopIcons,
  pinnedAppIds,
  processes,
  startMenuDefaultPinnedIds,
} from "./processRegistry";

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

  it("desktop groups include each icon exactly once", () => {
    const flattenedIds = desktopIconGroups.flatMap((group) => group.icons.map((icon) => icon.id));
    expect(flattenedIds).toHaveLength(desktopIcons.length);
    expect(new Set(flattenedIds).size).toBe(desktopIcons.length);
  });

  it("desktop groups contain only valid process ids", () => {
    const processIds = new Set(processes.map((p) => p.id));
    for (const group of desktopIconGroups) {
      for (const icon of group.icons) {
        expect(processIds.has(icon.processId)).toBe(true);
      }
    }
  });

  it("start menu default pins are valid process ids", () => {
    const processIds = new Set(processes.map((p) => p.id));
    for (const id of startMenuDefaultPinnedIds) {
      expect(processIds.has(id)).toBe(true);
    }
  });

  it("exposes proof-at-execution as an operator tool", () => {
    const proofProcess = processes.find((p) => p.id === "execution-proof");
    expect(proofProcess?.name).toBe("Proof at Execution");
    expect(desktopIcons.some((icon) => icon.processId === "execution-proof")).toBe(true);
  });

  it("exposes privacy reports as an operator tool", () => {
    const privacyProcess = processes.find((p) => p.id === "privacy-report");
    expect(privacyProcess?.name).toBe("Privacy Report");
    expect(desktopIcons.some((icon) => icon.processId === "privacy-report")).toBe(true);
  });

  it("exposes causal finding groups as an operator tool", () => {
    const causalProcess = processes.find((p) => p.id === "causal-groups");
    expect(causalProcess?.name).toBe("Causal Groups");
    expect(desktopIcons.some((icon) => icon.processId === "causal-groups")).toBe(true);
  });

  it("exposes process cause as an operator tool", () => {
    const processCause = processes.find((p) => p.id === "process-cause");
    expect(processCause?.name).toBe("Process Cause");
    expect(desktopIcons.some((icon) => icon.processId === "process-cause")).toBe(true);
  });

  it("exposes policy replay as an operator tool", () => {
    const policyReplay = processes.find((p) => p.id === "policy-replay");
    expect(policyReplay?.name).toBe("Policy Replay");
    expect(desktopIcons.some((icon) => icon.processId === "policy-replay")).toBe(true);
  });

  it("exposes rule impact as an operator tool", () => {
    const ruleImpact = processes.find((p) => p.id === "rule-impact");
    expect(ruleImpact?.name).toBe("Rule Impact");
    expect(desktopIcons.some((icon) => icon.processId === "rule-impact")).toBe(true);
  });

  it("exposes local containment as an operator tool", () => {
    const localContainment = processes.find((p) => p.id === "local-containment");
    expect(localContainment?.name).toBe("Local Containment");
    expect(desktopIcons.some((icon) => icon.processId === "local-containment")).toBe(true);
  });

  it("exposes agent secret touches as an operator tool", () => {
    const agentSecretTouches = processes.find((p) => p.id === "agent-secret-touches");
    expect(agentSecretTouches?.name).toBe("Agent Secret Touches");
    expect(desktopIcons.some((icon) => icon.processId === "agent-secret-touches")).toBe(true);
  });

  it("exposes fleet cases as an operator tool", () => {
    const fleetCases = processes.find((p) => p.id === "fleet-cases");
    expect(fleetCases?.name).toBe("Fleet Cases");
    expect(desktopIcons.some((icon) => icon.processId === "fleet-cases")).toBe(true);
  });
});
