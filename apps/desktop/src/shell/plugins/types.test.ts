import { describe, expect, it } from "vitest";
import {
  getPluginIconPath,
  PLUGIN_ICONS,
  registerPluginIcon,
} from "./types";

describe("desktop plugin icon registry", () => {
  it("restores the previous icon path when a custom override is disposed", () => {
    const originalShield = getPluginIconPath("shield");
    const dispose = registerPluginIcon("shield", "M0 0h24v24");

    expect(getPluginIconPath("shield")).toBe("M0 0h24v24");

    dispose();

    expect(getPluginIconPath("shield")).toBe(originalShield);
  });

  it("preserves inherited Object.prototype methods on the PLUGIN_ICONS proxy", () => {
    expect(typeof PLUGIN_ICONS.toString).toBe("function");
    expect(String(PLUGIN_ICONS)).toBe("[object Object]");
    expect("toString" in PLUGIN_ICONS).toBe(true);
    expect("valueOf" in PLUGIN_ICONS).toBe(true);
  });

  it("keeps compatibility with direct PLUGIN_ICONS assignments", () => {
    PLUGIN_ICONS.custom = "M1 1h22v22";

    expect(getPluginIconPath("custom")).toBe("M1 1h22v22");
    expect(PLUGIN_ICONS.custom).toBe("M1 1h22v22");

    delete PLUGIN_ICONS.custom;
    expect(getPluginIconPath("custom")).toBeUndefined();
  });
});
