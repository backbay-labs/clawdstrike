import { describe, it, expect, afterEach, vi } from "vitest";
import {
  registerEnrichmentRenderer,
  getEnrichmentRenderer,
  onEnrichmentRendererChange,
  enrichmentTypeRegistry,
} from "../enrichment-type-registry";

// Simple mock component
function VTRenderer() {
  return null;
}
function AnotherRenderer() {
  return null;
}

describe("enrichment-type-registry", () => {
  const disposers: Array<() => void> = [];

  afterEach(() => {
    for (const d of disposers) d();
    disposers.length = 0;
  });

  it("registerEnrichmentRenderer stores the mapping and notifies listeners", () => {
    const listener = vi.fn();
    const unsub = onEnrichmentRendererChange(listener);
    disposers.push(unsub);

    disposers.push(registerEnrichmentRenderer("virustotal", VTRenderer));
    expect(listener).toHaveBeenCalledTimes(1);

    const renderer = getEnrichmentRenderer("virustotal");
    expect(renderer).toBe(VTRenderer);
  });

  it("registerEnrichmentRenderer throws when type already registered", () => {
    disposers.push(registerEnrichmentRenderer("virustotal", VTRenderer));
    expect(() =>
      registerEnrichmentRenderer("virustotal", AnotherRenderer),
    ).toThrow('Enrichment renderer for type "virustotal" already registered');
  });

  it("getEnrichmentRenderer returns the component after registration", () => {
    disposers.push(registerEnrichmentRenderer("virustotal", VTRenderer));
    expect(getEnrichmentRenderer("virustotal")).toBe(VTRenderer);
  });

  it("getEnrichmentRenderer returns undefined for unknown types", () => {
    expect(getEnrichmentRenderer("unknown")).toBeUndefined();
  });

  it("dispose function removes the renderer and notifies listeners", () => {
    const listener = vi.fn();
    const unsub = onEnrichmentRendererChange(listener);
    disposers.push(unsub);

    const dispose = registerEnrichmentRenderer("virustotal", VTRenderer);
    expect(listener).toHaveBeenCalledTimes(1);

    dispose();
    expect(getEnrichmentRenderer("virustotal")).toBeUndefined();
    expect(listener).toHaveBeenCalledTimes(2);
  });

  it("enrichmentTypeRegistry convenience object has register/get/onChange", () => {
    expect(typeof enrichmentTypeRegistry.register).toBe("function");
    expect(typeof enrichmentTypeRegistry.get).toBe("function");
    expect(typeof enrichmentTypeRegistry.onChange).toBe("function");
  });

  it("enrichmentTypeRegistry.register works as alias", () => {
    disposers.push(enrichmentTypeRegistry.register("abuseipdb", VTRenderer));
    expect(enrichmentTypeRegistry.get("abuseipdb")).toBe(VTRenderer);
  });
});
