import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { pluginRegistry } from "@/lib/plugins/plugin-registry";
import { getThreatIntelSource, _resetForTesting } from "@/lib/workbench/threat-intel-registry";
import { bootstrapThreatIntelPlugins } from "../bootstrap";
import { BUILTIN_THREAT_INTEL_PLUGINS } from "../catalog";
import { GREYNOISE_MANIFEST } from "../greynoise-plugin";
import { VIRUSTOTAL_MANIFEST } from "../virustotal-plugin";

const mockSecureStore = vi.hoisted(() => ({
  get: vi.fn<(_: string) => Promise<string | null>>().mockResolvedValue(null),
}));

vi.mock("@/features/settings/secure-store", () => ({
  secureStore: mockSecureStore,
}));

describe("bootstrapThreatIntelPlugins", () => {
  beforeEach(() => {
    pluginRegistry.reset();
    _resetForTesting();
    vi.clearAllMocks();
    mockSecureStore.get.mockResolvedValue(null);
  });

  afterEach(() => {
    pluginRegistry.reset();
    _resetForTesting();
  });

  it("registers built-in intel manifests in the plugin registry even without saved secrets", async () => {
    const registeredCount = await bootstrapThreatIntelPlugins();

    expect(registeredCount).toBe(0);
    const registeredIds = pluginRegistry
      .getAll()
      .map((plugin) => plugin.manifest.id)
      .sort();

    expect(registeredIds).toEqual(
      BUILTIN_THREAT_INTEL_PLUGINS.map((plugin) => plugin.manifest.id).sort(),
    );
  });

  it("activates and registers built-in sources when required secrets are present", async () => {
    mockSecureStore.get.mockImplementation(async (key: string) => {
      if (key === `plugin:${VIRUSTOTAL_MANIFEST.id}:api_key`) {
        return "vt-key";
      }
      return null;
    });

    const registeredCount = await bootstrapThreatIntelPlugins();

    expect(registeredCount).toBe(1);
    expect(getThreatIntelSource("virustotal")).toBeDefined();
    expect(pluginRegistry.get(VIRUSTOTAL_MANIFEST.id)?.state).toBe("activated");
  });

  it("continues bootstrapping later plugins when manifest registration throws", async () => {
    vi.spyOn(pluginRegistry, "register").mockImplementationOnce(() => {
      throw new Error("invalid manifest");
    });
    mockSecureStore.get.mockImplementation(async (key: string) => {
      if (key === `plugin:${GREYNOISE_MANIFEST.id}:api_key`) {
        return "gn-key";
      }
      return null;
    });

    const registeredCount = await bootstrapThreatIntelPlugins();

    expect(registeredCount).toBe(1);
    expect(pluginRegistry.get(VIRUSTOTAL_MANIFEST.id)).toBeUndefined();
    expect(pluginRegistry.get(GREYNOISE_MANIFEST.id)?.state).toBe("activated");
  });
});
