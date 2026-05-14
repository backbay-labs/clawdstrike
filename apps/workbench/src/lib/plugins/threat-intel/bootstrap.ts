import { secureStore } from "@/features/settings/secure-store";
import { pluginRegistry } from "@/lib/plugins/plugin-registry";
import {
  registerThreatIntelSource,
  unregisterThreatIntelSource,
} from "@/lib/workbench/threat-intel-registry";
import { MISP_MANIFEST } from "./misp-plugin";
import { BUILTIN_THREAT_INTEL_PLUGINS } from "./catalog";

// Bootstrap
/**
 * Register all built-in threat intel sources whose API keys are
 * already configured in secureStore.
 *
 * @returns The number of sources successfully registered.
 */
export async function bootstrapThreatIntelPlugins(): Promise<number> {
  let registered = 0;

  for (const plugin of BUILTIN_THREAT_INTEL_PLUGINS) {
    const { manifest } = plugin;

    try {
      if (!pluginRegistry.get(manifest.id)) {
        pluginRegistry.register(manifest);
      }

      const secrets = await Promise.all(
        plugin.secretKeys.map((key) =>
          secureStore.get(`plugin:${manifest.id}:${key}`),
        ),
      );

      const primarySecret = secrets[0];
      if (!primarySecret) {
        console.info(
          `[threat-intel-bootstrap] Skipping ${manifest.displayName ?? manifest.name} -- no API key configured`,
        );
        continue;
      }

      if (manifest.id === MISP_MANIFEST.id) {
        const baseUrl = secrets[1];
        if (!baseUrl || !/^https?:\/\/.+/.test(baseUrl)) {
          console.warn(
            `[threat-intel-bootstrap] Skipping ${manifest.displayName ?? manifest.name} -- base_url not configured or invalid`,
          );
          continue;
        }
      }

      const source = plugin.create(secrets);
      unregisterThreatIntelSource(source.id);
      registerThreatIntelSource(source);
      pluginRegistry.setState(manifest.id, "activated");
      registered++;
      console.info(
        `[threat-intel-bootstrap] Registered ${manifest.displayName ?? manifest.name} (${source.id})`,
      );
    } catch (err: unknown) {
      console.warn(
        `[threat-intel-bootstrap] Failed to register ${manifest.displayName ?? manifest.name}:`,
        err instanceof Error ? err.message : String(err),
      );
    }
  }

  console.info(
    `[threat-intel-bootstrap] ${registered}/${BUILTIN_THREAT_INTEL_PLUGINS.length} threat intel sources registered`,
  );
  return registered;
}
