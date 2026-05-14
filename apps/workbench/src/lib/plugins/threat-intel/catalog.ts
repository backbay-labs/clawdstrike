import type { ThreatIntelSource } from "@clawdstrike/plugin-sdk";
import type { PluginManifest } from "@/lib/plugins/types";
import { VIRUSTOTAL_MANIFEST, createVirusTotalSource } from "./virustotal-plugin";
import { GREYNOISE_MANIFEST, createGreyNoiseSource } from "./greynoise-plugin";
import { SHODAN_MANIFEST, createShodanSource } from "./shodan-plugin";
import { ABUSEIPDB_MANIFEST, createAbuseIPDBSource } from "./abuseipdb-plugin";
import { OTX_MANIFEST, createOtxSource } from "./otx-plugin";
import { MISP_MANIFEST, createMispSource } from "./misp-plugin";

export interface BuiltinThreatIntelPluginDescriptor {
  manifest: PluginManifest;
  secretKeys: string[];
  create: (secrets: (string | null)[]) => ThreatIntelSource;
}

function requireSecret(
  secrets: (string | null)[],
  index: number,
  name: string,
): string {
  const value = secrets[index];
  if (!value) {
    throw new Error(`Missing required secret: ${name}`);
  }
  return value;
}

export const BUILTIN_THREAT_INTEL_PLUGINS: BuiltinThreatIntelPluginDescriptor[] = [
  {
    manifest: VIRUSTOTAL_MANIFEST,
    secretKeys: ["api_key"],
    create: (secrets) => createVirusTotalSource(requireSecret(secrets, 0, "api_key")),
  },
  {
    manifest: GREYNOISE_MANIFEST,
    secretKeys: ["api_key"],
    create: (secrets) => createGreyNoiseSource(requireSecret(secrets, 0, "api_key")),
  },
  {
    manifest: SHODAN_MANIFEST,
    secretKeys: ["api_key"],
    create: (secrets) => createShodanSource(requireSecret(secrets, 0, "api_key")),
  },
  {
    manifest: ABUSEIPDB_MANIFEST,
    secretKeys: ["api_key"],
    create: (secrets) => createAbuseIPDBSource(requireSecret(secrets, 0, "api_key")),
  },
  {
    manifest: OTX_MANIFEST,
    secretKeys: ["api_key"],
    create: (secrets) => createOtxSource(requireSecret(secrets, 0, "api_key")),
  },
  {
    manifest: MISP_MANIFEST,
    secretKeys: ["api_key", "base_url"],
    create: (secrets) =>
      createMispSource(
        requireSecret(secrets, 0, "api_key"),
        requireSecret(secrets, 1, "base_url"),
      ),
  },
];

export function getBuiltinThreatIntelDescriptor(
  pluginId: string,
): BuiltinThreatIntelPluginDescriptor | undefined {
  return BUILTIN_THREAT_INTEL_PLUGINS.find(
    (plugin) => plugin.manifest.id === pluginId,
  );
}
