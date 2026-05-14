# Threat Intel Sources

Threat intel source contributions integrate external threat intelligence feeds into the workbench enrichment pipeline. When an indicator (IP, domain, hash, URL, email) is extracted from a finding, the enrichment orchestrator queries all registered threat intel sources and aggregates the results.

## ThreatIntelSourceContribution (manifest)

The manifest contribution declares that your plugin provides a threat intel source:

```typescript,ignore
interface ThreatIntelSourceContribution {
  /** Unique identifier for this intel source. */
  id: string;
  /** Human-readable name (e.g. "VirusTotal", "AbuseIPDB"). */
  name: string;
  /** Description of the intel source. */
  description: string;
  /** Path to the source adapter module within the plugin package. */
  entrypoint: string;
}
```

## ThreatIntelSource (runtime)

At runtime, your plugin implements the `ThreatIntelSource` interface and registers an instance with the threat intel source registry:

```typescript,ignore
interface ThreatIntelSource {
  /** Unique source identifier. */
  id: string;
  /** Human-readable display name. */
  name: string;
  /** Indicator types this source can enrich. */
  supportedIndicatorTypes: IndicatorType[];
  /** Rate limiting configuration. */
  rateLimit: { maxPerMinute: number };
  /** Enrich an indicator. Called by the orchestrator. */
  enrich(indicator: Indicator): Promise<EnrichmentResult>;
  /** Optional health check for source status. */
  healthCheck?(): Promise<{ healthy: boolean; message?: string }>;
}
```

Where `IndicatorType` is one of: `"hash"`, `"ip"`, `"domain"`, `"url"`, `"email"`.

## Indicator type

```typescript,ignore
interface Indicator {
  type: IndicatorType;
  value: string;
  hashAlgorithm?: "md5" | "sha1" | "sha256";
  context?: {
    findingId?: string;
    signalIds?: string[];
  };
}
```

## EnrichmentResult type

```typescript,ignore
interface EnrichmentResult {
  sourceId: string;
  sourceName: string;
  verdict: ThreatVerdict;
  rawData: Record<string, unknown>;
  mitreTechniques?: Array<{
    techniqueId: string;
    techniqueName: string;
    tactic: string;
  }>;
  relatedIndicators?: Indicator[];
  permalink?: string;
  fetchedAt: number;   // Unix milliseconds
  cacheTtlMs: number;  // Cache duration in milliseconds
}

interface ThreatVerdict {
  classification: "malicious" | "benign" | "suspicious" | "unknown";
  confidence: number;  // 0.0 to 1.0
  summary: string;
}
```

## Full example

```typescript,ignore
import { createPlugin } from "@clawdstrike/plugin-sdk";
import type {
  ThreatIntelSource,
  Indicator,
  EnrichmentResult,
} from "@clawdstrike/plugin-sdk";

class MyIntelSource implements ThreatIntelSource {
  id = "acme.reputation-check";
  name = "Acme Reputation";
  supportedIndicatorTypes = ["ip", "domain"] as const;
  rateLimit = { maxPerMinute: 30 };

  async enrich(indicator: Indicator): Promise<EnrichmentResult> {
    const apiKey = ""; // Retrieve via ctx.secrets.get("api_key")
    const response = await fetch(
      `https://api.acme-intel.com/lookup?type=${indicator.type}&value=${indicator.value}`,
      { headers: { Authorization: `Bearer ${apiKey}` } }
    );
    const data = await response.json();

    return {
      sourceId: this.id,
      sourceName: this.name,
      verdict: {
        classification: data.malicious ? "malicious" : "benign",
        confidence: data.confidence,
        summary: data.summary,
      },
      rawData: data,
      permalink: `https://acme-intel.com/indicator/${indicator.value}`,
      fetchedAt: Date.now(),
      cacheTtlMs: 300_000, // 5 minutes
    };
  }

  async healthCheck() {
    try {
      const res = await fetch("https://api.acme-intel.com/health");
      return { healthy: res.ok };
    } catch {
      return { healthy: false, message: "API unreachable" };
    }
  }
}

export default createPlugin({
  manifest: {
    id: "acme.reputation-check",
    name: "reputation-check",
    displayName: "Acme Reputation",
    description: "IP and domain reputation lookups via Acme Intelligence",
    version: "1.0.0",
    publisher: "Acme",
    categories: ["intel"],
    trust: "community",
    activationEvents: ["onStartup"],
    contributions: {
      threatIntelSources: [
        {
          id: "acme.reputation-check",
          name: "Acme Reputation",
          description: "IP and domain reputation lookups",
          entrypoint: "dist/source.js",
        },
      ],
    },
    requiredSecrets: [
      {
        key: "api_key",
        label: "Acme Intel API Key",
        description: "Get your API key from https://acme-intel.com/settings",
      },
    ],
  },

  activate(ctx) {
    // The ThreatIntelSource is registered via the contribution entrypoint.
    // The orchestrator loads the source adapter and calls enrich() when needed.
    console.log("Acme Reputation source activated");
  },
});
```
