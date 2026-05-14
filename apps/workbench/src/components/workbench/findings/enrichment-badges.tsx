import type { Enrichment } from "@/lib/workbench/finding-engine";

interface SourceBadgeConfig {
  abbr: string;
  color: string;
  bg: string;
}

const SOURCE_BADGE_CONFIG: Record<string, SourceBadgeConfig> = {
  virustotal: { abbr: "VT", color: "#394EFF", bg: "#394EFF15" },
  greynoise: { abbr: "GN", color: "#28A745", bg: "#28A74515" },
  shodan: { abbr: "SH", color: "#B80000", bg: "#B8000015" },
  abuseipdb: { abbr: "AB", color: "#D32F2F", bg: "#D32F2F15" },
  otx: { abbr: "OTX", color: "#00B0A6", bg: "#00B0A615" },
  misp: { abbr: "MISP", color: "#1A237E", bg: "#1A237E15" },
};

const UNKNOWN_COLOR = "#6f7f9a";
const UNKNOWN_BG = "#6f7f9a15";

function getSourceConfig(source: string): SourceBadgeConfig {
  const config = SOURCE_BADGE_CONFIG[source.toLowerCase()];
  if (config) return config;

  return {
    abbr: source.slice(0, 2).toUpperCase(),
    color: UNKNOWN_COLOR,
    bg: UNKNOWN_BG,
  };
}

export interface EnrichmentBadgesProps {
  enrichments: Enrichment[];
}

export function EnrichmentBadges({ enrichments }: EnrichmentBadgesProps) {
  if (enrichments.length === 0) return null;

  const seenSources = new Set<string>();
  const uniqueSources: string[] = [];
  for (const enrichment of enrichments) {
    const key = enrichment.source.toLowerCase();
    if (!seenSources.has(key)) {
      seenSources.add(key);
      uniqueSources.push(enrichment.source);
    }
  }

  return (
    <>
      {uniqueSources.map((source) => {
        const config = getSourceConfig(source);
        return (
          <span
            key={source}
            data-testid={`badge-${source.toLowerCase()}`}
            title={source}
            className="inline-flex items-center rounded-full px-1.5 py-0.5 font-semibold uppercase select-none"
            style={{
              fontSize: "9px",
              lineHeight: "12px",
              color: config.color,
              backgroundColor: config.bg,
              border: `1px solid ${config.color}4D`,
            }}
          >
            {config.abbr}
          </span>
        );
      })}
    </>
  );
}
