/**
 * SwarmLegend - Legend for trust level colors
 */
import { GlassCard } from "@backbay/glia/primitives";
import { TRUST_COLORS, type TrustLevel } from "@/types/agents";

const TRUST_LEVELS: { level: TrustLevel; label: string }[] = [
  { level: "System", label: "System" },
  { level: "High", label: "High Trust" },
  { level: "Medium", label: "Medium Trust" },
  { level: "Low", label: "Low Trust" },
  { level: "Untrusted", label: "Untrusted" },
];

export function SwarmLegend() {
  return (
    <GlassCard className="p-3">
      <h3 className="text-xs font-medium text-sdr-text-muted uppercase tracking-wide mb-2">
        Trust Levels
      </h3>
      <div className="space-y-1.5">
        {TRUST_LEVELS.map(({ level, label }) => (
          <div key={level} className="flex items-center gap-2">
            <div
              className="w-3 h-3 rounded-full"
              style={{ backgroundColor: TRUST_COLORS[level] }}
            />
            <span className="text-xs text-sdr-text-secondary">{label}</span>
          </div>
        ))}
      </div>

      <div className="mt-3 pt-3 border-t border-sdr-border">
        <h3 className="text-xs font-medium text-sdr-text-muted uppercase tracking-wide mb-2">
          Connections
        </h3>
        <div className="space-y-1.5">
          <div className="flex items-center gap-2">
            <div className="w-6 h-0.5 bg-sdr-accent-blue" />
            <span className="text-xs text-sdr-text-secondary">Active delegation</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-6 h-0.5 bg-sdr-accent-red opacity-50" style={{ backgroundImage: "repeating-linear-gradient(90deg, transparent, transparent 2px, currentColor 2px, currentColor 4px)" }} />
            <span className="text-xs text-sdr-text-secondary">Expired/Revoked</span>
          </div>
        </div>
      </div>

      <div className="mt-3 pt-3 border-t border-sdr-border">
        <h3 className="text-xs font-medium text-sdr-text-muted uppercase tracking-wide mb-2">
          Controls
        </h3>
        <div className="text-xs text-sdr-text-muted space-y-0.5">
          <p>Drag to rotate</p>
          <p>Scroll to zoom</p>
          <p>Click agent to select</p>
        </div>
      </div>
    </GlassCard>
  );
}
