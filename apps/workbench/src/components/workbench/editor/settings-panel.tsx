import { useWorkbench } from "@/lib/workbench/multi-policy-store";
import { Switch } from "@/components/ui/switch";
import { Slider } from "@/components/ui/slider";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import type { PolicySchemaVersion } from "@/lib/workbench/types";

const VERSIONS: PolicySchemaVersion[] = ["1.1.0", "1.2.0", "1.3.0", "1.4.0"];

function formatTimeout(secs: number): string {
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  if (h > 0 && m > 0) return `${h}h ${m}m`;
  if (h > 0) return `${h}h`;
  return `${m}m`;
}

export function SettingsPanel() {
  const { state, dispatch } = useWorkbench();
  const { settings, version } = state.activePolicy;

  return (
    <div className="flex flex-col gap-4 p-4 border-t border-[#2d3240]/60">
      <h3 className="text-[10px] font-semibold uppercase tracking-wider text-[#6f7f9a]">
        Policy Settings
      </h3>

      {/* Schema version */}
      <div className="flex items-center justify-between gap-3">
        <label className="text-xs text-[#ece7dc]">Schema Version</label>
        <Select
          value={version}
          onValueChange={(val) => {
            dispatch({ type: "UPDATE_META", version: val as string });
          }}
        >
          <SelectTrigger className="w-28 bg-[#131721] border-[#2d3240] text-[#ece7dc] text-xs font-mono">
            <SelectValue />
          </SelectTrigger>
          <SelectContent className="bg-[#131721] border-[#2d3240]">
            {VERSIONS.map((v) => (
              <SelectItem
                key={v}
                value={v}
                className="text-xs font-mono text-[#ece7dc] focus:bg-[#2d3240] focus:text-[#ece7dc]"
              >
                {v}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {/* Fail fast */}
      <div className="flex items-center justify-between gap-3">
        <div className="flex flex-col gap-0.5">
          <label className="text-xs text-[#ece7dc]">Fail Fast</label>
          <span className="text-[10px] text-[#6f7f9a]">
            Stop on first guard failure
          </span>
        </div>
        <Switch
          checked={settings.fail_fast ?? false}
          onCheckedChange={(checked) => {
            dispatch({ type: "UPDATE_SETTINGS", settings: { fail_fast: !!checked } });
          }}
          className="data-checked:bg-[#d4a84b]"
        />
      </div>

      {/* Verbose logging */}
      <div className="flex items-center justify-between gap-3">
        <div className="flex flex-col gap-0.5">
          <label className="text-xs text-[#ece7dc]">Verbose Logging</label>
          <span className="text-[10px] text-[#6f7f9a]">
            Enable detailed audit logs
          </span>
        </div>
        <Switch
          checked={settings.verbose_logging ?? false}
          onCheckedChange={(checked) => {
            dispatch({ type: "UPDATE_SETTINGS", settings: { verbose_logging: !!checked } });
          }}
          className="data-checked:bg-[#d4a84b]"
        />
      </div>

      {/* Session timeout */}
      <div className="flex flex-col gap-2">
        <div className="flex items-center justify-between">
          <label className="text-xs text-[#ece7dc]">Session Timeout</label>
          <span className="text-xs font-mono text-[#d4a84b]">
            {formatTimeout(settings.session_timeout_secs ?? 3600)}
          </span>
        </div>
        <Slider
          value={[settings.session_timeout_secs ?? 3600]}
          min={300}
          max={28800}
          step={300}
          onValueChange={(val) => {
            const v = Array.isArray(val) ? val[0] : val;
            dispatch({ type: "UPDATE_SETTINGS", settings: { session_timeout_secs: v } });
          }}
          className="[&_[data-slot=slider-range]]:bg-[#d4a84b] [&_[data-slot=slider-thumb]]:border-[#d4a84b]"
        />
        <div className="flex justify-between text-[10px] text-[#6f7f9a] font-mono">
          <span>5m</span>
          <span>8h</span>
        </div>
      </div>
    </div>
  );
}
