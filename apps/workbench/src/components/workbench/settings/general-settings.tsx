import { useGeneralSettings, type FontSize, type AutosaveInterval } from "@/lib/workbench/use-general-settings";
import { IconPalette, IconTypography, IconDeviceFloppy, IconHash } from "@tabler/icons-react";
import { cn } from "@/lib/utils";


const FONT_SIZE_OPTIONS: { value: FontSize; label: string; description: string }[] = [
  { value: "small", label: "Small", description: "11.5px" },
  { value: "medium", label: "Medium", description: "12.5px" },
  { value: "large", label: "Large", description: "14px" },
];

const AUTOSAVE_OPTIONS: { value: AutosaveInterval; label: string }[] = [
  { value: "off", label: "Off" },
  { value: "5", label: "5 seconds" },
  { value: "15", label: "15 seconds" },
  { value: "30", label: "30 seconds" },
  { value: "60", label: "60 seconds" },
];


export function GeneralSettings() {
  const { settings, updateSettings } = useGeneralSettings();

  return (
    <div className="flex flex-col gap-6">
      {/* Theme */}
      <SettingsSection
        icon={<IconPalette size={14} stroke={1.5} />}
        label="Theme"
        description="Application color scheme"
      >
        <div className="flex items-center gap-2">
          <button
            disabled
            className={cn(
              "flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors",
              "text-[#d4a84b] border-[#d4a84b]/30 bg-[#d4a84b]/10 cursor-default",
            )}
          >
            <span className="w-3 h-3 rounded-full bg-[#0b0d13] border border-[#2d3240]" />
            Dark
          </button>
          <span className="text-[10px] text-[#6f7f9a] italic">
            More themes coming soon
          </span>
        </div>
      </SettingsSection>

      {/* Font size */}
      <SettingsSection
        icon={<IconTypography size={14} stroke={1.5} />}
        label="Editor font size"
        description="Adjusts the font size in the YAML editor"
      >
        <div className="flex items-center gap-1.5">
          {FONT_SIZE_OPTIONS.map((opt) => {
            const active = settings.fontSize === opt.value;
            return (
              <button
                key={opt.value}
                onClick={() => updateSettings({ fontSize: opt.value })}
                className={cn(
                  "flex flex-col items-center px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors",
                  active
                    ? "text-[#d4a84b] border-[#d4a84b]/30 bg-[#d4a84b]/10"
                    : "text-[#6f7f9a] border-[#2d3240] bg-[#131721] hover:border-[#d4a84b]/20 hover:text-[#ece7dc]",
                )}
              >
                <span>{opt.label}</span>
                <span className="text-[10px] font-mono opacity-60 mt-0.5">{opt.description}</span>
              </button>
            );
          })}
        </div>
      </SettingsSection>

      {/* Autosave interval */}
      <SettingsSection
        icon={<IconDeviceFloppy size={14} stroke={1.5} />}
        label="Autosave interval"
        description="How often unsaved changes are backed up to local storage"
      >
        <div className="flex flex-wrap items-center gap-1.5">
          {AUTOSAVE_OPTIONS.map((opt) => {
            const active = settings.autosaveInterval === opt.value;
            return (
              <button
                key={opt.value}
                onClick={() => updateSettings({ autosaveInterval: opt.value })}
                className={cn(
                  "px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors",
                  active
                    ? "text-[#d4a84b] border-[#d4a84b]/30 bg-[#d4a84b]/10"
                    : "text-[#6f7f9a] border-[#2d3240] bg-[#131721] hover:border-[#d4a84b]/20 hover:text-[#ece7dc]",
                )}
              >
                {opt.label}
              </button>
            );
          })}
        </div>
      </SettingsSection>

      {/* Show line numbers */}
      <SettingsSection
        icon={<IconHash size={14} stroke={1.5} />}
        label="Show line numbers"
        description="Display line numbers in the YAML editor gutter"
      >
        <button
          onClick={() => updateSettings({ showLineNumbers: !settings.showLineNumbers })}
          className="flex items-center gap-2.5 group"
        >
          <span
            className={cn(
              "relative inline-flex h-[18px] w-[32px] shrink-0 items-center rounded-full border transition-colors",
              settings.showLineNumbers
                ? "bg-[#d4a84b] border-[#d4a84b]"
                : "bg-[#2d3240] border-[#2d3240]",
            )}
          >
            <span
              className={cn(
                "block h-3.5 w-3.5 rounded-full bg-[#0b0d13] transition-transform",
                settings.showLineNumbers ? "translate-x-[14px]" : "translate-x-[1px]",
              )}
            />
          </span>
          <span className="text-xs text-[#6f7f9a] group-hover:text-[#ece7dc] transition-colors">
            {settings.showLineNumbers ? "Enabled" : "Disabled"}
          </span>
        </button>
      </SettingsSection>
    </div>
  );
}


function SettingsSection({
  icon,
  label,
  description,
  children,
}: {
  icon: React.ReactNode;
  label: string;
  description: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center gap-2">
        <span className="text-[#d4a84b]">{icon}</span>
        <span className="text-xs font-medium text-[#ece7dc]">{label}</span>
      </div>
      <span className="text-[10px] text-[#6f7f9a] -mt-1 ml-[22px]">{description}</span>
      <div className="ml-[22px]">{children}</div>
    </div>
  );
}
