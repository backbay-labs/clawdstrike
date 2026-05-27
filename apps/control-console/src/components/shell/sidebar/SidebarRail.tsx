import { useDesktopOS } from "@backbay/glia-desktop";
import { Fragment, useCallback } from "react";
import { pinnedAppIds } from "../../../state/processRegistry";
import { NavIconButton } from "./NavItem";
import { SidebarHeader } from "./SidebarHeader";
import { type NavApp, useNavApps } from "./useNavApps";

const RAIL_FALLBACK_COUNT = 4;
const SETTINGS_PROCESS_ID = "settings";
const PINNED = new Set(pinnedAppIds);

/** Icon-only 64px rail showing each group's pinned apps, with a Settings footer. */
export function SidebarRail() {
  const { processes } = useDesktopOS();
  const groups = useNavApps();

  const launch = useCallback((processId: string) => processes.launch(processId), [processes]);

  const settings = groups
    .flatMap((group) => group.apps)
    .find((app) => app.processId === SETTINGS_PROCESS_ID);

  return (
    <nav
      aria-label="Primary navigation"
      style={{
        width: 64,
        flexShrink: 0,
        height: "100%",
        background: "linear-gradient(180deg, rgba(11,13,16,0.96), rgba(7,8,10,0.96))",
        borderRight: "1px solid rgba(27,34,48,0.6)",
        display: "flex",
        flexDirection: "column",
        boxShadow: "inset -1px 0 0 rgba(214,177,90,0.04), 4px 0 24px rgba(0,0,0,0.4)",
      }}
    >
      <SidebarHeader collapsed />

      <div
        style={{
          flex: 1,
          overflow: "auto",
          padding: "10px 8px",
          display: "flex",
          flexDirection: "column",
          gap: 4,
        }}
      >
        {groups.map((group, groupIndex) => {
          const display = railAppsFor(group.apps);
          if (display.length === 0) return null;
          return (
            <Fragment key={group.id}>
              {groupIndex > 0 && (
                <div style={{ height: 1, background: "rgba(27,34,48,0.6)", margin: "6px 6px" }} />
              )}
              {display.map((app) => (
                <NavIconButton
                  key={app.processId}
                  label={app.label}
                  Sigil={app.Sigil}
                  tone={app.tone}
                  active={app.active}
                  running={app.running}
                  onClick={() => launch(app.processId)}
                />
              ))}
            </Fragment>
          );
        })}
      </div>

      {settings && (
        <div
          style={{
            padding: "10px 8px",
            borderTop: "1px solid rgba(27,34,48,0.6)",
            display: "flex",
            flexDirection: "column",
            gap: 4,
          }}
        >
          <NavIconButton
            label={settings.label}
            Sigil={settings.Sigil}
            tone={settings.tone}
            active={settings.active}
            running={settings.running}
            onClick={() => launch(settings.processId)}
          />
        </div>
      )}
    </nav>
  );
}

/**
 * Pinned apps in a group, falling back to the first few when none are pinned.
 * Settings is excluded — it has a dedicated footer slot.
 */
function railAppsFor(apps: NavApp[]): NavApp[] {
  const candidates = apps.filter((app) => app.processId !== SETTINGS_PROCESS_ID);
  const pinned = candidates.filter((app) => PINNED.has(app.processId));
  return pinned.length > 0 ? pinned : candidates.slice(0, RAIL_FALLBACK_COUNT);
}
