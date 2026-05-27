import { SidebarHeader } from "./SidebarHeader";
import { SidebarRailBody } from "./SidebarRailBody";

/** Icon-only 64px rail showing each group's pinned apps, with a Settings footer. */
export function SidebarRail() {
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
      <SidebarRailBody />
    </nav>
  );
}
