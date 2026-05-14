import { useLocation } from "react-router-dom";
import { Link } from "react-router-dom";
import {
  IconPencil,
  IconShieldCheck,
  IconCertificate,
  IconBooks,
  IconChevronsLeft,
  IconChevronsRight,
  IconRadar,
  IconAlertTriangle,
  IconNetwork,
  IconFlag3,
  IconFlask,
  IconGavel,
  IconFileAnalytics,
  IconServer,
  IconSitemap,
} from "@tabler/icons-react";
import { ClawLogo } from "@/components/brand/claw-logo";
import { cn } from "@/lib/utils";
import { useWorkbenchUIStore } from "@/features/policy/stores/workbench-ui-store";

interface NavItem {
  readonly label: string;
  readonly icon: typeof IconPencil;
  readonly href: string;
}

interface NavSection {
  readonly title: string;
  readonly accent: string;
  readonly items: readonly NavItem[];
}

const navSections: readonly NavSection[] = [
  {
    title: "Detect & Respond",
    accent: "#8b5555",
    items: [
      { label: "Sentinels", icon: IconRadar, href: "/sentinels" },
      { label: "Mission Control", icon: IconFlag3, href: "/missions" },
      { label: "Findings & Intel", icon: IconAlertTriangle, href: "/findings" },
      { label: "Lab", icon: IconFlask, href: "/lab" },
      { label: "Swarms", icon: IconNetwork, href: "/swarms" },
    ],
  },
  {
    title: "Author & Test",
    accent: "#8b7355",
    items: [
      { label: "Editor", icon: IconPencil, href: "/editor" },
      { label: "Library", icon: IconBooks, href: "/library" },
    ],
  },
  {
    title: "Platform",
    accent: "#7b6b8b",
    items: [
      { label: "Compliance", icon: IconShieldCheck, href: "/compliance" },
      { label: "Approvals", icon: IconGavel, href: "/approvals" },
      { label: "Audit", icon: IconFileAnalytics, href: "/audit" },
      { label: "Receipts", icon: IconCertificate, href: "/receipts" },
      { label: "Fleet", icon: IconServer, href: "/fleet" },
      { label: "Topology", icon: IconSitemap, href: "/topology" },
    ],
  },
] as const;

export function WorkbenchSidebar() {
  const pathname = useLocation().pathname;
  const collapsed = useWorkbenchUIStore(s => s.sidebarCollapsed);

  return (
    <aside
      className={cn(
        "fixed top-0 left-0 h-screen flex flex-col bg-[#0b0d13] border-r border-[#2d3240] z-40 transition-all duration-300",
        collapsed ? "w-[60px]" : "w-[240px]"
      )}
    >
      {/* Logo */}
      <div
        className={cn(
          "flex items-center h-14 border-b border-[#2d3240] shrink-0",
          collapsed ? "justify-center px-0" : "px-4 gap-2.5"
        )}
      >
        <ClawLogo size={22} />
        {!collapsed && (
          <span className="font-syne font-bold text-sm tracking-tight text-[#ece7dc]">
            CLAWDSTRIKE
          </span>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 py-3 flex flex-col gap-0.5 overflow-y-auto">
        {navSections.map((section, idx) => (
          <div key={section.title} className={idx > 0 ? "mt-2" : undefined}>
            {/* Section header */}
            {collapsed ? (
              idx > 0 ? <div className="mx-3 my-1.5 h-px bg-[#2d324060]" /> : null
            ) : (
              <div className="flex items-center gap-2 mx-3 mb-1">
                <span
                  className="w-[2px] h-2.5 rounded-full shrink-0"
                  style={{ backgroundColor: section.accent }}
                />
                <span
                  className="text-[8.5px] font-semibold uppercase tracking-wider select-none whitespace-nowrap"
                  style={{ color: section.accent }}
                >
                  {section.title}
                </span>
              </div>
            )}

            {section.items.map((item) => {
              const active = pathname.startsWith(item.href);
              const Icon = item.icon;

              return (
                <Link
                  key={item.href}
                  to={item.href}
                  className={cn(
                    "relative flex items-center gap-3 mx-2 rounded-md transition-colors duration-150",
                    collapsed ? "justify-center px-0 py-2.5" : "px-3 py-2.5",
                    active
                      ? "bg-[#131721] text-[#ece7dc]"
                      : "text-[#6f7f9a] hover:text-[#ece7dc] hover:bg-[#131721]/50"
                  )}
                >
                  {active && (
                    <span className="absolute left-0 top-1.5 bottom-1.5 w-[3px] rounded-r-sm bg-[#d4a84b]" />
                  )}
                  <Icon size={18} stroke={1.5} className="shrink-0" />
                  {!collapsed && (
                    <span className="text-sm font-medium truncate">
                      {item.label}
                    </span>
                  )}
                </Link>
              );
            })}
          </div>
        ))}
      </nav>

      {/* Collapse toggle */}
      <div className="shrink-0 border-t border-[#2d3240] p-2">
        <button
          onClick={() =>
            useWorkbenchUIStore.getState().setSidebarCollapsed(!collapsed)
          }
          className={cn(
            "flex items-center justify-center w-full rounded-md py-2 text-[#6f7f9a] hover:text-[#ece7dc] hover:bg-[#131721]/50 transition-colors active:scale-[0.98] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#d4a84b]/40 focus-visible:ring-offset-1 focus-visible:ring-offset-[#05060a]",
            collapsed ? "px-0" : "gap-2 px-3"
          )}
        >
          {collapsed ? (
            <IconChevronsRight size={16} stroke={1.5} />
          ) : (
            <>
              <IconChevronsLeft size={16} stroke={1.5} />
              <span className="text-xs font-medium">Collapse</span>
            </>
          )}
        </button>
      </div>
    </aside>
  );
}
