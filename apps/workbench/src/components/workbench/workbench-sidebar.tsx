import { useLocation } from "react-router-dom";
import { Link } from "react-router-dom";
import {
  IconPencil,
  IconCrosshair,
  IconColumns,
  IconShieldCheck,
  IconCertificate,
  IconBooks,
  IconChevronsLeft,
  IconChevronsRight,
} from "@tabler/icons-react";
import { ClawLogo } from "@/components/brand/claw-logo";
import { useWorkbench } from "@/lib/workbench/multi-policy-store";
import { cn } from "@/lib/utils";

const navItems = [
  { label: "Editor", icon: IconPencil, href: "/workbench/editor" },
  { label: "Threat Lab", icon: IconCrosshair, href: "/workbench/simulator" },
  { label: "Compare", icon: IconColumns, href: "/workbench/compare" },
  { label: "Compliance", icon: IconShieldCheck, href: "/workbench/compliance" },
  { label: "Receipts", icon: IconCertificate, href: "/workbench/receipts" },
  { label: "Library", icon: IconBooks, href: "/workbench/library" },
] as const;

export function WorkbenchSidebar() {
  const pathname = useLocation().pathname;
  const { state, dispatch } = useWorkbench();
  const collapsed = state.ui.sidebarCollapsed;

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
        {navItems.map((item) => {
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
              {/* Gold left border for active */}
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
      </nav>

      {/* Collapse toggle */}
      <div className="shrink-0 border-t border-[#2d3240] p-2">
        <button
          onClick={() =>
            dispatch({ type: "SET_SIDEBAR_COLLAPSED", collapsed: !collapsed })
          }
          className={cn(
            "flex items-center justify-center w-full rounded-md py-2 text-[#6f7f9a] hover:text-[#ece7dc] hover:bg-[#131721]/50 transition-colors",
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
