import { useMemo, useState, useEffect, useRef } from "react";
import { useLocation, Link } from "react-router-dom";
import {
  IconLayoutDashboard,
  IconPencil,
  IconCrosshair,
  IconColumns,
  IconShieldCheck,
  IconCertificate,
  IconBinaryTree2,
  IconGavel,
  IconSitemap,
  IconBooks,
  IconSettings,
  IconChevronsLeft,
  IconChevronsRight,
  IconServer,
  IconFileAnalytics,
} from "@tabler/icons-react";
import { useWorkbench } from "@/lib/workbench/multi-policy-store";
import { useFleetConnection } from "@/lib/workbench/use-fleet-connection";
import { cn } from "@/lib/utils";
import { fleetClient } from "@/lib/workbench/fleet-client";
import { DEMO_APPROVAL_REQUESTS } from "@/lib/workbench/approval-demo-data";

const navItems = [
  { label: "Home", icon: IconLayoutDashboard, href: "/home" },
  { label: "Editor", icon: IconPencil, href: "/editor" },
  { label: "Threat Lab", icon: IconCrosshair, href: "/simulator" },
  { label: "Compare", icon: IconColumns, href: "/compare" },
  { label: "Compliance", icon: IconShieldCheck, href: "/compliance" },
  { label: "Receipts", icon: IconCertificate, href: "/receipts" },
  { label: "Audit", icon: IconFileAnalytics, href: "/audit" },
  { label: "Delegation", icon: IconBinaryTree2, href: "/delegation" },
  { label: "Approvals", icon: IconGavel, href: "/approvals", badge: true },
  { label: "Hierarchy", icon: IconSitemap, href: "/hierarchy" },
  { label: "Fleet", icon: IconServer, href: "/fleet" },
  { label: "Library", icon: IconBooks, href: "/library" },
] as const;

export function DesktopSidebar() {
  const pathname = useLocation().pathname;
  const { state, dispatch } = useWorkbench();
  const collapsed = state.ui.sidebarCollapsed;
  const { connection } = useFleetConnection();
  const fleetConnected = connection.connected;

  const [liveApprovalCount, setLiveApprovalCount] = useState<number | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (pollRef.current) clearInterval(pollRef.current);
    pollRef.current = null;

    if (!fleetConnected) {
      setLiveApprovalCount(null);
      return;
    }

    const fetchCount = async () => {
      try {
        const result = await fleetClient.fetchApprovals();
        if (result) {
          setLiveApprovalCount(result.requests.filter((r) => r.status === "pending").length);
        }
      } catch { /* stale count is acceptable */ }
    };

    fetchCount();
    pollRef.current = setInterval(fetchCount, 30_000);
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, [fleetConnected]);

  const isLiveBadge = fleetConnected && liveApprovalCount !== null;
  const demoPendingCount = useMemo(
    () => DEMO_APPROVAL_REQUESTS.filter((r) => r.status === "pending").length,
    [],
  );
  const pendingApprovalCount = isLiveBadge ? liveApprovalCount : demoPendingCount;
  const settingsActive = pathname === "/settings" || pathname.startsWith("/settings/");

  return (
    <aside
      aria-label="Main navigation"
      className={cn(
        "flex flex-col bg-[#0b0d13] border-r border-[#2d324060] shrink-0 h-full",
        "transition-[width] duration-300 ease-[cubic-bezier(0.4,0,0.2,1)]",
        collapsed ? "w-[52px]" : "w-[200px]",
      )}
    >
      <nav className="flex-1 py-3 flex flex-col gap-0.5 overflow-y-auto">
        {navItems.map((item) => {
          const active = pathname === item.href || pathname.startsWith(item.href + "/");
          const Icon = item.icon;
          const showBadge = "badge" in item && item.badge && pendingApprovalCount > 0;

          return (
            <Link
              key={item.href}
              to={item.href}
              className={cn(
                "sidebar-link relative flex items-center gap-2.5 mx-2 rounded-lg transition-all duration-150",
                collapsed ? "justify-center px-0 py-2.5" : "px-3 py-2.5",
                active
                  ? "bg-[#131721] text-[#ece7dc]"
                  : "text-[#6f7f9a] hover:text-[#ece7dc] hover:bg-[#131721]/40",
              )}
            >
              {active && (
                <span className="sidebar-accent-bar absolute left-0 top-2 bottom-2 w-[2.5px] rounded-r-full bg-[#d4a84b]" />
              )}
              <span className="relative shrink-0">
                <Icon
                  size={17}
                  stroke={1.5}
                  className={cn(
                    "transition-colors duration-150",
                    active ? "text-[#d4a84b]" : "",
                  )}
                />
                {showBadge && collapsed && (
                  <span
                    className={cn(
                      "absolute -right-1 -top-1 h-2 w-2 rounded-full animate-pulse",
                      isLiveBadge ? "bg-[#d4a84b]" : "bg-[#6f7f9a]",
                    )}
                  />
                )}
              </span>
              {!collapsed && (
                <>
                  <span className="text-[12.5px] font-medium tracking-[-0.01em] truncate">
                    {item.label}
                  </span>
                  {showBadge && (
                    <span
                      className={cn(
                        "ml-auto flex h-4 min-w-[16px] items-center justify-center rounded-full px-1 text-[9px] font-semibold animate-pulse",
                        isLiveBadge
                          ? "bg-[#d4a84b]/20 text-[#d4a84b]"
                          : "bg-[#6f7f9a]/20 text-[#6f7f9a]",
                      )}
                    >
                      {pendingApprovalCount}
                    </span>
                  )}
                </>
              )}
            </Link>
          );
        })}
      </nav>

      <div className="shrink-0 px-2 pb-1">
        <Link
          to="/settings"
          className={cn(
            "sidebar-link relative flex items-center gap-2.5 rounded-lg transition-all duration-150",
            collapsed ? "justify-center px-0 py-2.5" : "px-3 py-2.5",
            settingsActive
              ? "bg-[#131721] text-[#ece7dc]"
              : "text-[#6f7f9a] hover:text-[#ece7dc] hover:bg-[#131721]/40",
          )}
        >
          {settingsActive && (
            <span className="sidebar-accent-bar absolute left-0 top-2 bottom-2 w-[2.5px] rounded-r-full bg-[#d4a84b]" />
          )}
          <IconSettings
            size={17}
            stroke={1.5}
            className={cn(
              "shrink-0 transition-colors duration-150",
              settingsActive ? "text-[#d4a84b]" : "",
            )}
          />
          {!collapsed && (
            <span className="text-[12.5px] font-medium tracking-[-0.01em] truncate">
              Settings
            </span>
          )}
        </Link>
      </div>

      <div className="shrink-0 border-t border-[#2d324060] p-2">
        <button
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          onClick={() =>
            dispatch({ type: "SET_SIDEBAR_COLLAPSED", collapsed: !collapsed })
          }
          className={cn(
            "flex items-center justify-center w-full rounded-lg py-2 text-[#6f7f9a] hover:text-[#ece7dc] hover:bg-[#131721]/40 transition-all duration-150",
            collapsed ? "px-0" : "gap-1.5 px-2",
          )}
        >
          {collapsed ? (
            <IconChevronsRight size={14} stroke={1.5} />
          ) : (
            <>
              <IconChevronsLeft size={14} stroke={1.5} />
              <span className="text-[11px] font-medium tracking-[-0.01em]">Collapse</span>
            </>
          )}
        </button>
      </div>
    </aside>
  );
}
