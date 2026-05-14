import { useEffect } from "react";
import { ClawLogo } from "@/components/brand/claw-logo";
import { minimizeWindow, maximizeWindow, closeWindow, isDesktop, isMacOS } from "@/lib/tauri-bridge";
import { usePolicyTabsStore } from "@/features/policy/stores/policy-tabs-store";
import { usePolicyEditStore } from "@/features/policy/stores/policy-edit-store";

export function Titlebar() {
  const activeTabId = usePolicyTabsStore(s => s.activeTabId);
  const activeTab = usePolicyTabsStore(s => s.tabs.find(t => t.id === s.activeTabId));
  const editState = usePolicyEditStore(s => s.editStates.get(activeTabId));
  const activePolicy = editState?.policy ?? { version: "1.1.0", name: "", description: "", guards: {}, settings: {} };
  const dirty = activeTab?.dirty ?? false;
  const filePath = activeTab?.filePath ?? null;

  // Update the native window title when the policy name or dirty state changes
  useEffect(() => {
    if (!isDesktop()) return;

    const policyName = activePolicy.name || "Untitled Policy";
    const dirtyMarker = dirty ? " *" : "";
    const title = `${policyName}${dirtyMarker} — ClawdStrike Workbench`;

    (async () => {
      try {
        const { getCurrentWindow } = await import("@tauri-apps/api/window");
        await getCurrentWindow().setTitle(title);
      } catch {
        // ignore -- may fail outside Tauri
      }
    })();
  }, [activePolicy.name, dirty, filePath]);

  const handleMinimize = () => minimizeWindow();
  const handleMaximize = () => maximizeWindow();
  const handleClose = () => closeWindow();

  const showNativeControls = isMacOS();

  return (
    <header
      data-tauri-drag-region
      className="desktop-titlebar drag-region shrink-0 select-none"
      style={{ height: 36 }}
    >
      {/* ---- Left: brand (with traffic-light inset on macOS) ---- */}
      <div
        className="flex items-center gap-2.5 no-drag pointer-events-none"
        style={showNativeControls ? { paddingLeft: 60 } : undefined}
      >
        <ClawLogo size={15} />
        <span className="font-syne font-bold text-[10.5px] tracking-[0.12em] text-[#6f7f9a]/80 uppercase">
          Clawdstrike
        </span>
        <span className="text-[10.5px] tracking-[0.12em] text-[#6f7f9a]/40 uppercase font-medium">
          Workbench
        </span>
      </div>

      {/* ---- Center: policy name + dirty dot ---- */}
      <div className="absolute left-1/2 -translate-x-1/2 flex items-center gap-1.5">
        <span className="font-syne text-[12px] font-semibold text-[#ece7dc]/90 truncate max-w-[240px]">
          {activePolicy.name || "Untitled Policy"}
        </span>
        {dirty && (
          <span
            className="inline-block w-[5px] h-[5px] rounded-full bg-[#d4a84b] animate-pulse"
            title="Unsaved changes"
          />
        )}
      </div>

      {/* ---- Right: window controls (hidden on macOS — native traffic lights handle it) ---- */}
      {isDesktop() && !showNativeControls && (
        <div className="flex items-center gap-0 no-drag">
          {/* Minimize */}
          <button
            onClick={handleMinimize}
            className="group flex items-center justify-center w-[36px] h-[36px] transition-colors duration-150 hover:bg-[#131721]/80"
            aria-label="Minimize"
          >
            <svg width="10" height="1" viewBox="0 0 10 1" className="text-[#6f7f9a]/70 group-hover:text-[#ece7dc] transition-colors duration-150">
              <rect width="10" height="1" fill="currentColor" />
            </svg>
          </button>

          {/* Maximize / Restore */}
          <button
            onClick={handleMaximize}
            className="group flex items-center justify-center w-[36px] h-[36px] transition-colors duration-150 hover:bg-[#131721]/80"
            aria-label="Maximize"
          >
            <svg width="10" height="10" viewBox="0 0 10 10" className="text-[#6f7f9a]/70 group-hover:text-[#ece7dc] transition-colors duration-150">
              <rect x="0.5" y="0.5" width="9" height="9" fill="none" stroke="currentColor" strokeWidth="1" />
            </svg>
          </button>

          {/* Close */}
          <button
            onClick={handleClose}
            className="group flex items-center justify-center w-[36px] h-[36px] transition-colors duration-150 hover:bg-[#c45c5c]"
            aria-label="Close"
          >
            <svg width="10" height="10" viewBox="0 0 10 10" className="text-[#6f7f9a]/70 group-hover:text-[#ece7dc] transition-colors duration-150">
              <line x1="0" y1="0" x2="10" y2="10" stroke="currentColor" strokeWidth="1.2" />
              <line x1="10" y1="0" x2="0" y2="10" stroke="currentColor" strokeWidth="1.2" />
            </svg>
          </button>
        </div>
      )}
    </header>
  );
}
