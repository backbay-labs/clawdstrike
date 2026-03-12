import { useState } from "react";
import { useFleetConnection } from "@/lib/workbench/use-fleet-connection";
import { cn } from "@/lib/utils";
import { IconUpload, IconRadar, IconCircle } from "@tabler/icons-react";
import { ObserveSynthPanel } from "./observe-synth-panel";
import { FleetTestingPanel } from "./fleet-testing-panel";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type ObserveSource = "import" | "fleet";

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function FleetBadge({ connected }: { connected: boolean }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 px-1.5 py-0 text-[8px] font-mono uppercase border rounded select-none tracking-wide ml-1",
        connected
          ? "text-[#3dbf84]/70 border-[#3dbf84]/20 bg-[#3dbf84]/5"
          : "text-[#6f7f9a]/50 border-[#2d3240] bg-[#131721]/50",
      )}
    >
      <IconCircle
        size={4}
        stroke={0}
        fill={connected ? "#3dbf84" : "#6f7f9a"}
      />
      {connected ? "live" : "offline"}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Main Panel
// ---------------------------------------------------------------------------

export function ObservePanel() {
  const [source, setSource] = useState<ObserveSource>("import");
  const { connection } = useFleetConnection();

  return (
    <div className="flex flex-col h-full">
      {/* Source toggle bar */}
      <div className="flex items-center gap-1 px-4 py-2 border-b border-[#2d3240] bg-[#0b0d13] shrink-0">
        <div className="flex items-center rounded-lg bg-[#0d1017] border border-[#2d3240] p-0.5">
          <button
            onClick={() => setSource("import")}
            className={cn(
              "flex items-center gap-1.5 px-3 py-1.5 rounded-md text-[11px] font-medium transition-all duration-150",
              source === "import"
                ? "bg-[#131721] text-[#ece7dc] shadow-sm"
                : "text-[#6f7f9a] hover:text-[#ece7dc]",
            )}
          >
            <IconUpload size={13} stroke={1.5} />
            Import Logs
          </button>
          <button
            onClick={() => setSource("fleet")}
            className={cn(
              "flex items-center gap-1.5 px-3 py-1.5 rounded-md text-[11px] font-medium transition-all duration-150",
              source === "fleet"
                ? "bg-[#131721] text-[#ece7dc] shadow-sm"
                : "text-[#6f7f9a] hover:text-[#ece7dc]",
            )}
          >
            <IconRadar size={13} stroke={1.5} />
            Fleet Live
            {source === "fleet" && (
              <FleetBadge connected={connection.connected} />
            )}
          </button>
        </div>
      </div>

      {/* Panel content */}
      <div className="flex-1 min-h-0">
        {source === "import" ? (
          <ObserveSynthPanel />
        ) : (
          <FleetTestingPanel />
        )}
      </div>
    </div>
  );
}
