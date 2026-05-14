import { useCallback } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import { IconAlertTriangle, IconBrain, IconChartBar } from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import { useFindings } from "@/features/findings/stores/finding-store";
import { useIntel } from "@/features/findings/stores/intel-store";
import { promoteToIntel } from "@/lib/workbench/intel-forge";
import { FindingsList } from "./findings-list";
import { IntelPage } from "../intel/intel-page";
import { EnrichmentDashboard } from "./enrichment-dashboard";

type Tab = "findings" | "intel" | "dashboard";

function resolveTab(raw: string | null): Tab {
  if (raw === "intel") return "intel";
  if (raw === "dashboard") return "dashboard";
  return "findings";
}

export function FindingsIntelPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  const activeTab = resolveTab(searchParams.get("tab"));

  const { findings, confirm, dismiss, markFalsePositive, promote } = useFindings();
  const { localIntel, swarmIntel, upsertLocalIntel } = useIntel();

  const promoteFinding = useCallback(
    (findingId: string) => {
      const finding = findings.find((entry) => entry.id === findingId);
      if (!finding) return;

      const intel = promoteToIntel(finding, [], {
        authorFingerprint: finding.createdBy || "operator",
        shareability: "private",
      });

      upsertLocalIntel(intel);
      promote(findingId, "operator", intel.id);
    },
    [findings, promote, upsertLocalIntel],
  );

  const setTab = useCallback(
    (tab: Tab) => {
      setSearchParams(tab === "findings" ? {} : { tab }, { replace: true });
    },
    [setSearchParams],
  );

  return (
    <div className="flex h-full w-full flex-col overflow-hidden">
      <div className="border-b border-[#2d3240] bg-[#0b0d13] px-5 py-0 flex items-center gap-0 shrink-0">
        <button
          onClick={() => setTab("findings")}
          className={cn(
            "px-4 py-2.5 text-[11px] font-mono uppercase tracking-wider flex items-center border-b-2 transition-colors",
            activeTab === "findings"
              ? "text-[#ece7dc] border-[#d4a84b]"
              : "text-[#6f7f9a] hover:text-[#ece7dc]/70 border-transparent",
          )}
        >
          <IconAlertTriangle size={14} stroke={1.5} className="mr-1.5" />
          Findings
        </button>
        <button
          onClick={() => setTab("intel")}
          className={cn(
            "px-4 py-2.5 text-[11px] font-mono uppercase tracking-wider flex items-center border-b-2 transition-colors",
            activeTab === "intel"
              ? "text-[#ece7dc] border-[#d4a84b]"
              : "text-[#6f7f9a] hover:text-[#ece7dc]/70 border-transparent",
          )}
        >
          <IconBrain size={14} stroke={1.5} className="mr-1.5" />
          Intel
        </button>
        <button
          onClick={() => setTab("dashboard")}
          className={cn(
            "px-4 py-2.5 text-[11px] font-mono uppercase tracking-wider flex items-center border-b-2 transition-colors",
            activeTab === "dashboard"
              ? "text-[#ece7dc] border-[#d4a84b]"
              : "text-[#6f7f9a] hover:text-[#ece7dc]/70 border-transparent",
          )}
        >
          <IconChartBar size={14} stroke={1.5} className="mr-1.5" />
          Dashboard
        </button>
      </div>

      <div className="flex-1 overflow-hidden">
        {activeTab === "findings" ? (
          <FindingsList
            findings={findings}
            onSelect={(id: string) => navigate(`/findings/${id}`)}
            onConfirm={(id: string) => confirm(id, "operator")}
            onDismiss={(id: string) => dismiss(id, "operator")}
            onPromote={promoteFinding}
            onMarkFalsePositive={(id: string) =>
              markFalsePositive(id, "operator")
            }
          />
        ) : activeTab === "intel" ? (
          <IntelPage
            localIntel={localIntel}
            swarmIntel={swarmIntel}
            onSelectIntel={(intelId: string) =>
              navigate(`/intel/${intelId}`)
            }
          />
        ) : (
          <EnrichmentDashboard findings={findings} />
        )}
      </div>
    </div>
  );
}
