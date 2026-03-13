/**
 * Findings & Intel — Merged tabbed page.
 *
 * Two tabs:
 * - Findings: renders FindingsList with store-connected props.
 * - Intel: renders IntelPage with store-connected props.
 *
 * Tab state is driven by the URL search param `?tab=intel`.
 * Default tab is "findings".
 */

import { useCallback, useState } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import { IconAlertTriangle, IconBrain } from "@tabler/icons-react";
import { useFindings } from "@/lib/workbench/finding-store";
import { SegmentedControl, type SegmentedTab } from "../shared/segmented-control";
import { FindingsList } from "./findings-list";
import { IntelPage } from "../intel/intel-page";
import type { Intel } from "@/lib/workbench/sentinel-types";

// ---------------------------------------------------------------------------
// Tab definitions
// ---------------------------------------------------------------------------

type Tab = "findings" | "intel";

function resolveTab(raw: string | null): Tab {
  return raw === "intel" ? "intel" : "findings";
}

const TABS: SegmentedTab[] = [
  { id: "findings", label: "Findings", icon: IconAlertTriangle },
  { id: "intel", label: "Intel", icon: IconBrain },
];

// ---------------------------------------------------------------------------
// Main Component
// ---------------------------------------------------------------------------

export function FindingsIntelPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  const activeTab = resolveTab(searchParams.get("tab"));

  // --- Findings store ---
  const { findings, confirm, dismiss, markFalsePositive, promote } =
    useFindings();

  // --- Intel (no store yet — placeholder) ---
  const [localIntel] = useState<Intel[]>([]);

  // --- Tab switching ---
  const setTab = useCallback(
    (tab: string) => {
      setSearchParams(tab === "findings" ? {} : { tab }, { replace: true });
    },
    [setSearchParams],
  );

  return (
    <div className="flex h-full w-full flex-col overflow-hidden">
      {/* Segmented control for page-level mode switching */}
      <SegmentedControl
        tabs={TABS}
        activeTab={activeTab}
        onTabChange={setTab}
      />

      {/* Tab content — only the active tab is mounted */}
      <div className="flex-1 overflow-hidden">
        {activeTab === "findings" ? (
          <FindingsList
            findings={findings}
            onSelect={(id: string) => navigate(`/findings/${id}`)}
            onConfirm={(id: string) => confirm(id, "operator")}
            onDismiss={(id: string) => dismiss(id, "operator")}
            onPromote={(id: string) => promote(id, "operator", `intel_${id}`)}
            onMarkFalsePositive={(id: string) =>
              markFalsePositive(id, "operator")
            }
          />
        ) : (
          <IntelPage
            localIntel={localIntel}
            onSelectIntel={(intelId: string) =>
              navigate(`/intel/${intelId}`)
            }
          />
        )}
      </div>
    </div>
  );
}
