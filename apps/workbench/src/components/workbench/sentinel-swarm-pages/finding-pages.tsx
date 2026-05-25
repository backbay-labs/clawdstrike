import { useCallback } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useFindings } from "@/features/findings/stores/finding-store";
import { useIntel } from "@/features/findings/stores/intel-store";
import { promoteToIntel } from "@/lib/workbench/intel-forge";
import { usePolicyTabs } from "@/features/policy/hooks/use-policy-actions";
import { useDraftDetection } from "@/lib/workbench/detection-workflow/use-draft-detection";
import { useSignalStore } from "@/features/findings/stores/signal-store";
import { usePaneStore } from "@/features/panes/pane-store";
import { FindingsIntelPage } from "../findings/findings-intel-page";
import { FindingDetail } from "../findings/finding-detail";

export function FindingsPage() {
  return <FindingsIntelPage />;
}

export function FindingDetailPage() {
  const { id } = useParams<{ id: string }>();
  const {
    findings,
    confirm,
    dismiss,
    markFalsePositive,
    promote,
    addAnnotation,
  } = useFindings();
  const { upsertLocalIntel } = useIntel();
  const navigate = useNavigate();
  const finding = findings.find((f) => f.id === id);

  // Draft detection wiring
  const { multiDispatch } = usePolicyTabs();
  const allSignals = useSignalStore.use.signals();
  const { draftFromFinding } = useDraftDetection({
    dispatch: multiDispatch,
    onNavigateToEditor: async () => {
      // Open the newly created detection file tab
      const { usePolicyTabsStore } = await import("@/features/policy/stores/policy-tabs-store");
      const activeTab = usePolicyTabsStore.getState().getActiveTab();
      if (activeTab) {
        const route = activeTab.filePath
          ? `/file/${activeTab.filePath}`
          : `/file/__new__/${activeTab.id}`;
        usePaneStore.getState().openApp(route, activeTab.name || "Detection");
      }
    },
  });

  const promoteFinding = useCallback(
    (findingId: string) => {
      const targetFinding = findings.find((entry) => entry.id === findingId);
      if (!targetFinding) return;

      const intel = promoteToIntel(targetFinding, [], {
        authorFingerprint: targetFinding.createdBy || "operator",
        shareability: "private",
      });

      upsertLocalIntel(intel);
      promote(findingId, "operator", intel.id);
    },
    [findings, promote, upsertLocalIntel],
  );

  const handleDraftDetection = useCallback(
    (findingId: string) => {
      const targetFinding = findings.find((entry) => entry.id === findingId);
      if (!targetFinding) return;
      void draftFromFinding(targetFinding, allSignals);
    },
    [findings, allSignals, draftFromFinding],
  );

  const handleDraftGuard = useCallback(
    (findingId: string) => {
      const targetFinding = findings.find((entry) => entry.id === findingId);
      if (!targetFinding) return;
      // Force policy format by passing a gap hint that prefers clawdstrike_policy
      void draftFromFinding(targetFinding, allSignals, {
        techniqueHints: [],
        dataSourceHints: [],
        suggestedFormats: ["clawdstrike_policy"],
      } as any);
    },
    [findings, allSignals, draftFromFinding],
  );

  if (!finding) {
    return (
      <div className="flex h-full items-center justify-center text-[#6f7f9a] text-sm font-mono">
        Finding not found
      </div>
    );
  }

  return (
    <FindingDetail
      finding={finding}
      onConfirm={(fid: string) => confirm(fid, "operator")}
      onDismiss={(fid: string) => dismiss(fid, "operator")}
      onPromote={promoteFinding}
      onMarkFalsePositive={(fid: string) =>
        markFalsePositive(fid, "operator")
      }
      onAddAnnotation={(fid: string, text: string) =>
        addAnnotation(fid, {
          id: `ann_${Date.now()}`,
          text,
          createdBy: "operator",
          createdAt: new Date().toISOString(),
        })
      }
      onDraftDetection={handleDraftDetection}
      onDraftGuard={handleDraftGuard}
      onBack={() => navigate("/findings")}
    />
  );
}
