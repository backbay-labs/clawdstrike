/**
 * Sentinel Swarm — Connected route-level page components.
 *
 * These wrappers read from React Context stores (SentinelProvider,
 * FindingProvider) and pass props to the presentational components.
 * Each page is exported for lazy-loading in App.tsx.
 */

import { useState, useCallback } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useSentinels } from "@/lib/workbench/sentinel-store";
import { useFindings } from "@/lib/workbench/finding-store";
import { SentinelList } from "./sentinels/sentinel-list";
import { SentinelCreate } from "./sentinels/sentinel-create";
import { SentinelDetail } from "./sentinels/sentinel-detail";
import { FindingsIntelPage } from "./findings/findings-intel-page";
import { FindingDetail } from "./findings/finding-detail";
import { IntelPage } from "./intel/intel-page";
import { IntelDetail } from "./intel/intel-detail";
import type { Sentinel, Intel } from "@/lib/workbench/sentinel-types";

// ---------------------------------------------------------------------------
// Sentinel Pages
// ---------------------------------------------------------------------------

export function SentinelsPage() {
  const { sentinels } = useSentinels();
  return <SentinelList sentinels={sentinels} />;
}

export function SentinelCreatePage() {
  const { createSentinel } = useSentinels();
  const navigate = useNavigate();
  const handleCreated = useCallback(() => {
    navigate("/sentinels");
  }, [navigate]);
  return <SentinelCreate onCreated={handleCreated} createFn={createSentinel} />;
}

export function SentinelDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { sentinels, updateSentinel } = useSentinels();
  const navigate = useNavigate();
  const sentinel = sentinels.find((s) => s.id === id);

  const handleUpdate = useCallback(
    (updated: Sentinel) => {
      updateSentinel(updated.id, {
        name: updated.name,
        goals: updated.goals as Parameters<typeof updateSentinel>[1]["goals"],
        status: updated.status,
        mode: updated.mode,
      });
    },
    [updateSentinel],
  );

  if (!sentinel) {
    return (
      <div className="flex h-full items-center justify-center text-[#6f7f9a] text-sm font-mono">
        Sentinel not found
      </div>
    );
  }

  return (
    <SentinelDetail
      sentinel={sentinel}
      onUpdate={handleUpdate}
    />
  );
}

// ---------------------------------------------------------------------------
// Finding Pages
// ---------------------------------------------------------------------------

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
  const navigate = useNavigate();
  const finding = findings.find((f) => f.id === id);

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
      onPromote={(fid: string) => promote(fid, "operator", `intel_${fid}`)}
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
      onBack={() => navigate("/findings")}
    />
  );
}

// ---------------------------------------------------------------------------
// Intel Pages (no Intel store yet — managed locally)
// ---------------------------------------------------------------------------

export function IntelPageConnected() {
  const [localIntel] = useState<Intel[]>([]);
  const navigate = useNavigate();

  return (
    <IntelPage
      localIntel={localIntel}
      onSelectIntel={(intelId: string) => navigate(`/intel/${intelId}`)}
    />
  );
}

export function IntelDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  // TODO: Read from intel store once created
  if (!id) {
    return (
      <div className="flex h-full items-center justify-center text-[#6f7f9a] text-sm font-mono">
        Intel not found
      </div>
    );
  }

  return (
    <div className="flex h-full items-center justify-center text-[#6f7f9a] text-sm font-mono">
      <div className="text-center">
        <p>Intel detail view</p>
        <p className="text-[10px] mt-1">{id}</p>
        <button
          onClick={() => navigate("/intel")}
          className="mt-3 text-[#5b8def] hover:underline text-xs"
        >
          Back to Intel
        </button>
      </div>
    </div>
  );
}
