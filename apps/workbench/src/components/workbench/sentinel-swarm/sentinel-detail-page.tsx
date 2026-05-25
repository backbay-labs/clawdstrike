import { useCallback } from "react";
import { useParams } from "react-router-dom";
import { useSentinels } from "@/features/sentinels/stores/sentinel-store";
import type { SentinelMutablePatch } from "@/lib/workbench/sentinel-manager";
import type { Sentinel } from "@/lib/workbench/sentinel-types";
import { SentinelDetail } from "../sentinels/sentinel-detail";

export function SentinelDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { sentinels, updateSentinel } = useSentinels();
  const sentinel = sentinels.find((s) => s.id === id);

  const handleUpdate = useCallback(
    (updated: Sentinel) => {
      const patch: SentinelMutablePatch = {
        name: updated.name,
        goals: updated.goals,
        schedule: updated.schedule,
        status: updated.status,
        policy: updated.policy,
        mode: updated.mode,
        runtime: updated.runtime,
        fleetAgentId: updated.fleetAgentId,
      };
      updateSentinel(updated.id, patch);
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

export default SentinelDetailPage;
