import { HUNT_STATION_LABELS } from "./stations";
import type { HuntStationId, HuntStationStatus } from "./types";
import type { ObservatoryReplaySnapshot } from "./observatory-telemetry";

export interface ObservatoryReplayDistrictDiff {
  districtId: HuntStationId;
  label: string;
  emphasisDelta: number;
  artifactDelta: number;
  statusBefore: HuntStationStatus | null;
  statusAfter: HuntStationStatus | null;
  reasonBefore: string | null;
  reasonAfter: string | null;
  quiet: boolean;
  summary: string;
}

function formatSignedDelta(value: number): string {
  const rounded = Math.round(value * 100) / 100;
  return `${rounded >= 0 ? "+" : ""}${rounded.toFixed(2)}`;
}

function formatArtifactDelta(value: number): string {
  const rounded = Math.trunc(value);
  return `${rounded >= 0 ? "+" : ""}${rounded}`;
}

function compareReplayDiffSignificance(
  left: ObservatoryReplayDistrictDiff,
  right: ObservatoryReplayDistrictDiff,
): number {
  const emphasisDelta = Math.abs(right.emphasisDelta) - Math.abs(left.emphasisDelta);
  if (emphasisDelta !== 0) {
    return emphasisDelta;
  }
  const artifactDelta = Math.abs(right.artifactDelta) - Math.abs(left.artifactDelta);
  if (artifactDelta !== 0) {
    return artifactDelta;
  }
  return left.label.localeCompare(right.label);
}

function buildReplayDiffSummary(input: {
  label: string;
  emphasisDelta: number;
  artifactDelta: number;
  statusBefore: HuntStationStatus | null;
  statusAfter: HuntStationStatus | null;
  quiet: boolean;
}): string {
  if (input.quiet) {
    return `${input.label} stayed quiet; no material delta since the selected frame.`;
  }

  const statusChanged = input.statusBefore !== input.statusAfter;
  const transition = statusChanged
    ? `${input.statusBefore ?? "idle"} to ${input.statusAfter ?? "idle"}`
    : `${input.statusAfter ?? input.statusBefore ?? "steady"}`;
  const statusLead = statusChanged
    ? `${input.label} hardened from ${transition}`
    : `${input.label} shifted`;

  return `${statusLead} (${formatArtifactDelta(input.artifactDelta)} artifacts, ${formatSignedDelta(input.emphasisDelta)} emphasis).`;
}

export function compareObservatoryReplaySnapshots(
  liveSnapshot: ObservatoryReplaySnapshot | null,
  replaySnapshot: ObservatoryReplaySnapshot | null,
): ObservatoryReplayDistrictDiff[] {
  if (!liveSnapshot || !replaySnapshot) {
    return [];
  }

  const liveDistricts = new Map(liveSnapshot.districts.map((district) => [district.districtId, district]));
  const replayDistricts = new Map(replaySnapshot.districts.map((district) => [district.districtId, district]));
  const allDistrictIds = new Set<HuntStationId>([
    ...liveSnapshot.districts.map((district) => district.districtId),
    ...replaySnapshot.districts.map((district) => district.districtId),
  ]);

  const diffs = Array.from(allDistrictIds).map<ObservatoryReplayDistrictDiff>((districtId) => {
    const before = replayDistricts.get(districtId) ?? null;
    const after = liveDistricts.get(districtId) ?? null;
    const emphasisDelta = (after?.emphasis ?? 0) - (before?.emphasis ?? 0);
    const artifactDelta = (after?.artifactCount ?? 0) - (before?.artifactCount ?? 0);
    const statusBefore = before?.status ?? null;
    const statusAfter = after?.status ?? null;
    const reasonBefore = before?.reason ?? null;
    const reasonAfter = after?.reason ?? null;
    const quiet = Math.abs(emphasisDelta) < 0.08 && artifactDelta === 0 && statusBefore === statusAfter;

    return {
      artifactDelta,
      districtId,
      emphasisDelta,
      label: after?.label ?? before?.label ?? HUNT_STATION_LABELS[districtId],
      quiet,
      reasonAfter,
      reasonBefore,
      statusAfter,
      statusBefore,
      summary: buildReplayDiffSummary({
        artifactDelta,
        emphasisDelta,
        label: after?.label ?? before?.label ?? HUNT_STATION_LABELS[districtId],
        quiet,
        statusAfter,
        statusBefore,
      }),
    };
  });

  return diffs.sort(compareReplayDiffSignificance);
}
