import type { HuntSpiritSignalSnapshot } from "./selectors";

export function clamp01(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(1, value));
}

export function countOf(
  counts: HuntSpiritSignalSnapshot["artifactCounts"] | HuntSpiritSignalSnapshot["semanticCounts"],
  key: string,
): number {
  const value = counts[key as keyof typeof counts];
  return typeof value === "number" ? value : 0;
}

export function hasRecentBind(
  snapshot: HuntSpiritSignalSnapshot,
  previousSnapshot: HuntSpiritSignalSnapshot | null,
  nowMs: number,
): boolean {
  const spirit = snapshot.boundSpirit;
  if (!spirit) return false;

  const previousSpirit = previousSnapshot?.boundSpirit ?? null;
  const latestBindAt = Math.max(spirit.boundAt, spirit.reboundAt ?? 0);
  if (previousSpirit === null) return true;
  if (spirit.reboundAt !== previousSpirit.reboundAt) return true;
  return nowMs - latestBindAt <= 4_500;
}
