/**
 * SpiritExperienceTracker — zero-render component that detects XP-granting events
 * and calls useSpiritEvolutionStore.grantXp for the currently bound spirit kind.
 *
 * XP events:
 *   probe finding: activeProbes transitions from > 0 to 0 while station has new artifacts
 *                  (detect: prevActiveProbes > 0 && activeProbes === 0 → 10 XP)
 *   lint pass:     hasLintErrors transitions true → false (5 XP)
 *
 * Cooldown: each event type has a 10-second cooldown via useRef to prevent grinding.
 * Mounted once in DesktopLayout alongside SpiritMoodReactor.
 */
import { useEffect, useRef } from "react";
import { useSpiritStore } from "../stores/spirit-store";
import { useSpiritEvolutionStore } from "../stores/spirit-evolution-store";
import { useObservatoryStore } from "@/features/observatory/stores/observatory-store";
import { useMultiPolicy } from "@/features/policy/stores/multi-policy-store";

const PROBE_XP = 10;
const LINT_PASS_XP = 5;
const COOLDOWN_MS = 10_000;

export function SpiritExperienceTracker() {
  const kind = useSpiritStore.use.kind();
  const activeProbes = useObservatoryStore.use.seamSummary().activeProbes;
  const { tabs } = useMultiPolicy();
  const hasLintErrors = tabs.some((t) => t.validation.errors.length > 0);

  const prevActiveProbesRef = useRef<number>(activeProbes);
  const prevHasLintErrorsRef = useRef<boolean>(hasLintErrors);
  const probeLastGrantedRef = useRef<number>(0);
  const lintLastGrantedRef = useRef<number>(0);

  // Probe completion: activeProbes drops to 0 (probe finished with findings)
  useEffect(() => {
    const prev = prevActiveProbesRef.current;
    prevActiveProbesRef.current = activeProbes;

    if (!kind) return;
    if (prev > 0 && activeProbes === 0) {
      const now = Date.now();
      if (now - probeLastGrantedRef.current > COOLDOWN_MS) {
        probeLastGrantedRef.current = now;
        useSpiritEvolutionStore.getState().actions.grantXp(kind, PROBE_XP);
      }
    }
  }, [activeProbes, kind]);

  // Lint pass: errors transition from present to absent
  useEffect(() => {
    const prev = prevHasLintErrorsRef.current;
    prevHasLintErrorsRef.current = hasLintErrors;

    if (!kind) return;
    if (prev && !hasLintErrors) {
      const now = Date.now();
      if (now - lintLastGrantedRef.current > COOLDOWN_MS) {
        lintLastGrantedRef.current = now;
        useSpiritEvolutionStore.getState().actions.grantXp(kind, LINT_PASS_XP);
      }
    }
  }, [hasLintErrors, kind]);

  return null;
}
