/**
 * SpiritMoodReactor — zero-render component that derives spirit mood from
 * workbench signals and calls setMood on spirit-store.
 *
 * Signals:
 *   - hasLintErrors: any open policy tab has validation.errors.length > 0
 *   - probeActive: observatory seamSummary.activeProbes > 0
 *
 * Debounce: 500ms — prevents mood thrashing during rapid lint toggles.
 * Mounted once in DesktopLayout alongside SpiritFieldInjector.
 */
import { useEffect, useRef } from "react";
import { useSpiritStore } from "../stores/spirit-store";
import { useObservatoryStore } from "@/features/observatory/stores/observatory-store";
import { usePolicyTabsStore } from "@/features/policy/stores/policy-tabs-store";
import { usePolicyEditStore } from "@/features/policy/stores/policy-edit-store";
import { deriveSpiritMood } from "../mood";

export function SpiritMoodReactor() {
  const kind = useSpiritStore.use.kind();
  const setMood = useSpiritStore.use.actions().setMood;
  const activeProbes = useObservatoryStore((state) => state.seamSummary.activeProbes);
  const tabs = usePolicyTabsStore((state) => state.tabs);
  const editStates = usePolicyEditStore((state) => state.editStates);
  const hasLintErrors = tabs.some((tab) => {
    const validation = editStates.get(tab.id)?.validation;
    return (validation?.errors.length ?? 0) > 0;
  });
  const derived = deriveSpiritMood({ kind, hasLintErrors, probeActive: activeProbes > 0 });

  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (timerRef.current) clearTimeout(timerRef.current);
    timerRef.current = setTimeout(() => {
      setMood(derived);
    }, 500);
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [derived, setMood]);

  return null;
}
