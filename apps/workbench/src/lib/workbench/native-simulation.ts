import type {
  TauriGuardResultEntry,
  TauriPostureSimulationResponse,
  TauriSimulationResponse,
} from "@/lib/tauri-commands";
import type { Verdict } from "@/lib/workbench/types";

type NativeSimulationLike = Pick<TauriSimulationResponse, "allowed" | "results">;
type NativePostureSimulationLike = Pick<TauriPostureSimulationResponse, "allowed" | "results">;

export function isNativeWarningSeverity(severity: string | null | undefined): boolean {
  return severity === "warn" || severity === "warning";
}

export function verdictFromNativeGuardResult(
  result: Pick<TauriGuardResultEntry, "allowed" | "severity">,
): Verdict {
  if (!result.allowed) {
    return "deny";
  }

  return isNativeWarningSeverity(result.severity) ? "warn" : "allow";
}

export function verdictFromNativeSimulation(
  response: NativeSimulationLike | NativePostureSimulationLike,
): Verdict {
  if (!response.allowed) {
    return "deny";
  }

  return response.results.some((result) => verdictFromNativeGuardResult(result) === "warn")
    ? "warn"
    : "allow";
}
