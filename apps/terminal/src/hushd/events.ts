import type { CheckEventData, DaemonEvent } from "./types"

export function asCheckEventData(event: DaemonEvent): CheckEventData | null {
  const data = event.data
  if (!data || typeof data !== "object") {
    return null
  }

  const actionType = (data as Record<string, unknown>).action_type
  const target = (data as Record<string, unknown>).target
  const decision = (data as Record<string, unknown>).decision

  if (
    typeof actionType !== "string" ||
    typeof target !== "string" ||
    (decision !== "allow" && decision !== "deny")
  ) {
    return null
  }

  return data as CheckEventData
}

export function eventDecision(event: DaemonEvent): "allow" | "deny" | null {
  return asCheckEventData(event)?.decision ?? null
}
