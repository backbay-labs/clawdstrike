/**
 * Gate registry - Quality gate exports
 */

export { PytestGate } from "./pytest"
export { MypyGate } from "./mypy"
export { RuffGate } from "./ruff"
export { ClawdStrikeGate } from "./clawdstrike"

import { PytestGate } from "./pytest"
import { MypyGate } from "./mypy"
import { RuffGate } from "./ruff"
import { ClawdStrikeGate } from "./clawdstrike"
import type { Gate } from "../index"

/**
 * Built-in gates registry
 */
export const gates: Record<string, Gate> = {
  pytest: PytestGate,
  mypy: MypyGate,
  ruff: RuffGate,
  clawdstrike: ClawdStrikeGate,
}

/**
 * Get gate by ID
 */
export function getGate(id: string): Gate | undefined {
  return gates[id]
}

/**
 * Get all gates
 */
export function getAllGates(): Gate[] {
  return Object.values(gates)
}

/**
 * Register a custom gate
 */
export function registerGate(gate: Gate): void {
  gates[gate.info.id] = gate
}
