/**
 * Adapter registry - CLI adapter exports
 */

export { CodexAdapter } from "./codex"
export { ClaudeAdapter } from "./claude"
export { OpenCodeAdapter } from "./opencode"
export { CrushAdapter } from "./crush"

import { CodexAdapter } from "./codex"
import { ClaudeAdapter } from "./claude"
import { OpenCodeAdapter } from "./opencode"
import { CrushAdapter } from "./crush"
import type { Adapter } from "../index"

/**
 * All available adapters
 */
export const adapters: Record<string, Adapter> = {
  codex: CodexAdapter,
  claude: ClaudeAdapter,
  opencode: OpenCodeAdapter,
  crush: CrushAdapter,
}

/**
 * Get adapter by ID
 */
export function getAdapter(id: string): Adapter | undefined {
  return adapters[id]
}

/**
 * Get all adapters
 */
export function getAllAdapters(): Adapter[] {
  return Object.values(adapters)
}

/**
 * Get available adapters (those that pass isAvailable check)
 */
export async function getAvailableAdapters(): Promise<Adapter[]> {
  const available: Adapter[] = []
  for (const adapter of Object.values(adapters)) {
    if (await adapter.isAvailable()) {
      available.push(adapter)
    }
  }
  return available
}
