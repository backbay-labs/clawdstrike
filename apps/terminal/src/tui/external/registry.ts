import { kittyAdapter } from "./kitty"
import { terminalAppAdapter } from "./terminal-app"
import { tmuxSplitAdapter, tmuxWindowAdapter } from "./tmux"
import type { ExternalTerminalAdapter, ExternalTerminalAdapterOption } from "./types"
import { weztermAdapter } from "./wezterm"

const DEFAULT_ADAPTERS: ExternalTerminalAdapter[] = [
  tmuxSplitAdapter,
  tmuxWindowAdapter,
  weztermAdapter,
  kittyAdapter,
  terminalAppAdapter,
]

export function getExternalAdapters(): ExternalTerminalAdapter[] {
  return DEFAULT_ADAPTERS
}

export async function getAvailableExternalAdapters(
  adapters: ExternalTerminalAdapter[] = DEFAULT_ADAPTERS,
): Promise<ExternalTerminalAdapter[]> {
  const settled = await Promise.all(
    adapters.map(async (adapter) => ({
      adapter,
      available: await adapter.isAvailable().catch(() => false),
    })),
  )

  return settled.filter((entry) => entry.available).map((entry) => entry.adapter)
}

export function getExternalAdapter(
  id: string,
  adapters: ExternalTerminalAdapter[] = DEFAULT_ADAPTERS,
): ExternalTerminalAdapter | null {
  return adapters.find((adapter) => adapter.id === id) ?? null
}

export function toExternalAdapterOptions(
  adapters: ExternalTerminalAdapter[],
): ExternalTerminalAdapterOption[] {
  return adapters.map((adapter) => ({
    id: adapter.id,
    label: adapter.label,
    description: adapter.description,
  }))
}
