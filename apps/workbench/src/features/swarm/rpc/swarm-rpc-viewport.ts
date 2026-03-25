import type { Viewport } from "@xyflow/react";

export interface SwarmRpcViewportController {
  getViewport: () => Viewport;
  setViewport: (
    viewport: Viewport,
    options?: { duration?: number },
  ) => Promise<Viewport> | Viewport;
}

let activeViewportController: SwarmRpcViewportController | null = null;

export function registerSwarmRpcViewportController(
  controller: SwarmRpcViewportController,
): () => void {
  activeViewportController = controller;
  return () => {
    if (activeViewportController === controller) {
      activeViewportController = null;
    }
  };
}

export function getSwarmRpcViewportController(): SwarmRpcViewportController | null {
  return activeViewportController;
}
