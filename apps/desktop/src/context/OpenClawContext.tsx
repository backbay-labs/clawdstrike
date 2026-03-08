import * as React from "react";
import { OpenClawAgentProvider, useOpenClawAgent } from "./OpenClawAgentProvider";
import {
  type OpenClawContextValue,
  OpenClawProvider as OpenClawDirectProvider,
  useOpenClaw as useOpenClawDirect,
} from "./OpenClawDirectFallback";

export type {
  ExecApprovalDecision,
  ExecApprovalQueueItem,
  OpenClawDevicePairingSnapshot,
  OpenClawGatewayConfig,
  OpenClawGatewayRuntime,
  OpenClawNode,
} from "./OpenClawDirectFallback";
export { applyGatewayEventFrame } from "./OpenClawDirectFallback";

const USE_DIRECT_MODE = import.meta.env.DEV && import.meta.env.VITE_OPENCLAW_DIRECT_MODE === "1";

export function OpenClawProvider({ children }: { children: React.ReactNode }) {
  if (USE_DIRECT_MODE) return <OpenClawDirectProvider>{children}</OpenClawDirectProvider>;
  return <OpenClawAgentProvider>{children}</OpenClawAgentProvider>;
}

// Select hook implementation at module scope (constant after Vite env replacement).
const useOpenClawImpl = USE_DIRECT_MODE ? useOpenClawDirect : useOpenClawAgent;

export function useOpenClaw(): OpenClawContextValue {
  return useOpenClawImpl();
}
