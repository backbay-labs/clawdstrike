import * as React from "react";
import {
  OpenClawProvider as OpenClawDirectProvider,
  useOpenClaw as useOpenClawDirect,
  type OpenClawContextValue,
} from "./OpenClawDirectFallback";
import { OpenClawAgentProvider, useOpenClawAgent } from "./OpenClawAgentProvider";

export type {
  ExecApprovalDecision,
  ExecApprovalQueueItem,
  OpenClawDevicePairingSnapshot,
  OpenClawGatewayConfig,
  OpenClawGatewayRuntime,
  OpenClawNode,
} from "./OpenClawDirectFallback";
export { applyGatewayEventFrame } from "./OpenClawDirectFallback";

const USE_DIRECT_MODE =
  import.meta.env.DEV && import.meta.env.VITE_OPENCLAW_DIRECT_MODE === "1";

export function OpenClawProvider({ children }: { children: React.ReactNode }) {
  if (USE_DIRECT_MODE) return <OpenClawDirectProvider>{children}</OpenClawDirectProvider>;
  return <OpenClawAgentProvider>{children}</OpenClawAgentProvider>;
}

export function useOpenClaw(): OpenClawContextValue {
  if (USE_DIRECT_MODE) return useOpenClawDirect();
  return useOpenClawAgent();
}

