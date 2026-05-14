// usePresenceConnection — React hook that bootstraps the PresenceSocket
// singleton and wires incoming server messages to the presence Zustand store.
//
// Called once in App.tsx WorkbenchBootstraps (after useFleetConnection).
// Manages the full lifecycle: create socket when fleet is connected + operator
// identity is available, tear down when either goes away or on unmount.

import { useEffect } from "react";
import { PresenceSocket } from "./presence-socket";
import { usePresenceStore } from "./stores/presence-store";
import { useFleetConnectionStore } from "@/features/fleet/use-fleet-connection";
import { useOperatorStore } from "@/features/operator/stores/operator-store";
import type { PresenceConnectionState, ServerMessageRaw } from "./types";

// ---------------------------------------------------------------------------
// Module-level singleton — ensures one WebSocket regardless of React re-renders
// ---------------------------------------------------------------------------

let presenceSocket: PresenceSocket | null = null;
let currentHushdUrl: string | null = null;

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export function usePresenceConnection(): void {
  const hushdUrl = useFleetConnectionStore((s) => s.connection.hushdUrl);
  const fleetConnected = useFleetConnectionStore((s) => s.connection.connected);
  const operator = useOperatorStore((s) => s.currentOperator);

  useEffect(() => {
    // Guard: need fleet connected + hushdUrl + operator identity
    if (!fleetConnected || !hushdUrl || !operator) {
      // Disconnect existing socket if prerequisites lost
      if (presenceSocket) {
        presenceSocket.disconnect();
        presenceSocket = null;
        currentHushdUrl = null;
      }
      usePresenceStore.getState().actions.reset();
      return;
    }

    // Already connected to the same hushd — nothing to do
    if (presenceSocket && currentHushdUrl === hushdUrl) {
      return;
    }

    // Disconnect old socket if switching hushd instances
    if (presenceSocket) {
      presenceSocket.disconnect();
      presenceSocket = null;
      currentHushdUrl = null;
    }

    // Create new PresenceSocket
    presenceSocket = new PresenceSocket({
      hushdUrl,
      getApiKey: () =>
        useFleetConnectionStore.getState().actions.getCredentials().apiKey,
      getIdentity: () => {
        const op = useOperatorStore.getState().currentOperator;
        if (!op) return null;
        return {
          fingerprint: op.fingerprint,
          displayName: op.displayName,
          sigil: op.sigil,
        };
      },
      onMessage: (msg: ServerMessageRaw) => {
        usePresenceStore.getState().actions.handleServerMessage(msg);
      },
      onStateChange: (state: PresenceConnectionState) => {
        usePresenceStore.getState().actions.setConnectionState(state);
      },
      onReconnect: () => {
        // On reconnect the server sends a fresh Welcome with full roster.
        // handleServerMessage("welcome") resets state — no additional action needed.
      },
    });
    currentHushdUrl = hushdUrl;
    presenceSocket.connect();

    // Cleanup on unmount
    return () => {
      if (presenceSocket) {
        presenceSocket.disconnect();
        presenceSocket = null;
        currentHushdUrl = null;
      }
      usePresenceStore.getState().actions.reset();
    };
  }, [hushdUrl, fleetConnected, operator?.fingerprint]);
}

// ---------------------------------------------------------------------------
// Non-React accessor for Phase 21 CM6 ViewPlugin
// ---------------------------------------------------------------------------

/**
 * Get the current PresenceSocket instance. Returns null when not connected.
 * Used by the CM6 presence extension (Phase 21) to send cursor/selection
 * messages without going through React.
 */
export function getPresenceSocket(): PresenceSocket | null {
  return presenceSocket;
}
