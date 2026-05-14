// Presence wire protocol types — mirrors the server's ServerMessage/ClientMessage
// enums from crates/services/hushd/src/api/presence.rs.
//
// All type discriminators and field names use snake_case to match the Rust
// serde(rename_all = "snake_case") serialization exactly.

// ---------------------------------------------------------------------------
// Connection state
// ---------------------------------------------------------------------------

export type PresenceConnectionState =
  | "idle"
  | "connecting"
  | "connected"
  | "reconnecting"
  | "disconnected";

// ---------------------------------------------------------------------------
// Analyst presence (client-side enriched view of AnalystInfo)
// ---------------------------------------------------------------------------

export interface AnalystPresence {
  fingerprint: string;
  displayName: string;
  sigil: string;
  color: string;
  activeFile: string | null;
  cursor: { line: number; ch: number } | null;
  selection: {
    anchorLine: number;
    anchorCh: number;
    headLine: number;
    headCh: number;
  } | null;
  lastSeen: number; // Date.now() timestamp
}

// ---------------------------------------------------------------------------
// Wire types — raw JSON shapes from the server (snake_case field names)
// ---------------------------------------------------------------------------

export interface AnalystInfoWire {
  fingerprint: string;
  display_name: string;
  sigil: string;
  color: string;
  active_file: string | null;
}

/**
 * Raw server-to-client messages. The `type` field is the snake_case
 * discriminator produced by serde(tag = "type", rename_all = "snake_case").
 */
export type ServerMessageRaw =
  | {
      type: "welcome";
      analyst_id: string;
      color: string;
      roster: AnalystInfoWire[];
    }
  | { type: "analyst_joined"; analyst: AnalystInfoWire }
  | { type: "analyst_left"; fingerprint: string }
  | { type: "analyst_viewing"; fingerprint: string; file_path: string }
  | { type: "analyst_left_file"; fingerprint: string; file_path: string }
  | {
      type: "analyst_cursor";
      fingerprint: string;
      file_path: string;
      line: number;
      ch: number;
    }
  | {
      type: "analyst_selection";
      fingerprint: string;
      file_path: string;
      anchor_line: number;
      anchor_ch: number;
      head_line: number;
      head_ch: number;
    }
  | { type: "heartbeat_ack" }
  | { type: "error"; message: string };

/**
 * Client-to-server messages. Field names are snake_case for direct
 * JSON.stringify -> serde deserialization on the server.
 */
export type ClientMessage =
  | {
      type: "join";
      fingerprint: string;
      display_name: string;
      sigil: string;
    }
  | { type: "view_file"; file_path: string }
  | { type: "leave_file"; file_path: string }
  | { type: "cursor"; file_path: string; line: number; ch: number }
  | {
      type: "selection";
      file_path: string;
      anchor_line: number;
      anchor_ch: number;
      head_line: number;
      head_ch: number;
    }
  | { type: "heartbeat" };

// ---------------------------------------------------------------------------
// Socket options
// ---------------------------------------------------------------------------

export interface PresenceSocketOptions {
  hushdUrl: string;
  getApiKey: () => string;
  getIdentity: () => {
    fingerprint: string;
    displayName: string;
    sigil: string;
  } | null;
  onMessage: (msg: ServerMessageRaw) => void;
  onStateChange: (state: PresenceConnectionState) => void;
  onReconnect: () => void;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Convert a wire-format AnalystInfo to the client-side AnalystPresence. */
export function parseAnalystInfo(wire: AnalystInfoWire): AnalystPresence {
  return {
    fingerprint: wire.fingerprint,
    displayName: wire.display_name,
    sigil: wire.sigil,
    color: wire.color,
    activeFile: wire.active_file,
    cursor: null,
    selection: null,
    lastSeen: Date.now(),
  };
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Heartbeat interval in milliseconds — matches server HEARTBEAT_INTERVAL_SECS (15). */
export const HEARTBEAT_INTERVAL_MS = 15_000;

/** Deterministic color palette — same 8 colors as the server. */
export const PRESENCE_COLORS: readonly string[] = [
  "#5b8def",
  "#e06c75",
  "#98c379",
  "#d19a66",
  "#c678dd",
  "#56b6c2",
  "#be5046",
  "#e5c07b",
];
