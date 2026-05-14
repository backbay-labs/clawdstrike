/**
 * Prefixed ULID generation for swarm engine entities.
 *
 * @module
 */

export type SwarmEngineIdPrefix =
  | "agt" // AgentSession
  | "tsk" // Task
  | "swe" // SwarmEngine instance
  | "top" // Topology snapshot
  | "csn" // Consensus proposal
  | "msg" // Internal message
  | "rct"; // Receipt

const CROCKFORD_BASE32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/** 10-char Crockford Base32 from 48-bit millisecond timestamp. */
function encodeTime(ms: number): string {
  let value = ms;
  const chars: string[] = new Array(10);
  for (let i = 9; i >= 0; i--) {
    chars[i] = CROCKFORD_BASE32[value & 0x1f]!;
    value = Math.floor(value / 32);
  }
  return chars.join("");
}

/** 16 random Crockford Base32 characters (80 bits). */
function encodeRandom(): string {
  const chars: string[] = new Array(16);
  if (typeof crypto !== "undefined" && crypto.getRandomValues) {
    const bytes = new Uint8Array(10);
    crypto.getRandomValues(bytes);
    for (let i = 0; i < 10; i++) {
      chars[i] = CROCKFORD_BASE32[bytes[i]! & 0x1f]!;
    }
    // Extract 6 more 5-bit chars by combining upper bits of adjacent bytes
    for (let i = 0; i < 6; i++) {
      const hi = (bytes[i]! >> 5) & 0x07;
      const lo = (bytes[i + 1]! >> 6) & 0x03;
      chars[10 + i] = CROCKFORD_BASE32[(hi << 2) | lo]!;
    }
  } else {
    for (let i = 0; i < 16; i++) {
      chars[i] = CROCKFORD_BASE32[Math.floor(Math.random() * 32)]!;
    }
  }
  return chars.join("");
}

/** Generate a prefixed ULID, e.g. `agt_01HXK8M3N2...` */
export function generateSwarmId(prefix: SwarmEngineIdPrefix): string {
  return `${prefix}_${encodeTime(Date.now())}${encodeRandom()}`;
}
