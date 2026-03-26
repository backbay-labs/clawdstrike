import { describe, expect, it, vi, beforeEach } from "vitest";

// ---------------------------------------------------------------------------
// Mocks -- must be set up before importing the module under test
// ---------------------------------------------------------------------------

const { readPayloadNativeMock, writePayloadNativeMock } = vi.hoisted(() => ({
  readPayloadNativeMock: vi.fn(),
  writePayloadNativeMock: vi.fn(),
}));

vi.mock("@/lib/workbench/terminal-service", () => ({
  terminalService: {
    getCwd: vi.fn().mockResolvedValue("/mock/cwd"),
    create: vi.fn().mockResolvedValue({
      id: "mock-session",
      branch: "main",
      shell: "zsh",
      persistence_mode: "tmux",
      recovery_state: "fresh",
    }),
    discover: vi.fn().mockResolvedValue([]),
    reconnect: vi.fn().mockResolvedValue({
      id: "mock-session",
      branch: "main",
      shell: "zsh",
      persistence_mode: "tmux",
      recovery_state: "recovered",
    }),
    preview: vi.fn().mockResolvedValue([]),
    write: vi.fn().mockResolvedValue(undefined),
    kill: vi.fn().mockResolvedValue(undefined),
    onExit: vi.fn().mockResolvedValue(() => {}),
  },
  worktreeService: {
    create: vi.fn().mockResolvedValue({ path: "/mock/worktree", branch: "test-branch" }),
    remove: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock("@/lib/tauri-bridge", async () => {
  const actual = await vi.importActual<typeof import("@/lib/tauri-bridge")>("@/lib/tauri-bridge");
  return {
    ...actual,
    isDesktop: () => true,
  };
});

vi.mock("@/lib/tauri-commands", () => ({
  readAppPersistenceFileNative: readPayloadNativeMock,
  writeAppPersistenceFileNative: writePayloadNativeMock,
}));

vi.mock("../swarm-file-watch", () => ({
  setSwarmFileWatchScope: vi.fn().mockResolvedValue(undefined),
  clearSwarmFileWatchScope: vi.fn().mockResolvedValue(undefined),
  subscribeSwarmFileWatchEvents: vi.fn().mockReturnValue(() => {}),
}));

// ---------------------------------------------------------------------------
// Imports -- after mocks
// ---------------------------------------------------------------------------

import {
  unwrapEnvelopeForTesting,
  getArchiveFilename,
  writeArchivePayload,
} from "../swarm-persistence";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("swarm-feed-recovery", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // -------------------------------------------------------------------------
  // unwrapEnvelope version handling
  // -------------------------------------------------------------------------

  describe("unwrapEnvelope version migration", () => {
    it("migrates v1 envelope by adding empty highWaterMarks", () => {
      const raw = JSON.stringify({
        version: 1,
        savedAt: "2026-03-25T00:00:00Z",
        payload: {
          findingEnvelopes: [{ id: "f1" }],
        },
      });
      const result = unwrapEnvelopeForTesting(raw);
      expect(result).toEqual({
        findingEnvelopes: [{ id: "f1" }],
        highWaterMarks: {},
      });
    });

    it("returns v2 envelope payload unchanged", () => {
      const raw = JSON.stringify({
        version: 2,
        savedAt: "2026-03-25T00:00:00Z",
        payload: {
          findingEnvelopes: [{ id: "f1" }],
          highWaterMarks: { s1: { f1: 42 } },
        },
      });
      const result = unwrapEnvelopeForTesting(raw);
      expect(result).toEqual({
        findingEnvelopes: [{ id: "f1" }],
        highWaterMarks: { s1: { f1: 42 } },
      });
    });

    it("returns null for future version (v3) with console.warn", () => {
      const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
      const raw = JSON.stringify({
        version: 3,
        savedAt: "2026-03-25T00:00:00Z",
        payload: { findingEnvelopes: [] },
      });
      const result = unwrapEnvelopeForTesting(raw);
      expect(result).toBeNull();
      expect(warnSpy).toHaveBeenCalledWith(
        expect.stringContaining("Unsupported"),
      );
      warnSpy.mockRestore();
    });

    it("returns unversioned (legacy) JSON as-is", () => {
      const raw = JSON.stringify({
        findingEnvelopes: [{ id: "legacy" }],
      });
      const result = unwrapEnvelopeForTesting(raw);
      expect(result).toEqual({
        findingEnvelopes: [{ id: "legacy" }],
      });
    });

    it("returns null for corrupt (unparseable) string", () => {
      const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
      const result = unwrapEnvelopeForTesting("not json{{");
      expect(result).toBeNull();
      warnSpy.mockRestore();
    });

    it("returns null for empty string", () => {
      const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
      const result = unwrapEnvelopeForTesting("");
      expect(result).toBeNull();
      warnSpy.mockRestore();
    });
  });

  // -------------------------------------------------------------------------
  // Archive filename generation
  // -------------------------------------------------------------------------

  describe("getArchiveFilename", () => {
    it("generates monthly archive filename from explicit month key", () => {
      expect(getArchiveFilename("2026-03")).toBe("swarm-feed-archive-2026-03.json");
    });

    it("uses current month when no key provided", () => {
      const filename = getArchiveFilename();
      // Should match pattern: swarm-feed-archive-YYYY-MM.json
      expect(filename).toMatch(/^swarm-feed-archive-\d{4}-\d{2}\.json$/);
    });
  });

  // -------------------------------------------------------------------------
  // Archive write
  // -------------------------------------------------------------------------

  describe("writeArchivePayload", () => {
    it("writes overflow to archive file when no existing archive", async () => {
      readPayloadNativeMock.mockResolvedValue(null);
      writePayloadNativeMock.mockResolvedValue(true);

      const overflow = { findingEnvelopes: [{ id: "f1" }] };
      const result = await writeArchivePayload(overflow);

      expect(result).toBe(true);
      expect(writePayloadNativeMock).toHaveBeenCalledOnce();
      const [filename, content] = writePayloadNativeMock.mock.calls[0]!;
      expect(filename).toMatch(/^swarm-feed-archive-\d{4}-\d{2}\.json$/);
      const parsed = JSON.parse(content as string);
      expect(Array.isArray(parsed)).toBe(true);
      expect(parsed).toHaveLength(1);
      expect(parsed[0].findingEnvelopes).toEqual([{ id: "f1" }]);
      expect(parsed[0].archivedAt).toBeDefined();
    });

    it("merges with existing archive entries", async () => {
      const existingArchive = JSON.stringify([
        { archivedAt: "2026-03-01T00:00:00Z", findingEnvelopes: [{ id: "old" }] },
      ]);
      readPayloadNativeMock.mockResolvedValue(existingArchive);
      writePayloadNativeMock.mockResolvedValue(true);

      const overflow = { findingEnvelopes: [{ id: "new" }] };
      const result = await writeArchivePayload(overflow);

      expect(result).toBe(true);
      const [, content] = writePayloadNativeMock.mock.calls[0]!;
      const parsed = JSON.parse(content as string);
      expect(parsed).toHaveLength(2);
      expect(parsed[0].findingEnvelopes[0].id).toBe("old");
      expect(parsed[1].findingEnvelopes[0].id).toBe("new");
    });
  });
});
