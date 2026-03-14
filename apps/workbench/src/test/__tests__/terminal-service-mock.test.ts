import { beforeEach, describe, expect, it } from "vitest";

import {
  MockTerminalService,
  createMockTerminalService,
  type MockTerminalSession,
} from "../terminal-service-mock";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("MockTerminalService", () => {
  let svc: MockTerminalService;

  beforeEach(() => {
    svc = createMockTerminalService();
  });

  describe("createSession", () => {
    it("returns a valid SessionInfo object", () => {
      const session = svc.createSession("Test Agent", "/tmp/project");

      expect(session.id).toMatch(/^mock-session-\d+$/);
      expect(session.title).toBe("Test Agent");
      expect(session.cwd).toBe("/tmp/project");
      expect(session.outputLines).toEqual([]);
      expect(session.exitCode).toBeNull();
      expect(session.running).toBe(true);
      expect(session.createdAt).toBeGreaterThan(0);
    });

    it("uses /tmp as default cwd", () => {
      const session = svc.createSession("Agent");
      expect(session.cwd).toBe("/tmp");
    });

    it("generates unique IDs for each session", () => {
      const s1 = svc.createSession("A");
      const s2 = svc.createSession("B");
      const s3 = svc.createSession("C");

      expect(s1.id).not.toBe(s2.id);
      expect(s2.id).not.toBe(s3.id);
      expect(s1.id).not.toBe(s3.id);
    });

    it("fires onSessionCreated callback", () => {
      const session = svc.createSession("Agent", "/home/user");

      expect(svc.onSessionCreated).toHaveBeenCalledTimes(1);
      expect(svc.onSessionCreated).toHaveBeenCalledWith(session);
    });

    it("increments sessionCount", () => {
      expect(svc.sessionCount).toBe(0);

      svc.createSession("A");
      expect(svc.sessionCount).toBe(1);

      svc.createSession("B");
      expect(svc.sessionCount).toBe(2);
    });
  });

  describe("write", () => {
    it("updates output lines with written data", () => {
      const session = svc.createSession("Agent");

      svc.write(session.id, "cargo test\ncargo build");

      expect(session.outputLines).toEqual(["cargo test", "cargo build"]);
    });

    it("returns bytes written", () => {
      const session = svc.createSession("Agent");

      const result = svc.write(session.id, "hello world");
      expect(result.bytesWritten).toBe(11);
    });

    it("appends to existing output", () => {
      const session = svc.createSession("Agent");

      svc.write(session.id, "line1");
      svc.write(session.id, "line2\nline3");

      expect(session.outputLines).toEqual(["line1", "line2", "line3"]);
    });

    it("throws on unknown session", () => {
      expect(() => svc.write("nonexistent", "data")).toThrow("Session not found: nonexistent");
    });

    it("throws on exited session", () => {
      const session = svc.createSession("Agent");
      svc.exitSession(session.id);

      expect(() => svc.write(session.id, "data")).toThrow("Session already exited");
    });

    it("ignores empty lines when splitting", () => {
      const session = svc.createSession("Agent");
      svc.write(session.id, "\n\n");

      expect(session.outputLines).toEqual([]);
    });
  });

  describe("simulateOutput", () => {
    it("adds output lines to a session", () => {
      const session = svc.createSession("Agent");

      svc.simulateOutput(session.id, ["running 5 tests...", "test auth ... ok"]);

      expect(session.outputLines).toEqual(["running 5 tests...", "test auth ... ok"]);
    });

    it("throws on unknown session", () => {
      expect(() => svc.simulateOutput("nonexistent", ["data"])).toThrow("Session not found");
    });
  });

  describe("getPreviewLines", () => {
    it("returns last N lines of output", () => {
      const session = svc.createSession("Agent");
      svc.simulateOutput(session.id, [
        "line1", "line2", "line3", "line4", "line5",
        "line6", "line7", "line8", "line9", "line10",
      ]);

      const preview = svc.getPreviewLines(session.id, 3);
      expect(preview).toEqual(["line8", "line9", "line10"]);
    });

    it("returns all lines when count exceeds total", () => {
      const session = svc.createSession("Agent");
      svc.simulateOutput(session.id, ["line1", "line2"]);

      const preview = svc.getPreviewLines(session.id, 10);
      expect(preview).toEqual(["line1", "line2"]);
    });

    it("defaults to 6 lines", () => {
      const session = svc.createSession("Agent");
      svc.simulateOutput(session.id, [
        "a", "b", "c", "d", "e", "f", "g", "h",
      ]);

      const preview = svc.getPreviewLines(session.id);
      expect(preview).toHaveLength(6);
      expect(preview).toEqual(["c", "d", "e", "f", "g", "h"]);
    });

    it("returns empty array for unknown session", () => {
      const preview = svc.getPreviewLines("nonexistent");
      expect(preview).toEqual([]);
    });

    it("returns empty array for session with no output", () => {
      const session = svc.createSession("Agent");
      const preview = svc.getPreviewLines(session.id);
      expect(preview).toEqual([]);
    });
  });

  describe("listSessions", () => {
    it("returns all active sessions", () => {
      svc.createSession("A");
      svc.createSession("B");
      svc.createSession("C");

      const all = svc.listSessions();
      expect(all).toHaveLength(3);
    });

    it("filters by running state", () => {
      const s1 = svc.createSession("A");
      svc.createSession("B");
      svc.exitSession(s1.id);

      const running = svc.listSessions({ running: true });
      expect(running).toHaveLength(1);
      expect(running[0].title).toBe("B");

      const exited = svc.listSessions({ running: false });
      expect(exited).toHaveLength(1);
      expect(exited[0].title).toBe("A");
    });

    it("returns empty array when no sessions", () => {
      expect(svc.listSessions()).toEqual([]);
    });
  });

  describe("getSession", () => {
    it("returns session by ID", () => {
      const session = svc.createSession("Agent");
      const result = svc.getSession(session.id);

      expect(result).not.toBeNull();
      expect(result!.title).toBe("Agent");
    });

    it("returns null for unknown ID", () => {
      expect(svc.getSession("nonexistent")).toBeNull();
    });
  });

  describe("exitSession (kill)", () => {
    it("marks session as exited with exit code", () => {
      const session = svc.createSession("Agent");
      svc.exitSession(session.id, 0);

      expect(session.running).toBe(false);
      expect(session.exitCode).toBe(0);
    });

    it("marks session as exited with non-zero exit code", () => {
      const session = svc.createSession("Agent");
      svc.exitSession(session.id, 1);

      expect(session.running).toBe(false);
      expect(session.exitCode).toBe(1);
    });

    it("defaults to exit code 0", () => {
      const session = svc.createSession("Agent");
      svc.exitSession(session.id);

      expect(session.exitCode).toBe(0);
    });

    it("fires onSessionExited callback", () => {
      const session = svc.createSession("Agent");
      svc.exitSession(session.id, 42);

      expect(svc.onSessionExited).toHaveBeenCalledTimes(1);
      expect(svc.onSessionExited).toHaveBeenCalledWith(session.id, 42);
    });

    it("throws on unknown session", () => {
      expect(() => svc.exitSession("nonexistent")).toThrow("Session not found");
    });
  });

  describe("destroySession", () => {
    it("removes session from the map", () => {
      const session = svc.createSession("Agent");
      expect(svc.sessionCount).toBe(1);

      svc.destroySession(session.id);
      expect(svc.sessionCount).toBe(0);
      expect(svc.getSession(session.id)).toBeNull();
    });
  });

  describe("reset", () => {
    it("clears all sessions", () => {
      svc.createSession("A");
      svc.createSession("B");
      expect(svc.sessionCount).toBe(2);

      svc.reset();
      expect(svc.sessionCount).toBe(0);
    });

    it("resets the counter so next IDs start fresh", () => {
      svc.createSession("A");
      svc.createSession("B");
      svc.reset();

      const session = svc.createSession("C");
      expect(session.id).toBe("mock-session-1");
    });

    it("clears callback spies", () => {
      svc.createSession("A");
      expect(svc.onSessionCreated).toHaveBeenCalledTimes(1);

      svc.reset();
      expect(svc.onSessionCreated).toHaveBeenCalledTimes(0);
      expect(svc.onSessionExited).toHaveBeenCalledTimes(0);
    });
  });

  describe("createMockTerminalService factory", () => {
    it("returns a new instance each time", () => {
      const svc1 = createMockTerminalService();
      const svc2 = createMockTerminalService();

      expect(svc1).not.toBe(svc2);
    });

    it("returns a clean instance", () => {
      const fresh = createMockTerminalService();
      expect(fresh.sessionCount).toBe(0);
      expect(fresh.listSessions()).toEqual([]);
    });
  });
});
