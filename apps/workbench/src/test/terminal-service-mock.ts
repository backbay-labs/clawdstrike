/**
 * Mock for the terminal service used in SwarmBoard tests.
 *
 * Tracks created sessions in memory, simulates stdout output on write,
 * returns preview lines, supports session listing, and can simulate
 * session exit.
 */
import { vi } from "vitest";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface MockTerminalSession {
  id: string;
  title: string;
  cwd: string;
  outputLines: string[];
  exitCode: number | null;
  running: boolean;
  createdAt: number;
}

export interface WriteResult {
  bytesWritten: number;
}

// ---------------------------------------------------------------------------
// MockTerminalService
// ---------------------------------------------------------------------------

export class MockTerminalService {
  private sessions = new Map<string, MockTerminalSession>();
  private counter = 0;

  /** Spy-friendly versions of each method. */
  readonly onSessionCreated = vi.fn<(session: MockTerminalSession) => void>();
  readonly onSessionExited = vi.fn<(sessionId: string, exitCode: number) => void>();

  /**
   * Create a new terminal session.
   */
  createSession(title: string, cwd: string = "/tmp"): MockTerminalSession {
    this.counter += 1;
    const session: MockTerminalSession = {
      id: `mock-session-${this.counter}`,
      title,
      cwd,
      outputLines: [],
      exitCode: null,
      running: true,
      createdAt: Date.now(),
    };
    this.sessions.set(session.id, session);
    this.onSessionCreated(session);
    return session;
  }

  /**
   * Write data to a session's stdin. Simulates stdout by appending
   * the written data to the session's output lines.
   */
  write(sessionId: string, data: string): WriteResult {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error(`Session not found: ${sessionId}`);
    }
    if (!session.running) {
      throw new Error(`Session already exited: ${sessionId}`);
    }

    // Split data into lines and add to output
    const lines = data.split("\n").filter((l) => l.length > 0);
    session.outputLines.push(...lines);

    return { bytesWritten: data.length };
  }

  /**
   * Simulate receiving output from the terminal (e.g., command results).
   */
  simulateOutput(sessionId: string, lines: string[]): void {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error(`Session not found: ${sessionId}`);
    }
    session.outputLines.push(...lines);
  }

  /**
   * Get preview lines for a session (last N lines of output).
   */
  getPreviewLines(sessionId: string, count: number = 6): string[] {
    const session = this.sessions.get(sessionId);
    if (!session) {
      return [];
    }
    return session.outputLines.slice(-count);
  }

  /**
   * List all sessions, optionally filtering by running state.
   */
  listSessions(opts?: { running?: boolean }): MockTerminalSession[] {
    const all = Array.from(this.sessions.values());
    if (opts?.running !== undefined) {
      return all.filter((s) => s.running === opts.running);
    }
    return all;
  }

  /**
   * Get a specific session by ID.
   */
  getSession(sessionId: string): MockTerminalSession | null {
    return this.sessions.get(sessionId) ?? null;
  }

  /**
   * Simulate session exit with an exit code.
   */
  exitSession(sessionId: string, exitCode: number = 0): void {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error(`Session not found: ${sessionId}`);
    }
    session.running = false;
    session.exitCode = exitCode;
    this.onSessionExited(sessionId, exitCode);
  }

  /**
   * Destroy a session (remove from the map entirely).
   */
  destroySession(sessionId: string): void {
    this.sessions.delete(sessionId);
  }

  /**
   * Reset all state. Useful in beforeEach.
   */
  reset(): void {
    this.sessions.clear();
    this.counter = 0;
    this.onSessionCreated.mockClear();
    this.onSessionExited.mockClear();
  }

  /**
   * Get total number of sessions (including exited ones).
   */
  get sessionCount(): number {
    return this.sessions.size;
  }
}

/**
 * Create a pre-configured mock terminal service instance.
 * Commonly used in test setup.
 */
export function createMockTerminalService(): MockTerminalService {
  return new MockTerminalService();
}
