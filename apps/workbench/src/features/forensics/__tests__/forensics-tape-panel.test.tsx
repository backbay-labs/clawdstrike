// apps/workbench/src/features/forensics/__tests__/forensics-tape-panel.test.tsx
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { ForensicsTapePanel } from "../components/ForensicsTapePanel";
import type { TapeEvent, TapeEventKind } from "../types";

describe("ForensicsTapePanel", () => {
  it("renders without crash", () => {
    const { container } = render(<ForensicsTapePanel />);
    expect(container.firstChild).not.toBeNull();
  });

  it("renders 4 mock event cards", () => {
    const { getAllByRole } = render(<ForensicsTapePanel />);
    const cards = getAllByRole("article");
    expect(cards).toHaveLength(4);
  });

  it("shows footer deferred notice text", () => {
    render(<ForensicsTapePanel />);
    expect(screen.getByText(/forensics tape.*mock data/i)).toBeTruthy();
  });

  it("each event card shows the event label text", () => {
    render(<ForensicsTapePanel />);
    expect(screen.getByText("file_read /etc/hosts")).toBeTruthy();
    expect(screen.getByText("shell_exec rm -rf")).toBeTruthy();
    expect(screen.getByText("Ed25519 signed")).toBeTruthy();
    expect(screen.getByText("station:run scanned")).toBeTruthy();
  });

  it("TapeEvent type includes id, timestamp, kind, and label fields", () => {
    // Compile-time type check via construction — if this type-checks, the interface is correct
    const event: TapeEvent = {
      id: "test-1",
      timestamp: Date.now(),
      kind: "allow" as TapeEventKind,
      label: "test event",
    };
    expect(event.id).toBe("test-1");
    expect(event.kind).toBe("allow");
  });
});
