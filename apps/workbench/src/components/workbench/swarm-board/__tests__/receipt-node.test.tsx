import React from "react";
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { SwarmBoardNodeData } from "@/features/swarm/swarm-board-types";

// ---------------------------------------------------------------------------
// Stub component exercising the receipt node contract.
// Replace with real component import when available.
// ---------------------------------------------------------------------------

function ReceiptNode({ data }: { data: SwarmBoardNodeData }) {
  const verdictColorMap: Record<string, string> = {
    allow: "#3dbf84",
    deny: "#ef4444",
    warn: "#d4a84b",
  };

  const verdictColor = data.verdict ? verdictColorMap[data.verdict] ?? "#6f7f9a" : "#6f7f9a";

  // Simulate a truncated signature hash
  const signatureHash = data.verdict
    ? `sha256:${data.verdict.split("").map((c) => c.charCodeAt(0).toString(16)).join("")}...`
    : "";

  return (
    <div data-testid="receipt-node">
      <h3 data-testid="node-title">{data.title}</h3>
      {data.verdict && (
        <span
          data-testid="verdict-badge"
          style={{ backgroundColor: verdictColor }}
        >
          {data.verdict}
        </span>
      )}
      {data.guardResults && data.guardResults.length > 0 && (
        <ul data-testid="guard-results-list">
          {data.guardResults.map((gr, i) => (
            <li
              key={i}
              data-testid="guard-result-item"
              data-allowed={gr.allowed}
            >
              <span data-testid="guard-name">{gr.guard}</span>
              <span data-testid="guard-allowed">{gr.allowed ? "pass" : "fail"}</span>
              {gr.duration_ms !== undefined && (
                <span data-testid="guard-duration">{gr.duration_ms}ms</span>
              )}
            </li>
          ))}
        </ul>
      )}
      {signatureHash && (
        <span data-testid="signature-hash">{signatureHash}</span>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("ReceiptNode", () => {
  describe("verdict badge", () => {
    it("renders allow verdict with green color", () => {
      render(
        <ReceiptNode
          data={{
            title: "File write check",
            status: "completed",
            nodeType: "receipt",
            verdict: "allow",
            guardResults: [],
          }}
        />,
      );

      const badge = screen.getByTestId("verdict-badge");
      expect(badge.textContent).toBe("allow");
      expect(badge.style.backgroundColor).toBe("rgb(61, 191, 132)");
    });

    it("renders deny verdict with red color", () => {
      render(
        <ReceiptNode
          data={{
            title: "Blocked action",
            status: "completed",
            nodeType: "receipt",
            verdict: "deny",
            guardResults: [],
          }}
        />,
      );

      const badge = screen.getByTestId("verdict-badge");
      expect(badge.textContent).toBe("deny");
      expect(badge.style.backgroundColor).toBe("rgb(239, 68, 68)");
    });

    it("renders warn verdict with gold color", () => {
      render(
        <ReceiptNode
          data={{
            title: "Warning check",
            status: "completed",
            nodeType: "receipt",
            verdict: "warn",
            guardResults: [],
          }}
        />,
      );

      const badge = screen.getByTestId("verdict-badge");
      expect(badge.textContent).toBe("warn");
      expect(badge.style.backgroundColor).toBe("rgb(212, 168, 75)");
    });

    it("does not render verdict badge when verdict is undefined", () => {
      render(
        <ReceiptNode
          data={{
            title: "No verdict",
            status: "idle",
            nodeType: "receipt",
          }}
        />,
      );

      expect(screen.queryByTestId("verdict-badge")).toBeNull();
    });
  });

  describe("guard results list", () => {
    it("shows guard results with correct data", () => {
      render(
        <ReceiptNode
          data={{
            title: "Multi-guard check",
            status: "completed",
            nodeType: "receipt",
            verdict: "allow",
            guardResults: [
              { guard: "ForbiddenPathGuard", allowed: true, duration_ms: 2 },
              { guard: "SecretLeakGuard", allowed: true, duration_ms: 8 },
              { guard: "PatchIntegrityGuard", allowed: true, duration_ms: 3 },
            ],
          }}
        />,
      );

      const items = screen.getAllByTestId("guard-result-item");
      expect(items).toHaveLength(3);

      const names = screen.getAllByTestId("guard-name");
      expect(names[0].textContent).toBe("ForbiddenPathGuard");
      expect(names[1].textContent).toBe("SecretLeakGuard");
      expect(names[2].textContent).toBe("PatchIntegrityGuard");

      const allowed = screen.getAllByTestId("guard-allowed");
      expect(allowed[0].textContent).toBe("pass");
      expect(allowed[1].textContent).toBe("pass");
      expect(allowed[2].textContent).toBe("pass");
    });

    it("shows failed guards correctly", () => {
      render(
        <ReceiptNode
          data={{
            title: "Denied check",
            status: "completed",
            nodeType: "receipt",
            verdict: "deny",
            guardResults: [
              { guard: "ForbiddenPathGuard", allowed: false, duration_ms: 1 },
              { guard: "SecretLeakGuard", allowed: true, duration_ms: 5 },
            ],
          }}
        />,
      );

      const items = screen.getAllByTestId("guard-result-item");
      expect(items[0].getAttribute("data-allowed")).toBe("false");
      expect(items[1].getAttribute("data-allowed")).toBe("true");

      const allowed = screen.getAllByTestId("guard-allowed");
      expect(allowed[0].textContent).toBe("fail");
      expect(allowed[1].textContent).toBe("pass");
    });

    it("shows guard durations", () => {
      render(
        <ReceiptNode
          data={{
            title: "Timed check",
            status: "completed",
            nodeType: "receipt",
            verdict: "allow",
            guardResults: [
              { guard: "ShellCommandGuard", allowed: true, duration_ms: 15 },
            ],
          }}
        />,
      );

      expect(screen.getByTestId("guard-duration").textContent).toBe("15ms");
    });

    it("does not render list when guardResults is empty", () => {
      render(
        <ReceiptNode
          data={{
            title: "No guards",
            status: "completed",
            nodeType: "receipt",
            verdict: "allow",
            guardResults: [],
          }}
        />,
      );

      expect(screen.queryByTestId("guard-results-list")).toBeNull();
    });

    it("does not render list when guardResults is undefined", () => {
      render(
        <ReceiptNode
          data={{
            title: "No guards",
            status: "completed",
            nodeType: "receipt",
            verdict: "allow",
          }}
        />,
      );

      expect(screen.queryByTestId("guard-results-list")).toBeNull();
    });
  });

  describe("signature hash", () => {
    it("shows truncated signature hash when verdict exists", () => {
      render(
        <ReceiptNode
          data={{
            title: "Signed receipt",
            status: "completed",
            nodeType: "receipt",
            verdict: "allow",
            guardResults: [],
          }}
        />,
      );

      const hash = screen.getByTestId("signature-hash");
      expect(hash.textContent).toContain("sha256:");
      expect(hash.textContent).toContain("...");
    });

    it("does not show signature hash when verdict is missing", () => {
      render(
        <ReceiptNode
          data={{
            title: "Unsigned",
            status: "idle",
            nodeType: "receipt",
          }}
        />,
      );

      expect(screen.queryByTestId("signature-hash")).toBeNull();
    });
  });

  it("renders node title", () => {
    render(
      <ReceiptNode
        data={{
          title: "Custom Title",
          status: "completed",
          nodeType: "receipt",
          verdict: "allow",
        }}
      />,
    );

    expect(screen.getByTestId("node-title").textContent).toBe("Custom Title");
  });
});
