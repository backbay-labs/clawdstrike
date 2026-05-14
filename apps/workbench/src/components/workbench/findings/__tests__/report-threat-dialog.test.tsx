import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { ReportThreatDialog } from "../report-threat-dialog";
import type { Finding, ExtractedIoc } from "@/lib/workbench/finding-engine";

// ---- Mock threat-reporting module ----

vi.mock("@/lib/workbench/threat-reporting", () => ({
  reportToAbuseIPDB: vi.fn().mockResolvedValue({ success: true }),
  reportToMisp: vi.fn().mockResolvedValue({ success: true }),
}));

// ---- Fixtures ----

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "fnd_test1",
    title: "Test finding",
    status: "emerging",
    severity: "high",
    confidence: 0.8,
    signalIds: ["sig_1"],
    signalCount: 1,
    scope: {
      agentIds: ["agent_1"],
      sessionIds: ["sess_1"],
      timeRange: { start: "2026-01-01T00:00:00Z", end: "2026-01-01T01:00:00Z" },
    },
    timeline: [],
    enrichments: [],
    annotations: [],
    verdict: null,
    actions: [],
    promotedToIntel: null,
    receipt: null,
    speakeasyId: null,
    createdBy: "test",
    updatedBy: "test",
    createdAt: Date.now(),
    updatedAt: Date.now(),
    ...overrides,
  };
}

function makeIndicators(): ExtractedIoc[] {
  return [
    { indicator: "1.2.3.4", iocType: "ip", source: "test" },
    { indicator: "evil.com", iocType: "domain", source: "test" },
  ];
}

// ---- Tests ----

describe("ReportThreatDialog", () => {
  const defaultProps = {
    open: true,
    onClose: vi.fn(),
    finding: makeFinding(),
    indicators: makeIndicators(),
    getApiKey: vi.fn().mockResolvedValue("test-api-key"),
  };

  describe("ARIA accessibility", () => {
    it("dialog has role='dialog' and aria-modal='true'", () => {
      render(<ReportThreatDialog {...defaultProps} />);

      const dialog = screen.getByRole("dialog");
      expect(dialog).toBeInTheDocument();
      expect(dialog).toHaveAttribute("aria-modal", "true");
    });

    it("dialog has aria-labelledby pointing to the title", () => {
      render(<ReportThreatDialog {...defaultProps} />);

      const dialog = screen.getByRole("dialog");
      expect(dialog).toHaveAttribute("aria-labelledby", "report-dialog-title");

      // The referenced element should exist and contain the title text
      const title = document.getElementById("report-dialog-title");
      expect(title).not.toBeNull();
      expect(title!.textContent).toContain("Report Threat");
    });

    it("pressing Escape calls onClose", () => {
      const onClose = vi.fn();
      render(<ReportThreatDialog {...defaultProps} onClose={onClose} />);

      // The dialog's container div listens for keydown Escape
      const dialogContainer = screen.getByRole("dialog").parentElement!;
      fireEvent.keyDown(dialogContainer, { key: "Escape" });

      expect(onClose).toHaveBeenCalledTimes(1);
    });

    it("clicking the overlay calls onClose", () => {
      const onClose = vi.fn();
      render(<ReportThreatDialog {...defaultProps} onClose={onClose} />);

      // The overlay has aria-hidden="true"
      const overlay = document.querySelector("[aria-hidden='true']");
      expect(overlay).not.toBeNull();

      fireEvent.click(overlay!);
      expect(onClose).toHaveBeenCalledTimes(1);
    });

    it("clicking the X close button calls onClose", () => {
      const onClose = vi.fn();
      render(<ReportThreatDialog {...defaultProps} onClose={onClose} />);

      // Find the close button in the header -- it's the button near the title
      const dialog = screen.getByRole("dialog");
      const buttons = dialog.querySelectorAll("button");
      // The first button in the header area is the X/close button
      const closeButton = buttons[0];
      fireEvent.click(closeButton);

      expect(onClose).toHaveBeenCalledTimes(1);
    });
  });

  describe("dialog visibility", () => {
    it("renders nothing when open is false", () => {
      const { container } = render(
        <ReportThreatDialog {...defaultProps} open={false} />,
      );

      expect(container.innerHTML).toBe("");
    });

    it("renders the dialog when open is true", () => {
      render(<ReportThreatDialog {...defaultProps} />);

      expect(screen.getByRole("dialog")).toBeInTheDocument();
      expect(screen.getByText("Report Threat")).toBeInTheDocument();
    });
  });
});

describe("ReportThreatDialog structural (source-level)", () => {
  it("report-threat-dialog.tsx source uses role='dialog' and aria-modal='true'", async () => {
    const fs = await import("fs");
    const path = await import("path");

    const source = fs.readFileSync(
      path.resolve(
        import.meta.dirname,
        "../report-threat-dialog.tsx",
      ),
      "utf-8",
    );

    expect(source).toContain('role="dialog"');
    expect(source).toContain('aria-modal="true"');
    expect(source).toContain('aria-labelledby=');
    expect(source).toMatch(/onKeyDown.*Escape.*onClose/s);
  });
});
