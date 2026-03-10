import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { App } from "../App";

// Mock tauri bridge
vi.mock("@/lib/tauri-bridge", () => ({
  isDesktop: vi.fn(() => false),
  isMacOS: vi.fn(() => false),
  minimizeWindow: vi.fn(),
  maximizeWindow: vi.fn(),
  closeWindow: vi.fn(),
}));

// Mock page components to avoid pulling in heavy dependency trees.
// Each mock renders a simple div with a data-testid for identification.
vi.mock("@/components/workbench/home/home-page", () => ({
  HomePage: () => <div data-testid="page-home">HomePage</div>,
}));

vi.mock("@/components/workbench/editor/policy-editor", () => ({
  PolicyEditor: () => <div data-testid="page-editor">PolicyEditor</div>,
}));

vi.mock("@/components/workbench/simulator/simulator-layout", () => ({
  SimulatorLayout: () => <div data-testid="page-simulator">SimulatorLayout</div>,
}));

vi.mock("@/components/workbench/compare/compare-layout", () => ({
  CompareLayout: () => <div data-testid="page-compare">CompareLayout</div>,
}));

vi.mock("@/components/workbench/compliance/compliance-dashboard", () => ({
  ComplianceDashboard: () => <div data-testid="page-compliance">ComplianceDashboard</div>,
}));

vi.mock("@/components/workbench/receipts/receipt-inspector", () => ({
  ReceiptInspector: () => <div data-testid="page-receipts">ReceiptInspector</div>,
}));

vi.mock("@/components/workbench/library/library-gallery", () => ({
  LibraryGallery: () => <div data-testid="page-library">LibraryGallery</div>,
}));

vi.mock("@/components/workbench/settings/settings-page", () => ({
  SettingsPage: () => <div data-testid="page-settings">SettingsPage</div>,
}));

vi.mock("@/components/workbench/delegation/delegation-page", () => ({
  DelegationPage: () => <div data-testid="page-delegation">DelegationPage</div>,
}));

vi.mock("@/components/workbench/approvals/approval-queue", () => ({
  ApprovalQueue: () => <div data-testid="page-approvals">ApprovalQueue</div>,
}));

vi.mock("@/components/workbench/hierarchy/hierarchy-page", () => ({
  HierarchyPage: () => <div data-testid="page-hierarchy">HierarchyPage</div>,
}));

vi.mock("@/components/workbench/fleet/fleet-dashboard", () => ({
  FleetDashboard: () => <div data-testid="page-fleet">FleetDashboard</div>,
}));

vi.mock("@/components/workbench/audit/audit-log", () => ({
  AuditLog: () => <div data-testid="page-audit">AuditLog</div>,
}));

afterEach(() => {
  window.location.hash = "";
});

describe("App", () => {
  it("renders the desktop layout shell", () => {
    render(<App />);

    // Brand should be visible in the titlebar (split into two spans)
    expect(screen.getByText("Clawdstrike")).toBeInTheDocument();
    expect(screen.getByText("Workbench")).toBeInTheDocument();
  });

  it("default route redirects to /home", async () => {
    render(<App />);

    // The HashRouter starts at #/ which should redirect to /home
    await waitFor(() => {
      expect(screen.getByTestId("page-home")).toBeInTheDocument();
    });
  });

  it("renders the editor route", async () => {
    // HashRouter uses window.location.hash, set it before render
    window.location.hash = "#/editor";
    render(<App />);

    await waitFor(() => {
      expect(screen.getByTestId("page-editor")).toBeInTheDocument();
    });
  });

  it("renders the simulator route", async () => {
    window.location.hash = "#/simulator";
    render(<App />);

    await waitFor(() => {
      expect(screen.getByTestId("page-simulator")).toBeInTheDocument();
    });
  });

  it("renders the compare route", async () => {
    window.location.hash = "#/compare";
    render(<App />);

    await waitFor(() => {
      expect(screen.getByTestId("page-compare")).toBeInTheDocument();
    });
  });

  it("renders the compliance route", async () => {
    window.location.hash = "#/compliance";
    render(<App />);

    await waitFor(() => {
      expect(screen.getByTestId("page-compliance")).toBeInTheDocument();
    });
  });

  it("renders the receipts route", async () => {
    window.location.hash = "#/receipts";
    render(<App />);

    await waitFor(() => {
      expect(screen.getByTestId("page-receipts")).toBeInTheDocument();
    });
  });

  it("renders the library route", async () => {
    window.location.hash = "#/library";
    render(<App />);

    await waitFor(() => {
      expect(screen.getByTestId("page-library")).toBeInTheDocument();
    });
  });

  it("redirects unknown routes to /home", async () => {
    window.location.hash = "#/nonexistent-route";
    render(<App />);

    await waitFor(() => {
      expect(screen.getByTestId("page-home")).toBeInTheDocument();
    });
  });

  it("wraps routes in WorkbenchProvider (sidebar can read context)", async () => {
    render(<App />);

    // If WorkbenchProvider is missing, the sidebar would throw.
    // The sidebar nav items prove the context is available.
    await waitFor(() => {
      expect(screen.getByText("Editor")).toBeInTheDocument();
      expect(screen.getByText("Threat Lab")).toBeInTheDocument();
    });
  });
});
