import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { screen, within, act, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderWithProviders } from "@/test/test-helpers";
import { ApprovalQueue } from "../approval-queue";

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

// Mock fleet-client so no real HTTP calls happen
vi.mock("@/lib/workbench/fleet-client", () => ({
  fleetClient: {
    healthCheck: vi.fn().mockResolvedValue(false),
    fetchApprovals: vi.fn().mockResolvedValue({ requests: [], decisions: [] }),
    resolveApproval: vi.fn().mockResolvedValue({ success: true }),
  },
  loadSavedConnection: vi.fn().mockReturnValue({}),
  loadSavedConnectionAsync: vi.fn().mockResolvedValue({}),
  saveConnectionConfig: vi.fn(),
  clearConnectionConfig: vi.fn(),
  clearCredentials: vi.fn(),
  testConnection: vi.fn().mockResolvedValue({ ok: false }),
  fetchRemotePolicy: vi.fn().mockResolvedValue(null),
  fetchAgentCount: vi.fn().mockResolvedValue(0),
  fetchAgentList: vi.fn().mockResolvedValue([]),
  fetchAuditEvents: vi.fn().mockResolvedValue([]),
  deployPolicy: vi.fn().mockResolvedValue({ success: false }),
  validateRemotely: vi.fn().mockResolvedValue({ valid: false }),
  distributePolicy: vi.fn().mockResolvedValue({ success: false }),
  fetchApprovals: vi.fn().mockResolvedValue({ requests: [], decisions: [] }),
  resolveApproval: vi.fn().mockResolvedValue({ success: true }),
  fetchDelegationGraphFromApi: vi.fn().mockResolvedValue(null),
}));

// Mock use-fleet-connection to provide a disconnected state by default
const mockConnection = {
  connected: false,
  hushdUrl: "",
  controlApiUrl: "",
  apiKey: "",
  controlApiToken: "",
  hushdHealth: null,
  agentCount: 0,
};

vi.mock("@/lib/workbench/use-fleet-connection", async () => {
  const actual = await vi.importActual<typeof import("@/lib/workbench/use-fleet-connection")>(
    "@/lib/workbench/use-fleet-connection",
  );
  return {
    ...actual,
    useFleetConnection: () => ({
      connection: mockConnection,
      isConnecting: false,
      error: null,
      agents: [],
      remotePolicyInfo: null,
      connect: vi.fn(),
      disconnect: vi.fn(),
      testConnection: vi.fn(),
      refreshAgents: vi.fn(),
      refreshRemotePolicy: vi.fn(),
    }),
  };
});

// Mock tauri bridge
vi.mock("@/lib/tauri-bridge", () => ({
  isDesktop: vi.fn(() => false),
  isMacOS: vi.fn(() => false),
}));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function renderQueue() {
  return renderWithProviders(<ApprovalQueue />);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("ApprovalQueue", () => {
  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  // -----------------------------------------------------------------------
  // Rendering
  // -----------------------------------------------------------------------

  it("renders with demo data by default", () => {
    renderQueue();

    // Demo data includes shell_command requests
    expect(screen.getAllByText("shell_command").length).toBeGreaterThan(0);
    // Summary badges should be visible
    expect(screen.getAllByText("Pending").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Approved").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Denied").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Expired").length).toBeGreaterThan(0);
  });

  it("shows demo mode button", () => {
    renderQueue();
    expect(screen.getByText("Demo")).toBeInTheDocument();
  });

  it("renders pending request count badge", () => {
    renderQueue();
    // Demo data has 6 pending requests
    const pendingBadges = screen.getAllByText("6");
    expect(pendingBadges.length).toBeGreaterThan(0);
  });

  // -----------------------------------------------------------------------
  // Filtering
  // -----------------------------------------------------------------------

  it("filters by status", async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    renderQueue();

    // The shadcn Select renders a <button> trigger with role="combobox", not a native <select>.
    // Click the trigger to open the popup, then click the desired option.
    const selects = screen.getAllByRole("combobox");
    const statusSelect = selects[0]; // first select is status filter

    // Open the status filter dropdown
    await user.click(statusSelect);
    // Wait for the popup portal to render options
    const option = await screen.findByRole("option", { name: /denied/i });
    await user.click(option);

    // Should show the denied request (apr-008 from demo data)
    await waitFor(() => {
      expect(screen.getByText("Dependabot Scanner")).toBeInTheDocument();
    });
    // Pending requests should be hidden
    expect(screen.queryByText("Infra Remediation Bot")).not.toBeInTheDocument();
  });

  it("filters by risk level", async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    renderQueue();

    const selects = screen.getAllByRole("combobox");
    const riskSelect = selects[1]; // second select is risk filter

    // Open the risk filter dropdown
    await user.click(riskSelect);
    // Wait for the popup portal to render options
    const option = await screen.findByRole("option", { name: /critical/i });
    await user.click(option);

    // apr-005 is the only critical risk request
    await waitFor(() => {
      expect(screen.getByText("Production Deployer")).toBeInTheDocument();
    });
  });

  it("filters by search query", async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    renderQueue();

    const searchInput = screen.getByPlaceholderText("Search tool, agent, reason...");
    await user.type(searchInput, "kubectl");

    // apr-001 mentions kubectl in reason
    expect(screen.getByText("Infra Remediation Bot")).toBeInTheDocument();
    // Others should be filtered out
    expect(screen.queryByText("NPM Publish Agent")).not.toBeInTheDocument();
  });

  it("shows empty state when no results match", async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    renderQueue();

    const searchInput = screen.getByPlaceholderText("Search tool, agent, reason...");
    await user.type(searchInput, "zzz-nonexistent-query-zzz");

    expect(screen.getByText("No approval requests match your filters.")).toBeInTheDocument();
  });

  // -----------------------------------------------------------------------
  // Approval Actions
  // -----------------------------------------------------------------------

  it("shows approve dropdown with scope presets", async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    renderQueue();

    // Find an Approve button (there will be multiple for pending requests)
    const approveButtons = screen.getAllByText("Approve");
    await user.click(approveButtons[0]);

    // Scope presets should appear
    expect(screen.getByText("Allow Once")).toBeInTheDocument();
    expect(screen.getByText("Allow for Session")).toBeInTheDocument();
    expect(screen.getByText("Allow Always")).toBeInTheDocument();
  });

  it("shows confirm dialog after selecting approval scope", async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    renderQueue();

    // Open approve dropdown
    const approveButtons = screen.getAllByText("Approve");
    await user.click(approveButtons[0]);

    // Select "Allow Once"
    await user.click(screen.getByText("Allow Once"));

    // Confirmation should appear
    expect(screen.getByText("Confirm")).toBeInTheDocument();
    expect(screen.getByText("Cancel")).toBeInTheDocument();
  });

  it("shows deny confirmation with reason input", async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    renderQueue();

    // Click deny on first pending request
    const denyButtons = screen.getAllByText("Deny");
    await user.click(denyButtons[0]);

    // Should show deny confirmation UI
    expect(screen.getByText("Deny this request?")).toBeInTheDocument();
    expect(screen.getByPlaceholderText("Reason (optional)...")).toBeInTheDocument();
    expect(screen.getByText("Confirm")).toBeInTheDocument();
  });

  it("executes approve action and updates status", async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    renderQueue();

    // Open approve dropdown for first pending request
    const approveButtons = screen.getAllByText("Approve");
    await user.click(approveButtons[0]);

    // Select scope
    await user.click(screen.getByText("Allow Once"));

    // Confirm
    await user.click(screen.getByText("Confirm"));

    // The request should now show as approved
    // The pending count should decrease
    const badge5 = screen.getAllByText("5");
    expect(badge5.length).toBeGreaterThan(0);
  });

  it("cancels approval action", async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    renderQueue();

    const approveButtons = screen.getAllByText("Approve");
    await user.click(approveButtons[0]);
    await user.click(screen.getByText("Allow Once"));

    // Cancel instead of confirm
    await user.click(screen.getByText("Cancel"));

    // Should return to normal state with approve/deny buttons
    expect(screen.getAllByText("Approve").length).toBeGreaterThan(0);
  });

  // -----------------------------------------------------------------------
  // Detail Drawer
  // -----------------------------------------------------------------------

  it("opens detail drawer when clicking a request", async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    renderQueue();

    // Click on a request card (click the tool name area)
    await user.click(screen.getByText("Infra Remediation Bot"));

    // Detail drawer should appear
    expect(screen.getByText("Request Details")).toBeInTheDocument();
    expect(screen.getByText("Origin Context")).toBeInTheDocument();
    expect(screen.getByText("Agent Identity")).toBeInTheDocument();
  });

  it("closes detail drawer", async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    renderQueue();

    // Open drawer
    await user.click(screen.getByText("Infra Remediation Bot"));
    expect(screen.getByText("Request Details")).toBeInTheDocument();

    // Close button (IconX)
    const closeButton = screen.getByText("Request Details").parentElement?.querySelector("button");
    if (closeButton) {
      await user.click(closeButton);
    }

    expect(screen.queryByText("Request Details")).not.toBeInTheDocument();
  });

  // -----------------------------------------------------------------------
  // Auto-expire (the bug we fixed)
  // -----------------------------------------------------------------------

  it("does not cause infinite re-render loop (no maximum update depth exceeded)", () => {
    // This is the regression test for the infinite loop bug.
    // If the useEffect dependency array fix is reverted, this will throw
    // "Maximum update depth exceeded" during render.
    expect(() => renderQueue()).not.toThrow();
  });

  it("auto-expires pending requests when their expiry time passes", () => {
    renderQueue();

    // Count initial pending requests
    const initialPending = screen.getAllByText("Approve").length;
    expect(initialPending).toBeGreaterThan(0);

    // Advance time by 30 minutes — should expire some requests
    // apr-005 expires in 3 minutes, apr-006 expires in 10 minutes
    act(() => {
      vi.advanceTimersByTime(30 * 60 * 1000);
    });

    // After advancing time, some requests should have transitioned to expired
    const remainingApprove = screen.queryAllByText("Approve");
    expect(remainingApprove.length).toBeLessThan(initialPending);
  });

  it("does not change already-expired requests on re-render", () => {
    renderQueue();

    // Get the initial expired count badge
    const expiredCount1 = screen.getAllByText("Expired");

    // Advance tick but not enough to expire anything new
    act(() => {
      vi.advanceTimersByTime(1000);
    });

    // Expired label should still be present
    const expiredCount2 = screen.getAllByText("Expired");
    expect(expiredCount2.length).toBe(expiredCount1.length);
  });

  // -----------------------------------------------------------------------
  // Data source toggle
  // -----------------------------------------------------------------------

  it("disables live toggle when fleet is not connected", () => {
    renderQueue();

    // The Demo button should be present but live toggle should be disabled
    const demoButton = screen.getByText("Demo").closest("button");
    expect(demoButton).toBeDisabled();
  });

  // -----------------------------------------------------------------------
  // Countdown formatting
  // -----------------------------------------------------------------------

  it("displays countdown timers for pending requests", () => {
    renderQueue();

    // Pending requests should show time remaining (e.g., "18m", "27m")
    // Look for the clock-formatted text patterns
    const timerElements = document.querySelectorAll("[class*='font-mono']");
    expect(timerElements.length).toBeGreaterThan(0);
  });

  // -----------------------------------------------------------------------
  // Provider badges
  // -----------------------------------------------------------------------

  it("renders provider abbreviation badges", () => {
    renderQueue();

    // Demo data has Slack ("S"), GitHub ("G"), Teams ("T"), etc.
    expect(screen.getAllByText("S").length).toBeGreaterThan(0); // Slack
    expect(screen.getAllByText("G").length).toBeGreaterThan(0); // GitHub
  });

  // -----------------------------------------------------------------------
  // Risk level badges
  // -----------------------------------------------------------------------

  it("renders risk level badges on cards", () => {
    renderQueue();

    expect(screen.getAllByText("High").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Medium").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Critical").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Low").length).toBeGreaterThan(0);
  });

  // -----------------------------------------------------------------------
  // Sort order
  // -----------------------------------------------------------------------

  it("sorts pending requests before resolved ones", () => {
    renderQueue();

    // Get all card elements — use the "group" class that is unique to ApprovalCard wrappers
    // to avoid matching Select trigger buttons that also have "rounded-lg border"
    const cards = document.querySelectorAll("[class*='group relative rounded-lg border']");
    expect(cards.length).toBeGreaterThan(0);

    // First cards should have Approve buttons (pending), last cards should not
    const firstCard = cards[0];
    const lastCard = cards[cards.length - 1];

    expect(within(firstCard as HTMLElement).queryByText("Approve")).toBeInTheDocument();
    expect(within(lastCard as HTMLElement).queryByText("Approve")).not.toBeInTheDocument();
  });
});
