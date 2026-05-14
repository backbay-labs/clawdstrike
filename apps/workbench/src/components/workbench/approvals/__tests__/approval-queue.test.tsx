import "@testing-library/jest-dom/vitest";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { screen, within, act, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderWithProviders } from "@/test/test-helpers";
import { fleetClient } from "@/features/fleet/fleet-client";
import { ApprovalQueue } from "../approval-queue";


// Mock fleet-client so no real HTTP calls happen
vi.mock("@/features/fleet/fleet-client", () => ({
  fleetClient: {
    healthCheck: vi.fn().mockResolvedValue(false),
    fetchApprovals: vi.fn().mockResolvedValue({ requests: [], decisions: [] }),
    resolveApproval: vi.fn().mockResolvedValue({ success: true }),
  },
  redactFleetConnection: vi.fn((conn: Record<string, unknown>) => {
    const { apiKey: _, controlApiToken: __, ...info } = conn;
    return info;
  }),
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
  fetchDelegationGraphFromApi: vi.fn().mockResolvedValue(null),
}));

// Mock use-fleet-connection to provide a disconnected state by default
const mockConnection = {
  connected: false,
  hushdUrl: "",
  controlApiUrl: "",
  hushdHealth: null,
  agentCount: 0,
};

const mockCredentials = {
  apiKey: "",
  controlApiToken: "",
};

vi.mock("@/features/fleet/use-fleet-connection", async () => {
  const actual = await vi.importActual<typeof import("@/features/fleet/use-fleet-connection")>(
    "@/features/fleet/use-fleet-connection",
  );
  return {
    ...actual,
    useFleetConnection: () => ({
      connection: mockConnection,
      isConnecting: false,
      error: null,
      pollError: null,
      secureStorageWarning: false,
      agents: [],
      remotePolicyInfo: null,
      connect: vi.fn(),
      disconnect: vi.fn(),
      testConnection: vi.fn(),
      refreshAgents: vi.fn(),
      refreshRemotePolicy: vi.fn(),
      getCredentials: () => mockCredentials,
      getAuthenticatedConnection: () => ({ ...mockConnection, ...mockCredentials }),
    }),
  };
});

// Mock tauri bridge
vi.mock("@/lib/tauri-bridge", () => ({
  isDesktop: vi.fn(() => false),
  isMacOS: vi.fn(() => false),
}));


function renderQueue() {
  return renderWithProviders(<ApprovalQueue />);
}

function expectPresent(node: unknown) {
  expect(node).not.toBeNull();
  expect(node).not.toBeUndefined();
}

function expectAbsent(node: unknown) {
  expect(node).toBeNull();
}

function expectDisabled(node: Element | null) {
  expect(node).not.toBeNull();
  expect((node as HTMLButtonElement).disabled).toBe(true);
}

function expectEnabled(node: Element | null) {
  expect(node).not.toBeNull();
  expect((node as HTMLButtonElement).disabled).toBe(false);
}


describe("ApprovalQueue", () => {
  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    vi.clearAllMocks();
    mockConnection.connected = false;
    mockConnection.hushdUrl = "";
    mockConnection.controlApiUrl = "";
    mockConnection.hushdHealth = null;
    mockConnection.agentCount = 0;
    mockCredentials.apiKey = "";
    mockCredentials.controlApiToken = "";
  });

  afterEach(() => {
    vi.useRealTimers();
  });


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
    expectPresent(screen.getByText("Demo"));
  });

  it("renders pending request count badge", () => {
    renderQueue();
    // Demo data has 6 pending requests
    const pendingBadges = screen.getAllByText("6");
    expect(pendingBadges.length).toBeGreaterThan(0);
  });


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
      expectPresent(screen.getByText("Dependabot Scanner"));
    });
    // Pending requests should be hidden
    expectAbsent(screen.queryByText("Infra Remediation Bot"));
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
      expectPresent(screen.getByText("Production Deployer"));
    });
  });

  it("filters by search query", async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    renderQueue();

    const searchInput = screen.getByPlaceholderText("Search tool, agent, reason...");
    await user.type(searchInput, "kubectl");

    // apr-001 mentions kubectl in reason
    expectPresent(screen.getByText("Infra Remediation Bot"));
    // Others should be filtered out
    expectAbsent(screen.queryByText("NPM Publish Agent"));
  });

  it("shows empty state when no results match", async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    renderQueue();

    const searchInput = screen.getByPlaceholderText("Search tool, agent, reason...");
    await user.type(searchInput, "zzz-nonexistent-query-zzz");

    expectPresent(screen.getByText("No approval requests match your filters."));
  });


  it("shows approve dropdown with scope presets", async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    renderQueue();

    // Find an Approve button (there will be multiple for pending requests)
    const approveButtons = screen.getAllByText("Approve");
    await user.click(approveButtons[0]);

    // Scope presets should appear
    expectPresent(screen.getByText("Allow Once"));
    expectPresent(screen.getByText("Allow for Session"));
    expectPresent(screen.getByText("Allow Always"));
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
    expectPresent(screen.getByText("Confirm"));
    expectPresent(screen.getByText("Cancel"));
  });

  it("shows deny confirmation with reason input", async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    renderQueue();

    // Click deny on first pending request
    const denyButtons = screen.getAllByText("Deny");
    await user.click(denyButtons[0]);

    // Should show deny confirmation UI
    expectPresent(screen.getByText("Deny this request?"));
    expectPresent(screen.getByPlaceholderText("Reason (optional)..."));
    expectPresent(screen.getByText("Confirm"));
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


  it("opens detail drawer when clicking a request", async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    renderQueue();

    // Click on a request card (click the tool name area)
    await user.click(screen.getByText("Infra Remediation Bot"));

    // Detail drawer should appear
    expectPresent(screen.getByText("Request Details"));
    expectPresent(screen.getByText("Origin Context"));
    expectPresent(screen.getByText("Agent Identity"));
  });

  it("closes detail drawer", async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    renderQueue();

    // Open drawer
    await user.click(screen.getByText("Infra Remediation Bot"));
    expectPresent(screen.getByText("Request Details"));

    // Close button (IconX)
    const closeButton = screen.getByText("Request Details").parentElement?.querySelector("button");
    if (closeButton) {
      await user.click(closeButton);
    }

    expectAbsent(screen.queryByText("Request Details"));
  });


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


  it("disables live toggle when fleet is not connected", () => {
    renderQueue();

    // The Demo button should be present but live toggle should be disabled
    const demoButton = screen.getByText("Demo").closest("button");
    expectDisabled(demoButton);
  });

  it("explains that control-api is required for live approvals", () => {
    mockConnection.connected = true;
    mockConnection.hushdUrl = "http://localhost:9876";

    renderQueue();

    expectPresent(screen.getByText("Configure control-api in Settings to view live approvals"));
    expectDisabled(screen.getByText("Demo").closest("button"));
  });

  it("enables live approvals when control-api is configured", () => {
    mockConnection.connected = true;
    mockConnection.hushdUrl = "http://localhost:9876";
    mockConnection.controlApiUrl = "http://localhost:8090";

    renderQueue();

    expectEnabled(screen.getByText("Demo").closest("button"));
  });

  it("does not fetch live approvals when control-api is missing", () => {
    mockConnection.connected = true;
    mockConnection.hushdUrl = "http://localhost:9876";

    renderQueue();

    expect(vi.mocked(fleetClient.fetchApprovals)).not.toHaveBeenCalled();
  });


  it("displays countdown timers for pending requests", () => {
    renderQueue();

    // Pending requests should show time remaining (e.g., "18m", "27m")
    // Look for the clock-formatted text patterns
    const timerElements = document.querySelectorAll("[class*='font-mono']");
    expect(timerElements.length).toBeGreaterThan(0);
  });


  it("renders provider abbreviation badges", () => {
    renderQueue();

    // Demo data has Slack ("S"), GitHub ("G"), Teams ("T"), etc.
    expect(screen.getAllByText("S").length).toBeGreaterThan(0); // Slack
    expect(screen.getAllByText("G").length).toBeGreaterThan(0); // GitHub
  });


  it("renders risk level badges on cards", () => {
    renderQueue();

    expect(screen.getAllByText("High").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Medium").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Critical").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Low").length).toBeGreaterThan(0);
  });


  it("sorts pending requests before resolved ones", () => {
    renderQueue();

    // Get all card elements — use the "group" class that is unique to ApprovalCard wrappers
    // to avoid matching Select trigger buttons that also have "rounded-lg border"
    const cards = document.querySelectorAll("[class*='group relative rounded-lg border']");
    expect(cards.length).toBeGreaterThan(0);

    // First cards should have Approve buttons (pending), last cards should not
    const firstCard = cards[0];
    const lastCard = cards[cards.length - 1];

    expectPresent(within(firstCard as HTMLElement).queryByText("Approve"));
    expectAbsent(within(lastCard as HTMLElement).queryByText("Approve"));
  });
});
