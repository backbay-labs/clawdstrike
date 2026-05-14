/**
 * PluginAuditViewer Tests
 *
 * Tests for the plugin audit viewer component that displays plugin action
 * receipts in a filterable table with visual distinction for denied receipts.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { PluginActionReceipt } from "@/lib/plugins/bridge/receipt-types";

// ---- Mock receipt store ----

const mockClear = vi.fn();
const mockQueryReceipts = vi.fn();
let mockReceipts: PluginActionReceipt[] = [];

vi.mock("@/lib/plugins/bridge/receipt-store", () => ({
  usePluginReceipts: () => ({
    receipts: mockReceipts,
    clearReceipts: mockClear,
    queryReceipts: mockQueryReceipts,
    addReceipt: vi.fn(),
  }),
}));

import { PluginAuditViewer } from "../plugin-audit-viewer";

// ---- Test Helpers ----

function makeReceipt(overrides?: {
  pluginId?: string;
  actionType?: string;
  result?: "allowed" | "denied" | "error";
  permissionChecked?: string;
  durationMs?: number;
  timestamp?: string;
}): PluginActionReceipt {
  return {
    content: {
      version: "1.0.0",
      receipt_id: crypto.randomUUID(),
      timestamp: overrides?.timestamp ?? "2026-03-19T12:00:00.000Z",
      plugin: {
        id: overrides?.pluginId ?? "plugin-a",
        version: "1.0.0",
        publisher: "pub",
        trust_tier: "community",
      },
      action: {
        type: overrides?.actionType ?? "guards.register",
        params_hash: "a".repeat(64),
        result: overrides?.result ?? "allowed",
        permission_checked: overrides?.permissionChecked ?? "guards:register",
        duration_ms: overrides?.durationMs ?? 10,
      },
    },
    signature: "sig-hex",
    signer_public_key: "pub-hex",
  };
}

// ---- Tests ----

describe("PluginAuditViewer", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockReceipts = [];
  });

  it("shows empty state when no receipts exist", () => {
    render(<PluginAuditViewer />);

    expect(screen.getByText("No plugin audit receipts")).toBeTruthy();
  });

  it("renders a table with correct column headers", () => {
    mockReceipts = [makeReceipt()];
    render(<PluginAuditViewer />);

    expect(screen.getByText("Time")).toBeTruthy();
    expect(screen.getByText("Plugin")).toBeTruthy();
    expect(screen.getByText("Action")).toBeTruthy();
    expect(screen.getByText("Result")).toBeTruthy();
    expect(screen.getByText("Permission")).toBeTruthy();
    expect(screen.getByText("Duration")).toBeTruthy();
  });

  it("renders 3 rows when store has 3 receipts", () => {
    mockReceipts = [
      makeReceipt({ pluginId: "p1" }),
      makeReceipt({ pluginId: "p2" }),
      makeReceipt({ pluginId: "p3" }),
    ];
    render(<PluginAuditViewer />);

    const tbody = screen.getByRole("table").querySelector("tbody");
    expect(tbody).toBeTruthy();
    const rows = within(tbody!).getAllByRole("row");
    expect(rows).toHaveLength(3);
  });

  it("displays receipt data in each row", () => {
    mockReceipts = [
      makeReceipt({
        pluginId: "my-plugin",
        actionType: "storage.set",
        result: "allowed",
        permissionChecked: "storage:set",
        durationMs: 42,
      }),
    ];
    render(<PluginAuditViewer />);

    expect(screen.getByText("my-plugin")).toBeTruthy();
    expect(screen.getByText("storage.set")).toBeTruthy();
    expect(screen.getByText("allowed")).toBeTruthy();
    expect(screen.getByText("storage:set")).toBeTruthy();
    expect(screen.getByText("42ms")).toBeTruthy();
  });

  it("applies red styling class to denied receipts", () => {
    mockReceipts = [makeReceipt({ result: "denied" })];
    render(<PluginAuditViewer />);

    const deniedCell = screen.getByText("denied");
    expect(deniedCell.className).toMatch(/text-red|red/);
  });

  it("applies amber styling class to error receipts", () => {
    mockReceipts = [makeReceipt({ result: "error" })];
    render(<PluginAuditViewer />);

    const errorCell = screen.getByText("error");
    expect(errorCell.className).toMatch(/text-amber|amber/);
  });

  it("applies green styling class to allowed receipts", () => {
    mockReceipts = [makeReceipt({ result: "allowed" })];
    render(<PluginAuditViewer />);

    const allowedCell = screen.getByText("allowed");
    expect(allowedCell.className).toMatch(/text-green|green/);
  });

  it("filters rows by plugin ID when plugin filter is typed", async () => {
    const user = userEvent.setup();
    mockReceipts = [
      makeReceipt({ pluginId: "alpha-plugin" }),
      makeReceipt({ pluginId: "beta-plugin" }),
      makeReceipt({ pluginId: "alpha-plugin" }),
    ];
    render(<PluginAuditViewer />);

    const pluginInput = screen.getByPlaceholderText("Filter by plugin...");
    await user.type(pluginInput, "alpha");

    const tbody = screen.getByRole("table").querySelector("tbody");
    const rows = within(tbody!).getAllByRole("row");
    expect(rows).toHaveLength(2);
    expect(screen.queryByText("beta-plugin")).toBeNull();
  });

  it("filters rows by action type when action filter is typed", async () => {
    const user = userEvent.setup();
    mockReceipts = [
      makeReceipt({ actionType: "guards.register" }),
      makeReceipt({ actionType: "storage.set" }),
      makeReceipt({ actionType: "guards.register" }),
    ];
    render(<PluginAuditViewer />);

    const actionInput = screen.getByPlaceholderText("Filter by action...");
    await user.type(actionInput, "storage");

    const tbody = screen.getByRole("table").querySelector("tbody");
    const rows = within(tbody!).getAllByRole("row");
    expect(rows).toHaveLength(1);
  });

  it("filters rows by result when result filter is selected", async () => {
    const user = userEvent.setup();
    mockReceipts = [
      makeReceipt({ result: "allowed" }),
      makeReceipt({ result: "denied" }),
      makeReceipt({ result: "allowed" }),
    ];
    render(<PluginAuditViewer />);

    const resultSelect = screen.getByRole("combobox");
    await user.selectOptions(resultSelect, "denied");

    const tbody = screen.getByRole("table").querySelector("tbody");
    const rows = within(tbody!).getAllByRole("row");
    expect(rows).toHaveLength(1);
  });

  it("calls clear function when Clear button is clicked", async () => {
    const user = userEvent.setup();
    mockReceipts = [makeReceipt()];
    render(<PluginAuditViewer />);

    const clearButton = screen.getByRole("button", { name: /clear/i });
    await user.click(clearButton);

    expect(mockClear).toHaveBeenCalledTimes(1);
  });

  it("shows empty state when all receipts are filtered out", async () => {
    const user = userEvent.setup();
    mockReceipts = [makeReceipt({ pluginId: "alpha" })];
    render(<PluginAuditViewer />);

    const pluginInput = screen.getByPlaceholderText("Filter by plugin...");
    await user.type(pluginInput, "nonexistent");

    expect(screen.getByText("No plugin audit receipts")).toBeTruthy();
  });
});
