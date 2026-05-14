import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { EvidencePackPanel } from "../evidence-pack-panel";
import type { EvidencePack, EvidenceDatasetKind } from "@/lib/workbench/detection-workflow/shared-types";
import { createEmptyDatasets } from "@/lib/workbench/detection-workflow/shared-types";
import type { ImportResult } from "@/lib/workbench/detection-workflow/use-evidence-packs";

// ---- Mock the hook ----

const mockCreatePack = vi.fn();
const mockDeletePack = vi.fn();
const mockSelectPack = vi.fn();
const mockRemoveItem = vi.fn();
const mockReclassifyItem = vi.fn();
const mockImportPack = vi.fn();
const mockExportPack = vi.fn();

let mockPacks: EvidencePack[] = [];
let mockLoading = false;
let mockSelectedPackId: string | null = null;

vi.mock("@/lib/workbench/detection-workflow/use-evidence-packs", () => ({
  useEvidencePacks: () => ({
    packs: mockPacks,
    loading: mockLoading,
    selectedPackId: mockSelectedPackId,
    selectPack: mockSelectPack,
    createPack: mockCreatePack,
    deletePack: mockDeletePack,
    addItem: vi.fn(),
    removeItem: mockRemoveItem,
    reclassifyItem: mockReclassifyItem,
    importPack: mockImportPack,
    exportPack: mockExportPack,
  }),
}));

function makePack(overrides: Partial<EvidencePack> = {}): EvidencePack {
  return {
    id: crypto.randomUUID(),
    documentId: "doc-1",
    fileType: "clawdstrike_policy",
    title: "Test Pack",
    createdAt: new Date().toISOString(),
    datasets: createEmptyDatasets(),
    redactionState: "clean",
    ...overrides,
  };
}

describe("EvidencePackPanel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockPacks = [];
    mockLoading = false;
    mockSelectedPackId = null;
  });

  it("renders empty state when no packs exist", () => {
    render(<EvidencePackPanel documentId="doc-1" fileType="sigma_rule" />);

    expect(screen.getByText("No evidence packs yet")).toBeInTheDocument();
  });

  it("renders message when no documentId provided", () => {
    render(<EvidencePackPanel documentId={undefined} fileType={undefined} />);

    expect(
      screen.getByText("Open a detection document to view evidence packs"),
    ).toBeInTheDocument();
  });

  it("displays pack list with correct metadata", () => {
    const pack1 = makePack({
      title: "Alpha Pack",
      datasets: {
        ...createEmptyDatasets(),
        positive: [
          {
            id: "item-1",
            kind: "structured_event",
            format: "json",
            payload: { test: true },
            expected: "match",
          },
        ],
        negative: [
          {
            id: "item-2",
            kind: "structured_event",
            format: "json",
            payload: { test: false },
            expected: "no_match",
          },
        ],
      },
      redactionState: "clean",
    });

    const pack2 = makePack({
      title: "Beta Pack",
      redactionState: "redacted",
    });

    mockPacks = [pack1, pack2];

    render(<EvidencePackPanel documentId="doc-1" fileType="sigma_rule" />);

    expect(screen.getByText("Alpha Pack")).toBeInTheDocument();
    expect(screen.getByText("Beta Pack")).toBeInTheDocument();
    // Check redaction badges
    expect(screen.getByText("Clean")).toBeInTheDocument();
    expect(screen.getByText("Redacted")).toBeInTheDocument();
  });

  it("create pack button calls createPack", async () => {
    const user = userEvent.setup();
    render(<EvidencePackPanel documentId="doc-1" fileType="sigma_rule" />);

    const createBtn = screen.getByText("New Pack");
    await user.click(createBtn);

    expect(mockCreatePack).toHaveBeenCalledTimes(1);
  });

  it("delete pack shows confirmation", async () => {
    const user = userEvent.setup();
    const pack = makePack({ title: "To Delete" });
    mockPacks = [pack];
    mockSelectedPackId = pack.id;

    render(<EvidencePackPanel documentId="doc-1" fileType="sigma_rule" />);

    // Click on the pack to expand it
    await user.click(screen.getByText("To Delete"));

    // Find and click Delete button
    const deleteBtn = screen.getByText("Delete");
    await user.click(deleteBtn);

    // Confirmation should appear
    expect(screen.getByText("Delete?")).toBeInTheDocument();
    expect(screen.getByTestId("confirm-delete")).toBeInTheDocument();

    // Confirm deletion
    await user.click(screen.getByTestId("confirm-delete"));
    expect(mockDeletePack).toHaveBeenCalledWith(pack.id);
  });

  it("import validates size limits via the hook", async () => {
    const user = userEvent.setup();
    mockImportPack.mockResolvedValue({
      imported: 1,
      failed: [{ index: 1, reason: "payload exceeds 65536 bytes" }],
    } satisfies ImportResult);

    render(<EvidencePackPanel documentId="doc-1" fileType="sigma_rule" />);

    const importBtn = screen.getByText("Import");
    await user.click(importBtn);

    // Simulate selecting a file via the hidden input
    const fileInput = screen.getByTestId("import-file-input") as HTMLInputElement;
    const file = new File(['{"title":"test","datasets":{}}'], "test.json", {
      type: "application/json",
    });

    await user.upload(fileInput, file);

    expect(mockImportPack).toHaveBeenCalledWith(file);
  });

  it("export triggers exportPack for the selected pack", async () => {
    const user = userEvent.setup();
    const pack = makePack({ title: "Export Me" });
    mockPacks = [pack];
    mockSelectedPackId = pack.id;

    render(<EvidencePackPanel documentId="doc-1" fileType="sigma_rule" />);

    // Click to expand the pack
    await user.click(screen.getByText("Export Me"));

    // Click Export JSON
    const exportBtn = screen.getByText("Export JSON");
    await user.click(exportBtn);

    expect(mockExportPack).toHaveBeenCalledWith(pack.id);
  });

  it("shows loading skeleton when loading", () => {
    mockLoading = true;

    const { container } = render(<EvidencePackPanel documentId="doc-1" fileType="sigma_rule" />);

    // Should show skeleton placeholders (animate-pulse divs)
    const skeletons = container.querySelectorAll(".animate-pulse");
    expect(skeletons.length).toBeGreaterThan(0);
  });

  it("displays the count badge in header", () => {
    mockPacks = [
      makePack({ title: "Pack 1" }),
      makePack({ title: "Pack 2" }),
      makePack({ title: "Pack 3" }),
    ];

    render(<EvidencePackPanel documentId="doc-1" fileType="sigma_rule" />);

    // The header should show "3"
    expect(screen.getByText("3")).toBeInTheDocument();
  });
});
