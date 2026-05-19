import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  bulkUpdateFleetCaseStatus,
  createFleetCase,
  downloadFleetEvidenceBundle,
  exportFleetCaseEvidenceBundle,
  fetchFleetCase,
  fetchFleetCases,
  fetchFleetCaseTimeline,
  updateFleetCase,
  type CaseTimelineEvent,
  type FleetCase,
  type FleetCaseDetail,
  type FleetEvidenceBundle,
} from "../api/client";
import { downloadBlob } from "../utils/exportData";
import { FleetCases } from "./FleetCases";

vi.mock("../api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api/client")>();
  return {
    ...actual,
    createFleetCase: vi.fn(),
    bulkUpdateFleetCaseStatus: vi.fn(),
    downloadFleetEvidenceBundle: vi.fn(),
    exportFleetCaseEvidenceBundle: vi.fn(),
    fetchFleetCase: vi.fn(),
    fetchFleetCases: vi.fn(),
    fetchFleetCaseTimeline: vi.fn(),
    updateFleetCase: vi.fn(),
  };
});

vi.mock("../utils/exportData", () => ({
  downloadBlob: vi.fn(),
}));

const existingCase: FleetCase = {
  id: "case-1",
  tenantId: "tenant-1",
  title: "Endpoint archive case",
  summary: "Retained archive investigation",
  severity: "high",
  status: "open",
  createdBy: "operator@example.com",
  principalIds: ["principal-1"],
  detectionIds: [],
  responseActionIds: [],
  grantIds: [],
  tags: ["endpoint-evidence"],
  metadata: { archiveId: "archive-1" },
  createdAt: "2026-05-16T12:00:00Z",
  updatedAt: "2026-05-16T12:05:00Z",
};

const existingDetail: FleetCaseDetail = {
  case: existingCase,
  artifacts: [
    {
      id: "artifact-1",
      caseId: "case-1",
      artifactKind: "endpoint_evidence_archive",
      artifactId: "archive-1",
      summary: "endpoint evidence archive evidence_bundle-1",
      metadata: { archiveHash: "0xarchive", verification: { verified: true } },
      addedBy: "operator@example.com",
      addedAt: "2026-05-16T12:01:00Z",
    },
  ],
  evidenceBundles: [],
};

const existingTimeline: CaseTimelineEvent[] = [
  {
    id: "timeline-1",
    caseId: "case-1",
    eventKind: "artifact_added",
    actorId: "operator@example.com",
    payload: { artifactKind: "endpoint_evidence_archive" },
    createdAt: "2026-05-16T12:01:00Z",
  },
];

const exportedBundle: FleetEvidenceBundle = {
  exportId: "caseexp-1",
  tenantId: "tenant-1",
  caseId: "case-1",
  status: "completed",
  requestedBy: "operator@example.com",
  requestedAt: "2026-05-16T12:02:00Z",
  completedAt: "2026-05-16T12:03:00Z",
  sha256: "0xbundle",
  sizeBytes: 2048,
  retentionDays: 30,
  filters: {},
  artifactCounts: { endpoint_evidence_archive: 1 },
  metadata: {},
};

describe("FleetCases", () => {
  beforeEach(() => {
    vi.mocked(bulkUpdateFleetCaseStatus).mockReset();
    vi.mocked(createFleetCase).mockReset();
    vi.mocked(downloadFleetEvidenceBundle).mockReset();
    vi.mocked(exportFleetCaseEvidenceBundle).mockReset();
    vi.mocked(fetchFleetCase).mockReset();
    vi.mocked(fetchFleetCases).mockReset();
    vi.mocked(fetchFleetCaseTimeline).mockReset();
    vi.mocked(updateFleetCase).mockReset();
    vi.mocked(downloadBlob).mockReset();
  });

  it("loads cases, shows selected evidence, and exports a signed case bundle", async () => {
    vi.mocked(fetchFleetCases).mockResolvedValue([existingCase]);
    vi.mocked(fetchFleetCase).mockResolvedValue(existingDetail);
    vi.mocked(fetchFleetCaseTimeline).mockResolvedValue(existingTimeline);
    vi.mocked(exportFleetCaseEvidenceBundle).mockResolvedValue(exportedBundle);
    vi.mocked(updateFleetCase).mockResolvedValue({ ...existingCase, status: "closed" });
    const bundleBlob = new Blob(["zip"], { type: "application/zip" });
    vi.mocked(downloadFleetEvidenceBundle).mockResolvedValue(bundleBlob);

    render(<FleetCases />);

    expect((await screen.findAllByText("Endpoint archive case")).length).toBeGreaterThan(0);
    await waitFor(() => {
      expect(fetchFleetCase).toHaveBeenCalledWith("case-1");
      expect(fetchFleetCaseTimeline).toHaveBeenCalledWith("case-1");
    });
    expect(await screen.findByText("endpoint_evidence_archive")).toBeTruthy();
    expect(screen.getByText("artifact_added")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Export Bundle" }));

    await waitFor(() => {
      expect(exportFleetCaseEvidenceBundle).toHaveBeenCalledWith("case-1", {
        includeRawEnvelopes: true,
      });
    });
    expect(await screen.findByText("caseexp-1")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Download Bundle" }));

    await waitFor(() => {
      expect(downloadFleetEvidenceBundle).toHaveBeenCalledWith("caseexp-1");
    });
    expect(downloadBlob).toHaveBeenCalledWith(bundleBlob, "caseexp-1.zip");

    fireEvent.change(screen.getByLabelText("Case status"), {
      target: { value: "closed" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save Status" }));

    await waitFor(() => {
      expect(updateFleetCase).toHaveBeenCalledWith("case-1", { status: "closed" });
    });
    expect((await screen.findAllByText("closed")).length).toBeGreaterThan(0);
  });

  it("creates a remote case and selects it for detail loading", async () => {
    const createdCase: FleetCase = {
      ...existingCase,
      id: "case-new",
      title: "New investigation",
      summary: "Operator-created case",
      severity: "critical",
      tags: ["case-management"],
    };
    vi.mocked(fetchFleetCases).mockResolvedValue([]);
    vi.mocked(createFleetCase).mockResolvedValue(createdCase);
    vi.mocked(fetchFleetCase).mockResolvedValue({
      case: createdCase,
      artifacts: [],
      evidenceBundles: [],
    });
    vi.mocked(fetchFleetCaseTimeline).mockResolvedValue([]);

    render(<FleetCases />);

    expect(await screen.findByText("No cases loaded")).toBeTruthy();

    fireEvent.change(screen.getByLabelText("Case title"), {
      target: { value: "New investigation" },
    });
    fireEvent.change(screen.getByLabelText("Case summary"), {
      target: { value: "Operator-created case" },
    });
    fireEvent.change(screen.getByLabelText("Severity"), {
      target: { value: "critical" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Create Case" }));

    await waitFor(() => {
      expect(createFleetCase).toHaveBeenCalledWith({
        title: "New investigation",
        summary: "Operator-created case",
        severity: "critical",
        tags: ["case-management"],
        metadata: { source: "control-console" },
      });
    });
    await waitFor(() => {
      expect(fetchFleetCase).toHaveBeenCalledWith("case-new");
    });
    expect((await screen.findAllByText("case-new")).length).toBeGreaterThan(0);
  });

  it("filters loaded cases by search text, status, and severity", async () => {
    vi.mocked(fetchFleetCases).mockResolvedValue([
      existingCase,
      {
        ...existingCase,
        id: "case-closed",
        title: "Closed phishing investigation",
        severity: "low",
        status: "closed",
        tags: ["phishing"],
      },
    ]);
    vi.mocked(fetchFleetCase).mockResolvedValue(existingDetail);
    vi.mocked(fetchFleetCaseTimeline).mockResolvedValue(existingTimeline);

    render(<FleetCases />);

    expect(await screen.findByRole("button", { name: /Endpoint archive case/ })).toBeTruthy();
    expect(screen.getByRole("button", { name: /Closed phishing investigation/ })).toBeTruthy();

    fireEvent.change(screen.getByLabelText("Case search"), {
      target: { value: "phishing" },
    });
    fireEvent.change(screen.getByLabelText("Case status filter"), {
      target: { value: "closed" },
    });
    fireEvent.change(screen.getByLabelText("Case severity filter"), {
      target: { value: "low" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Refresh Cases" }));

    await waitFor(() => {
      expect(fetchFleetCases).toHaveBeenLastCalledWith({
        query: "phishing",
        status: "closed",
        severity: "low",
      });
    });

    expect(screen.queryByRole("button", { name: /Endpoint archive case/ })).toBeNull();
    expect(screen.getByRole("button", { name: /Closed phishing investigation/ })).toBeTruthy();
  });

  it("bulk updates selected case statuses", async () => {
    const secondaryCase: FleetCase = {
      ...existingCase,
      id: "case-2",
      title: "Secondary investigation",
      status: "in_progress",
      severity: "medium",
    };
    vi.mocked(fetchFleetCases).mockResolvedValue([existingCase, secondaryCase]);
    vi.mocked(fetchFleetCase).mockResolvedValue(existingDetail);
    vi.mocked(fetchFleetCaseTimeline).mockResolvedValue(existingTimeline);
    vi.mocked(bulkUpdateFleetCaseStatus).mockResolvedValue([
      { ...existingCase, status: "closed" },
      { ...secondaryCase, status: "closed" },
    ]);

    render(<FleetCases />);

    fireEvent.click(await screen.findByLabelText("Select case Endpoint archive case"));
    fireEvent.click(screen.getByLabelText("Select case Secondary investigation"));
    fireEvent.change(screen.getByLabelText("Bulk case status"), {
      target: { value: "closed" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Apply Bulk Status" }));

    await waitFor(() => {
      expect(bulkUpdateFleetCaseStatus).toHaveBeenCalledWith(["case-1", "case-2"], "closed");
    });
    expect((await screen.findAllByText("closed")).length).toBeGreaterThan(1);
  });
});
