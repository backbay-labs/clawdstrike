import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  attachEndpointEvidenceArchiveToCase,
  backfillEndpointEvidenceArchivesToControl,
  createFleetCase,
  downloadEndpointEvidenceArchive,
  downloadFleetEvidenceBundle,
  type EndpointEvidenceArchiveDownload,
  type EndpointEvidenceArchiveRecord,
  exportFleetCaseEvidenceBundle,
  fetchEndpointEvidenceArchive,
  fetchFleetCase,
  fetchFleetCases,
  fetchFleetCaseTimeline,
  publishEndpointEvidenceBundleToFleet,
} from "../../api/client";
import { downloadBlob, exportAsJSON } from "../../utils/exportData";
import { EventDetailDrawer } from "./EventDetailDrawer";

vi.mock("../../api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../api/client")>();
  return {
    ...actual,
    attachEndpointEvidenceArchiveToCase: vi.fn(),
    backfillEndpointEvidenceArchivesToControl: vi.fn(),
    createFleetCase: vi.fn(),
    downloadEndpointEvidenceArchive: vi.fn(),
    downloadFleetEvidenceBundle: vi.fn(),
    exportFleetCaseEvidenceBundle: vi.fn(),
    fetchEndpointEvidenceArchive: vi.fn(),
    fetchFleetCase: vi.fn(),
    fetchFleetCases: vi.fn(),
    fetchFleetCaseTimeline: vi.fn(),
    publishEndpointEvidenceBundleToFleet: vi.fn(),
  };
});

vi.mock("../../utils/exportData", () => ({
  downloadBlob: vi.fn(),
  exportAsJSON: vi.fn(),
}));

const archiveRecord: EndpointEvidenceArchiveRecord = {
  archiveId: "evidence_bundle_archive-1",
  archiveHash: "0xarchive",
  rawRef: "endpoint-evidence-bundle-archive:evidence_bundle_archive-1:0xarchive",
  bundleId: "evidence_bundle-1",
  endpointAgentId: "endpoint-agent-1",
  eventId: "evidence-bundle-archive:endpoint-agent-1:evidence_bundle_archive-1",
  contentHash: "0xcontent",
  graphSliceId: "graph_slice-1",
  rawArtifactApprovalId: "approval-archive-1",
  rawArtifactApprovalReasonHash: "0xapprovalreason",
  uploadedAt: "2026-05-16T12:00:00Z",
  expiresAt: "2026-06-15T12:00:00Z",
  retentionDays: 30,
  sizeBytes: 4096,
  verification: { verified: true, receiptFailureCount: 0 },
  metadata: {
    source: "clawdstrike-agent",
    uploadPath: "fleet_publish",
    rawArtifactApprovalId: "approval-archive-1",
    rawArtifactApprovalReasonHash: "0xapprovalreason",
  },
};

const archiveDownload: EndpointEvidenceArchiveDownload = {
  record: archiveRecord,
  archive: {
    bundle: {
      bundleId: "evidence_bundle-1",
      graphSliceId: "graph_slice-1",
      contentHash: "0xcontent",
    },
    receipts: [],
  },
};

describe("EventDetailDrawer", () => {
  beforeEach(() => {
    localStorage.clear();
    vi.mocked(attachEndpointEvidenceArchiveToCase).mockReset();
    vi.mocked(backfillEndpointEvidenceArchivesToControl).mockReset();
    vi.mocked(createFleetCase).mockReset();
    vi.mocked(downloadEndpointEvidenceArchive).mockReset();
    vi.mocked(downloadFleetEvidenceBundle).mockReset();
    vi.mocked(exportFleetCaseEvidenceBundle).mockReset();
    vi.mocked(fetchEndpointEvidenceArchive).mockReset();
    vi.mocked(fetchFleetCase).mockReset();
    vi.mocked(fetchFleetCases).mockReset();
    vi.mocked(fetchFleetCaseTimeline).mockReset();
    vi.mocked(publishEndpointEvidenceBundleToFleet).mockReset();
    vi.mocked(downloadBlob).mockReset();
    vi.mocked(exportAsJSON).mockReset();
  });

  it("surfaces retained endpoint archive metadata in the incident bundle", async () => {
    vi.mocked(fetchEndpointEvidenceArchive).mockResolvedValue(archiveRecord);

    render(
      <EventDetailDrawer
        onClose={() => {}}
        event={
          {
            _id: 7,
            event_type: "hunt_event",
            action_type: "evidence_bundle_archive",
            target: "evidence_bundle-1",
            timestamp: "2026-05-16T12:00:00Z",
            attributes: {
              archiveId: "evidence_bundle_archive-1",
              archiveHash: "0xarchive",
              bundleId: "evidence_bundle-1",
              verification: { verified: true },
            },
            evidence: {
              rawRef: "endpoint-evidence-bundle-archive:evidence_bundle_archive-1:0xarchive",
            },
          } as never
        }
      />,
    );

    expect(screen.getByText("Archive Evidence")).toBeTruthy();
    expect(screen.getByText("evidence_bundle_archive-1")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Attach Archive Evidence" }));

    await waitFor(() => {
      expect(fetchEndpointEvidenceArchive).toHaveBeenCalledWith("evidence_bundle_archive-1");
    });
    expect(await screen.findByText("4096 bytes")).toBeTruthy();
    expect(screen.getByText("verified")).toBeTruthy();
    expect(screen.getByText("approval-archive-1")).toBeTruthy();
    expect(screen.getByText("0xapprovalreason")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Export Bundle" }));
    expect(exportAsJSON).toHaveBeenCalledWith(
      [
        expect.objectContaining({
          endpointEvidenceArchive: archiveRecord,
        }),
      ],
      expect.stringContaining("incident-inc-7-open-"),
    );
  });

  it("surfaces raw archive approval evidence from audit metadata before fetching the archive", () => {
    render(
      <EventDetailDrawer
        onClose={() => {}}
        event={
          {
            id: "audit-archive-approval",
            action_type: "endpoint_evidence_archive.raw_uploaded",
            decision: "allowed",
            target: "evidence_bundle_archive-1",
            timestamp: "2026-05-16T12:00:00Z",
            metadata: {
              archiveId: "evidence_bundle_archive-1",
              archiveHash: "0xarchive",
              rawRef: "endpoint-evidence-bundle-archive:evidence_bundle_archive-1:0xarchive",
              bundleId: "evidence_bundle-1",
              rawArtifactApprovalId: "approval-from-audit",
              rawArtifactApprovalReasonHash: "0xauditapprovalreason",
            },
          } as never
        }
      />,
    );

    expect(screen.getByText("Archive Evidence")).toBeTruthy();
    expect(screen.getByText("approval-from-audit")).toBeTruthy();
    expect(screen.getByText("0xauditapprovalreason")).toBeTruthy();
  });

  it("submits raw archive approval for fleet publish and Control API backfill", async () => {
    vi.mocked(publishEndpointEvidenceBundleToFleet).mockResolvedValue({
      bundleId: "evidence_bundle-1",
      archiveId: "evidence_bundle_archive-1",
      archiveHash: "0xarchive",
      published: true,
      queued: false,
      controlUpload: {
        attempted: true,
        accepted: true,
        rawArtifactUploadAllowed: true,
        rawArtifactApprovalRequired: true,
        rawArtifactApprovalProvided: true,
        rawArtifactApprovalId: "approval-ui-archive-1",
        rawArtifactApprovalReasonHash: "0xapprovalhash",
        policySource: "/tmp/policy.yml",
        retryQueued: false,
      },
      eventId: "evidence-bundle-archive:endpoint-agent-1:evidence_bundle_archive-1",
      rawRef: "endpoint-evidence-bundle-archive:evidence_bundle_archive-1:0xarchive",
    });
    vi.mocked(backfillEndpointEvidenceArchivesToControl).mockResolvedValue({
      attempted: 1,
      delivered: 1,
      failed: 0,
      skipped: 0,
      records: [
        {
          bundleId: "evidence_bundle-1",
          archiveId: "evidence_bundle_archive-1",
          archiveHash: "0xarchive",
          rawRef: "endpoint-evidence-bundle-archive:evidence_bundle_archive-1:0xarchive",
          controlUpload: {
            attempted: true,
            accepted: true,
            rawArtifactUploadAllowed: true,
            rawArtifactApprovalRequired: true,
            rawArtifactApprovalProvided: true,
            rawArtifactApprovalId: "approval-ui-archive-1",
            rawArtifactApprovalReasonHash: "0xapprovalhash",
            policySource: "/tmp/policy.yml",
            retryQueued: false,
          },
        },
      ],
    });

    render(
      <EventDetailDrawer
        onClose={() => {}}
        event={
          {
            _id: 13,
            event_type: "hunt_event",
            action_type: "evidence_bundle_archive",
            target: "evidence_bundle-1",
            timestamp: "2026-05-16T12:00:00Z",
            attributes: {
              archiveId: "evidence_bundle_archive-1",
              archiveHash: "0xarchive",
              bundleId: "evidence_bundle-1",
            },
          } as never
        }
      />,
    );

    fireEvent.change(screen.getByLabelText("Raw archive approval ID"), {
      target: { value: "approval-ui-archive-1" },
    });
    fireEvent.change(screen.getByLabelText("Raw archive approval reason"), {
      target: { value: "incident ir-ui-archive raw archive approved" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Publish Approved Raw Archive" }));

    await waitFor(() => {
      expect(publishEndpointEvidenceBundleToFleet).toHaveBeenCalledWith("evidence_bundle-1", {
        rawArtifactApprovalId: "approval-ui-archive-1",
        rawArtifactApprovalReason: "incident ir-ui-archive raw archive approved",
      });
    });
    expect(
      await screen.findByText("Published archive evidence_bundle_archive-1 accepted"),
    ).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Backfill Approved Archive" }));

    await waitFor(() => {
      expect(backfillEndpointEvidenceArchivesToControl).toHaveBeenCalledWith({
        bundleId: "evidence_bundle-1",
        limit: 1,
        rawArtifactApprovalId: "approval-ui-archive-1",
        rawArtifactApprovalReason: "incident ir-ui-archive raw archive approved",
      });
    });
    expect(await screen.findByText("Backfill delivered 1/1")).toBeTruthy();
  });

  it("exports the retained raw archive for case handoff", async () => {
    vi.mocked(fetchEndpointEvidenceArchive).mockResolvedValue(archiveRecord);
    vi.mocked(downloadEndpointEvidenceArchive).mockResolvedValue(archiveDownload);

    render(
      <EventDetailDrawer
        onClose={() => {}}
        event={
          {
            _id: 8,
            event_type: "hunt_event",
            action_type: "evidence_bundle_archive",
            target: "evidence_bundle-1",
            timestamp: "2026-05-16T12:00:00Z",
            attributes: {
              archiveId: "evidence_bundle_archive-1",
              archiveHash: "0xarchive",
              bundleId: "evidence_bundle-1",
            },
          } as never
        }
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: "Attach Archive Evidence" }));
    await screen.findByText("4096 bytes");

    fireEvent.click(screen.getByRole("button", { name: "Export Raw Archive" }));

    await waitFor(() => {
      expect(downloadEndpointEvidenceArchive).toHaveBeenCalledWith("evidence_bundle_archive-1");
    });
    expect(exportAsJSON).toHaveBeenCalledWith(
      [archiveDownload],
      "endpoint-evidence-archive-evidence_bundle_archive-1",
    );
  });

  it("attaches retained archive metadata to a remote case artifact", async () => {
    vi.mocked(fetchEndpointEvidenceArchive).mockResolvedValue(archiveRecord);
    vi.mocked(attachEndpointEvidenceArchiveToCase).mockResolvedValue({
      id: "artifact-1",
      caseId: "case-123",
      artifactKind: "endpoint_evidence_archive",
      artifactId: "evidence_bundle_archive-1",
      summary: "endpoint evidence archive evidence_bundle-1",
      metadata: {
        artifactClass: "verified_reference",
        sourceTable: "endpoint_evidence_archives",
      },
      addedBy: "operator@example.com",
      addedAt: "2026-05-16T12:01:00Z",
    });

    render(
      <EventDetailDrawer
        onClose={() => {}}
        event={
          {
            _id: 9,
            event_type: "hunt_event",
            action_type: "evidence_bundle_archive",
            target: "evidence_bundle-1",
            timestamp: "2026-05-16T12:00:00Z",
            attributes: {
              archiveId: "evidence_bundle_archive-1",
              archiveHash: "0xarchive",
              bundleId: "evidence_bundle-1",
            },
          } as never
        }
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: "Attach Archive Evidence" }));
    await screen.findByText("4096 bytes");

    fireEvent.change(screen.getByPlaceholderText("Remote case ID"), {
      target: { value: "case-123" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Attach To Case" }));

    await waitFor(() => {
      expect(attachEndpointEvidenceArchiveToCase).toHaveBeenCalledWith(
        "case-123",
        "evidence_bundle_archive-1",
      );
    });
    expect(await screen.findByText("Attached to case case-123")).toBeTruthy();
  });

  it("loads remote cases and attaches the archive to a selected case", async () => {
    vi.mocked(fetchEndpointEvidenceArchive).mockResolvedValue(archiveRecord);
    vi.mocked(fetchFleetCases).mockResolvedValue([
      {
        id: "case-1",
        tenantId: "tenant-1",
        title: "Existing endpoint case",
        severity: "high",
        status: "open",
        createdBy: "operator@example.com",
        principalIds: [],
        detectionIds: [],
        responseActionIds: [],
        grantIds: [],
        tags: ["endpoint-evidence"],
        metadata: {},
        createdAt: "2026-05-16T12:00:00Z",
        updatedAt: "2026-05-16T12:00:00Z",
      },
    ]);
    vi.mocked(attachEndpointEvidenceArchiveToCase).mockResolvedValue({
      id: "artifact-1",
      caseId: "case-1",
      artifactKind: "endpoint_evidence_archive",
      artifactId: "evidence_bundle_archive-1",
      summary: "endpoint evidence archive evidence_bundle-1",
      metadata: {
        artifactClass: "verified_reference",
        sourceTable: "endpoint_evidence_archives",
      },
      addedBy: "operator@example.com",
      addedAt: "2026-05-16T12:01:00Z",
    });

    render(
      <EventDetailDrawer
        onClose={() => {}}
        event={
          {
            _id: 10,
            event_type: "hunt_event",
            action_type: "evidence_bundle_archive",
            target: "evidence_bundle-1",
            timestamp: "2026-05-16T12:00:00Z",
            attributes: {
              archiveId: "evidence_bundle_archive-1",
              archiveHash: "0xarchive",
              bundleId: "evidence_bundle-1",
            },
          } as never
        }
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: "Attach Archive Evidence" }));
    await screen.findByText("4096 bytes");

    fireEvent.click(screen.getByRole("button", { name: "Load Cases" }));
    await screen.findByText("Existing endpoint case");

    fireEvent.change(screen.getByLabelText("Remote case"), {
      target: { value: "case-1" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Attach To Case" }));

    await waitFor(() => {
      expect(attachEndpointEvidenceArchiveToCase).toHaveBeenCalledWith(
        "case-1",
        "evidence_bundle_archive-1",
      );
    });
  });

  it("creates a remote case from retained archive metadata and attaches the archive", async () => {
    vi.mocked(fetchEndpointEvidenceArchive).mockResolvedValue(archiveRecord);
    vi.mocked(createFleetCase).mockResolvedValue({
      id: "case-created",
      tenantId: "tenant-1",
      title: "Endpoint evidence archive evidence_bundle-1",
      severity: "high",
      status: "open",
      createdBy: "operator@example.com",
      principalIds: [],
      detectionIds: [],
      responseActionIds: [],
      grantIds: [],
      tags: ["endpoint-evidence", "case-handoff"],
      metadata: { archiveId: "evidence_bundle_archive-1" },
      createdAt: "2026-05-16T12:00:00Z",
      updatedAt: "2026-05-16T12:00:00Z",
    });
    vi.mocked(attachEndpointEvidenceArchiveToCase).mockResolvedValue({
      id: "artifact-created",
      caseId: "case-created",
      artifactKind: "endpoint_evidence_archive",
      artifactId: "evidence_bundle_archive-1",
      summary: "endpoint evidence archive evidence_bundle-1",
      metadata: {
        artifactClass: "verified_reference",
        sourceTable: "endpoint_evidence_archives",
      },
      addedBy: "operator@example.com",
      addedAt: "2026-05-16T12:01:00Z",
    });

    render(
      <EventDetailDrawer
        onClose={() => {}}
        event={
          {
            _id: 11,
            event_type: "hunt_event",
            action_type: "evidence_bundle_archive",
            target: "evidence_bundle-1",
            timestamp: "2026-05-16T12:00:00Z",
            attributes: {
              archiveId: "evidence_bundle_archive-1",
              archiveHash: "0xarchive",
              bundleId: "evidence_bundle-1",
            },
            evidence: {
              rawRef: "endpoint-evidence-bundle-archive:evidence_bundle_archive-1:0xarchive",
            },
          } as never
        }
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: "Attach Archive Evidence" }));
    await screen.findByText("4096 bytes");

    fireEvent.click(screen.getByRole("button", { name: "Create Case" }));

    await waitFor(() => {
      expect(createFleetCase).toHaveBeenCalledWith({
        title: "Endpoint evidence archive evidence_bundle-1",
        summary: "Remote case created from retained endpoint archive evidence_bundle_archive-1",
        severity: "high",
        tags: ["endpoint-evidence", "case-handoff"],
        metadata: {
          archiveId: "evidence_bundle_archive-1",
          archiveHash: "0xarchive",
          bundleId: "evidence_bundle-1",
          rawRef: "endpoint-evidence-bundle-archive:evidence_bundle_archive-1:0xarchive",
          endpointAgentId: "endpoint-agent-1",
          rawArtifactApprovalId: "approval-archive-1",
          rawArtifactApprovalReasonHash: "0xapprovalreason",
        },
      });
    });
    expect(attachEndpointEvidenceArchiveToCase).toHaveBeenCalledWith(
      "case-created",
      "evidence_bundle_archive-1",
    );
    expect(await screen.findByText("Attached to case case-created")).toBeTruthy();
  });

  it("loads selected remote case detail, timeline, and requests a case bundle export", async () => {
    vi.mocked(fetchEndpointEvidenceArchive).mockResolvedValue(archiveRecord);
    vi.mocked(fetchFleetCase).mockResolvedValue({
      case: {
        id: "case-123",
        tenantId: "tenant-1",
        title: "Existing endpoint case",
        severity: "high",
        status: "open",
        createdBy: "operator@example.com",
        principalIds: [],
        detectionIds: [],
        responseActionIds: [],
        grantIds: [],
        tags: ["endpoint-evidence"],
        metadata: {},
        createdAt: "2026-05-16T12:00:00Z",
        updatedAt: "2026-05-16T12:00:00Z",
      },
      artifacts: [
        {
          id: "artifact-1",
          caseId: "case-123",
          artifactKind: "endpoint_evidence_archive",
          artifactId: "evidence_bundle_archive-1",
          summary: "endpoint evidence archive evidence_bundle-1",
          metadata: {},
          addedBy: "operator@example.com",
          addedAt: "2026-05-16T12:01:00Z",
        },
      ],
      evidenceBundles: [],
    });
    vi.mocked(fetchFleetCaseTimeline).mockResolvedValue([
      {
        id: "timeline-1",
        caseId: "case-123",
        eventKind: "artifact_added",
        actorId: "operator@example.com",
        payload: { artifactKind: "endpoint_evidence_archive" },
        createdAt: "2026-05-16T12:01:00Z",
      },
    ]);
    vi.mocked(exportFleetCaseEvidenceBundle).mockResolvedValue({
      exportId: "caseexp-1",
      tenantId: "tenant-1",
      caseId: "case-123",
      status: "completed",
      requestedBy: "operator@example.com",
      requestedAt: "2026-05-16T12:02:00Z",
      retentionDays: 30,
      filters: {},
      artifactCounts: { endpoint_evidence_archive: 1 },
      metadata: { manifestRef: "manifest.json" },
    });

    render(
      <EventDetailDrawer
        onClose={() => {}}
        event={
          {
            _id: 12,
            event_type: "hunt_event",
            action_type: "evidence_bundle_archive",
            target: "evidence_bundle-1",
            timestamp: "2026-05-16T12:00:00Z",
            attributes: {
              archiveId: "evidence_bundle_archive-1",
              archiveHash: "0xarchive",
              bundleId: "evidence_bundle-1",
            },
          } as never
        }
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: "Attach Archive Evidence" }));
    await screen.findByText("4096 bytes");

    fireEvent.change(screen.getByPlaceholderText("Remote case ID"), {
      target: { value: "case-123" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Load Case" }));

    await waitFor(() => {
      expect(fetchFleetCase).toHaveBeenCalledWith("case-123");
      expect(fetchFleetCaseTimeline).toHaveBeenCalledWith("case-123");
    });
    expect(await screen.findByText("Existing endpoint case")).toBeTruthy();
    expect(screen.getByText("artifact_added")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Export Case Bundle" }));

    await waitFor(() => {
      expect(exportFleetCaseEvidenceBundle).toHaveBeenCalledWith("case-123", {
        includeRawEnvelopes: true,
      });
    });
    expect(await screen.findByText("Export caseexp-1 completed")).toBeTruthy();

    const bundle = new Blob(["zip"], { type: "application/zip" });
    vi.mocked(downloadFleetEvidenceBundle).mockResolvedValue(bundle);

    fireEvent.click(screen.getByRole("button", { name: "Download Case Bundle" }));

    await waitFor(() => {
      expect(downloadFleetEvidenceBundle).toHaveBeenCalledWith("caseexp-1");
    });
    expect(downloadBlob).toHaveBeenCalledWith(bundle, "caseexp-1.zip");
  });
});
