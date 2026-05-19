import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  type CreatePrivacyReportResponse,
  createPrivacyReport,
  type EndpointTelemetryPrivacyMode,
} from "../api/client";
import { exportAsJSON } from "../utils/exportData";
import { PrivacyReport } from "./PrivacyReport";

vi.mock("../api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api/client")>();
  return {
    ...actual,
    createPrivacyReport: vi.fn(),
  };
});

vi.mock("../utils/exportData", () => ({
  exportAsJSON: vi.fn(),
}));

const privacyPayload: CreatePrivacyReportResponse = {
  report: {
    reportId: "privacy-1",
    privacyMode: "hashes_features",
    rawArtifactUploadPermitted: false,
    observationCount: 1,
    fieldCount: 3,
    hashOnlyCount: 1,
    metadataOnlyCount: 1,
    redactedCount: 0,
    rawSuppressedCount: 2,
    localOnlyCount: 2,
    observations: [
      {
        observationId: "obs-1",
        eventKind: "file_access",
        fieldCount: 3,
        rawSuppressedCount: 2,
        localOnlyCount: 2,
        projections: [
          {
            fieldPath: "event.fileAccess.contentPreview",
            redactionClass: "local_only",
            valueHash: "0xabc123",
            reason: "raw artifact remains local",
          },
          {
            fieldPath: "process.commandLine",
            redactionClass: "hash_only",
            valueHash: "0xdef456",
            featureValue: "python3 * --token *",
            reason: "command line hashed",
          },
        ],
      },
    ],
  },
  privacy_policy: {
    requestedPrivacyMode: "raw_artifact_permitted",
    effectivePrivacyMode: "hashes_features",
    rawArtifactUploadRequested: true,
    rawArtifactUploadAllowed: false,
    rawArtifactApprovalRequired: false,
    rawArtifactApprovalProvided: true,
    policySource: "/tmp/policy.yml",
    deniedReason: "raw_artifact_permitted was requested",
  },
  receipt: {
    receipt: {
      metadata: {
        endpointDecision: {
          receiptFamily: "privacy_report",
          decision: { findingId: "privacy-1" },
        },
      },
    },
  },
};

describe("PrivacyReport", () => {
  beforeEach(() => {
    vi.mocked(createPrivacyReport).mockReset();
    vi.mocked(exportAsJSON).mockReset();
  });

  it("surfaces redacted and raw-suppressed evidence from signed privacy reports", async () => {
    vi.mocked(createPrivacyReport).mockResolvedValue(privacyPayload);

    render(<PrivacyReport />);

    fireEvent.change(screen.getByLabelText("Privacy Mode"), {
      target: { value: "raw_artifact_permitted" satisfies EndpointTelemetryPrivacyMode },
    });
    fireEvent.change(screen.getByLabelText("Raw Artifact Approval ID"), {
      target: { value: "approval-privacy-1" },
    });
    fireEvent.change(screen.getByLabelText("Raw Artifact Approval Reason"), {
      target: { value: "incident ir-privacy-1 raw collection approved" },
    });
    fireEvent.change(screen.getByLabelText("Observations JSON"), {
      target: {
        value: JSON.stringify([
          {
            observationId: "obs-1",
            event: { fileAccess: { contentPreview: "raw customer token" } },
          },
        ]),
      },
    });
    fireEvent.click(screen.getByRole("button", { name: "Generate Report" }));

    await waitFor(() => {
      expect(createPrivacyReport).toHaveBeenCalledWith({
        privacyMode: "raw_artifact_permitted",
        rawArtifactApprovalId: "approval-privacy-1",
        rawArtifactApprovalReason: "incident ir-privacy-1 raw collection approved",
        observations: [
          {
            observationId: "obs-1",
            event: { fileAccess: { contentPreview: "raw customer token" } },
          },
        ],
      });
    });
    expect(await screen.findByText("privacy-1")).toBeTruthy();
    expect(screen.getByText("Effective mode: hashes_features")).toBeTruthy();
    expect(screen.getByText("Raw policy: blocked")).toBeTruthy();
    expect(screen.getByText("Approval: provided")).toBeTruthy();
    expect(screen.getByText("Raw suppressed")).toBeTruthy();
    expect(screen.getAllByText("2").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("event.fileAccess.contentPreview")).toBeTruthy();
    expect(screen.getByText("LOCAL ONLY")).toBeTruthy();
    expect(screen.getByText("process.commandLine")).toBeTruthy();
    expect(screen.getByText("HASH ONLY")).toBeTruthy();
    expect(screen.getByText("privacy_report")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Export Report" }));
    expect(exportAsJSON).toHaveBeenCalledWith([privacyPayload], "privacy-report-privacy-1");
  });

  it("distinguishes every privacy projection redaction state", async () => {
    const projectionStates: CreatePrivacyReportResponse = {
      ...privacyPayload,
      report: {
        ...privacyPayload.report,
        reportId: "privacy-states",
        redactedCount: 1,
        rawSuppressedCount: 2,
        localOnlyCount: 1,
        observations: [
          {
            observationId: "obs-states",
            eventKind: "process_event",
            fieldCount: 5,
            rawSuppressedCount: 2,
            localOnlyCount: 1,
            projections: [
              {
                fieldPath: "event.secret.preview",
                redactionClass: "redacted",
                valueHash: "0xredacted",
                reason: "raw value removed by policy",
              },
              {
                fieldPath: "event.file.contents",
                redactionClass: "local_only",
                valueHash: "0xlocal",
                reason: "raw file remains on endpoint",
              },
              {
                fieldPath: "process.commandLine",
                redactionClass: "hash_only",
                valueHash: "0xhash",
                featureValue: "python3 *",
                reason: "command line hashed",
              },
              {
                fieldPath: "process.pid",
                redactionClass: "metadata_only",
                featureValue: "pid-present",
                reason: "metadata allowed",
              },
              {
                fieldPath: "event.raw.allowed",
                redactionClass: "raw_artifact_permitted",
                rawValue: "allowed-secret",
                reason: "raw artifact policy allowed",
              },
            ],
          },
        ],
      },
    };
    vi.mocked(createPrivacyReport).mockResolvedValue(projectionStates);

    render(<PrivacyReport />);
    fireEvent.click(screen.getByRole("button", { name: "Generate Report" }));

    expect(await screen.findByText("REDACTED")).toBeTruthy();
    expect(screen.getByText("LOCAL ONLY")).toBeTruthy();
    expect(screen.getByText("HASH ONLY")).toBeTruthy();
    expect(screen.getByText("METADATA")).toBeTruthy();
    expect(screen.getByText("RAW PERMITTED")).toBeTruthy();
    expect(screen.getByText("raw:allowed-secret")).toBeTruthy();
  });
});
