import { useMemo, useState } from "react";
import {
  type CreatePrivacyReportResponse,
  createPrivacyReport,
  type EndpointTelemetryFieldProjection,
  type EndpointTelemetryPrivacyMode,
  type SignedReceiptJson,
} from "../api/client";
import { GlassButton, NoiseGrain, Plate } from "../components/ui";
import { exportAsJSON } from "../utils/exportData";

const DEFAULT_OBSERVATIONS = `[
  {
    "observationId": "obs-local-1",
    "process": {
      "image": "/usr/local/bin/python3",
      "commandLine": "python3 exfil.py --token raw-secret"
    },
    "event": {
      "fileAccess": {
        "operation": "read",
        "path": "/Users/alice/Work/customer-secret.txt",
        "contentPreview": "raw customer token material"
      }
    }
  }
]`;

const PRIVACY_MODES: EndpointTelemetryPrivacyMode[] = [
  "hashes_features",
  "summary_with_receipts",
  "local_only",
  "raw_artifact_permitted",
];

export function PrivacyReport(_props: { windowId?: string }) {
  const [privacyMode, setPrivacyMode] = useState<EndpointTelemetryPrivacyMode>("hashes_features");
  const [rawArtifactApprovalId, setRawArtifactApprovalId] = useState("");
  const [rawArtifactApprovalReason, setRawArtifactApprovalReason] = useState("");
  const [observationsJson, setObservationsJson] = useState(DEFAULT_OBSERVATIONS);
  const [report, setReport] = useState<CreatePrivacyReportResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const receiptFamily = useMemo(() => receiptFamilyText(report?.receipt), [report]);
  const projections = useMemo(() => flattenProjections(report), [report]);

  async function generateReport() {
    let observations: Record<string, unknown>[];
    try {
      const parsed = JSON.parse(observationsJson) as unknown;
      observations = Array.isArray(parsed)
        ? parsed.filter((item): item is Record<string, unknown> => isRecord(item))
        : [];
      if (observations.length === 0) {
        throw new Error("Observations JSON must be a non-empty array");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Invalid observations JSON");
      return;
    }

    setLoading(true);
    try {
      const approvalId = rawArtifactApprovalId.trim();
      const approvalReason = rawArtifactApprovalReason.trim();
      const response = await createPrivacyReport({
        privacyMode,
        observations,
        ...(privacyMode === "raw_artifact_permitted" && approvalId
          ? { rawArtifactApprovalId: approvalId }
          : {}),
        ...(privacyMode === "raw_artifact_permitted" && approvalReason
          ? { rawArtifactApprovalReason: approvalReason }
          : {}),
      });
      setReport(response);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to generate privacy report");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div
      className="space-y-5"
      style={{ padding: 20, color: "var(--text)", overflow: "auto", height: "100%" }}
    >
      <header className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <p
            className="font-mono"
            style={{
              color: "rgba(214,177,90,0.72)",
              fontSize: "0.68rem",
              letterSpacing: "0.16em",
              textTransform: "uppercase",
            }}
          >
            Local telemetry privacy
          </p>
          <h1
            className="font-display"
            style={{ fontSize: "1.85rem", fontWeight: 700, letterSpacing: 0, marginTop: 2 }}
          >
            Privacy Report
          </h1>
        </div>

        <div className="flex flex-wrap gap-2">
          <GlassButton variant="primary" onClick={generateReport} disabled={loading}>
            {loading ? "Generating..." : "Generate Report"}
          </GlassButton>
          <GlassButton
            onClick={() =>
              report &&
              exportAsJSON([report], `privacy-report-${safeFilenameId(report.report.reportId)}`)
            }
            disabled={!report}
          >
            Export Report
          </GlassButton>
        </div>
      </header>

      {error && <StatusBanner message={error} />}

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-[minmax(360px,0.85fr)_minmax(0,1.15fr)]">
        <Plate className="p-4">
          <PanelTitle eyebrow="Input" title="Observation Projection" />
          <div className="mt-4 space-y-3">
            <label className="flex flex-col gap-1">
              <span className="font-mono uppercase tracking-[0.12em] text-[0.65rem] text-[rgba(154,167,181,0.62)]">
                Privacy Mode
              </span>
              <select
                value={privacyMode}
                onChange={(event) =>
                  setPrivacyMode(event.target.value as EndpointTelemetryPrivacyMode)
                }
                className="glass-input font-mono rounded-md px-3 py-2 text-sm outline-none"
                style={{ color: "var(--text)", background: "rgba(7,8,10,0.72)" }}
              >
                {PRIVACY_MODES.map((mode) => (
                  <option key={mode} value={mode}>
                    {mode}
                  </option>
                ))}
              </select>
            </label>

            {privacyMode === "raw_artifact_permitted" && (
              <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
                <label className="flex flex-col gap-1">
                  <span className="font-mono uppercase tracking-[0.12em] text-[0.65rem] text-[rgba(154,167,181,0.62)]">
                    Raw Artifact Approval ID
                  </span>
                  <input
                    value={rawArtifactApprovalId}
                    onChange={(event) => setRawArtifactApprovalId(event.target.value)}
                    className="glass-input font-mono rounded-md px-3 py-2 text-sm outline-none"
                    style={{ color: "var(--text)", background: "rgba(7,8,10,0.72)" }}
                  />
                </label>

                <label className="flex flex-col gap-1">
                  <span className="font-mono uppercase tracking-[0.12em] text-[0.65rem] text-[rgba(154,167,181,0.62)]">
                    Raw Artifact Approval Reason
                  </span>
                  <input
                    value={rawArtifactApprovalReason}
                    onChange={(event) => setRawArtifactApprovalReason(event.target.value)}
                    className="glass-input font-mono rounded-md px-3 py-2 text-sm outline-none"
                    style={{ color: "var(--text)", background: "rgba(7,8,10,0.72)" }}
                  />
                </label>
              </div>
            )}

            <label className="flex flex-col gap-1">
              <span className="font-mono uppercase tracking-[0.12em] text-[0.65rem] text-[rgba(154,167,181,0.62)]">
                Observations JSON
              </span>
              <textarea
                value={observationsJson}
                onChange={(event) => setObservationsJson(event.target.value)}
                className="glass-input font-mono min-h-[360px] rounded-md px-3 py-2 text-xs outline-none"
                spellCheck={false}
                style={{
                  color: "var(--text)",
                  resize: "vertical",
                  lineHeight: 1.55,
                  background: "rgba(7,8,10,0.72)",
                }}
              />
            </label>
          </div>
        </Plate>

        <section className="space-y-5">
          <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
            <PrivacyMetric label="Report" value={report?.report.reportId ?? "-"} mono />
            <PrivacyMetric
              label="Raw suppressed"
              value={numberText(report?.report.rawSuppressedCount)}
            />
            <PrivacyMetric label="Local only" value={numberText(report?.report.localOnlyCount)} />
          </div>

          <Plate className="p-4" goldEdge>
            <PanelTitle eyebrow="Policy" title={report?.privacy_policy.policySource ?? "-"} />
            <div className="mt-4 grid grid-cols-1 gap-3 lg:grid-cols-2">
              <SmallFact
                label="Requested"
                value={report?.privacy_policy.requestedPrivacyMode ?? "-"}
              />
              <SmallFact
                label="Effective"
                value={
                  report ? `Effective mode: ${report.privacy_policy.effectivePrivacyMode}` : "-"
                }
              />
              <SmallFact
                label="Raw policy"
                value={
                  report
                    ? `Raw policy: ${
                        report.privacy_policy.rawArtifactUploadAllowed ? "allowed" : "blocked"
                      }`
                    : "-"
                }
              />
              <SmallFact
                label="Approval"
                value={
                  report
                    ? `Approval: ${
                        report.privacy_policy.rawArtifactApprovalProvided ? "provided" : "missing"
                      }${report.privacy_policy.rawArtifactApprovalRequired ? " (required)" : ""}`
                    : "-"
                }
              />
              <SmallFact
                label="Approval ID"
                value={report?.privacy_policy.rawArtifactApprovalId ?? "-"}
              />
              <SmallFact
                label="Approval reason"
                value={shortHash(report?.privacy_policy.rawArtifactApprovalReasonHash)}
              />
              <SmallFact label="Receipt" value={receiptFamily ?? "-"} />
            </div>
            {report?.privacy_policy.deniedReason && (
              <p
                className="font-mono mt-4 rounded-md px-3 py-2"
                style={{
                  border: "1px solid rgba(194,59,59,0.32)",
                  background: "rgba(194,59,59,0.08)",
                  color: "var(--crimson)",
                  fontSize: "0.7rem",
                }}
              >
                {report.privacy_policy.deniedReason}
              </p>
            )}
          </Plate>

          <Plate className="p-4">
            <PanelTitle eyebrow="Evidence" title="Field Projections" />
            <div className="mt-4 space-y-2">
              {projections.length === 0 ? (
                <EmptyState text="No privacy projections" />
              ) : (
                projections.map((projection) => (
                  <ProjectionRow
                    key={`${projection.observationId}:${projection.field.fieldPath}`}
                    observationId={projection.observationId}
                    field={projection.field}
                  />
                ))
              )}
            </div>
          </Plate>
        </section>
      </div>
    </div>
  );
}

function PanelTitle({ eyebrow, title }: { eyebrow: string; title: string }) {
  return (
    <div style={{ position: "relative" }}>
      <p
        className="font-mono"
        style={{
          color: "rgba(214,177,90,0.66)",
          fontSize: "0.62rem",
          letterSpacing: "0.14em",
          textTransform: "uppercase",
        }}
      >
        {eyebrow}
      </p>
      <h2
        className="font-display mt-1"
        style={{ color: "var(--text)", fontSize: "1.05rem", fontWeight: 700 }}
      >
        {title}
      </h2>
    </div>
  );
}

function PrivacyMetric({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <Plate className="p-4">
      <p
        className="font-mono"
        style={{
          position: "relative",
          color: "rgba(154,167,181,0.58)",
          fontSize: "0.62rem",
          letterSpacing: "0.13em",
          textTransform: "uppercase",
        }}
      >
        {label}
      </p>
      <p
        className={mono ? "font-mono mt-2 truncate" : "font-display mt-2 truncate"}
        style={{
          position: "relative",
          color: "var(--text)",
          fontSize: mono ? "0.84rem" : "1.25rem",
          fontWeight: mono ? 500 : 700,
        }}
      >
        {value}
      </p>
    </Plate>
  );
}

function SmallFact({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p
        className="font-mono"
        style={{
          color: "rgba(154,167,181,0.54)",
          fontSize: "0.62rem",
          letterSpacing: "0.12em",
          textTransform: "uppercase",
        }}
      >
        {label}
      </p>
      <p className="font-mono mt-1 truncate" style={{ color: "var(--text)", fontSize: "0.78rem" }}>
        {value}
      </p>
    </div>
  );
}

function ProjectionRow({
  observationId,
  field,
}: {
  observationId: string;
  field: EndpointTelemetryFieldProjection;
}) {
  const state = projectionDisplayState(field.redactionClass);
  const rawValue =
    field.redactionClass === "raw_artifact_permitted" ? shortText(field.rawValue ?? "-") : null;

  return (
    <div
      className="rounded-md px-3 py-2"
      style={{
        border: `1px solid ${state.border}`,
        background: state.background,
      }}
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="font-mono text-sm" style={{ color: "var(--text)" }}>
          {field.fieldPath}
        </p>
        <span
          className="font-mono"
          style={{
            color: state.color,
            border: `1px solid ${state.border}`,
            borderRadius: 5,
            padding: "2px 7px",
            fontSize: "0.62rem",
            letterSpacing: 0,
            textTransform: "uppercase",
          }}
        >
          {state.label}
        </span>
      </div>
      <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1">
        <InlineMeta label="observation" value={observationId} />
        <InlineMeta label="hash" value={shortHash(field.valueHash)} />
        <InlineMeta label="feature" value={field.featureValue ?? "-"} />
        {rawValue != null && <InlineMeta label="raw" value={rawValue} />}
      </div>
      <p
        className="font-mono mt-2 truncate"
        style={{ color: "rgba(154,167,181,0.52)", fontSize: "0.64rem" }}
      >
        {field.reason || "-"}
      </p>
    </div>
  );
}

function projectionDisplayState(
  redactionClass: EndpointTelemetryFieldProjection["redactionClass"],
) {
  switch (redactionClass) {
    case "redacted":
      return {
        label: "REDACTED",
        color: "var(--crimson)",
        border: "rgba(194,59,59,0.36)",
        background: "rgba(194,59,59,0.08)",
      };
    case "local_only":
      return {
        label: "LOCAL ONLY",
        color: "var(--stamp-warn)",
        border: "rgba(214,177,90,0.38)",
        background: "rgba(214,177,90,0.08)",
      };
    case "hash_only":
      return {
        label: "HASH ONLY",
        color: "var(--stamp-allowed)",
        border: "rgba(45,170,106,0.34)",
        background: "rgba(45,170,106,0.06)",
      };
    case "metadata_only":
      return {
        label: "METADATA",
        color: "rgb(105,158,214)",
        border: "rgba(105,158,214,0.36)",
        background: "rgba(105,158,214,0.07)",
      };
    case "raw_artifact_permitted":
      return {
        label: "RAW PERMITTED",
        color: "rgb(227,128,69)",
        border: "rgba(227,128,69,0.38)",
        background: "rgba(227,128,69,0.08)",
      };
  }
}

function InlineMeta({ label, value }: { label: string; value: string }) {
  return (
    <span className="font-mono" style={{ color: "rgba(154,167,181,0.48)", fontSize: "0.64rem" }}>
      {label}:{value}
    </span>
  );
}

function StatusBanner({ message }: { message: string }) {
  return (
    <div
      className="glass-panel"
      style={{
        background: "rgba(194,59,59,0.08)",
        border: "1px solid rgba(194,59,59,0.3)",
        padding: "0.7rem 1rem",
      }}
    >
      <NoiseGrain />
      <p
        className="font-mono"
        style={{ position: "relative", color: "var(--crimson)", fontSize: "0.78rem" }}
      >
        {message}
      </p>
    </div>
  );
}

function EmptyState({ text }: { text: string }) {
  return (
    <p
      className="font-mono"
      style={{
        position: "relative",
        color: "rgba(154,167,181,0.5)",
        fontSize: "0.78rem",
        letterSpacing: "0.06em",
      }}
    >
      {text}
    </p>
  );
}

function flattenProjections(report: CreatePrivacyReportResponse | null) {
  if (!report) return [];
  return report.report.observations.flatMap((observation) =>
    observation.projections.map((field) => ({
      observationId: observation.observationId || "-",
      field,
    })),
  );
}

function receiptFamilyText(receipt: SignedReceiptJson | undefined): string | null {
  const receiptValue = isRecord(receipt?.receipt) ? receipt?.receipt : null;
  const metadata = isRecord(receiptValue?.metadata) ? receiptValue.metadata : null;
  const decision = isRecord(metadata?.endpointDecision) ? metadata.endpointDecision : null;
  const family = decision?.receiptFamily;
  return typeof family === "string" && family.trim() ? family : null;
}

function numberText(value: unknown): string {
  return typeof value === "number" ? String(value) : "-";
}

function shortHash(value: string | null | undefined): string {
  if (!value) return "-";
  return value.length > 18 ? `${value.slice(0, 18)}...` : value;
}

function shortText(value: string): string {
  return value.length > 36 ? `${value.slice(0, 36)}...` : value;
}

function safeFilenameId(value: string): string {
  return value.trim().replace(/[^A-Za-z0-9_.-]+/g, "-") || "unknown";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
