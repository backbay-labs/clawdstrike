import { AnimatePresence, motion } from "framer-motion";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  attachEndpointEvidenceArchiveToCase,
  backfillEndpointEvidenceArchivesToControl,
  type CaseArtifactRef,
  type CaseTimelineEvent,
  createFleetCase,
  downloadEndpointEvidenceArchive,
  downloadFleetEvidenceBundle,
  type EndpointEvidenceArchiveBackfillResponse,
  type EndpointEvidenceArchiveRecord,
  type EndpointEvidenceBundleFleetPublishResponse,
  exportFleetCaseEvidenceBundle,
  type FleetCase,
  type FleetCaseDetail,
  type FleetEvidenceBundle,
  fetchEndpointEvidenceArchive,
  fetchFleetCase,
  fetchFleetCases,
  fetchFleetCaseTimeline,
  publishEndpointEvidenceBundleToFleet,
} from "../../api/client";
import type { SSEEvent } from "../../hooks/useSSE";
import { downloadBlob, exportAsJSON } from "../../utils/exportData";
import { NoiseGrain, Stamp } from "../ui";

interface AuditEventLike {
  id?: string;
  _id?: number;
  event_type?: string;
  action_type?: string;
  target?: string;
  allowed?: boolean;
  decision?: string;
  guard?: string;
  policy_hash?: string;
  session_id?: string;
  agent_id?: string;
  timestamp: string;
  severity?: string;
  message?: string;
  attributes?: Record<string, unknown>;
  evidence?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}

type DrawerEvent = SSEEvent | AuditEventLike;
type IncidentStatus = "open" | "acknowledged" | "resolved";

interface IncidentNote {
  id: string;
  created_at: string;
  note: string;
}

interface IncidentRecord {
  incident_id: string;
  event_id: string;
  status: IncidentStatus;
  owner?: string;
  notes: IncidentNote[];
  created_at: string;
  updated_at: string;
  acknowledged_at?: string;
  resolved_at?: string;
}

const INCIDENT_STORE_KEY = "cs.incident.workflow.v1";

interface ArchiveEvidenceHint {
  archiveId: string;
  archiveHash?: string;
  bundleId?: string;
  rawRef?: string;
  rawArtifactApprovalId?: string;
  rawArtifactApprovalReasonHash?: string;
}

function getDecision(event: DrawerEvent): "allowed" | "blocked" | "warn" | null {
  if ("decision" in event && event.decision) {
    if (event.decision === "blocked") return "blocked";
    if (event.decision === "warn") return "warn";
    if (event.decision === "allowed") return "allowed";
    return null;
  }
  if ("allowed" in event) {
    if (event.allowed === true) return "allowed";
    if (event.allowed === false) return "blocked";
  }
  return null;
}

function getEventId(event: DrawerEvent): string {
  if ("id" in event && event.id) return event.id;
  if ("_id" in event && event._id != null) return String(event._id);
  return event.timestamp;
}

function buildDefaultIncident(eventId: string, event: DrawerEvent): IncidentRecord {
  const now = new Date().toISOString();
  const seed = eventId.replace(/[^a-zA-Z0-9_-]+/g, "").slice(0, 24) || "event";
  return {
    incident_id: `inc-${seed}`,
    event_id: eventId,
    status: "open",
    notes: [],
    created_at: now,
    updated_at: now,
  };
}

function readIncidentStore(): Record<string, IncidentRecord> {
  try {
    const raw = localStorage.getItem(INCIDENT_STORE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? (parsed as Record<string, IncidentRecord>) : {};
  } catch {
    return {};
  }
}

function writeIncidentStore(store: Record<string, IncidentRecord>) {
  localStorage.setItem(INCIDENT_STORE_KEY, JSON.stringify(store));
}

function objectValue(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function parseArchiveRawRef(rawRef: string | undefined): Partial<ArchiveEvidenceHint> {
  if (!rawRef) return {};
  const parts = rawRef.split(":");
  if (parts.length < 3 || parts[0] !== "endpoint-evidence-bundle-archive") {
    return {};
  }
  return {
    archiveId: parts[1],
    archiveHash: parts.slice(2).join(":"),
    rawRef,
  };
}

function archiveEvidenceHint(event: DrawerEvent): ArchiveEvidenceHint | null {
  const record = event as unknown as Record<string, unknown>;
  const attributes = objectValue(record.attributes);
  const evidence = objectValue(record.evidence);
  const metadata = objectValue(record.metadata);
  const rawRef =
    stringValue(evidence?.rawRef) ??
    stringValue(metadata?.rawRef) ??
    stringValue(attributes?.rawRef) ??
    stringValue(record.rawRef);
  const parsed = parseArchiveRawRef(rawRef);
  const archiveId =
    stringValue(attributes?.archiveId) ??
    stringValue(metadata?.archiveId) ??
    stringValue(record.archiveId) ??
    parsed.archiveId;
  if (!archiveId) return null;
  return {
    archiveId,
    archiveHash:
      stringValue(attributes?.archiveHash) ??
      stringValue(metadata?.archiveHash) ??
      stringValue(record.archiveHash) ??
      parsed.archiveHash,
    bundleId:
      stringValue(attributes?.bundleId) ??
      stringValue(metadata?.bundleId) ??
      stringValue(record.bundleId) ??
      stringValue(record.target),
    rawRef: rawRef ?? parsed.rawRef,
    rawArtifactApprovalId:
      stringValue(attributes?.rawArtifactApprovalId) ??
      stringValue(metadata?.rawArtifactApprovalId) ??
      stringValue(evidence?.rawArtifactApprovalId) ??
      stringValue(record.rawArtifactApprovalId),
    rawArtifactApprovalReasonHash:
      stringValue(attributes?.rawArtifactApprovalReasonHash) ??
      stringValue(metadata?.rawArtifactApprovalReasonHash) ??
      stringValue(evidence?.rawArtifactApprovalReasonHash) ??
      stringValue(record.rawArtifactApprovalReasonHash),
  };
}

function archiveApprovalId(
  record: EndpointEvidenceArchiveRecord | null,
  hint: ArchiveEvidenceHint | null,
): string | undefined {
  return (
    stringValue(record?.rawArtifactApprovalId) ??
    stringValue(record?.metadata.rawArtifactApprovalId) ??
    hint?.rawArtifactApprovalId
  );
}

function archiveApprovalReasonHash(
  record: EndpointEvidenceArchiveRecord | null,
  hint: ArchiveEvidenceHint | null,
): string | undefined {
  return (
    stringValue(record?.rawArtifactApprovalReasonHash) ??
    stringValue(record?.metadata.rawArtifactApprovalReasonHash) ??
    hint?.rawArtifactApprovalReasonHash
  );
}

export function EventDetailDrawer({
  event,
  onClose,
}: {
  event: DrawerEvent | null;
  onClose: () => void;
}) {
  useEffect(() => {
    if (!event) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, [event, onClose]);

  const eventId = useMemo(() => (event ? getEventId(event) : null), [event]);
  const [incident, setIncident] = useState<IncidentRecord | null>(null);
  const [ownerDraft, setOwnerDraft] = useState("");
  const [noteDraft, setNoteDraft] = useState("");
  const archiveHint = useMemo(() => (event ? archiveEvidenceHint(event) : null), [event]);
  const [archiveRecord, setArchiveRecord] = useState<EndpointEvidenceArchiveRecord | null>(null);
  const [archiveLoading, setArchiveLoading] = useState(false);
  const [archiveDownloadLoading, setArchiveDownloadLoading] = useState(false);
  const [archiveError, setArchiveError] = useState<string | null>(null);
  const [rawArchiveApprovalId, setRawArchiveApprovalId] = useState("");
  const [rawArchiveApprovalReason, setRawArchiveApprovalReason] = useState("");
  const [archivePublishLoading, setArchivePublishLoading] = useState(false);
  const [archivePublishResult, setArchivePublishResult] =
    useState<EndpointEvidenceBundleFleetPublishResponse | null>(null);
  const [archiveBackfillLoading, setArchiveBackfillLoading] = useState(false);
  const [archiveBackfillResult, setArchiveBackfillResult] =
    useState<EndpointEvidenceArchiveBackfillResponse | null>(null);
  const [archiveApprovalError, setArchiveApprovalError] = useState<string | null>(null);
  const [remoteCaseId, setRemoteCaseId] = useState("");
  const [caseAttachLoading, setCaseAttachLoading] = useState(false);
  const [caseAttachError, setCaseAttachError] = useState<string | null>(null);
  const [caseAttachArtifact, setCaseAttachArtifact] = useState<CaseArtifactRef | null>(null);
  const [remoteCases, setRemoteCases] = useState<FleetCase[]>([]);
  const [remoteCasesLoading, setRemoteCasesLoading] = useState(false);
  const [remoteCasesError, setRemoteCasesError] = useState<string | null>(null);
  const [caseCreateLoading, setCaseCreateLoading] = useState(false);
  const [caseDetail, setCaseDetail] = useState<FleetCaseDetail | null>(null);
  const [caseTimeline, setCaseTimeline] = useState<CaseTimelineEvent[]>([]);
  const [caseDetailLoading, setCaseDetailLoading] = useState(false);
  const [caseDetailError, setCaseDetailError] = useState<string | null>(null);
  const [caseBundleExport, setCaseBundleExport] = useState<FleetEvidenceBundle | null>(null);
  const [caseBundleExportLoading, setCaseBundleExportLoading] = useState(false);
  const [caseBundleDownloadLoading, setCaseBundleDownloadLoading] = useState(false);

  useEffect(() => {
    if (!event || !eventId) {
      setIncident(null);
      setOwnerDraft("");
      setNoteDraft("");
      setArchiveRecord(null);
      setArchiveError(null);
      setArchiveLoading(false);
      setArchiveDownloadLoading(false);
      setRawArchiveApprovalId("");
      setRawArchiveApprovalReason("");
      setArchivePublishLoading(false);
      setArchivePublishResult(null);
      setArchiveBackfillLoading(false);
      setArchiveBackfillResult(null);
      setArchiveApprovalError(null);
      setRemoteCaseId("");
      setCaseAttachLoading(false);
      setCaseAttachError(null);
      setCaseAttachArtifact(null);
      setRemoteCases([]);
      setRemoteCasesLoading(false);
      setRemoteCasesError(null);
      setCaseCreateLoading(false);
      setCaseDetail(null);
      setCaseTimeline([]);
      setCaseDetailLoading(false);
      setCaseDetailError(null);
      setCaseBundleExport(null);
      setCaseBundleExportLoading(false);
      setCaseBundleDownloadLoading(false);
      return;
    }

    const store = readIncidentStore();
    const existing = store[eventId] ?? buildDefaultIncident(eventId, event);
    if (!store[eventId]) {
      store[eventId] = existing;
      writeIncidentStore(store);
    }

    setIncident(existing);
    setOwnerDraft(existing.owner ?? "");
    setNoteDraft("");
    setArchiveRecord(null);
    setArchiveError(null);
    setArchiveLoading(false);
    setArchiveDownloadLoading(false);
    setRawArchiveApprovalId("");
    setRawArchiveApprovalReason("");
    setArchivePublishLoading(false);
    setArchivePublishResult(null);
    setArchiveBackfillLoading(false);
    setArchiveBackfillResult(null);
    setArchiveApprovalError(null);
    setRemoteCaseId("");
    setCaseAttachLoading(false);
    setCaseAttachError(null);
    setCaseAttachArtifact(null);
    setRemoteCases([]);
    setRemoteCasesLoading(false);
    setRemoteCasesError(null);
    setCaseCreateLoading(false);
    setCaseDetail(null);
    setCaseTimeline([]);
    setCaseDetailLoading(false);
    setCaseDetailError(null);
    setCaseBundleExport(null);
    setCaseBundleExportLoading(false);
    setCaseBundleDownloadLoading(false);
  }, [event, eventId]);

  const persistIncident = useCallback(
    (next: IncidentRecord) => {
      setIncident(next);
      if (!eventId) return;
      const store = readIncidentStore();
      store[eventId] = next;
      writeIncidentStore(store);
    },
    [eventId],
  );

  const updateIncident = useCallback(
    (mutate: (current: IncidentRecord) => IncidentRecord) => {
      if (!incident) return;
      const next = mutate(incident);
      persistIncident({
        ...next,
        updated_at: new Date().toISOString(),
      });
    },
    [incident, persistIncident],
  );

  const acknowledgeIncident = useCallback(() => {
    updateIncident((current) => {
      if (current.status === "acknowledged" || current.status === "resolved") return current;
      return {
        ...current,
        status: "acknowledged",
        acknowledged_at: new Date().toISOString(),
      };
    });
  }, [updateIncident]);

  const resolveIncident = useCallback(() => {
    updateIncident((current) => ({
      ...current,
      status: "resolved",
      resolved_at: new Date().toISOString(),
    }));
  }, [updateIncident]);

  const assignOwner = useCallback(() => {
    const owner = ownerDraft.trim();
    updateIncident((current) => ({
      ...current,
      owner: owner || undefined,
    }));
  }, [ownerDraft, updateIncident]);

  const addNote = useCallback(() => {
    const note = noteDraft.trim();
    if (!note) return;
    updateIncident((current) => ({
      ...current,
      notes: [
        {
          id: `note-${Date.now()}`,
          created_at: new Date().toISOString(),
          note,
        },
        ...current.notes,
      ].slice(0, 25),
    }));
    setNoteDraft("");
  }, [noteDraft, updateIncident]);

  const attachArchiveEvidence = useCallback(async () => {
    if (!archiveHint) return;
    setArchiveLoading(true);
    setArchiveError(null);
    try {
      const record = await fetchEndpointEvidenceArchive(archiveHint.archiveId);
      setArchiveRecord(record);
    } catch (err) {
      setArchiveError(err instanceof Error ? err.message : "Failed to fetch archive evidence");
    } finally {
      setArchiveLoading(false);
    }
  }, [archiveHint]);

  const exportRawArchive = useCallback(async () => {
    const archiveId = archiveRecord?.archiveId ?? archiveHint?.archiveId;
    if (!archiveId) return;
    setArchiveDownloadLoading(true);
    setArchiveError(null);
    try {
      const archive = await downloadEndpointEvidenceArchive(archiveId);
      exportAsJSON([archive], `endpoint-evidence-archive-${archiveId}`);
    } catch (err) {
      setArchiveError(err instanceof Error ? err.message : "Failed to download archive evidence");
    } finally {
      setArchiveDownloadLoading(false);
    }
  }, [archiveHint, archiveRecord]);

  const approvedArchiveInput = useCallback(() => {
    const approvalId = rawArchiveApprovalId.trim();
    const approvalReason = rawArchiveApprovalReason.trim();
    if (!approvalId || !approvalReason) {
      throw new Error("Approval ID and approval reason are required");
    }
    return { rawArtifactApprovalId: approvalId, rawArtifactApprovalReason: approvalReason };
  }, [rawArchiveApprovalId, rawArchiveApprovalReason]);

  const publishArchiveToFleet = useCallback(async () => {
    const bundleId = archiveRecord?.bundleId ?? archiveHint?.bundleId;
    if (!bundleId) return;
    setArchivePublishLoading(true);
    setArchiveApprovalError(null);
    setArchivePublishResult(null);
    try {
      const result = await publishEndpointEvidenceBundleToFleet(bundleId, approvedArchiveInput());
      setArchivePublishResult(result);
      if (result.archiveId) {
        setArchiveRecord((current) =>
          current && current.archiveId === result.archiveId
            ? {
                ...current,
                rawArtifactApprovalId:
                  result.controlUpload?.rawArtifactApprovalId ?? current.rawArtifactApprovalId,
                rawArtifactApprovalReasonHash:
                  result.controlUpload?.rawArtifactApprovalReasonHash ??
                  current.rawArtifactApprovalReasonHash,
              }
            : current,
        );
      }
    } catch (err) {
      setArchiveApprovalError(
        err instanceof Error ? err.message : "Failed to publish approved archive",
      );
    } finally {
      setArchivePublishLoading(false);
    }
  }, [approvedArchiveInput, archiveHint, archiveRecord]);

  const backfillArchiveToControl = useCallback(async () => {
    const bundleId = archiveRecord?.bundleId ?? archiveHint?.bundleId;
    setArchiveBackfillLoading(true);
    setArchiveApprovalError(null);
    setArchiveBackfillResult(null);
    try {
      const result = await backfillEndpointEvidenceArchivesToControl({
        ...(bundleId && { bundleId }),
        limit: 1,
        ...approvedArchiveInput(),
      });
      setArchiveBackfillResult(result);
    } catch (err) {
      setArchiveApprovalError(
        err instanceof Error ? err.message : "Failed to backfill approved archive",
      );
    } finally {
      setArchiveBackfillLoading(false);
    }
  }, [approvedArchiveInput, archiveHint, archiveRecord]);

  const attachArchiveToCase = useCallback(async () => {
    const archiveId = archiveRecord?.archiveId ?? archiveHint?.archiveId;
    const caseId = remoteCaseId.trim();
    if (!archiveId || !caseId) return;
    setCaseAttachLoading(true);
    setCaseAttachError(null);
    try {
      const artifact = await attachEndpointEvidenceArchiveToCase(caseId, archiveId);
      setCaseAttachArtifact(artifact);
    } catch (err) {
      setCaseAttachError(err instanceof Error ? err.message : "Failed to attach archive to case");
    } finally {
      setCaseAttachLoading(false);
    }
  }, [archiveHint, archiveRecord, remoteCaseId]);

  const loadRemoteCases = useCallback(async () => {
    setRemoteCasesLoading(true);
    setRemoteCasesError(null);
    try {
      const cases = await fetchFleetCases();
      setRemoteCases(cases);
    } catch (err) {
      setRemoteCasesError(err instanceof Error ? err.message : "Failed to load remote cases");
    } finally {
      setRemoteCasesLoading(false);
    }
  }, []);

  const createCaseFromArchive = useCallback(async () => {
    const archive = archiveRecord;
    const archiveId = archive?.archiveId ?? archiveHint?.archiveId;
    if (!archive || !archiveId) return;
    const titleTarget = archive.bundleId || archiveHint?.bundleId || archiveId;
    const metadata: Record<string, unknown> = {
      archiveId,
      archiveHash: archive.archiveHash,
      bundleId: archive.bundleId,
      rawRef: archive.rawRef,
    };
    if (archive.endpointAgentId) {
      metadata.endpointAgentId = archive.endpointAgentId;
    }
    const approvalId = archiveApprovalId(archive, archiveHint);
    const approvalReasonHash = archiveApprovalReasonHash(archive, archiveHint);
    if (approvalId) {
      metadata.rawArtifactApprovalId = approvalId;
    }
    if (approvalReasonHash) {
      metadata.rawArtifactApprovalReasonHash = approvalReasonHash;
    }
    setCaseCreateLoading(true);
    setCaseAttachError(null);
    try {
      const remoteCase = await createFleetCase({
        title: `Endpoint evidence archive ${titleTarget}`,
        summary: `Remote case created from retained endpoint archive ${archiveId}`,
        severity: "high",
        tags: ["endpoint-evidence", "case-handoff"],
        metadata,
      });
      setRemoteCaseId(remoteCase.id);
      setRemoteCases((cases) =>
        cases.some((candidate) => candidate.id === remoteCase.id) ? cases : [remoteCase, ...cases],
      );
      const artifact = await attachEndpointEvidenceArchiveToCase(remoteCase.id, archiveId);
      setCaseAttachArtifact(artifact);
    } catch (err) {
      setCaseAttachError(err instanceof Error ? err.message : "Failed to create archive case");
    } finally {
      setCaseCreateLoading(false);
    }
  }, [archiveHint, archiveRecord]);

  const loadSelectedCase = useCallback(async () => {
    const caseId = remoteCaseId.trim();
    if (!caseId) return;
    setCaseDetailLoading(true);
    setCaseDetailError(null);
    try {
      const [detail, timeline] = await Promise.all([
        fetchFleetCase(caseId),
        fetchFleetCaseTimeline(caseId),
      ]);
      setCaseDetail(detail);
      setCaseTimeline(timeline);
    } catch (err) {
      setCaseDetailError(err instanceof Error ? err.message : "Failed to load remote case");
    } finally {
      setCaseDetailLoading(false);
    }
  }, [remoteCaseId]);

  const exportSelectedCaseBundle = useCallback(async () => {
    const caseId = remoteCaseId.trim();
    if (!caseId) return;
    setCaseBundleExportLoading(true);
    setCaseBundleDownloadLoading(false);
    setCaseDetailError(null);
    try {
      const bundle = await exportFleetCaseEvidenceBundle(caseId, { includeRawEnvelopes: true });
      setCaseBundleExport(bundle);
    } catch (err) {
      setCaseDetailError(err instanceof Error ? err.message : "Failed to export case bundle");
    } finally {
      setCaseBundleExportLoading(false);
    }
  }, [remoteCaseId]);

  const downloadSelectedCaseBundle = useCallback(async () => {
    if (!caseBundleExport?.exportId) return;
    setCaseBundleDownloadLoading(true);
    setCaseDetailError(null);
    try {
      const bundle = await downloadFleetEvidenceBundle(caseBundleExport.exportId);
      downloadBlob(bundle, `${caseBundleExport.exportId}.zip`);
    } catch (err) {
      setCaseDetailError(err instanceof Error ? err.message : "Failed to download case bundle");
    } finally {
      setCaseBundleDownloadLoading(false);
    }
  }, [caseBundleExport]);

  const exportIncidentBundle = useCallback(() => {
    if (!event || !incident) return;
    const bundle = {
      exported_at: new Date().toISOString(),
      incident,
      event,
      endpointEvidenceArchive: archiveRecord,
    };
    exportAsJSON(
      [bundle],
      `incident-${incident.incident_id}-${incident.status}-${Date.now().toString().slice(-6)}`,
    );
  }, [archiveRecord, event, incident]);

  const decision = event ? getDecision(event) : null;
  const displayedRawArchiveApprovalId = archiveApprovalId(archiveRecord, archiveHint);
  const displayedRawArchiveApprovalReasonHash = archiveApprovalReasonHash(
    archiveRecord,
    archiveHint,
  );
  const approvedArchiveFieldsReady =
    Boolean(rawArchiveApprovalId.trim()) && Boolean(rawArchiveApprovalReason.trim());
  const archiveBundleId = archiveRecord?.bundleId ?? archiveHint?.bundleId;

  return (
    <AnimatePresence>
      {event && (
        <motion.div
          key={getEventId(event)}
          initial={{ x: "100%" }}
          animate={{ x: 0 }}
          exit={{ x: "100%" }}
          transition={{ type: "spring", damping: 25, stiffness: 300 }}
          className="glass-panel"
          style={{
            position: "absolute",
            top: 0,
            right: 0,
            bottom: 0,
            width: 420,
            zIndex: 50,
            overflow: "auto",
            display: "flex",
            flexDirection: "column",
          }}
        >
          <NoiseGrain />
          {/* Header */}
          <div
            style={{
              position: "relative",
              zIndex: 2,
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              padding: "16px 20px",
              borderBottom: "1px solid var(--slate)",
            }}
          >
            <span
              className="font-mono"
              style={{
                fontSize: 11,
                textTransform: "uppercase",
                letterSpacing: "0.1em",
                color: "var(--gold)",
              }}
            >
              Event Detail
            </span>
            <button
              type="button"
              onClick={onClose}
              style={{
                background: "none",
                border: "none",
                color: "var(--muted)",
                cursor: "pointer",
                fontSize: 18,
                lineHeight: 1,
              }}
            >
              &#10005;
            </button>
          </div>

          {/* Summary */}
          <div
            style={{
              position: "relative",
              zIndex: 2,
              padding: "16px 20px",
              display: "flex",
              flexDirection: "column",
              gap: 10,
            }}
          >
            <Row label="Type" value={event.event_type ?? "-"} />
            <Row label="Action" value={event.action_type ?? "-"} />
            <Row label="Target" value={event.target ?? "-"} />
            <Row label="Guard" value={event.guard ?? "-"} />
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span
                className="font-mono"
                style={{
                  fontSize: 10,
                  textTransform: "uppercase",
                  letterSpacing: "0.1em",
                  color: "rgba(214,177,90,0.55)",
                  width: 80,
                  flexShrink: 0,
                }}
              >
                Decision
              </span>
              {decision ? (
                <Stamp variant={decision}>{decision.toUpperCase()}</Stamp>
              ) : (
                <span style={{ color: "rgba(154,167,181,0.3)", fontSize: 13 }}>-</span>
              )}
            </div>
            <Row label="Timestamp" value={new Date(event.timestamp).toLocaleString()} />
            {event.session_id && <Row label="Session" value={event.session_id} />}
            {event.agent_id && <Row label="Agent" value={event.agent_id} />}
            {event.policy_hash && <Row label="Policy Hash" value={event.policy_hash} />}
            {"severity" in event && event.severity && (
              <Row label="Severity" value={event.severity} />
            )}
            {"message" in event && event.message && <Row label="Message" value={event.message} />}
          </div>

          {/* Archive evidence */}
          {archiveHint && (
            <div
              style={{
                position: "relative",
                zIndex: 2,
                padding: "0 20px 20px",
                borderTop: "1px solid var(--slate)",
              }}
            >
              <span
                className="font-mono"
                style={{
                  fontSize: 10,
                  textTransform: "uppercase",
                  letterSpacing: "0.1em",
                  color: "rgba(214,177,90,0.55)",
                  display: "block",
                  margin: "12px 0 10px",
                }}
              >
                Archive Evidence
              </span>
              <div style={{ display: "grid", gap: 8 }}>
                <Row label="Archive" value={archiveRecord?.archiveId ?? archiveHint.archiveId} />
                {(archiveRecord?.bundleId ?? archiveHint.bundleId) && (
                  <Row
                    label="Bundle"
                    value={archiveRecord?.bundleId ?? archiveHint.bundleId ?? "-"}
                  />
                )}
                {(archiveRecord?.archiveHash ?? archiveHint.archiveHash) && (
                  <Row
                    label="Hash"
                    value={archiveRecord?.archiveHash ?? archiveHint.archiveHash ?? "-"}
                  />
                )}
                {(archiveRecord?.rawRef ?? archiveHint.rawRef) && (
                  <Row label="Raw Ref" value={archiveRecord?.rawRef ?? archiveHint.rawRef ?? "-"} />
                )}
                {displayedRawArchiveApprovalId && (
                  <Row label="Approval ID" value={displayedRawArchiveApprovalId} />
                )}
                {displayedRawArchiveApprovalReasonHash && (
                  <Row label="Approval Hash" value={displayedRawArchiveApprovalReasonHash} />
                )}
                {archiveRecord && (
                  <>
                    <Row label="Size" value={`${archiveRecord.sizeBytes} bytes`} />
                    <Row
                      label="Verified"
                      value={
                        archiveRecord.verification.verified === true ? "verified" : "unverified"
                      }
                    />
                    <Row
                      label="Expires"
                      value={new Date(archiveRecord.expiresAt).toLocaleString()}
                    />
                  </>
                )}
                {archiveError && (
                  <span
                    className="font-mono"
                    style={{ fontSize: 11, color: "rgba(194,59,59,0.8)" }}
                  >
                    {archiveError}
                  </span>
                )}
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                  <button
                    type="button"
                    onClick={attachArchiveEvidence}
                    disabled={archiveLoading}
                    style={incidentButtonStyle(!archiveLoading)}
                  >
                    {archiveLoading ? "Attaching…" : "Attach Archive Evidence"}
                  </button>
                  {archiveRecord && (
                    <button
                      type="button"
                      onClick={exportRawArchive}
                      disabled={archiveDownloadLoading}
                      style={incidentButtonStyle(!archiveDownloadLoading)}
                    >
                      {archiveDownloadLoading ? "Exporting…" : "Export Raw Archive"}
                    </button>
                  )}
                </div>
                <div style={{ display: "grid", gap: 6 }}>
                  <input
                    type="text"
                    value={rawArchiveApprovalId}
                    onChange={(e) => {
                      setRawArchiveApprovalId(e.target.value);
                      setArchiveApprovalError(null);
                    }}
                    placeholder="Raw archive approval ID"
                    aria-label="Raw archive approval ID"
                    className="glass-input font-mono"
                    style={{ fontSize: 11, padding: "6px 8px" }}
                  />
                  <textarea
                    value={rawArchiveApprovalReason}
                    onChange={(e) => {
                      setRawArchiveApprovalReason(e.target.value);
                      setArchiveApprovalError(null);
                    }}
                    placeholder="Raw archive approval reason"
                    aria-label="Raw archive approval reason"
                    className="glass-input font-mono"
                    style={{ minHeight: 54, resize: "vertical", fontSize: 11, padding: "6px 8px" }}
                  />
                  <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                    <button
                      type="button"
                      onClick={publishArchiveToFleet}
                      disabled={
                        !archiveBundleId || !approvedArchiveFieldsReady || archivePublishLoading
                      }
                      style={incidentButtonStyle(
                        Boolean(archiveBundleId) &&
                          approvedArchiveFieldsReady &&
                          !archivePublishLoading,
                      )}
                    >
                      {archivePublishLoading ? "Publishing…" : "Publish Approved Raw Archive"}
                    </button>
                    <button
                      type="button"
                      onClick={backfillArchiveToControl}
                      disabled={
                        !archiveBundleId || !approvedArchiveFieldsReady || archiveBackfillLoading
                      }
                      style={incidentButtonStyle(
                        Boolean(archiveBundleId) &&
                          approvedArchiveFieldsReady &&
                          !archiveBackfillLoading,
                      )}
                    >
                      {archiveBackfillLoading ? "Backfilling…" : "Backfill Approved Archive"}
                    </button>
                  </div>
                  {archiveApprovalError && (
                    <span
                      className="font-mono"
                      style={{ fontSize: 11, color: "rgba(194,59,59,0.8)" }}
                    >
                      {archiveApprovalError}
                    </span>
                  )}
                  {archivePublishResult && (
                    <span
                      className="font-mono"
                      style={{ fontSize: 11, color: "rgba(73,167,92,0.88)" }}
                    >
                      Published archive {archivePublishResult.archiveId}{" "}
                      {archivePublishResult.controlUpload?.accepted ? "accepted" : "not accepted"}
                    </span>
                  )}
                  {archiveBackfillResult && (
                    <span
                      className="font-mono"
                      style={{ fontSize: 11, color: "rgba(73,167,92,0.88)" }}
                    >
                      Backfill delivered {archiveBackfillResult.delivered}/
                      {archiveBackfillResult.attempted}
                    </span>
                  )}
                </div>
                {archiveRecord && (
                  <div style={{ display: "grid", gap: 6 }}>
                    <div style={{ display: "flex", gap: 6, minWidth: 0 }}>
                      <select
                        aria-label="Remote case"
                        value={remoteCaseId}
                        onChange={(e) => {
                          setRemoteCaseId(e.target.value);
                          setCaseAttachArtifact(null);
                          setCaseAttachError(null);
                          setCaseDetail(null);
                          setCaseTimeline([]);
                          setCaseDetailError(null);
                          setCaseBundleExport(null);
                          setCaseBundleDownloadLoading(false);
                        }}
                        className="glass-input font-mono"
                        style={{ flex: 1, minWidth: 0, fontSize: 11, padding: "6px 8px" }}
                      >
                        <option value="">Select remote case</option>
                        {remoteCases.map((remoteCase) => (
                          <option key={remoteCase.id} value={remoteCase.id}>
                            {remoteCase.title}
                          </option>
                        ))}
                      </select>
                      <button
                        type="button"
                        onClick={loadRemoteCases}
                        disabled={remoteCasesLoading}
                        style={incidentButtonStyle(!remoteCasesLoading)}
                      >
                        {remoteCasesLoading ? "Loading…" : "Load Cases"}
                      </button>
                    </div>
                    {remoteCasesError && (
                      <span
                        className="font-mono"
                        style={{ fontSize: 11, color: "rgba(194,59,59,0.8)" }}
                      >
                        {remoteCasesError}
                      </span>
                    )}
                  </div>
                )}
                {archiveRecord && (
                  <div style={{ display: "flex", gap: 6, minWidth: 0, flexWrap: "wrap" }}>
                    <input
                      type="text"
                      value={remoteCaseId}
                      onChange={(e) => {
                        setRemoteCaseId(e.target.value);
                        setCaseAttachArtifact(null);
                        setCaseAttachError(null);
                        setCaseDetail(null);
                        setCaseTimeline([]);
                        setCaseDetailError(null);
                        setCaseBundleExport(null);
                        setCaseBundleDownloadLoading(false);
                      }}
                      placeholder="Remote case ID"
                      aria-label="Remote case ID"
                      className="glass-input font-mono"
                      style={{ flex: 1, minWidth: 0, fontSize: 11, padding: "6px 8px" }}
                    />
                    <button
                      type="button"
                      onClick={attachArchiveToCase}
                      disabled={!remoteCaseId.trim() || caseAttachLoading}
                      style={incidentButtonStyle(
                        Boolean(remoteCaseId.trim()) && !caseAttachLoading,
                      )}
                    >
                      {caseAttachLoading ? "Attaching…" : "Attach To Case"}
                    </button>
                    <button
                      type="button"
                      onClick={createCaseFromArchive}
                      disabled={caseCreateLoading}
                      style={incidentButtonStyle(!caseCreateLoading)}
                    >
                      {caseCreateLoading ? "Creating…" : "Create Case"}
                    </button>
                    <button
                      type="button"
                      onClick={loadSelectedCase}
                      disabled={!remoteCaseId.trim() || caseDetailLoading}
                      style={incidentButtonStyle(
                        Boolean(remoteCaseId.trim()) && !caseDetailLoading,
                      )}
                    >
                      {caseDetailLoading ? "Loading…" : "Load Case"}
                    </button>
                    <button
                      type="button"
                      onClick={exportSelectedCaseBundle}
                      disabled={!remoteCaseId.trim() || caseBundleExportLoading}
                      style={incidentButtonStyle(
                        Boolean(remoteCaseId.trim()) && !caseBundleExportLoading,
                      )}
                    >
                      {caseBundleExportLoading ? "Exporting…" : "Export Case Bundle"}
                    </button>
                  </div>
                )}
                {caseAttachError && (
                  <span
                    className="font-mono"
                    style={{ fontSize: 11, color: "rgba(194,59,59,0.8)" }}
                  >
                    {caseAttachError}
                  </span>
                )}
                {caseAttachArtifact && (
                  <span
                    className="font-mono"
                    style={{ fontSize: 11, color: "rgba(73,167,92,0.88)" }}
                  >
                    Attached to case {caseAttachArtifact.caseId}
                  </span>
                )}
                {caseDetailError && (
                  <span
                    className="font-mono"
                    style={{ fontSize: 11, color: "rgba(194,59,59,0.8)" }}
                  >
                    {caseDetailError}
                  </span>
                )}
                {caseDetail && (
                  <div
                    style={{
                      display: "grid",
                      gap: 8,
                      borderTop: "1px solid var(--slate)",
                      paddingTop: 8,
                    }}
                  >
                    <Row label="Case" value={caseDetail.case.title} />
                    <Row label="Status" value={caseDetail.case.status} />
                    <Row label="Artifacts" value={String(caseDetail.artifacts.length)} />
                    {caseTimeline[0] && <Row label="Timeline" value={caseTimeline[0].eventKind} />}
                  </div>
                )}
                {caseBundleExport && (
                  <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
                    <span
                      className="font-mono"
                      style={{ fontSize: 11, color: "rgba(73,167,92,0.88)" }}
                    >
                      Export {caseBundleExport.exportId} {caseBundleExport.status}
                    </span>
                    <button
                      type="button"
                      onClick={downloadSelectedCaseBundle}
                      disabled={caseBundleDownloadLoading}
                      style={incidentButtonStyle(!caseBundleDownloadLoading)}
                    >
                      {caseBundleDownloadLoading ? "Downloading…" : "Download Case Bundle"}
                    </button>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Incident workflow */}
          {incident && (
            <div
              style={{
                position: "relative",
                zIndex: 2,
                padding: "0 20px 20px",
                borderTop: "1px solid var(--slate)",
              }}
            >
              <span
                className="font-mono"
                style={{
                  fontSize: 10,
                  textTransform: "uppercase",
                  letterSpacing: "0.1em",
                  color: "rgba(214,177,90,0.55)",
                  display: "block",
                  margin: "12px 0 10px",
                }}
              >
                Incident Workflow
              </span>

              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
                <span
                  className="font-mono"
                  style={{ fontSize: 11, color: "rgba(154,167,181,0.7)" }}
                >
                  Status
                </span>
                <Stamp
                  variant={
                    incident.status === "resolved"
                      ? "allowed"
                      : incident.status === "acknowledged"
                        ? "warn"
                        : "blocked"
                  }
                >
                  {incident.status.toUpperCase()}
                </Stamp>
                {incident.owner && (
                  <span
                    className="font-mono"
                    style={{ fontSize: 10, color: "rgba(154,167,181,0.75)" }}
                  >
                    owner: {incident.owner}
                  </span>
                )}
              </div>

              <div style={{ display: "flex", gap: 6, marginBottom: 10, flexWrap: "wrap" }}>
                <button
                  type="button"
                  onClick={acknowledgeIncident}
                  disabled={incident.status !== "open"}
                  style={incidentButtonStyle(incident.status === "open")}
                >
                  Acknowledge
                </button>
                <button
                  type="button"
                  onClick={resolveIncident}
                  disabled={incident.status === "resolved"}
                  style={incidentButtonStyle(incident.status !== "resolved")}
                >
                  Mark Resolved
                </button>
                <button
                  type="button"
                  onClick={exportIncidentBundle}
                  style={incidentButtonStyle(true)}
                >
                  Export Bundle
                </button>
              </div>

              <div style={{ display: "flex", gap: 6, marginBottom: 10 }}>
                <input
                  type="text"
                  value={ownerDraft}
                  onChange={(e) => setOwnerDraft(e.target.value)}
                  placeholder="Assign owner (name or @handle)"
                  className="glass-input font-mono"
                  style={{ flex: 1, fontSize: 11, padding: "6px 8px" }}
                />
                <button type="button" onClick={assignOwner} style={incidentButtonStyle(true)}>
                  Assign
                </button>
              </div>

              <div style={{ display: "grid", gap: 6 }}>
                <textarea
                  value={noteDraft}
                  onChange={(e) => setNoteDraft(e.target.value)}
                  placeholder="Add incident note..."
                  className="glass-input font-mono"
                  style={{
                    minHeight: 58,
                    resize: "vertical",
                    fontSize: 11,
                    padding: "7px 8px",
                  }}
                />
                <div style={{ display: "flex", justifyContent: "flex-end" }}>
                  <button
                    type="button"
                    onClick={addNote}
                    style={incidentButtonStyle(Boolean(noteDraft.trim()))}
                  >
                    Add Note
                  </button>
                </div>
              </div>

              <div
                style={{
                  marginTop: 10,
                  border: "1px solid rgba(27,34,48,0.75)",
                  borderRadius: 8,
                  maxHeight: 130,
                  overflow: "auto",
                }}
              >
                {incident.notes.length === 0 ? (
                  <div
                    className="font-mono"
                    style={{ padding: 10, fontSize: 11, color: "rgba(154,167,181,0.45)" }}
                  >
                    No notes yet.
                  </div>
                ) : (
                  incident.notes.map((note) => (
                    <div
                      key={note.id}
                      style={{
                        padding: "8px 10px",
                        borderTop: "1px solid rgba(27,34,48,0.55)",
                        display: "grid",
                        gap: 2,
                      }}
                    >
                      <span
                        className="font-mono"
                        style={{ fontSize: 10, color: "rgba(154,167,181,0.55)" }}
                      >
                        {new Date(note.created_at).toLocaleString()}
                      </span>
                      <span
                        className="font-body"
                        style={{ fontSize: 12, color: "rgba(229,231,235,0.82)" }}
                      >
                        {note.note}
                      </span>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}

          {/* Raw JSON */}
          <div
            style={{
              position: "relative",
              zIndex: 2,
              padding: "0 20px 20px",
              flex: 1,
            }}
          >
            <span
              className="font-mono"
              style={{
                fontSize: 10,
                textTransform: "uppercase",
                letterSpacing: "0.1em",
                color: "rgba(214,177,90,0.55)",
                display: "block",
                marginBottom: 8,
              }}
            >
              Raw JSON
            </span>
            <pre
              className="font-mono"
              style={{
                fontSize: 11,
                color: "rgba(229,231,235,0.7)",
                background: "rgba(0,0,0,0.3)",
                borderRadius: 8,
                padding: 12,
                overflow: "auto",
                maxHeight: 300,
                whiteSpace: "pre-wrap",
                wordBreak: "break-all",
              }}
            >
              {JSON.stringify(event, null, 2)}
            </pre>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

function incidentButtonStyle(enabled: boolean): React.CSSProperties {
  return {
    border: "1px solid rgba(214,177,90,0.3)",
    borderRadius: 6,
    background: enabled ? "rgba(214,177,90,0.09)" : "rgba(27,34,48,0.3)",
    color: enabled ? "var(--gold)" : "rgba(154,167,181,0.45)",
    fontFamily: '"JetBrains Mono", monospace',
    fontSize: 10,
    textTransform: "uppercase",
    letterSpacing: "0.08em",
    padding: "6px 8px",
    cursor: enabled ? "pointer" : "not-allowed",
  };
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ display: "flex", alignItems: "baseline", gap: 8 }}>
      <span
        className="font-mono"
        style={{
          fontSize: 10,
          textTransform: "uppercase",
          letterSpacing: "0.1em",
          color: "rgba(214,177,90,0.55)",
          width: 80,
          flexShrink: 0,
        }}
      >
        {label}
      </span>
      <span
        className="font-mono"
        style={{ fontSize: 13, color: "var(--text)", wordBreak: "break-all" }}
      >
        {value}
      </span>
    </div>
  );
}
