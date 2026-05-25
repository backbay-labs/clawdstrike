import { useCallback, useEffect, useMemo, useState } from "react";
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
  type FleetCaseSeverity,
  type FleetCaseStatus,
  type FleetEvidenceBundle,
} from "../api/client";
import { GlassButton, Plate } from "../components/ui";
import { downloadBlob } from "../utils/exportData";

type LoadingKey =
  | "cases"
  | "detail"
  | "create"
  | "export"
  | "download"
  | "status"
  | "bulkStatus"
  | null;
type CaseStatusFilter = "all" | FleetCaseStatus;
type CaseSeverityFilter = "all" | FleetCaseSeverity;

export function FleetCases(_props: { windowId?: string }) {
  const [cases, setCases] = useState<FleetCase[]>([]);
  const [selectedCaseId, setSelectedCaseId] = useState("");
  const [detail, setDetail] = useState<FleetCaseDetail | null>(null);
  const [timeline, setTimeline] = useState<CaseTimelineEvent[]>([]);
  const [caseBundleExport, setCaseBundleExport] = useState<FleetEvidenceBundle | null>(null);
  const [loading, setLoading] = useState<LoadingKey>(null);
  const [error, setError] = useState<string | null>(null);
  const [caseTitle, setCaseTitle] = useState("");
  const [caseSummary, setCaseSummary] = useState("");
  const [caseSeverity, setCaseSeverity] = useState<FleetCaseSeverity>("high");
  const [caseStatusDraft, setCaseStatusDraft] = useState<FleetCaseStatus>("open");
  const [caseSearch, setCaseSearch] = useState("");
  const [caseStatusFilter, setCaseStatusFilter] = useState<CaseStatusFilter>("all");
  const [caseSeverityFilter, setCaseSeverityFilter] = useState<CaseSeverityFilter>("all");
  const [selectedCaseIds, setSelectedCaseIds] = useState<string[]>([]);
  const [bulkStatusDraft, setBulkStatusDraft] = useState<FleetCaseStatus>("closed");

  const selectedCase = useMemo(
    () => detail?.case ?? cases.find((candidate) => candidate.id === selectedCaseId) ?? null,
    [cases, detail, selectedCaseId],
  );
  const filteredCases = useMemo(() => {
    const query = caseSearch.trim().toLowerCase();
    return cases.filter((fleetCase) => {
      const matchesSearch =
        !query ||
        [
          fleetCase.id,
          fleetCase.title,
          fleetCase.summary ?? "",
          fleetCase.createdBy,
          fleetCase.severity,
          fleetCase.status,
          ...fleetCase.tags,
          ...fleetCase.principalIds,
          ...fleetCase.detectionIds,
          ...fleetCase.responseActionIds,
          ...fleetCase.grantIds,
        ]
          .join(" ")
          .toLowerCase()
          .includes(query);
      const matchesStatus = caseStatusFilter === "all" || fleetCase.status === caseStatusFilter;
      const matchesSeverity =
        caseSeverityFilter === "all" || fleetCase.severity === caseSeverityFilter;
      return matchesSearch && matchesStatus && matchesSeverity;
    });
  }, [caseSearch, caseSeverityFilter, caseStatusFilter, cases]);
  const selectedCaseIdSet = useMemo(() => new Set(selectedCaseIds), [selectedCaseIds]);

  useEffect(() => {
    if (selectedCase) {
      setCaseStatusDraft(selectedCase.status);
    }
  }, [selectedCase]);

  const loadCase = useCallback(async (caseId: string) => {
    const trimmed = caseId.trim();
    if (!trimmed) return;
    setSelectedCaseId(trimmed);
    setLoading("detail");
    setError(null);
    try {
      const [nextDetail, nextTimeline] = await Promise.all([
        fetchFleetCase(trimmed),
        fetchFleetCaseTimeline(trimmed),
      ]);
      setDetail(nextDetail);
      setTimeline(nextTimeline);
      setCaseBundleExport(nextDetail.evidenceBundles[0] ?? null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load fleet case");
    } finally {
      setLoading(null);
    }
  }, []);

  const loadCases = useCallback(async () => {
    setLoading("cases");
    setError(null);
    try {
      const nextCases = await fetchFleetCases({
        ...(caseSearch.trim() && { query: caseSearch.trim() }),
        ...(caseStatusFilter !== "all" && { status: caseStatusFilter }),
        ...(caseSeverityFilter !== "all" && { severity: caseSeverityFilter }),
      });
      setCases(nextCases);
      setSelectedCaseIds((current) =>
        current.filter((caseId) => nextCases.some((candidate) => candidate.id === caseId)),
      );
      const currentStillExists = nextCases.some((candidate) => candidate.id === selectedCaseId);
      if (nextCases.length > 0 && !currentStillExists) {
        await loadCase(nextCases[0].id);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load fleet cases");
    } finally {
      setLoading(null);
    }
  }, [caseSearch, caseSeverityFilter, caseStatusFilter, loadCase, selectedCaseId]);

  useEffect(() => {
    void loadCases();
    // Initial load only; manual refresh handles later changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const createCase = useCallback(async () => {
    const title = caseTitle.trim();
    if (!title) return;
    setLoading("create");
    setError(null);
    try {
      const created = await createFleetCase({
        title,
        ...(caseSummary.trim() && { summary: caseSummary.trim() }),
        severity: caseSeverity,
        tags: ["case-management"],
        metadata: { source: "control-console" },
      });
      setCases((current) =>
        current.some((candidate) => candidate.id === created.id) ? current : [created, ...current],
      );
      setCaseTitle("");
      setCaseSummary("");
      await loadCase(created.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create fleet case");
    } finally {
      setLoading(null);
    }
  }, [caseSeverity, caseSummary, caseTitle, loadCase]);

  const exportBundle = useCallback(async () => {
    const caseId = selectedCase?.id;
    if (!caseId) return;
    setLoading("export");
    setError(null);
    try {
      const bundle = await exportFleetCaseEvidenceBundle(caseId, { includeRawEnvelopes: true });
      setCaseBundleExport(bundle);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to export case evidence bundle");
    } finally {
      setLoading(null);
    }
  }, [selectedCase]);

  const downloadBundle = useCallback(async () => {
    if (!caseBundleExport?.exportId) return;
    setLoading("download");
    setError(null);
    try {
      const bundle = await downloadFleetEvidenceBundle(caseBundleExport.exportId);
      downloadBlob(bundle, `${caseBundleExport.exportId}.zip`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to download evidence bundle");
    } finally {
      setLoading(null);
    }
  }, [caseBundleExport]);

  const saveStatus = useCallback(async () => {
    const caseId = selectedCase?.id;
    if (!caseId) return;
    setLoading("status");
    setError(null);
    try {
      const updated = await updateFleetCase(caseId, { status: caseStatusDraft });
      setCases((current) =>
        current.map((candidate) => (candidate.id === updated.id ? updated : candidate)),
      );
      setDetail((current) => (current ? { ...current, case: updated } : current));
      const nextTimeline = await fetchFleetCaseTimeline(updated.id);
      setTimeline(nextTimeline);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update case status");
    } finally {
      setLoading(null);
    }
  }, [caseStatusDraft, selectedCase]);

  const toggleCaseSelection = useCallback((caseId: string) => {
    setSelectedCaseIds((current) =>
      current.includes(caseId)
        ? current.filter((selectedCaseId) => selectedCaseId !== caseId)
        : [...current, caseId],
    );
  }, []);

  const applyBulkStatus = useCallback(async () => {
    if (selectedCaseIds.length === 0) return;
    setLoading("bulkStatus");
    setError(null);
    try {
      const updatedCases = await bulkUpdateFleetCaseStatus(selectedCaseIds, bulkStatusDraft);
      const updatedById = new Map(updatedCases.map((fleetCase) => [fleetCase.id, fleetCase]));
      setCases((current) =>
        current.map((fleetCase) => updatedById.get(fleetCase.id) ?? fleetCase),
      );
      setDetail((current) => {
        if (!current) return current;
        const updated = updatedById.get(current.case.id);
        return updated ? { ...current, case: updated } : current;
      });
      if (selectedCaseId && updatedById.has(selectedCaseId)) {
        const nextTimeline = await fetchFleetCaseTimeline(selectedCaseId);
        setTimeline(nextTimeline);
      }
      setSelectedCaseIds([]);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to bulk update case status");
    } finally {
      setLoading(null);
    }
  }, [bulkStatusDraft, selectedCaseId, selectedCaseIds]);

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
            Fleet investigation ledger
          </p>
          <h1
            className="font-display"
            style={{ fontSize: "1.85rem", fontWeight: 700, letterSpacing: 0, marginTop: 2 }}
          >
            Fleet Cases
          </h1>
        </div>

        <div className="flex flex-wrap gap-2">
          <GlassButton variant="primary" onClick={loadCases} disabled={loading != null}>
            {loading === "cases" ? "Refreshing..." : "Refresh Cases"}
          </GlassButton>
          <GlassButton onClick={exportBundle} disabled={!selectedCase || loading != null}>
            {loading === "export" ? "Exporting..." : "Export Bundle"}
          </GlassButton>
          <GlassButton onClick={downloadBundle} disabled={!caseBundleExport || loading != null}>
            {loading === "download" ? "Downloading..." : "Download Bundle"}
          </GlassButton>
        </div>
      </header>

      {error && <StatusBanner message={error} />}

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-[minmax(320px,0.78fr)_minmax(0,1.22fr)]">
        <section className="space-y-5">
          <Plate className="p-4">
            <PanelTitle eyebrow="New case" title="Create Remote Case" />
            <div className="mt-4 space-y-3">
              <TextField label="Case title" value={caseTitle} onChange={setCaseTitle} />
              <TextField label="Case summary" value={caseSummary} onChange={setCaseSummary} />
              <label className="flex flex-col gap-1">
                <span className="font-mono uppercase tracking-[0.12em] text-[0.65rem] text-[rgba(154,167,181,0.62)]">
                  Severity
                </span>
                <select
                  aria-label="Severity"
                  value={caseSeverity}
                  onChange={(event) => setCaseSeverity(event.target.value as FleetCaseSeverity)}
                  className="glass-input font-mono rounded-md px-3 py-2 text-sm outline-none"
                  style={{ color: "var(--text)" }}
                >
                  <option value="low">low</option>
                  <option value="medium">medium</option>
                  <option value="high">high</option>
                  <option value="critical">critical</option>
                </select>
              </label>
              <GlassButton
                variant="primary"
                onClick={createCase}
                disabled={loading != null || !caseTitle.trim()}
              >
                {loading === "create" ? "Creating..." : "Create Case"}
              </GlassButton>
            </div>
          </Plate>

          <Plate className="p-4" goldEdge>
            <PanelTitle
              eyebrow="Remote cases"
              title={`${filteredCases.length} / ${cases.length} Case${cases.length === 1 ? "" : "s"}`}
            />
            <div className="mt-4 grid grid-cols-1 gap-3 lg:grid-cols-[minmax(0,1fr)_160px_160px]">
              <TextField label="Case search" value={caseSearch} onChange={setCaseSearch} />
              <label className="flex flex-col gap-1">
                <span className="font-mono uppercase tracking-[0.12em] text-[0.65rem] text-[rgba(154,167,181,0.62)]">
                  Case status filter
                </span>
                <select
                  aria-label="Case status filter"
                  value={caseStatusFilter}
                  onChange={(event) => setCaseStatusFilter(event.target.value as CaseStatusFilter)}
                  className="glass-input font-mono rounded-md px-3 py-2 text-sm outline-none"
                  style={{ color: "var(--text)" }}
                >
                  <option value="all">all</option>
                  <option value="open">open</option>
                  <option value="in_progress">in_progress</option>
                  <option value="contained">contained</option>
                  <option value="closed">closed</option>
                </select>
              </label>
              <label className="flex flex-col gap-1">
                <span className="font-mono uppercase tracking-[0.12em] text-[0.65rem] text-[rgba(154,167,181,0.62)]">
                  Case severity filter
                </span>
                <select
                  aria-label="Case severity filter"
                  value={caseSeverityFilter}
                  onChange={(event) =>
                    setCaseSeverityFilter(event.target.value as CaseSeverityFilter)
                  }
                  className="glass-input font-mono rounded-md px-3 py-2 text-sm outline-none"
                  style={{ color: "var(--text)" }}
                >
                  <option value="all">all</option>
                  <option value="low">low</option>
                  <option value="medium">medium</option>
                  <option value="high">high</option>
                  <option value="critical">critical</option>
                </select>
              </label>
            </div>
            <div className="mt-4 grid grid-cols-1 gap-3 lg:grid-cols-[120px_160px_minmax(120px,auto)] lg:items-end">
              <SmallFact label="Selected" value={numberText(selectedCaseIds.length)} />
              <label className="flex flex-col gap-1">
                <span className="font-mono uppercase tracking-[0.12em] text-[0.65rem] text-[rgba(154,167,181,0.62)]">
                  Bulk case status
                </span>
                <select
                  aria-label="Bulk case status"
                  value={bulkStatusDraft}
                  onChange={(event) => setBulkStatusDraft(event.target.value as FleetCaseStatus)}
                  className="glass-input font-mono rounded-md px-3 py-2 text-sm outline-none"
                  style={{ color: "var(--text)" }}
                >
                  <option value="open">open</option>
                  <option value="in_progress">in_progress</option>
                  <option value="contained">contained</option>
                  <option value="closed">closed</option>
                </select>
              </label>
              <GlassButton
                onClick={applyBulkStatus}
                disabled={loading != null || selectedCaseIds.length === 0}
              >
                {loading === "bulkStatus" ? "Applying..." : "Apply Bulk Status"}
              </GlassButton>
            </div>
            <div className="mt-4 max-h-[520px] space-y-2 overflow-y-auto pr-1">
              {filteredCases.length === 0 ? (
                <EmptyState
                  text={
                    loading === "cases"
                      ? "Loading cases"
                      : cases.length === 0
                        ? "No cases loaded"
                        : "No cases match filters"
                  }
                />
              ) : (
                filteredCases.map((fleetCase) => (
                  <CaseRow
                    key={fleetCase.id}
                    fleetCase={fleetCase}
                    selected={fleetCase.id === selectedCaseId}
                    selectedForBulk={selectedCaseIdSet.has(fleetCase.id)}
                    onToggleBulk={() => toggleCaseSelection(fleetCase.id)}
                    onSelect={() => void loadCase(fleetCase.id)}
                    loading={loading === "detail"}
                  />
                ))
              )}
            </div>
          </Plate>
        </section>

        <section className="space-y-5">
          <div className="grid grid-cols-1 gap-3 md:grid-cols-4">
            <Metric label="Case" value={selectedCase?.id ?? "-"} />
            <Metric label="Severity" value={selectedCase?.severity ?? "-"} />
            <Metric label="Status" value={selectedCase?.status ?? "-"} />
            <Metric label="Bundles" value={numberText(detail?.evidenceBundles.length)} />
          </div>

          <Plate className="p-4">
            <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
              <PanelTitle
                eyebrow={selectedCase ? "Selected case" : "No selection"}
                title={selectedCase?.title ?? "Select a case"}
              />
              {selectedCase && <StatusPill value={selectedCase.id} />}
            </div>
            {selectedCase?.summary && (
              <p className="mt-3 text-sm" style={{ color: "rgba(229,231,235,0.74)" }}>
                {selectedCase.summary}
              </p>
            )}
            {selectedCase && (
              <div className="mt-4 flex flex-col gap-2 sm:flex-row sm:items-end">
                <label className="flex min-w-[180px] flex-col gap-1">
                  <span className="font-mono uppercase tracking-[0.12em] text-[0.65rem] text-[rgba(154,167,181,0.62)]">
                    Case status
                  </span>
                  <select
                    aria-label="Case status"
                    value={caseStatusDraft}
                    onChange={(event) => setCaseStatusDraft(event.target.value as FleetCaseStatus)}
                    className="glass-input font-mono rounded-md px-3 py-2 text-sm outline-none"
                    style={{ color: "var(--text)" }}
                  >
                    <option value="open">open</option>
                    <option value="in_progress">in_progress</option>
                    <option value="contained">contained</option>
                    <option value="closed">closed</option>
                  </select>
                </label>
                <GlassButton
                  onClick={saveStatus}
                  disabled={loading != null || caseStatusDraft === selectedCase.status}
                >
                  {loading === "status" ? "Saving..." : "Save Status"}
                </GlassButton>
              </div>
            )}
            <div className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-3">
              <SmallFact label="Created By" value={selectedCase?.createdBy ?? "-"} />
              <SmallFact label="Updated" value={formatDateTime(selectedCase?.updatedAt)} />
              <SmallFact label="Tags" value={selectedCase?.tags.join(", ") || "-"} />
            </div>
          </Plate>

          <div className="grid grid-cols-1 gap-5 xl:grid-cols-2">
            <Plate className="p-4">
              <PanelTitle
                eyebrow="Artifacts"
                title={`${detail?.artifacts.length ?? 0} Reference${detail?.artifacts.length === 1 ? "" : "s"}`}
              />
              <div className="mt-4 space-y-2">
                {!detail || detail.artifacts.length === 0 ? (
                  <EmptyState text="No artifacts on selected case" />
                ) : (
                  detail.artifacts.map((artifact) => (
                    <ArtifactRow key={artifact.id} artifact={artifact} />
                  ))
                )}
              </div>
            </Plate>

            <Plate className="p-4">
              <PanelTitle eyebrow="Timeline" title={`${timeline.length} Event${timeline.length === 1 ? "" : "s"}`} />
              <div className="mt-4 space-y-2">
                {timeline.length === 0 ? (
                  <EmptyState text="No timeline events loaded" />
                ) : (
                  timeline.map((event) => <TimelineRow key={event.id} event={event} />)
                )}
              </div>
            </Plate>
          </div>

          <Plate className="p-4">
            <PanelTitle eyebrow="Signed export" title="Case Evidence Bundle" />
            <div className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-4">
              <SmallFact label="Export ID" value={caseBundleExport?.exportId ?? "-"} mono />
              <SmallFact label="Status" value={caseBundleExport?.status ?? "-"} />
              <SmallFact label="Size" value={byteText(caseBundleExport?.sizeBytes)} />
              <SmallFact label="SHA-256" value={caseBundleExport?.sha256 ?? "-"} mono />
            </div>
          </Plate>
        </section>
      </div>
    </div>
  );
}

function CaseRow({
  fleetCase,
  selected,
  selectedForBulk,
  onToggleBulk,
  onSelect,
  loading,
}: {
  fleetCase: FleetCase;
  selected: boolean;
  selectedForBulk: boolean;
  onToggleBulk: () => void;
  onSelect: () => void;
  loading: boolean;
}) {
  return (
    <div
      className="w-full rounded-md p-3 text-left"
      style={{
        border: selected ? "1px solid rgba(214,177,90,0.42)" : "1px solid rgba(27,34,48,0.78)",
        background: selected ? "rgba(214,177,90,0.08)" : "rgba(0,0,0,0.18)",
        color: "var(--text)",
      }}
    >
      <div className="flex items-start gap-3">
        <input
          type="checkbox"
          aria-label={`Select case ${fleetCase.title}`}
          checked={selectedForBulk}
          onChange={onToggleBulk}
          className="mt-1 h-4 w-4"
        />
        <button
          type="button"
          onClick={onSelect}
          disabled={loading && selected}
          className="min-w-0 flex-1 text-left"
          style={{
            color: "var(--text)",
            cursor: loading && selected ? "wait" : "pointer",
          }}
        >
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <p className="font-display truncate" style={{ fontSize: "0.98rem", fontWeight: 700 }}>
                {fleetCase.title}
              </p>
              <p
                className="font-mono mt-1 break-all"
                style={{ color: "rgba(154,167,181,0.62)", fontSize: "0.66rem" }}
              >
                {fleetCase.id}
              </p>
            </div>
            <StatusPill value={fleetCase.severity} />
          </div>
          <div className="mt-3 grid grid-cols-2 gap-2">
            <SmallFact label="Status" value={fleetCase.status} />
            <SmallFact label="Updated" value={formatDateTime(fleetCase.updatedAt)} />
          </div>
        </button>
      </div>
    </div>
  );
}

function ArtifactRow({ artifact }: { artifact: FleetCaseDetail["artifacts"][number] }) {
  return (
    <div
      className="rounded-md p-3"
      style={{ border: "1px solid rgba(27,34,48,0.78)", background: "rgba(0,0,0,0.18)" }}
    >
      <div className="flex flex-col gap-2 md:flex-row md:items-start md:justify-between">
        <div className="min-w-0">
          <p className="font-mono break-all" style={{ color: "var(--text)", fontSize: "0.78rem" }}>
            {artifact.artifactKind}
          </p>
          <p
            className="font-mono mt-1 break-all"
            style={{ color: "rgba(154,167,181,0.62)", fontSize: "0.66rem" }}
          >
            {artifact.artifactId}
          </p>
        </div>
        <StatusPill value={artifact.addedBy} />
      </div>
      {artifact.summary && (
        <p className="mt-3 text-sm" style={{ color: "rgba(229,231,235,0.7)" }}>
          {artifact.summary}
        </p>
      )}
    </div>
  );
}

function TimelineRow({ event }: { event: CaseTimelineEvent }) {
  return (
    <div
      className="rounded-md p-3"
      style={{ border: "1px solid rgba(27,34,48,0.78)", background: "rgba(0,0,0,0.18)" }}
    >
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="font-mono" style={{ color: "var(--text)", fontSize: "0.78rem" }}>
            {event.eventKind}
          </p>
          <p
            className="font-mono mt-1"
            style={{ color: "rgba(154,167,181,0.62)", fontSize: "0.66rem" }}
          >
            {event.actorId}
          </p>
        </div>
        <StatusPill value={formatDateTime(event.createdAt)} />
      </div>
    </div>
  );
}

function TextField({
  label,
  value,
  onChange,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
}) {
  return (
    <label className="flex flex-col gap-1">
      <span className="font-mono uppercase tracking-[0.12em] text-[0.65rem] text-[rgba(154,167,181,0.62)]">
        {label}
      </span>
      <input
        aria-label={label}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="glass-input font-mono rounded-md px-3 py-2 text-sm outline-none"
        style={{ color: "var(--text)", minWidth: 0 }}
      />
    </label>
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

function Metric({ label, value }: { label: string; value: string }) {
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
        className="font-display mt-2 truncate"
        style={{ position: "relative", color: "var(--text)", fontSize: "1.08rem", fontWeight: 700 }}
      >
        {value}
      </p>
    </Plate>
  );
}

function SmallFact({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="min-w-0">
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
      <p
        className={mono ? "font-mono mt-1 break-all" : "font-body mt-1 truncate"}
        style={{ color: "var(--text)", fontSize: mono ? "0.72rem" : "0.88rem" }}
      >
        {value}
      </p>
    </div>
  );
}

function StatusPill({ value }: { value: string }) {
  return (
    <span
      className="font-mono rounded-md px-3 py-1"
      style={{
        border: "1px solid rgba(214,177,90,0.36)",
        background: "rgba(214,177,90,0.08)",
        color: "var(--gold)",
        fontSize: "0.72rem",
        alignSelf: "flex-start",
      }}
    >
      {value}
    </span>
  );
}

function EmptyState({ text }: { text: string }) {
  return (
    <div
      className="rounded-md px-3 py-5 text-center font-mono"
      style={{
        border: "1px dashed rgba(154,167,181,0.24)",
        color: "rgba(154,167,181,0.48)",
        fontSize: "0.72rem",
      }}
    >
      {text}
    </div>
  );
}

function StatusBanner({ message }: { message: string }) {
  return (
    <div
      className="glass-panel"
      style={{
        background: "rgba(194,59,59,0.08)",
        border: "1px solid rgba(194,59,59,0.3)",
        color: "rgba(255,220,220,0.9)",
        padding: "10px 12px",
        fontSize: "0.8rem",
      }}
    >
      {message}
    </div>
  );
}

function numberText(value: number | undefined): string {
  return value == null ? "-" : String(value);
}

function byteText(value: number | null | undefined): string {
  return value == null ? "-" : `${value} bytes`;
}

function formatDateTime(value: string | undefined): string {
  return value ? new Date(value).toLocaleString() : "-";
}
