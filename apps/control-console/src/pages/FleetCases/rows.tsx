import {
  type CaseTimelineEvent,
  type FleetCase,
  type FleetCaseDetail,
} from "../../api/client";
import { SmallFact, StatusPill } from "./display";
import { formatDateTime } from "./utils";

export function CaseRow({
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

export function ArtifactRow({ artifact }: { artifact: FleetCaseDetail["artifacts"][number] }) {
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

export function TimelineRow({ event }: { event: CaseTimelineEvent }) {
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
