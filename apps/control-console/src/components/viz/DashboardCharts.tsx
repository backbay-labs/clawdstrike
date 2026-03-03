import type { SSEEvent } from "../../hooks/useSSE";
import { Plate } from "../ui";
import { DecisionDonut } from "./DecisionDonut";
import { GuardHeatmap } from "./GuardHeatmap";
import { ViolationSparkline } from "./ViolationSparkline";

export function DashboardCharts({ events }: { events: SSEEvent[] }) {
  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
      <Plate className="p-4">
        <span
          className="font-mono relative z-10"
          style={{
            display: "block",
            fontSize: 10,
            textTransform: "uppercase",
            letterSpacing: "0.12em",
            color: "rgba(214,177,90,0.7)",
            marginBottom: 8,
          }}
        >
          Violations — Last Hour
        </span>
        <div style={{ position: "relative", zIndex: 2 }}>
          <ViolationSparkline events={events} />
        </div>
      </Plate>
      <Plate
        className="p-4"
        style={{ display: "flex", alignItems: "center", justifyContent: "center" }}
      >
        <div style={{ position: "relative", zIndex: 2 }}>
          <DecisionDonut events={events} />
        </div>
      </Plate>
      <Plate className="p-4">
        <span
          className="font-mono relative z-10"
          style={{
            display: "block",
            fontSize: 10,
            textTransform: "uppercase",
            letterSpacing: "0.12em",
            color: "rgba(214,177,90,0.7)",
            marginBottom: 8,
          }}
        >
          Guard Activity
        </span>
        <div style={{ position: "relative", zIndex: 2 }}>
          <GuardHeatmap events={events} />
        </div>
      </Plate>
    </div>
  );
}
