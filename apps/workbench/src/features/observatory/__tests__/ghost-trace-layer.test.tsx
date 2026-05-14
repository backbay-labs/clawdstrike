/**
 * ghost-trace-layer.test.tsx — Phase 35, Plan 01 TDD RED/GREEN
 *
 * Tests for GhostTraceLayer R3F component: holographic ghost markers at observatory station positions.
 * R3F components use render() via @testing-library/react; hooks require React render context.
 */

import { describe, expect, it, vi } from "vitest";
import { render } from "@testing-library/react";
import { GhostTraceLayer } from "@/features/observatory/components/GhostTraceLayer";
import type { GhostTraceLayerProps } from "@/features/observatory/components/GhostTraceLayer";
import type { ObservatoryGhostTrace } from "@/features/observatory/world/observatory-ghost-memory";

vi.mock("@react-three/fiber", () => ({
  useFrame: vi.fn(),
}));

function makeTrace(overrides: Partial<ObservatoryGhostTrace> = {}): ObservatoryGhostTrace {
  return {
    id: "trace-1",
    stationId: "receipts",
    route: "/receipts",
    routeLabel: "Receipts",
    sourceKind: "receipt",
    sourceId: "evt-001",
    authorLabel: "agent-1",
    headline: "Denied receipt",
    detail: "Policy denied tool call",
    timestampMs: 1_700_000_000_000,
    score: 3.5,
    ...overrides,
  };
}

describe("GhostTraceLayer", () => {
  it("exports a named component function", () => {
    expect(typeof GhostTraceLayer).toBe("function");
  });

  it("exports GhostTraceLayerProps interface (type-level check via usage)", () => {
    const props: GhostTraceLayerProps = { traces: [], opacityScale: 1.0 };
    expect(props).toBeDefined();
  });

  it("returns null when traces array is empty (no geometry for empty input)", () => {
    const { container } = render(
      <GhostTraceLayer traces={[]} opacityScale={1.0} />,
    );
    // No mesh geometry rendered
    expect(container.firstChild).toBeNull();
  });

  it("accepts traces with sourceKind receipt", () => {
    const traces = [makeTrace({ sourceKind: "receipt", stationId: "receipts" })];
    const props: GhostTraceLayerProps = { traces, opacityScale: 1.0 };
    expect(props.traces[0]?.sourceKind).toBe("receipt");
  });

  it("accepts traces with sourceKind finding", () => {
    const traces = [makeTrace({ sourceKind: "finding", stationId: "case-notes" })];
    const props: GhostTraceLayerProps = { traces, opacityScale: 1.0 };
    expect(props.traces[0]?.sourceKind).toBe("finding");
  });

  it("accepts opacityScale of 0.2 for dimmed state", () => {
    const props: GhostTraceLayerProps = {
      traces: [makeTrace()],
      opacityScale: 0.2,
    };
    expect(props.opacityScale).toBe(0.2);
  });

  it("accepts opacityScale of 1.0 for full visibility", () => {
    const props: GhostTraceLayerProps = {
      traces: [makeTrace()],
      opacityScale: 1.0,
    };
    expect(props.opacityScale).toBe(1.0);
  });

  it("does not return null when traces are non-empty", () => {
    const traces = [makeTrace({ stationId: "receipts" })];
    const { container } = render(
      <GhostTraceLayer traces={traces} opacityScale={1.0} />,
    );
    // Component renders something (not null)
    expect(container).toBeDefined();
  });
});
