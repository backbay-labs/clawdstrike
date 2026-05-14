import React from "react";
import { act, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";

import {
  SwarmBoardProvider,
  useSwarmBoard,
} from "@/features/swarm/stores/swarm-board-store";
import type { SwarmBoardNodeData, SwarmNodeType } from "@/features/swarm/swarm-board-types";

// ---------------------------------------------------------------------------
// Mock @xyflow/react
// ---------------------------------------------------------------------------

vi.mock("@xyflow/react", () => ({
  ReactFlow: ({ children }: { children?: React.ReactNode }) => <div>{children}</div>,
  Background: () => null,
  Controls: () => null,
  MiniMap: () => null,
  Panel: ({ children }: { children?: React.ReactNode }) => <div>{children}</div>,
  ReactFlowProvider: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  useNodesState: (initial: unknown[]) => [initial, vi.fn(), vi.fn()],
  useEdgesState: (initial: unknown[]) => [initial, vi.fn(), vi.fn()],
  useReactFlow: () => ({
    setViewport: vi.fn(),
    getViewport: () => ({ x: 0, y: 0, zoom: 1 }),
    fitView: vi.fn(),
    zoomIn: vi.fn(),
    zoomOut: vi.fn(),
    getNodes: () => [],
  }),
  MarkerType: { ArrowClosed: "arrowclosed" },
  Position: { Left: "left", Right: "right", Top: "top", Bottom: "bottom" },
  Handle: () => null,
}));

// ---------------------------------------------------------------------------
// Mock motion/react
// ---------------------------------------------------------------------------

vi.mock("motion/react", () => {
  const MotionComponent = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
    (props, ref) => <div ref={ref} {...props} />,
  );
  MotionComponent.displayName = "MotionComponent";
  return {
    AnimatePresence: ({ children }: { children: React.ReactNode }) => <>{children}</>,
    motion: {
      aside: MotionComponent,
      div: MotionComponent,
    },
  };
});

// ---------------------------------------------------------------------------
// Mock detection workflow stores (IndexedDB not available in tests)
// ---------------------------------------------------------------------------

vi.mock("@/lib/workbench/detection-workflow/evidence-pack-store", () => ({
  getEvidencePackStore: () => ({
    init: vi.fn().mockResolvedValue(undefined),
    getPack: vi.fn().mockResolvedValue({
      id: "ep-001",
      documentId: "doc-001",
      fileType: "sigma_rule",
      title: "Test Evidence Pack",
      createdAt: "2026-03-15T10:00:00Z",
      datasets: {
        positive: [{ id: "i1" }, { id: "i2" }, { id: "i3" }],
        negative: [{ id: "i4" }],
        regression: [],
        false_positive: [],
      },
      redactionState: "redacted",
    }),
  }),
  EvidencePackStore: vi.fn(),
}));

vi.mock("@/lib/workbench/detection-workflow/lab-run-store", () => ({
  getLabRunStore: () => ({
    init: vi.fn().mockResolvedValue(undefined),
    getRun: vi.fn().mockResolvedValue({
      id: "lr-001",
      documentId: "doc-001",
      evidencePackId: "ep-001",
      fileType: "sigma_rule",
      startedAt: "2026-03-15T10:00:00Z",
      completedAt: "2026-03-15T10:00:01Z",
      summary: {
        totalCases: 10,
        passed: 8,
        failed: 2,
        matched: 6,
        missed: 1,
        falsePositives: 1,
        engine: "native",
      },
      results: [],
      explainability: [],
    }),
  }),
  LabRunStore: vi.fn(),
}));

vi.mock("@/lib/workbench/detection-workflow/publication-store", () => ({
  getPublicationStore: () => ({
    init: vi.fn().mockResolvedValue(undefined),
    getManifest: vi.fn().mockResolvedValue({
      id: "pub-001",
      documentId: "doc-001",
      sourceFileType: "sigma_rule",
      target: "native_policy",
      createdAt: "2026-03-15T10:00:00Z",
      sourceHash: "sha256:src123abc",
      outputHash: "sha256:out456def",
      validationSnapshot: { valid: true, diagnosticCount: 0 },
      runSnapshot: { evidencePackId: "ep-001", labRunId: "lr-001", passed: true },
      coverageSnapshot: null,
      converter: { id: "sigma-to-policy", version: "1.2.0" },
      signer: null,
      provenance: null,
      receiptId: "rcpt-001",
      deployResponse: { success: true, hash: "deploy-hash", destination: "fleet-prod" },
    }),
    getOutputContent: vi.fn().mockResolvedValue("converted publication output"),
  }),
  PublicationStore: vi.fn(),
}));

const STORAGE_KEY = "clawdstrike_workbench_swarm_board";

// ---------------------------------------------------------------------------
// Import the real component after mocks are set up
// ---------------------------------------------------------------------------

import { SwarmBoardInspector } from "../swarm-board-inspector";

// ---------------------------------------------------------------------------
// Harness — wraps provider and exposes add/select actions
// ---------------------------------------------------------------------------

function DetectionInspectorHarness() {
  const { state, addNode, selectNode, clearBoard } = useSwarmBoard();

  return (
    <div>
      <pre data-testid="inspector-open">{String(state.inspectorOpen)}</pre>
      <pre data-testid="node-count">{state.nodes.length}</pre>

      {/* Detection rule node */}
      <button
        type="button"
        data-testid="add-detection-rule"
        onClick={() =>
          addNode({
            nodeType: "artifact",
            title: "Sigma: T1059.001",
            position: { x: 0, y: 0 },
            data: {
              status: "idle",
              artifactKind: "detection_rule",
              documentId: "doc-001",
              format: "sigma_rule",
              publishState: "validated",
              coverageDelta: { added: ["T1059.001"], removed: ["T1055.003"] },
            },
          })
        }
      >
        add-detection-rule
      </button>

      {/* Evidence pack node */}
      <button
        type="button"
        data-testid="add-evidence-pack"
        onClick={() =>
          addNode({
            nodeType: "artifact",
            title: "Test Evidence",
            position: { x: 200, y: 0 },
            data: {
              status: "idle",
              artifactKind: "evidence_pack",
              documentId: "doc-001",
              evidencePackId: "ep-001",
              format: "sigma_rule",
            },
          })
        }
      >
        add-evidence-pack
      </button>

      {/* Lab run node */}
      <button
        type="button"
        data-testid="add-lab-run"
        onClick={() =>
          addNode({
            nodeType: "artifact",
            title: "Lab: 8/10 passed",
            position: { x: 400, y: 0 },
            data: {
              status: "completed",
              artifactKind: "lab_run",
              documentId: "doc-001",
              labRunId: "lr-001",
              evidencePackId: "ep-001",
              format: "sigma_rule",
            },
          })
        }
      >
        add-lab-run
      </button>

      {/* Publication manifest node */}
      <button
        type="button"
        data-testid="add-publication"
        onClick={() =>
          addNode({
            nodeType: "artifact",
            title: "Publish: native_policy",
            position: { x: 0, y: 200 },
            data: {
              status: "idle",
              artifactKind: "publication_manifest",
              documentId: "doc-001",
              publicationId: "pub-001",
              format: "sigma_rule",
              publishState: "deployed",
            },
          })
        }
      >
        add-publication
      </button>

      {/* Missing artifact node (no valid IDs) */}
      <button
        type="button"
        data-testid="add-missing-artifact"
        onClick={() =>
          addNode({
            nodeType: "artifact",
            title: "Missing Pack",
            position: { x: 200, y: 200 },
            data: {
              status: "idle",
              artifactKind: "evidence_pack",
              documentId: "doc-999",
              // No evidencePackId — triggers missing artifact path
            },
          })
        }
      >
        add-missing-artifact
      </button>

      <button
        type="button"
        data-testid="select-first"
        onClick={() => {
          if (state.nodes.length > 0) selectNode(state.nodes[0].id);
        }}
      >
        select-first
      </button>
      <button type="button" data-testid="clear-board" onClick={clearBoard}>
        clear
      </button>

      <SwarmBoardInspector />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function seedEmptyBoard(): void {
  localStorage.setItem(
    STORAGE_KEY,
    JSON.stringify({
      boardId: "b-test",
      repoRoot: "",
      nodes: [
        {
          id: "__placeholder__",
          type: "note",
          position: { x: 0, y: 0 },
          data: { title: "__placeholder__", status: "idle", nodeType: "note", createdAt: 0 },
        },
      ],
      edges: [],
    }),
  );
}

function renderDetectionInspector() {
  seedEmptyBoard();
  const result = render(
    <MemoryRouter>
      <SwarmBoardProvider>
        <DetectionInspectorHarness />
      </SwarmBoardProvider>
    </MemoryRouter>,
  );
  act(() => {
    screen.getByTestId("clear-board").click();
  });
  return result;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

beforeEach(() => {
  localStorage.clear();
});

describe("Detection Inspector — Detection Rule", () => {
  it("renders format badge and publish state", async () => {
    renderDetectionInspector();

    act(() => {
      screen.getByTestId("add-detection-rule").click();
    });
    act(() => {
      screen.getByTestId("select-first").click();
    });

    const inspector = screen.getByLabelText("Node inspector");

    // Format badge
    expect(inspector).toHaveTextContent("Sigma");

    // Publish state badge
    expect(inspector).toHaveTextContent("validated");

    // Document ID
    expect(inspector).toHaveTextContent("doc-001");

    // Coverage delta
    expect(inspector).toHaveTextContent("T1059.001");
    expect(inspector).toHaveTextContent("T1055.003");
  });

  it("shows detection rule footer actions", () => {
    renderDetectionInspector();

    act(() => {
      screen.getByTestId("add-detection-rule").click();
    });
    act(() => {
      screen.getByTestId("select-first").click();
    });

    expect(screen.getByLabelText("Open in Editor")).toBeInTheDocument();
    expect(screen.getByLabelText("Run Lab")).toBeInTheDocument();
  });
});

describe("Detection Inspector — Evidence Pack", () => {
  it("shows dataset counts after loading", async () => {
    renderDetectionInspector();

    act(() => {
      screen.getByTestId("add-evidence-pack").click();
    });
    act(() => {
      screen.getByTestId("select-first").click();
    });

    // Initially shows loading skeleton
    // After async load, should show pack data
    // Use findBy to wait for async render
    const datasetCounts = await screen.findByTestId("dataset-counts");
    expect(datasetCounts).toHaveTextContent("4 items");
    expect(datasetCounts).toHaveTextContent("3 pos");
    expect(datasetCounts).toHaveTextContent("1 neg");
  });
});

describe("Detection Inspector — Lab Run", () => {
  it("shows summary after loading", async () => {
    renderDetectionInspector();

    act(() => {
      screen.getByTestId("add-lab-run").click();
    });
    act(() => {
      screen.getByTestId("select-first").click();
    });

    const summary = await screen.findByTestId("lab-run-summary");
    expect(summary).toHaveTextContent("8 passed");
    expect(summary).toHaveTextContent("2 failed");
    expect(summary).toHaveTextContent("6 matched");
  });

  it("shows lab run footer actions", async () => {
    renderDetectionInspector();

    act(() => {
      screen.getByTestId("add-lab-run").click();
    });
    act(() => {
      screen.getByTestId("select-first").click();
    });

    // Wait for async load
    await screen.findByTestId("lab-run-summary");

    expect(screen.getByLabelText("View in Lab")).toBeInTheDocument();
    expect(screen.getByLabelText("Open in Editor")).toBeInTheDocument();
  });
});

describe("Detection Inspector — Publication Manifest", () => {
  it("shows hashes after loading", async () => {
    renderDetectionInspector();

    act(() => {
      screen.getByTestId("add-publication").click();
    });
    act(() => {
      screen.getByTestId("select-first").click();
    });

    const hashes = await screen.findByTestId("publication-hashes");
    expect(hashes).toHaveTextContent("src: sha256:src123abc");
    expect(hashes).toHaveTextContent("out: sha256:out456def");
  });

  it("shows deploy info when present", async () => {
    renderDetectionInspector();

    act(() => {
      screen.getByTestId("add-publication").click();
    });
    act(() => {
      screen.getByTestId("select-first").click();
    });

    // Wait for load
    await screen.findByTestId("publication-hashes");

    const inspector = screen.getByLabelText("Node inspector");
    expect(inspector).toHaveTextContent("fleet-prod");
    expect(inspector).toHaveTextContent("success");
  });

  it("shows publication footer actions", async () => {
    renderDetectionInspector();

    act(() => {
      screen.getByTestId("add-publication").click();
    });
    act(() => {
      screen.getByTestId("select-first").click();
    });

    await screen.findByTestId("publication-hashes");

    expect(screen.getByLabelText("View Manifest")).toBeInTheDocument();
    expect(screen.getByLabelText("Verify")).toBeInTheDocument();
  });
});

describe("Detection Inspector — Missing Artifacts", () => {
  it("handles missing evidence pack gracefully", async () => {
    // Override the mock to return null for this test
    const { getEvidencePackStore } = await import(
      "@/lib/workbench/detection-workflow/evidence-pack-store"
    );
    const store = getEvidencePackStore();
    vi.mocked(store.getPack).mockResolvedValueOnce(null);

    renderDetectionInspector();

    act(() => {
      screen.getByTestId("add-missing-artifact").click();
    });
    act(() => {
      screen.getByTestId("select-first").click();
    });

    // Should show the missing artifact message
    const missing = await screen.findByTestId("missing-artifact");
    expect(missing).toHaveTextContent("not found or has been deleted");
  });
});
