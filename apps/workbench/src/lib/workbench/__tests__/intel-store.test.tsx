import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { IntelProvider, useIntel } from "../intel-store";
import type { Intel } from "../sentinel-types";

const STORAGE_KEY = "clawdstrike_workbench_intel";

function makeIntel(overrides: Partial<Intel> = {}): Intel {
  return {
    id: "int_local_01",
    type: "advisory",
    title: "Credential reuse across runtimes",
    description: "Multiple runtimes attempted the same credential replay path.",
    content: {
      kind: "advisory",
      narrative: "Operators should rotate the affected credentials and review agent scope.",
      recommendations: ["Rotate credentials", "Audit agent sessions"],
    },
    derivedFrom: ["fnd_01"],
    confidence: 0.93,
    tags: ["credential", "replay"],
    mitre: [
      {
        techniqueId: "T1078",
        techniqueName: "Valid Accounts",
        tactic: "Defense Evasion",
      },
    ],
    shareability: "private",
    signature: "",
    signerPublicKey: "",
    receipt: {
      id: "rcpt_01",
      timestamp: new Date(1_715_000_000_000).toISOString(),
      verdict: "allow",
      guard: "intel_forge",
      policyName: "intel_promotion",
      action: {
        type: "file_access",
        target: "intel:int_local_01",
      },
      evidence: {
        content_hash: "pending",
      },
      signature: "",
      publicKey: "",
      valid: false,
    },
    author: "feedfacefeedface",
    createdAt: 1_715_000_000_000,
    version: 1,
    ...overrides,
  };
}

function IntelHarness() {
  const {
    localIntel,
    swarmIntel,
    swarmIntelRecords,
    activeIntel,
    upsertLocalIntel,
    ingestSwarmIntel,
    setActiveIntel,
    getIntelById,
    getSwarmIntelRecord,
    getSwarmIntelRecords,
    listIntelBySource,
  } = useIntel();

  return (
    <>
      <button
        data-testid="add-local"
        onClick={() =>
          upsertLocalIntel(
            makeIntel({
              id: "int_local_01",
              title: "Local Intel",
            }),
          )
        }
      >
        add local
      </button>
      <button
        data-testid="ingest-swarm"
        onClick={() =>
          ingestSwarmIntel({
            swarmId: "swm_alpha",
            publishedBy: "deadbeefdeadbeef",
            receivedAt: 1_716_000_000_000,
            intel: makeIntel({
              id: "int_swarm_01",
              title: "Swarm Intel",
              shareability: "swarm",
              author: "deadbeefdeadbeef",
            }),
          })
        }
      >
        ingest swarm
      </button>
      <button
        data-testid="ingest-shared-alpha"
        onClick={() =>
          ingestSwarmIntel({
            swarmId: "swm_alpha",
            publishedBy: "alphaalphaalpha1",
            receivedAt: 1_716_000_000_010,
            intel: makeIntel({
              id: "int_shared_01",
              title: "Shared Intel",
              shareability: "swarm",
            }),
          })
        }
      >
        ingest shared alpha
      </button>
      <button
        data-testid="ingest-shared-bravo"
        onClick={() =>
          ingestSwarmIntel({
            swarmId: "swm_bravo",
            publishedBy: "bravobravobravo2",
            receivedAt: 1_716_000_000_020,
            intel: makeIntel({
              id: "int_shared_01",
              title: "Shared Intel",
              shareability: "swarm",
            }),
          })
        }
      >
        ingest shared bravo
      </button>
      <button data-testid="set-active" onClick={() => setActiveIntel("int_swarm_01")}>
        set active
      </button>
      <pre data-testid="snapshot">
        {JSON.stringify({
          localTitles: localIntel.map((intel) => intel.title),
          swarmTitles: swarmIntel.map((intel) => intel.title),
          localIds: listIntelBySource("local").map((intel) => intel.id),
          swarmIds: listIntelBySource("swarm").map((intel) => intel.id),
          activeTitle: activeIntel?.title ?? null,
          lookupTitle: getIntelById("int_swarm_01")?.title ?? null,
          swarmRecordCount: swarmIntelRecords.length,
          swarmMeta: getSwarmIntelRecord("int_swarm_01")
            ? {
                swarmId: getSwarmIntelRecord("int_swarm_01")?.swarmId,
                publishedBy: getSwarmIntelRecord("int_swarm_01")?.publishedBy,
              }
            : null,
          sharedIntelSwarmIds:
            getSwarmIntelRecords("int_shared_01")?.map((record) => record.swarmId) ?? [],
        })}
      </pre>
    </>
  );
}

afterEach(() => {
  vi.useRealTimers();
  localStorage.clear();
});

describe("intel-store", () => {
  it("persists local and swarm intel and restores source-backed queries", () => {
    vi.useFakeTimers();

    const { unmount } = render(
      <IntelProvider>
        <IntelHarness />
      </IntelProvider>,
    );

    fireEvent.click(screen.getByTestId("add-local"));
    fireEvent.click(screen.getByTestId("ingest-swarm"));
    fireEvent.click(screen.getByTestId("set-active"));

    expect(JSON.parse(screen.getByTestId("snapshot").textContent ?? "{}")).toMatchObject({
      localTitles: ["Local Intel"],
      swarmTitles: ["Swarm Intel"],
      localIds: ["int_local_01"],
      swarmIds: ["int_swarm_01"],
      activeTitle: "Swarm Intel",
      lookupTitle: "Swarm Intel",
      swarmMeta: {
        swarmId: "swm_alpha",
        publishedBy: "deadbeefdeadbeef",
      },
    });

    act(() => {
      vi.advanceTimersByTime(500);
    });

    const persisted = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "{}");
    expect(persisted).toMatchObject({
      activeIntelId: "int_swarm_01",
    });
    expect(persisted.localIntel).toHaveLength(1);
    expect(persisted.localIntel[0]).toMatchObject({
      id: "int_local_01",
      title: "Local Intel",
    });
    expect(persisted.swarmIntel).toHaveLength(1);
    expect(persisted.swarmIntel[0]).toMatchObject({
      swarmId: "swm_alpha",
      publishedBy: "deadbeefdeadbeef",
      intel: {
        id: "int_swarm_01",
        title: "Swarm Intel",
      },
    });

    unmount();

    render(
      <IntelProvider>
        <IntelHarness />
      </IntelProvider>,
    );

    expect(JSON.parse(screen.getByTestId("snapshot").textContent ?? "{}")).toMatchObject({
      localTitles: ["Local Intel"],
      swarmTitles: ["Swarm Intel"],
      activeTitle: "Swarm Intel",
      lookupTitle: "Swarm Intel",
    });
  });

  it("preserves per-swarm provenance when the same intel arrives from multiple swarms", () => {
    render(
      <IntelProvider>
        <IntelHarness />
      </IntelProvider>,
    );

    fireEvent.click(screen.getByTestId("ingest-shared-alpha"));
    fireEvent.click(screen.getByTestId("ingest-shared-bravo"));

    expect(JSON.parse(screen.getByTestId("snapshot").textContent ?? "{}")).toMatchObject({
      swarmRecordCount: 2,
      sharedIntelSwarmIds: ["swm_bravo", "swm_alpha"],
    });
  });
});
