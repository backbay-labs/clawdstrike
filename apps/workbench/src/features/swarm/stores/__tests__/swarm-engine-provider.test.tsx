import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SwarmEngineProvider, useSwarmEngine } from "../swarm-engine-provider";

const mockInitialize = vi.fn();
const mockShutdown = vi.fn();
const mockTaskGraphConfig = vi.fn();

vi.mock("@clawdstrike/swarm-engine", () => {
  class MockSwarmOrchestrator {
    initialize = mockInitialize;
    shutdown = mockShutdown;
  }

  class MockTypedEventEmitter {}
  class MockAgentRegistry {}
  class MockTaskGraph {
    constructor(
      _events: unknown,
      _registry: unknown,
      config?: unknown,
    ) {
      mockTaskGraphConfig(config);
    }
  }
  class MockTopologyManager {}

  return {
    SwarmOrchestrator: MockSwarmOrchestrator,
    TypedEventEmitter: MockTypedEventEmitter,
    AgentRegistry: MockAgentRegistry,
    TaskGraph: MockTaskGraph,
    TopologyManager: MockTopologyManager,
  };
});

function Probe() {
  const { mode, error } = useSwarmEngine();
  return <div data-testid="engine-state">{mode}:{error ?? "none"}</div>;
}

describe("SwarmEngineProvider", () => {
  let warnSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    mockInitialize.mockReset();
    mockShutdown.mockReset();
    mockTaskGraphConfig.mockReset();
    mockInitialize.mockImplementation(() => {
      throw new Error("engine exploded");
    });
    warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
  });

  afterEach(() => {
    warnSpy.mockRestore();
  });

  it("shuts down a partially initialized orchestrator when initialize throws", async () => {
    const { unmount } = render(
      <SwarmEngineProvider>
        <Probe />
      </SwarmEngineProvider>,
    );

    await waitFor(() => {
      expect(screen.getByTestId("engine-state").textContent).toBe("error:engine exploded");
    });

    expect(mockInitialize).toHaveBeenCalledTimes(1);
    expect(mockShutdown).toHaveBeenCalledTimes(1);
    expect(mockTaskGraphConfig).toHaveBeenCalledWith(
      expect.objectContaining({
        maxTasks: 200,
        defaultTimeoutMs: 300_000,
      }),
    );

    unmount();

    expect(mockShutdown).toHaveBeenCalledTimes(1);
  });
});
