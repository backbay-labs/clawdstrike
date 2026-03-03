/**
 * Module stub tests
 *
 * Verifies that all modules export correctly and stubs throw appropriate errors.
 */

import { describe, expect, test } from "bun:test"

// Import all modules to verify they compile
import { Router } from "../src/router"
import { Dispatcher } from "../src/dispatcher"
import { Workcell, PoolConfig } from "../src/workcell"
import { Verifier } from "../src/verifier"
import { Speculate } from "../src/speculate"
import { PatchLifecycle } from "../src/patch"
import { Beads } from "../src/beads"
import { Telemetry } from "../src/telemetry"
import { tools, getTool, dispatchTool, speculateTool, gateTool } from "../src/tools"

// Import adapters and gates
import { adapters, getAdapter } from "../src/dispatcher/adapters"
import { gates, getGate } from "../src/verifier/gates"

describe("Module exports", () => {
  test("Router namespace exists", () => {
    expect(Router).toBeDefined()
    expect(Router.route).toBeFunction()
    expect(Router.reroute).toBeFunction()
    expect(Router.evaluateRules).toBeFunction()
  })

  test("Dispatcher namespace exists", () => {
    expect(Dispatcher).toBeDefined()
    expect(Dispatcher.execute).toBeFunction()
    expect(Dispatcher.executeWithRetry).toBeFunction()
    expect(Dispatcher.getAvailableAdapters).toBeFunction()
  })

  test("Workcell namespace exists", () => {
    expect(Workcell).toBeDefined()
    expect(Workcell.acquire).toBeFunction()
    expect(Workcell.release).toBeFunction()
    expect(Workcell.status).toBeFunction()
    expect(Workcell.gc).toBeFunction()
    expect(Workcell.destroyAll).toBeFunction()
  })

  test("PoolConfig schema works", () => {
    const config = PoolConfig.parse({})
    expect(config.minSize).toBe(2)
    expect(config.maxSize).toBe(10)
    expect(config.preWarm).toBe(true)
  })

  test("Verifier namespace exists", () => {
    expect(Verifier).toBeDefined()
    expect(Verifier.run).toBeFunction()
    expect(Verifier.runGate).toBeFunction()
    expect(Verifier.getAvailableGates).toBeFunction()
    expect(Verifier.calculateScore).toBeFunction()
  })

  test("Speculate namespace exists", () => {
    expect(Speculate).toBeDefined()
    expect(Speculate.run).toBeFunction()
    expect(Speculate.vote).toBeFunction()
    expect(Speculate.voteFirstPass).toBeFunction()
    expect(Speculate.voteBestScore).toBeFunction()
  })

  test("PatchLifecycle namespace exists", () => {
    expect(PatchLifecycle).toBeDefined()
    expect(PatchLifecycle.capture).toBeFunction()
    expect(PatchLifecycle.stage).toBeFunction()
    expect(PatchLifecycle.approve).toBeFunction()
    expect(PatchLifecycle.merge).toBeFunction()
  })

  test("Beads namespace exists", () => {
    expect(Beads).toBeDefined()
    expect(Beads.init).toBeFunction()
    expect(Beads.query).toBeFunction()
    expect(Beads.getReady).toBeFunction()
    expect(Beads.create).toBeFunction()
    expect(Beads.updateStatus).toBeFunction()
  })

  test("Telemetry namespace exists", () => {
    expect(Telemetry).toBeDefined()
    expect(Telemetry.init).toBeFunction()
    expect(Telemetry.startRollout).toBeFunction()
    expect(Telemetry.recordEvent).toBeFunction()
    expect(Telemetry.completeRollout).toBeFunction()
  })
})

describe("Tools", () => {
  test("tools array contains all tools", () => {
    expect(tools).toHaveLength(3)
    expect(tools.map((t) => t.name)).toEqual(["dispatch", "speculate", "gate"])
  })

  test("getTool returns correct tool", () => {
    expect(getTool("dispatch")).toBe(dispatchTool)
    expect(getTool("speculate")).toBe(speculateTool)
    expect(getTool("gate")).toBe(gateTool)
    expect(getTool("nonexistent")).toBeUndefined()
  })

  test("dispatchTool has correct schema", () => {
    expect(dispatchTool.name).toBe("dispatch")
    expect(dispatchTool.parameters.required).toContain("prompt")
    expect(dispatchTool.parameters.properties).toHaveProperty("toolchain")
  })

  test("speculateTool has correct schema", () => {
    expect(speculateTool.name).toBe("speculate")
    expect(speculateTool.parameters.required).toContain("prompt")
    expect(speculateTool.parameters.properties).toHaveProperty("voteStrategy")
  })

  test("gateTool has correct schema", () => {
    expect(gateTool.name).toBe("gate")
    expect(gateTool.parameters.required).toEqual([])
    expect(gateTool.parameters.properties).toHaveProperty("gates")
  })
})

describe("Adapters", () => {
  test("all adapters registered", () => {
    expect(Object.keys(adapters)).toEqual(["codex", "claude", "opencode", "crush"])
  })

  test("getAdapter returns correct adapter", () => {
    expect(getAdapter("codex")?.info.id).toBe("codex")
    expect(getAdapter("claude")?.info.id).toBe("claude")
    expect(getAdapter("opencode")?.info.id).toBe("opencode")
    expect(getAdapter("crush")?.info.id).toBe("crush")
    expect(getAdapter("nonexistent")).toBeUndefined()
  })

  test("adapters have correct auth types", () => {
    expect(getAdapter("codex")?.info.authType).toBe("oauth")
    expect(getAdapter("claude")?.info.authType).toBe("oauth")
    expect(getAdapter("opencode")?.info.authType).toBe("api_key")
    expect(getAdapter("crush")?.info.authType).toBe("api_key")
  })
})

describe("Gates", () => {
  test("all gates registered", () => {
    expect(Object.keys(gates)).toEqual(["pytest", "mypy", "ruff", "clawdstrike"])
  })

  test("getGate returns correct gate", () => {
    expect(getGate("pytest")?.info.id).toBe("pytest")
    expect(getGate("mypy")?.info.id).toBe("mypy")
    expect(getGate("ruff")?.info.id).toBe("ruff")
    expect(getGate("nonexistent")).toBeUndefined()
  })

  test("gates have correct critical flags", () => {
    expect(getGate("pytest")?.info.critical).toBe(true)
    expect(getGate("mypy")?.info.critical).toBe(false)
    expect(getGate("ruff")?.info.critical).toBe(false)
  })
})

describe("Implemented modules", () => {
  test("Router.route returns routing decision", async () => {
    const task = {
      prompt: "test",
      context: { cwd: "/", projectId: "p" },
    }
    const decision = await Router.route(task)
    expect(decision.toolchain).toBeDefined()
    expect(decision.strategy).toBeDefined()
    expect(decision.gates).toBeDefined()
  })

  test("Verifier.runGate returns result for unknown gate", async () => {
    const workcell = {
      id: "123e4567-e89b-12d3-a456-426614174000",
      name: "wc",
      directory: "/",
      branch: "main",
      status: "warm" as const,
      projectId: "p",
      createdAt: 0,
      useCount: 0,
    }
    const result = await Verifier.runGate(workcell, "unknown")
    expect(result.passed).toBe(false)
    expect(result.output).toContain("not found")
  })
})

describe("Stub errors", () => {
  test("Dispatcher.execute returns error when adapter unavailable", async () => {
    const result = await Dispatcher.execute({
      task: { prompt: "test", context: { cwd: "/", projectId: "p" } },
      workcell: {
        id: "123e4567-e89b-12d3-a456-426614174000",
        name: "wc",
        directory: "/",
        branch: "main",
        status: "warm",
        projectId: "p",
        createdAt: 0,
        useCount: 0,
      },
      toolchain: "codex",
    })
    // When adapter is not available (no CLI/auth), it should return error
    expect(result.success).toBe(false)
    expect(result.error).toBeDefined()
  })

  test("Workcell.acquire throws when git root not found", async () => {
    await expect(Workcell.acquire("project", undefined, { cwd: "/nonexistent" })).rejects.toThrow()
  })
})
