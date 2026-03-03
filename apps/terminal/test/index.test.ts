/**
 * Main entry point tests
 *
 * Verifies that the main index exports everything correctly.
 */

import { describe, expect, test } from "bun:test"

// Test main exports
import {
  // Types
  TaskId,
  WorkcellId,
  BeadId,
  Toolchain,
  TaskInput,
  TaskStatus,
  ExecutionResult,
  GateResult,
  GateResults,
  WorkcellInfo,
  WorkcellStatus,
  SpeculationConfig,
  RoutingDecision,
  Patch,
  Bead,
  // Modules
  Router,
  Dispatcher,
  Workcell,
  Verifier,
  Speculate,
  PatchLifecycle,
  Beads,
  Telemetry,
  // Tools
  tools,
  getTool,
  registerTools,
  // Version and init
  VERSION,
  init,
  shutdown,
} from "../src"

describe("Main exports", () => {
  test("VERSION is defined", () => {
    expect(VERSION).toBe("0.1.0")
  })

  test("Type schemas are exported", () => {
    expect(TaskId).toBeDefined()
    expect(WorkcellId).toBeDefined()
    expect(BeadId).toBeDefined()
    expect(Toolchain).toBeDefined()
    expect(TaskInput).toBeDefined()
    expect(TaskStatus).toBeDefined()
    expect(ExecutionResult).toBeDefined()
    expect(GateResult).toBeDefined()
    expect(GateResults).toBeDefined()
    expect(WorkcellInfo).toBeDefined()
    expect(WorkcellStatus).toBeDefined()
    expect(SpeculationConfig).toBeDefined()
    expect(RoutingDecision).toBeDefined()
    expect(Patch).toBeDefined()
    expect(Bead).toBeDefined()
  })

  test("Namespace modules are exported", () => {
    expect(Router).toBeDefined()
    expect(Dispatcher).toBeDefined()
    expect(Workcell).toBeDefined()
    expect(Verifier).toBeDefined()
    expect(Speculate).toBeDefined()
    expect(PatchLifecycle).toBeDefined()
    expect(Beads).toBeDefined()
    expect(Telemetry).toBeDefined()
  })

  test("Tools are exported", () => {
    expect(tools).toBeDefined()
    expect(tools).toHaveLength(3)
    expect(getTool).toBeFunction()
    expect(registerTools).toBeFunction()
  })

  test("init and shutdown are exported", () => {
    expect(init).toBeFunction()
    expect(shutdown).toBeFunction()
  })

  test("init and shutdown work", async () => {
    // init should complete without error
    await expect(init()).resolves.toBeUndefined()
    // shutdown should complete without error
    await expect(shutdown()).resolves.toBeUndefined()
  })
})

describe("Type inference", () => {
  test("TaskInput type can be inferred", () => {
    const task: TaskInput = {
      prompt: "Test task",
      context: {
        cwd: "/project",
        projectId: "test",
      },
    }

    // This test verifies TypeScript types work correctly
    expect(task.prompt).toBe("Test task")
  })

  test("Toolchain type is correct", () => {
    const toolchain: Toolchain = "codex"
    expect(["codex", "claude", "opencode", "crush"]).toContain(toolchain)
  })
})
