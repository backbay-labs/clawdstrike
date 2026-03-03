/**
 * Router tests
 *
 * Tests for the routing rules engine and Router namespace.
 */

import { describe, expect, test } from "bun:test"
import { Router } from "../src/router"
import { DEFAULT_RULES, matchesRule, evaluateRules, mergeActions, isValidToolchain } from "../src/router/rules"
import type { TaskInput } from "../src/types"
import type { RoutingRule } from "../src/router"

// Helper to create minimal task input
function makeTask(overrides: Partial<TaskInput> = {}): TaskInput {
  return {
    prompt: "test prompt",
    context: {
      cwd: "/test",
      projectId: "test-project",
    },
    ...overrides,
  }
}

describe("Router Rules", () => {
  describe("matchesRule", () => {
    test("matches hint rule with wildcard", () => {
      const rule: RoutingRule = {
        name: "hint-test",
        priority: 100,
        match: { hint: "*" },
        action: {},
      }

      const taskWithHint = makeTask({ hint: "codex" })
      const taskWithoutHint = makeTask({})

      expect(matchesRule(taskWithHint, rule)).toBe(true)
      expect(matchesRule(taskWithoutHint, rule)).toBe(false)
    })

    test("matches specific hint", () => {
      const rule: RoutingRule = {
        name: "claude-hint",
        priority: 100,
        match: { hint: "claude" },
        action: {},
      }

      expect(matchesRule(makeTask({ hint: "claude" }), rule)).toBe(true)
      expect(matchesRule(makeTask({ hint: "codex" }), rule)).toBe(false)
      expect(matchesRule(makeTask({}), rule)).toBe(false)
    })

    test("matches labels", () => {
      const rule: RoutingRule = {
        name: "high-risk",
        priority: 100,
        match: { labels: ["dk_risk:high"] },
        action: {},
      }

      expect(matchesRule(makeTask({ labels: ["dk_risk:high"] }), rule)).toBe(true)
      expect(matchesRule(makeTask({ labels: ["dk_risk:high", "other"] }), rule)).toBe(true)
      expect(matchesRule(makeTask({ labels: ["dk_risk:low"] }), rule)).toBe(false)
      expect(matchesRule(makeTask({}), rule)).toBe(false)
    })

    test("matches multiple labels (all must match)", () => {
      const rule: RoutingRule = {
        name: "multi-label",
        priority: 100,
        match: { labels: ["dk_risk:high", "dk_size:xs"] },
        action: {},
      }

      expect(matchesRule(makeTask({ labels: ["dk_risk:high", "dk_size:xs"] }), rule)).toBe(true)
      expect(matchesRule(makeTask({ labels: ["dk_risk:high"] }), rule)).toBe(false)
      expect(matchesRule(makeTask({ labels: ["dk_size:xs"] }), rule)).toBe(false)
    })

    test("matches file patterns", () => {
      const rule: RoutingRule = {
        name: "python-files",
        priority: 100,
        match: { filePatterns: ["**/*.py"] },
        action: {},
      }

      expect(
        matchesRule(makeTask({ context: { cwd: "/", projectId: "p", files: ["foo.py"] } }), rule)
      ).toBe(true)
      expect(
        matchesRule(makeTask({ context: { cwd: "/", projectId: "p", files: ["src/main.py"] } }), rule)
      ).toBe(true)
      expect(
        matchesRule(makeTask({ context: { cwd: "/", projectId: "p", files: ["foo.ts"] } }), rule)
      ).toBe(false)
      expect(matchesRule(makeTask({}), rule)).toBe(false)
    })

    test("matches prompt patterns", () => {
      const rule: RoutingRule = {
        name: "refactor-prompt",
        priority: 100,
        match: { promptPatterns: ["refactor", "rewrite"] },
        action: {},
      }

      expect(matchesRule(makeTask({ prompt: "Please refactor this code" }), rule)).toBe(true)
      expect(matchesRule(makeTask({ prompt: "Rewrite the function" }), rule)).toBe(true)
      expect(matchesRule(makeTask({ prompt: "Add a new feature" }), rule)).toBe(false)
    })

    test("matches context size", () => {
      const rule: RoutingRule = {
        name: "small-prompt",
        priority: 100,
        match: { contextSize: { min: 10, max: 50 } },
        action: {},
      }

      expect(matchesRule(makeTask({ prompt: "a".repeat(30) }), rule)).toBe(true)
      expect(matchesRule(makeTask({ prompt: "a".repeat(5) }), rule)).toBe(false)
      expect(matchesRule(makeTask({ prompt: "a".repeat(100) }), rule)).toBe(false)
    })
  })

  describe("mergeActions", () => {
    test("higher priority takes precedence", () => {
      const actions = [
        { priority: 50, action: { toolchain: "claude" } },
        { priority: 100, action: { toolchain: "codex" } },
      ]

      const merged = mergeActions(actions)
      expect(merged.toolchain).toBe("codex")
    })

    test("lower priority fills missing fields", () => {
      const actions = [
        { priority: 100, action: { toolchain: "codex" } },
        { priority: 50, action: { toolchain: "claude", retries: 3 } },
      ]

      const merged = mergeActions(actions)
      expect(merged.toolchain).toBe("codex")
      expect(merged.retries).toBe(3)
    })

    test("gates accumulate", () => {
      const actions = [
        { priority: 100, action: { gates: ["pytest"] } },
        { priority: 50, action: { gatesAdd: ["mypy", "ruff"] } },
      ]

      const merged = mergeActions(actions)
      expect(merged.gates).toContain("pytest")
      expect(merged.gates).toContain("mypy")
      expect(merged.gates).toContain("ruff")
    })

    test("gatesRemove removes gates", () => {
      const actions = [
        { priority: 100, action: { gates: ["pytest", "mypy", "ruff"] } },
        { priority: 50, action: { gatesRemove: ["ruff"] } },
      ]

      const merged = mergeActions(actions)
      expect(merged.gates).toContain("pytest")
      expect(merged.gates).toContain("mypy")
      expect(merged.gates).not.toContain("ruff")
    })
  })

  describe("evaluateRules", () => {
    test("applies matching rules in priority order", () => {
      const task = makeTask({ labels: ["dk_risk:high"] })
      const rules: RoutingRule[] = [
        {
          name: "default",
          priority: 10,
          match: {},
          action: { toolchain: "claude", retries: 1 },
        },
        {
          name: "high-risk",
          priority: 100,
          match: { labels: ["dk_risk:high"] },
          action: { toolchain: "codex", retries: 3 },
        },
      ]

      const result = evaluateRules(task, rules)
      expect(result.toolchain).toBe("codex")
      expect(result.retries).toBe(3)
    })

    test("hint-override rule uses task hint as toolchain", () => {
      const task = makeTask({ hint: "opencode" })
      const result = evaluateRules(task, DEFAULT_RULES)
      expect(result.toolchain).toBe("opencode")
    })
  })

  describe("isValidToolchain", () => {
    test("validates known toolchains", () => {
      expect(isValidToolchain("codex")).toBe(true)
      expect(isValidToolchain("claude")).toBe(true)
      expect(isValidToolchain("opencode")).toBe(true)
      expect(isValidToolchain("crush")).toBe(true)
      expect(isValidToolchain("invalid")).toBe(false)
      expect(isValidToolchain("")).toBe(false)
    })
  })
})

describe("Router namespace", () => {
  describe("route", () => {
    test("returns routing decision with default config", async () => {
      const task = makeTask()
      const decision = await Router.route(task)

      expect(decision.taskId).toBeDefined()
      expect(decision.toolchain).toBe("claude") // default
      expect(decision.strategy).toBe("single")
      expect(decision.gates).toEqual(["pytest", "mypy", "ruff"])
      expect(decision.retries).toBe(2)
      expect(decision.priority).toBe(50)
    })

    test("uses task ID if provided", async () => {
      const taskId = crypto.randomUUID()
      const task = makeTask({ id: taskId })
      const decision = await Router.route(task)

      expect(decision.taskId).toBe(taskId)
    })

    test("respects hint override", async () => {
      const task = makeTask({ hint: "opencode" })
      const decision = await Router.route(task)

      expect(decision.toolchain).toBe("opencode")
    })

    test("applies high-risk speculate rule", async () => {
      const task = makeTask({ labels: ["dk_risk:high"] })
      const decision = await Router.route(task)

      expect(decision.toolchain).toBe("codex")
      expect(decision.strategy).toBe("speculate")
      expect(decision.speculation).toBeDefined()
      expect(decision.speculation?.count).toBe(3)
      expect(decision.speculation?.toolchains).toContain("codex")
      expect(decision.speculation?.voteStrategy).toBe("first_pass")
    })

    test("applies small-fast-path rule", async () => {
      const task = makeTask({ labels: ["dk_size:xs"] })
      const decision = await Router.route(task)

      expect(decision.toolchain).toBe("opencode")
      expect(decision.strategy).toBe("single")
      expect(decision.gates).toContain("ruff")
      expect(decision.retries).toBe(1)
    })
  })

  describe("reroute", () => {
    test("returns null when no reroute possible", async () => {
      const task = makeTask()
      // Use a custom config with only critical gates to ensure gate reduction is exhausted
      const config = {
        rules: [],
        defaults: {
          toolchain: "claude" as const,
          gates: ["pytest"], // Only critical gate, can't reduce further
          retries: 1,
        },
      }
      const previousResult = {
        taskId: "test-task",
        workcellId: "test-workcell",
        success: false,
        toolchain: "crush" as const, // Last in fallback order
        output: "failed",
        telemetry: { startedAt: 0, completedAt: 0 },
      }

      const decision = await Router.reroute(task, previousResult, config)
      expect(decision).toBeNull()
    })

    test("tries next toolchain on toolchain error", async () => {
      const task = makeTask()
      const previousResult = {
        taskId: "test-task",
        workcellId: "test-workcell",
        success: false,
        toolchain: "codex" as const,
        output: "",
        error: "Toolchain not available",
        telemetry: { startedAt: 0, completedAt: 0 },
      }

      const decision = await Router.reroute(task, previousResult)
      expect(decision).not.toBeNull()
      expect(decision?.toolchain).toBe("claude") // next in fallback order
    })

    test("reduces gates on gate failure", async () => {
      const task = makeTask()
      const previousResult = {
        taskId: "test-task",
        workcellId: "test-workcell",
        success: false,
        toolchain: "claude" as const,
        output: "mypy failed",
        telemetry: { startedAt: 0, completedAt: 0 },
      }

      const decision = await Router.reroute(task, previousResult)
      expect(decision).not.toBeNull()
      expect(decision?.gates).toEqual(["pytest"]) // only critical gates
    })
  })

  describe("getDefaultConfig", () => {
    test("returns default configuration", () => {
      const config = Router.getDefaultConfig()
      expect(config.defaults.toolchain).toBe("claude")
      expect(config.defaults.gates).toEqual(["pytest", "mypy", "ruff"])
      expect(config.defaults.retries).toBe(2)
    })
  })
})
