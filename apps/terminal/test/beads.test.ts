/**
 * Beads tests
 *
 * Tests for the Beads work graph integration.
 */

import { describe, expect, test, beforeEach, afterEach } from "bun:test"
import * as fs from "node:fs/promises"
import * as path from "node:path"
import * as os from "node:os"
import { Beads, JSONL } from "../src/beads"
import type { Bead, BeadId } from "../src/types"

// Create temp directory for tests
let tempDir: string

beforeEach(async () => {
  tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "clawdstrike-beads-test-"))
  Beads.reset()
})

afterEach(async () => {
  Beads.reset()
  await fs.rm(tempDir, { recursive: true, force: true })
})

// Helper to create a bead
function makeBead(overrides: Partial<Bead> = {}): Bead {
  return {
    id: "PROJ-1" as BeadId,
    title: "Test Issue",
    status: "open",
    createdAt: Date.now(),
    updatedAt: Date.now(),
    ...overrides,
  }
}

describe("JSONL", () => {
  describe("read/write", () => {
    test("reads empty file", async () => {
      await JSONL.init(tempDir)
      const issues = await JSONL.read(tempDir)
      expect(issues).toEqual([])
    })

    test("writes and reads issues", async () => {
      const issues = [
        makeBead({ id: "PROJ-1" as BeadId }),
        makeBead({ id: "PROJ-2" as BeadId, title: "Second Issue" }),
      ]

      await JSONL.write(tempDir, issues)
      const read = await JSONL.read(tempDir)

      expect(read).toHaveLength(2)
      expect(read[0].id).toBe("PROJ-1")
      expect(read[1].id).toBe("PROJ-2")
    })

    test("appends issue", async () => {
      await JSONL.init(tempDir)

      const issue1 = makeBead({ id: "PROJ-1" as BeadId })
      await JSONL.append(tempDir, issue1)

      const issue2 = makeBead({ id: "PROJ-2" as BeadId })
      await JSONL.append(tempDir, issue2)

      const read = await JSONL.read(tempDir)
      expect(read).toHaveLength(2)
    })

    test("updates issue", async () => {
      const issues = [makeBead({ id: "PROJ-1" as BeadId, title: "Original" })]
      await JSONL.write(tempDir, issues)

      const updated = await JSONL.update(tempDir, "PROJ-1" as BeadId, (issue) => ({
        ...issue,
        title: "Updated",
      }))

      expect(updated.title).toBe("Updated")

      const read = await JSONL.read(tempDir)
      expect(read[0].title).toBe("Updated")
    })

    test("update throws for non-existent issue", async () => {
      await JSONL.init(tempDir)

      expect(
        JSONL.update(tempDir, "PROJ-999" as BeadId, (i) => i)
      ).rejects.toThrow("Issue not found")
    })

    test("removes issue", async () => {
      const issues = [
        makeBead({ id: "PROJ-1" as BeadId }),
        makeBead({ id: "PROJ-2" as BeadId }),
      ]
      await JSONL.write(tempDir, issues)

      const removed = await JSONL.remove(tempDir, "PROJ-1" as BeadId)
      expect(removed).toBe(true)

      const read = await JSONL.read(tempDir)
      expect(read).toHaveLength(1)
      expect(read[0].id).toBe("PROJ-2")
    })

    test("remove returns false for non-existent issue", async () => {
      await JSONL.init(tempDir)

      const removed = await JSONL.remove(tempDir, "PROJ-999" as BeadId)
      expect(removed).toBe(false)
    })
  })
})

describe("Beads", () => {
  beforeEach(async () => {
    await Beads.init({ path: tempDir })
  })

  describe("init", () => {
    test("initializes beads", async () => {
      expect(Beads.isInitialized()).toBe(true)
    })

    test("creates issues file", async () => {
      const exists = await JSONL.exists(tempDir)
      expect(exists).toBe(true)
    })
  })

  describe("query", () => {
    test("returns empty for no issues", async () => {
      const issues = await Beads.query()
      expect(issues).toEqual([])
    })

    test("returns all issues", async () => {
      await JSONL.write(tempDir, [
        makeBead({ id: "PROJ-1" as BeadId }),
        makeBead({ id: "PROJ-2" as BeadId }),
      ])

      const issues = await Beads.query()
      expect(issues).toHaveLength(2)
    })

    test("filters by status", async () => {
      await JSONL.write(tempDir, [
        makeBead({ id: "PROJ-1" as BeadId, status: "open" }),
        makeBead({ id: "PROJ-2" as BeadId, status: "completed" }),
      ])

      const open = await Beads.query({ status: "open" })
      expect(open).toHaveLength(1)
      expect(open[0].id).toBe("PROJ-1")

      const completed = await Beads.query({ status: "completed" })
      expect(completed).toHaveLength(1)
      expect(completed[0].id).toBe("PROJ-2")
    })

    test("filters by multiple statuses", async () => {
      await JSONL.write(tempDir, [
        makeBead({ id: "PROJ-1" as BeadId, status: "open" }),
        makeBead({ id: "PROJ-2" as BeadId, status: "in_progress" }),
        makeBead({ id: "PROJ-3" as BeadId, status: "completed" }),
      ])

      const active = await Beads.query({ status: ["open", "in_progress"] })
      expect(active).toHaveLength(2)
    })

    test("filters by priority", async () => {
      await JSONL.write(tempDir, [
        makeBead({ id: "PROJ-1" as BeadId, priority: "p0" }),
        makeBead({ id: "PROJ-2" as BeadId, priority: "p2" }),
      ])

      const urgent = await Beads.query({ priority: "p0" })
      expect(urgent).toHaveLength(1)
      expect(urgent[0].id).toBe("PROJ-1")
    })

    test("filters by labels", async () => {
      await JSONL.write(tempDir, [
        makeBead({ id: "PROJ-1" as BeadId, labels: ["bug", "urgent"] }),
        makeBead({ id: "PROJ-2" as BeadId, labels: ["feature"] }),
      ])

      const bugs = await Beads.query({ labels: ["bug"] })
      expect(bugs).toHaveLength(1)
      expect(bugs[0].id).toBe("PROJ-1")
    })

    test("applies limit and offset", async () => {
      await JSONL.write(tempDir, [
        makeBead({ id: "PROJ-1" as BeadId }),
        makeBead({ id: "PROJ-2" as BeadId }),
        makeBead({ id: "PROJ-3" as BeadId }),
      ])

      const limited = await Beads.query({ limit: 2 })
      expect(limited).toHaveLength(2)

      const offset = await Beads.query({ offset: 1, limit: 2 })
      expect(offset).toHaveLength(2)
      expect(offset[0].id).toBe("PROJ-2")
    })
  })

  describe("get", () => {
    test("returns issue by ID", async () => {
      await JSONL.write(tempDir, [
        makeBead({ id: "PROJ-1" as BeadId, title: "Found" }),
      ])

      const issue = await Beads.get("PROJ-1" as BeadId)
      expect(issue).toBeDefined()
      expect(issue!.title).toBe("Found")
    })

    test("returns undefined for non-existent ID", async () => {
      const issue = await Beads.get("PROJ-999" as BeadId)
      expect(issue).toBeUndefined()
    })
  })

  describe("create", () => {
    test("creates new issue with auto-generated ID", async () => {
      const issue = await Beads.create({
        title: "New Issue",
        status: "open",
      })

      expect(issue.id).toBe("PROJ-1")
      expect(issue.title).toBe("New Issue")
      expect(issue.createdAt).toBeDefined()
    })

    test("increments ID from existing issues", async () => {
      await JSONL.write(tempDir, [
        makeBead({ id: "TEST-5" as BeadId }),
      ])

      const issue = await Beads.create({
        title: "New Issue",
        status: "open",
      })

      expect(issue.id).toBe("TEST-6")
    })
  })

  describe("updateStatus", () => {
    test("updates issue status", async () => {
      await JSONL.write(tempDir, [
        makeBead({ id: "PROJ-1" as BeadId, status: "open" }),
      ])

      const updated = await Beads.updateStatus("PROJ-1" as BeadId, "in_progress")
      expect(updated.status).toBe("in_progress")
    })

    test("sets closedAt when completing", async () => {
      await JSONL.write(tempDir, [
        makeBead({ id: "PROJ-1" as BeadId, status: "open" }),
      ])

      const updated = await Beads.updateStatus("PROJ-1" as BeadId, "completed")
      expect(updated.closedAt).toBeDefined()
    })
  })

  describe("update", () => {
    test("updates issue fields", async () => {
      await JSONL.write(tempDir, [
        makeBead({ id: "PROJ-1" as BeadId, title: "Original" }),
      ])

      const updated = await Beads.update("PROJ-1" as BeadId, {
        title: "Updated",
        priority: "p0",
      })

      expect(updated.title).toBe("Updated")
      expect(updated.priority).toBe("p0")
    })

    test("cannot change ID", async () => {
      await JSONL.write(tempDir, [
        makeBead({ id: "PROJ-1" as BeadId }),
      ])

      const updated = await Beads.update("PROJ-1" as BeadId, {
        id: "PROJ-999" as BeadId,
      })

      expect(updated.id).toBe("PROJ-1")
    })
  })

  describe("getReady", () => {
    test("returns open issues", async () => {
      await JSONL.write(tempDir, [
        makeBead({ id: "PROJ-1" as BeadId, status: "open" }),
        makeBead({ id: "PROJ-2" as BeadId, status: "in_progress" }),
        makeBead({ id: "PROJ-3" as BeadId, status: "open" }),
      ])

      const ready = await Beads.getReady()
      expect(ready).toHaveLength(2)
      expect(ready[0].reasoning).toContain("open")
    })

    test("infers toolchain from labels", async () => {
      await JSONL.write(tempDir, [
        makeBead({
          id: "PROJ-1" as BeadId,
          status: "open",
          labels: ["dk_risk:high"],
        }),
        makeBead({
          id: "PROJ-2" as BeadId,
          status: "open",
          labels: ["dk_size:xs"],
        }),
      ])

      const ready = await Beads.getReady()

      const highRisk = ready.find((r) => r.id === "PROJ-1")
      expect(highRisk?.suggestedToolchain).toBe("codex")

      const small = ready.find((r) => r.id === "PROJ-2")
      expect(small?.suggestedToolchain).toBe("opencode")
    })
  })
})
