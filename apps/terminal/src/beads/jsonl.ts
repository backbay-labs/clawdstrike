/**
 * JSONL - Line-delimited JSON storage for Beads
 *
 * Handles reading and writing the .beads/issues.jsonl file format.
 */

import * as fs from "node:fs/promises"
import * as path from "node:path"
import type { Bead, BeadId } from "../types"

const ISSUES_FILE = "issues.jsonl"

/**
 * JSONL namespace - File operations for beads storage
 */
export namespace JSONL {
  /**
   * Get the full path to issues.jsonl
   */
  export function getIssuesPath(beadsDir: string): string {
    return path.join(beadsDir, ISSUES_FILE)
  }

  /**
   * Read all issues from JSONL file
   */
  export async function read(beadsDir: string): Promise<Bead[]> {
    const filePath = getIssuesPath(beadsDir)

    try {
      const content = await Bun.file(filePath).text()
      return content
        .split("\n")
        .filter((line) => line.trim())
        .map((line) => JSON.parse(line) as Bead)
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") {
        return []
      }
      throw e
    }
  }

  /**
   * Write all issues to JSONL file (overwrites)
   */
  export async function write(beadsDir: string, issues: Bead[]): Promise<void> {
    const filePath = getIssuesPath(beadsDir)
    await fs.mkdir(path.dirname(filePath), { recursive: true })

    const content = issues.map((issue) => JSON.stringify(issue)).join("\n")

    await Bun.write(filePath, content ? content + "\n" : "")
  }

  /**
   * Append a single issue to JSONL file
   */
  export async function append(beadsDir: string, issue: Bead): Promise<void> {
    const filePath = getIssuesPath(beadsDir)
    await fs.mkdir(path.dirname(filePath), { recursive: true })

    const file = Bun.file(filePath)
    const exists = await file.exists()

    if (exists) {
      // Append to existing file
      const existingContent = await file.text()
      const newContent = existingContent.endsWith("\n")
        ? existingContent + JSON.stringify(issue) + "\n"
        : existingContent + "\n" + JSON.stringify(issue) + "\n"
      await Bun.write(filePath, newContent)
    } else {
      await Bun.write(filePath, JSON.stringify(issue) + "\n")
    }
  }

  /**
   * Update a single issue in JSONL file
   */
  export async function update(
    beadsDir: string,
    id: BeadId,
    updater: (issue: Bead) => Bead
  ): Promise<Bead> {
    const issues = await read(beadsDir)
    const index = issues.findIndex((i) => i.id === id)

    if (index === -1) {
      throw new Error(`Issue not found: ${id}`)
    }

    const updated = updater(issues[index])
    issues[index] = {
      ...updated,
      updatedAt: Date.now(),
    }

    await write(beadsDir, issues)
    return issues[index]
  }

  /**
   * Delete a single issue from JSONL file
   */
  export async function remove(beadsDir: string, id: BeadId): Promise<boolean> {
    const issues = await read(beadsDir)
    const filtered = issues.filter((i) => i.id !== id)

    if (filtered.length === issues.length) {
      return false // Issue not found
    }

    await write(beadsDir, filtered)
    return true
  }

  /**
   * Check if issues file exists
   */
  export async function exists(beadsDir: string): Promise<boolean> {
    const filePath = getIssuesPath(beadsDir)
    return await Bun.file(filePath).exists()
  }

  /**
   * Initialize empty issues file
   */
  export async function init(beadsDir: string): Promise<void> {
    const filePath = getIssuesPath(beadsDir)
    await fs.mkdir(path.dirname(filePath), { recursive: true })

    if (!(await Bun.file(filePath).exists())) {
      await Bun.write(filePath, "")
    }
  }
}

export default JSONL
