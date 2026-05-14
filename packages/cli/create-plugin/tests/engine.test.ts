import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { writeProjectFile } from "../src/engine";
import { mkdtempSync, rmSync, existsSync, readFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

let tempDir: string;

beforeAll(() => {
  tempDir = mkdtempSync(join(tmpdir(), "clawdstrike-engine-test-"));
  // Pre-create src/ subdirectory for sub-path tests
  mkdirSync(join(tempDir, "src"), { recursive: true });
});

afterAll(() => {
  rmSync(tempDir, { recursive: true, force: true });
});

describe("writeProjectFile", () => {
  describe("valid paths", () => {
    it("writes a file at a normal relative path", async () => {
      await writeProjectFile(tempDir, "src/index.ts", "export default {};");
      const filePath = join(tempDir, "src/index.ts");
      expect(existsSync(filePath)).toBe(true);
      expect(readFileSync(filePath, "utf-8")).toBe("export default {};");
    });

    it("normalises src/../src/index.ts and stays within dir", async () => {
      await writeProjectFile(tempDir, "src/../src/index.ts", "normalised content");
      const filePath = join(tempDir, "src/index.ts");
      expect(existsSync(filePath)).toBe(true);
      expect(readFileSync(filePath, "utf-8")).toBe("normalised content");
    });
  });

  describe("path traversal rejection", () => {
    it("throws on ../../etc/passwd", async () => {
      await expect(
        writeProjectFile(tempDir, "../../etc/passwd", "malicious"),
      ).rejects.toThrow("Path traversal detected");
    });

    it("throws on ../sibling/file.txt", async () => {
      await expect(
        writeProjectFile(tempDir, "../sibling/file.txt", "escape"),
      ).rejects.toThrow("Path traversal detected");
    });
  });

  describe("edge cases", () => {
    it("empty filename resolves to the dir itself (no traversal)", async () => {
      // An empty filename resolves to the dir itself.
      // The guard allows resolved === dirResolved, so this should not throw
      // from the traversal check. It may fail at the fs level (writing to
      // a directory path), but the guard itself should pass.
      // We only assert the traversal guard does NOT fire.
      let traversalError = false;
      try {
        await writeProjectFile(tempDir, "", "content");
      } catch (err: unknown) {
        if (err instanceof Error && err.message.includes("Path traversal detected")) {
          traversalError = true;
        }
        // Other errors (e.g., EISDIR) are acceptable -- not a traversal
      }
      expect(traversalError).toBe(false);
    });

    it("overwrites an existing file without error", async () => {
      await writeProjectFile(tempDir, "src/index.ts", "first content");
      await writeProjectFile(tempDir, "src/index.ts", "second content");
      const filePath = join(tempDir, "src/index.ts");
      expect(readFileSync(filePath, "utf-8")).toBe("second content");
    });
  });
});
