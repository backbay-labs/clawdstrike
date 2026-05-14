import { describe, expect, it } from "vitest";
import {
  deriveSearchRootPath,
  getProjectPathBasename,
  getProjectPathDirname,
  isValidProjectBasename,
  replaceProjectPathBasename,
  resolveProjectPath,
  stripProjectRoot,
} from "../resolve-project-path";

describe("resolve-project-path", () => {
  it("derives a real search root from absolute workspace file paths", () => {
    expect(
      deriveSearchRootPath("workspace", [
        "/repo/policies/example.yml",
        "/repo/rules/detections.yml",
      ], [
        "policies/example.yml",
        "rules/detections.yml",
      ]),
    ).toBe("/repo");
  });

  it("derives the workspace root from a single absolute file and relative project paths", () => {
    expect(
      deriveSearchRootPath(
        "workspace",
        ["/repo/policies/example.yml"],
        ["policies/example.yml", "rules/detections.yml"],
      ),
    ).toBe("/repo");
  });

  it("preserves Windows absolute paths when replacing a file basename", () => {
    expect(
      replaceProjectPathBasename("C:\\repo\\rules\\example.yml", "renamed.yml"),
    ).toBe("C:\\repo\\rules\\renamed.yml");
  });

  it("returns a parent directory for mixed-separator paths", () => {
    expect(getProjectPathDirname("rules/example.yml")).toBe("rules");
    expect(getProjectPathDirname("C:\\repo\\rules\\example.yml")).toBe("C:\\repo\\rules");
  });

  it("extracts basenames across path styles", () => {
    expect(getProjectPathBasename("rules/example.yml")).toBe("example.yml");
    expect(getProjectPathBasename("C:\\repo\\rules\\example.yml")).toBe("example.yml");
  });

  it("normalizes relative paths when stripping the project root", () => {
    expect(
      stripProjectRoot("C:\\repo", "C:\\repo\\rules\\example.yml"),
    ).toBe("rules/example.yml");
  });

  it("normalizes resolved Windows project paths to workspace-style separators", () => {
    expect(
      resolveProjectPath("C:\\repo", "rules/example.yml"),
    ).toBe("C:/repo/rules/example.yml");
  });

  it("normalizes absolute Windows project paths to workspace-style separators", () => {
    expect(
      resolveProjectPath("workspace", "C:\\repo\\rules\\example.yml"),
    ).toBe("C:/repo/rules/example.yml");
  });

  it("preserves UNC prefixes when resolving relative project paths", () => {
    expect(
      resolveProjectPath("\\\\server\\share", "rules/example.yml"),
    ).toBe("//server/share/rules/example.yml");
  });

  it("preserves UNC prefixes when normalizing absolute project paths", () => {
    expect(
      resolveProjectPath("workspace", "\\\\server\\share\\rules\\example.yml"),
    ).toBe("//server/share/rules/example.yml");
  });

  it("derives UNC search roots from absolute workspace file paths", () => {
    expect(
      deriveSearchRootPath("workspace", [
        "//server/share/policies/example.yml",
      ], [
        "policies/example.yml",
        "rules/detections.yml",
      ]),
    ).toBe("//server/share");
  });

  it("rejects rename basenames that include path traversal or separators", () => {
    expect(isValidProjectBasename("renamed.yml")).toBe(true);
    expect(isValidProjectBasename(" nested name.yml ")).toBe(true);
    expect(isValidProjectBasename("")).toBe(false);
    expect(isValidProjectBasename(".")).toBe(false);
    expect(isValidProjectBasename("..")).toBe(false);
    expect(isValidProjectBasename("../outside.yml")).toBe(false);
    expect(isValidProjectBasename("subdir/rule.yml")).toBe(false);
    expect(isValidProjectBasename("subdir\\rule.yml")).toBe(false);
  });
});
