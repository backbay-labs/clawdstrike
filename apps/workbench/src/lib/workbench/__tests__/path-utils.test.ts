import { describe, expect, it } from "vitest";
import {
  isAbsoluteWorkspacePath,
  joinWorkspacePath,
  relativeWorkspacePath,
  resolveWorkspaceRootPath,
  restoreFileRoutePath,
} from "@/lib/workbench/path-utils";

describe("path-utils", () => {
  it("recognizes Windows absolute paths", () => {
    expect(isAbsoluteWorkspacePath("C:/workspace/policy.yaml")).toBe(true);
    expect(isAbsoluteWorkspacePath("C:\\workspace\\policy.yaml")).toBe(true);
    expect(isAbsoluteWorkspacePath("policies/policy.yaml")).toBe(false);
  });

  it("joins workspace paths using normalized separators", () => {
    expect(joinWorkspacePath("C:\\workspace", "policies\\strict.yaml")).toBe(
      "C:/workspace/policies/strict.yaml",
    );
  });

  it("computes relative paths for Windows roots", () => {
    expect(
      relativeWorkspacePath(
        "C:\\workspace",
        "C:\\workspace\\policies\\strict.yaml",
      ),
    ).toBe("policies/strict.yaml");
  });

  it("resolves the owning root for Windows absolute paths", () => {
    expect(
      resolveWorkspaceRootPath(
        ["D:/other", "C:\\workspace"],
        "C:\\workspace\\policies\\strict.yaml",
      ),
    ).toBe("C:\\workspace");
  });

  it("preserves Windows absolute file routes without prefixing a slash", () => {
    expect(restoreFileRoutePath("C:/workspace/policies/strict.yaml")).toBe(
      "C:/workspace/policies/strict.yaml",
    );
    expect(restoreFileRoutePath("policies/strict.yaml")).toBe(
      "/policies/strict.yaml",
    );
  });
});
