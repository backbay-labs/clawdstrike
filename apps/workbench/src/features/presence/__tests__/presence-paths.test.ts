import { describe, expect, it } from "vitest";
import { fromPresencePath } from "../presence-paths";

describe("fromPresencePath", () => {
  it("rebuilds an absolute unix path from the matching project root", () => {
    expect(
      fromPresencePath("Users/connor/workspace/src/policy.yaml", [
        "/Users/connor/workspace",
      ]),
    ).toBe("/Users/connor/workspace/src/policy.yaml");
  });

  it("rebuilds a windows path from a normalized server path", () => {
    expect(
      fromPresencePath("repo/src/policy.yaml", ["C:/repo"]),
    ).toBe("C:/repo/src/policy.yaml");
  });

  it("falls back to a route-safe absolute path when no project root matches", () => {
    expect(fromPresencePath("Users/connor/other/file.txt", [])).toBe(
      "/Users/connor/other/file.txt",
    );
  });
});
