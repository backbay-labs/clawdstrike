import { describe, it, expect } from "vitest";
import { diffLines } from "./simpleDiff";

describe("diffLines", () => {
  it("returns unchanged lines for identical strings", () => {
    const result = diffLines("hello\nworld", "hello\nworld");
    expect(result.left.every((l) => l.type === "unchanged")).toBe(true);
    expect(result.right.every((l) => l.type === "unchanged")).toBe(true);
    expect(result.left).toHaveLength(2);
  });

  it("detects added lines", () => {
    const result = diffLines("a\nb", "a\nb\nc");
    const addedRight = result.right.filter((l) => l.type === "added");
    expect(addedRight.length).toBeGreaterThanOrEqual(1);
    expect(addedRight.some((l) => l.content === "c")).toBe(true);
  });

  it("detects removed lines", () => {
    const result = diffLines("a\nb\nc", "a\nc");
    const removedLeft = result.left.filter((l) => l.type === "removed");
    expect(removedLeft.length).toBeGreaterThanOrEqual(1);
    expect(removedLeft.some((l) => l.content === "b")).toBe(true);
  });

  it("handles empty inputs", () => {
    const result = diffLines("", "");
    // "".split("\n") gives [""], so we get 1 unchanged line per side
    expect(result.left).toHaveLength(1);
    expect(result.right).toHaveLength(1);
  });

  it("handles one side empty", () => {
    const result = diffLines("", "a\nb");
    const addedRight = result.right.filter((l) => l.type === "added");
    expect(addedRight.length).toBeGreaterThanOrEqual(2);
  });
});
