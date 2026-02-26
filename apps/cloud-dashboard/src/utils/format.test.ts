import { describe, it, expect } from "vitest";
import { formatUptime } from "./format";

describe("formatUptime", () => {
  it("returns seconds for values under 60", () => {
    expect(formatUptime(0)).toBe("0s");
    expect(formatUptime(1)).toBe("1s");
    expect(formatUptime(59)).toBe("59s");
  });

  it("returns minutes for values under 3600", () => {
    expect(formatUptime(60)).toBe("1m");
    expect(formatUptime(120)).toBe("2m");
    expect(formatUptime(3599)).toBe("59m");
  });

  it("returns hours and minutes for larger values", () => {
    expect(formatUptime(3600)).toBe("1h 0m");
    expect(formatUptime(3661)).toBe("1h 1m");
    expect(formatUptime(7200)).toBe("2h 0m");
    expect(formatUptime(86400)).toBe("24h 0m");
  });
});
