import { describe, expect, it } from "vitest";

import * as exports from "./index.js";

describe("public exports compatibility", () => {
  it("keeps legacy langchain symbols available", () => {
    expect(typeof exports.wrapTool).toBe("function");
    expect(typeof exports.wrapTools).toBe("function");
    expect(typeof exports.wrapToolWithConfig).toBe("function");
    expect(typeof exports.wrapToolsWithConfig).toBe("function");
    expect(typeof exports.createLangChainInterceptor).toBe("function");
    expect(typeof exports.LangChainAdapter).toBe("function");
    expect(typeof exports.ClawdstrikeViolationError).toBe("function");
  });
});
