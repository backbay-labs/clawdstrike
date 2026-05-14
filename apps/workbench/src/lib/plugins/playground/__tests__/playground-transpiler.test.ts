import { describe, it, expect } from "vitest";
import { transpilePlugin } from "../playground-transpiler";

describe("transpilePlugin - SDK import rewriting", () => {
  describe("named imports", () => {
    it("rewrites single-line named import to window global destructuring", () => {
      const source = `import { createPlugin } from "@clawdstrike/plugin-sdk";\ncreatePlugin({});`;
      const { code, error } = transpilePlugin(source);

      expect(error).toBeNull();
      expect(code).toContain(
        `const { createPlugin } = window.__CLAWDSTRIKE_PLUGIN_SDK__;`,
      );
      expect(code).not.toContain("from");
    });

    it("rewrites multi-line named import to destructuring", () => {
      // Both symbols must be referenced as values so sucrase doesn't
      // strip them as unused type-only imports during TS transform.
      const source = [
        `import {`,
        `  createPlugin,`,
        `  defineGuard`,
        `} from "@clawdstrike/plugin-sdk";`,
        `createPlugin({});`,
        `defineGuard({});`,
      ].join("\n");
      const { code, error } = transpilePlugin(source);

      expect(error).toBeNull();
      expect(code).toContain("createPlugin");
      expect(code).toContain("defineGuard");
      expect(code).toContain("window.__CLAWDSTRIKE_PLUGIN_SDK__");
      // Should be destructured, not a type-only strip
      expect(code).toContain("const {");
    });

    it("rewrites aliased named imports to valid object destructuring", () => {
      const source = `import { createPlugin as cp } from "@clawdstrike/plugin-sdk";\ncp({});`;
      const { code, error } = transpilePlugin(source);

      expect(error).toBeNull();
      expect(code).toContain(
        `const { createPlugin: cp } = window.__CLAWDSTRIKE_PLUGIN_SDK__;`,
      );
      expect(code).not.toContain("createPlugin as cp");
    });
  });

  describe("type-only imports", () => {
    it("strips import type entirely", () => {
      const source = `import type { PluginManifest } from "@clawdstrike/plugin-sdk";\nconst x = 1;`;
      const { code, error } = transpilePlugin(source);

      expect(error).toBeNull();
      // Sucrase strips the `type` keyword, but our regex should strip the whole import
      // The resulting code should NOT contain PluginManifest as an import
      expect(code).not.toContain("PluginManifest");
      // Should still contain the rest of the code
      expect(code).toContain("const x = 1");
    });
  });

  describe("namespace imports", () => {
    it("rewrites import * as SDK to const assignment", () => {
      const source = `import * as SDK from "@clawdstrike/plugin-sdk";\nSDK.createPlugin({});`;
      const { code, error } = transpilePlugin(source);

      expect(error).toBeNull();
      expect(code).toContain(
        `const SDK = window.__CLAWDSTRIKE_PLUGIN_SDK__;`,
      );
      expect(code).not.toContain("import *");
    });
  });

  describe("subpath imports", () => {
    it("rewrites subpath import to window global destructuring", () => {
      const source = `import { createSpyContext } from "@clawdstrike/plugin-sdk/testing";\ncreateSpyContext();`;
      const { code, error } = transpilePlugin(source);

      expect(error).toBeNull();
      expect(code).toContain(
        `const { createSpyContext } = window.__CLAWDSTRIKE_PLUGIN_SDK__;`,
      );
    });
  });

  describe("non-SDK imports", () => {
    it("does NOT modify non-SDK imports", () => {
      // Note: sucrase strips TypeScript types but doesn't transform JS imports
      // to something else. The import statement for "react" will remain as-is
      // in the transpiled output since sucrase only strips TS, not ESM.
      const source = `import React from "react";\nconst x = React;`;
      const { code, error } = transpilePlugin(source);

      expect(error).toBeNull();
      // The non-SDK import should still reference "react" in some form
      expect(code).toContain("react");
      // Should NOT contain the SDK global
      expect(code).not.toContain("__CLAWDSTRIKE_PLUGIN_SDK__");
    });
  });

  describe("console proxy injection", () => {
    it("injects console proxy assignment at the top", () => {
      const source = `const x = 1;`;
      const { code, error } = transpilePlugin(source);

      expect(error).toBeNull();
      expect(code).toContain("window.__PLAYGROUND_CONSOLE__");
      // Should be at the very start of the output
      expect(code.indexOf("__PLAYGROUND_CONSOLE__")).toBeLessThan(
        code.indexOf("const x = 1"),
      );
    });
  });

  describe("export default rewriting", () => {
    it("replaces export default with window assignment", () => {
      const source = `export default createPlugin({});`;
      const { code, error } = transpilePlugin(source);

      expect(error).toBeNull();
      expect(code).toContain("window.__PLAYGROUND_PLUGIN__");
      expect(code).not.toContain("export default");
    });
  });

  describe("error handling", () => {
    it("returns error for unterminated string literal", () => {
      const source = `const x = "unterminated;`;
      const { code, error } = transpilePlugin(source);

      // Should return an error rather than throwing
      expect(error).not.toBeNull();
    });

    it("returns error for invalid TypeScript syntax", () => {
      const source = `const = ;`;
      const { code, error } = transpilePlugin(source);

      expect(error).not.toBeNull();
    });
  });
});
