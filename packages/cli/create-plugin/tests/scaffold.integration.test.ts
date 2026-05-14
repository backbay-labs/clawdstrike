import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { scaffoldProject } from "../src/engine";
import type { ScaffoldOptions, PluginType } from "../src/types";
import { PLUGIN_TYPE_DEFAULTS } from "../src/types";
import { existsSync, readFileSync, rmSync, mkdtempSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const ALL_TYPES = ["guard", "detection", "ui", "intel", "compliance", "full"] as const;

let tempDir: string;

beforeAll(() => {
  tempDir = mkdtempSync(join(tmpdir(), "clawdstrike-scaffold-"));
});

afterAll(() => {
  rmSync(tempDir, { recursive: true, force: true });
});

function makeOptions(type: PluginType): ScaffoldOptions {
  return {
    name: `test-${type}-plugin`,
    displayName: `Test ${type.charAt(0).toUpperCase() + type.slice(1)} Plugin`,
    publisher: "test-org",
    type,
    contributions: PLUGIN_TYPE_DEFAULTS[type],
    packageManager: "npm",
    outputDir: join(tempDir, `test-${type}-plugin`),
  };
}

const expectedSupplementalFiles: Record<PluginType, string[]> = {
  guard: [],
  detection: [],
  ui: ["src/panel.ts"],
  intel: ["src/source.ts"],
  compliance: [],
  full: [
    "src/source.ts",
    "src/panel.ts",
    "src/status-widget.ts",
  ],
};

const expectedExportKeys: Record<PluginType, string[]> = {
  guard: ["."],
  detection: ["."],
  ui: [".", "./panel"],
  intel: [".", "./source"],
  compliance: ["."],
  full: [".", "./source", "./panel", "./status-widget"],
};

for (const type of ALL_TYPES) {
  describe(`scaffold: ${type} template`, () => {
    let projectDir: string;

    beforeAll(async () => {
      const options = makeOptions(type);
      projectDir = options.outputDir;
      await scaffoldProject(options);
    });

    it("creates package.json with SDK dependency and scripts", () => {
      const filePath = join(projectDir, "package.json");
      expect(existsSync(filePath)).toBe(true);

      const pkg = JSON.parse(readFileSync(filePath, "utf-8"));
      expect(pkg.name).toBe(`test-${type}-plugin`);
      expect(pkg.dependencies["@clawdstrike/plugin-sdk"]).toBeDefined();
      expect(pkg.scripts.build).toBeDefined();
      expect(pkg.scripts.test).toBeDefined();
      expect(pkg.scripts.typecheck).toBeDefined();
    });

    it("creates tsconfig.json with strict mode and ES2022 target", () => {
      const filePath = join(projectDir, "tsconfig.json");
      expect(existsSync(filePath)).toBe(true);

      const tsconfig = JSON.parse(readFileSync(filePath, "utf-8"));
      expect(tsconfig.compilerOptions.strict).toBe(true);
      expect(tsconfig.compilerOptions.target).toBe("ES2022");
      expect(tsconfig.compilerOptions.module).toBe("ESNext");
      expect(tsconfig.compilerOptions.lib).toContain("DOM");
    });

    it("creates tsup.config.ts", () => {
      expect(existsSync(join(projectDir, "tsup.config.ts"))).toBe(true);
    });

    it("creates supplemental entrypoint modules for contributed runtime files", () => {
      for (const file of expectedSupplementalFiles[type]) {
        expect(existsSync(join(projectDir, file))).toBe(true);
      }
    });

    it("exports every generated entrypoint module from package.json", () => {
      const pkg = JSON.parse(readFileSync(join(projectDir, "package.json"), "utf-8"));
      expect(Object.keys(pkg.exports)).toEqual(expectedExportKeys[type]);
    });

    it("includes every generated entrypoint in tsup.config.ts", () => {
      const tsupConfig = readFileSync(join(projectDir, "tsup.config.ts"), "utf-8");
      for (const exportKey of expectedExportKeys[type]) {
        const moduleName = exportKey === "." ? "index" : exportKey.slice(2);
        expect(tsupConfig).toContain(`src/${moduleName}.ts`);
      }
      expect(tsupConfig).toContain("splitting: false");
    });

    it("creates vitest.config.ts", () => {
      expect(existsSync(join(projectDir, "vitest.config.ts"))).toBe(true);
    });

    it("creates .gitignore containing node_modules", () => {
      const filePath = join(projectDir, ".gitignore");
      expect(existsSync(filePath)).toBe(true);

      const content = readFileSync(filePath, "utf-8");
      expect(content).toContain("node_modules");
    });

    it("creates src/index.ts containing createPlugin", () => {
      const filePath = join(projectDir, "src/index.ts");
      expect(existsSync(filePath)).toBe(true);

      const content = readFileSync(filePath, "utf-8");
      expect(content).toContain("createPlugin");
    });

    it("does not advertise unsupported runtime contribution scaffolds", () => {
      const content = readFileSync(join(projectDir, "src/index.ts"), "utf-8");
      expect(content).not.toContain("detectionAdapters");
      expect(content).not.toContain("complianceFrameworks");
    });

    it("creates tests/plugin.test.ts containing createSpyContext", () => {
      const filePath = join(projectDir, "tests/plugin.test.ts");
      expect(existsSync(filePath)).toBe(true);

      const content = readFileSync(filePath, "utf-8");
      expect(content).toContain("createSpyContext");
      expect(content).toContain("plugin-sdk/testing");
    });
  });
}

describe("scaffold: all types summary", () => {
  it("all 6 types scaffold successfully with at least 5 files each", () => {
    for (const type of ALL_TYPES) {
      const projectDir = join(tempDir, `test-${type}-plugin`);
      expect(existsSync(projectDir)).toBe(true);

      // Count files recursively (flatten src/ and tests/ subdirs)
      const topLevel = readdirSync(projectDir);
      // Should have at minimum: package.json, tsconfig.json, tsup.config.ts, vitest.config.ts, .gitignore, src/, tests/
      expect(topLevel.length).toBeGreaterThanOrEqual(5);
    }
  });
});

// TODO: Enable after Phase 1 (testing harness) completes
// The full SCAF-07 CI integration test requires @clawdstrike/plugin-sdk/testing
// sub-path export to be available for npm install in scaffolded projects.
//
// describe("scaffold: full CI build+test", () => {
//   for (const type of ALL_TYPES) {
//     it(`${type} project builds and tests successfully`, async () => {
//       const projectDir = join(tempDir, `ci-test-${type}-plugin`);
//       const options = makeOptions(type);
//       options.outputDir = projectDir;
//       await scaffoldProject(options);
//
//       // npm install
//       const install = await exec("npm install", { cwd: projectDir });
//       expect(install.exitCode).toBe(0);
//
//       // npm run build
//       const build = await exec("npm run build", { cwd: projectDir });
//       expect(build.exitCode).toBe(0);
//
//       // npm test
//       const test = await exec("npm test", { cwd: projectDir });
//       expect(test.exitCode).toBe(0);
//     });
//   }
// });
