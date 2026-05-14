import type { ScaffoldOptions } from "../types";

function getEntrypointModules(options: ScaffoldOptions): string[] {
  const modules = new Set<string>(["index"]);

  for (const contribution of options.contributions) {
    switch (contribution) {
      case "threatIntelSources":
        modules.add("source");
        break;
      case "editorTabs":
      case "bottomPanelTabs":
      case "rightSidebarPanels":
        modules.add("panel");
        break;
      case "statusBarItems":
        modules.add("status-widget");
        break;
      default:
        break;
    }
  }

  return Array.from(modules);
}

function buildExports(
  modules: string[],
): Record<string, { types: string; import: string; require: string }> {
  return Object.fromEntries(
    modules.map((moduleName) => {
      const subpath = moduleName === "index" ? "." : `./${moduleName}`;
      const distName = moduleName === "index" ? "index" : moduleName;
      return [
        subpath,
        {
          types: `./dist/${distName}.d.ts`,
          import: `./dist/${distName}.js`,
          require: `./dist/${distName}.cjs`,
        },
      ];
    }),
  );
}

export function generatePackageJson(options: ScaffoldOptions): string {
  const modules = getEntrypointModules(options);
  const pkg = {
    name: options.name,
    version: "0.1.0",
    description: `A ClawdStrike ${options.type} plugin`,
    type: "module",
    main: "./dist/index.js",
    types: "./dist/index.d.ts",
    exports: buildExports(modules),
    scripts: {
      build: "tsup",
      test: "vitest run",
      typecheck: "tsc --noEmit",
      dev: "tsup --watch",
    },
    dependencies: {
      "@clawdstrike/plugin-sdk": "^0.1.0",
    },
    devDependencies: {
      typescript: "^5.9.3",
      tsup: "^8.5.1",
      vitest: "^4.0.18",
    },
    license: "Apache-2.0",
    engines: {
      node: ">=20.19.0",
    },
  };

  return JSON.stringify(pkg, null, 2) + "\n";
}

export function generateTsconfig(): string {
  const tsconfig = {
    compilerOptions: {
      target: "ES2022",
      module: "ESNext",
      moduleResolution: "bundler",
      lib: ["ES2022", "DOM"],
      strict: true,
      esModuleInterop: true,
      skipLibCheck: true,
      forceConsistentCasingInFileNames: true,
      declaration: true,
      declarationMap: true,
      sourceMap: true,
      outDir: "./dist",
      rootDir: "./src",
      resolveJsonModule: true,
      isolatedModules: true,
      noUnusedLocals: true,
      noUnusedParameters: true,
      noImplicitReturns: true,
      noFallthroughCasesInSwitch: true,
    },
    include: ["src/**/*"],
    exclude: ["node_modules", "dist", "tests"],
  };

  return JSON.stringify(tsconfig, null, 2) + "\n";
}

export function generateTsupConfig(options: ScaffoldOptions): string {
  const entries = getEntrypointModules(options).map(
    (moduleName) => `src/${moduleName}.ts`,
  );
  return `import { defineConfig } from "tsup";

export default defineConfig({
  entry: ${JSON.stringify(entries)},
  format: ["esm", "cjs"],
  dts: true,
  clean: true,
  sourcemap: true,
  splitting: false,
});
`;
}

export function generateVitestConfig(): string {
  return `import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    include: ["tests/**/*.test.ts"],
  },
});
`;
}

export function generateGitignore(): string {
  return `node_modules/
dist/
*.tsbuildinfo
.DS_Store
`;
}
