import { mkdir, writeFile as fsWriteFile } from "node:fs/promises";
import path from "node:path";
import type { ContributionPoint, ScaffoldOptions } from "./types";
import {
  generatePackageJson,
  generateTsconfig,
  generateTsupConfig,
  generateVitestConfig,
  generateGitignore,
} from "./templates/config";
import { getSourceTemplate, getTestTemplate } from "./templates/source";

function toPascalCase(name: string): string {
  return name
    .split("-")
    .map((segment) => segment.charAt(0).toUpperCase() + segment.slice(1))
    .join("");
}

function getSupplementalEntrypointFiles(
  options: ScaffoldOptions,
): Array<{ filename: string; content: string }> {
  const componentName = toPascalCase(options.name);
  const files = new Map<string, string>();
  const register = (contribution: ContributionPoint): void => {
    switch (contribution) {
      case "threatIntelSources":
        files.set(
          "src/source.ts",
          `export default {
  id: "${options.name}-intel",
  name: "${options.displayName}",
  supportedIndicatorTypes: ["hash"],
  rateLimit: { maxPerMinute: 30 },
  async enrich(_indicator: unknown) {
    throw new Error("${options.displayName} source enrich() is not implemented yet.");
  },
};
`,
        );
        break;
      case "editorTabs":
      case "bottomPanelTabs":
      case "rightSidebarPanels":
        files.set(
          "src/panel.ts",
          `export default function ${componentName}Panel() {
  return null;
}
`,
        );
        break;
      case "statusBarItems":
        files.set(
          "src/status-widget.ts",
          `export default function ${componentName}StatusWidget() {
  return null;
}
`,
        );
        break;
      default:
        break;
    }
  };

  for (const contribution of options.contributions) {
    register(contribution);
  }

  return Array.from(files.entries()).map(([filename, content]) => ({
    filename,
    content,
  }));
}

export async function writeProjectFile(
  dir: string,
  filename: string,
  content: string,
): Promise<void> {
  const resolved = path.resolve(dir, filename);
  const dirResolved = path.resolve(dir);
  if (!resolved.startsWith(dirResolved + path.sep) && resolved !== dirResolved) {
    throw new Error(`Path traversal detected: ${filename}`);
  }
  const filePath = path.join(dir, filename);
  await fsWriteFile(filePath, content, "utf-8");
}

export async function scaffoldProject(options: ScaffoldOptions): Promise<void> {
  const { outputDir } = options;

  await mkdir(outputDir, { recursive: true });
  await mkdir(path.join(outputDir, "src"), { recursive: true });
  await mkdir(path.join(outputDir, "tests"), { recursive: true });

  await writeProjectFile(outputDir, "package.json", generatePackageJson(options));
  await writeProjectFile(outputDir, "tsconfig.json", generateTsconfig());
  await writeProjectFile(outputDir, "tsup.config.ts", generateTsupConfig(options));
  await writeProjectFile(outputDir, "vitest.config.ts", generateVitestConfig());
  await writeProjectFile(outputDir, ".gitignore", generateGitignore());

  await writeProjectFile(outputDir, "src/index.ts", getSourceTemplate(options));
  for (const file of getSupplementalEntrypointFiles(options)) {
    await writeProjectFile(outputDir, file.filename, file.content);
  }

  await writeProjectFile(outputDir, "tests/plugin.test.ts", getTestTemplate(options));
}
