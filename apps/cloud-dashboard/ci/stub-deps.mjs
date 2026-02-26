/**
 * Creates stub packages for file: dependencies that resolve outside
 * this repository. Only used in CI where the Backbay workspace root
 * is not available.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "../../..");

function stubPkg(relPath, name, dts = "export {};") {
  const dir = resolve(repoRoot, relPath);
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    resolve(dir, "package.json"),
    JSON.stringify({ name, version: "0.0.0", main: "index.js", types: "index.d.ts" }),
  );
  writeFileSync(resolve(dir, "index.js"), "module.exports = {};");
  writeFileSync(resolve(dir, "index.d.ts"), dts);
}

// @backbay/glia — not directly imported by cloud-dashboard
stubPkg("../backbay-sdk/packages/glia", "@backbay/glia");

// @backbay/glia-desktop — provides the desktop OS shell primitives
stubPkg(
  "../backbay-sdk/packages/glia-desktop",
  "@backbay/glia-desktop",
  `import { ComponentType, ReactNode } from "react";
export type WindowId = string;
export interface ProcessDefinition {
  id: string;
  name: string;
  icon?: string | ReactNode;
  component: ComponentType<{ windowId?: WindowId }>;
  defaultSize?: { width: number; height: number };
  minSize?: { width: number; height: number };
  singleton?: boolean;
  category?: string;
  description?: string;
}
export declare function DesktopOSProvider(props: {
  processes: ProcessDefinition[];
  initialPinnedApps?: string[];
  enableSnapZones?: boolean;
  enableWindowGroups?: boolean;
  enableAnimations?: boolean;
  children: ReactNode;
}): ReactNode;
export declare function useDesktopOS(): {
  processes: {
    instances: Array<{ windowId: WindowId; processId: string }>;
    getDefinition: (id: string) => ProcessDefinition | undefined;
    launch: (id: string) => void;
  };
};
export declare function useWindowIds(): WindowId[];
export declare function useWindow(id: WindowId): { isMinimized: boolean } | null;
export declare function Window(props: { id: WindowId; children: ReactNode }): ReactNode;
export declare function Taskbar(props: { showClock?: boolean }): ReactNode;
export declare function useSystemTray(): {
  registerItem: (item: {
    id: string;
    icon: ReactNode;
    tooltip: string;
    onClick: () => void;
    order?: number;
  }) => void;
  updateItem: (id: string, updates: {
    icon?: ReactNode;
    tooltip?: string;
    onClick?: () => void;
  }) => void;
  unregisterItem: (id: string) => void;
};
`,
);
