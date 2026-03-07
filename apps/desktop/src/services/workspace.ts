import { isTauri } from "./tauri";

export interface WorkspaceRoot {
  id: string;
  name: string;
  canonicalPath: string;
  createdAt: string;
  lastOpenedAt: string;
}

export type WorkspaceEntryKind = "file" | "directory";

export interface WorkspaceEntry {
  rootId: string;
  relativePath: string;
  name: string;
  kind: WorkspaceEntryKind;
  size?: number;
  modifiedAt?: string;
  children?: WorkspaceEntry[];
}

export interface WorkspaceFile {
  rootId: string;
  relativePath: string;
  contents: string;
  encoding?: string;
  modifiedAt?: string;
}

interface BackendWorkspaceFile {
  root?: WorkspaceRoot;
  entry?: WorkspaceEntry & { canonicalPath?: string };
  rootId?: string;
  relativePath?: string;
  contents: string;
  encoding?: string;
  modifiedAt?: string;
}

export interface WorkspaceShellSnapshot {
  roots: WorkspaceRoot[];
  activeRootId?: string;
  tree: WorkspaceEntry[];
  suggestedTabs: Array<{
    id: string;
    title: string;
    relativePath: string;
    kind: "file" | "preview";
  }>;
}

export interface WorkspaceServiceErrorPayload {
  code:
    | "workspace_unavailable"
    | "workspace_root_unknown"
    | "workspace_access_denied"
    | "workspace_path_invalid"
    | "workspace_request_failed";
  message: string;
}

export class WorkspaceServiceError extends Error {
  code: WorkspaceServiceErrorPayload["code"];

  constructor(payload: WorkspaceServiceErrorPayload) {
    super(payload.message);
    this.code = payload.code;
    this.name = "WorkspaceServiceError";
  }
}

type WorkspaceCommandName =
  | "workspace_register_root"
  | "workspace_list_dir"
  | "workspace_read_file"
  | "workspace_list_recent_roots";

async function getTauriInvoke() {
  const { invoke } = await import("@tauri-apps/api/core");
  return invoke;
}

function toWorkspaceServiceError(error: unknown): WorkspaceServiceError {
  if (error instanceof WorkspaceServiceError) return error;

  const message = error instanceof Error ? error.message : "Unknown workspace error";

  if (/unknown root|root.*not found|workspace_root_unknown/i.test(message)) {
    return new WorkspaceServiceError({ code: "workspace_root_unknown", message });
  }

  if (/denied|forbidden|workspace_access_denied/i.test(message)) {
    return new WorkspaceServiceError({ code: "workspace_access_denied", message });
  }

  if (/invalid path|escape|workspace_path_invalid/i.test(message)) {
    return new WorkspaceServiceError({ code: "workspace_path_invalid", message });
  }

  if (/not running in tauri|command .* not found|workspace unavailable/i.test(message)) {
    return new WorkspaceServiceError({ code: "workspace_unavailable", message });
  }

  return new WorkspaceServiceError({ code: "workspace_request_failed", message });
}

async function invokeWorkspace<T>(command: WorkspaceCommandName, args: Record<string, unknown>) {
  if (!isTauri()) {
    throw new WorkspaceServiceError({
      code: "workspace_unavailable",
      message: `Workspace command ${command} requires Tauri`,
    });
  }

  try {
    const invoke = await getTauriInvoke();
    return await invoke<T>(command, args);
  } catch (error) {
    throw toWorkspaceServiceError(error);
  }
}

const MOCK_ROOT: WorkspaceRoot = {
  id: "mock-root-huntronomer",
  name: "huntronomer-workspace",
  canonicalPath: "/workspace/huntronomer-workspace",
  createdAt: "2026-03-07T12:00:00.000Z",
  lastOpenedAt: "2026-03-07T12:00:00.000Z",
};

const MOCK_TREE: WorkspaceEntry[] = [
  {
    rootId: MOCK_ROOT.id,
    relativePath: "briefs",
    name: "briefs",
    kind: "directory",
    children: [
      {
        rootId: MOCK_ROOT.id,
        relativePath: "briefs/hunt-plan.md",
        name: "hunt-plan.md",
        kind: "file",
        size: 4280,
      },
      {
        rootId: MOCK_ROOT.id,
        relativePath: "briefs/operators.md",
        name: "operators.md",
        kind: "file",
        size: 980,
      },
    ],
  },
  {
    rootId: MOCK_ROOT.id,
    relativePath: "rules",
    name: "rules",
    kind: "directory",
    children: [
      {
        rootId: MOCK_ROOT.id,
        relativePath: "rules/yara",
        name: "yara",
        kind: "directory",
        children: [
          {
            rootId: MOCK_ROOT.id,
            relativePath: "rules/yara/suspicious-loader.yar",
            name: "suspicious-loader.yar",
            kind: "file",
            size: 1820,
          },
        ],
      },
      {
        rootId: MOCK_ROOT.id,
        relativePath: "rules/sigma",
        name: "sigma",
        kind: "directory",
        children: [
          {
            rootId: MOCK_ROOT.id,
            relativePath: "rules/sigma/outbound-spike.yml",
            name: "outbound-spike.yml",
            kind: "file",
            size: 720,
          },
        ],
      },
    ],
  },
  {
    rootId: MOCK_ROOT.id,
    relativePath: "receipts",
    name: "receipts",
    kind: "directory",
    children: [
      {
        rootId: MOCK_ROOT.id,
        relativePath: "receipts/case-114.json",
        name: "case-114.json",
        kind: "file",
        size: 1200,
      },
    ],
  },
  {
    rootId: MOCK_ROOT.id,
    relativePath: "README.md",
    name: "README.md",
    kind: "file",
    size: 640,
  },
];

const MOCK_FILE_CONTENTS: Record<string, string> = {
  "briefs/hunt-plan.md": "# Hunt Plan\n\n- Confirm trust roots\n- Stand up workspace shell\n- Wire Monaco in WS4\n",
  "briefs/operators.md": "# Operators\n\nThis workspace shell is route-aware and trust-rooted.\n",
  "rules/yara/suspicious-loader.yar": "rule SuspiciousLoader {\n  condition:\n    filesize < 2MB\n}\n",
  "rules/sigma/outbound-spike.yml": "title: Outbound Spike\nstatus: experimental\nlogsource:\n  category: network\n",
  "receipts/case-114.json": '{"case":"114","status":"open"}\n',
  "README.md": "# Huntronomer Workspace\n\nScaffold root for the desktop workspace shell.\n",
};

function flattenEntries(entries: WorkspaceEntry[]): WorkspaceEntry[] {
  return entries.flatMap((entry) => [entry, ...(entry.children ? flattenEntries(entry.children) : [])]);
}

function findEntryByRelativePath(entries: WorkspaceEntry[], relativePath: string) {
  return flattenEntries(entries).find((entry) => entry.relativePath === relativePath);
}

function createSuggestedTabs(entries: WorkspaceEntry[]) {
  return flattenEntries(entries)
    .filter((entry) => entry.kind === "file")
    .sort((left, right) => {
      const leftDepth = left.relativePath.split("/").filter(Boolean).length;
      const rightDepth = right.relativePath.split("/").filter(Boolean).length;
      if (leftDepth !== rightDepth) {
        return leftDepth - rightDepth;
      }
      if (left.name === "README.md" && right.name !== "README.md") {
        return -1;
      }
      if (right.name === "README.md" && left.name !== "README.md") {
        return 1;
      }
      return left.relativePath.localeCompare(right.relativePath);
    })
    .slice(0, 2)
    .map((entry, index) => ({
      id: `workspace-tab-${index}-${entry.relativePath}`,
      title: entry.name,
      relativePath: entry.relativePath,
      kind: index === 0 ? ("preview" as const) : ("file" as const),
    }));
}

function normalizeRelativePath(relativePath?: string): string {
  return relativePath?.replace(/^\/+/, "").replace(/\/+/g, "/") ?? "";
}

function listMockDirectory(relativePath = ""): WorkspaceEntry[] {
  const normalized = normalizeRelativePath(relativePath);
  if (!normalized) return MOCK_TREE;

  const target = findEntryByRelativePath(MOCK_TREE, normalized);
  if (!target) {
    throw new WorkspaceServiceError({
      code: "workspace_path_invalid",
      message: `Unknown mock workspace path: ${normalized}`,
    });
  }

  return target.kind === "directory" ? target.children ?? [] : [target];
}

export function createMockWorkspaceShellSnapshot(): WorkspaceShellSnapshot {
  return {
    roots: [MOCK_ROOT],
    activeRootId: MOCK_ROOT.id,
    tree: MOCK_TREE,
    suggestedTabs: createSuggestedTabs(MOCK_TREE),
  };
}

export async function registerWorkspaceRoot(path: string): Promise<WorkspaceRoot> {
  if (!isTauri()) {
    const trimmed = path.trim();
    if (!trimmed) {
      throw new WorkspaceServiceError({
        code: "workspace_path_invalid",
        message: "A candidate workspace path is required",
      });
    }

    const segments = trimmed.split("/").filter(Boolean);
    const name = segments[segments.length - 1] ?? "workspace";
    const now = new Date().toISOString();
    return {
      id: `mock-root-${name}`,
      name,
      canonicalPath: trimmed,
      createdAt: now,
      lastOpenedAt: now,
    };
  }

  return invokeWorkspace<WorkspaceRoot>("workspace_register_root", { path });
}

export async function listWorkspaceDirectory(
  rootId: string,
  relativePath = "",
): Promise<WorkspaceEntry[]> {
  if (!isTauri()) {
    if (rootId !== MOCK_ROOT.id) {
      throw new WorkspaceServiceError({
        code: "workspace_root_unknown",
        message: `Unknown mock root: ${rootId}`,
      });
    }

    return listMockDirectory(relativePath);
  }

  return invokeWorkspace<WorkspaceEntry[]>("workspace_list_dir", { rootId, relativePath });
}

async function loadWorkspaceTree(rootId: string, relativePath = ""): Promise<WorkspaceEntry[]> {
  const entries = await listWorkspaceDirectory(rootId, relativePath);

  return Promise.all(
    entries.map(async (entry) => {
      if (entry.kind !== "directory") {
        return entry;
      }

      return {
        ...entry,
        children: await loadWorkspaceTree(rootId, entry.relativePath),
      };
    }),
  );
}

function toWorkspaceFile(payload: BackendWorkspaceFile): WorkspaceFile {
  return {
    rootId: payload.rootId ?? payload.entry?.rootId ?? payload.root?.id ?? "",
    relativePath:
      payload.relativePath ?? payload.entry?.relativePath ?? "",
    contents: payload.contents,
    encoding: payload.encoding ?? "utf-8",
    modifiedAt: payload.modifiedAt ?? payload.entry?.modifiedAt,
  };
}

export async function readWorkspaceFile(
  rootId: string,
  relativePath: string,
): Promise<WorkspaceFile> {
  if (!isTauri()) {
    if (rootId !== MOCK_ROOT.id) {
      throw new WorkspaceServiceError({
        code: "workspace_root_unknown",
        message: `Unknown mock root: ${rootId}`,
      });
    }

    const normalized = normalizeRelativePath(relativePath);
    const entry = findEntryByRelativePath(MOCK_TREE, normalized);
    if (!entry || entry.kind !== "file") {
      throw new WorkspaceServiceError({
        code: "workspace_path_invalid",
        message: `Unknown mock file: ${normalized}`,
      });
    }

    return {
      rootId,
      relativePath: normalized,
      contents: MOCK_FILE_CONTENTS[normalized] ?? "",
      encoding: "utf-8",
    };
  }

  const payload = await invokeWorkspace<BackendWorkspaceFile>("workspace_read_file", {
    rootId,
    relativePath,
  });

  return toWorkspaceFile(payload);
}

export async function listRecentWorkspaceRoots(): Promise<WorkspaceRoot[]> {
  if (!isTauri()) {
    return [MOCK_ROOT];
  }

  return invokeWorkspace<WorkspaceRoot[]>("workspace_list_recent_roots", {});
}

export async function getWorkspaceShellSnapshot(): Promise<WorkspaceShellSnapshot> {
  if (!isTauri()) {
    return createMockWorkspaceShellSnapshot();
  }

  const roots = await listRecentWorkspaceRoots();
  const activeRoot = roots[0];

  if (!activeRoot) {
    return {
      roots: [],
      tree: [],
      suggestedTabs: [],
    };
  }

  const tree = await loadWorkspaceTree(activeRoot.id, "");

  return {
    roots,
    activeRootId: activeRoot.id,
    tree,
    suggestedTabs: createSuggestedTabs(tree),
  };
}
