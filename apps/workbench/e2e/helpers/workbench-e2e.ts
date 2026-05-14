import { expect, type Page } from "@playwright/test";

type E2EFileType =
  | "clawdstrike_policy"
  | "sigma_rule"
  | "yara_rule"
  | "ocsf_event";

interface SeededFile {
  path: string;
  content: string;
  fileType: E2EFileType;
}

interface PersistedTabSeed {
  id: string;
  documentId: string;
  name: string;
  filePath: string | null;
  yaml: string;
  fileType: E2EFileType;
}

interface SeedWorkbenchOptions {
  files: SeededFile[];
  tabs: PersistedTabSeed[];
  activeTabId?: string;
}

const DEFAULT_CONTENT_BY_TYPE: Record<E2EFileType, string> = {
  clawdstrike_policy: [
    'version: "1.2.0"',
    "name: __NAME__",
    'description: ""',
    "guards: {}",
    "settings: {}",
    "",
  ].join("\n"),
  sigma_rule: [
    "title: __NAME__",
    "id: 11111111-1111-1111-1111-111111111111",
    "status: experimental",
    "logsource: {}",
    "detection:",
    "  selection: {}",
    "  condition: selection",
    "",
  ].join("\n"),
  yara_rule: [
    "rule __NAME__ {",
    "  strings:",
    '    $a = "demo"',
    "  condition:",
    "    $a",
    "}",
    "",
  ].join("\n"),
  ocsf_event: JSON.stringify({ name: "__NAME__", severity_id: 1 }, null, 2),
};

const DEFAULT_OPERATOR = {
  publicKey: "e2e-public-key",
  fingerprint: "e2e-fingerprint",
  sigil: "star",
  nickname: "e2e",
  displayName: "E2E Operator",
  idpClaims: null,
  createdAt: 0,
  originDeviceId: "e2e-device",
  devices: [{ deviceId: "e2e-device", deviceName: "E2E Device", addedAt: 0, lastSeenAt: 0 }],
};

const MAX_LINE_CONTENT_LEN = 500;

export function makePolicyYaml(name: string, description = ""): string {
  return [
    'version: "1.2.0"',
    `name: ${name}`,
    `description: ${description === "" ? '""' : description}`,
    "guards: {}",
    "settings: {}",
    "",
  ].join("\n");
}

export async function seedWorkbench(page: Page, options: SeedWorkbenchOptions): Promise<void> {
  const activeTabId = options.activeTabId ?? options.tabs[0]?.id ?? "";

  await page.addInitScript(
    ({ files, tabs, activeTabId, defaultContentsByType, operator }) => {
      const normalizePath = (value: string) =>
        value.replace(/\\/g, "/").replace(/\/+/g, "/").replace(/\/$/, "");

      const normalizeSeedPath = (value: string) => {
        const normalized = normalizePath(value);
        if (
          normalized === "" ||
          normalized.startsWith("/") ||
          normalized.startsWith("//") ||
          /^[A-Za-z]:\//.test(normalized)
        ) {
          return normalized || "/";
        }
        return `/${normalized.replace(/^\/+/, "")}`;
      };

      const normalizedFiles = files.map((file) => ({
        ...file,
        path: normalizeSeedPath(file.path),
      }));
      const normalizedTabs = tabs.map((tab) => ({
        ...tab,
        filePath: tab.filePath ? normalizeSeedPath(tab.filePath) : null,
      }));
      const persistedTabs = {
        tabs: normalizedTabs.map((tab) => ({
          id: tab.id,
          documentId: tab.documentId,
          name: tab.name,
          filePath: tab.filePath,
          yaml: tab.yaml,
          fileType: tab.fileType,
        })),
        activeTabId,
      };
      const fileMap = new Map<string, { path: string; content: string; fileType: string }>(
        normalizedFiles.map((file) => [file.path, { ...file }]),
      );

      const deriveWorkspaceRoot = () => {
        const firstPath = normalizedFiles[0]?.path ?? normalizedTabs[0]?.filePath ?? "/workspace";
        if (firstPath.startsWith("/") && firstPath !== "/") {
          const [firstSegment] = firstPath.split("/").filter(Boolean);
          return firstSegment ? `/${firstSegment}` : "/";
        }
        return firstPath;
      };
      const workspaceRoot = deriveWorkspaceRoot();
      const activeTab = normalizedTabs.find((tab) => tab.id === activeTabId) ?? normalizedTabs[0] ?? null;
      const activeRoute = activeTab
        ? activeTab.filePath
          ? `/file/${activeTab.filePath}`
          : `/file/__new__/${activeTab.id}`
        : "/home";
      const paneSession = {
        root: {
          type: "group",
          id: "pane-e2e",
          views: [
            {
              id: "view-e2e",
              route: activeRoute,
              label: activeTab?.name ?? "Home",
            },
          ],
          activeViewId: "view-e2e",
        },
        activePaneId: "pane-e2e",
      };

      const relativePathFor = (rootPath: string, filePath: string) => {
        const normalizedRoot = normalizePath(rootPath);
        const normalizedFile = normalizePath(filePath);
        const prefix = `${normalizedRoot}/`;
        return normalizedFile.startsWith(prefix)
          ? normalizedFile.slice(prefix.length)
          : normalizedFile;
      };

      const escapeRegex = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const codeUnitIndexToCharIndex = (value: string, codeUnitIndex: number) =>
        Array.from(value.slice(0, codeUnitIndex)).length;
      const truncateSearchLine = (line: string) => {
        const characters = Array.from(line);
        if (characters.length <= MAX_LINE_CONTENT_LEN) {
          return {
            content: line,
            charLength: characters.length,
          };
        }

        return {
          content: characters.slice(0, MAX_LINE_CONTENT_LEN).join(""),
          charLength: MAX_LINE_CONTENT_LEN,
        };
      };
      const isWordChar = (value: string) => /[\p{Alphabetic}\p{N}_]/u.test(value);
      const hasWholeWordBoundary = (line: string, start: number, end: number) => {
        const previousChar = Array.from(line.slice(0, start)).at(-1);
        const nextChar = Array.from(line.slice(end))[0];
        const beforeOk = previousChar === undefined || !isWordChar(previousChar);
        const afterOk = nextChar === undefined || !isWordChar(nextChar);
        return beforeOk && afterOk;
      };

      const buildMatcher = (
        query: string,
        caseSensitive: boolean,
        wholeWord: boolean,
        useRegex: boolean,
      ) => {
        const source = useRegex ? query : escapeRegex(query);
        const bounded = wholeWord && useRegex ? `\\b(?:${source})\\b` : source;
        return new RegExp(bounded, caseSensitive ? "gu" : "giu");
      };

      const searchProject = (
        rootPath: string,
        query: string,
        caseSensitive: boolean,
        wholeWord: boolean,
        useRegex: boolean,
      ) => {
        const matches: Array<{
          file_path: string;
          line_number: number;
          line_content: string;
          match_start: number;
          match_end: number;
          source_match_start: number;
          source_match_end: number;
        }> = [];
        const rootPrefix = `${normalizePath(rootPath)}/`;

        for (const file of fileMap.values()) {
          if (!normalizePath(file.path).startsWith(rootPrefix)) {
            continue;
          }

          const lines = file.content.split(/\r?\n/);
          for (let index = 0; index < lines.length; index += 1) {
            const line = lines[index] ?? "";
            const matcher = buildMatcher(query, caseSensitive, wholeWord, useRegex);
            let match = matcher.exec(line);
            while (match) {
              const value = match[0] ?? "";
              if (wholeWord && !useRegex
                && !hasWholeWordBoundary(line, match.index, match.index + value.length)) {
                match = matcher.exec(line);
                continue;
              }
              const linePreview = truncateSearchLine(line);
              const sourceMatchStart = codeUnitIndexToCharIndex(line, match.index);
              const sourceMatchEnd = sourceMatchStart + Array.from(value).length;
              matches.push({
                file_path: relativePathFor(rootPath, file.path),
                line_number: index + 1,
                line_content: linePreview.content,
                match_start: Math.min(linePreview.charLength, sourceMatchStart),
                match_end: Math.min(linePreview.charLength, sourceMatchEnd),
                source_match_start: sourceMatchStart,
                source_match_end: sourceMatchEnd,
              });

              if (value.length === 0) {
                matcher.lastIndex += 1;
              }
              match = matcher.exec(line);
            }
          }
        }

        return {
          matches,
          file_count: new Set(matches.map((match) => match.file_path)).size,
          total_matches: matches.length,
          truncated: false,
        };
      };

      const resolveSeededContent = (fileName: string, fileType: string) => {
        const stem = fileName.replace(/\.[^.]+$/, "");
        const template = defaultContentsByType[fileType] ?? "";
        return template.replace(/__NAME__/g, stem);
      };

      window.__WORKBENCH_E2E__ = {
        readDetectionFileByPath: async (filePath: string) => {
          const file = fileMap.get(normalizeSeedPath(filePath));
          return file ? { content: file.content, path: file.path, fileType: file.fileType as E2EFileType } : null;
        },
        readDetectionDir: async (dirPath: string) => {
          const normalizedDir = normalizeSeedPath(dirPath);
          const dirPrefix = normalizedDir === "/" ? "/" : `${normalizedDir}/`;
          const entries = new Map<string, { name: string; isDirectory: boolean }>();

          for (const file of fileMap.values()) {
            const normalizedFilePath = normalizePath(file.path);
            if (
              normalizedFilePath !== normalizedDir &&
              !normalizedFilePath.startsWith(dirPrefix)
            ) {
              continue;
            }

            const remainder = normalizedFilePath.slice(dirPrefix.length);
            if (!remainder) {
              continue;
            }

            const segments = remainder.split("/").filter(Boolean);
            const entryName = segments[0];
            if (!entryName) {
              continue;
            }

            const isDirectory = segments.length > 1;
            const existingEntry = entries.get(entryName);
            entries.set(entryName, {
              name: entryName,
              isDirectory: existingEntry?.isDirectory || isDirectory,
            });
          }

          return Array.from(entries.values()).sort((a, b) => {
            if (a.isDirectory !== b.isDirectory) {
              return a.isDirectory ? -1 : 1;
            }
            return a.name.localeCompare(b.name);
          });
        },
        createDetectionFile: async (dirPath: string, fileName: string, fileType: string) => {
          const fullPath = normalizeSeedPath(`${dirPath}/${fileName}`);
          fileMap.set(fullPath, {
            path: fullPath,
            content: resolveSeededContent(fileName, fileType),
            fileType,
          });
          return fullPath;
        },
        renameDetectionFile: async (oldPath: string, newPath: string) => {
          const existing = fileMap.get(normalizeSeedPath(oldPath));
          if (!existing) {
            return false;
          }

          const nextPath = normalizeSeedPath(newPath);
          fileMap.delete(normalizeSeedPath(oldPath));
          fileMap.set(nextPath, { ...existing, path: nextPath });
          return true;
        },
        deleteDetectionFile: async (filePath: string) => fileMap.delete(normalizeSeedPath(filePath)),
        invoke: async (cmd: string, args?: Record<string, unknown>) => {
          if (cmd === "search_in_project") {
            return searchProject(
              String(args?.rootPath ?? ""),
              String(args?.query ?? ""),
              Boolean(args?.caseSensitive),
              Boolean(args?.wholeWord),
              Boolean(args?.useRegex),
            );
          }

          return null;
        },
      };

      window.addEventListener("clawdstrike:editor-reveal", (event) => {
        const customEvent = event as CustomEvent;
        (window as Window & { __WORKBENCH_E2E_LAST_REVEAL__?: unknown }).__WORKBENCH_E2E_LAST_REVEAL__ =
          customEvent.detail ?? null;
      });

      localStorage.clear();
      sessionStorage.clear();
      localStorage.setItem("clawdstrike_workbench_operator", JSON.stringify(operator));
      localStorage.setItem("clawdstrike_workbench_tabs", JSON.stringify(persistedTabs));
      localStorage.setItem("clawdstrike_workbench_policies", "[]");
      localStorage.setItem("clawdstrike_workspace_roots", JSON.stringify([workspaceRoot]));
      localStorage.setItem("clawdstrike_pane_layout", JSON.stringify(paneSession));
      localStorage.setItem(
        "clawdstrike_hint_settings",
        JSON.stringify({ showHints: true, overrides: {} }),
      );
    },
    {
      files: options.files,
      tabs: options.tabs,
      activeTabId,
      defaultContentsByType: DEFAULT_CONTENT_BY_TYPE,
      operator: DEFAULT_OPERATOR,
    },
  );
}

export async function expectEditorToContain(page: Page, text: string): Promise<void> {
  await expect(page.locator(".cm-content").first()).toContainText(text);
}
