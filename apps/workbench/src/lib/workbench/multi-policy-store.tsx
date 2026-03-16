import React, {
  createContext,
  useContext,
  useReducer,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  type ReactNode,
} from "react";
import type {
  WorkbenchPolicy,
  ValidationResult,
  ValidationIssue,
  SavedPolicy,
  GuardId,
  GuardConfigMap,
  OriginsConfig,
} from "./types";
import {
  DEFAULT_POLICY,
  type WorkbenchState,
  type WorkbenchAction,
  type PolicySnapshot,
  type NativeValidationState,
} from "./policy-store";
import { policyToYaml, yamlToPolicy, validatePolicy } from "./yaml-utils";
import { parseSigmaYaml } from "./sigma-types";
import {
  sanitizeObjectForStorageWithMetadata,
  sanitizeYamlForStorageWithMetadata,
} from "./storage-sanitizer";
import {
  FILE_TYPE_REGISTRY,
  coerceFileType,
  getPrimaryExtension,
  isPolicyFileType,
  sanitizeFilenameStem,
  basenameFromPath,
  type FileType,
} from "./file-type-registry";
import {
  isDesktop,
  openDetectionFile,
  saveDetectionFile,
  readDetectionFileByPath,
} from "@/lib/tauri-bridge";
import { getDocumentIdentityStore } from "./detection-workflow/document-identity-store";


export interface PolicyTab {
  id: string;
  /** Stable document identity — survives tab close/reopen, save, rename. */
  documentId: string;
  name: string;
  filePath: string | null;
  dirty: boolean;
  fileType: FileType;
  policy: WorkbenchPolicy;
  yaml: string;
  validation: ValidationResult;
  nativeValidation: NativeValidationState;
  testSuiteYaml?: string;
  _undoPast: PolicySnapshot[];
  _undoFuture: PolicySnapshot[];
  _cleanSnapshot: PolicySnapshot | null;
}

export type SplitMode = "none" | "horizontal" | "vertical";

export interface MultiPolicyState {
  tabs: PolicyTab[];
  activeTabId: string;
  splitMode: SplitMode;
  splitTabId: string | null;
  savedPolicies: SavedPolicy[];
  ui: {
    sidebarCollapsed: boolean;
    activeEditorTab: "visual" | "yaml";
    editorSyncDirection: "visual" | "yaml" | null;
  };
}

export interface BulkGuardUpdate {
  tabId: string;
  guardId: GuardId;
  enabled: boolean;
  config?: Record<string, unknown>;
}

export type MultiPolicyAction =
  | {
    type: "NEW_TAB";
    policy?: WorkbenchPolicy;
    filePath?: string | null;
    fileType?: FileType;
    yaml?: string;
    documentId?: string;
  }
  | { type: "CLOSE_TAB"; tabId: string }
  | { type: "SWITCH_TAB"; tabId: string }
  | { type: "SET_SPLIT_MODE"; mode: SplitMode }
  | { type: "SET_SPLIT_TAB"; tabId: string | null }
  | { type: "RENAME_TAB"; tabId: string; name: string }
  | { type: "REORDER_TABS"; fromIndex: number; toIndex: number }
  | { type: "DUPLICATE_TAB"; tabId: string }
  | { type: "BULK_UPDATE_GUARDS"; updates: BulkGuardUpdate[] }
  | { type: "OPEN_TAB_OR_SWITCH"; filePath: string; fileType: FileType; yaml: string; name?: string }
  | { type: "SET_TAB_TEST_SUITE"; tabId: string; yaml: string }
  | {
    type: "RESTORE_AUTOSAVE_ENTRIES";
    entries: Array<{
      tabId?: string;
      yaml: string;
      filePath: string | null;
      timestamp: number;
      policyName: string;
      fileType?: FileType;
    }>;
  }
  // Delegated to active tab — same as WorkbenchAction
  | { type: "SET_POLICY"; policy: WorkbenchPolicy }
  | { type: "SET_YAML"; yaml: string }
  | { type: "UPDATE_GUARD"; guardId: GuardId; config: Partial<GuardConfigMap[GuardId]> }
  | { type: "TOGGLE_GUARD"; guardId: GuardId; enabled: boolean }
  | { type: "UPDATE_SETTINGS"; settings: Partial<WorkbenchPolicy["settings"]> }
  | { type: "UPDATE_META"; name?: string; description?: string; version?: string; extends?: string }
  | { type: "UPDATE_ORIGINS"; origins: OriginsConfig | undefined }
  | { type: "SAVE_POLICY"; savedPolicy: SavedPolicy }
  | { type: "DELETE_SAVED_POLICY"; id: string }
  | { type: "LOAD_SAVED_POLICIES"; policies: SavedPolicy[] }
  | { type: "SET_COMPARISON"; policy: WorkbenchPolicy | null; yaml?: string }
  | { type: "SET_SIDEBAR_COLLAPSED"; collapsed: boolean }
  | { type: "SET_EDITOR_TAB"; tab: "visual" | "yaml" }
  | { type: "SET_FILE_PATH"; path: string | null }
  | { type: "MARK_CLEAN" }
  | { type: "SET_NATIVE_VALIDATION"; payload: NativeValidationState }
  | { type: "UNDO" }
  | { type: "REDO" };


const TABS_STORAGE_KEY = "clawdstrike_workbench_tabs";
const SAVED_POLICIES_KEY = "clawdstrike_workbench_policies";
const RECENT_FILES_KEY = "clawdstrike_recent_files";
const MAX_RECENT_FILES = 10;
const MAX_TABS = 25;
const MAX_HISTORY = 50;


function createTabId(): string {
  return crypto.randomUUID();
}

function createDocumentId(): string {
  return crypto.randomUUID();
}

/**
 * Resolve or create a documentId for a file path.
 * If the file has been opened before, returns its existing documentId.
 * Otherwise creates a new one and registers the alias.
 */
function resolveDocumentId(filePath: string | null): string {
  if (!filePath) return createDocumentId();

  const store = getDocumentIdentityStore();
  const existing = store.resolve(filePath);
  if (existing) return existing;

  const newId = createDocumentId();
  store.register(filePath, newId);
  return newId;
}

function emptyValidation(): ValidationResult {
  return {
    valid: true,
    errors: [],
    warnings: [],
  };
}

function emptyNativeValidation(): NativeValidationState {
  return {
    guardErrors: {},
    topLevelErrors: [],
    topLevelWarnings: [],
    loading: false,
    valid: null,
  };
}

function createPlaceholderPolicy(name: string): WorkbenchPolicy {
  return {
    version: DEFAULT_POLICY.version,
    name,
    description: "",
    guards: {},
    settings: {},
  };
}

function toValidationResult(
  messages: string[],
  path: string,
  severity: ValidationIssue["severity"] = "error",
): ValidationResult {
  const issues = messages.map((message) => ({
    path,
    message,
    severity,
  }));

  return {
    valid: severity !== "error" && issues.length > 0 ? true : issues.length === 0,
    errors: severity === "error" ? issues : [],
    warnings: severity === "warning" ? issues : [],
  };
}

function stripWrappingQuotes(value: string): string {
  return value.replace(/^['"]|['"]$/g, "").trim();
}

function extractNameFromPolicyYaml(yaml: string): string | null {
  const [policy, errors] = yamlToPolicy(yaml);
  if (policy?.name?.trim() && errors.length === 0) {
    return policy.name.trim();
  }

  const match = yaml.match(/^\s*name:\s*(.+)$/m);
  return match ? stripWrappingQuotes(match[1]) : null;
}

function extractNameFromSigmaYaml(yaml: string): string | null {
  const { rule } = parseSigmaYaml(yaml);
  if (rule?.title?.trim()) {
    return rule.title.trim();
  }

  const match = yaml.match(/^\s*title:\s*(.+)$/m);
  return match ? stripWrappingQuotes(match[1]) : null;
}

function extractNameFromYaraSource(source: string): string | null {
  const match = source.match(/(?:private\s+|global\s+)*rule\s+([A-Za-z_]\w*)/);
  return match?.[1] ?? null;
}

function extractNameFromOcsfJson(json: string): string | null {
  try {
    const value = JSON.parse(json) as Record<string, unknown>;
    const findingTitle = value.finding_info
      && typeof value.finding_info === "object"
      && typeof (value.finding_info as Record<string, unknown>).title === "string"
      ? String((value.finding_info as Record<string, unknown>).title).trim()
      : "";
    if (findingTitle) return findingTitle;

    const message = typeof value.message === "string" ? value.message.trim() : "";
    if (message) return message;
  } catch {
    // ignore parse failures when deriving a label
  }

  return null;
}

function extractNameFromSource(
  fileType: FileType,
  source: string,
  filePath?: string | null,
  fallback?: string,
): string {
  const fromContent = (() => {
    switch (fileType) {
      case "sigma_rule":
        return extractNameFromSigmaYaml(source);
      case "yara_rule":
        return extractNameFromYaraSource(source);
      case "ocsf_event":
        return extractNameFromOcsfJson(source);
      case "clawdstrike_policy":
      default:
        return extractNameFromPolicyYaml(source);
    }
  })();

  if (fromContent) return fromContent;

  const basename = basenameFromPath(filePath);
  if (basename) {
    return basename.replace(/\.[^.]+$/, "");
  }

  return fallback || FILE_TYPE_REGISTRY[fileType].label;
}

function hasSigmaObjectValuedDetectionSelector(detection: Record<string, unknown>): boolean {
  return Object.entries(detection).some(
    ([key, value]) =>
      key !== "condition"
      && key !== "timeframe"
      && value != null
      && typeof value === "object"
      && !Array.isArray(value),
  );
}

function validateSigmaSource(yaml: string): ValidationResult {
  const { rule, errors } = parseSigmaYaml(yaml);
  const nextErrors = [...errors];

  if (rule && !hasSigmaObjectValuedDetectionSelector(rule.detection as Record<string, unknown>)) {
    nextErrors.push("Sigma import requires at least one object-valued detection selector");
  }

  return toValidationResult(nextErrors, "sigma");
}

interface YaraScanState {
  inBlockComment: boolean;
  inHexString: boolean;
}

function analyzeYaraLine(
  line: string,
  state: YaraScanState,
): {
  code: string;
  opens: number;
  closes: number;
  hasCondition: boolean;
  state: YaraScanState;
} {
  let opens = 0;
  let closes = 0;
  let inString = false;
  let inRegex = false;
  let escaped = false;
  let inBlockComment = state.inBlockComment;
  let inHexString = state.inHexString;
  let lastStructuralNonWs = "";
  let code = "";

  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    const next = line[i + 1];

    if (inBlockComment) {
      if (ch === "*" && next === "/") {
        inBlockComment = false;
        i++;
      }
      continue;
    }

    if (escaped) {
      escaped = false;
      continue;
    }

    if (ch === "\\" && (inString || inRegex)) {
      escaped = true;
      continue;
    }

    if (!inString && !inRegex && !inHexString && ch === "/" && next === "/") {
      break;
    }

    if (!inString && !inRegex && !inHexString && ch === "/" && next === "*") {
      inBlockComment = true;
      i++;
      continue;
    }

    if (inHexString) {
      if (ch === "}") {
        inHexString = false;
        lastStructuralNonWs = "";
      }
      continue;
    }

    if (ch === '"' && !inRegex) {
      inString = !inString;
      if (!inString) {
        lastStructuralNonWs = "";
      }
      continue;
    }

    if (ch === "/" && !inString) {
      const prev = i > 0 ? line[i - 1] : " ";
      if (!inRegex && !/[A-Za-z0-9_]/.test(prev) && next !== "/" && next !== "*") {
        inRegex = true;
        continue;
      }
      if (inRegex) {
        inRegex = false;
        lastStructuralNonWs = "";
        while (/[A-Za-z]/.test(line[i + 1] ?? "")) {
          i++;
        }
        continue;
      }
    }

    if (!inString && !inRegex) {
      if (ch === "{") {
        if (lastStructuralNonWs === "=") {
          inHexString = true;
          continue;
        }
        opens++;
      } else if (ch === "}") {
        closes++;
      }

      code += ch;
      if (ch.trim()) {
        lastStructuralNonWs = ch;
      }
    }
  }

  return {
    code,
    opens,
    closes,
    hasCondition: code.includes("condition:"),
    state: { inBlockComment, inHexString },
  };
}

function stripYaraRuleModifiers(line: string): string {
  let rest = line.trim();
  while (rest.startsWith("private ") || rest.startsWith("global ")) {
    if (rest.startsWith("private ")) {
      rest = rest.slice("private ".length).trimStart();
      continue;
    }
    rest = rest.slice("global ".length).trimStart();
  }
  return rest;
}

function validateYaraSource(source: string): ValidationResult {
  const errors: string[] = [];
  const lines = source.split(/\r?\n/);
  let ruleCount = 0;
  let scanState: YaraScanState = { inBlockComment: false, inHexString: false };
  let currentRule: { name: string; sawCondition: boolean; braceDepth: number } | null = null;

  for (const line of lines) {
    const analyzed = analyzeYaraLine(line, scanState);
    scanState = analyzed.state;
    const ruleMatch = stripYaraRuleModifiers(analyzed.code).match(/^rule\s+([A-Za-z_]\w*)\b/);

    if (ruleMatch) {
      if (currentRule && !currentRule.sawCondition) {
        errors.push(`Rule "${currentRule.name}" is missing a condition section`);
      }
      currentRule = {
        name: ruleMatch[1],
        sawCondition: analyzed.hasCondition,
        braceDepth: analyzed.opens - analyzed.closes,
      };
      ruleCount += 1;
      continue;
    }

    if (!currentRule) continue;

    if (analyzed.hasCondition) {
      currentRule.sawCondition = true;
    }

    currentRule.braceDepth += analyzed.opens - analyzed.closes;

    if (currentRule.braceDepth <= 0) {
      if (!currentRule.sawCondition) {
        errors.push(`Rule "${currentRule.name}" is missing a condition section`);
      }
      currentRule = null;
    }
  }

  if (ruleCount === 0) {
    errors.push("No YARA rule declarations found");
  } else if (currentRule && !currentRule.sawCondition) {
    errors.push(`Rule "${currentRule.name}" is missing a condition section`);
  }

  return toValidationResult(errors, "yara");
}

function validateOcsfSource(json: string): ValidationResult {
  try {
    const value = JSON.parse(json) as unknown;
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      return toValidationResult(["OCSF event must be a JSON object"], "ocsf");
    }

    const event = value as Record<string, unknown>;
    const errors: string[] = [];

    const asRecord = (candidate: unknown): Record<string, unknown> | null =>
      candidate && typeof candidate === "object" && !Array.isArray(candidate)
        ? candidate as Record<string, unknown>
        : null;

    const readUnsignedInteger = (field: string): number | null => {
      const current = event[field];
      if (current === undefined || current === null) {
        errors.push(`Missing required OCSF field: ${field}`);
        return null;
      }
      if (typeof current !== "number" || !Number.isInteger(current) || current < 0) {
        errors.push(`Invalid type for OCSF field ${field}: expected unsigned integer`);
        return null;
      }
      return current;
    };

    const readInteger = (field: string): number | null => {
      const current = event[field];
      if (current === undefined || current === null) {
        errors.push(`Missing required OCSF field: ${field}`);
        return null;
      }
      if (typeof current !== "number" || !Number.isInteger(current)) {
        errors.push(`Invalid type for OCSF field ${field}: expected integer`);
        return null;
      }
      return current;
    };

    const classUid = readUnsignedInteger("class_uid");
    const activityId = readUnsignedInteger("activity_id");
    const typeUid = readUnsignedInteger("type_uid");
    const severityId = readUnsignedInteger("severity_id");
    readUnsignedInteger("status_id");
    readInteger("time");
    readUnsignedInteger("category_uid");

    const metadata = asRecord(event.metadata);
    if (!metadata) {
      errors.push("Missing required OCSF field: metadata");
    } else {
      if (typeof metadata.version !== "string" || metadata.version.trim() === "") {
        errors.push("Missing required OCSF field: metadata.version");
      }

      const product = asRecord(metadata.product);
      if (!product) {
        errors.push("Missing required OCSF field: metadata.product");
      } else {
        if (typeof product.name !== "string" || product.name.trim() === "") {
          errors.push("Missing required OCSF field: metadata.product.name");
        }
        if (typeof product.vendor_name !== "string" || product.vendor_name.trim() === "") {
          errors.push("Missing required OCSF field: metadata.product.vendor_name");
        }
      }
    }

    if (classUid !== null && activityId !== null && typeUid !== null && typeUid !== classUid * 100 + activityId) {
      errors.push(`type_uid mismatch: expected ${classUid * 100 + activityId}, got ${typeUid}`);
    }

    if (severityId !== null && severityId > 6 && severityId !== 99) {
      errors.push(`severity_id ${severityId} is not a valid OCSF severity (0-6, 99)`);
    }

    if (classUid === 2004) {
      const findingInfo = asRecord(event.finding_info);
      if (!findingInfo) {
        errors.push("Missing required OCSF field: finding_info");
      } else {
        if (typeof findingInfo.uid !== "string" || findingInfo.uid.trim() === "") {
          errors.push("Missing required OCSF field: finding_info.uid");
        }
        if (typeof findingInfo.title !== "string" || findingInfo.title.trim() === "") {
          errors.push("Missing required OCSF field: finding_info.title");
        }
        if (findingInfo.analytic === undefined || findingInfo.analytic === null) {
          errors.push("Missing required OCSF field: finding_info.analytic");
        }
      }

      readUnsignedInteger("action_id");
      readUnsignedInteger("disposition_id");
    }

    return toValidationResult(errors, "ocsf");
  } catch (error) {
    return toValidationResult(
      [`JSON parse error: ${error instanceof Error ? error.message : String(error)}`],
      "ocsf",
    );
  }
}

function validateSourceForFileType(fileType: FileType, source: string): ValidationResult {
  switch (fileType) {
    case "sigma_rule":
      return validateSigmaSource(source);
    case "yara_rule":
      return validateYaraSource(source);
    case "ocsf_event":
      return validateOcsfSource(source);
    case "clawdstrike_policy":
    default:
      return emptyValidation();
  }
}

function evaluateTabSource(
  fileType: FileType,
  source: string,
  currentPolicy: WorkbenchPolicy,
  filePath?: string | null,
  fallbackName?: string,
): { policy: WorkbenchPolicy; validation: ValidationResult; name: string } {
  const derivedName = extractNameFromSource(fileType, source, filePath, fallbackName);

  if (isPolicyFileType(fileType)) {
    const [policy, errors] = yamlToPolicy(source);
    if (policy && errors.length === 0) {
      return {
        policy,
        validation: validatePolicy(policy),
        name: policy.name || derivedName,
      };
    }

    return {
      policy: currentPolicy,
      validation: toValidationResult(errors, "yaml"),
      name: derivedName,
    };
  }

  return {
    policy: createPlaceholderPolicy(derivedName),
    validation: validateSourceForFileType(fileType, source),
    name: derivedName,
  };
}

function createDefaultTab(id?: string, fileType?: FileType, documentId?: string): PolicyTab {
  const nextFileType = coerceFileType(fileType);
  const yaml = isPolicyFileType(nextFileType)
    ? policyToYaml(DEFAULT_POLICY)
    : FILE_TYPE_REGISTRY[nextFileType].defaultContent;
  const { policy, validation, name } = evaluateTabSource(
    nextFileType,
    yaml,
    DEFAULT_POLICY,
    null,
    DEFAULT_POLICY.name,
  );
  return {
    id: id ?? createTabId(),
    documentId: documentId ?? createDocumentId(),
    name,
    filePath: null,
    dirty: false,
    fileType: nextFileType,
    policy,
    yaml,
    validation,
    nativeValidation: emptyNativeValidation(),
    _undoPast: [],
    _undoFuture: [],
    _cleanSnapshot: null,
  };
}

function createTabFromPolicy(policy: WorkbenchPolicy, filePath?: string | null, fileType?: FileType): PolicyTab {
  const yaml = policyToYaml(policy);
  return {
    id: createTabId(),
    documentId: resolveDocumentId(filePath ?? null),
    name: policy.name || "Untitled",
    filePath: filePath ?? null,
    dirty: false,
    fileType: fileType ?? "clawdstrike_policy",
    policy,
    yaml,
    validation: validatePolicy(policy),
    nativeValidation: emptyNativeValidation(),
    _undoPast: [],
    _undoFuture: [],
    _cleanSnapshot: {
      activePolicy: policy,
      yaml,
      validation: validatePolicy(policy),
    },
  };
}

function replaceTabFromOpenedFile(
  tab: PolicyTab,
  filePath: string,
  fileType: FileType,
  yamlFromDisk: string,
  name?: string,
): PolicyTab {
  const evaluated = evaluateTabSource(
    fileType,
    yamlFromDisk,
    tab.policy,
    filePath,
    name ?? tab.name,
  );

  return {
    ...tab,
    name: evaluated.name || "Untitled",
    filePath,
    fileType,
    yaml: yamlFromDisk,
    policy: evaluated.policy,
    dirty: false,
    validation: evaluated.validation,
    nativeValidation: emptyNativeValidation(),
    _undoPast: [],
    _undoFuture: [],
    _cleanSnapshot: {
      activePolicy: evaluated.policy,
      yaml: yamlFromDisk,
      validation: evaluated.validation,
    },
  };
}

function takeTabSnapshot(tab: PolicyTab): PolicySnapshot {
  return {
    activePolicy: tab.policy,
    yaml: tab.yaml,
    validation: tab.validation,
  };
}

function snapshotsEqual(a: PolicySnapshot, b: PolicySnapshot): boolean {
  return a.yaml === b.yaml;
}

function isTabDirtyVsClean(tab: PolicyTab): boolean {
  if (!tab._cleanSnapshot) return true;
  return !snapshotsEqual(takeTabSnapshot(tab), tab._cleanSnapshot);
}

function revalidate(policy: WorkbenchPolicy, yaml?: string): { yaml: string; validation: ValidationResult } {
  const y = yaml ?? policyToYaml(policy);
  return {
    yaml: y,
    validation: validatePolicy(policy),
  };
}

function applySourceToTab(
  tab: PolicyTab,
  source: string,
  options?: {
    dirty?: boolean;
    filePath?: string | null;
    nameFallback?: string;
    fileType?: FileType;
  },
): PolicyTab {
  const nextDirty = options?.dirty ?? tab.dirty;
  const nextFilePath = options?.filePath !== undefined ? options.filePath : tab.filePath;
  const nextFileType = options?.fileType ?? tab.fileType;
  const evaluated = evaluateTabSource(
    nextFileType,
    source,
    tab.policy,
    nextFilePath,
    options?.nameFallback ?? tab.name,
  );

  return {
    ...tab,
    fileType: nextFileType,
    policy: evaluated.policy,
    name: evaluated.name,
    yaml: source,
    filePath: nextFilePath,
    dirty: nextDirty,
    validation: evaluated.validation,
    nativeValidation: emptyNativeValidation(),
  };
}

/** Actions that modify the policy and should be tracked by undo/redo. */
const POLICY_MODIFYING_ACTIONS = new Set([
  "SET_POLICY",
  "SET_YAML",
  "UPDATE_GUARD",
  "TOGGLE_GUARD",
  "UPDATE_SETTINGS",
  "UPDATE_META",
  "UPDATE_ORIGINS",
]);

/** Actions that are delegated to the active tab's policy state. */
const TAB_DELEGATED_ACTIONS = new Set([
  "SET_POLICY",
  "SET_YAML",
  "UPDATE_GUARD",
  "TOGGLE_GUARD",
  "UPDATE_SETTINGS",
  "UPDATE_META",
  "UPDATE_ORIGINS",
  "SET_FILE_PATH",
  "MARK_CLEAN",
  "SET_NATIVE_VALIDATION",
  "UNDO",
  "REDO",
]);


function tabCoreReducer(tab: PolicyTab, action: MultiPolicyAction): PolicyTab {
  switch (action.type) {
    case "SET_POLICY": {
      if (!isPolicyFileType(tab.fileType)) {
        return tab;
      }
      const rv = revalidate(action.policy);
      return {
        ...tab,
        policy: action.policy,
        name: action.policy.name || tab.name,
        dirty: true,
        ...rv,
      };
    }

    case "SET_YAML": {
      return applySourceToTab(tab, action.yaml, { dirty: true });
    }

    case "UPDATE_GUARD": {
      if (!isPolicyFileType(tab.fileType)) {
        return tab;
      }
      const newGuards = {
        ...tab.policy.guards,
        [action.guardId]: {
          ...(tab.policy.guards[action.guardId] || {}),
          ...action.config,
        },
      };
      const newPolicy = { ...tab.policy, guards: newGuards };
      return { ...tab, policy: newPolicy, dirty: true, ...revalidate(newPolicy) };
    }

    case "TOGGLE_GUARD": {
      if (!isPolicyFileType(tab.fileType)) {
        return tab;
      }
      const existing = tab.policy.guards[action.guardId] || {};
      const newGuards = {
        ...tab.policy.guards,
        [action.guardId]: { ...existing, enabled: action.enabled },
      };
      if (!action.enabled) {
        const config = newGuards[action.guardId];
        if (config && Object.keys(config).length === 1 && "enabled" in config) {
          delete newGuards[action.guardId];
        }
      }
      const newPolicy = { ...tab.policy, guards: newGuards };
      return { ...tab, policy: newPolicy, dirty: true, ...revalidate(newPolicy) };
    }

    case "UPDATE_SETTINGS": {
      if (!isPolicyFileType(tab.fileType)) {
        return tab;
      }
      const newPolicy = {
        ...tab.policy,
        settings: { ...tab.policy.settings, ...action.settings },
      };
      return { ...tab, policy: newPolicy, dirty: true, ...revalidate(newPolicy) };
    }

    case "UPDATE_META": {
      if (!isPolicyFileType(tab.fileType)) {
        return tab;
      }
      const newPolicy = { ...tab.policy };
      if (action.name !== undefined) {
        newPolicy.name = action.name;
      }
      if (action.description !== undefined) newPolicy.description = action.description;
      if (action.version !== undefined) newPolicy.version = action.version as WorkbenchPolicy["version"];
      if (action.extends !== undefined) newPolicy.extends = action.extends || undefined;
      const rv = revalidate(newPolicy);
      return {
        ...tab,
        policy: newPolicy,
        name: newPolicy.name || tab.name,
        dirty: true,
        ...rv,
      };
    }

    case "UPDATE_ORIGINS": {
      if (!isPolicyFileType(tab.fileType)) {
        return tab;
      }
      const newPolicy = { ...tab.policy, origins: action.origins };
      return { ...tab, policy: newPolicy, dirty: true, ...revalidate(newPolicy) };
    }

    case "SET_FILE_PATH": {
      return { ...tab, filePath: action.path };
    }

    case "MARK_CLEAN": {
      return {
        ...tab,
        dirty: false,
        _cleanSnapshot: takeTabSnapshot(tab),
      };
    }

    case "SET_NATIVE_VALIDATION": {
      return { ...tab, nativeValidation: action.payload };
    }

    case "UNDO":
    case "REDO":
      return tab;

    default:
      return tab;
  }
}

function tabReducer(tab: PolicyTab, action: MultiPolicyAction): PolicyTab {
  if (action.type === "UNDO") {
    if (tab._undoPast.length === 0) return tab;
    const past = [...tab._undoPast];
    const snapshot = past.pop()!;
    const currentSnapshot = takeTabSnapshot(tab);
    const newTab: PolicyTab = {
      ...tab,
      policy: snapshot.activePolicy,
      yaml: snapshot.yaml,
      validation: snapshot.validation,
      _undoPast: past,
      _undoFuture: [currentSnapshot, ...tab._undoFuture],
    };
    newTab.dirty = isTabDirtyVsClean(newTab);
    return newTab;
  }

  if (action.type === "REDO") {
    if (tab._undoFuture.length === 0) return tab;
    const future = [...tab._undoFuture];
    const snapshot = future.shift()!;
    const currentSnapshot = takeTabSnapshot(tab);
    const newTab: PolicyTab = {
      ...tab,
      policy: snapshot.activePolicy,
      yaml: snapshot.yaml,
      validation: snapshot.validation,
      _undoPast: [...tab._undoPast, currentSnapshot].slice(-MAX_HISTORY),
      _undoFuture: future,
    };
    newTab.dirty = isTabDirtyVsClean(newTab);
    return newTab;
  }

  if (POLICY_MODIFYING_ACTIONS.has(action.type)) {
    const currentSnapshot = takeTabSnapshot(tab);
    const next = tabCoreReducer(tab, action);
    const nextSnapshot = takeTabSnapshot(next);
    if (snapshotsEqual(currentSnapshot, nextSnapshot)) return next;
    return {
      ...next,
      _undoPast: [...tab._undoPast, currentSnapshot].slice(-MAX_HISTORY),
      _undoFuture: [],
    };
  }

  return tabCoreReducer(tab, action);
}


function multiPolicyReducer(state: MultiPolicyState, action: MultiPolicyAction): MultiPolicyState {
  switch (action.type) {
    case "NEW_TAB": {
      if (state.tabs.length >= MAX_TABS) return state;
      let newTab: PolicyTab;
      if (action.policy) {
        newTab = createTabFromPolicy(action.policy, action.filePath, action.fileType);
      } else if (action.yaml) {
        newTab = createDefaultTab(undefined, action.fileType, action.documentId);
        newTab = applySourceToTab(newTab, action.yaml, {
          dirty: false,
          nameFallback: FILE_TYPE_REGISTRY[action.fileType ?? newTab.fileType].label,
          fileType: action.fileType,
        });
        newTab._cleanSnapshot = takeTabSnapshot(newTab);
      } else {
        newTab = createDefaultTab(undefined, action.fileType, action.documentId);
      }
      return {
        ...state,
        tabs: [...state.tabs, newTab],
        activeTabId: newTab.id,
      };
    }

    case "CLOSE_TAB": {
      const idx = state.tabs.findIndex((t) => t.id === action.tabId);
      if (idx === -1) return state;
      const newTabs = state.tabs.filter((t) => t.id !== action.tabId);

      // Don't allow closing the last tab — create a fresh default one
      if (newTabs.length === 0) {
        const freshTab = createDefaultTab();
        return {
          ...state,
          tabs: [freshTab],
          activeTabId: freshTab.id,
          splitTabId: null,
          splitMode: "none",
        };
      }

      let newActiveId = state.activeTabId;
      if (state.activeTabId === action.tabId) {
        // Switch to the tab before the closed one, or the first
        const newIdx = Math.min(idx, newTabs.length - 1);
        newActiveId = newTabs[newIdx].id;
      }

      let newSplitTabId = state.splitTabId;
      if (state.splitTabId === action.tabId) {
        newSplitTabId = null;
      }

      return {
        ...state,
        tabs: newTabs,
        activeTabId: newActiveId,
        splitTabId: newSplitTabId,
        splitMode: newSplitTabId === null && state.splitMode !== "none" ? "none" : state.splitMode,
      };
    }

    case "SWITCH_TAB": {
      if (!state.tabs.some((t) => t.id === action.tabId)) return state;
      return { ...state, activeTabId: action.tabId };
    }

    case "SET_SPLIT_MODE": {
      if (action.mode === "none") {
        return { ...state, splitMode: "none", splitTabId: null };
      }
      return { ...state, splitMode: action.mode };
    }

    case "SET_SPLIT_TAB": {
      return { ...state, splitTabId: action.tabId };
    }

    case "RENAME_TAB": {
      return {
        ...state,
        tabs: state.tabs.map((t) =>
          t.id === action.tabId ? { ...t, name: action.name } : t
        ),
      };
    }

    case "REORDER_TABS": {
      if (
        action.fromIndex < 0 ||
        action.toIndex < 0 ||
        action.fromIndex >= state.tabs.length ||
        action.toIndex >= state.tabs.length
      ) {
        return state;
      }
      const newTabs = [...state.tabs];
      const [moved] = newTabs.splice(action.fromIndex, 1);
      newTabs.splice(action.toIndex, 0, moved);
      return { ...state, tabs: newTabs };
    }

    case "DUPLICATE_TAB": {
      if (state.tabs.length >= MAX_TABS) return state;
      const source = state.tabs.find((t) => t.id === action.tabId);
      if (!source) return state;
      const duped: PolicyTab = {
        ...source,
        id: createTabId(),
        documentId: createDocumentId(), // New document identity for duplicates
        name: `${source.name} (copy)`,
        filePath: null,
        dirty: true,
        _undoPast: [],
        _undoFuture: [],
        _cleanSnapshot: null,
      };
      const idx = state.tabs.findIndex((t) => t.id === action.tabId);
      const newTabs = [...state.tabs];
      newTabs.splice(idx + 1, 0, duped);
      return {
        ...state,
        tabs: newTabs,
        activeTabId: duped.id,
      };
    }

    // Bulk guard update — applies guard changes across multiple tabs in a single
    // reducer call, avoiding the SWITCH_TAB + TOGGLE_GUARD race (#6).
    case "BULK_UPDATE_GUARDS": {
      const updatesByTab = new Map<string, BulkGuardUpdate[]>();
      for (const u of action.updates) {
        const list = updatesByTab.get(u.tabId) ?? [];
        list.push(u);
        updatesByTab.set(u.tabId, list);
      }

      const newTabs = state.tabs.map((tab) => {
        const updates = updatesByTab.get(tab.id);
        if (!updates) return tab;

        let current = tab;
        for (const u of updates) {
          // Apply toggle
          const toggleAction: MultiPolicyAction = {
            type: "TOGGLE_GUARD",
            guardId: u.guardId,
            enabled: u.enabled,
          };
          current = tabReducer(current, toggleAction);

          // Apply additional config if provided
          if (u.config && Object.keys(u.config).length > 0) {
            const configAction: MultiPolicyAction = {
              type: "UPDATE_GUARD",
              guardId: u.guardId,
              config: u.config as Partial<GuardConfigMap[GuardId]>,
            };
            current = tabReducer(current, configAction);
          }
        }

        return current;
      });

      return { ...state, tabs: newTabs };
    }

    // Atomically check if a file path is already open and switch to it, or
    // create a new tab — avoids stale closure race in async file dialogs (#31).
    case "OPEN_TAB_OR_SWITCH": {
      const existing = state.tabs.find((t) => t.filePath === action.filePath);
      if (existing) {
        // If content hasn't changed, just switch to the existing tab without
        // resetting documentId, undo history, or other metadata.
        if (existing.yaml === action.yaml && existing.fileType === action.fileType) {
          return { ...state, activeTabId: existing.id };
        }
        // Content changed on disk — replace but preserve documentId
        return {
          ...state,
          tabs: state.tabs.map((tab) => {
            if (tab.id !== existing.id) return tab;
            const replaced = replaceTabFromOpenedFile(tab, action.filePath, action.fileType, action.yaml, action.name);
            return { ...replaced, documentId: existing.documentId };
          }),
          activeTabId: existing.id,
        };
      }
      if (state.tabs.length >= MAX_TABS) return state;
      // Resolve documentId from alias store so reopened files keep their identity
      const resolvedDocId = resolveDocumentId(action.filePath);
      const newTab = replaceTabFromOpenedFile(
        createDefaultTab(undefined, action.fileType, resolvedDocId),
        action.filePath,
        action.fileType,
        action.yaml,
        action.name,
      );
      return {
        ...state,
        tabs: [...state.tabs, newTab],
        activeTabId: newTab.id,
      };
    }

    // Saved policies (global, not per-tab)
    case "SAVE_POLICY": {
      const existing = state.savedPolicies.filter((p) => p.id !== action.savedPolicy.id);
      return { ...state, savedPolicies: [...existing, action.savedPolicy] };
    }

    case "DELETE_SAVED_POLICY": {
      return {
        ...state,
        savedPolicies: state.savedPolicies.filter((p) => p.id !== action.id),
      };
    }

    case "LOAD_SAVED_POLICIES": {
      return { ...state, savedPolicies: action.policies };
    }

    // UI state (global)
    case "SET_SIDEBAR_COLLAPSED": {
      return { ...state, ui: { ...state.ui, sidebarCollapsed: action.collapsed } };
    }

    case "SET_EDITOR_TAB": {
      return { ...state, ui: { ...state.ui, activeEditorTab: action.tab } };
    }

    case "SET_TAB_TEST_SUITE": {
      return {
        ...state,
        tabs: state.tabs.map((t) =>
          t.id === action.tabId ? { ...t, testSuiteYaml: action.yaml } : t
        ),
      };
    }

    case "RESTORE_AUTOSAVE_ENTRIES": {
      if (action.entries.length === 0) return state;

      let nextTabs = [...state.tabs];
      let nextActiveTabId = state.activeTabId;

      for (const entry of action.entries) {
        const existingIndex = nextTabs.findIndex((tab) => {
          if (entry.tabId && tab.id === entry.tabId) return true;
          return entry.filePath !== null && tab.filePath === entry.filePath;
        });

        if (existingIndex >= 0) {
          const existing = nextTabs[existingIndex];
          nextTabs[existingIndex] = {
            ...applySourceToTab(existing, entry.yaml, {
              dirty: true,
              filePath: entry.filePath,
              nameFallback: entry.policyName || existing.name,
              fileType: entry.fileType ?? existing.fileType,
            }),
            _undoPast: [],
            _undoFuture: [],
          };
          nextActiveTabId = nextTabs[existingIndex].id;
          continue;
        }

        if (nextTabs.length >= MAX_TABS) {
          break;
        }

        // Resolve documentId for restored tabs via alias store
        const restoredDocId = resolveDocumentId(entry.filePath);
        const restored = applySourceToTab(createDefaultTab(entry.tabId, entry.fileType, restoredDocId), entry.yaml, {
          dirty: true,
          filePath: entry.filePath,
          nameFallback: entry.policyName || "Recovered Policy",
          fileType: entry.fileType,
        });
        nextTabs = [
          ...nextTabs,
          {
            ...restored,
            _undoPast: [],
            _undoFuture: [],
            _cleanSnapshot: null,
          },
        ];
        nextActiveTabId = restored.id;
      }

      return {
        ...state,
        tabs: nextTabs,
        activeTabId: nextActiveTabId,
      };
    }

    // SET_COMPARISON is a no-op in multi-policy mode (comparison lives in /compare route)
    case "SET_COMPARISON":
      return state;

    default:
      break;
  }

  // Delegate to active tab
  if (TAB_DELEGATED_ACTIONS.has(action.type)) {
    return {
      ...state,
      tabs: state.tabs.map((t) =>
        t.id === state.activeTabId ? tabReducer(t, action) : t
      ),
      // Sync UI editorSyncDirection for delegated SET_POLICY / SET_YAML
      ui: action.type === "SET_POLICY"
        ? { ...state.ui, editorSyncDirection: "visual" }
        : action.type === "SET_YAML"
        ? { ...state.ui, editorSyncDirection: "yaml" }
        : state.ui,
    };
  }

  return state;
}


function activeTab(state: MultiPolicyState): PolicyTab | undefined {
  return state.tabs.find((t) => t.id === state.activeTabId);
}

function toWorkbenchState(state: MultiPolicyState): WorkbenchState {
  const tab = activeTab(state);
  if (!tab) {
    // Should not happen, but defensive
    const yaml = policyToYaml(DEFAULT_POLICY);
    return {
      activePolicy: DEFAULT_POLICY,
      yaml,
      validation: validatePolicy(DEFAULT_POLICY),
      savedPolicies: state.savedPolicies,
      comparisonPolicy: null,
      comparisonYaml: "",
      filePath: null,
      dirty: false,
      nativeValidation: { guardErrors: {}, topLevelErrors: [], topLevelWarnings: [], loading: false, valid: null },
      _undoPast: [],
      _undoFuture: [],
      _cleanSnapshot: null,
      ui: state.ui,
    };
  }

  return {
    activePolicy: tab.policy,
    yaml: tab.yaml,
    validation: tab.validation,
    savedPolicies: state.savedPolicies,
    comparisonPolicy: null,
    comparisonYaml: "",
    filePath: tab.filePath,
    dirty: tab.dirty,
    nativeValidation: tab.nativeValidation,
    _undoPast: tab._undoPast,
    _undoFuture: tab._undoFuture,
    _cleanSnapshot: tab._cleanSnapshot,
    ui: state.ui,
  };
}


interface PersistedTab {
  id: string;
  /** Stable document identity — persisted so restored tabs keep their documentId. */
  documentId?: string;
  name: string;
  filePath: string | null;
  yaml: string;
  sensitiveFieldsStripped?: boolean;
  fileType?: FileType;
}

interface PersistedTabState {
  tabs: PersistedTab[];
  activeTabId: string;
}

function persistTabs(state: MultiPolicyState): void {
  try {
    const persisted: PersistedTabState = {
      tabs: state.tabs.map((t) => {
        const sanitized = sanitizeYamlForStorageWithMetadata(t.yaml);
        const sensitiveFieldsStripped = sanitized.sensitiveFieldsStripped;
        return {
          id: t.id,
          documentId: t.documentId,
          name: t.name,
          filePath: sensitiveFieldsStripped ? null : t.filePath,
          yaml: sanitized.yaml,
          sensitiveFieldsStripped: sensitiveFieldsStripped || undefined,
          fileType: t.fileType,
        };
      }),
      activeTabId: state.activeTabId,
    };
    localStorage.setItem(TABS_STORAGE_KEY, JSON.stringify(persisted));
  } catch (e) {
    // TODO: surface via toast when toast system is available outside React components
    console.error("[multi-policy-store] persistTabs failed — changes may be lost on reload:", e);
  }
}

function loadPersistedTabs(): MultiPolicyState | null {
  try {
    const raw = localStorage.getItem(TABS_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    // Validate persisted data shape
    if (!parsed || typeof parsed !== "object" || !Array.isArray(parsed.tabs)) {
      console.warn("[multi-policy-store] Invalid persisted tab data, using defaults");
      return null;
    }
    const persisted = parsed as PersistedTabState;
    if (persisted.tabs.length === 0) return null;

    // Per-entry type validation (#30): skip entries with invalid shape
    const validPersistedTabs = persisted.tabs.filter((pt) =>
      typeof pt.id === "string" && typeof pt.yaml === "string"
    );
    if (validPersistedTabs.length === 0) return null;

    const tabs: PolicyTab[] = validPersistedTabs.map((pt) => {
      const fileType = coerceFileType(pt.fileType);
      // Migration: legacy tabs without documentId get one resolved from filePath or generated fresh
      const documentId = pt.documentId ?? resolveDocumentId(pt.filePath);
      const hydrated = applySourceToTab(createDefaultTab(pt.id, fileType, documentId), pt.yaml, {
        dirty: false,
        filePath: pt.filePath,
        nameFallback: pt.name || FILE_TYPE_REGISTRY[fileType].label,
        fileType,
      });
      const sensitiveFieldsStripped = pt.sensitiveFieldsStripped === true;
      return {
        ...hydrated,
        filePath: sensitiveFieldsStripped ? null : pt.filePath,
        dirty: sensitiveFieldsStripped,
        nativeValidation: emptyNativeValidation(),
        _undoPast: [],
        _undoFuture: [],
        _cleanSnapshot: sensitiveFieldsStripped
          ? null
          : {
              activePolicy: hydrated.policy,
              yaml: hydrated.yaml,
              validation: hydrated.validation,
            },
      };
    });

    const activeTabId = tabs.some((t) => t.id === persisted.activeTabId)
      ? persisted.activeTabId
      : tabs[0].id;

    return {
      tabs,
      activeTabId,
      splitMode: "none",
      splitTabId: null,
      savedPolicies: [],
      ui: {
        sidebarCollapsed: false,
        activeEditorTab: "visual",
        editorSyncDirection: null,
      },
    };
  } catch (e) {
    console.warn("[multi-policy-store] loadPersistedTabs failed:", e);
    return null;
  }
}

function pushRecentFile(filePath: string): void {
  try {
    const stored = localStorage.getItem(RECENT_FILES_KEY);
    const parsed = stored ? JSON.parse(stored) : [];
    const files = Array.isArray(parsed) ? parsed.filter((f): f is string => typeof f === "string") : [];
    const updated = [filePath, ...files.filter((p) => p !== filePath)].slice(0, MAX_RECENT_FILES);
    localStorage.setItem(RECENT_FILES_KEY, JSON.stringify(updated));
  } catch (e) {
    console.warn("[multi-policy-store] pushRecentFile localStorage operation failed:", e);
  }
}

function sanitizeSavedPolicy(savedPolicy: SavedPolicy): SavedPolicy {
  const sanitized = sanitizeYamlForStorageWithMetadata(savedPolicy.yaml);
  const sanitizedPolicy = sanitizeObjectForStorageWithMetadata(savedPolicy.policy);
  const [parsedPolicy, errors] = yamlToPolicy(sanitized.yaml);
  const sensitiveFieldsStripped =
    sanitized.sensitiveFieldsStripped || sanitizedPolicy.sensitiveFieldsStripped;
  const storedPolicy =
    sensitiveFieldsStripped && parsedPolicy && errors.length === 0
      ? parsedPolicy
      : sanitizedPolicy.value;

  return {
    ...savedPolicy,
    yaml: sanitized.yaml,
    policy: storedPolicy,
    sensitiveFieldsStripped: sensitiveFieldsStripped || undefined,
  };
}


interface MultiPolicyContextValue {
  /** The full multi-policy state for components that need tab awareness. */
  multiState: MultiPolicyState;
  /** Dispatch for multi-policy actions. */
  multiDispatch: React.Dispatch<MultiPolicyAction>;
  /** Active tab, or undefined if no tabs exist (should never happen). */
  activeTab: PolicyTab | undefined;
  /** All open tabs. */
  tabs: PolicyTab[];
  /** Whether new tabs can be added. */
  canAddTab: boolean;
}

/**
 * Backward-compatible WorkbenchContext value — identical API to the single-policy store.
 * Components using useWorkbench() get this transparently.
 */
interface WorkbenchContextValue {
  state: WorkbenchState;
  dispatch: React.Dispatch<WorkbenchAction>;
  saveCurrentPolicy: () => void;
  exportYaml: () => void;
  copyYaml: () => void;
  loadPolicy: (policy: WorkbenchPolicy) => void;
  openFile: () => Promise<void>;
  openFileByPath: (filePath: string) => Promise<void>;
  saveFile: () => Promise<void>;
  saveFileAs: () => Promise<void>;
  newPolicy: () => void;
  undo: () => void;
  redo: () => void;
  canUndo: boolean;
  canRedo: boolean;
}

const MultiPolicyContext = createContext<MultiPolicyContextValue | null>(null);
const WorkbenchContext = createContext<WorkbenchContextValue | null>(null);


/** Access the multi-policy tab state (for tab bar, split pane, etc.). */
export function useMultiPolicy(): MultiPolicyContextValue {
  const ctx = useContext(MultiPolicyContext);
  if (!ctx) throw new Error("useMultiPolicy must be used within MultiPolicyProvider");
  return ctx;
}

/**
 * Backward-compatible hook — returns the active tab's state shaped as WorkbenchState.
 * Existing components that call useWorkbench() continue to work unchanged.
 */
export function useWorkbench(): WorkbenchContextValue {
  const ctx = useContext(WorkbenchContext);
  if (!ctx) throw new Error("useWorkbench must be used within MultiPolicyProvider");
  return ctx;
}


function getInitialState(): MultiPolicyState {
  const restored = loadPersistedTabs();
  if (restored) return restored;

  const defaultTab = createDefaultTab();
  return {
    tabs: [defaultTab],
    activeTabId: defaultTab.id,
    splitMode: "none",
    splitTabId: null,
    savedPolicies: [],
    ui: {
      sidebarCollapsed: false,
      activeEditorTab: "visual",
      editorSyncDirection: null,
    },
  };
}


export function MultiPolicyProvider({ children }: { children: ReactNode }) {
  const [multiState, multiDispatch] = useReducer(multiPolicyReducer, undefined, getInitialState);

  // Hydrate saved policies from localStorage with shape validation (#17)
  useEffect(() => {
    try {
      const stored = localStorage.getItem(SAVED_POLICIES_KEY);
      if (stored) {
        const parsed: unknown = JSON.parse(stored);
        if (!Array.isArray(parsed)) {
          console.warn("[multi-policy-store] Saved policies is not an array, skipping hydration");
          return;
        }
        const policies: SavedPolicy[] = parsed.filter((entry: unknown): entry is SavedPolicy => {
          if (!entry || typeof entry !== "object") return false;
          const e = entry as Record<string, unknown>;
          return (
            typeof e.id === "string" &&
            typeof e.policy === "object" && e.policy !== null &&
            typeof e.yaml === "string"
          );
        }).map(sanitizeSavedPolicy);
        multiDispatch({ type: "LOAD_SAVED_POLICIES", policies });
      }
    } catch (e) {
      console.warn("[multi-policy-store] hydrate saved policies failed:", e);
    }
  }, []);

  // Persist saved policies
  useEffect(() => {
    try {
      localStorage.setItem(
        SAVED_POLICIES_KEY,
        JSON.stringify(multiState.savedPolicies.map(sanitizeSavedPolicy)),
      );
    } catch (e) {
      // TODO: surface via toast when toast system is available outside React components
      console.error("[multi-policy-store] persist saved policies failed — changes may be lost on reload:", e);
    }
  }, [multiState.savedPolicies]);

  // Persist tab state on changes (debounced to avoid perf hit)
  const persistRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => {
    if (persistRef.current) clearTimeout(persistRef.current);
    persistRef.current = setTimeout(() => {
      persistTabs(multiState);
    }, 500);
    return () => {
      if (persistRef.current) clearTimeout(persistRef.current);
    };
  }, [multiState.tabs, multiState.activeTabId]);

  const currentTab = activeTab(multiState);

  // Compute backward-compatible WorkbenchState, memoized to avoid creating a
  // new reference on every render when the inputs haven't changed.
  const workbenchState = useMemo(
    () => toWorkbenchState(multiState),
    [
      currentTab?.policy,
      currentTab?.yaml,
      currentTab?.validation,
      currentTab?.nativeValidation,
      currentTab?.filePath,
      currentTab?.dirty,
      currentTab?._undoPast,
      currentTab?._undoFuture,
      currentTab?._cleanSnapshot,
      multiState.savedPolicies,
      multiState.ui,
    ],
  );

  // Bridge dispatch: WorkbenchAction -> MultiPolicyAction
  // The type sets are identical, so we can forward directly
  const workbenchDispatch = useCallback(
    (action: WorkbenchAction) => {
      multiDispatch(action as MultiPolicyAction);
    },
    [multiDispatch],
  );

  // ---- Callback implementations (mirroring single-policy store) ----

  const saveCurrentPolicy = useCallback(() => {
    if (!currentTab || !isPolicyFileType(currentTab.fileType)) return;
    const id = crypto.randomUUID();
    const now = new Date().toISOString();
    const savedPolicy = sanitizeSavedPolicy({
      id,
      policy: currentTab.policy,
      yaml: currentTab.yaml,
      createdAt: now,
      updatedAt: now,
    });
    multiDispatch({ type: "SAVE_POLICY", savedPolicy });
  }, [currentTab, multiDispatch]);

  const exportYaml = useCallback(() => {
    if (!currentTab) return;
    const blob = new Blob([currentTab.yaml], {
      type: currentTab.fileType === "ocsf_event" ? "application/json" : "text/plain",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    const stem = sanitizeFilenameStem(currentTab.name || "untitled", "untitled");
    a.download = `${stem}${getPrimaryExtension(currentTab.fileType)}`;
    a.click();
    URL.revokeObjectURL(url);
  }, [currentTab]);

  const copyYaml = useCallback(() => {
    if (!currentTab) return;
    navigator.clipboard.writeText(currentTab.yaml).catch(() => {});
  }, [currentTab]);

  const loadPolicy = useCallback(
    (policy: WorkbenchPolicy) => {
      if (currentTab && !isPolicyFileType(currentTab.fileType)) {
        multiDispatch({ type: "NEW_TAB", policy });
        return;
      }
      multiDispatch({ type: "SET_POLICY", policy });
    },
    [currentTab, multiDispatch],
  );

  const openFile = useCallback(async () => {
    try {
      const result = await openDetectionFile();
      if (!result) return;

      multiDispatch({
        type: "OPEN_TAB_OR_SWITCH",
        filePath: result.path,
        fileType: result.fileType,
        yaml: result.content,
      });
      pushRecentFile(result.path);
    } catch (err) {
      console.error("[multi-policy] Failed to open file:", err);
    }
  }, [multiDispatch]);

  const openFileByPath = useCallback(
    async (filePath: string) => {
      try {
        const result = await readDetectionFileByPath(filePath);
        if (!result) return;

        multiDispatch({
          type: "OPEN_TAB_OR_SWITCH",
          filePath: result.path,
          fileType: result.fileType,
          yaml: result.content,
        });
        pushRecentFile(result.path);
      } catch (err) {
        console.error("[multi-policy] Failed to open file by path:", err);
      }
    },
    [multiDispatch],
  );

  const saveFileAs = useCallback(async () => {
    if (!currentTab) return;
    try {
      if (!isDesktop()) {
        exportYaml();
        return;
      }
      const savedPath = await saveDetectionFile(
        currentTab.yaml,
        currentTab.fileType,
        null,
        currentTab.name,
      );
      if (!savedPath) return;
      // Register alias so reopening this path resolves the same documentId
      getDocumentIdentityStore().register(savedPath, currentTab.documentId);
      multiDispatch({ type: "SET_FILE_PATH", path: savedPath });
      multiDispatch({ type: "MARK_CLEAN" });
      pushRecentFile(savedPath);
    } catch (err) {
      console.error("[multi-policy] Failed to save file:", err);
    }
  }, [currentTab, exportYaml, multiDispatch]);

  const saveFile = useCallback(async () => {
    if (!currentTab) return;
    try {
      if (!isDesktop()) {
        exportYaml();
        return;
      }
      if (currentTab.filePath) {
        await saveDetectionFile(
          currentTab.yaml,
          currentTab.fileType,
          currentTab.filePath,
          currentTab.name,
        );
        multiDispatch({ type: "MARK_CLEAN" });
      } else {
        await saveFileAs();
      }
    } catch (err) {
      console.error("[multi-policy] Failed to save file:", err);
    }
  }, [currentTab, saveFileAs, exportYaml, multiDispatch]);

  const newPolicy = useCallback(() => {
    multiDispatch({ type: "NEW_TAB" });
  }, [multiDispatch]);

  const undo = useCallback(() => multiDispatch({ type: "UNDO" }), [multiDispatch]);
  const redo = useCallback(() => multiDispatch({ type: "REDO" }), [multiDispatch]);

  const canUndo = currentTab ? currentTab._undoPast.length > 0 : false;
  const canRedo = currentTab ? currentTab._undoFuture.length > 0 : false;

  const multiContextValue: MultiPolicyContextValue = {
    multiState,
    multiDispatch,
    activeTab: currentTab,
    tabs: multiState.tabs,
    canAddTab: multiState.tabs.length < MAX_TABS,
  };

  const workbenchContextValue: WorkbenchContextValue = {
    state: workbenchState,
    dispatch: workbenchDispatch,
    saveCurrentPolicy,
    exportYaml,
    copyYaml,
    loadPolicy,
    openFile,
    openFileByPath,
    saveFile,
    saveFileAs,
    newPolicy,
    undo,
    redo,
    canUndo,
    canRedo,
  };

  return (
    <MultiPolicyContext.Provider value={multiContextValue}>
      <WorkbenchContext.Provider value={workbenchContextValue}>
        {children}
      </WorkbenchContext.Provider>
    </MultiPolicyContext.Provider>
  );
}
