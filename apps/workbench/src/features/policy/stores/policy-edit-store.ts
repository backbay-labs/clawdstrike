/**
 * policy-edit-store.ts — Zustand store for per-tab editing state.
 *
 * Extracted from the monolithic multi-policy-store.tsx (Phase B1).
 * All editing data is stored in Maps keyed by tabId.
 * Cross-reads from policy-tabs-store for active tab ID.
 */
import { create } from "zustand";
import type {
  WorkbenchPolicy,
  ValidationResult,
  ValidationIssue,
  GuardId,
  GuardConfigMap,
  OriginsConfig,
} from "@/lib/workbench/types";
import {
  DEFAULT_POLICY,
  type PolicySnapshot,
  type NativeValidationState,
} from "@/features/policy/stores/policy-store";
import {
  policyToYaml,
  yamlToPolicy,
  validatePolicy,
} from "@/features/policy/yaml-utils";
import { parseSigmaYaml } from "@/lib/workbench/sigma-types";
import {
  FILE_TYPE_REGISTRY,
  isPolicyFileType,
  basenameFromPath,
  type FileType,
} from "@/lib/workbench/file-type-registry";

// ---- Constants ----

const MAX_HISTORY = 50;

// ---- Helper types ----

export interface UndoStack {
  past: PolicySnapshot[];
  future: PolicySnapshot[];
}

export interface TabEditState {
  policy: WorkbenchPolicy;
  yaml: string;
  validation: ValidationResult;
  nativeValidation: NativeValidationState;
  undoStack: UndoStack;
  cleanSnapshot: PolicySnapshot | null;
  testSuiteYaml?: string;
}

// ---- Pure helpers (extracted from multi-policy-store.tsx) ----

function emptyValidation(): ValidationResult {
  return { valid: true, errors: [], warnings: [] };
}

export function emptyNativeValidation(): NativeValidationState {
  return {
    guardErrors: {},
    topLevelErrors: [],
    topLevelWarnings: [],
    loading: false,
    valid: null,
  };
}

function toValidationResult(
  messages: string[],
  path: string,
  severity: ValidationIssue["severity"] = "error",
): ValidationResult {
  const issues = messages.map((message) => ({ path, message, severity }));
  return {
    valid:
      severity !== "error" && issues.length > 0 ? true : issues.length === 0,
    errors: severity === "error" ? issues : [],
    warnings: severity === "warning" ? issues : [],
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
  const match = source.match(
    /(?:private\s+|global\s+)*rule\s+([A-Za-z_]\w*)/,
  );
  return match?.[1] ?? null;
}

function extractNameFromOcsfJson(json: string): string | null {
  try {
    const value = JSON.parse(json) as Record<string, unknown>;
    const findingTitle =
      value.finding_info &&
      typeof value.finding_info === "object" &&
      typeof (value.finding_info as Record<string, unknown>).title === "string"
        ? String((value.finding_info as Record<string, unknown>).title).trim()
        : "";
    if (findingTitle) return findingTitle;
    const message =
      typeof value.message === "string" ? value.message.trim() : "";
    if (message) return message;
  } catch {
    // ignore parse failures when deriving a label
  }
  return null;
}

export function extractNameFromSource(
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

function hasSigmaObjectValuedDetectionSelector(
  detection: Record<string, unknown>,
): boolean {
  return Object.entries(detection).some(
    ([key, value]) =>
      key !== "condition" &&
      key !== "timeframe" &&
      value != null &&
      typeof value === "object" &&
      !Array.isArray(value),
  );
}

function validateSigmaSource(yaml: string): ValidationResult {
  const { rule, errors } = parseSigmaYaml(yaml);
  const nextErrors = [...errors];
  if (
    rule &&
    !hasSigmaObjectValuedDetectionSelector(
      rule.detection as Record<string, unknown>,
    )
  ) {
    nextErrors.push(
      "Sigma import requires at least one object-valued detection selector",
    );
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
      if (
        !inRegex &&
        !/[A-Za-z0-9_]/.test(prev) &&
        next !== "/" &&
        next !== "*"
      ) {
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
  let scanState: YaraScanState = {
    inBlockComment: false,
    inHexString: false,
  };
  let currentRule: {
    name: string;
    sawCondition: boolean;
    braceDepth: number;
  } | null = null;

  for (const line of lines) {
    const analyzed = analyzeYaraLine(line, scanState);
    scanState = analyzed.state;
    const ruleMatch = stripYaraRuleModifiers(analyzed.code).match(
      /^rule\s+([A-Za-z_]\w*)\b/,
    );

    if (ruleMatch) {
      if (currentRule && !currentRule.sawCondition) {
        errors.push(
          `Rule "${currentRule.name}" is missing a condition section`,
        );
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
        errors.push(
          `Rule "${currentRule.name}" is missing a condition section`,
        );
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
      return toValidationResult(
        ["OCSF event must be a JSON object"],
        "ocsf",
      );
    }

    const event = value as Record<string, unknown>;
    const errors: string[] = [];

    const asRecord = (
      candidate: unknown,
    ): Record<string, unknown> | null =>
      candidate &&
      typeof candidate === "object" &&
      !Array.isArray(candidate)
        ? (candidate as Record<string, unknown>)
        : null;

    const readUnsignedInteger = (field: string): number | null => {
      const current = event[field];
      if (current === undefined || current === null) {
        errors.push(`Missing required OCSF field: ${field}`);
        return null;
      }
      if (
        typeof current !== "number" ||
        !Number.isInteger(current) ||
        current < 0
      ) {
        errors.push(
          `Invalid type for OCSF field ${field}: expected unsigned integer`,
        );
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
        errors.push(
          `Invalid type for OCSF field ${field}: expected integer`,
        );
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
      if (
        typeof metadata.version !== "string" ||
        metadata.version.trim() === ""
      ) {
        errors.push("Missing required OCSF field: metadata.version");
      }

      const product = asRecord(metadata.product);
      if (!product) {
        errors.push("Missing required OCSF field: metadata.product");
      } else {
        if (
          typeof product.name !== "string" ||
          product.name.trim() === ""
        ) {
          errors.push("Missing required OCSF field: metadata.product.name");
        }
        if (
          typeof product.vendor_name !== "string" ||
          product.vendor_name.trim() === ""
        ) {
          errors.push(
            "Missing required OCSF field: metadata.product.vendor_name",
          );
        }
      }
    }

    if (
      classUid !== null &&
      activityId !== null &&
      typeUid !== null &&
      typeUid !== classUid * 100 + activityId
    ) {
      errors.push(
        `type_uid mismatch: expected ${classUid * 100 + activityId}, got ${typeUid}`,
      );
    }

    if (severityId !== null && severityId > 6 && severityId !== 99) {
      errors.push(
        `severity_id ${severityId} is not a valid OCSF severity (0-6, 99)`,
      );
    }

    if (classUid === 2004) {
      const findingInfo = asRecord(event.finding_info);
      if (!findingInfo) {
        errors.push("Missing required OCSF field: finding_info");
      } else {
        if (
          typeof findingInfo.uid !== "string" ||
          findingInfo.uid.trim() === ""
        ) {
          errors.push("Missing required OCSF field: finding_info.uid");
        }
        if (
          typeof findingInfo.title !== "string" ||
          findingInfo.title.trim() === ""
        ) {
          errors.push("Missing required OCSF field: finding_info.title");
        }
        if (
          findingInfo.analytic === undefined ||
          findingInfo.analytic === null
        ) {
          errors.push("Missing required OCSF field: finding_info.analytic");
        }
      }

      readUnsignedInteger("action_id");
      readUnsignedInteger("disposition_id");
    }

    return toValidationResult(errors, "ocsf");
  } catch (error) {
    return toValidationResult(
      [
        `JSON parse error: ${error instanceof Error ? error.message : String(error)}`,
      ],
      "ocsf",
    );
  }
}

export function validateSourceForFileType(
  fileType: FileType,
  source: string,
): ValidationResult {
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

export function evaluateTabSource(
  fileType: FileType,
  source: string,
  currentPolicy: WorkbenchPolicy,
  filePath?: string | null,
  fallbackName?: string,
): { policy: WorkbenchPolicy; validation: ValidationResult; name: string } {
  const derivedName = extractNameFromSource(
    fileType,
    source,
    filePath,
    fallbackName,
  );

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

function revalidate(
  policy: WorkbenchPolicy,
  yaml?: string,
): { yaml: string; validation: ValidationResult } {
  const y = yaml ?? policyToYaml(policy);
  return { yaml: y, validation: validatePolicy(policy) };
}

function takeSnapshot(editState: TabEditState): PolicySnapshot {
  return {
    activePolicy: editState.policy,
    yaml: editState.yaml,
    validation: editState.validation,
  };
}

function snapshotsEqual(a: PolicySnapshot, b: PolicySnapshot): boolean {
  return a.yaml === b.yaml;
}

function isDirtyVsClean(
  editState: TabEditState,
  cleanSnapshot: PolicySnapshot | null,
): boolean {
  if (!cleanSnapshot) return true;
  return !snapshotsEqual(takeSnapshot(editState), cleanSnapshot);
}

// ---- Store interface ----

export interface PolicyEditState {
  /** Per-tab editing data, keyed by tab ID. */
  editStates: Map<string, TabEditState>;
}

export interface PolicyEditActions {
  /** Initialize editing state for a new tab. */
  initTab: (
    tabId: string,
    editState: TabEditState,
  ) => void;

  /** Remove editing state for a closed tab. */
  removeTab: (tabId: string) => void;

  /** Update policy for a tab (from visual editor). */
  updatePolicy: (tabId: string, policy: WorkbenchPolicy, fileType: FileType) => void;

  /** Set raw YAML for a tab. */
  setYaml: (tabId: string, yaml: string, fileType: FileType, filePath: string | null, nameFallback: string) => void;

  /** Set validation result. */
  setValidation: (tabId: string, validation: ValidationResult) => void;

  /** Set native validation state. */
  setNativeValidation: (
    tabId: string,
    nativeValidation: NativeValidationState,
  ) => void;

  /** Undo the last policy-modifying action for a tab. */
  undo: (tabId: string) => void;

  /** Redo the last undone action for a tab. */
  redo: (tabId: string) => void;

  /** Mark the current state as clean (after save). */
  markClean: (tabId: string) => void;

  /** Check whether a tab's state differs from its clean snapshot. */
  isDirty: (tabId: string) => boolean;

  /** Set the test suite YAML for a tab. */
  setTestSuite: (tabId: string, yaml: string) => void;

  /** Update guard config for a tab. */
  updateGuard: (tabId: string, guardId: GuardId, config: Partial<GuardConfigMap[GuardId]>, fileType: FileType) => void;

  /** Toggle guard enabled state. */
  toggleGuard: (tabId: string, guardId: GuardId, enabled: boolean, fileType: FileType) => void;

  /** Update policy settings. */
  updateSettings: (tabId: string, settings: Partial<WorkbenchPolicy["settings"]>, fileType: FileType) => void;

  /** Update policy metadata. */
  updateMeta: (tabId: string, meta: { name?: string; description?: string; version?: string; extends?: string }, fileType: FileType) => void;

  /** Update origins config. */
  updateOrigins: (tabId: string, origins: OriginsConfig | undefined, fileType: FileType) => void;

  /** Replace editing state completely (used during tab open/restore). */
  replaceEditState: (tabId: string, editState: TabEditState) => void;

  /** Get the tab editing state for a given tab ID. */
  getTabEditState: (tabId: string) => TabEditState | undefined;

  /** Reset to empty state (used by MultiPolicyProvider for test isolation). */
  _reset: () => void;
}

export type PolicyEditStore = PolicyEditState & PolicyEditActions;

// ---- Helper to apply a policy-modifying action with undo tracking ----

function withUndoTracking(
  current: TabEditState,
  apply: (state: TabEditState) => TabEditState,
): TabEditState {
  const currentSnapshot = takeSnapshot(current);
  const next = apply(current);
  const nextSnapshot = takeSnapshot(next);
  if (snapshotsEqual(currentSnapshot, nextSnapshot)) return next;
  return {
    ...next,
    undoStack: {
      past: [...current.undoStack.past, currentSnapshot].slice(-MAX_HISTORY),
      future: [],
    },
  };
}

// ---- Store creation ----

export const usePolicyEditStore = create<PolicyEditStore>((set, get) => ({
  editStates: new Map(),

  initTab: (tabId, editState) =>
    set((state) => {
      const next = new Map(state.editStates);
      next.set(tabId, editState);
      return { editStates: next };
    }),

  removeTab: (tabId) =>
    set((state) => {
      const next = new Map(state.editStates);
      next.delete(tabId);
      return { editStates: next };
    }),

  updatePolicy: (tabId, policy, fileType) =>
    set((state) => {
      const current = state.editStates.get(tabId);
      if (!current) return state;
      if (!isPolicyFileType(fileType)) return state;

      const next = new Map(state.editStates);
      next.set(
        tabId,
        withUndoTracking(current, (s) => {
          const rv = revalidate(policy);
          return { ...s, policy, ...rv };
        }),
      );
      return { editStates: next };
    }),

  setYaml: (tabId, yaml, fileType, filePath, nameFallback) =>
    set((state) => {
      const current = state.editStates.get(tabId);
      if (!current) return state;

      const next = new Map(state.editStates);
      const evaluated = evaluateTabSource(
        fileType,
        yaml,
        current.policy,
        filePath,
        nameFallback,
      );
      next.set(
        tabId,
        withUndoTracking(current, (s) => ({
          ...s,
          policy: evaluated.policy,
          yaml,
          validation: evaluated.validation,
          nativeValidation: emptyNativeValidation(),
        })),
      );
      return { editStates: next };
    }),

  setValidation: (tabId, validation) =>
    set((state) => {
      const current = state.editStates.get(tabId);
      if (!current) return state;
      const next = new Map(state.editStates);
      next.set(tabId, { ...current, validation });
      return { editStates: next };
    }),

  setNativeValidation: (tabId, nativeValidation) =>
    set((state) => {
      const current = state.editStates.get(tabId);
      if (!current) return state;
      const next = new Map(state.editStates);
      next.set(tabId, { ...current, nativeValidation });
      return { editStates: next };
    }),

  undo: (tabId) =>
    set((state) => {
      const current = state.editStates.get(tabId);
      if (!current || current.undoStack.past.length === 0) return state;

      const past = [...current.undoStack.past];
      const snapshot = past.pop()!;
      const currentSnapshot = takeSnapshot(current);

      const newEditState: TabEditState = {
        ...current,
        policy: snapshot.activePolicy,
        yaml: snapshot.yaml,
        validation: snapshot.validation,
        undoStack: {
          past,
          future: [currentSnapshot, ...current.undoStack.future],
        },
      };

      const next = new Map(state.editStates);
      next.set(tabId, newEditState);
      return { editStates: next };
    }),

  redo: (tabId) =>
    set((state) => {
      const current = state.editStates.get(tabId);
      if (!current || current.undoStack.future.length === 0) return state;

      const future = [...current.undoStack.future];
      const snapshot = future.shift()!;
      const currentSnapshot = takeSnapshot(current);

      const newEditState: TabEditState = {
        ...current,
        policy: snapshot.activePolicy,
        yaml: snapshot.yaml,
        validation: snapshot.validation,
        undoStack: {
          past: [...current.undoStack.past, currentSnapshot].slice(
            -MAX_HISTORY,
          ),
          future,
        },
      };

      const next = new Map(state.editStates);
      next.set(tabId, newEditState);
      return { editStates: next };
    }),

  markClean: (tabId) =>
    set((state) => {
      const current = state.editStates.get(tabId);
      if (!current) return state;
      const next = new Map(state.editStates);
      next.set(tabId, {
        ...current,
        cleanSnapshot: takeSnapshot(current),
      });
      return { editStates: next };
    }),

  isDirty: (tabId) => {
    const current = get().editStates.get(tabId);
    if (!current) return false;
    return isDirtyVsClean(current, current.cleanSnapshot);
  },

  setTestSuite: (tabId, yaml) =>
    set((state) => {
      const current = state.editStates.get(tabId);
      if (!current) return state;
      const next = new Map(state.editStates);
      next.set(tabId, { ...current, testSuiteYaml: yaml });
      return { editStates: next };
    }),

  updateGuard: (tabId, guardId, config, fileType) =>
    set((state) => {
      const current = state.editStates.get(tabId);
      if (!current) return state;
      if (!isPolicyFileType(fileType)) return state;

      const next = new Map(state.editStates);
      next.set(
        tabId,
        withUndoTracking(current, (s) => {
          const newGuards = {
            ...s.policy.guards,
            [guardId]: {
              ...(s.policy.guards[guardId] || {}),
              ...config,
            },
          };
          const newPolicy = { ...s.policy, guards: newGuards };
          return { ...s, policy: newPolicy, ...revalidate(newPolicy) };
        }),
      );
      return { editStates: next };
    }),

  toggleGuard: (tabId, guardId, enabled, fileType) =>
    set((state) => {
      const current = state.editStates.get(tabId);
      if (!current) return state;
      if (!isPolicyFileType(fileType)) return state;

      const next = new Map(state.editStates);
      next.set(
        tabId,
        withUndoTracking(current, (s) => {
          const existing = s.policy.guards[guardId] || {};
          const newGuards = {
            ...s.policy.guards,
            [guardId]: { ...existing, enabled },
          };
          if (!enabled) {
            const guardConfig = newGuards[guardId];
            if (
              guardConfig &&
              Object.keys(guardConfig).length === 1 &&
              "enabled" in guardConfig
            ) {
              delete newGuards[guardId];
            }
          }
          const newPolicy = { ...s.policy, guards: newGuards };
          return { ...s, policy: newPolicy, ...revalidate(newPolicy) };
        }),
      );
      return { editStates: next };
    }),

  updateSettings: (tabId, settings, fileType) =>
    set((state) => {
      const current = state.editStates.get(tabId);
      if (!current) return state;
      if (!isPolicyFileType(fileType)) return state;

      const next = new Map(state.editStates);
      next.set(
        tabId,
        withUndoTracking(current, (s) => {
          const newPolicy = {
            ...s.policy,
            settings: { ...s.policy.settings, ...settings },
          };
          return { ...s, policy: newPolicy, ...revalidate(newPolicy) };
        }),
      );
      return { editStates: next };
    }),

  updateMeta: (tabId, meta, fileType) =>
    set((state) => {
      const current = state.editStates.get(tabId);
      if (!current) return state;
      if (!isPolicyFileType(fileType)) return state;

      const next = new Map(state.editStates);
      next.set(
        tabId,
        withUndoTracking(current, (s) => {
          const newPolicy = { ...s.policy };
          if (meta.name !== undefined) newPolicy.name = meta.name;
          if (meta.description !== undefined)
            newPolicy.description = meta.description;
          if (meta.version !== undefined)
            newPolicy.version =
              meta.version as WorkbenchPolicy["version"];
          if (meta.extends !== undefined)
            newPolicy.extends = meta.extends || undefined;
          return { ...s, policy: newPolicy, ...revalidate(newPolicy) };
        }),
      );
      return { editStates: next };
    }),

  updateOrigins: (tabId, origins, fileType) =>
    set((state) => {
      const current = state.editStates.get(tabId);
      if (!current) return state;
      if (!isPolicyFileType(fileType)) return state;

      const next = new Map(state.editStates);
      next.set(
        tabId,
        withUndoTracking(current, (s) => {
          const newPolicy = { ...s.policy, origins };
          return { ...s, policy: newPolicy, ...revalidate(newPolicy) };
        }),
      );
      return { editStates: next };
    }),

  replaceEditState: (tabId, editState) =>
    set((state) => {
      const next = new Map(state.editStates);
      next.set(tabId, editState);
      return { editStates: next };
    }),

  getTabEditState: (tabId) => get().editStates.get(tabId),

  _reset: () => set({ editStates: new Map() }),
}));
