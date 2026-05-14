# Detection Engineering IDE — Technical Architecture

**Version:** 1.0.0-draft
**Date:** 2026-03-14

---

## 1. File Type System

### FileType Enum

```typescript
type FileType = "clawdstrike_policy" | "sigma_rule" | "yara_rule" | "ocsf_event";
```

### FileTypeDescriptor

```typescript
interface FileTypeDescriptor {
  /** Unique identifier matching FileType union */
  id: FileType;

  /** Human-readable label (e.g. "Sigma Rule") */
  label: string;

  /** Recognized file extensions, first is canonical */
  extensions: string[];

  /** Lucide icon name for tab chrome and explorer */
  icon: string;

  /** Tailwind color class for icon tinting */
  iconColor: string;

  /** Factory returning a CodeMirror 6 language extension */
  codemirrorLanguage: () => Extension;

  /** Optional CompletionSource for context-aware autocomplete */
  completionSource?: CompletionSource;

  /** Snippet definitions keyed by trigger prefix */
  snippets: Record<string, Snippet>;

  /** Template content for "New File" action */
  defaultContent: string;

  /** Tauri command name for backend validation */
  validationBackend: string;

  /** Whether format supports the test runner */
  testable: boolean;

  /** Target formats this type can convert to */
  convertibleTo: FileType[];
}
```

### File Type Detection Priority

Detection follows a fixed priority chain. The first match wins.

```
1. Explicit user selection   (user picks from FileTypePicker dropdown)
2. File extension mapping    (.yar/.yara -> YARA, .json -> OCSF)
3. Content heuristic         (for ambiguous .yml/.yaml files)
```

Content heuristic rules for `.yml` / `.yaml`:

| Condition | Result |
|-----------|--------|
| Contains `guards:` or `schema_version:` | `clawdstrike_policy` |
| Contains `detection:` **and** `logsource:` | `sigma_rule` |
| Contains `title:` **and** `status:` (no `guards:`) | `sigma_rule` |
| Fallback | `clawdstrike_policy` |

### Registry Location

**File:** `apps/workbench/src/lib/workbench/file-type-registry.ts`

The registry exports a `Map<FileType, FileTypeDescriptor>` and a `detectFileType(filename: string, content: string): FileType` function implementing the priority chain above.

---

## 2. Tab Data Model

### DetectionTab (generalized from PolicyTab)

```typescript
type TabContent =
  | { fileType: "clawdstrike_policy"; policy: WorkbenchPolicy }
  | { fileType: "sigma_rule"; rule: SigmaRule }
  | { fileType: "yara_rule"; rule: YaraRule }
  | { fileType: "ocsf_event"; event: OcsfEvent };

interface DetectionTab {
  id: string;
  name: string;
  filePath: string | null;
  dirty: boolean;
  fileType: FileType;
  content: TabContent;

  /** Raw source text backing the editor */
  sourceText: string;

  /** Client-side validation state */
  validation: ValidationResult;

  /** Rust backend validation state */
  nativeValidation: NativeValidationState;

  /** Undo history (snapshot-based) */
  _undoPast: TabSnapshot[];
  _undoFuture: TabSnapshot[];
  _cleanSnapshot: TabSnapshot | null;
}
```

### Migration Strategy

| Phase | Change | Risk |
|-------|--------|------|
| 1 | Add `fileType` field to existing `PolicyTab`, default `"clawdstrike_policy"` | None — purely additive |
| 2 | `PolicyTab` becomes type alias: `DetectionTab & { fileType: "clawdstrike_policy" }` | Low — consumers unchanged |
| 3 | New hooks `useDetectionTab()` alongside existing `useWorkbench()` | None — opt-in |

---

## 3. Language Support

### CodeMirror 6 Extensions per Format

| Format | Base Language | Completion Source |
|--------|---------------|-------------------|
| ClawdStrike Policy | `@codemirror/lang-yaml` | `policyYamlCompletionSource` (existing) |
| Sigma Rule | `@codemirror/lang-yaml` | `sigmaYamlCompletionSource` (new) |
| YARA Rule | Custom `StreamLanguage` tokenizer | Keyword + variable completion |
| OCSF Event | `@codemirror/lang-json` | `ocsfJsonCompletionSource` (new) |

### YARA StreamLanguage Tokenizer

The YARA tokenizer handles keywords, hex string literals, regex patterns, and `$`-prefixed string variables. It is implemented as a `StreamLanguage.define()` parser.

### Theme Consistency

All formats share `createClawdTheme()`. YARA-specific highlight overrides:

| Token | Color | Hex |
|-------|-------|-----|
| Rule names | Amber | `#e0915c` |
| Keywords (`rule`, `meta`, `strings`, `condition`) | Gold | `#d4a84b` |
| String variables (`$...`) | Green | `#3dbf84` |
| Hex patterns | Steel | `#6f7f9a` |

---

## 4. Validation Pipeline

### Three-Layer Architecture

```
+----------------------------------------------------------+
| Layer 1: Format Parse                                    |
| YAML parse / JSON parse / YARA tokenize                  |
| Catches syntax errors immediately (no debounce)          |
+----------------------------------------------------------+
           |
           v
+----------------------------------------------------------+
| Layer 2: Client-Side Schema Validation                   |
| Field presence, enum values, type checking               |
| Runs synchronously after successful parse                |
+----------------------------------------------------------+
           |
           v  (800ms debounce)
+----------------------------------------------------------+
| Layer 3: Rust Native Validation (Tauri IPC)              |
| Deep semantic checks, cross-reference, policy engine     |
+----------------------------------------------------------+
```

### Validation Router

The router dispatches to the correct Tauri command based on `fileType`:

```typescript
const VALIDATION_COMMANDS: Record<FileType, string> = {
  clawdstrike_policy: "validate_policy",     // existing
  sigma_rule:         "validate_sigma_rule",  // new
  yara_rule:          "validate_yara_rule",   // new
  ocsf_event:         "validate_ocsf_event",  // new
};
```

### useDetectionValidation Hook

Follows the same debounce pattern as the existing `useNativeValidation`, parameterized by `fileType`. Accepts `sourceText` and `fileType`, returns `NativeValidationState`.

```typescript
function useDetectionValidation(
  sourceText: string,
  fileType: FileType,
  debounceMs?: number   // default 800
): NativeValidationState;
```

---

## 5. Editor Component Architecture

### SplitEditor Routing

```typescript
switch (activeTab.fileType) {
  case "clawdstrike_policy":
    return <EditorVisualPanel /> + <YamlPreviewPanel />;   // unchanged
  case "sigma_rule":
    return <SigmaVisualPanel /> + <YamlEditor />;          // sigma mode
  case "yara_rule":
    return <YaraVisualPanel /> + <YaraEditor />;           // code-only left
  case "ocsf_event":
    return <OcsfVisualPanel /> + <JsonEditor />;
}
```

### Component Hierarchy

```
WorkbenchShell
 |
 +-- CommandPalette               (Cmd+K fuzzy command search)
 +-- ExplorerPanel                (file tree sidebar)
 |    +-- ExplorerTreeItem
 |
 +-- TabBar
 |    +-- FileTypePicker          (per-tab type override)
 |
 +-- SplitEditor
 |    +-- [left panel — visual]
 |    |    +-- EditorVisualPanel        (clawdstrike, existing)
 |    |    +-- SigmaVisualPanel         (sigma)
 |    |    |    +-- LogsourcePicker
 |    |    |    +-- DetectionBuilder
 |    |    |    +-- ConditionPills
 |    |    +-- YaraVisualPanel          (yara)
 |    |    |    +-- MetaForm
 |    |    |    +-- StringsTable
 |    |    |    +-- RawConditionEditor
 |    |    +-- OcsfVisualPanel          (ocsf)
 |    |         +-- EventClassSelector
 |    |         +-- FieldTreeEditor
 |    |         +-- SchemaBrowser
 |    |
 |    +-- [right panel — source]
 |         +-- YamlEditor / YaraEditor / JsonEditor
 |
 +-- BottomPanel
 |    +-- ProblemsPanel           (unified diagnostics)
 |    +-- DetectionTestRunner
 |    |    +-- SigmaTestPanel
 |    |    +-- YaraTestPanel
 |    |    +-- OcsfValidationPanel
 |    +-- ConversionDialog        (cross-format with preview)
 |
 +-- MitreHeatmap                 (ATT&CK coverage matrix)
 +-- CoverageSummary
```

### New Components Summary

| Component | Purpose |
|-----------|---------|
| `SigmaVisualPanel` | Header form, logsource picker, detection builder, condition pills |
| `YaraVisualPanel` | Meta form, strings table, raw condition editor |
| `OcsfVisualPanel` | Event class selector, field tree editor, schema browser |
| `ProblemsPanel` | Unified diagnostics across all formats |
| `DetectionTestRunner` | Format-aware test runner wrapper |
| `SigmaTestPanel` | Sigma-specific test UI with log event input |
| `YaraTestPanel` | YARA-specific test UI with sample hex input |
| `OcsfValidationPanel` | OCSF schema conformance checker |
| `ExplorerPanel` | File tree sidebar with project navigation |
| `MitreHeatmap` | ATT&CK technique coverage matrix visualization |
| `ConversionDialog` | Cross-format conversion with side-by-side preview |
| `CommandPalette` | Cmd+K fuzzy command search |

---

## 6. Tauri Backend Extensions

### New Commands (`detection.rs`)

```rust
// --- Sigma ---

/// Validate a Sigma rule source string. Returns structured diagnostics.
#[tauri::command]
fn validate_sigma_rule(source: String) -> Result<SigmaValidationResponse, String>;

/// Run a Sigma rule against a set of JSON log events.
#[tauri::command]
fn test_sigma_rule(source: String, events_json: String) -> Result<SigmaTestResult, String>;

/// Compile a Sigma rule to native hunt-correlate IR.
#[tauri::command]
fn compile_sigma_to_native(source: String) -> Result<String, String>;

/// Convert a Sigma rule to Splunk SPL query.
#[tauri::command]
fn convert_sigma_to_spl(source: String) -> Result<String, String>;

/// Convert a Sigma rule to Microsoft KQL query.
#[tauri::command]
fn convert_sigma_to_kql(source: String) -> Result<String, String>;

// --- YARA ---

/// Validate a YARA rule source string.
#[tauri::command]
fn validate_yara_rule(source: String) -> Result<YaraValidationResponse, String>;

/// Test a YARA rule against hex-encoded sample bytes.
#[tauri::command]
fn test_yara_rule(source: String, sample_hex: String) -> Result<YaraTestResult, String>;

// --- OCSF ---

/// Validate a JSON string against the OCSF schema.
#[tauri::command]
fn validate_ocsf_event(json: String) -> Result<OcsfValidationResponse, String>;

// --- File System ---

/// Detect the FileType of a source string using content heuristics.
#[tauri::command]
fn detect_file_type(content: String) -> FileType;

/// List project files under a root path, returning type-annotated entries.
#[tauri::command]
fn list_project_files(root_path: String) -> Result<Vec<ProjectFile>, String>;
```

### Cargo Dependencies (`src-tauri/Cargo.toml` additions)

```toml
[dependencies]
hunt-correlate   = { path = "../../../crates/libs/hunt-correlate" }
clawdstrike-ocsf = { path = "../../../crates/libs/clawdstrike-ocsf" }

# Phase 3 stretch — compiled YARA execution:
# yara-x = "1.13"
```

### Security Constraints

| Constraint | Detail |
|------------|--------|
| `MAX_SOURCE_SIZE` | 2 MiB for all detection source text passed via IPC |
| YARA sample content | In-memory bytes only, never file paths |
| YARA execution | Runs in subprocess, not main Tauri process |
| Path validation | All file paths validated via existing `validate_file_path()` |

---

## 7. Test Framework

### Generalized Test Model

```typescript
type TestModality =
  | "policy_simulation"
  | "sigma_correlation"
  | "yara_scan"
  | "ocsf_validation";

interface DetectionTestCase {
  id: string;
  modality: TestModality;
  name: string;

  /** Source text of the rule/policy under test */
  ruleSource: string;

  /** Test input — log events, sample bytes, or JSON payload */
  testData: string;

  /** Optional expected outcome for pass/fail assertion */
  expectedOutcome?: string;
}

interface TestFinding {
  severity: "info" | "warning" | "error";
  message: string;
  location?: string;
}

interface DetectionTestResult {
  testCaseId: string;
  passed: boolean;
  findings: TestFinding[];
  durationMs: number;
  errors: string[];
}
```

### Test Flow

```
DetectionTestRunner
  |
  +-- resolve TestModality from activeTab.fileType
  |
  +-- serialize (ruleSource, testData) -> Tauri IPC
  |     |
  |     +-- policy_simulation  -> test_policy()        (existing)
  |     +-- sigma_correlation  -> test_sigma_rule()    (new)
  |     +-- yara_scan          -> test_yara_rule()     (new)
  |     +-- ocsf_validation    -> validate_ocsf_event() (new)
  |
  +-- deserialize DetectionTestResult
  |
  +-- render in format-specific test panel
```

---

## 8. Conversion Pipeline

### Supported Conversions

```
+---------------------+     +--------------------------------------+
| Source Format        |     | Target Formats                       |
+---------------------+     +--------------------------------------+
| Sigma Rule          | --> | Native correlation, SPL, KQL, ES|QL  |
| YARA Rule           | --> | ClawdStrike policy (YaraGuard config)|
| OCSF Event          | --> | JSON export, Parquet schema          |
| ClawdStrike Policy  | --> | OCSF Detection Finding               |
+---------------------+     +--------------------------------------+
```

### Architecture

```
ConversionDialog (frontend)
  |
  +-- User selects source tab + target format
  |
  +-- Tauri IPC call
  |     |
  |     +-- convert_sigma_to_spl()
  |     +-- convert_sigma_to_kql()
  |     +-- compile_sigma_to_native()
  |     +-- (future: convert_yara_to_policy, etc.)
  |
  +-- hunt-correlate Rust backend
  |     |
  |     +-- sigma_output.rs   (SPL/KQL/ES translation)
  |     +-- yara_to_policy.rs  (YARA -> policy)
  |
  +-- Result displayed in side-by-side split
       (source left, converted output right)
```

---

## 9. File Structure (New Files)

```
apps/workbench/src/
 |
 +-- lib/workbench/
 |    +-- file-type-registry.ts        # FileType enum, descriptors, detection
 |    +-- sigma-schema.ts              # Sigma rule TS types + schema constants
 |    +-- yara-language.ts             # YARA StreamLanguage tokenizer
 |    +-- ocsf-schema.ts              # OCSF event TS types + schema constants
 |    +-- sigma-validator.ts           # Client-side Sigma validation (Layer 2)
 |    +-- yara-validator.ts            # Client-side YARA validation (Layer 2)
 |    +-- ocsf-validator.ts            # Client-side OCSF validation (Layer 2)
 |    +-- detection-test-runner.ts     # Generalized test runner dispatch
 |    +-- conversion-engine.ts         # Conversion dialog logic + IPC calls
 |    +-- mitre-attack-registry.ts     # ATT&CK technique lookup + mapping
 |    +-- project-store.tsx            # Project file tree state (Zustand)
 |
 +-- data/
 |    +-- mitre-attack-techniques.json # ATT&CK technique catalog
 |
 +-- components/workbench/
      +-- editor/
      |    +-- sigma-visual-panel.tsx   # Sigma visual editor
      |    +-- yara-visual-panel.tsx    # YARA visual editor
      |    +-- ocsf-visual-panel.tsx    # OCSF visual editor
      |    +-- conversion-dialog.tsx    # Cross-format conversion UI
      |    +-- file-type-picker.tsx     # File type selector dropdown
      |
      +-- explorer/
      |    +-- explorer-panel.tsx       # File tree sidebar
      |    +-- explorer-tree-item.tsx   # Single tree node
      |
      +-- coverage/
      |    +-- mitre-heatmap.tsx        # ATT&CK coverage matrix
      |    +-- coverage-summary.tsx     # Aggregate coverage stats
      |
      +-- testing/
           +-- sigma-test-panel.tsx     # Sigma test UI
           +-- yara-test-panel.tsx      # YARA test UI
           +-- ocsf-validation-panel.tsx # OCSF validation UI

apps/workbench/src-tauri/src/commands/
 +-- detection.rs                       # All new Tauri commands

crates/libs/hunt-correlate/src/
 +-- sigma_output.rs                    # SPL/KQL/ES|QL translation
 +-- yara_to_policy.rs                  # YARA -> ClawdStrike policy conversion
```
