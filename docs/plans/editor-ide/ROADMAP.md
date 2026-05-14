# Detection Engineering IDE --- Implementation Roadmap

> **Version:** 1.0.0-draft
> **Date:** 2026-03-14

This roadmap describes the phased plan for extending the ClawdStrike Workbench into a detection engineering IDE. It synthesizes the architect's 6-phase plan with the critic's scope recommendations.

---

## Phase 0: Foundation Refactors (Pre-requisites, ~1 week)

Before adding any format, address critical risks:

1. **Generalize `PolicyTab` to `DetectionTab` with `fileType` discriminator**
   - File: `multi-policy-store.tsx`
   - Add `fileType: FileType` field defaulting to `"clawdstrike_policy"`
   - All existing code continues to work unchanged

2. **Raise tab limit from 10 to 25**
   - Move tab persistence from localStorage to IndexedDB

3. **Add `fileType` prop to `YamlEditor` component**
   - Select language extension + completion source from FileTypeRegistry

4. **Create `file-type-registry.ts`** with descriptors for all 4 formats

5. **Create `commands/detection.rs` in Tauri backend** (empty scaffold)

6. **Add `hunt-correlate` and `clawdstrike-ocsf` as Cargo dependencies**

---

## Phase 1: Sigma Rule Editing (MVP, ~3 weeks)

**Goal:** Detection engineers can author, validate, and test Sigma rules in the workbench.

### Week 1: Sigma editing basics

- New tab creation with `fileType: "sigma_rule"`
- Sigma-specific YAML autocomplete (`sigma-schema.ts`)
  - Top-level keys, logsource taxonomy, status/level enums, modifier completions
- Wire `validate_sigma_rule` Tauri command to `hunt-correlate::compile_sigma_rule()`
- Format indicator dots on tabs (indigo `#7c9aef` for Sigma)

### Week 2: Sigma visual editor

- `SigmaVisualPanel` --- form-based editor matching guard card pattern
  - Header section: title, id (UUID), status, level, author, date, tags
  - Logsource picker: category/product/service dropdowns from taxonomy
  - Detection builder: selection cards with field-value-modifier rows
  - Condition line: visual expression with clickable pills
- Bidirectional sync between visual panel and YAML
- `SplitEditor` format dispatch: `format === "sigma_rule"` leads to SigmaVisualPanel + YamlEditor

### Week 3: Sigma testing and conversion

- Wire `test_sigma_rule` Tauri command to `hunt-correlate::test_rule_source()`
- `SigmaTestPanel` --- event log input (JSONL paste/upload) + findings output
- Sigma to native correlation preview (already exists in Rust)
- Basic Sigma to SPL conversion preview (new `sigma_to_spl()` in hunt-correlate)
- Template gallery: 5 Sigma templates (process_creation, network, DNS, cloud, file_event)

**Deliverable:** Users can create, edit, validate, test, and convert Sigma rules.

---

## Phase 2: OCSF Event Support (~2 weeks)

**Goal:** Users can author and validate OCSF events with schema-aware editing.

### Week 4: OCSF editing

- JSON language support via `@codemirror/lang-json`
- OCSF autocomplete (`ocsf-schema.ts`) --- class_uid, severity_id, metadata fields
- Wire `validate_ocsf_event` Tauri command to `clawdstrike-ocsf::validate_ocsf_json()`
- OCSF tab indicator (teal `#5cc5c4`)
- OCSF templates: DetectionFinding, FileActivity, NetworkActivity, ProcessActivity

### Week 5: OCSF visual editor and validation

- `OcsfVisualPanel` --- event class selector + field tree editor
- Schema validation overlay showing required/optional field completion
- OCSF event preview with formatted JSON output
- Integration with existing OCSF golden fixtures for testing

**Deliverable:** Users can author OCSF events with schema-aware validation and field completion.

---

## Phase 3: YARA Rule Editing (~3 weeks)

**Goal:** Users can author and validate YARA rules with syntax highlighting.

### Week 6: YARA language support

- Custom StreamLanguage tokenizer for YARA (`yara-language.ts`)
  - Keywords, string variables, hex patterns, regex literals, comments
- YARA tab indicator (amber `#e0915c`)
- Basic autocomplete: keywords, meta fields, string modifiers, modules
- Wire `validate_yara_rule` Tauri command to `hunt-correlate::prepare_yara_rule()`

### Week 7: YARA visual editor (simplified)

- `YaraVisualPanel` --- meta form + strings table + raw condition editor
  - NOT a full condition builder (YARA conditions are too complex for visual building)
- YARA templates: malware detection, webshell, credential dumper, ransomware

### Week 8: YARA scanning (stretch goal)

- Integrate `yara-x` crate in Tauri backend
- Wire `test_yara_rule` Tauri command
- `YaraTestPanel` --- sample content input + match results
- Sandbox YARA execution in subprocess (security requirement)

**Deliverable:** Users can author YARA rules with highlighting/validation. Scanning is stretch.

---

## Phase 4: Cross-Cutting Features (~3 weeks)

**Goal:** Problems panel, ATT&CK coverage, conversion pipeline.

### Week 9: Problems panel + unified diagnostics

- Unified `ProblemsPanel` component (Cmd+Shift+M)
- Per-format validators feeding into shared diagnostic interface
- Inline diagnostics (squiggly lines, gutter markers) for all formats

### Week 10: MITRE ATT&CK integration

- `mitre-attack-techniques.json` static dataset
- ATT&CK tag parsing from Sigma rules + YARA meta
- `MitreHeatmap` component --- interactive coverage matrix
- Coverage summary strip in editor toolbar

### Week 11: Conversion pipeline

- `ConversionDialog` --- source format to target format with preview
- Sigma to SPL, KQL, ES|QL (via hunt-correlate extensions)
- YARA to ClawdStrike policy snippet (YaraGuard config block)
- Copy/save converted output

---

## Phase 5: File Explorer & Project Model (~3 weeks)

**Goal:** Multi-file project management with file tree.

### Week 12: File explorer panel

- `ExplorerPanel` --- collapsible left panel within editor area
- Tree view with file type icons, format accent colors
- Directory traversal via Tauri FS plugin
- Toggle via Cmd+Shift+E

### Week 13: Project system

- `ProjectStore` with IndexedDB persistence
- Project root path, virtual file tree, metadata
- File watcher for external changes (Tauri FSEvents)
- Recent projects list

### Week 14: Git integration (basic)

- Cherry-pick `worktree.rs` from PR #193 for git operations
- Git status/diff display in explorer panel
- Cherry-pick `capability.rs` for IPC authorization
- Branch indicator in status bar

---

## Phase 6: Polish & Advanced Features (~3 weeks)

**Goal:** Command palette, keyboard shortcuts, MCP integration, SigmaHQ import.

### Week 15: Command palette and shortcuts

- `CommandPalette` component (Cmd+K)
- Format-specific keyboard shortcuts
- Cmd+P quick file open
- `ShortcutHelpDialog` extension for new shortcuts

### Week 16: SigmaHQ integration and templates

- SigmaHQ community rule browser (catalog view)
- Import rules from SigmaHQ repository
- Extended template gallery for all formats
- Rule lifecycle states (draft, testing, production, deprecated)

### Week 17: MCP and integration

- MCP tools for detection rule CRUD
- Performance optimization (lazy-load language extensions)
- Integration testing across all file types
- Documentation and onboarding tooltips

---

## Milestones

| Milestone | Target | Deliverable |
|-----------|--------|-------------|
| M1: Sigma MVP | End of Phase 1 | Sigma editing, validation, testing |
| M2: Multi-Format | End of Phase 2 | + OCSF event support |
| M3: Full IDE | End of Phase 3 | + YARA rule support |
| M4: Coverage | End of Phase 4 | + ATT&CK, diagnostics, conversion |
| M5: Project System | End of Phase 5 | + File explorer, git basics |
| M6: GA | End of Phase 6 | + Command palette, SigmaHQ, MCP |

---

## Dependencies

- Phase 0 blocks all subsequent phases.
- Phase 1 (Sigma) can start immediately after Phase 0.
- Phases 2 and 3 can run in parallel after Phase 1.
- Phase 4 depends on at least Phase 1.
- Phase 5 can start after Phase 1.
- Phase 6 depends on Phase 4 and Phase 5.

---

## Risk Mitigations

- **Scope:** Each phase ships independently. Can stop after Phase 1 and still have value.
- **Context providers:** Monitor render performance. Refactor to zustand if perf degrades.
- **Tab limit:** IndexedDB migration in Phase 0 eliminates localStorage constraint.
- **YARA scanner:** Phase 3 Week 8 is explicitly a stretch goal. Can ship without.
- **VS Code competition:** Lean into vertical integration (policy enforcement, receipts, fleet deployment).
