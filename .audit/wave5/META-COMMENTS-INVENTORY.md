# Meta-comment inventory

Sweep performed against `/Users/connor/.codex/worktrees/ts-sprints-deps-clawdstrike` for Rust, TypeScript, and Python source. Tests, vendor, target, dist, node_modules, `.audit/` excluded. Doc-comments (`///`, `/** */`) are only included when they're clearly noise.

## Summary

- **Bucket A (delete outright):** ~95 findings — dominated by short verb+noun comments restating one-line operations, "moved to crate::..." gravestones in `apps/agent/src-tauri/src/api_server*.rs`, and decorative section dividers.
- **Bucket B (rewrite):** ~12 findings — useful context phrased as narration; should be rewritten to describe WHY.
- **Bucket C (keep):** ~10 findings — load-bearing security, concurrency, or compatibility context.

The "moved to crate::..." cluster in the `apps/agent/src-tauri` extraction is by far the most egregious category: 12 left-over markers from a recent refactor that point to crate paths the reader can already discover from the absence of code. Delete on sight.

## A. Delete outright

### "moved to crate::..." gravestones (12 — all from the recent EDR extraction)

- `apps/agent/src-tauri/src/api_server.rs:2298` — `// identity_filter_matches moved to crate::edr::queries::causal` — the function is gone; the marker just clutters the file.
- `apps/agent/src-tauri/src/api_server.rs:2300` — `// PendingFindingGroup moved to crate::edr::queries::finding_groups` — same.
- `apps/agent/src-tauri/src/api_server.rs:2309` — `// PendingGraphSearchMatch moved to crate::edr::queries::graph_search` — same.
- `apps/agent/src-tauri/src/api_server/response_actions.rs:1940` — `// quarantine_file_target_path moved to crate::edr::response` — same.
- `apps/agent/src-tauri/src/api_server/response_actions.rs:2475` — `// ProcessSignalTarget, suspend_process_tree_targets moved to crate::edr::response` — same.
- `apps/agent/src-tauri/src/api_server/response_actions.rs:2476` — `// process_node_pid moved to crate::edr::response` — same.
- `apps/agent/src-tauri/src/api_server/response_actions.rs:3646-3648` — `// quarantine_file_effect, disable_persistence_effect, suspend_process_tree_effect, process_tree_effect_pids moved to crate::edr::response // quarantine_destination_path, safe_filename_fragment moved to crate::edr::response` — same.
- `apps/agent/src-tauri/src/api_server/response_actions.rs:3686` — `// endpoint_security_event_* helpers moved to crate::edr::conversion::endpoint_security` — same.
- `apps/agent/src-tauri/src/api_server/policy_delta.rs:862-865` — `// build_edr_policy_delta_artifact, ..., merge_json_values // moved to crate::edr::policy_events` — same.
- `apps/agent/src-tauri/src/api_server/policy_history.rs:753` — `// affected_identities_for_causal_impact and push_affected_identity moved to crate::edr::queries::causal` — same.
- `apps/agent/src-tauri/src/api_server/policy_history.rs:1403-1405` — `// build_policy_event_replay_report, ... build_policy_event_impact_report // moved to crate::edr::policy_events` — same.
- `apps/agent/src-tauri/src/edr/handlers/causal.rs:107` — `// build_finding_groups and helpers moved to crate::edr::queries::finding_groups` — same.
- `apps/agent/src-tauri/src/edr/handlers/causal.rs:334` — `// validate_graph_search_input, build_graph_search_matches and helpers moved to crate::edr::queries::graph_search` — same.

### Short verb+noun comments above trivial code (44)

- `apps/workbench/src/lib/workbench/version-store.ts:320` — `// Update the version's tags array` — code literally builds an updated tags array on the next line.
- `apps/workbench/src/lib/workbench/version-store.ts:347` — `// Get all tags for this policy` — followed by `tx.objectStore(TAGS_STORE).index("policyId")`.
- `apps/workbench/src/lib/workbench/version-store.ts:436` — `// Get all versions, newest first` — followed by `this.getVersions(policyId, 1000, 0)`.
- `apps/workbench/src/lib/workbench/version-store.ts:440` — `// Get the policy name from the latest version` — followed by `versions[0]?.policy.name`.
- `apps/workbench/src/lib/workbench/use-version-history.ts:19` — `// Initialize the store once` — followed by `useEffect` whose only job is initialization.
- `apps/workbench/src/lib/workbench/use-version-history.ts:120` — `// Update the local state` — `setVersions` follows.
- `apps/workbench/src/lib/workbench/use-version-history.ts:139` — `// Update the local state` — same.
- `apps/workbench/src/features/policy/use-auto-version.ts:27` — `// Initialize the store once` — exact same pattern as above.
- `apps/workbench/src/features/policy/stores/policy-tabs-store.ts:437` — `// Create a default tab` — `createDefaultTabAndEditState()` makes that obvious.
- `apps/workbench/src/components/workbench/editor/version-history-panel.tsx:145` — `// Save version` — over `handleSaveVersion`.
- `apps/workbench/src/components/workbench/editor/version-history-panel.tsx:154` — `// Add tag` — over `handleAddTag`.
- `apps/workbench/src/components/workbench/editor/version-history-panel.tsx:167` — `// Remove tag` — over `handleRemoveTag`.
- `apps/workbench/src/components/workbench/editor/scenario-graph.tsx:81` — `// Compute layout` — function name `computeLayout` follows.
- `apps/workbench/src/components/workbench/editor/version-diff-dialog.tsx:142` — `// Compute diff`.
- `apps/workbench/src/components/workbench/editor/test-runner-panel.tsx:908` — `// Compute coverage`.
- `apps/workbench/src/components/workbench/editor/trustprint-pattern-explorer.tsx:404` — `// Apply filters`.
- `apps/workbench/src/components/workbench/intel/intel-page.tsx:440` — `// Apply filters`.
- `apps/workbench/src/components/workbench/receipts/receipt-inspector.tsx:769` — `// Apply filters`.
- `apps/workbench/src/components/workbench/swarms/swarm-detail.tsx:696` — `// Apply velocities`.
- `apps/workbench/src/components/workbench/swarms/swarm-detail.tsx:727` — `// Compute layout`.
- `apps/workbench/src/components/workbench/simulator/observe-synth-panel.tsx:405` — `// Clear all`.
- `apps/workbench/src/components/workbench/guards/guards-page.tsx:126` — `// Filter pills`.
- `apps/workbench/src/components/workbench/guards/guards-page.tsx:555` — `// Filter guards`.
- `apps/workbench/src/lib/workbench/cross-reference.ts:180` — `// Check egress_allowlist`.
- `apps/workbench/src/lib/workbench/detection-mcp-tools.ts:238` — `// Build tags`.
- `apps/workbench/src/lib/workbench/detection-workflow/draft-mappers.ts:453` — `// Check target`.
- `apps/workbench/src/lib/workbench/detection-workflow/eql-parser.ts:187` — `// Check negation`.
- `apps/workbench/src/lib/workbench/detection-workflow/spl-parser.ts:401` — `// Apply negation`.
- `apps/workbench/src/lib/workbench/detection-workflow/ocsf-adapter.ts:267` — `// Process Activity`.
- `apps/workbench/src/lib/workbench/finding-engine.ts:827` — `// Sort chronologically` — followed by `allEntries.sort((a, b) => a.timestamp - b.timestamp)`.
- `apps/workbench/src/lib/workbench/force-graph-engine.ts:75` — `// Build adjacency`.
- `apps/workbench/src/lib/workbench/force-graph-engine.ts:169` — `// Initialize all to 0`.
- `apps/workbench/src/lib/workbench/sigma-schema.ts:225` — `// Calculate indentation`.
- `apps/workbench/src/features/policy/yaml-schema.ts:259` — `// Calculate indentation`.
- `apps/workbench/src/lib/workbench/use-guard-order.ts:102` — `// Remove source`.
- `apps/workbench/src/lib/workbench/detection-workflow/swarm-receipt-linking.ts:68` — `// Create the edge` — over `const edgeId = ...`.
- `apps/workbench/src-tauri/src/commands/terminal.rs:421` — `// Create the PTY pair`.
- `apps/workbench/src-tauri/src/commands/terminal.rs:432` — `// Build the command`.
- `apps/workbench/src/features/findings/hooks/use-signal-correlator.ts:108` — `// Run correlation`.
- `apps/workbench/src/features/findings/hooks/use-signal-correlator.ts:131` — `// Create the finding through the store action (handles persistence)` — function name makes this obvious.
- `apps/workbench/src/lib/plugins/plugin-loader.ts:610` — `// Create the bridge host`.
- `apps/workbench/src/lib/plugins/plugin-registry.ts:115` — `// Create the registered plugin entry`.
- `apps/workbench/src/features/presence/use-presence-connection.ts:56` — `// Create new PresenceSocket`.
- `apps/desktop/src/features/events/EventStreamView.tsx:40` — `// Apply filters`.
- `apps/desktop/src/shell/components/CommandPalette.tsx:65` — `// Filter commands`.

### apps/terminal trivial init/reset/run noise (17)

- `apps/terminal/src/index.ts:107` — `// Initialize Beads` — followed by `Beads.init(...)`.
- `apps/terminal/src/index.ts:111` — `// Initialize Telemetry` — followed by `Telemetry.init(...)`.
- `apps/terminal/src/index.ts:118` — `// Initialize Hushd client` — followed by `Hushd.init()`.
- `apps/terminal/src/index.ts:133` — `// Stop MCP server` — followed by `MCP.stop()`.
- `apps/terminal/src/index.ts:137` — `// Reset Beads` — followed by `Beads.reset()`.
- `apps/terminal/src/index.ts:141` — `// Reset Telemetry` — followed by `Telemetry.reset()`.
- `apps/terminal/src/index.ts:145` — `// Destroy all workcells` — followed by `Workcell.destroyAll()`.
- `apps/terminal/src/index.ts:149` — `// Clear health cache` — followed by `Health.clearCache()`.
- `apps/terminal/src/index.ts:153` — `// Reset Hushd` — followed by `Hushd.reset()`.
- `apps/terminal/src/health/index.ts:266` — `// Update cache`.
- `apps/terminal/src/beads/index.ts:64` — `// Apply filters`.
- `apps/terminal/src/beads/index.ts:89` — `// Apply pagination`.
- `apps/terminal/src/beads/index.ts:108` — `// Get all open issues`.
- `apps/terminal/src/tools/index.ts:337` — `// Run speculation`.
- `apps/terminal/src/tools/index.ts:349` — `// Format results`.
- `apps/terminal/src/tools/index.ts:450` — `// Run gates`.
- `apps/terminal/src/tools/index.ts:456` — `// Format results`.
- `apps/terminal/src/verifier/gates/mypy.ts:149` — `// Run mypy`.
- `apps/terminal/src/verifier/gates/pytest.ts:104` — `// Run pytest`.

### hushd / hush-cli trivial init noise (7)

- `crates/services/hushd/src/cli.rs:136` — `// Load configuration`.
- `crates/services/hushd/src/cli.rs:150` — `// Initialize logging`.
- `crates/services/hushd/src/cli.rs:208` — `// Create router`.
- `crates/services/hushd/src/cli.rs:214` — `// Create listener`.
- `crates/services/hushd/src/cli.rs:303` — `// Run server`.
- `crates/services/hushd/src/api/policy.rs:452` — `// Parse the new policy`.
- `crates/services/hushd/src/api/policy.rs:464` — `// Update the engine`.
- `crates/services/hushd/src/audit/mod.rs:347` — `// Create tables` — over `conn.execute_batch(schema::CREATE_TABLES)`.
- `crates/services/hush-cli/src/main.rs:1374` — `// Initialize logging`.
- `crates/services/hush-cli/src/main.rs:3046` — `// Parse scopes`.
- `crates/services/hush-cli/src/main.rs:3054` — `// Calculate expiration`.
- `crates/services/hushd/src/config.rs:1584` — `// Parse scopes`.
- `crates/services/control-api/src/main.rs:74` — `// Initialize services`.

### control-api hierarchy banner dividers (3)

- `crates/services/control-api/src/services/hierarchy.rs:88-90` — `// ---- // Create node // ----` — the function below is named `create_node`.
- `crates/services/control-api/src/services/hierarchy.rs:160-162` — `// ---- // Update node // ----` — function is named `update_node`.
- `crates/services/control-api/src/services/hierarchy.rs:447-449` — `// ---- // Delete node // ----` — function is named `delete_node`.

### "Step N" narration in detection-workflow translation (9, sample shown)

These bracket otherwise self-explanatory parsing pipelines. Either replace with a single block comment that lists the stages, or delete entirely.

- `apps/workbench/src/lib/workbench/detection-workflow/eql-translation.ts:246` — `// Step 1: Parse Sigma YAML`.
- `apps/workbench/src/lib/workbench/detection-workflow/eql-translation.ts:264` — `// Step 2: Map logsource category to EQL event category`.
- `apps/workbench/src/lib/workbench/detection-workflow/eql-translation.ts:267` — `// Step 3: Extract selection blocks from detection`.
- `apps/workbench/src/lib/workbench/detection-workflow/eql-translation.ts:285` — `// Step 4: Build EQL conditions from selection fields`.
- `apps/workbench/src/lib/workbench/detection-workflow/eql-translation.ts:382` — `// Step 5: Build EQL AST`.
- `apps/workbench/src/lib/workbench/detection-workflow/eql-translation.ts:396` — `// Step 6: Generate EQL text`.
- `apps/workbench/src/lib/workbench/detection-workflow/eql-translation.ts:399` — `// Step 7: Add comment header`.
- `apps/workbench/src/lib/workbench/detection-workflow/sigma-conversion.ts:552-658` — same "Step 1..9" narration across nine landings.

### "extracted from"/"migrated from" sourcing notes (3)

- `apps/workbench/src/features/policy/stores/policy-edit-store.ts:56` — `// ---- Pure helpers (extracted from multi-policy-store.tsx) ----` — the historical provenance has no current value.
- `apps/workbench/src/features/settings/use-general-settings.ts:1-4` — `// General Settings ... // Zustand + immer store (migrated from React Context + useState).` — keep the description of behaviour, delete the migration provenance.
- `apps/workbench/src/features/settings/use-hint-settings.ts:1-4` — `// Hint Settings ... // Zustand + immer store (migrated from React Context + useState).` — same.

### Shortcut/dock removal markers

- `apps/workbench/src/components/desktop/shortcut-provider.tsx:171-172` — `// SHORTCUT_DEFINITIONS removed — was always empty at module load time // (registry not populated yet). Use getShortcutDefinitions() for live data.` — the live function is right above it; the gravestone is pure history.
- `apps/workbench/src/features/swarm/engine/topology.ts:520` — `// length - 1: the node was already pushed before this call` — restates the index arithmetic on the next line.

### Hash dividers without informational header (sample)

`apps/workbench/src/components/workbench/guards/guards-page.tsx` alone has 14 `// ---------------------------------------------------------------------------` divider pairs sprinkled across the file at lines 36/38, 60/62, 125/127, 141/142/144, 158/160, 242/244, 310/312, 521/523. Comparable density in `apps/workbench/src/components/plugins/view-tab-renderer.tsx` (lines 23/25, 36/38, 80/82) and `apps/workbench/src/components/plugins/view-container.tsx` (13/15, 46/48). All are pure section banners with no informational header on the line between them — delete the banner pairs (TS lacks `pragma` use for them) and let the function name speak.

### Other obvious-code restating examples

- `examples/secure-agent-swarm/index.ts:125` — `// Create adapters`.
- `examples/hello-secure-agent-ts/agent.ts:17` — `// Parse flags`.
- `examples/rust/basic-verification/src/main.rs:20` — `// Load the receipt`.
- `apps/desktop/src/shell/dock/useDockDemo.ts:452` — `// Add sessions`.
- `apps/workbench/src/features/observatory/components/hud/HeadingCompass.tsx:73` — `// Render the inner strip contents (static — rendered once)` — the function name and JSX make this obvious.
- `apps/workbench/src/components/desktop/command-palette.tsx:94` — `// Build the result list: recent (no query) or searched`.
- `apps/workbench/src/lib/workbench/detection-workflow/yaral-translation.ts:185` — `// Iterate over selection blocks (everything except "condition")` — code is `for ... if key === "condition" continue`.
- `apps/workbench/src/lib/workbench/detection-workflow/yaral-translation.ts:224` — `// Build the YARA-L rule`.
- `apps/workbench/src/lib/workbench/detection-workflow/yaral-adapter.ts:419` — `// Build the rule source`.
- `apps/workbench/src/lib/workbench/detection-workflow/yaral-adapter.ts:462` — `// Add a negative baseline`.
- `apps/workbench/src/lib/workbench/detection-workflow/sigma-adapter.ts:312` — `// Add a negative baseline`.
- `apps/workbench/src/lib/workbench/detection-workflow/kql-adapter.ts:579` — `// Add a negative baseline`.
- `apps/workbench/src/lib/workbench/detection-workflow/spl-adapter.ts:133` — `// Add a negative baseline with CIM field names`.
- `apps/workbench/src/lib/workbench/detection-workflow/eql-adapter.ts:556` — `// Add a negative baseline event`.
- `apps/workbench/src/lib/workbench/detection-workflow/policy-adapter.ts:186` — `// Add a benign baseline scenario`.
- `apps/workbench/src/lib/workbench/detection-workflow/ocsf-adapter.ts:364` — `// Add an invalid baseline for negative testing`.
- `apps/workbench/src/lib/workbench/detection-workflow/yara-adapter.ts:117` — `// If no strings were extracted, add a placeholder`.
- `apps/workbench/src/lib/workbench/detection-workflow/eql-parser.ts:381` — `// Find all bracket blocks`.
- `apps/workbench/src/lib/workbench/detection-workflow/use-publication.ts:269` — `// Build the full manifest`.
- `apps/workbench/src/lib/workbench/detection-workflow/draft-generator.ts:86` — `// Create a document reference for the starter evidence`.
- `apps/workbench/src/lib/workbench/detection-workflow/coverage-gap-engine.ts:356` — `// Build a synthetic seed to use recommendFormats`.
- `apps/workbench/src/lib/workbench/detection-workflow/coverage-gap-engine.ts:396` — `// Build a minimal seed to get format recommendations`.
- `apps/workbench/src/lib/workbench/reputation-tracker.ts:533` — `// Build a map of fingerprint -> member for fast lookup`.
- `apps/workbench/src/lib/workbench/signal-pipeline.ts:783` — `// Find all signals from this session`.
- `apps/workbench/src/lib/workbench/signal-pipeline.ts:861` — `// Build a union-find for cluster merging` — over `new Map()`. The why is interesting but the what is restated.
- `apps/workbench/src/lib/workbench/report-generator.ts:168` — `// Build a lookup map for results by scenario ID`.
- `apps/workbench/src/lib/workbench/coverage-analyzer.ts:114` — `// Build a map of guard -> scenario IDs`.
- `apps/workbench/src/lib/workbench/catalog-deps.ts:31` — `// Check if the base exists in builtins`.
- `apps/workbench/src/lib/workbench/hushd-event-simulator.ts:240` — `// Find the specific guard's result, or use overall verdict`.
- `apps/workbench/src/lib/workbench/ocsf-schema.ts:141` — `// Find the last unmatched colon or comma/brace`.
- `apps/workbench/src/lib/workbench/ocsf-schema.ts:172` — `// Build the object path by scanning for nested "key": {` patterns`.
- `apps/workbench/src/features/project/stores/project-store.tsx:246` — `// Insert each path segment-by-segment.`
- `apps/workbench/src/features/project/stores/project-store.tsx:275` — `// Convert the intermediate tree to ProjectFile[].`
- `apps/workbench/src/features/swarm/swarm-coordinator.ts:408` — `// Create a listener that fires for any subscribed topic`.
- `apps/workbench/src/features/swarm/swarm-coordinator.ts:997` — `// Re-subscribe to all previously active swarm topics` — the loop body does exactly this. Delete; keep the function-level docstring instead.
- `apps/workbench/src/features/swarm/hooks/use-trust-graph-bridge.ts:87` — `// Create a handoff edge from the first existing agentSession node`.
- `apps/workbench/src/features/swarm/hooks/use-trust-graph-bridge.ts:112` — `// Find the node with this memberId`.
- `apps/workbench/src/features/swarm/hooks/use-receipt-flow-bridge.ts:109` — `// Find the source agent session node by matching swarmId to huntId`.
- `apps/workbench/src/features/swarm/hooks/use-receipt-flow-bridge.ts:151` — `// Increment the session's receiptCount`.
- `apps/workbench/src/features/swarm/hooks/use-policy-eval-board-bridge.ts:60` — `// Find the matching agent session node`.
- `apps/workbench/src/features/observatory/components/MissionObjectiveBeacons.tsx:48` — `// Find the first non-completed objective's stationId`.
- `apps/workbench/src/components/workbench/swarm-board/nodes/note-node.tsx:30` — `// Clear the flag so it doesn't re-trigger`.
- `apps/workbench/src/components/workbench/swarms/trust-graph.tsx:358` — `// Build a set of fingerprints in the display list for edge filtering`.
- `apps/workbench/src/components/workbench/hierarchy/hierarchy-page.tsx:1283` — `// Find the new node and select it`.
- `apps/workbench/src/components/workbench/hierarchy/hierarchy-page.tsx:1798` — `// Find the root node in the array`.
- `apps/workbench/src/components/workbench/hierarchy/hierarchy-page.tsx:1896` — `// Build the node map from remote data`.
- `apps/workbench/src/components/workbench/origins/origins-page.tsx:2204` — `// Find the index of the previously selected profile to pick a neighbor`.
- `apps/workbench/src/components/workbench/origins/origins-page.tsx:2547` — `// Find the real index in the full library for reordering`.
- `apps/workbench/src/components/workbench/editor/test-diff-panel.tsx:112` — `// Find the guard that likely caused the overall verdict change`.
- `apps/workbench/src/components/workbench/editor/bulk-operations-dialog.tsx:181` — `// Build a single BULK_UPDATE_GUARDS dispatch that applies all guard changes`.
- `apps/workbench/src/components/workbench/editor/test-runner-panel.tsx:673` — `// Build a results map keyed by scenario name for graph overlay`.
- `apps/workbench/src/components/workbench/editor/sdk-integration-tab.tsx:280` — `// Create the editor once (runs only on mount)`.
- `apps/workbench/src/components/workbench/editor/sigma-visual-panel.tsx:591` — `// Remove the field if value is empty`.
- `apps/workbench/src/components/workbench/editor/kql-visual-panel.tsx:245` — `// Parse the current KQL source into structured components`.
- `apps/workbench/src/components/workbench/editor/spl-visual-panel.tsx:314` — `// Get the comment block for reconstruction`.
- `apps/workbench/src/components/workbench/editor/yara-visual-panel.tsx:116` — `// Find the rule body (content between the first { after rule declaration and last })`.
- `apps/workbench/src/components/workbench/editor/yara-visual-panel.tsx:138` — `// Remove the "meta:" header line`.
- `apps/workbench/src/components/workbench/speakeasy/speakeasy-panel.tsx:280` — `// Send a chat message`.
- `apps/workbench/src/components/workbench/library/catalog-browser.tsx:628` — `// Add any remote-only categories`.
- `apps/workbench/src/components/ui/yaml-editor.tsx:431` — `// Build the list of extensions (rebuilds when readOnly, fontSize, ...)` — the extension array is right there; the change-list belongs in dep-array.
- `apps/workbench/src/components/desktop/titlebar.tsx:15` — `// Update the native window title when the policy name or dirty state changes`.
- `apps/workbench/src/lib/commands/edit-commands.ts:86` — `// Find the Mod-h command from searchKeymap which opens search with replace enabled`.
- `apps/workbench/src/lib/plugins/plugin-trust.ts:93` — `// 5. Build the manifest object that was originally signed (without the signature field)` — drop the leading "5." narration.
- `apps/workbench/src/lib/plugins/view-registry.ts:82` — `// Sort each group by priority ascending (default 100)`.
- `apps/workbench/src/lib/plugins/context-menu-registry.ts:74` — `// Sort each group by priority ascending (default 100)`.
- `apps/workbench/src/lib/plugins/plugin-view-tab-store.ts:90` — `// Find the tab with the smallest lastActiveAt among hidden tabs`.
- `apps/workbench/src/lib/plugins/plugin-view-tab-store.ts:156` — `// Find the remaining tab with the highest lastActiveAt`.
- `apps/workbench/src/lib/plugins/revocation-store.ts:153` — `// Build a set of plugin IDs present in the remote snapshot (non-expired)`.
- `apps/desktop/src/services/openclaw/gatewayClient.ts:382` — `// For now we rely on token-based auth. Signed challenges are supported` — see Bucket B; either expand or delete.
- `apps/desktop/src/services/tauri.ts:191` — `// Return mock data for browser testing`.
- `apps/desktop/src/shell/dock/useDockDemo.ts:452` — `// Add sessions`.
- `apps/desktop/src/shell/sessions/sessionStore.ts:197` — `// Create a cache key from filter`.
- `apps/desktop/src/features/threat-radar/ThreatRadarView.tsx:50` — `// Find the original SDR event for a threat to get its timestamp`.
- `apps/desktop/src-tauri/src/commands/spine.rs:215` — `// Parse the envelope JSON from the message payload`.
- `apps/academy/src/lib/policy-linter.ts:81` — `// Find the end of the line containing 'from'.`
- `crates/services/hush-cli/src/pkg_cli.rs:1569` — `// Remove the installed package since trust verification failed.` — restates `cleanup_install()` on the next line.
- `crates/services/control-api/src/routes/agents.rs:364` — `// Delete the agent row.`
- `crates/services/control-api/src/services/hierarchy.rs:587` — `// Delete the node itself`.
- `crates/services/control-api/src/services/catalog.rs:307` — `// to prevent TOCTOU races (the source being deleted between read and insert).` — split paragraph; the previous sentence carries the info.
- `crates/services/clawdstrike-registry/src/api/audit.rs:68` — `// Get all versions (includes yanked flag).`
- `crates/services/clawdstrike-registry/src/api/checkpoint.rs:57` — `// Build the canonical checkpoint message.`
- `crates/libs/clawdstrike/src/pkg/resolver_deps.rs:329` — `// Find the exact version.`
- `crates/libs/clawdstrike/src/output_sanitizer.rs:842` — `// Sort by start desc so replacements don't affect earlier spans.` — borderline; the why is interesting but the operation is obvious; consider rewriting to focus on the invariant.
- `crates/libs/hunt-correlate/src/engine.rs:117` — `// Remove empty entries.`
- `crates/libs/hunt-correlate/src/report.rs:86` — `// Build the Merkle tree.`
- `crates/libs/hunt-scan/src/storage.rs:218` — `// Detect removed servers`.
- `crates/libs/hunt-scan/src/storage.rs:333` — `// Empty results = server was removed`.
- `crates/libs/hush-proxy/src/dns.rs:31` — `// Parse the first question`.
- `crates/libs/hush-proxy/src/sni.rs:39-40` — `// Parse ClientHello` / `parse_client_hello(handshake)`.
- `crates/libs/hush-proxy/src/sni.rs:91` — `// Parse extensions`.
- `crates/libs/clawdstrike/src/hushspec_compiler.rs:276` — `// Build extensions`.
- `crates/libs/hush-wasm/src/lib.rs:498` — `// Compute root`.
- `crates/libs/hunt-scan/src/receipt.rs:110` — `// Build the receipt.`
- `crates/bridges/darwin-telemetry-bridge/src/event.rs:31` — `// Process events`.
- `crates/bridges/darwin-telemetry-bridge/src/event.rs:445` — `// Process events`.
- `apps/terminal/src/tui/screens/hunt-playbook.ts:233` — `// Run playbook`.
- `apps/terminal/src/tui/screens/hunt-rule-builder.ts:237/246/297` — `// Add condition` / `// Delete condition` / `// Save rule`.
- `apps/terminal/src/tui/screens/hunt-watch.ts:340/361` — `// Filter cycle` / `// Clear log`.
- `apps/terminal/src/tui/screens/hunt-scan.ts:408` — `// Build tree`.
- `apps/terminal/src/tui/screens/hunt-diff.ts:105` — `// Find removed`.
- `apps/terminal/src/tui/types.ts:534` — `// Setup wizard`.
- `apps/terminal/src/workcell/lifecycle.ts:232` — `// Update status`.
- `apps/terminal/src/workcell/lifecycle.ts:209` — `// Return to pool as warm`.
- `apps/terminal/src/workcell/pool.ts:49` — `// Create new pool`.
- `apps/terminal/src/workcell/pool.ts:70` — `// Return defaults`.
- `apps/terminal/src/speculate/voter.ts:67` — `// Return the one that completed first`.
- `apps/terminal/src/speculate/voter.ts:111` — `// Return candidate with highest total similarity`.

### Other "previously"/"used to" narration

- `apps/workbench/src/lib/workbench/reputation-tracker.ts:411` — `// Only explore if this path gives better trust than previously seen` — the "previously" framing reads as history; "Skip paths whose trust is worse than the current best" is cleaner.
- `apps/desktop/src/services/openclaw/gatewayClient.ts:382` — `// For now we rely on token-based auth. Signed challenges are supported ...` — "For now we" is history narration; rewrite per Bucket B.

## B. Rewrite (suggested wording)

- `apps/workbench/src/components/workbench/sentinels/sentinel-detail.tsx:337-338`
  current: `// In a real implementation this would pull from SignalProvider filtered by sentinelId. // For now we show a placeholder that communicates the design intent.`
  proposed: `// Placeholder: SignalProvider integration ships in a later phase.`

- `apps/agent/src-tauri/src/daemon.rs:1941-1943`
  current: `// Hushd no longer accepts legacy guard keys like fs_blocklist. // When an incompatible policy is detected, fall back to built-in ruleset // so the daemon stays available instead of restart-looping.`
  proposed: `// Incompatible policies (e.g. legacy fs_blocklist guards) must not crash-loop the daemon — fall back to the built-in ruleset and surface a warning.`

- `crates/libs/clawdstrike/src/curator_config.rs:26-28`
  current: `// --------- // Original flat config types (preserved for backward compatibility) // ---------`
  proposed: `// Flat trusted_curators.toml schema — kept for compatibility with pre-1.2 configs.`

- `apps/workbench/src/features/settings/use-general-settings.ts:1-4`
  current: `// General Settings — app-level preferences (theme, editor, autosave) // Persisted to localStorage independently of the policy store. // // Zustand + immer store (migrated from React Context + useState).`
  proposed: `// App-level preferences (theme, editor, autosave). Persists to localStorage independently of the policy store.`

- `apps/workbench/src/features/settings/use-hint-settings.ts:1-4`
  current: `// Hint Settings — configurable Claude Code hint text and visibility // ... // Zustand + immer store (migrated from React Context + useState).`
  proposed: `// Hint visibility + Claude Code hint text. Persists to localStorage.`

- `apps/desktop/src/services/openclaw/gatewayClient.ts:382`
  current: `// For now we rely on token-based auth. Signed challenges are supported by the gateway but disabled here until the desktop has a signing key.`
  proposed: `// Token-based auth only. Gateway supports signed challenges, but the desktop has no signing key yet.`

- `apps/workbench/src/features/swarm/swarm-coordinator.ts:997`
  current: `// Re-subscribe to all previously active swarm topics`
  proposed: `// Reconnect recovers subscriptions; the transport drops them on disconnect.`

- `apps/workbench/src/features/policy/stores/policy-edit-store.ts:56`
  current: `// ---- Pure helpers (extracted from multi-policy-store.tsx) ----`
  proposed: `// ---- Pure helpers ----` (drop the extraction provenance entirely).

- `apps/workbench/src/components/workbench/sentinel-swarm-pages.tsx:2`
  current: `// Components moved to ./sentinel-swarm/ for maintainability. This file is kept for backwards ...`
  proposed: `// Re-exports from ./sentinel-swarm/ for legacy import paths.` (then verify any callers still using this re-export warrant the file at all).

- `apps/workbench/mcp-server/index.ts:120`
  current: `// diagnostics (e.g. deprecated fields) and must not invalidate a policy.`
  proposed: keep, but tighten leading paragraph that introduces this clause.

- `apps/workbench/src/components/desktop/shortcut-provider.tsx:171-172`
  current: `// SHORTCUT_DEFINITIONS removed — was always empty at module load time // (registry not populated yet). Use getShortcutDefinitions() for live data.`
  proposed: delete entirely; `getShortcutDefinitions()` already documents the live data path.

- `crates/services/control-api/src/services/hierarchy.rs:100-101`
  current: `// Resolve the stored node_type string — map legacy "agent" to "endpoint" // so new rows always use the canonical type.`
  proposed: keep the why, drop the "legacy" wording: `// Persist "agent" as "endpoint" so new rows use the canonical type only.`

## C. Keep (load-bearing context)

- `crates/services/clawdstrike-brokerd/src/provider/generic_https.rs:91-93` — `// When a pinned address is available (DNS was resolved during validation), // build a one-shot client that resolves the hostname to that address, // preventing DNS rebinding between validation and execution.` — security invariant. Lose this and the next reader will refactor it away.
- `apps/agent/src-tauri/src/daemon.rs:1941-1943` — fallback-to-built-in policy explanation (suggested to rewrite, not delete; see Bucket B).
- `apps/agent/src-tauri/src/enrollment.rs:180` — `// Clear legacy auth fields so token-based auth is used consistently.` — explains an invariant the next field assignments rely on.
- `crates/services/control-api/src/services/hunt.rs:990-991` — `// We never rewrite a previously ingested event on key collision. Exact duplicates are // idempotent; everything else is an explicit conflict.` — describes the policy decision behind the INSERT, not the SQL.
- `crates/services/control-api/src/services/stale_agent_detector.rs:93-95` — `// Mark previously stale agents as dead. // Ordering matters: this runs before the stale transition so agents cannot // jump directly from active -> dead within a single detection cycle.` — ordering invariant.
- `crates/services/control-api/src/services/hierarchy.rs:168-173` — comment explains why the SELECT FOR UPDATE is wrapped in a transaction (TOCTOU). Keep.
- `crates/services/hushd/src/api/certification.rs:163` — `// Same temporary scope mapping as the legacy middleware.` — load-bearing while RBAC migration is in progress; revisit after Phase 4 lands.
- `crates/services/hushd/src/auth/middleware.rs:128` — `// Temporary scope mapping (replaced by RBAC in Phase 4).` — same.
- `crates/services/hushd/src/rbac/mod.rs:733` — `// If RBAC is disabled, treat identity roles as role IDs (legacy behavior).` — explains the fallback semantics; not a history note.
- `packages/adapters/clawdstrike-vercel-ai/src/middleware.ts:331-333` — `// "experimental_wrapLanguageModel" was removed in "ai@5+" and renamed // to "wrapLanguageModel". Prefer the stable export; fall back to the // legacy name for callers still on "ai@3-4".` — explains why both names are probed dynamically.
- `crates/libs/clawdstrike/src/pkg/store.rs:223` — `// Disarm the guard — the temp dir no longer exists (it was renamed).` — guarded RAII invariant.
- `apps/agent/src-tauri/src/session.rs:462` — `// Session invalid/expired (or no longer accessible). Clear local state so we don't ...` — explains state machine.
- `crates/libs/clawdstrike-ocsf/src/convert/from_security_event.rs:170` — `// Convenience wrapper for backward compatibility.` — keep; documents an OCSF surface boundary.
- `apps/workbench/src-tauri/src/commands/workbench.rs:1278` — `// is empty). Unparseable signatures alone no longer count as "valid". (#20)` — explains a regression-test invariant tied to a publicly tracked issue.
- `crates/libs/hush-ffi/src/watermark.rs:66` — `// would silently rotate keys and break verification for callers that previously trusted the ...` — explains why a key rotation path is intentionally not taken.
- `apps/workbench/src/lib/workbench/yara-language.ts:165-171` — heuristic disambiguating YARA `{ XX XX }` hex from rule bodies; describes parser state machine.
- `packages/sdk/hush-py/src/clawdstrike/prompt_security.py:91-92` — `# If redaction reshapes previously-emitted bytes, fall back to emitting the full // sanitized buffer ...` — describes streaming sanitizer semantics under reshape.

## Top 10 most egregious examples (quoted)

1. `apps/agent/src-tauri/src/api_server/response_actions.rs:3646-3648` — `// quarantine_file_effect, disable_persistence_effect, suspend_process_tree_effect, // process_tree_effect_pids moved to crate::edr::response // quarantine_destination_path, safe_filename_fragment moved to crate::edr::response` — six function names referenced just to say "we moved them".
2. `apps/agent/src-tauri/src/api_server/policy_history.rs:1403-1405` — `// build_policy_event_replay_report, build_policy_event_impact_changes, // build_policy_event_impact_drivers, build_policy_event_impact_report // moved to crate::edr::policy_events` — same pattern, four functions.
3. `apps/workbench/src/components/desktop/shortcut-provider.tsx:171-172` — `// SHORTCUT_DEFINITIONS removed — was always empty at module load time // (registry not populated yet). Use getShortcutDefinitions() for live data.` — a tombstone for a removed constant directly above the live function.
4. `apps/terminal/src/index.ts:107-156` — nine consecutive `// Initialize X` / `// Reset X` / `// Stop X` annotations over single-method calls (`Beads.init`, `Telemetry.reset`, etc.).
5. `crates/services/hushd/src/cli.rs:136-303` — `// Load configuration`, `// Initialize logging`, `// Create router`, `// Create listener`, `// Run server` — restating every step of a daemon `main`.
6. `apps/workbench/src/lib/workbench/version-store.ts:320/347/436/440` — `// Update the version's tags array` / `// Get all tags for this policy` / `// Get all versions, newest first` / `// Get the policy name from the latest version` — four consecutive comments restating the line below.
7. `crates/services/control-api/src/services/hierarchy.rs:88-89` — `// --------- // Create node // ---------` over `pub async fn create_node(...)`. Repeated for `update_node` (160) and `delete_node` (448).
8. `apps/workbench/src/components/workbench/editor/version-history-panel.tsx:145/154/167` — `// Save version` / `// Add tag` / `// Remove tag` over `handleSaveVersion` / `handleAddTag` / `handleRemoveTag`.
9. `apps/workbench/src/features/policy/stores/policy-edit-store.ts:56` — `// ---- Pure helpers (extracted from multi-policy-store.tsx) ----` — extraction provenance preserved as a banner.
10. `apps/workbench/src/lib/workbench/detection-workflow/sigma-conversion.ts:552-658` and `eql-translation.ts:246-399` — "Step 1 ... Step 9" narration across the whole file body, restating function flow that the function names already make clear.

## Methodology notes

- Searches used `rg -n` against TS/Rust/Python with explicit excludes for `node_modules`, `dist`, `target`, `infra/vendor`, `vendor/`, `.audit/`, `*test*` files, and `tests/`/`test/`/`__tests__/` directories.
- Doc-comments (`///`, `//!`, `/** */`) were excluded unless clearly noise.
- Findings were de-duplicated against legitimate trait/field docs that happen to use words like "removed" or "previously" in their proper sense (e.g. `presence::leave` returning the removed `AnalystInfo`).
- Two divider conventions exist in this codebase: hyphen banners (`// ---- Section ----`) and equal-sign banners. Both are listed as Bucket A. If the team prefers banners, replace with a single line `// === Section ===` rather than `--`-bracketed pairs.
