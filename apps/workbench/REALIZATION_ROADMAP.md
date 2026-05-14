# Realization Roadmap: Strip Demo → Live

**Status:** Phase 1 + Phase 2 COMPLETE. Phase 3 + Phase 4 remaining.
**Backend finding:** hushd + control-api are far more complete than expected. Most APIs already exist.

## Dependency Graph

```
Phase 1 (no backend needed)          Phase 2 (wire existing APIs)
├─ P1-1 Settings General      [DONE] ├─ P2-1 Approval adapter      [DONE]
├─ P1-2 Agent Profile          [DONE] ├─ P2-2 Delegation adapter    [DONE]
├─ P1-3 Receipt Persistence    [DONE] ├─ P2-3 Hierarchy→ScopedPol   [DONE]
├─ P1-4 Receipt Format Fix     [DONE] └─ P2-4 Compliance data file  [DONE]
│   └─ P1-5 Real Receipt Gen   [DONE]
├─ P1-6 Local Audit Trail      [DONE] Phase 3 (new backend endpoints)
└─ P1-7 MCP Status Check       [DONE] ├─ P3-1 Hierarchy CRUD API    [L] → P3-2 Fleet Sync [M]
                                       ├─ P3-3 Receipt Storage API   [M] → P3-4 Fleet Store [M]
Phase 4 (security hardening)           └─ P3-5 Catalog Registry API  [M] → P3-6 Live Catalog [M]
├─ P4-1 Stronghold Plugin      [M]
│   ├─ P4-2 Credential Migrate [M]   Blocker fix: [DONE]
│   └─ P4-3 Persistent Keys    [M]   - fleet-client /policy/distribute → /policies/deploy path fix
└─ P4-4 HSM/Keychain           [L]
```

## Completed Items

### Blocker Fix [DONE]
- Fixed fleet-client API path: `/api/v1/policy/distribute` → `/api/v1/policies/deploy`
- Fixed request body field: `{ yaml }` → `{ policy_yaml: yaml }` (matches backend `deny_unknown_fields`)
- Updated mock server + tests

### P1-1: Settings General Tab [DONE]
- New `use-general-settings.ts` context: theme, font size (S/M/L), autosave interval, line numbers
- New `settings/general-settings.tsx` UI with pill selectors and toggle
- Wired into editor: dynamic font size + line number toggle
- Persisted to localStorage

### P1-2: Agent Profile in Scenarios [DONE]
- Added `AgentProfile` + `AgentRuntime` types to `types.ts`
- Dynamic fleet-aware agent selector: dropdown of fleet agents when connected, free text when not
- Agent runtime selector (Claude, GPT-4, Gemini, Llama, Mistral, Custom)
- Tag-based permissions input

### P1-3: Receipt Persistence [DONE]
- New `use-persisted-receipts.ts` hook with localStorage backing
- 1000 receipt cap with FIFO eviction
- Debounced 500ms writes, shape validation on read

### P1-4: Receipt Format Fix [DONE]
- Added RFC 8785 canonical JSON fallback in `verify_receipt_chain`
- Colon-delimited remains primary, canonical JSON as fallback
- 2 new Rust tests for fallback verification + security non-regression

### P1-5: Real Receipt Generation [DONE]
- Desktop mode: `simulateActionNative()` → real verdict → `signReceiptNative()` → real Ed25519 signature
- Action type selector (6 preset actions)
- Web mode: falls back to test receipt generation
- Emits `receipt.generate_real` audit events

### P1-6: Local Audit Trail [DONE]
- New `local-audit.ts` with localStorage backend (5000 cap, FIFO)
- `useSyncExternalStore`-based reactive hook
- Events emitted from: editor validation, simulator runs, receipt signing, import/export, fleet connect/disconnect, deploy
- Audit log page: dual-source display (auto/local/fleet), source badges, filtered views

### P1-7: MCP Status Check [DONE]
- Copy-to-clipboard for MCP launch command
- Green pulsing status indicator (available when workbench is running)

### P2-1: Approval Shape Adapter [DONE]
- Full backend → frontend type mapping in `fleet-client.ts`
- Extracts originContext, toolName, riskLevel from `event_data` JSONB
- Derives "expired" from timestamps
- Handles 3 response shapes (flat array, wrapped, passthrough)
- 10 new tests

### P2-2: Delegation Graph Adapter [DONE]
- `fetchDelegationGraphSnapshot()` via `GET /principals/{id}/delegation-graph`
- `fetchPrincipals()` via `GET /api/v1/principals`
- Principal selector dropdown in delegation page
- Graceful fallback chain: snapshot → grants-based → demo data

### P2-3: Hierarchy → Scoped Policies [DONE]
- `fetchScopedPolicies()`, `createScopedPolicy()`, `fetchPolicyAssignments()`, `assignPolicyToScope()`
- LIVE/DEMO toggle (disabled when fleet disconnected)
- Push to Fleet / Pull from Fleet sync buttons
- Tree reconstruction from backend assignments

### P2-4: Compliance Data File [DONE]
- Extracted frameworks to `src/data/compliance-frameworks.json`
- Runtime hydration merges JSON metadata with check functions
- Same exported API, no downstream changes

## Remaining: Phase 3 (new backend endpoints)

### P3-1: Hierarchy CRUD API [L, Rust]
- New endpoints in control-api for hierarchy node CRUD
- `GET/POST/PUT/DELETE /api/v1/hierarchy/nodes`

### P3-2: Fleet Sync [M, TS]
- Wire hierarchy page to real-time sync with P3-1 endpoints
- **Depends on:** P3-1

### P3-3: Receipt Storage API [M, Rust]
- Persistent receipt storage in control-api database
- `GET/POST /api/v1/receipts`

### P3-4: Fleet Receipt Store [M, TS]
- Wire receipt inspector to store/retrieve receipts from fleet
- **Depends on:** P3-3

### P3-5: Catalog Registry API [M, Rust]
- Policy template catalog in control-api
- `GET/POST /api/v1/catalog/templates`

### P3-6: Live Catalog [M, TS]
- Wire library gallery to live catalog
- **Depends on:** P3-5

## Remaining: Phase 4 (security hardening)

### P4-1: Stronghold Plugin [M, Rust+TS]
- Add `tauri-plugin-stronghold` dependency
- Create secure credential store

### P4-2: Credential Migration [M, TS]
- Migrate fleet credentials from localStorage to Stronghold
- **Depends on:** P4-1

### P4-3: Persistent Signing Keys [M, TS+Rust]
- Store Ed25519 signing keys in Stronghold instead of ephemeral generation
- **Depends on:** P4-1

### P4-4: HSM/Keychain [L, Rust]
- Optional platform keychain (macOS Keychain, Windows Credential Manager) integration
- **Depends on:** P4-1
