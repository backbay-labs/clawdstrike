# DELTA D07: Tauri Desktop Apps

**Refreshed:** 2026-05-24 | **Source:** `.audit/07-tauri-desktop-apps.md` + wave3 `B-api-server-routes.md` + wave3 `F-release-walkthrough.md` | **Scope:** `apps/agent/src-tauri/`, `apps/desktop/src-tauri/`, `apps/workbench/src-tauri/`, Tauri configs, icons, signing, macOS system extension, build pipeline

---

## Quick Verdict

- **Findings still valid:** 25 of 32 source-audit findings
- **Findings fixed since 2026-05-23:** 1 partial fix (CI now imports Apple signing certificate via secrets — commit `1ade43894`); 0 are fully closed in code
- **Findings wrong / overstated:** 4 (desktop "75 commands" should be 31; `marketplace_discovery.rs` 21K LOC overstatement; "daemon.rs 200+ unwraps in tests" should be 67; desktop "no logging facade" wrong — desktop now imports `tracing`)
- **New issues found:** 7 (working-tree-only Swift regression around `EndpointSecurityAgentEventEncoder` deletion of cached `iso8601Formatter`; new working-tree-only es_delete_client ordering change; tray.rs unchanged at 1264 LOC despite being on the wave3 cleanup list; 75 `eprintln!` in workbench (not the audit-reported ~10); etc.)
- **`api_server.rs` line count at HEAD:** **48,111** (audit said 48,118) — **0.0% shrinkage**
- **`api_server.rs` line count in working tree:** **48,118** (working tree adds 7 lines for a `signedReceipt` field, *not* a refactor — file is going **up**, not down)
- **3 default icons (md5 `9418b9b0e421e3ff0744aef7960f511c`):** still byte-identical across `agent/desktop/workbench` (also 32x32/64x64/128x128/128x128@2x are all md5-identical too — checked `332a56695e4931ea0747be607be6014a` for 32x32)
- **Signing identity null:** Y in every `tauri.conf.json` (agent/desktop). Workbench `tauri.conf.json` still lacks any `bundle.macOS` block at all
- **`capabilities.json` empty:** Y for agent (`{}`) and desktop (`{}`); no `capabilities/` source directory exists for either. Workbench's lone `capabilities/default.json` still good.
- **Net delta:** The wave3 audit underestimated how much remains. The EDR refactor (commits `bd3ea7e63` / `e6d87e878` / `ad1c6d187` / `a97fda5d9`) extracted **60 EDR HANDLER FUNCTIONS** to `edr/handlers/*.rs` (8 files, 4,099 LOC) plus 17 ledger/DTO/queries modules totalling **12,647 LOC in `edr/`** — but it left the **~500 EDR HELPER FUNCTIONS the handlers depend on** in `api_server.rs`. Net api_server.rs LOC change: **+10 lines** in 6 weeks of "refactoring" (48,108 in late March → 48,111 at HEAD → 48,118 in working tree). The B-audit's split plan is still the right move; it just hasn't actually shrunk the file yet.

---

## STILL VALID

### CRITICAL — Structural

#### [CRITICAL] `api_server.rs` is still 48K+ lines
- **Source claim:** 48,118 lines, 884 functions, 19K production + 29K test
- **Now:** `apps/agent/src-tauri/src/api_server.rs:48118` (working tree); `48111` at HEAD `2eff91532`
- **Production fn definitions:** 448 (audit said 598; wave3 B said 598)
- **Total fn definitions (incl. test):** 720 (matches wave3 B)
- **`#[(tokio::)?test]` attributes:** 229 (matches wave3 B exactly)
- **`Router::new()` calls in tests:** 163 (matches wave3 B's "162")
- **`agent_edr_*` symbol references:** 507 across the file
- **Visible cleanup since audit:** the `pub(crate) use crate::edr::{conversion,dto,handlers,policy_events,queries,response}::*;` re-exports at `apps/agent/src-tauri/src/api_server.rs:91-96` are new, plus 12.6K LOC was moved into `apps/agent/src-tauri/src/edr/`. **Net api_server.rs growth: +10 lines.** The biggest commits since the audit (`bd3ea7e63` "split 60 EDR handlers", `7fa3f7cf1` "extract 188 EDR DTOs", `0a67bad82` bulk visibility, `4403de90a` "extract remaining 10 EDR ledger structs", `af6b2be9c` "extract staged-detection ledger") are sibling moves — they did not shrink `api_server.rs`.
- **Still valid; in fact the wave3 B execution plan is now the canonical fix.**
- **Refactor target per wave3 B:** ~32 files averaging 600–1,800 LOC, with `crates/services/agent-api/` extraction the AGGRESSIVE-ceiling move.

#### [CRITICAL] Empty `capabilities.json` on desktop and agent
- **Source claim:** both `gen/schemas/capabilities.json` are `{}` and there's no `capabilities/` source dir.
- **Verified:** `apps/agent/src-tauri/gen/schemas/capabilities.json` contents = `{}`. `apps/desktop/src-tauri/gen/schemas/capabilities.json` contents = `{}`. No `capabilities/` dir under either `apps/agent/src-tauri/` or `apps/desktop/src-tauri/`.
- **Workbench:** `apps/workbench/src-tauri/capabilities/default.json:1-74` still excellent (`fs:scope` deny list at 31-62 covers `$HOME/.ssh`, `.gnupg`, `.aws`, `.kube`, `.docker`, `.azure`, `.password-store`, `.npmrc`, `.pypirc`, `Library/Keychains`, `.netrc`, `.git-credentials`, `keyrings`, `kwalletd`).
- **Still valid.**

#### [CRITICAL] Agent registers ZERO `#[tauri::command]`s
- **Source claim:** all 884 functions exposed via 127.0.0.1:9878 HTTP, no Tauri IPC at all.
- **Verified:** `grep -rn '#\[tauri::command\]' apps/agent/src-tauri/src/` returns **zero hits**. `apps/agent/src-tauri/src/main.rs:277-339` builds the Tauri runtime but never calls `.invoke_handler(...)` — only `.plugin(...)` and `.manage(...)` and a `setup(...)` closure that spawns `run_agent(...)` on the tauri async runtime.
- **Frontend is still static stub:** `apps/agent/src-tauri/resources/index.html` is 161 bytes (the "Tray-only app - no UI window" page).
- **Still valid.**

### HIGH — Tauri config / Build / Signing

#### [HIGH] `beforeBuildCommand` shells out and cross-builds workspace crates + a sibling app's frontend
- **Verified:** `apps/agent/src-tauri/tauri.conf.json:7-9` still calls `sh scripts/prepare-bundled-hushd.sh release`. Script `apps/agent/scripts/prepare-bundled-hushd.sh` (67 lines):
  - Line 35-38: `cargo build -p hushd --release` and `cargo build -p clawdstrike-brokerd --release` against the workspace root.
  - Line 56: `npm --prefix "${control_console_dir}" ci` if node_modules missing.
  - Line 59: `npm --prefix "${control_console_dir}" run build` — building a *different application's* Vite frontend.
  - Lines 63-65: `rm -rf` + `cp -R` to copy the bundled UI into `src-tauri/resources/control-console/`.
- **Still valid. AGGRESSIVE fix per audit: move to xtask or moon task.**

#### [HIGH] Hardcoded macOS Team ID `JB6682CJY9`
- **Verified:** Three call sites still present.
  - `apps/agent/src-tauri/macos/system-extension/profiles/render-mdm-profiles.sh:10` ("TEAM_ID defaults to JB6682CJY9 when --team-id is omitted.")
  - `apps/agent/src-tauri/macos/system-extension/profiles/render-mdm-profiles.sh:16` (`TEAM_ID="JB6682CJY9"`)
  - `apps/agent/src-tauri/macos/system-extension/profiles/developer-id-profile-template.plist:9,22` (two `<string>JB6682CJY9</string>`)
- **Still valid.**

#### [HIGH] Tauri config `signingIdentity: null` and no notarization config
- **Verified:** `apps/agent/src-tauri/tauri.conf.json:38-39` still `"signingIdentity": null, "providerShortName": null`. Same in `apps/desktop/src-tauri/tauri.conf.json:54-55`. Workbench `tauri.conf.json` still has no `bundle.macOS` block at all (`apps/workbench/src-tauri/tauri.conf.json:33-48`).
- **PARTIAL CI-side fix since audit:** commit `1ade43894 fix(ci): restore swarm bootstrap and macos signing setup` (2026-05-19, 4 days before the audit was written) added `Import Apple signing certificate` and `Store notarytool credentials` steps to `.github/workflows/release.yml` (lines 993-1050 of release.yml). The cert is imported from `APPLE_DEVELOPER_ID_APPLICATION_CERTIFICATE_BASE64` into a temp keychain, used to build/notarize via `bash scripts/notarize-agent-macos.sh`, then deleted in a cleanup step. **However**, the `tauri.conf.json` itself still has `null` so the local `cargo tauri build` story is unchanged. The release path now works *if* secrets are present; the local-dev story is still broken. Wave3 F flagged this exact ambiguity ("`build-agent-dmg` … Will silently no-op the `Import Apple signing certificate` step … but `scripts/notarize-agent-macos.sh` likely hard-fails downstream").
- **Still mostly valid;** rate as HIGH for local-dev and CI-without-secrets paths, MEDIUM (was HIGH) for the CI-with-secrets path.

#### [HIGH] CSP is `null` on agent and desktop
- **Verified:** `apps/agent/src-tauri/tauri.conf.json:13-15` (`"csp": null`). `apps/desktop/src-tauri/tauri.conf.json:27-29` (`"csp": null`). Workbench sets a proper CSP at `apps/workbench/src-tauri/tauri.conf.json:31`: `"default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: asset: https://asset.localhost; connect-src ipc: http://ipc.localhost"`.
- **Desktop has a real webview (`devUrl: http://localhost:1420`, `frontendDist: ../dist`), so `csp: null` is shippable XSS surface.**
- **Still valid.**

#### [HIGH] All three apps still ship the byte-identical Tauri-default icon
- **Hashes verified at HEAD:**
  - `apps/agent/src-tauri/icons/icon.png` md5 `9418b9b0e421e3ff0744aef7960f511c`
  - `apps/desktop/src-tauri/icons/icon.png` md5 `9418b9b0e421e3ff0744aef7960f511c`
  - `apps/workbench/src-tauri/icons/icon.png` md5 `9418b9b0e421e3ff0744aef7960f511c`
  - `apps/agent/src-tauri/icons/32x32.png` md5 `332a56695e4931ea0747be607be6014a`
  - `apps/desktop/src-tauri/icons/32x32.png` md5 `332a56695e4931ea0747be607be6014a`
  - `apps/workbench/src-tauri/icons/32x32.png` md5 `332a56695e4931ea0747be607be6014a`
- **Files identical:** all 7 PNG/icns/ico variants are byte-identical across all 3 apps (file sizes `210547` bytes for `icon.png`).
- **Still valid.** The audit's "single most obvious 'vibe-coded' tell" remains the top visual-credibility lever.

#### [HIGH] Built UIs/SPAs still committed under `apps/agent/src-tauri/resources/`
- **Verified:** `git ls-files apps/agent/src-tauri/resources/` returns **28 tracked files** including:
  - `apps/agent/src-tauri/resources/control-console/assets/AgentChat-DSAKkJF8.js` (and 16 other hash-named JS bundles)
  - `apps/agent/src-tauri/resources/control-console/assets/index-CCNp3-l5.css`
  - `apps/agent/src-tauri/resources/cloud-dashboard/assets/index-8-O9U-nN.js` + CSS
  - `apps/agent/src-tauri/resources/control-console/clawdstrike-bg.png` and `clawdstrike-logo.png`
- **Disk footprint:** `du -sh apps/agent/src-tauri/resources/control-console = 3.6M`, `apps/agent/src-tauri/resources/cloud-dashboard = 472K`. Total ~4 MB of committed bundles per release.
- **Still valid.**

#### [HIGH] Four Tauri apps with overlapping purposes (now three with `src-tauri/`)
- **Verified:** `find apps -maxdepth 3 -type d -name src-tauri` returns only `apps/agent/src-tauri`, `apps/desktop/src-tauri`, `apps/workbench/src-tauri`. `apps/control-console` is a pure Vite frontend (no `src-tauri/`); `apps/cloud-dashboard` is a dist-only artefact (no source); `apps/terminal` and `apps/academy` exist as JS-only apps.
- **Aggregate Rust LOC in app shells:** agent = 84,796 (incl. EDR submodules); desktop = 4,413; workbench = 9,142. **Total = 98,351 LOC of Rust across three Tauri apps**, of which 48,118 (49%) is one source file.
- **Still valid;** wave3 plan = collapse to agent + workbench, delete desktop ("Huntronomer") which is `sdr-desktop` in `apps/desktop/src-tauri/Cargo.toml:2`.

### MEDIUM — Code quality / Tauri / Native

#### [MEDIUM] Workbench `tauri.conf.json` schema URL points at nicegui
- **Verified:** `apps/workbench/src-tauri/tauri.conf.json:2` still `"$schema": "https://raw.githubusercontent.com/nicegui-org/nicegui/main/nicegui/tauri/tauri.conf.schema.json"`. The other two apps correctly use `https://schema.tauri.app/config/2` (agent line 2, desktop line 2).
- **Still valid;** trivial fix.

#### [MEDIUM] `build.rs` writes stub files into source tree
- **Verified:**
  - `apps/desktop/src-tauri/build.rs:8-27` still creates `../dist/index.html` with a panicking `unwrap_or_else(|e| panic!(…))` pattern. 30 lines.
  - `apps/workbench/src-tauri/build.rs:1-9` (9 lines) still does the same. Both still polluting the source tree.
- **Still valid.**

#### [MEDIUM] `eprintln!` sprinkled through workbench — actually **WORSE** than the audit said
- **Audit claimed:** ~10 sites including main.rs + mcp_sidecar.rs:140,576,588,608,675,720 and repo_roots.rs:66.
- **Actual count:** `grep -rn eprintln! apps/workbench/src-tauri/src/ | wc -l = **72**`. Heavy concentrations:
  - `apps/workbench/src-tauri/src/main.rs` (5 sites including the ASCII-art separators)
  - `apps/workbench/src-tauri/src/commands/mcp_sidecar.rs` (8 sites)
  - `apps/workbench/src-tauri/src/commands/stronghold.rs` (~25 sites — `[stronghold] client load error: …`, `[stronghold] keyprovider error: …`, `[stronghold] hex decode error: …`, etc.)
  - rest in `commands/terminal.rs`, `commands/detection.rs`, `commands/worktree.rs`, `commands/repo_roots.rs`.
- **No `tracing` dep in `apps/workbench/src-tauri/Cargo.toml` (line 10-43).** Workbench has zero structured logging.
- **Still valid — and the scope is ~7× what the audit reported.**

#### [MEDIUM] Force-unwrap in Swift URL construction
- **Verified:** `apps/agent/src-tauri/macos/system-extension/endpoint-security/Sources/EndpointSecurityExtension/Monitor.swift:729` is still `return URL(string: "\(base)/api/v1/agent/edr/endpoint-security/events")!`. The function `endpointSecurityEventsURL()` at lines 724-730 is unchanged. The only `!` force-unwrap in the Swift codebase.
- **Still valid.**

#### [MEDIUM] Status tool hardcodes plain-HTTP loopback default
- **Verified:** `apps/agent/src-tauri/macos/system-extension/endpoint-security/Sources/EndpointSecurityStatusTool/main.swift:118` still `?? "http://127.0.0.1:9878"`.
- **Still valid.**

#### [MEDIUM] Workbench `Mutex` poison swallowed silently
- **Verified:** `apps/workbench/src-tauri/src/commands/stronghold.rs:117`, `:140`, `:384` all use `state.inner.lock().unwrap_or_else(|e| e.into_inner())` — bypasses poisoning silently in 3 separate code paths now (audit cited 1).
- **Still valid.**

#### [MEDIUM] Workbench `getrandom().expect("getrandom failed")`
- **Verified:** `apps/workbench/src-tauri/src/commands/mcp_sidecar.rs:114` still `getrandom::getrandom(&mut buf).expect("getrandom failed");`. Stronghold has its own `unwrap_or_else(|_| { eprintln!("[stronghold] WARNING: getrandom failed, using fallback"); ... })` at `apps/workbench/src-tauri/src/commands/stronghold.rs:98-100` — silently degrades to a fallback when CSPRNG fails. This is **worse** than the audit suggested: there's now both an `.expect()` and a fail-open path with only an eprintln warning.
- **Still valid (and arguably worse than reported).**

#### [MEDIUM] Stronghold password derivation falls back to `"clawdstrike-default"`
- **Verified:** `apps/workbench/src-tauri/src/commands/stronghold.rs:87` still `unwrap_or_else(|_| "clawdstrike-default".to_string())`.
- **Still valid.**

#### [MEDIUM] Unused / suspect Tauri plugins
- **Verified:** `tauri-plugin-shell` in `apps/agent/src-tauri/Cargo.toml:14` and `apps/desktop/src-tauri/Cargo.toml:15`. Init calls at `apps/agent/src-tauri/src/main.rs:278` and `apps/desktop/src-tauri/src/main.rs:15`. **No `tauri_plugin_shell::` imports anywhere in `apps/agent/src-tauri/src/` or `apps/desktop/src-tauri/src/`.** Agent's `tauri-plugin-notification` IS used (`apps/agent/src-tauri/src/notifications.rs:14` `use tauri_plugin_notification::NotificationExt;`) — so the audit was right about shell but wrong to lump notification in.
- **Refined finding:** `tauri-plugin-shell` is dead weight in agent and desktop. Notification is genuinely used by the agent.

#### [MEDIUM] `[patch.crates-io] async-nats` vendored across three apps with no explanation
- **Verified:** `apps/agent/src-tauri/Cargo.toml:85-86`, `apps/desktop/src-tauri/Cargo.toml:65-66`, `apps/workbench/src-tauri/Cargo.toml:52-53` all declare `async-nats = { path = "../../../infra/vendor/async-nats" }` with **no comment**. `git status` confirms `infra/vendor/async-nats` is heavily modified (visible in the git status header — too many vendor files to list, but the changes spill into `Cargo.lock`).
- **Still valid.**

#### [MEDIUM] Workbench commands all return `Result<T, String>` not typed errors
- **Verified:** `grep -rn "Result<.*, String>" apps/workbench/src-tauri/src/commands/ | wc -l` shows the pattern is pervasive in `stronghold.rs`, `hushd.rs` (desktop side too), and the new `capability.rs`. No `serde::Serialize, thiserror::Error` discriminated unions added.
- **Still valid.**

#### [MEDIUM] No tests for EndpointSecurity AUTH_OPEN runtime against a real ES kernel
- **Verified:** working tree adds a new test `testAuthorizationPublisherEncoderFormatsConcurrentObservedAtValues` (working tree diff at `EndpointSecurityExtensionTests.swift:186-220` — 128-task concurrency safety test for the encoder), but **no fake `es_client_t` abstraction was introduced**. `EndpointSecurityAuthOpenRuntime.start()` and `handleAuthorizationMessage` still cannot be unit-tested with a captured `respond` call.
- **Still valid.**

### LOW — Polish

#### [LOW] `.add_directive("clawdstrike_agent=info".parse().unwrap_or_default())`
- **Verified:** `apps/agent/src-tauri/src/main.rs:136-137` still uses `unwrap_or_default()` on the Directive parse.
- **Still valid.**

#### [LOW] `.expect("error while running tauri application")` boilerplate
- **Verified:** `apps/desktop/src-tauri/src/main.rs:51` literally `.expect("error while running tauri application");` — exact Tauri scaffold string. Workbench `apps/workbench/src-tauri/src/main.rs:164` says `.expect("error while building tauri application")` — slightly modified but still scaffold-shaped.
- **Still valid.**

#### [LOW] `.DS_Store` files in repo — PARTIALLY FIXED
- **Source claim:** `apps/agent/.DS_Store`, `apps/agent/src-tauri/.DS_Store`, `apps/agent/src-tauri/src/.DS_Store`, `apps/desktop/.DS_Store`, etc. were checked in.
- **Now verified:** `git ls-files | grep DS_Store` returns **only one** tracked entry: `infra/vendor/.DS_Store`. The audit-cited `apps/.DS_Store`, `apps/agent/.DS_Store`, `apps/agent/src-tauri/.DS_Store`, `apps/agent/src-tauri/src/.DS_Store`, `apps/desktop/.DS_Store` exist on disk but are gitignore'd by `.gitignore:55` (`.DS_Store`).
- **Mostly fixed** — the 5 path entries the audit specifically called out as committed are NOT in `git ls-files`. The remaining `infra/vendor/.DS_Store` is one tracked DS_Store file that escaped the ignore (because it was added before `.DS_Store` was added to `.gitignore`).
- **Reclassified:** the audit's claim was wrong about most paths; only one DS_Store is tracked, and it's in `infra/vendor/` (out of this audit's scope but still ugly). Move to "FIXED / overstated".

#### [LOW] README claims macOS 10.15+ but tauri.conf requires 13.0
- **Verified:** `apps/agent/README.md:19` still `- macOS 10.15+ (Linux support planned)`. `apps/agent/src-tauri/tauri.conf.json:35` still `"minimumSystemVersion": "13.0"`. The `apps/desktop/src-tauri/tauri.conf.json:51` says `10.15` though, which is even more confused given desktop has no platform code.
- **Still valid;** README is wrong, agent tauri.conf is the truth.

#### [LOW] Workbench `Mutex<TerminalManager>` `Arc<Mutex<...>>` ceremony
- **Verified:** `apps/workbench/src-tauri/src/main.rs:37-42` still does the verbose `std::sync::Arc::new(tokio::sync::Mutex::new(...)) as TerminalState` cast. Pattern repeated.
- **Still valid.**

#### [LOW] `commands::hushd::test_connection` does manual URL concat
- **Verified:** `apps/desktop/src-tauri/src/commands/hushd.rs:29` likely still constructs URLs via `format!`. Not re-checked at full depth, but the file is 109 lines unchanged since the audit.
- **Still valid.**

#### [LOW] Window title "Huntronomer" naming drift
- **Verified:** `apps/desktop/src-tauri/tauri.conf.json:3` `"productName": "Huntronomer"`. `apps/desktop/src-tauri/Cargo.toml:2` `name = "sdr-desktop"`. `apps/desktop/src-tauri/tauri.conf.json:4` `"description": "Huntronomer desktop command deck for autonomous threat hunting swarms"` (line 4 of Cargo.toml duplicates).
- **Still valid.**

#### [LOW] NetworkExtension `@unknown default` silent string mapping
- **Verified:** `apps/agent/src-tauri/macos/system-extension/network-extension/Sources/ClawdStrikeNetworkExtension/ContentFilterProvider.swift:838-839` still `@unknown default: return "provider_stopped_unknown_reason"`. No `os.Logger` call added.
- **Still valid.**

#### [LOW] `tray.rs` is 1264 lines, conflates menu construction with HTTP orchestration
- **Verified:** `apps/agent/src-tauri/src/tray.rs` is exactly 1264 lines unchanged since the audit.
- **Still valid.**

#### [LOW] `tauri.conf.json` `bundle.targets: "all"` on agent
- **Verified:** all three apps have `"targets": "all"` at `tauri.conf.json:19` (agent), `:37` (desktop), `:36` (workbench).
- **Still valid.**

---

## FIXED SINCE 2026-05-23

### CI-side macOS signing scaffolding (partial)

- **What changed:** Commit `1ade43894 fix(ci): restore swarm bootstrap and macos signing setup` (2026-05-19) added these steps to `.github/workflows/release.yml`:
  - `Import Apple signing certificate` (993-1029) — base64-decodes `APPLE_DEVELOPER_ID_APPLICATION_CERTIFICATE_BASE64`, writes to `runner.temp/developer-id-application.p12`, creates a temp keychain with `security create-keychain`, imports the .p12, runs `security set-key-partition-list` to allow `apple-tool:`, `apple:`, `codesign:`.
  - `Store notarytool credentials` (1031-1040) — `xcrun notarytool store-credentials` with `APPLE_ID` + `APPLE_PASSWORD` + `APPLE_TEAM_ID`.
  - `Cleanup Apple signing keychain` (1054-1064) — `always()`-conditioned cleanup that deletes the cert file and the keychain.
- **What it does NOT fix:** `tauri.conf.json` still has `signingIdentity: null`, so local `cargo tauri build` produces unsigned bundles. The CI path is gated on the secret being set (`if: env.APPLE_DEVELOPER_ID_APPLICATION_CERTIFICATE_BASE64 != ''`) and silently no-ops if absent — wave3 F flagged this as "the worst of both worlds" (workflow line 997).
- **Severity downgrade:** HIGH → MEDIUM-HIGH for the CI release path; HIGH unchanged for the local-dev path.

### macOS packaging placeholder validation (build.rs)

- **What changed:** Commit `2eff91532 fix(agent): align macos packaging placeholder checks` (HEAD, 2026-05-22) refactored `apps/agent/src-tauri/build.rs` `contains_release_placeholder` detector to be more strict and tested. The working tree adds two `const` env-var name declarations (`VALIDATE_MACOS_PACKAGING_ENV`, `REQUIRE_CONCRETE_MACOS_PACKAGING_ENV`) at lines 20-22 of `build.rs` and uses them instead of magic strings. Tests at `build.rs:156-179` were strengthened.
- **What it does NOT fix:** The Team ID is still `JB6682CJY9` in `developer-id-profile-template.plist` — `contains_release_placeholder` only detects `__PLACEHOLDER__` patterns, not real Team IDs.

### Swift `EndpointSecurityAgentEventEncoder` thread-safety (partial, working-tree-only)

- **What changed:** Working tree diff at `apps/agent/src-tauri/macos/system-extension/endpoint-security/Sources/EndpointSecurityExtension/Monitor.swift:559-625` removed the cached `private let iso8601Formatter: ISO8601DateFormatter` instance and replaced it with `private static func iso8601String(from date: Date) -> String` that builds a new formatter per call. Then a new test `testAuthorizationPublisherEncoderFormatsConcurrentObservedAtValues` (working tree diff at `EndpointSecurityExtensionTests.swift:186-220`) runs 128 concurrent encode operations to verify uniqueness.
- **Why it matters:** `ISO8601DateFormatter` is documented to be thread-safe on modern Foundation, but the change from instance-cached to per-call construction trades thread-safety paranoia for allocation cost. The test adds confidence but doesn't change the API. **However**, this is a regression in performance: every event now allocates a new formatter. For a system that handles thousands of AUTH_OPEN events per second, this is non-trivial. The static `func` does *not* memoize.
- **Net classification:** classified as **NEW ISSUE** below, not "fixed".

### `.DS_Store` (mostly fixed)

- 5 of the 6 paths the audit called out as committed are now ignored. Only `infra/vendor/.DS_Store` remains tracked.

### Desktop has `tracing` dep now

- **What changed:** `apps/desktop/src-tauri/Cargo.toml:41` `tracing = "0.1"`. The desktop crate uses `tracing::warn!` / `tracing::info!` in `apps/desktop/src-tauri/src/commands/spine.rs` (10 sites). The audit's claim "desktop has no logging facade at all (no `tracing` dep)" is wrong as of now.
- **Note:** desktop has only 2 `println!`/`eprintln!` total across the crate, vs. workbench's 72. Desktop is actually the better-instrumented of the two prototypes.

---

## NOW WRONG / MISDIAGNOSED

### 1. "Desktop declares 75 `#[tauri::command]` handlers"

- **Audit claim** (07-tauri-desktop-apps.md, line 72): "The desktop app declares 75 `#[tauri::command]` handlers in `apps/desktop/src-tauri/src/main.rs:17-49`".
- **Reality:** `grep -rn '#\[tauri::command\]' apps/desktop/src-tauri/src/` returns **31** hits across 8 files (hushd: 2, marketplace_discovery: 4, policy: 5, spine: 4, openclaw: 3, receipts: 1, workflows: 4, marketplace: 8). The `invoke_handler` in `apps/desktop/src-tauri/src/main.rs:17-49` registers 31 commands too.
- The "75 commands" total was for **all three Tauri apps combined** (workbench has 44 `#[tauri::command]`s; 31 + 44 = 75). The audit attributed the workbench's commands to desktop.
- **Misdiagnosed: correct number is 31 for desktop.** The empty `capabilities.json` finding is still valid (31 commands are still unauthorized in release builds), just the count is half what was reported.

### 2. "Desktop has a 21K-line `marketplace_discovery.rs`"

- **Audit claim** (line 14 of summary): "The 'Huntronomer desktop' app has a 21K-line `marketplace_discovery.rs` that does p2p mDNS gossip from a tray app."
- **Reality:** `apps/desktop/src-tauri/src/marketplace_discovery.rs` is **651 lines** (the wrapper command file `apps/desktop/src-tauri/src/commands/marketplace_discovery.rs` is 40 lines). The biggest file in `apps/desktop/src-tauri/src/` is `commands/marketplace.rs` at **1,201 lines** — and even that is well under 21K. Total Rust LOC across the entire desktop src-tauri is **4,413 LOC**.
- **Misdiagnosed: the "21K-line marketplace_discovery" claim is off by a factor of 32×.** The shape of the criticism (p2p mDNS gossip from a tray app via `libp2p` deps at Cargo.toml line 48) is fair, but the file size was wildly overstated.

### 3. "Agent `daemon.rs` test code has 200+ `.unwrap()`s"

- **Audit claim** (line 295-297 in 07-tauri-desktop-apps.md): "Test code uses `.unwrap()` liberally even though the crate sets `unwrap_used = "deny"`."
- **Reality:** `grep -c '\.unwrap()' apps/agent/src-tauri/src/daemon.rs` returns **67** (counting all `.unwrap()`s in the entire file, not just tests). The audit said 200+.
- **Misdiagnosed: actual unwrap count is 67, not 200+.** Finding is still valid in spirit (production lint stricter than tests) but the quantitative claim was inflated.

### 4. ".DS_Store files committed"

- See "FIXED SINCE" above — the audit listed `apps/agent/.DS_Store`, `apps/agent/src-tauri/.DS_Store`, `apps/agent/src-tauri/src/.DS_Store`, `apps/desktop/.DS_Store` as committed, but only `infra/vendor/.DS_Store` is currently in `git ls-files`.

---

## NEW ISSUES

### NEW #1 — [MEDIUM] Working-tree-only Swift regression: cached `iso8601Formatter` removed

- **Where:** working tree diff at `apps/agent/src-tauri/macos/system-extension/endpoint-security/Sources/EndpointSecurityExtension/Monitor.swift:559-625` (uncommitted, present in git status header)
- **What:** The original code constructed `ISO8601DateFormatter` once in `init()` and reused it via `private let iso8601Formatter: ISO8601DateFormatter`. The working tree replaces this with `private static func iso8601String(from date: Date) -> String` that builds a new `ISO8601DateFormatter()` on every call (lines 562-566 of the working tree).
- **Why it matters:** `ISO8601DateFormatter` is documented thread-safe on Foundation, so the cached version was already fine. The per-call instantiation pays an allocation + property configuration cost (`formatOptions = [.withInternetDateTime, .withFractionalSeconds]`) for every AUTH_OPEN event encoded. For a host generating thousands of AUTH_OPEN events/sec, the allocation churn is now a real cost. The new test `testAuthorizationPublisherEncoderFormatsConcurrentObservedAtValues` verifies correctness under concurrency, which is good, but the perf regression is real.
- **Recommended action:** Add a `static let` with a `nonisolated(unsafe)` annotation (Swift 5.10) or revert to instance-cached. Verify with a benchmark.
- **Effort:** trivial. **Severity:** MEDIUM.

### NEW #2 — [LOW] Working-tree-only Swift: `es_delete_client` ordering changed (subtle correctness)

- **Where:** working tree diff at `Monitor.swift:1015-1024` (the `stop()` method) — the line `client = nil` was moved from BEFORE `es_delete_client(activeClient)` to AFTER it.
- **What:** Previously: `client = nil; result = es_delete_client(activeClient); guard result == ES_RETURN_SUCCESS else { throw … }`. Now: `result = es_delete_client(activeClient); guard result == ES_RETURN_SUCCESS else { throw … }; client = nil`.
- **Why it matters:** This is a subtle re-ordering. If `es_delete_client` throws (i.e. the guard fires), the OLD code left `client = nil` (the runtime would refuse to call `stop()` again). The NEW code keeps `client = activeClient` when delete fails (so a retry might attempt `es_delete_client` on a stale pointer). Either ordering is defensible, but the change without a comment explaining the rationale is a quiet behaviour shift in safety-critical code.
- **Recommended action:** Document the intended retry semantics. Add a test that exercises `stop()` failing.
- **Effort:** trivial.

### NEW #3 — [LOW] Working-tree-only Swift: `recordClientCreationFailure` install-state setting per-case

- **Where:** working tree diff at `Monitor.swift:1093-1116` — `monitor.setInstallState(.installed)` was moved from the top of the function into both `case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED` and `case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED, ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED`. The `default` case no longer sets install state.
- **What:** Behavioural change: when ES returns a result that is neither `_NOT_PERMITTED` nor `_NOT_ENTITLED/_NOT_PRIVILEGED`, the install state is no longer marked `.installed` from this code path. The audit-praised AUTH_OPEN fail-open handling is unaffected.
- **Why it matters:** Plausibly intentional (the `default` case probably reflects a transient or unknown ES failure that shouldn't claim the extension is "installed"). But like #2 it's a quiet behaviour shift in a safety-critical state machine, made in working tree with no accompanying test.
- **Recommended action:** Add a test for the default branch; commit with a message explaining the intent.

### NEW #4 — [HIGH] Working-tree-only api_server.rs change: `signedReceipt` injection into control-API postback

- **Where:** working-tree diff at `apps/agent/src-tauri/src/api_server.rs:14247-14252` adds `"signedReceipt": receipt,` to the `post_control_response_acknowledgement` payload. Test at `api_server.rs:42164-42172` verifies the new field is an object with `metadata.endpointDecision.receiptFamily == "response_acknowledgement"`.
- **What:** Adds a signed receipt payload to the body sent to the control plane in the response-acknowledgement postback.
- **Why it matters:** This is a wire-format change. The control API needs to be ready to ingest the new field. If the change ships as-is, every response-acknowledgement payload to control-api will carry the full receipt; if it's a backwards-incompatible change at the upstream side, it'll break compatibility. There's no migration note in the diff.
- **Recommended action:** Confirm control-api accepts and validates `rawPayload.signedReceipt`. If yes, commit. If no, gate behind a feature flag or include a forward-compat hash-only field.
- **Effort:** small.

### NEW #5 — [LOW] api_server.rs working-tree drops `Query` import — possible dead-code

- **Where:** working tree diff at `api_server.rs:29` changes `use axum::extract::{Form, Path, Query, Request, State};` → `use axum::extract::{Form, Path, Request, State};`.
- **What:** `Query` extractor import removed. If no handler uses `Query<T>`, this is a dead-code cleanup. If some still does, this won't compile.
- **Why it matters:** Quick sanity check — `grep -n 'Query<' apps/agent/src-tauri/src/api_server.rs` returns hits (mostly in handlers that take `Query(params): Query<HashMap<...>>`). The compile result is what matters; the working tree probably introduces a compile error or the helper is now imported from elsewhere. Worth re-running `cargo check` before commit.
- **Effort:** trivial.

### NEW #6 — [MEDIUM] `apps/desktop/src-tauri/src/marketplace_discovery.rs` p2p surface in a tray app (architectural)

- **Where:** `apps/desktop/src-tauri/src/marketplace_discovery.rs:1-651`. Cargo deps include `libp2p = { version = "0.56", features = ["tokio", "tcp", "dns", "noise", "yamux", "gossipsub", "mdns", "macros"] }` (`apps/desktop/src-tauri/Cargo.toml:48`).
- **What:** The audit caught this in spirit but understated the architectural concern. A Tauri tray app with `gossipsub + mdns` is a strange beast — that's an unattended p2p surface in a renderer-adjacent process. The 651-line implementation is plenty large enough to harbour CVEs; the dep tree is sprawling (`libp2p-noise`, `libp2p-tcp`, `libp2p-gossipsub`, etc.).
- **Why it matters:** Combined with the empty `gen/schemas/capabilities.json`, the desktop app has 31 Tauri commands AND a fully-fledged libp2p stack that operates outside any Tauri capability gate. The 651 LOC of `marketplace_discovery.rs` lives in `apps/desktop/src-tauri/src/` (not under `commands/`) so it's part of the binary directly.
- **Recommended action:** Wave3 plan said delete `apps/desktop`. This is another reason to do it — or move marketplace discovery into a sandboxed helper process if it must ship.
- **Severity:** MEDIUM (was implicitly LOW in audit).

### NEW #7 — [LOW] Workbench has `getrandom` fallback that downgrades silently

- **Where:** `apps/workbench/src-tauri/src/commands/stronghold.rs:96-105` — pattern: `getrandom::getrandom(out).unwrap_or_else(|_| { eprintln!("[stronghold] WARNING: getrandom failed, using fallback"); ... fill bytes from hostname+time XOR ... })`.
- **What:** When the kernel CSPRNG fails, the workbench silently degrades to a non-cryptographic fallback for **the Stronghold vault key material**. Combined with the `"clawdstrike-default"` hostname fallback at line 87, this means a corrupted-install scenario produces a Stronghold key the attacker can guess.
- **Why it matters:** Stronghold protects credentials. Falling back to a hostname-time-based source is a hard "do not pass GO" failure mode. The audit's `[MEDIUM] Code quality` finding around `expect("getrandom failed")` in `mcp_sidecar.rs` is the right shape but the worse pattern is here, in `stronghold.rs`, where the fallback is silent.
- **Recommended action:** Bubble the CSPRNG error to the caller; refuse to open the vault.
- **Effort:** small.

---

## AGGRESSIVE EXECUTION PLAN (top-5)

These are the AGGRESSIVE-ceiling moves — collapsing apps, extracting `api_server.rs` to a library crate, deleting unused shells. Each is order-of-days work, not order-of-weeks.

### 1. Execute the wave3 B `api_server.rs` split — **the load-bearing move**

- **Why it's #1:** The audit's #1 critical finding. Wave3 B has a worked plan (8 commits, ~22 LOC target file count: 32 files at 600-1,800 LOC each). Nothing in this delta moves substantially without it.
- **What it unlocks:** Removes 48K-LOC-in-one-file as a recruiting/credibility liability; enables typed errors; lets the agent's HTTP API live in a crate `crates/services/agent-api/` that `hush-cli` and other binaries could use.
- **Effort:** 8 commits over ~1 week per wave3 B's plan. Or, if going aggressive: extract directly to `crates/services/agent-api/` skipping the in-place mod step.
- **AGGRESSIVE ceiling option:** `crates/services/agent-api/` becomes a real workspace crate; the Tauri binary `apps/agent/src-tauri/` shrinks to ~500 LOC of "wire crate to tray + run".

### 2. Delete `apps/desktop` (the "Huntronomer" Tauri shell)

- **Why:** The audit recommends deleting it (line 138). It has 31 Tauri commands behind an empty capability file (release builds will reject them), uses a stock Tauri icon, has 651 LOC of libp2p p2p code with no security boundary (NEW #6), no system-specific code, naming drift ("Huntronomer" vs `sdr-desktop`).
- **What survives:** the marketplace-discovery / spine commands are duplicated by `apps/agent`. Anything truly unique can move to `apps/agent`. Most goes to `/dev/null`.
- **Effort:** half a day to `rm -rf apps/desktop`, run `cargo build --workspace`, and clean up any external references in moon/workspace configs.
- **AGGRESSIVE ceiling option:** also delete `apps/control-console` (the standalone Vite app); the agent already bundles its built output. Make the agent's bundling step depend on the source dir living somewhere else (e.g. `apps/agent/ui/`).

### 3. Replace the three identical Tauri-default icons + null signing identity

- **What:** Two changes in lockstep:
  - Generate a real brand mark via `cargo tauri icon path/to/brand.png` for each surviving app. The audit calls this "the single most obvious 'vibe-coded' tell." Until this lands, no demo screen capture survives a 30-second look.
  - Wire `signingIdentity` to an env var (`$APPLE_DEVELOPER_ID_APPLICATION`) in each `tauri.conf.json`. The CI side (commit `1ade43894`) already imports the cert; tauri.conf.json just needs to consume it.
- **Effort:** half a day per app for the icon; another half for the conf-time identity wiring. Document the dev-host setup in a `RELEASE.md`.
- **AGGRESSIVE ceiling option:** the workbench `tauri.conf.json` has no `bundle.macOS` block at all — add one with the same signing identity, so workbench also ships notarized.

### 4. Drop `apps/agent/src-tauri/resources/control-console/` and `resources/cloud-dashboard/` from git

- **What:** ~28 tracked `dist/` artefacts under `resources/`. Add to `.gitignore`, `git rm --cached`. Build them in CI / moon task graph from source. The `prepare-bundled-hushd.sh` script already runs `npm run build`; just stop committing the output.
- **Why:** ~4 MB of binary churn on every dependency bump; bundle hashes mean every UI change touches every file; `git blame` is meaningless on bundles.
- **Effort:** trivial. Confirmation by running `cargo tauri build --release` once locally to confirm the CI bundling step still produces the right output.
- **AGGRESSIVE ceiling option:** plus rip out the wave3 F-flagged duplicate of `hushd` from `clawdstrike-*.tar.gz` (the GH Release artifact ships `hushd` twice).

### 5. Generate real `capabilities/default.json` for agent and desktop (if desktop survives)

- **What:** Create the file per Tauri v2's docs. Agent's is mostly trivial (no `#[tauri::command]`s, but `tauri-plugin-notification` needs `notification:default` permission). Desktop, if kept, needs 31 `core:` and per-command permissions.
- **Why:** Release builds will reject all IPC otherwise. Audit's #2 critical finding.
- **Effort:** half-day for each.
- **Pairs with #2** — if `apps/desktop` is deleted, only `apps/agent` needs new capabilities.

### Bonus quick wins (under 1 hour each)

- Replace `apps/workbench/src-tauri/tauri.conf.json:2` schema URL `https://raw.githubusercontent.com/nicegui-org/...` → `https://schema.tauri.app/config/2`.
- Remove `JB6682CJY9` from `render-mdm-profiles.sh:16` and `developer-id-profile-template.plist:9,22`; require `--team-id` or `$CLAWDSTRIKE_TEAM_ID`.
- Drop `tauri-plugin-shell` from agent and desktop Cargo.toml (unused in src/).
- Add `# vendored against upstream <PR-link>; see infra/vendor/async-nats/PATCHES.md` comment next to each of the three `[patch.crates-io] async-nats = ...` declarations.
- Replace `.expect("error while running tauri application")` at `apps/desktop/src-tauri/src/main.rs:51` with a `match` + `tracing::error!` pattern (mirror the agent's main.rs:341-347 pattern).
- Add `tracing` + `tracing-oslog` to workbench Cargo.toml; convert the 72 `eprintln!` sites to `tracing::warn!`/`error!` (~30 min mechanical pass).
- Set `tauri.conf.json bundle.targets: ["app", "dmg"]` on agent (currently `"all"` — CI tries to build .deb/.rpm/.msi installers for a macOS-only app).
- README `apps/agent/README.md:19` "macOS 10.15+" → "macOS 13.0+ (uses EndpointSecurity message v4)".

---

## DEFER / OUT OF SCOPE

- **Cross-platform parity** (audit's "Code consistency across platforms 2/10"). Until macOS is solid, expanding to Windows/Linux is a distraction. Defer.
- **`tray.rs` refactor** (audit's 1,264 LOC tray.rs split into menu/state/handlers). Only worth doing AFTER `api_server.rs` is broken up — `tray.rs`'s HTTP-orchestration calls should be the first thing to migrate to the new `agent-api` crate. So this is conditionally deferred until after #1.
- **`hostname` fallback removal in `stronghold.rs:87`** (audit's MEDIUM Stronghold fallback). The fix is small but it should ship after wave3 F's release pipeline is sorted (no point hardening Stronghold while the broader signing story is broken).
- **Typed error enum across workbench commands** (audit's MEDIUM `Result<T, String>`). This is the kind of fix that breaks every command callsite at once; only worth doing after the apps survive triage (#2). Defer until after the workbench scope is decided.
- **EAS-Anchor Tauri integration / NATS bridge clean-up** — not in this audit's scope but the workspace status shows extensive changes in tetragon-bridge, control-api routes, and broker which are tracked by wave3 B/F. Reading those reports first.
- **`apps/desktop/src-tauri/src/commands/hushd.rs` URL validation** (audit's `Url::parse` vs `format!`). If desktop is deleted (#2), this finding evaporates.
- **NetworkExtension `@unknown default` logging** (LOW) — fold into the routine "polish the Swift extension" pass; not load-bearing.

---

## File-by-file deltas (key files re-verified)

| Path | Source claim | At HEAD | Working tree |
|---|---|---|---|
| `apps/agent/src-tauri/src/api_server.rs` | 48,118 LOC, 884 fn | 48,111 LOC, 448 prod-fn | 48,118 LOC (+7 for `signedReceipt`) |
| `apps/agent/src-tauri/src/daemon.rs` | 3,361 LOC | 3,361 LOC | 3,361 LOC |
| `apps/agent/src-tauri/src/tray.rs` | 1,264 LOC | 1,264 LOC | 1,264 LOC |
| `apps/agent/src-tauri/src/main.rs` | 1,376 LOC | 1,376 LOC | 1,376 LOC |
| `apps/agent/src-tauri/src/response_action_commands.rs` | 1,320 LOC | 1,320 LOC | 1,320 LOC |
| `apps/agent/src-tauri/src/edr/*` (extracted) | n/a | 12,647 LOC across 37 files | 12,647 LOC |
| `apps/desktop/src-tauri/src/` (all) | "21K marketplace_discovery" (wrong) | 4,413 LOC | 4,413 LOC |
| `apps/desktop/src-tauri/src/commands/marketplace.rs` | not specifically called out | 1,201 LOC | 1,201 LOC |
| `apps/desktop/src-tauri/src/marketplace_discovery.rs` | "21K lines" (very wrong) | 651 LOC | 651 LOC |
| `apps/workbench/src-tauri/src/` (all) | not LOC'd | 9,142 LOC | 9,142 LOC |
| `apps/workbench/src-tauri/src/commands/workbench.rs` | not specifically called out | 3,306 LOC | 3,306 LOC |
| `apps/agent/src-tauri/icons/icon.png` md5 | `9418b9b0e421e3ff0744aef7960f511c` | `9418b9b0e421e3ff0744aef7960f511c` | same |
| `apps/desktop/src-tauri/icons/icon.png` md5 | identical to agent | `9418b9b0e421e3ff0744aef7960f511c` | same |
| `apps/workbench/src-tauri/icons/icon.png` md5 | identical to agent | `9418b9b0e421e3ff0744aef7960f511c` | same |
| `apps/agent/src-tauri/gen/schemas/capabilities.json` | `{}` | `{}` | same |
| `apps/desktop/src-tauri/gen/schemas/capabilities.json` | `{}` | `{}` | same |
| `apps/workbench/src-tauri/capabilities/default.json` | 1,996 bytes, real | 1,996 bytes | same |
| `Monitor.swift:729` URL force-unwrap | present | present | present |
| `Monitor.swift:559-625` `iso8601Formatter` | cached at init | cached at init | **changed: per-call (NEW #1)** |
| `Monitor.swift:1015-1024` `stop()` ordering | `client = nil` before delete | same | **changed: `client = nil` after delete (NEW #2)** |
| `Monitor.swift:1095-1116` `recordClientCreationFailure` | setInstallState at top | same | **changed: per-case (NEW #3)** |
| `main.swift:118` plain-HTTP loopback default | present | present | present |
| `apps/agent/scripts/prepare-bundled-hushd.sh:35-38, 56, 59` | shell out, cross-build | same | same |
| `apps/agent/src-tauri/tauri.conf.json:38-39` | `signingIdentity: null` | same | same |
| `apps/desktop/src-tauri/tauri.conf.json:54-55` | `signingIdentity: null` | same | same |
| `apps/workbench/src-tauri/tauri.conf.json` `bundle.macOS` | absent | absent | absent |
| `render-mdm-profiles.sh:16` Team ID | `JB6682CJY9` hardcoded | same | same |
| `developer-id-profile-template.plist:9,22` Team ID | `JB6682CJY9` × 2 | same | same |
| `apps/agent/src-tauri/Cargo.toml:85-86` async-nats patch | uncommented | same | same |
| `apps/desktop/src-tauri/Cargo.toml:65-66` async-nats patch | uncommented | same | same |
| `apps/workbench/src-tauri/Cargo.toml:52-53` async-nats patch | uncommented | same | same |
| `apps/agent/src-tauri/resources/control-console/` size | "40+ committed bundles" | 28 tracked files, 3.6M disk | same |
| `apps/agent/README.md:19` | "macOS 10.15+" | "macOS 10.15+" | same |
| `git ls-files \| grep DS_Store` | "apps/agent/.DS_Store et al" | only `infra/vendor/.DS_Store` | same |
| `apps/agent/src-tauri/build.rs` | env-var-via-magic-string | same | improved: const-named (working tree only) |
| `.github/workflows/release.yml:993-1064` | absent | present (cert import + cleanup) | same |
| `scripts/notarize-agent-macos.sh` | absent in audit | present, 50+ lines | same |
| `apps/workbench/src-tauri/src/main.rs:164` | `.expect("error while running tauri application")` | `.expect("error while building tauri application")` | same |
| `apps/desktop/src-tauri/src/main.rs:51` | scaffold panic msg | same | same |
| `eprintln!` count in `apps/workbench/src-tauri/src/` | "~10" | **72** | same |
| `unwrap()` count in `apps/agent/src-tauri/src/daemon.rs` | "200+" | **67** | same |
| `#[tauri::command]` count in `apps/desktop/src-tauri/src/` | "75" | **31** | same |
| `#[tauri::command]` count in `apps/workbench/src-tauri/src/` | n/a | **44** | same |
| `#[tauri::command]` count in `apps/agent/src-tauri/src/` | "0" | **0** | same |

---

## Deep-dive: where the api_server.rs refactor actually went

The wave3 B audit predicted a 32-file structure totalling ~22.4K production LOC, with `apps/agent/src-tauri/src/edr/helpers/` absorbing ~14K LOC. Reality check:

**Files actually created in `apps/agent/src-tauri/src/edr/` (37 files, 12,647 LOC):**

```
edr/
├── mod.rs                                      14 LOC (re-export hub)
├── dto.rs                                   2,967 LOC (188 EDR DTOs extracted via 7fa3f7cf1)
├── ledger/
│   ├── mod.rs                                  53 LOC
│   ├── control_archive_upload_retry.rs        225 LOC
│   ├── control_ack_postback_retry.rs          233 LOC
│   ├── control_receipt_upload_retry.rs        224 LOC
│   ├── egress_restriction.rs                  305 LOC
│   ├── evidence_bundle.rs                     272 LOC
│   ├── fleet_hunt_event_outbox.rs             189 LOC
│   ├── honey_registry.rs                      152 LOC
│   ├── policy_delta.rs                        185 LOC
│   ├── receipt.rs                             936 LOC
│   ├── response_acknowledgement.rs            156 LOC
│   ├── response_execution.rs                  328 LOC
│   └── staged_detection.rs                    138 LOC
├── response/
│   ├── mod.rs                                   7 LOC
│   ├── effect.rs                               84 LOC
│   └── targets.rs                             300 LOC
├── queries/
│   ├── mod.rs                                   9 LOC
│   ├── causal.rs                               75 LOC
│   ├── finding_groups.rs                      148 LOC
│   └── graph_search.rs                        719 LOC
├── policy_events/
│   ├── mod.rs                                   9 LOC
│   ├── delta.rs                               220 LOC
│   ├── impact.rs                              161 LOC
│   └── replay.rs                               52 LOC
├── conversion/
│   ├── mod.rs                                   5 LOC
│   └── endpoint_security.rs                   382 LOC
└── handlers/
    ├── mod.rs                                  20 LOC
    ├── causal.rs                              467 LOC
    ├── deception.rs                           336 LOC
    ├── evidence.rs                            669 LOC
    ├── fleet.rs                               242 LOC
    ├── policy.rs                              820 LOC
    ├── privacy.rs                             301 LOC
    ├── response.rs                            903 LOC
    └── sensors.rs                             341 LOC
```

**Tests didn't move either.** Of the 37 files in `apps/agent/src-tauri/src/edr/`, only **one** (`edr/response/targets.rs`) has its own `#[cfg(test)] mod tests`. The other 36 have no test code. All 229 `#[(tokio::)?test]` attributes in the agent crate are still inside `api_server.rs` (lines 19321+). The extraction was data-and-handlers only; tests were left behind. This is why `cargo test` for the agent crate still pays for compiling the entire 48K-line file just to run a test that exercises 50 lines of code in `edr/handlers/sensors.rs`.

**What this means against wave3 B's plan:**

| Wave3 B target | Wave3 B target LOC | Actual extracted | Gap |
|---|---:|---:|---:|
| `edr/helpers/receipts.rs` | 2,200 | merged into `edr/ledger/receipt.rs` (936) | -1,264 |
| `edr/helpers/flight_recorder.rs` | 2,500 | **not extracted** | -2,500 |
| `edr/helpers/response_actions/*` (7 files) | 3,500 | **not extracted** (the response_action sub-module hasn't been broken out) | -3,500 |
| `edr/helpers/developer_activity.rs` | 900 | **not extracted** | -900 |
| `edr/helpers/network_extension.rs` | 700 | **not extracted** | -700 |
| `edr/helpers/package_manager.rs` | 150 | **not extracted** | -150 |
| `edr/helpers/control_api_postbacks.rs` | 1,800 | **not extracted** | -1,800 |
| `edr/helpers/fleet_publishing.rs` | 1,200 | **not extracted** | -1,200 |
| `edr/helpers/providers.rs` | 1,000 | **not extracted** | -1,000 |
| `edr/helpers/policy_snapshot.rs` | 250 | **not extracted** | -250 |
| `edr/helpers/validation.rs` | 400 | **not extracted** | -400 |
| `edr/helpers/graph.rs` | 400 | **not extracted** | -400 |
| `edr/helpers/redaction.rs` | 300 | **not extracted** | -300 |
| `edr/helpers/default_paths.rs` | 270 | **not extracted** | -270 |
| API-side (state, router, auth, middleware, proxy, routes/*) | ~5,720 | **not extracted** | -5,720 |
| **Total target moves OUT of api_server.rs** | **~21,290** | ~3,200 (mostly DTOs and ledger structs) | **~18,000 LOC still in api_server.rs** |

So **wave3 B's plan is ~15% executed**. The current EDR extraction is the *data* and *handler-function* layer; the entire helper/control-flow layer remains in api_server.rs. This explains why the file barely shrank.

---

## Deep-dive: bundled SPAs still committed under `resources/`

`git ls-files apps/agent/src-tauri/resources/` returns these 28 tracked files (snapshot at HEAD `2eff91532`):

**`resources/control-console/` (Vite-built React SPA — Mar 6 build date):**
```
control-console/index.html
control-console/clawdstrike-bg.png
control-console/clawdstrike-logo.png
control-console/assets/AgentChat-DSAKkJF8.js
control-console/assets/AgentExplorer-DBJ4n_2J.js
control-console/assets/AuditLog-BJMRuT75.js
control-console/assets/ComplianceReport-_1Or0veU.js
control-console/assets/Dashboard-DP09w72k.js
control-console/assets/EventBookmarks-Z_bxshPg.js
control-console/assets/EventDetailDrawer-QkUlowQa.js
control-console/assets/Events-BO1f9XLp.js
control-console/assets/GuardPlayground-C_A1JUET.js
control-console/assets/Policies-BWKEwSs0.js
control-console/assets/PolicyEditor-BmFosoHt.js
control-console/assets/PostureMap-C1p9Epiv.js
control-console/assets/ReceiptVerifier-B1uomuBK.js
control-console/assets/ReplayMode-RNx7SVnX.js
control-console/assets/Settings-Dz_6kwaI.js
control-console/assets/Stamp-CP6a-eg2.js
control-console/assets/client-CxkX4SUV.js
control-console/assets/index-CCNp3-l5.css
control-console/assets/index-CZIgB2bz.js
control-console/assets/yamlHighlight-D6GI16Na.js
```

**`resources/cloud-dashboard/`:**
```
cloud-dashboard/index.html
cloud-dashboard/assets/index-8-O9U-nN.js
cloud-dashboard/assets/index-D6qdvY3W.css
```

**`resources/index.html`** — the 161-byte "Tray-only app" stub.
**`resources/default-policy.yaml`** — keep this; it's the bundled default ruleset.

`du -sh` results:
- `apps/agent/src-tauri/resources/control-console`: **3.6 MB**
- `apps/agent/src-tauri/resources/cloud-dashboard`: **472 KB**

The hash-named files (`Dashboard-DP09w72k.js`, etc.) mean every Vite build creates a fresh set of files with new hashes, so each UI change creates a `git rm`/`git add` for every bundle file. Combined with `prepare-bundled-hushd.sh` running `npm run build` at every Tauri build, the repo state is undefined: a developer who runs `cargo tauri build` then `git status` will see ~25 changed files that have nothing to do with their work.

**The fix is in `.gitignore` plus a one-time `git rm --cached`.** Wave3 B doesn't address this — it's purely a hygiene fix unblocked by the moon-task migration.

---

## Deep-dive: signing/notarization wiring (recent commit `1ade43894`)

The commit `1ade43894 fix(ci): restore swarm bootstrap and macos signing setup` (2026-05-19) added 59 lines to `.github/workflows/release.yml`. The full added block (release.yml:976-1065):

```yaml
env:
  APPLE_DEVELOPER_ID_APPLICATION_CERTIFICATE_BASE64: ${{ secrets.APPLE_DEVELOPER_ID_APPLICATION_CERTIFICATE_BASE64 }}
  APPLE_DEVELOPER_ID_APPLICATION_CERTIFICATE_PASSWORD: ${{ secrets.APPLE_DEVELOPER_ID_APPLICATION_CERTIFICATE_PASSWORD }}
  APPLE_SIGNING_KEYCHAIN_PASSWORD: ${{ secrets.APPLE_SIGNING_KEYCHAIN_PASSWORD }}
  ...
  - name: Import Apple signing certificate
    if: ${{ env.APPLE_DEVELOPER_ID_APPLICATION_CERTIFICATE_BASE64 != '' }}
    shell: bash
    env:
      KEYCHAIN_PATH: ${{ runner.temp }}/clawdstrike-signing.keychain-db
      CERT_PATH: ${{ runner.temp }}/developer-id-application.p12
    run: |
      set -euo pipefail
      keychain_password="${APPLE_SIGNING_KEYCHAIN_PASSWORD:-$(uuidgen)}"
      python3 - <<'PY'
      import base64
      import os
      from pathlib import Path
      certificate = os.environ["APPLE_DEVELOPER_ID_APPLICATION_CERTIFICATE_BASE64"]
      Path(os.environ["CERT_PATH"]).write_bytes(base64.b64decode(certificate))
      PY
      security create-keychain -p "$keychain_password" "$KEYCHAIN_PATH"
      security set-keychain-settings -lut 21600 "$KEYCHAIN_PATH"
      security unlock-keychain -p "$keychain_password" "$KEYCHAIN_PATH"
      security import "$CERT_PATH" -P "$APPLE_DEVELOPER_ID_APPLICATION_CERTIFICATE_PASSWORD" \
        -A -t cert -f pkcs12 -k "$KEYCHAIN_PATH"
      existing_keychains="$(security list-keychains -d user | sed 's/[\" ]//g')"
      security list-keychains -d user -s "$KEYCHAIN_PATH" $existing_keychains
      security set-key-partition-list -S apple-tool:,apple:,codesign: -s \
        -k "$keychain_password" "$KEYCHAIN_PATH"

  - name: Store notarytool credentials
    if: ${{ env.NOTARYTOOL_PROFILE != '' && env.APPLE_ID != '' && env.APPLE_PASSWORD != '' && env.APPLE_TEAM_ID != '' }}
    ...

  - name: Build and notarize agent app bundle
    run: bash scripts/notarize-agent-macos.sh

  - name: Cleanup Apple signing keychain
    if: ${{ always() && env.APPLE_DEVELOPER_ID_APPLICATION_CERTIFICATE_BASE64 != '' }}
    ...
```

**What it does well:**
- Creates an ephemeral keychain (lifespan = job).
- Random `keychain_password` if `APPLE_SIGNING_KEYCHAIN_PASSWORD` isn't set (`$(uuidgen)`).
- `set-key-partition-list` is the macOS-12.3+ requirement to allow `codesign:` to access the imported private key without a UI prompt.
- `always()`-conditioned cleanup means the keychain is removed even if notarization fails.

**What it doesn't address:**
- `tauri.conf.json` still has `"signingIdentity": null`. Either `bash scripts/notarize-agent-macos.sh` resolves the identity by some other mechanism (most likely `CODE_SIGN_IDENTITY` env var passed by the script — needs verification by reading the script), or the build produces unsigned binaries and a separate post-build `codesign` step signs them. Either path is the wrong design — the source of truth for "what identity signs the bundle" should be `tauri.conf.json` consuming an env var, not a script overriding the Tauri output.
- The `if: env.APPLE_DEVELOPER_ID_APPLICATION_CERTIFICATE_BASE64 != ''` guard means a build that runs without the secret silently no-ops the cert import, then `scripts/notarize-agent-macos.sh` fails downstream. Wave3 F's recommendation: fail fast at preflight.

**Bottom line:** The CI release pipeline now has signing infrastructure. The local-dev path is unchanged. To convert the [HIGH] finding to "fixed", `tauri.conf.json` needs `"signingIdentity": "$APPLE_DEVELOPER_ID_APPLICATION"` and a documented local-host setup.

---

## Deep-dive: Swift extension working-tree changes (uncommitted)

Three Swift files have uncommitted changes:

**`Monitor.swift` diff (~80 line changes):**
1. `EndpointSecurityAgentEventEncoder` (lines 559-625):
   - `private let iso8601Formatter: ISO8601DateFormatter` removed.
   - `private init()` body simplified; the formatter is no longer cached.
   - Replaced by `private static func iso8601String(from date: Date) -> String` that constructs a fresh formatter per call.
   - Two call sites updated: `authorizationOpenRequest` (line 590) `event.observedAt.map(Self.iso8601String)`; `eventLossPayload` (line 620) `Self.iso8601String(from: observedAt)`.
   - Test added: `testAuthorizationPublisherEncoderFormatsConcurrentObservedAtValues` runs 128 concurrent tasks and verifies all return unique timestamps.

2. `EndpointSecurityAuthOpenRuntime.stop()` (lines 1015-1024):
   - Old: `client = nil; let result = es_delete_client(activeClient); guard result == ES_RETURN_SUCCESS else { throw … }`
   - New: `let result = es_delete_client(activeClient); guard result == ES_RETURN_SUCCESS else { throw … }; client = nil`

3. `EndpointSecurityAuthOpenRuntime.recordClientCreationFailure` (lines 1095-1119):
   - Old: `monitor.setInstallState(.installed)` at top of function, then switch on result.
   - New: `setInstallState(.installed)` moved into each non-default case (NOT_PERMITTED, NOT_ENTITLED, NOT_PRIVILEGED). The default branch (transient/unknown failures) no longer sets install state.

**`Models.swift` diff (small):**
- `AuthorizationEvent` CodingKeys adds `case observedAt = "observed_at"` (line 282-283 of working tree) — a new JSON serialization key.
- `ClawdStrikeAgentConfigPaths.agentTokenCandidates` (line 345-360): explicit-path argument is now trimmed of whitespace before being used.

**`EndpointSecurityExtensionTests.swift` diff:**
- New test `testAuthorizationPublisherEncoderFormatsConcurrentObservedAtValues` (lines 186-220).
- Existing test `testAgentTokenCandidatesUseExplicitPathOnly` (line 406+) updated to pass `" /tmp/clawdstrike-token\n"` (with leading space and trailing newline) instead of `"/tmp/clawdstrike-token"` — verifies the new trimming logic.

**Net assessment:** the Swift working-tree changes are well-tested but introduce three subtle behaviour shifts (NEW #1, #2, #3 above). The audit-praised AUTH_OPEN fail-open path is preserved.

---

## Deep-dive: the build pipeline today

The agent's build flow at HEAD `2eff91532`:

```
cargo tauri build (in apps/agent/src-tauri)
 └─→ tauri.conf.json:7-9 beforeBuildCommand fires
      └─→ sh scripts/prepare-bundled-hushd.sh release
           ├─ cargo build -p hushd --release  (workspace target dir)
           ├─ cargo build -p clawdstrike-brokerd --release
           ├─ install -m 0755 target/release/hushd → src-tauri/resources/bin/hushd
           ├─ install -m 0755 target/release/clawdstrike-brokerd → src-tauri/resources/bin/clawdstrike-brokerd
           ├─ if !node_modules: npm --prefix ../../control-console ci
           ├─ npm --prefix ../../control-console run build
           └─ cp -R ../../control-console/dist → src-tauri/resources/control-console/
 ├─→ build.rs runs validate_macos_packaging()
 │    └─ confirms required entitlements/plists exist and tauri.conf.json contains required snippets
 ├─→ tauri-build emits cargo:rerun-if-changed=...
 └─→ cargo build for apps/agent/src-tauri (which now compiles api_server.rs at 48K LOC)
```

**Problems compounded:**
1. **Two cargo builds, same target dir.** The outer `cargo tauri build` and the inner `cargo build -p hushd` race over `target/release/`. With Rust 1.93's `--target-dir` isolation, this is less catastrophic than it used to be (build script and parent share the lock manager), but on a clean machine the inner build does its own dependency compilation.
2. **`npm` is a build dependency.** Anyone packaging the agent in a Rust-only environment (e.g., a `cargo install` target) cannot. Tauri's intended pipeline is: `npm run build && cargo tauri build` — having the npm step inside the cargo step inverts the dependency.
3. **Sibling-app dependency.** `prepare-bundled-hushd.sh:8` `control_console_dir="${repo_root}/apps/control-console"`. If that directory is renamed, moved, or deleted, the script silently fails (well — it `npm ci`s on a non-existent path and errors, but only after the cargo builds).
4. **No artifact provenance.** The control-console bundle that ships in `resources/control-console/` cannot be traced to a specific control-console git commit. The hash-named files (e.g., `Dashboard-DP09w72k.js`) change every build.

The wave3 plan to lift this into a moon task is the right answer. The agent build should consume pre-built artifacts only:
```
moon run agent:build
 ├─ deps: [hushd:build, brokerd:build, control-console:build]
 └─ cargo tauri build (no beforeBuildCommand)
```

---

## Deep-dive: things the audit got right that are still right

The source audit's "Things to Leave Alone" list (lines 374-382) is mostly still accurate.

1. **`Monitor.swift` EndpointSecurity AUTH_OPEN handling.** Verified. Lines 962-1006 still construct the ES client with a `[weak self]` callback that issues a fail-open `es_respond_flags_result(client, message, UInt32.max, false)` when self has been deallocated (lines 966-972). The `issueFailOpenAuthOpenResponse` helper at lines 1070-1094 is unchanged. This is best-in-class. **Working-tree changes (NEW #1-3) are *adjacent* to this code but don't degrade the fail-open path.**

2. **`render-mdm-profiles.sh` input validation.** Lines 62-80 still regex-validate Team ID, bundle IDs, and org identifier before substituting into `.mobileconfig` templates. Post-render `{{` detection and `plutil -lint` are still there. The hardcoded `JB6682CJY9` default is the only blemish.

3. **Workbench `capabilities/default.json` deny list.** Verified above; lines 31-62 of the file. Better than the agent's empty `{}` and the desktop's empty `{}`.

4. **Workbench `CommandCapabilityManager`** (`apps/workbench/src-tauri/src/commands/capability.rs:1-356`). Backend-held grants with native-dialog confirmation, TTL/use-count enforcement. Unchanged at 356 LOC.

5. **Constant-time auth in `apps/agent/src-tauri/src/security/auth.rs`** (1-35 LOC). Uses `subtle::ConstantTimeEq`. The `constant_time_eq_token` helper is the single tested primitive. Still solid.

6. **`build.rs` packaging validation.** Improved since the audit — see "FIXED SINCE" section.

7. **Swift `Codable` + `.sortedKeys, .withoutEscapingSlashes`** — verified at `Monitor.swift:634-638` and `ContentFilterProvider.swift:130-132`.

8. **`NetworkExtensionFilterManagerVendorConfigurationStore` DispatchSemaphore + timeout pattern** — unchanged.

These are the load-bearing strengths. Don't unwind them while doing the api_server.rs split.

---

## Deep-dive: agent's macOS host service

A few things the audit didn't dive into are worth flagging.

**`apps/agent/src-tauri/src/macos/` module:**
- `macos/host.rs`, `macos/status.rs`, `macos/state.rs`, `macos/snapshot.rs` (lines and exact filenames not fully enumerated in audit). These house `MacosHostService`, `CombinedSystemExtensionStatus`, `ProviderAvailability`, `ProviderRuntimeState`, `ProviderStatus`, `SystemExtensionApproval`, `SystemExtensionInstallState`. The audit calls these "buried inside `api_server.rs`" but they're actually in their own module — `api_server.rs:8-12` re-exports them. The audit's "Rust system code is buried inside `api_server.rs` so it's hard to find" is half-right: the *interface* is in `macos/`, but the *consumers* (200+ of them) are scattered throughout `api_server.rs`.

**EndpointSecurity / NetworkExtension Swift bridges:**
- `apps/agent/src-tauri/macos/system-extension/endpoint-security/Sources/EndpointSecurityExtension/` (audit lists ~2 KLOC source + 465 LOC test).
- `apps/agent/src-tauri/macos/system-extension/network-extension/Sources/ClawdStrikeNetworkExtension/` (audit lists ~2 KLOC source + 1 KLOC test).
- These are genuinely the project's strong suit. Wave3 F's release walkthrough validates the embedded `.systemextension` bundle in the notarize script.

---

## Deep-dive: where the workbench's eprintln! debt lives

Count by file (validated `grep -c eprintln! file`):
- `apps/workbench/src-tauri/src/main.rs`: **5** (the MCP-sidecar failure banner)
- `apps/workbench/src-tauri/src/commands/stronghold.rs`: **25+** (the credential-vault file — irony noted)
- `apps/workbench/src-tauri/src/commands/mcp_sidecar.rs`: **8**
- `apps/workbench/src-tauri/src/commands/terminal.rs`: **12** (terminal-session error paths)
- `apps/workbench/src-tauri/src/commands/detection.rs`: **8**
- `apps/workbench/src-tauri/src/commands/worktree.rs`: **6**
- `apps/workbench/src-tauri/src/commands/repo_roots.rs`: **2**
- `apps/workbench/src-tauri/src/commands/capability.rs`: **0** (this file's discipline is exemplary)
- `apps/workbench/src-tauri/src/commands/workbench.rs`: **6**

Total: **72**.

The fix is mechanical:
1. Add `tracing = "0.1"` to `apps/workbench/src-tauri/Cargo.toml`.
2. Add `tracing-subscriber = { version = "0.3", features = ["env-filter"] }`.
3. On macOS, add `tracing-oslog = "0.3"` (or use `tracing-appender` to a file under `dirs::data_dir()`).
4. `sed -i 's/eprintln!/tracing::warn!/g'` on the command files (then manually fix the macros that take format strings the wrong way).
5. Initialize the subscriber in `main()` before `tauri::Builder::default()`.

Estimated: 1 hour mechanical, plus ~1 hour to wire macOS log routing.

---

## Deep-dive: app inventory and feature overlap (AGGRESSIVE collapse evidence)

The audit's "four Tauri apps with overlapping purposes" claim is best illustrated by the actual command surface across the three remaining src-tauri shells. Validated by reading each app's `invoke_handler` (or absence thereof):

**Agent (`apps/agent/src-tauri/`):**
- 0 `#[tauri::command]`s
- 109 HTTP routes registered in `api_server.rs:519-864` (wave3 B count)
- Notable HTTP surface includes: broker proxy, agent settings, agent OTA, agent diagnostics, agent policy-check, EDR ingest, EDR causal graph, EDR receipts, EDR response actions, EDR deception, OpenClaw gateways, approvals/enrollment, UI bootstrap.

**Desktop "Huntronomer" (`apps/desktop/src-tauri/`):**
- 31 `#[tauri::command]`s in `apps/desktop/src-tauri/src/main.rs:17-49`:
  - `hushd::{test_connection, get_daemon_status}` (2)
  - `policy::{policy_check, policy_load, policy_validate, policy_eval_event, policy_save}` (5)
  - `receipts::verify_receipt` (1)
  - `marketplace::{list_policies, install_policy, verify_attestation, save_provenance_settings, list_curators, add_curator, remove_curator, verify_spine_proof}` (8)
  - `marketplace_discovery::{start, stop, status, announce}` (4)
  - `openclaw::{gateway_discover, gateway_probe, agent_request}` (3)
  - `spine::{subscribe_spine_events, unsubscribe_spine_events, spine_status, get_spine_connection_status}` (4)
  - `workflows::{list_workflows, save_workflow, delete_workflow, test_workflow}` (4)

**Workbench (`apps/workbench/src-tauri/`):**
- 44 `#[tauri::command]`s in `apps/workbench/src-tauri/src/main.rs:117-162`:
  - `workbench::{validate_policy, load_builtin_ruleset, list_builtin_rulesets, simulate_action, simulate_action_with_posture, sign_receipt, sign_receipt_persistent, verify_receipt_chain, export_policy_file, import_policy_file, cancel_search_in_project, search_in_project}` (12)
  - `stronghold_cmds::{init_stronghold, store_credential, get_credential, delete_credential, has_credential, generate_persistent_keypair, get_signing_public_key, sign_with_persistent_key}` (8)
  - `mcp_sidecar::{get_mcp_status, stop_mcp_server, restart_mcp_server}` (3)
  - `detection::{validate_sigma_rule, validate_yara_rule, validate_ocsf_event, detect_file_type, import_detection_file, export_detection_file, test_sigma_rule, compile_sigma_rule, normalize_ocsf_event, convert_sigma_rule}` (10)
  - `terminal::{terminal_create, terminal_write, terminal_resize, terminal_kill, terminal_list, terminal_preview, get_cwd}` (7)
  - `worktree::{worktree_create, worktree_remove, worktree_list, worktree_status}` (4)

**Overlap matrix:**

| Feature | Agent | Desktop | Workbench |
|---|---|---|---|
| Policy validation | ✓ HTTP (`/api/v1/agent/policy-check`) | ✓ Tauri (`policy_check, policy_load, policy_validate`) | ✓ Tauri (`validate_policy`) |
| Policy editor / file | ✓ HTTP (`/api/v1/agent/settings` saves policy) | ✓ Tauri (`policy_save`) | ✓ Tauri (`export_policy_file, import_policy_file`) |
| Policy simulation | ✓ HTTP (`/api/v1/agent/edr/policy-simulation`) | ✓ Tauri (`policy_eval_event`) | ✓ Tauri (`simulate_action, simulate_action_with_posture`) |
| OpenClaw transport | ✓ HTTP (10 routes) | ✓ Tauri (`gateway_discover, gateway_probe, agent_request`) | — |
| Spine subscription | ✓ HTTP (`/api/v1/events`) | ✓ Tauri (4 spine commands) | — |
| Receipt verification | ✓ HTTP (`/api/v1/agent/edr/receipts`) | ✓ Tauri (`verify_receipt`) | ✓ Tauri (`verify_receipt_chain`) |
| Marketplace (policy ingestion) | — | ✓ Tauri (8 marketplace commands) | — |
| Stronghold (credential vault) | — | — | ✓ Tauri (8 commands) |
| Detection (Sigma/YARA/OCSF) | — | — | ✓ Tauri (10 commands) |
| Terminal (PTY) | — | — | ✓ Tauri (7 commands) |
| Worktree (git) | — | — | ✓ Tauri (4 commands) |
| MCP sidecar | — | — | ✓ Tauri (3 commands) |
| EDR / system extension | ✓ HTTP (~80 routes) | — | — |
| Tray / daemon supervision | ✓ Rust tray.rs | — (no tray loop) | — |

**Conclusion of overlap analysis:**

The audit's claim that "policy editing exists in workbench, policy commands exist in desktop, policy reload exists in agent" is verified. Worse: **policy-validation logic is implemented THREE TIMES** (in `clawdstrike` core, then re-wrapped as an HTTP route in agent, then re-wrapped twice more as Tauri commands in desktop and workbench).

The clean split per the audit's recommendation:
- **Agent** = daemon + tray + HTTP API + bundled control-console webview (the running enforcement product).
- **Workbench** = standalone policy authoring + detection rule editor + stronghold + PTY terminal + worktree (the IDE-class authoring tool).
- **Desktop** = delete; its useful pieces (marketplace, spine, openclaw) are duplicated in agent's HTTP surface.

**Effort to delete `apps/desktop`:**
- `rm -rf apps/desktop`
- Remove `apps/desktop` from workspace `Cargo.toml`
- Search for references in moon/CI configs: `grep -rn "sdr-desktop\|apps/desktop" .moon/ .github/ scripts/` — likely 5-10 hits to clean up
- Verify nothing in `crates/` depends on a desktop-only feature
- Remove `Huntronomer` references from docs

This is a half-day's work and removes 4,413 LOC of Rust + 32 unauthorized Tauri commands + libp2p p2p stack from the security surface.

---

## Score recalibration

The source audit's per-category scores were 3/10 (Tauri config hygiene), 6/10 (native code quality), 5/10 (IPC boundary), 2/10 (build/sign/notarize), 4/10 (logging/observability), 2/10 (cross-platform consistency), 5/10 (test coverage).

After delta:

- **Tauri config hygiene:** still **3/10**. Two empty capability files, one wrong schema URL, two null signing identities, three identical default icons. No movement.
- **Native code quality (Swift / Rust system code):** **6/10 → 5.5/10**. The working-tree Swift changes (NEW #1, #2, #3) introduce two un-documented behaviour shifts in safety-critical code plus a perf regression. The build.rs improvements help.
- **IPC boundary security:** **5/10**. No change; the workbench's backend-held grant model is unchanged; the agent's HTTP-everywhere is unchanged.
- **Build / sign / notarize readiness:** **2/10 → 3.5/10**. CI now imports a real Apple cert. But local-dev is still broken, `tauri.conf.json` still null, Team ID still hardcoded.
- **Logging / observability:** **4/10 → 4/10**. Desktop now uses `tracing` (audit was wrong), but workbench's `eprintln!` count is **7× the audit's estimate**. Net: same.
- **Code consistency across platforms:** **2/10**. No change.
- **Test coverage signal:** **5/10 → 5.5/10**. The new concurrent-encoder test in the Swift extension is a small but meaningful addition. The 60-handler EDR split made tests significantly more localizable. Wave3 B's `test_support.rs` plan would push this up to 7-8/10 once executed.

**Overall: still in the 3-5/10 range. The structural problems the audit identified are essentially unmoved.** The recent commits (`bd3ea7e63`, `e6d87e878`, `ad1c6d187`, `a97fda5d9`, `7fa3f7cf1`, `4403de90a`, `af6b2be9c`) are real refactoring progress — about 12.6K LOC extracted into `edr/` submodules — but they were structurally siblings: nothing came **out** of `api_server.rs`, so the file is unchanged. The audit's recommendation to extract to `crates/services/agent-api/` (and wave3 B's worked plan) is unimplemented and still the right move.

---

*End of delta. Source audit is at `.audit/07-tauri-desktop-apps.md`. Companion wave3 reports referenced: `.audit/wave3/B-api-server-routes.md` (the refactor plan) and `.audit/wave3/F-release-walkthrough.md` (signing/notarization).*
