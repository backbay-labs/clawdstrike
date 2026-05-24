# Tauri / Desktop / Agent Apps Audit

**Scope:** `apps/agent/`, `apps/desktop/`, `apps/workbench/src-tauri/`, `apps/control-console/src-tauri/`
**Audited by:** Claude Code (Opus 4.7, 1M context)
**Date:** 2026-05-23
**Branch:** `fix/macos-es-ne-hardening`

---

## Executive Summary

No, a senior desktop/systems engineer would not respect this code. They would respect *parts* of it — the macOS system-extension Swift code (Models, Monitor, ContentFilterProvider) is genuinely thoughtful, the EndpointSecurity authorization-deadline / fail-open path is handled correctly, the workbench has a real backend-held capability grant model, and the agent uses constant-time token comparison. There is a senior engineer in here somewhere, mostly in the Swift layer and the workbench command surface. The professional moves (entitlements limited to exactly what is needed, MDM profile renderer with input validation, Tauri capability allowlist that explicitly denies `~/.ssh`, `~/.aws`, `~/.kube`, etc.) are real and worth keeping.

But the rest is a structural disaster that screams "we shipped four half-built Tauri scaffolds and never converged." There are **four** Tauri apps (`agent`, `desktop`, `workbench`, and a still-present `control-console` shell). The agent is a 64K-LOC headless Tauri binary with **zero `#[tauri::command]`s** that exposes its entire interface (884 functions) through a 48,118-line `api_server.rs` — a single source file larger than most production codebases. The desktop app has a 1,200-line marketplace command, no capabilities directory (the generated `capabilities.json` is literally `{}`), and ships with the **default Tauri "T" icon** — identical MD5 to the agent and workbench icons. The "Huntronomer desktop" app has a 21K-line `marketplace_discovery.rs` that does p2p mDNS gossip from a tray app. All three Cargo manifests `[patch.crates-io] async-nats = { path = "../../../infra/vendor/async-nats" }` — a vendored network-protocol patch with no comment explaining why.

The build pipeline is fragile in ways that a principal engineer would refuse to ship. `apps/agent/scripts/prepare-bundled-hushd.sh` is invoked as `beforeDevCommand` / `beforeBuildCommand` and `cargo build`s two separate workspace crates, then `npm ci`s and Vite-builds a *different* app (`apps/control-console`), then `cp -R`s the result into the agent's resources. The agent then bundles two whole prebuilt SPAs (`resources/cloud-dashboard/` and `resources/control-console/`) as committed binary assets — these `dist/` directories are checked in. The macOS Team ID `JB6682CJY9` is hardcoded in `developer-id-profile-template.plist` and `render-mdm-profiles.sh`. The Tauri code signing identity is `null` in every `tauri.conf.json`. There is no notarization step wired in, despite the agent installing a system extension that requires Developer ID + notarization to load.

What needs to happen: collapse to **two** apps maximum (one Tauri end-user product, one ops console), delete the desktop and control-console Tauri shells unless they have a distinct shipping plan, fix the agent so the local-API surface lives in a `crates/services/agent-api` library and the Tauri binary is a thin tray wrapper, split `api_server.rs` and `daemon.rs` by feature, generate real Tauri capabilities files (the empty `gen/schemas/capabilities.json: {}` will not survive a Tauri v2 release build), wire signing + notarization, replace the duplicate Tauri-default icon set with a real brand mark, and either delete the bundled SPAs from the agent or stop checking them into git. Until those land, this looks like a startup that learned Tauri from the template and never refactored.

---

## App inventory

| App | Platforms | Purpose (claimed) | Maturity |
|---|---|---|---|
| `apps/agent` | macOS 13+ (only platform with actual system code), Windows/Linux compile but no platform code | Tray app + local HTTP API + macOS combined system extension (EndpointSecurity + NetworkExtension content filter) | **Heavy** — 64K LOC Rust + 5.1K LOC Swift. Substantial but unstructured. |
| `apps/desktop` ("Huntronomer") | macOS 10.15+, Windows, Linux (no platform code) | "Desktop command deck for autonomous threat hunting swarms" — marketplace, spine, workflows, openclaw | **Prototype-quality** — 3.4K LOC Rust, no capability file (Tauri v2 will reject IPC at runtime), default icon, zero platform-specific code. |
| `apps/workbench/src-tauri` ("ClawdStrike Policy Workbench") | macOS, Windows, Linux | Policy editor with PTY terminal, stronghold-backed credential vault, MCP sidecar, detection rule editor | **Most coherent** — 7.3K LOC Rust, real capability file with deny rules for ssh/aws/kube keys, backend-held authorization grants for sensitive commands. |
| `apps/control-console` | n/a — **no `src-tauri/` directory** | Was apparently planned as Tauri shell; only the Vite frontend remains | **Stale** — out of scope for this audit but the agent bundles its built `dist/` as a resource. |
| `apps/agent/.../endpoint-security/` Swift package | macOS 13+ | EndpointSecurity AUTH_OPEN monitor, status tool, agent event publisher | **Surprisingly solid** — 2K LOC Swift, 465 lines of XCTest, fail-open path correct. |
| `apps/agent/.../network-extension/` Swift package | macOS 13+ | NEFilterDataProvider content filter, vendor-config policy reload IPC, status tool | **Solid** — 2K LOC Swift, 1K lines of tests, NEFilterFlow handling looks idiomatic. |

---

## Scores (1-10)

- **Tauri config hygiene:** `3/10` — desktop/agent have empty capability files; CSP is `null` on agent and desktop; signing identity null; icons are Tauri default duplicates.
- **Native code quality (Swift / Rust system code):** `6/10` — Swift is genuinely good; Rust system code is buried inside `api_server.rs` and `daemon.rs` so it's hard to find. One `URL(string:)!` force-unwrap in Swift, no `try!` / force casts elsewhere.
- **IPC boundary security:** `5/10` — workbench has a real capability-grant model and proper allow/deny lists. Agent has **no IPC boundary at all** — it exposes everything via 127.0.0.1 HTTP with constant-time bearer auth. Desktop has 75 commands behind an empty capabilities file.
- **Build / sign / notarize readiness:** `2/10` — no `signingIdentity`, no notarization, hardcoded Team ID in source, `dist/` committed, `beforeBuildCommand` shells out to a script that cross-builds two workspace crates and an unrelated SPA.
- **Logging / observability:** `4/10` — agent uses `tracing` correctly; workbench scatters `eprintln!("[workbench]…")` and `eprintln!("[mcp-sidecar]…")` at 8+ sites; desktop has no logging facade at all (no `tracing` dep).
- **Code consistency across platforms:** `2/10` — only macOS has any platform-specific code. `apps/desktop/Cargo.toml` declares `[target.'cfg(target_os = "macos")']` then leaves it empty with a comment "macOS-specific dependencies if needed". README claims macOS 10.15+ but tauri.conf says 13.0 and the system extension uses ES_NEW_CLIENT (10.15+) plus message v4 fields (13+).
- **Test coverage signal:** `5/10` — Swift extension is well-tested (1.5K lines test for 3K lines source). Agent Rust has tests inline in `api_server.rs` (the file *is* 60% tests by line count), which is reasonable in spirit but unworkable in a 48K-line file. Desktop's `commands/*.rs` have inline tests. Workbench `detection.rs` has solid coverage. No e2e tests for any Tauri surface.

---

## Strengths

1. **EndpointSecurity AUTH_OPEN handling is correct.** `Monitor.swift:962-1006` creates the ES client, subscribes only to `ES_EVENT_TYPE_AUTH_OPEN`, and the `[weak self]` callback issues a fail-open `es_respond_flags_result(client, message, UInt32.max, false)` if the runtime was deallocated before the deadline (`Monitor.swift:1070-1093`). This is the kind of detail most projects get wrong.
2. **Workbench backend-held capability grants.** `apps/workbench/src-tauri/src/commands/capability.rs:1-356` issues short-lived, use-counted grants per-scope (`TerminalRead`, `WorktreeWrite`, etc.) gated by a native `tauri-plugin-dialog` confirmation. The renderer never holds reusable auth material.
3. **Workbench `capabilities/default.json` denylist is real.** Lines 31-62 explicitly deny `$HOME/.ssh`, `.gnupg`, `.aws`, `.kube`, `.docker`, `Library/Keychains`, `.netrc`, `.git-credentials`, `.npmrc`, `.pypirc`. This is the right shape.
4. **Constant-time token comparison.** `apps/agent/src-tauri/src/security/auth.rs:1-12` uses `subtle::ConstantTimeEq`. Clippy lints set `unwrap_used = "deny"` and `expect_used = "deny"` on the agent crate (Cargo.toml:88-90).
5. **MDM profile renderer validates input.** `render-mdm-profiles.sh:62-80` regex-validates Team ID, bundle ID, and org identifier before substituting into `.mobileconfig` templates, then re-checks for unresolved `{{` tokens and runs `plutil -lint`.
6. **Swift extension models are properly Codable + Equatable + Sendable** and use `.sortedKeys` + `.withoutEscapingSlashes` for canonical JSON output (`Monitor.swift:634-638`, `ContentFilterProvider.swift:130-132`).
7. **Build-script packaging validation.** `apps/agent/src-tauri/build.rs:1-179` enforces that required entitlements, plists, and profiles exist when building for `apple-darwin`, with an opt-in `CLAWDSTRIKE_REQUIRE_CONCRETE_MACOS_PACKAGING` env var to reject `__PLACEHOLDER__` strings and the `scaffold_only` marker at release time.

---

## Findings

### [CRITICAL] [Structure] api_server.rs is 48,118 lines

- **Where:** `apps/agent/src-tauri/src/api_server.rs:1-48118`
- **What:** Single Rust source file containing 884 function definitions, ~19,000 lines of production code and ~29,000 lines of inline test code. `daemon.rs` is similarly bloated at 3,361 lines. Together with `tray.rs` (1,264), `response_action_commands.rs` (1,320), `main.rs` (1,376), the agent crate has ~64K LOC across a flat module layout.
- **Why it matters:** No principal engineer ships a 48K-line source file. It defeats `rust-analyzer`, makes blame/PR review impossible, prevents reasoning about compilation units, and signals that no one is enforcing architectural boundaries. `cargo build` for this crate will be brutal. Tests inside the same file mean you cannot run them in isolation without compiling the entire production code.
- **Recommended action:** **RESTRUCTURE.** Extract the agent's HTTP API into `crates/services/agent-api/` as a library crate with one module per route group (`broker`, `edr`, `policy`, `posture`, `openclaw`, `approval`, `session`, `ui_bootstrap`, etc.). The Tauri binary becomes a thin shell that imports the library and wires routes. Move tests next to the modules they test.
- **Effort:** large

### [CRITICAL] [Tauri] Desktop and Agent ship with empty generated capability files

- **Where:** `apps/desktop/src-tauri/gen/schemas/capabilities.json` (contents: `{}`), `apps/agent/src-tauri/gen/schemas/capabilities.json` (contents: `{}`). Neither app has a `capabilities/` source directory; only `apps/workbench/src-tauri/capabilities/default.json` exists.
- **What:** Tauri v2 requires every IPC command and every plugin permission to be granted via a capability file. The desktop app declares 75 `#[tauri::command]` handlers in `apps/desktop/src-tauri/src/main.rs:17-49` but has no capability authorizing them. The agent has zero `#[tauri::command]`s but still registers `tauri-plugin-shell` and `tauri-plugin-notification` plugins.
- **Why it matters:** Either (a) these apps are broken in release builds and survive only because dev mode is permissive, or (b) someone is bypassing capability checks. Either way it's not shippable. The desktop app cannot invoke `policy_check`, `marketplace_install_policy`, `spine_status`, `subscribe_spine_events`, etc. without a capability file granting them.
- **Recommended action:** **REWRITE.** Create `apps/desktop/src-tauri/capabilities/default.json` enumerating each command and each plugin permission needed. Same for agent (likely a trivial file because there are zero commands — but plugins still need permissions). Remove any plugins the apps don't actually use.
- **Effort:** small

### [CRITICAL] [Architecture] Agent has zero Tauri commands; exposes 884 functions over local HTTP

- **Where:** `apps/agent/src-tauri/src/main.rs:277-339` registers plugins and state but no `invoke_handler`. All 884 functions in `api_server.rs` are axum HTTP routes bound to `127.0.0.1:9878`.
- **What:** The Tauri runtime is being used purely as a tray-icon + lifecycle wrapper. The actual product is an axum HTTP server. The "frontend" is `resources/index.html`: 11 lines of static HTML reading "Tray-only app - no UI window". Bundled UIs (`resources/control-console/`, `resources/cloud-dashboard/`) are served by the embedded axum server, not by Tauri.
- **Why it matters:** This is a fundamentally confused product. If the UI runs in a browser pointed at `127.0.0.1:9878/ui`, you don't need Tauri — you need a system tray library (e.g., `tao` + `tray-icon` directly). Using Tauri here adds a webview runtime that's never opened, a CSP that's `null` because no UI loads, a build pipeline gated on Vite, and a packaging story that includes irrelevant `frontendDist`. The agent should either commit to Tauri (open a real webview against the bundled UI) or drop Tauri entirely and become a daemon with a tray-icon crate.
- **Recommended action:** **REWRITE.** Decide: (a) become a Tauri app with a real webview window showing the bundled control-console, OR (b) drop Tauri, become `clawdstrike-agentd` (a normal Rust daemon) with `tray-icon` + `tao` for the menu bar. The current hybrid is the worst of both worlds.
- **Effort:** large

### [HIGH] [Build] beforeBuildCommand shells out to cross-build workspace crates + a different app's frontend

- **Where:** `apps/agent/src-tauri/tauri.conf.json:7-9`, `apps/agent/scripts/prepare-bundled-hushd.sh:1-67`
- **What:** `beforeBuildCommand` is `sh scripts/prepare-bundled-hushd.sh release`. The script `cargo build --release`s `hushd` and `clawdstrike-brokerd` (separate workspace crates), `install -m 0755`s them into `src-tauri/resources/bin/`, then `npm --prefix ../../control-console ci`s and `npm run build`s a *different application's* Vite frontend, then `cp -R`s the output into `src-tauri/resources/control-console/`.
- **Why it matters:** A `cargo tauri build` should not invoke a second cargo build inside itself (and the second build runs in the workspace root, so it competes with the outer build for the target directory). It should not require `npm` to be installed. It should not modify a sibling application's `node_modules`. If `apps/control-console` is removed or moved, the agent build silently breaks. This is the kind of build script that fails in CI three months from now and nobody knows why.
- **Recommended action:** **RESTRUCTURE.** Move the bundling logic into a top-level `xtask` or moon task that runs *before* `cargo tauri build` and produces the binaries + UI artifacts as inputs. The Tauri build itself should only consume pre-built artifacts. Add a CI job that fails if `prepare-bundled-hushd.sh` is invoked from a non-orchestration context.
- **Effort:** medium

### [HIGH] [Packaging] Hardcoded macOS Team ID in source

- **Where:** `apps/agent/src-tauri/macos/system-extension/profiles/render-mdm-profiles.sh:16`, `apps/agent/src-tauri/macos/system-extension/profiles/developer-id-profile-template.plist:9,22`
- **What:** `TEAM_ID="JB6682CJY9"` and `<string>JB6682CJY9</string>` are checked into the public repo.
- **Why it matters:** Apple Team IDs are not secrets in the cryptographic sense, but they identify the signing organization and tie the project to a specific Apple Developer account. For an open-source project, this should be a build input (env var, CI secret, or `--team-id` argument with no default), not a checked-in constant. Other organizations consuming this repo cannot rebuild without overriding this.
- **Recommended action:** **REWRITE.** Remove the default from `render-mdm-profiles.sh` (require `--team-id`). Make the profile template a `.plist.in` with `{{TEAM_ID}}` placeholders (matching the other templates) and render it at build time. Add a `CLAWDSTRIKE_TEAM_ID` env var consumed by both `render-mdm-profiles.sh` and `build.rs`.
- **Effort:** small

### [HIGH] [Signing] Tauri config has null signing identity, no notarization

- **Where:** `apps/agent/src-tauri/tauri.conf.json:38-39`, `apps/desktop/src-tauri/tauri.conf.json:54-55`
- **What:** Both `"signingIdentity": null` and `"providerShortName": null` in `bundle.macOS`. No `notarize` configuration. Workbench's `tauri.conf.json` does not even declare a `bundle.macOS` section.
- **Why it matters:** The agent installs a system extension that **will not load** on macOS without Developer ID signature + notarization. Shipping unsigned/un-notarized binaries on macOS 15+ requires the user to right-click → Open every time and is blocked in many MDM configs. For a "security enforcement runtime for AI agents," this is table-stakes.
- **Recommended action:** **REWRITE.** Wire signing identity from env vars, add a `tauri-build` step or CI job that runs `xcrun notarytool submit` with the Apple ID stored in keychain. Document the signer host setup. Add a `release-checklist.md` next to the agent README.
- **Effort:** medium

### [HIGH] [Tauri] CSP is null on agent and desktop

- **Where:** `apps/agent/src-tauri/tauri.conf.json:13-15` (`"csp": null`), `apps/desktop/src-tauri/tauri.conf.json:27-29` (`"csp": null`)
- **What:** Tauri's CSP injection is disabled. Only the workbench sets a proper CSP (`apps/workbench/src-tauri/tauri.conf.json:31`).
- **Why it matters:** For the agent it's technically moot because no webview opens. But for the desktop "Huntronomer" app — which has a real `devUrl: http://localhost:1420` and a `frontendDist: ../dist` — `csp: null` means any compromised JS dependency can `fetch()` arbitrary external endpoints and exfiltrate.
- **Recommended action:** **REWRITE.** Set the workbench-style CSP on desktop. For agent, delete the field entirely since no UI exists (or set to `default-src 'none'`).
- **Effort:** trivial

### [HIGH] [Polish] All three Tauri apps ship with the default Tauri "T" icon

- **Where:** `apps/agent/src-tauri/icons/icon.png`, `apps/desktop/src-tauri/icons/icon.png`, `apps/workbench/src-tauri/icons/icon.png` all MD5 `9418b9b0e421e3ff0744aef7960f511c`
- **What:** Three "different" products share byte-identical 512×512 PNG icons, which is the stock Tauri scaffold icon.
- **Why it matters:** This is the single most obvious "vibe-coded" tell. Anyone evaluating the project for the first 30 seconds sees three apps named "Clawdstrike Agent", "Huntronomer", "ClawdStrike Workbench" with the Tauri logo. It signals nobody has shipped this.
- **Recommended action:** **REWRITE.** Produce one real brand mark per shipping product. Run `cargo tauri icon path/to/icon.png` for each app to regenerate the size variants + .icns + .ico.
- **Effort:** trivial

### [HIGH] [Repo hygiene] Built UIs and SPAs checked into git

- **Where:** `apps/agent/src-tauri/resources/control-console/assets/*.js` (all hash-named bundle files), `apps/agent/src-tauri/resources/cloud-dashboard/assets/index-8-O9U-nN.js`, `apps/desktop/dist/sdr-require-shim.js`
- **What:** `git ls-files` shows ~40+ pre-built Vite bundles committed under `apps/agent/src-tauri/resources/control-console/`. These are the output of `npm run build` for an entirely different app.
- **Why it matters:** Git blame is destroyed; every UI change creates a noisy commit. Bundle hashes mean every dependency bump rewrites these files. Repo size balloons. The bundles can drift from the source they were built from with no way to tell.
- **Recommended action:** **WIPE.** Add `apps/agent/src-tauri/resources/control-console/` and `apps/agent/src-tauri/resources/cloud-dashboard/` to `.gitignore`. Move the build into CI or the moon task graph so the agent bundle is built from source.
- **Effort:** small

### [HIGH] [Architecture] Four Tauri apps with overlapping purposes

- **Where:** `apps/agent`, `apps/desktop`, `apps/workbench`, `apps/control-console` (no src-tauri), plus `apps/cloud-dashboard`, `apps/terminal`, `apps/academy`
- **What:** It is unclear which app is the product. The agent claims to be the tray-only "Clawdstrike Agent". The desktop app is "Huntronomer" — a separate brand. The workbench is the "Policy Workbench". The control-console is a frontend that gets bundled into the agent. There is significant feature overlap: policy editing exists in workbench, policy commands exist in desktop, policy reload exists in agent.
- **Why it matters:** A serious project ships one app, maybe two. This looks like every passing idea got its own Tauri scaffold. Maintenance cost is 3-4×, builds are slower, security surface is bigger, and there's no clear answer to "what do I install?"
- **Recommended action:** **WIPE + RESTRUCTURE.** Pick: (1) `agent` = daemon + tray + bundled control-console webview, (2) `workbench` = standalone policy authoring tool. Delete `apps/desktop` ("Huntronomer") unless it has a distinct shipping plan — its 5K LOC of marketplace/spine/workflow commands likely duplicates code in `apps/agent`.
- **Effort:** large

### [MEDIUM] [Tauri] tauri.conf schema URL points to nicegui (workbench)

- **Where:** `apps/workbench/src-tauri/tauri.conf.json:2`
- **What:** `"$schema": "https://raw.githubusercontent.com/nicegui-org/nicegui/main/nicegui/tauri/tauri.conf.schema.json"`
- **Why it matters:** Wrong schema. The other apps use `https://schema.tauri.app/config/2` correctly. This will give wrong autocomplete and may pass an invalid config.
- **Recommended action:** **REWRITE.** Replace with `https://schema.tauri.app/config/2`.
- **Effort:** trivial

### [MEDIUM] [Build] Workbench / Desktop build.rs writes stub files into source tree

- **Where:** `apps/desktop/src-tauri/build.rs:1-30`, `apps/workbench/src-tauri/build.rs:1-9`
- **What:** Both `build.rs` files `std::fs::write` a stub `<html><body></body></html>` into `../dist/index.html` if it doesn't exist, so that `cargo test` works without a Vite build.
- **Why it matters:** `build.rs` should not mutate source-tree files. It works, but it pollutes the source tree, hides the missing build step, and surprises people who run `git status` after `cargo test`. The desktop version even `panic!`s with `unwrap_or_else(|e| panic!(...))` if writes fail — which is also wrong because `build.rs` should `println!("cargo:warning=…")` and exit gracefully where possible.
- **Recommended action:** **REWRITE.** Either: (a) make `tauri::generate_context!()` tolerate missing frontendDist in test builds (Tauri supports this via `[dev-dependencies] tauri = { features = ["test"] }`), (b) write the stub into `OUT_DIR` instead of `../dist`, or (c) ship a real `index.html` placeholder in source.
- **Effort:** small

### [MEDIUM] [Code quality] eprintln! sprinkled throughout workbench commands

- **Where:** `apps/workbench/src-tauri/src/main.rs:70-90`, `apps/workbench/src-tauri/src/commands/mcp_sidecar.rs:140,576,588,608,675,720`, `apps/workbench/src-tauri/src/commands/repo_roots.rs:66`
- **What:** ~10+ `eprintln!("[workbench] WARNING: …")` and `eprintln!("[mcp-sidecar] …")` calls. Some include ASCII art separators like `"[workbench] ============================================"`.
- **Why it matters:** This is a Tauri release binary. On macOS, stderr in a `.app` goes to Console.app under a generic process name with no filter integration. There's no log level, no structured fields, no rotation. A principal engineer would use `tracing` (the workbench already pulls in `chrono`/`uuid` but somehow not `tracing`).
- **Recommended action:** **REWRITE.** Add `tracing` + `tracing-subscriber` to workbench, replace `eprintln!` calls with `tracing::warn!` / `tracing::error!`, configure subscriber to route to a file under `dirs::data_dir().join("com.clawdstrike.workbench/logs/")` or to OS log (use `tracing-oslog` crate on macOS).
- **Effort:** small

### [MEDIUM] [Native] Force-unwrap in Swift URL construction

- **Where:** `apps/agent/src-tauri/macos/system-extension/endpoint-security/Sources/EndpointSecurityExtension/Monitor.swift:729`
- **What:** `return URL(string: "\(base)/api/v1/agent/edr/endpoint-security/events")!`
- **Why it matters:** The only `!` force-unwrap in the Swift codebase. It's safe in practice (validated URL plus a known suffix), but it's the kind of detail that signals the author was disciplined elsewhere. A `guard let` or `URL(string:)?` returning the trimmed-down `agentURL` directly would be more idiomatic.
- **Recommended action:** **REWRITE.** Replace with safe construction. Cache the events URL in `init` after validation so the force-unwrap moves to a constructor where failure is impossible.
- **Effort:** trivial

### [MEDIUM] [Native] Status tool hardcodes plain-HTTP loopback default

- **Where:** `apps/agent/src-tauri/macos/system-extension/endpoint-security/Sources/EndpointSecurityStatusTool/main.swift:118`
- **What:** `?? "http://127.0.0.1:9878"` — fallback when neither `CLAWDSTRIKE_ENDPOINT_SECURITY_AGENT_URL` nor `CLAWDSTRIKE_AGENT_URL` is set.
- **Why it matters:** A system extension running as root (or via `launchd` system context) posting to plain-HTTP loopback is acceptable on macOS only because loopback is isolated, but it's still worth eliminating: if the agent moves to mTLS on loopback (which it should, given there's an LOCAL_API_MTLS_MIN_PORT constant in `api_server.rs:165`), this default will silently break delivery and fail-open.
- **Recommended action:** **REWRITE.** Remove the default — require the env var. Fail loudly when missing. Update the launch profile/launchd plist to always set it.
- **Effort:** trivial

### [MEDIUM] [Code quality] Workbench `unwrap_or_else(|e| e.into_inner())` on Mutex

- **Where:** `apps/workbench/src-tauri/src/commands/stronghold.rs:117`
- **What:** `let guard = state.inner.lock().unwrap_or_else(|e| e.into_inner());`
- **Why it matters:** Bypassing mutex poisoning is sometimes correct, but doing it silently and unconditionally means a panic in any other thread leaves Stronghold in an unspecified state. For a credential vault, this is the wrong default.
- **Recommended action:** **REWRITE.** Either (a) propagate the poison error to the command result so the renderer can surface it, or (b) use `parking_lot::Mutex` (no poisoning) with a comment explaining the choice.
- **Effort:** trivial

### [MEDIUM] [Code quality] Workbench `getrandom().expect("getrandom failed")` in token generation

- **Where:** `apps/workbench/src-tauri/src/commands/mcp_sidecar.rs:114`
- **What:** `getrandom::getrandom(&mut buf).expect("getrandom failed");` inside `generate_token()`.
- **Why it matters:** Calling `.expect()` in a Tauri command panics the whole runtime. On a system where the CSPRNG is briefly unavailable (early boot, exotic platforms), the workbench will crash instead of returning a user-visible error. The clippy `expect_used = "deny"` lint that the agent has is conspicuously absent here.
- **Recommended action:** **REWRITE.** Return `Result<String, String>` from `generate_token`, propagate the error, surface it to the renderer. Add `#![deny(clippy::expect_used)]` to the workbench `lib.rs` / `main.rs`.
- **Effort:** trivial

### [MEDIUM] [Code quality] Stronghold password derivation falls back to "clawdstrike-default" on hostname failure

- **Where:** `apps/workbench/src-tauri/src/commands/stronghold.rs:85-93`
- **What:** If `hostname::get()` fails, the derivation uses the literal string `"clawdstrike-default"` as the hostname salt. Combined with the persisted `vault-machine-key`, this is fine; but if the machine secret file is also lost, the vault becomes deterministically decryptable.
- **Why it matters:** The fallback creates a worst-case scenario where a corrupted install has a known password. Better to refuse to open and force re-init.
- **Recommended action:** **REWRITE.** Hostname fallback should return an error rather than substitute a constant. Document the threat model in the file header (it currently says "A production build would use a more robust machine-bound key (Secure Enclave / TPM)." — that should be a tracked issue, not a code comment).
- **Effort:** small

### [MEDIUM] [Tauri] Plugins pulled in but possibly unused

- **Where:** `apps/agent/src-tauri/Cargo.toml:14-15`, `apps/desktop/src-tauri/Cargo.toml:15`
- **What:** Agent depends on `tauri-plugin-shell` and `tauri-plugin-notification`. Desktop depends on `tauri-plugin-shell`. Neither shows obvious use of shell plugin commands (the agent uses `tokio::process::Command` directly).
- **Why it matters:** Unused plugins inflate the binary, expose IPC surfaces, and require capability declarations. `tauri-plugin-shell` in particular is a frequent source of "shell.all" type vulnerabilities.
- **Recommended action:** **WIPE.** Audit usage with `cargo +nightly udeps` or manual grep. Delete any plugin not actually invoked through the Tauri runtime.
- **Effort:** trivial

### [MEDIUM] [Build] [patch.crates-io] async-nats vendored across three apps with no explanation

- **Where:** `apps/agent/src-tauri/Cargo.toml:85-86`, `apps/desktop/src-tauri/Cargo.toml:65-66`, `apps/workbench/src-tauri/Cargo.toml:52-53`
- **What:** `async-nats = { path = "../../../infra/vendor/async-nats" }` patch declared in all three apps without comment explaining why. The git status shows `infra/vendor/async-nats` is heavily modified.
- **Why it matters:** Maintaining a fork of a network-protocol client is a heavy long-term commitment. No comment in Cargo.toml or `infra/vendor/async-nats/README` explains what was patched. New contributors won't know whether to use this or upstream.
- **Recommended action:** **DOCUMENT.** At minimum add `# patched to <upstream-PR-link or commit hash>; see infra/vendor/async-nats/PATCHES.md` next to each declaration. Better: upstream the fixes and remove the vendor patch.
- **Effort:** small (document) or large (upstream)

### [MEDIUM] [Code quality] Workbench commands all expose `Result<T, String>` not typed errors

- **Where:** `apps/workbench/src-tauri/src/commands/*.rs` throughout (e.g. `stronghold.rs:113,120`, `hushd.rs:25,36`, etc.)
- **What:** Every Tauri command returns `Result<X, String>` and uses `.map_err(|e| format!("…: {}", e))?`.
- **Why it matters:** This is the Tauri tutorial pattern but it loses the error chain. The renderer cannot programmatically distinguish "stronghold not initialised" from "snapshot save failed" without parsing strings.
- **Recommended action:** **REWRITE.** Define `pub enum CommandError { … }` with `#[derive(serde::Serialize, thiserror::Error)]` per command module (or one shared one). Map to discriminated union JSON for the renderer.
- **Effort:** medium

### [MEDIUM] [Native] No tests for endpoint-security AUTH_OPEN runtime against real ES kernel

- **Where:** `apps/agent/src-tauri/macos/system-extension/endpoint-security/Tests/EndpointSecurityExtensionTests/EndpointSecurityExtensionTests.swift`
- **What:** Tests cover the `EndpointSecurityMonitor` state machine, encoder, and HTTP publisher in detail. They do not test `EndpointSecurityAuthOpenRuntime.start()` / `handleAuthorizationMessage` against a mock `es_client_t` because no abstraction exists for that.
- **Why it matters:** The most safety-critical code (the AUTH_OPEN callback that must answer before the kernel deadline or risk fail-open) has no unit test for its happy path or error paths. The fail-open recovery in `issueFailOpenAuthOpenResponse` is exercised by exactly zero tests.
- **Recommended action:** **REWRITE.** Wrap `es_client_t` interactions behind a `EndpointSecurityClientHandle` protocol so the runtime can be tested with a fake client that captures `respond` calls. Add tests for: (a) successful AUTH_OPEN allow, (b) successful AUTH_OPEN deny, (c) decode failure → fail-open response + event_loss publish, (d) self-deallocated during callback → static fail-open path.
- **Effort:** medium

### [LOW] [Code quality] `main.rs` panic in `unwrap_or_default` chain hides directive parse errors

- **Where:** `apps/agent/src-tauri/src/main.rs:136-137`
- **What:** `.add_directive("clawdstrike_agent=info".parse().unwrap_or_default())`
- **Why it matters:** `unwrap_or_default()` on a `Directive` parse silently swallows malformed directives. Compile-time string is fine here, but it's a copy-paste foot-gun for future directives that aren't validated.
- **Recommended action:** **LEAVE** (or use `EnvFilter::new("clawdstrike_agent=info,hushd=info")` directly to fail at startup).
- **Effort:** trivial

### [LOW] [Polish] `.expect("error while running tauri application")` boilerplate left in

- **Where:** `apps/desktop/src-tauri/src/main.rs:51`, `apps/workbench/src-tauri/src/main.rs:164`
- **What:** Default Tauri template panic message left unchanged.
- **Why it matters:** Cosmetic but unambiguous "I'm from the Tauri scaffold" signal. Real engineers replace this with a logged error + non-zero exit code.
- **Recommended action:** **REWRITE.** Match the agent's pattern (build then `match { Err(err) => tracing::error!(...); return; }`).
- **Effort:** trivial

### [LOW] [Repo hygiene] `.DS_Store` files committed

- **Where:** `apps/agent/.DS_Store`, `apps/agent/src-tauri/.DS_Store`, `apps/agent/src-tauri/src/.DS_Store`, `apps/desktop/.DS_Store`, etc.
- **What:** macOS `.DS_Store` files present in the repo (visible in `git status` and `ls -la`).
- **Why it matters:** Trivially noisy, looks unprofessional, and reveals macOS-only development.
- **Recommended action:** **WIPE.** Add `.DS_Store` to root `.gitignore`, `git rm --cached` existing ones.
- **Effort:** trivial

### [LOW] [Docs] README claims macOS 10.15+ but tauri.conf requires 13.0

- **Where:** `apps/agent/README.md:19` ("macOS 10.15+ (Linux support planned)") vs `apps/agent/src-tauri/tauri.conf.json:35` (`"minimumSystemVersion": "13.0"`)
- **What:** README says 10.15. tauri.conf says 13.0. Endpoint Security message v4 fields are 13+. Build script validates `"minimumSystemVersion": "13.0"` is present.
- **Why it matters:** Contradictory docs erode trust. Users on Catalina/Big Sur will install and crash.
- **Recommended action:** **DOCUMENT.** Update README to "macOS 13.0+ required (uses EndpointSecurity message v4)".
- **Effort:** trivial

### [LOW] [Code quality] Workbench `Mutex<TerminalManager>` with `Arc<...>` re-wrapping pattern

- **Where:** `apps/workbench/src-tauri/src/main.rs:37-42`
- **What:** `std::sync::Arc::new(tokio::sync::Mutex::new(...))` casted via `as TerminalState` (a type alias).
- **Why it matters:** Works but verbose. Pattern repeated for `CommandCapabilityManager` and `TerminalManager`. A constructor on the inner type returning the wrapped form would be cleaner.
- **Recommended action:** **REWRITE.** Add `TerminalState::new()` / `CommandCapabilityState::new()` constructors. Move the `Arc<Mutex<…>>` plumbing into the alias module.
- **Effort:** trivial

### [LOW] [Polish] `commands::hushd::test_connection` returns `Err` as `String` and joins URL with `format!("{}/health", url.trim_end_matches('/'))`

- **Where:** `apps/desktop/src-tauri/src/commands/hushd.rs:29`
- **What:** Manual URL concatenation rather than `reqwest::Url::join` or `Url::parse`. Trusts caller-supplied `url: String` without scheme validation.
- **Why it matters:** `test_connection` is a Tauri command receiving an arbitrary string from the renderer (or from a malicious renderer compromise). If `url` is `file:///etc/passwd`, the format gives `file:///etc/passwd/health` which `reqwest` happily rejects but the surface is wider than it needs to be.
- **Recommended action:** **REWRITE.** Validate scheme ∈ {http, https}, host is loopback or trusted, use `Url::join("health").unwrap_or_else(...)` rather than format.
- **Effort:** small

### [LOW] [Tauri] Window title "Huntronomer" for desktop product is whimsical

- **Where:** `apps/desktop/src-tauri/tauri.conf.json:3,16`
- **What:** `productName: "Huntronomer"`, `title: "Huntronomer"`. Cargo package `name = "sdr-desktop"`. Description: "Huntronomer desktop command deck for autonomous threat hunting swarms."
- **Why it matters:** Naming and brand drift across `productName`, package name, and description. If "Huntronomer" is a real product, it needs to live in a separate repo with its own brand. If it's a prototype, delete it.
- **Recommended action:** **WIPE** (delete the app) or **DOCUMENT** (justify why it ships from this repo).
- **Effort:** trivial (rename) or large (delete)

### [LOW] [Code quality] Agent `daemon.rs` test code has 200+ `.unwrap()`s

- **Where:** `apps/agent/src-tauri/src/daemon.rs:2404+` (all inside `#[cfg(test)]`)
- **What:** Test code uses `.unwrap()` liberally even though the crate sets `unwrap_used = "deny"`.
- **Why it matters:** The clippy deny only applies to non-test code, so this is technically fine. But it's worth noting that the test lint is not as strict as the production lint — moving to `unwrap_used = "deny"` for tests too (with `#[allow(clippy::unwrap_used)]` per-test where needed) would force people to write better tests.
- **Recommended action:** **LEAVE** (acceptable trade-off in tests, but worth a workspace-wide policy discussion).
- **Effort:** trivial

### [LOW] [Native] NetworkExtension `unknown default` provider stop reason maps to a string but doesn't log

- **Where:** `apps/agent/src-tauri/macos/system-extension/network-extension/Sources/ClawdStrikeNetworkExtension/ContentFilterProvider.swift:838-840`
- **What:** `@unknown default: return "provider_stopped_unknown_reason"`
- **Why it matters:** Apple adds new `NEProviderStopReason` cases occasionally. Silent string mapping means new reasons appear as `provider_stopped_unknown_reason` with no signal anywhere. Should at least `os_log` so we know to update.
- **Recommended action:** **REWRITE.** Log via `os.Logger(subsystem:category:)` when hitting the @unknown default with the raw rawValue.
- **Effort:** trivial

### [LOW] [Code quality] Tray `tray.rs` is 1264 lines

- **Where:** `apps/agent/src-tauri/src/tray.rs`
- **What:** Single file handles menu IDs, state, menu construction, event routing, URL building, bootstrap code orchestration, diagnostics bundle creation, and 8+ inline tests.
- **Why it matters:** Tray code being long is normal, but this file conflates menu-construction with HTTP orchestration (it makes `reqwest` calls to start UI bootstrap and create diagnostics bundles directly from menu handlers). Menu handlers should dispatch to services, not own them.
- **Recommended action:** **RESTRUCTURE.** Split into `tray/menu.rs` (UI), `tray/state.rs` (state), `tray/handlers.rs` (event routing), with HTTP orchestration moved into the agent-api library.
- **Effort:** medium

### [LOW] [Build] `tauri.conf.json` bundle.targets is `"all"` everywhere

- **Where:** All three `tauri.conf.json` files line ~19
- **What:** `"targets": "all"` builds .deb, .rpm, .AppImage, .msi, .nsis, .app, .dmg targets even though only macOS has any native code.
- **Why it matters:** CI builds will fail on non-macOS targets because `mac-notification-sys` and the system-extension Swift packages are macOS-only. Wastes CI time and produces fictional Linux/Windows installers.
- **Recommended action:** **REWRITE.** Set `targets: ["app", "dmg"]` for agent (until Windows/Linux are real). For workbench (which is genuinely cross-platform), leave as `"all"` but verify CI matrix matches.
- **Effort:** trivial

---

## Action Plan

### Phase 1 — Stop the bleeding (1 week)
1. Delete `.DS_Store`s, add to `.gitignore`.
2. Add `apps/agent/src-tauri/resources/control-console/`, `resources/cloud-dashboard/`, `apps/workbench/dist/`, `apps/desktop/dist/` to gitignore; `git rm --cached` existing entries.
3. Generate real `apps/desktop/src-tauri/capabilities/default.json` and `apps/agent/src-tauri/capabilities/default.json`. Verify `cargo tauri build --debug` succeeds on each.
4. Replace the three identical Tauri-default icons with real brand marks for whichever apps survive Phase 2.
5. Remove hardcoded `TEAM_ID=JB6682CJY9` from `render-mdm-profiles.sh` and `developer-id-profile-template.plist`.
6. Replace `eprintln!` with `tracing` in workbench; remove `.expect("error while running tauri application")` boilerplate.
7. Audit and remove unused Tauri plugins.

### Phase 2 — Architectural consolidation (3-4 weeks)
1. Decide app inventory. Recommended: keep `agent` + `workbench`, delete `desktop` ("Huntronomer") and `control-console` Tauri shell.
2. Extract `apps/agent/src-tauri/src/api_server.rs` and the EDR / broker / posture / response_action modules into a new library crate `crates/services/agent-api/`. Agent Tauri binary becomes a 200-line file that wires routes and runs the tray.
3. Resolve the "is the agent a Tauri app?" question — either commit to opening a webview against the bundled UI or drop Tauri and use `tao` + `tray-icon` directly.
4. Move `prepare-bundled-hushd.sh` into a moon task or top-level `xtask`. Tauri build consumes pre-built artifacts only.
5. Add CSP to whichever apps actually have webviews.

### Phase 3 — Release readiness (2 weeks)
1. Wire Tauri signing identity + notarytool. Document signer-host setup. Add CI release job.
2. Add an integration test that loads the EndpointSecurity system extension on a real macOS VM in CI (or a documented signer-host runbook if VM ES support isn't feasible).
3. Replace string error returns with typed errors in workbench Tauri commands.
4. Add log routing to OS log on macOS (`tracing-oslog`), Windows event log, and journal on Linux.

### Phase 4 — Native code hardening (1-2 weeks)
1. Wrap `es_client_t` in a protocol so `EndpointSecurityAuthOpenRuntime` can be unit-tested with a fake client. Add tests for fail-open paths.
2. Add `os.Logger` to the `@unknown default` arms in `ContentFilterProvider.swift`.
3. Eliminate the one Swift force-unwrap (`URL(string:)!` in Monitor.swift:729).

---

## Top 10 Quick Wins

1. **Replace duplicate Tauri-default icons.** Trivial, immediate visual credibility boost.
2. **Add `.DS_Store` to `.gitignore` + `git rm --cached`.** 5 minutes.
3. **Delete `apps/agent/src-tauri/resources/control-console/assets/*.js` from git.** Stop checking in built bundles.
4. **Remove hardcoded `TEAM_ID=JB6682CJY9`.** Replace with env var.
5. **Set CSP on desktop tauri.conf.json.** Currently `null`. Copy workbench's CSP.
6. **Create `capabilities/default.json` for desktop and agent.** Otherwise release builds break.
7. **Replace `eprintln!` with `tracing` in workbench.** ~20 sites.
8. **Replace `.expect("error while running tauri application")` boilerplate.** 2 files.
9. **Fix `bundle.targets: "all"` on agent.** Stops fictional Linux installers being built.
10. **Fix `tauri.conf.json` schema URL on workbench** (currently pointing at nicegui's repo).

---

## Things to Leave Alone

1. **`Monitor.swift` EndpointSecurity AUTH_OPEN handling.** Correct, careful, well-tested. The fail-open response in `issueFailOpenAuthOpenResponse` and the `[weak self]` deallocation path are exactly what you want.
2. **`render-mdm-profiles.sh` input validation.** Regex checks Team ID, bundle IDs, org identifier, plus post-render `{{` detection and `plutil -lint`. This is production-quality.
3. **Workbench `capabilities/default.json` deny list.** Explicitly denies `~/.ssh`, `~/.aws`, `~/.kube`, `~/.docker`, keychain dirs, `.netrc`, `.git-credentials`, `.npmrc`, `.pypirc`. This is the right shape — copy this pattern to any new app.
4. **Workbench `CommandCapabilityManager`.** The backend-held grant + native-dialog confirmation + TTL/use-count model in `capability.rs` is the right approach to renderer-IPC trust.
5. **Constant-time auth in `apps/agent/src-tauri/src/security/auth.rs`.** `subtle::ConstantTimeEq` is the correct primitive.
6. **`apps/agent/src-tauri/build.rs` packaging validation.** The `CLAWDSTRIKE_REQUIRE_CONCRETE_MACOS_PACKAGING` env var that rejects placeholder strings at release-build time is genuinely thoughtful and should be the model for other release gates.
7. **Swift `Codable` + `.sortedKeys, .withoutEscapingSlashes`** for canonical JSON throughout. Cross-language determinism done right.
8. **`NetworkExtensionFilterManagerVendorConfigurationStore` timeout pattern.** `DispatchSemaphore + timeout` wrapping `NEFilterManager.loadFromPreferences/saveToPreferences` is the correct way to expose Apple's callback API as throwing sync, with proper timeout error.

---

*End of report. Audit covers Tauri configuration, native Rust system code, Swift system extensions, build pipeline, signing/notarization readiness, IPC boundaries, logging, and cross-platform consistency. UI / frontend code in `apps/agent/src-tauri/resources/control-console/` and `apps/workbench/src/` is out of scope.*
