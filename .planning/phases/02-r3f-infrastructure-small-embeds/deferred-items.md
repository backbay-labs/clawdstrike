# Deferred Items — Phase 02

## Pre-existing Issue: @clawdstrike/sdk workspace build failure

**Discovered during:** Plan 02-01, Task 1 (bun add R3F packages)
**Issue:** `bun add` without `--ignore-scripts` fails because the `@clawdstrike/sdk` workspace package has a `prepare` build script that errors:
```
src/adapters/index.ts: Could not resolve "@clawdstrike/adapter-core"
src/index.ts: Cannot find module '@clawdstrike/adapter-core'
```
**Impact:** `bun add` must be used with `--ignore-scripts` to install new packages.
**Scope:** Pre-existing workspace configuration issue unrelated to Phase 2 work.
**Status:** Out of scope for this phase — do not fix here.
