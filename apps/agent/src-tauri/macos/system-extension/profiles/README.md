# ClawdStrike macOS MDM Profiles

This directory contains source templates for managed macOS deployment of the ClawdStrike agent and combined system extension.

Render concrete profiles with:

```bash
apps/agent/src-tauri/macos/system-extension/profiles/render-mdm-profiles.sh \
  --team-id JB6682CJY9 \
  --app-bundle-id dev.clawdstrike.agent \
  --extension-bundle-id dev.clawdstrike.agent.system-extension \
  --org-identifier com.example.enterprise \
  --out-dir /tmp/clawdstrike-mdm-profiles
```

Deploy the rendered profiles before installing the notarized app:

1. `clawdstrike-system-extension-approval.mobileconfig`
2. `clawdstrike-full-disk-access.mobileconfig`
3. `clawdstrike-network-content-filter.mobileconfig`

The profile renderer emits a `manifest.txt` next to the profiles so release evidence can record the Team ID, app bundle ID, system extension bundle ID, and organization identifier used for the managed-host validation run.
