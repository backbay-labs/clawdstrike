# Guards

Guard contributions add custom security guards to the ClawdStrike guard pipeline. Guards are the core extension point -- they evaluate actions (file access, network calls, shell commands) and return allow/deny/warn verdicts.

## GuardContribution interface

```typescript,ignore
interface GuardContribution {
  /** Guard ID to register in the guard registry. */
  id: string;
  /** Human-readable display name. */
  name: string;
  /** Technical/snake_case name for policy YAML keys. */
  technicalName: string;
  /** Description of what this guard checks. */
  description: string;
  /** Guard category (e.g. "filesystem", "network", "content"). */
  category: string;
  /** Default verdict when the guard triggers. */
  defaultVerdict: "allow" | "deny" | "warn";
  /** Icon identifier for UI rendering. */
  icon: string;
  /** Configuration field definitions for the guard config UI. */
  configFields: ConfigFieldDef[];
}
```

## Registering a guard

Declare the guard in the manifest's `contributions.guards` array, then register it in `activate()` using `ctx.guards.register()`:

```typescript,ignore
import { createPlugin } from "@clawdstrike/plugin-sdk";
import type { GuardContribution, ConfigFieldDef } from "@clawdstrike/plugin-sdk";

const myGuard: GuardContribution = {
  id: "acme.secret-scanner",
  name: "Secret Scanner",
  technicalName: "secret_scanner",
  description: "Detects hardcoded secrets in file writes using entropy analysis",
  category: "content",
  defaultVerdict: "deny",
  icon: "key",
  configFields: [
    {
      key: "sensitivity",
      label: "Detection Sensitivity",
      type: "select",
      description: "How aggressively to flag potential secrets",
      defaultValue: "medium",
      options: [
        { value: "low", label: "Low" },
        { value: "medium", label: "Medium" },
        { value: "high", label: "High" },
      ],
    },
    {
      key: "ignore_patterns",
      label: "Ignore Patterns",
      type: "string_list",
      description: "Glob patterns for files to skip",
      defaultValue: [],
    },
  ],
};

export default createPlugin({
  manifest: {
    id: "acme.secret-scanner",
    name: "secret-scanner",
    displayName: "Secret Scanner",
    description: "Entropy-based secret detection for file writes",
    version: "1.0.0",
    publisher: "Acme Security",
    categories: ["guards"],
    trust: "community",
    activationEvents: ["onStartup"],
    contributions: {
      guards: [myGuard],
    },
  },

  activate(ctx) {
    ctx.subscriptions.push(ctx.guards.register(myGuard));
  },
});
```

## Configuration fields

The `configFields` array defines the UI for configuring your guard. Each `ConfigFieldDef` maps to a form control in the guard config panel:

| `type` | Renders as | Notes |
|--------|-----------|-------|
| `"toggle"` | Switch/checkbox | Boolean on/off |
| `"string_list"` | Tag input | List of strings |
| `"pattern_list"` | Tag input | List of glob/regex patterns |
| `"number_slider"` | Slider | Requires `min`, `max`, optional `step` |
| `"number_input"` | Number field | Requires `min`, `max`, optional `step` |
| `"select"` | Dropdown | Requires `options` array |
| `"secret_pattern_list"` | Tag input | Like `string_list` but masked |
| `"json"` | JSON editor | Fallback for arbitrary config schemas |

Each field definition includes:

```typescript,ignore
interface ConfigFieldDef {
  key: string;           // Maps to the guard's config object
  label: string;         // Human-readable label
  type: ConfigFieldType; // Widget type (see table above)
  description?: string;  // Help text
  defaultValue?: unknown; // Default when no user override exists
  options?: { value: string; label: string }[]; // For "select" type
  min?: number;          // For numeric types
  max?: number;          // For numeric types
  step?: number;         // For numeric types
}
```
