# File Types

File type contributions declare custom detection engineering file formats. They define how the workbench recognizes, displays, and creates files of a new format.

## FileTypeContribution interface

```typescript,ignore
interface FileTypeContribution {
  /** Unique file type identifier. */
  id: string;
  /** Human-readable label (e.g. "Splunk SPL Rule"). */
  label: string;
  /** Short label for compact UI (e.g. "SPL"). */
  shortLabel: string;
  /** Associated file extensions (lowercase, with leading dot). */
  extensions: string[];
  /** Hex color for tab dots and explorer icons. */
  iconColor: string;
  /** Template content for new file creation. */
  defaultContent: string;
  /** Whether this format supports the test runner. */
  testable: boolean;
}
```

## Registering a file type

Declare the file type in `contributions.fileTypes`, then register it in `activate()`:

```typescript,ignore
import { createPlugin } from "@clawdstrike/plugin-sdk";
import type { FileTypeContribution } from "@clawdstrike/plugin-sdk";

const yaraFileType: FileTypeContribution = {
  id: "acme.yara-rule",
  label: "YARA Rule",
  shortLabel: "YARA",
  extensions: [".yar", ".yara"],
  iconColor: "#e74c3c",
  defaultContent: `rule example_rule {
    meta:
        author = "Your Name"
        description = "Example YARA rule"
    strings:
        $a = "malware_string"
    condition:
        $a
}
`,
  testable: true,
};

export default createPlugin({
  manifest: {
    id: "acme.yara-support",
    name: "yara-support",
    displayName: "YARA Support",
    description: "YARA rule editing and detection",
    version: "1.0.0",
    publisher: "Acme",
    categories: ["detection"],
    trust: "community",
    activationEvents: ["onFileType:acme.yara-rule"],
    contributions: {
      fileTypes: [yaraFileType],
    },
  },

  activate(ctx) {
    ctx.subscriptions.push(ctx.fileTypes.register(yaraFileType));
  },
});
```

## Field details

- **extensions**: Must be lowercase with leading dot (e.g. `[".yar", ".yara"]`). The workbench uses these to auto-detect file types when opening files.
- **iconColor**: Hex color string used for the colored dot on editor tabs and file explorer icons.
- **defaultContent**: Template content shown when a user creates a new file of this type via the "New File" command.
- **testable**: When `true`, files of this type can be run through the test runner. Set to `false` for formats that have no execution semantics.

## Detection adapters

If your file type represents a detection format that can be translated to other formats, you can pair it with a detection adapter contribution:

```typescript,ignore
interface DetectionAdapterContribution {
  /** File type this adapter handles. */
  fileType: string;
  /** Path to the adapter module within the plugin package. */
  entrypoint: string;
}
```

Detection adapters enable the translation UI to convert between detection formats (e.g. YARA to Sigma, SPL to KQL).
