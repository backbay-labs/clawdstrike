# Publishing

This guide covers how to distribute your plugin to other ClawdStrike users through the plugin registry.

## Distribution model

ClawdStrike plugins are distributed through the built-in package registry. Plugins are packaged as npm-style tarballs with cryptographic integrity verification. The trust tier system (internal, community, mcp) determines how plugins are loaded in the workbench.

For details on the registry architecture, see the [Package Manager](../package-manager/index.md) section.

## Publishing workflow

### 1. Build your plugin

Ensure your plugin builds cleanly:

```bash
npm run build
```

This produces the distributable bundle in `dist/`.

### 2. Validate the manifest

Run manifest validation to catch issues before publishing:

```typescript,ignore
import { assertManifestValid } from "@clawdstrike/plugin-sdk/testing";
import plugin from "./src/index";

assertManifestValid(plugin.manifest);
```

### 3. Add installation metadata

Add the `installation` field to your manifest with distribution metadata:

```typescript,ignore
installation: {
  downloadUrl: "https://registry.clawdstrike.dev/packages/acme.my-plugin/1.0.0.tgz",
  size: 45_200,
  checksum: "sha256:a1b2c3d4e5f6...",  // SHA-256 hex digest of the package
  signature: "ed25519:...",              // Ed25519 signature of the canonical manifest
  minWorkbenchVersion: "6.0.0",
  maxWorkbenchVersion: "7.0.0",
}
```

| Field | Description |
|-------|-------------|
| `downloadUrl` | URL where the package tarball can be fetched |
| `size` | Package size in bytes |
| `checksum` | SHA-256 hex digest of the package contents |
| `signature` | Ed25519 signature of the canonical (RFC 8785) JSON manifest |
| `minWorkbenchVersion` | Minimum compatible workbench version (semver, optional) |
| `maxWorkbenchVersion` | Maximum compatible workbench version (semver, optional) |

### 4. Sign the manifest

Plugin manifests are signed with Ed25519 to ensure integrity. The signature covers the canonical JSON (RFC 8785) representation of the manifest:

```bash
clawdstrike pkg sign --manifest package.json --key ~/.clawdstrike/publisher.key
```

See the [Trust & Verification](../package-manager/trust-verification.md) guide for details on key management and the verification model.

### 5. Publish

```bash
clawdstrike pkg publish
```

This uploads the package to the registry and makes it available for installation.

## Version compatibility

Use `minWorkbenchVersion` and `maxWorkbenchVersion` to declare which workbench versions your plugin supports. The workbench will refuse to load plugins outside the compatible range.

- If only `minWorkbenchVersion` is set, the plugin is compatible with all versions from that point forward
- If only `maxWorkbenchVersion` is set, the plugin is compatible with all versions up to that point
- If both are set, the plugin is compatible within the specified range
