import { describe, expect, it } from "vitest";
import {
  extractRegistryPackageFile,
  extractRegistryPackageMetadata,
  selectLatestInstallableVersion,
} from "../registry-package";

function createTarArchive(entries: Array<{ name: string; content: string }>): ArrayBuffer {
  const encoder = new TextEncoder();
  const chunks: Uint8Array[] = [];

  for (const entry of entries) {
    const contentBytes = encoder.encode(entry.content);
    const header = new Uint8Array(512);

    header.set(encoder.encode(entry.name), 0);
    header.set(encoder.encode("0000644\0"), 100);
    header.set(encoder.encode("0000000\0"), 108);
    header.set(encoder.encode("0000000\0"), 116);
    const sizeField = contentBytes.length.toString(8).padStart(11, "0");
    header.set(encoder.encode(`${sizeField}\0`), 124);
    header.set(encoder.encode("00000000000\0"), 136);
    header[156] = "0".charCodeAt(0);

    chunks.push(header);
    chunks.push(contentBytes);

    const padding = (512 - (contentBytes.length % 512)) % 512;
    if (padding > 0) {
      chunks.push(new Uint8Array(padding));
    }
  }

  chunks.push(new Uint8Array(1024));

  const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const output = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }
  return output.buffer;
}

describe("registry-package helpers", () => {
  it("extracts the published entrypoint from package/package.json", () => {
    const archiveBuffer = createTarArchive([
      {
        name: "package/package.json",
        content: JSON.stringify({
          name: "@acme/sample-plugin",
          displayName: "Sample Plugin",
          description: "Registry test fixture",
          exports: {
            ".": {
              import: "./dist/index.js",
              require: "./dist/index.cjs",
            },
          },
        }),
      },
    ]);

    const metadata = extractRegistryPackageMetadata(archiveBuffer);

    expect(metadata.entrypoint).toBe("dist/index.js");
    expect(metadata.packageJson).toMatchObject({
      name: "@acme/sample-plugin",
      displayName: "Sample Plugin",
    });
    expect(metadata.size).toBeGreaterThan(0);
  });

  it("selects the newest non-yanked version from ascending registry results", () => {
    const version = selectLatestInstallableVersion(
      [
        { version: "0.9.0", yanked: false },
        { version: "1.0.0", yanked: true },
        { version: "1.1.0", yanked: false },
      ],
      "1.1.0",
    );

    expect(version).toBe("1.1.0");
  });

  it("falls back when every registry version is yanked", () => {
    const version = selectLatestInstallableVersion(
      [
        { version: "1.0.0", yanked: true },
        { version: "1.1.0", yanked: true },
      ],
      "1.1.0",
    );

    expect(version).toBe("1.1.0");
  });

  it("extracts a package file relative to the tarball root", () => {
    const archiveBuffer = createTarArchive([
      {
        name: "package/dist/index.js",
        content: 'export { plugin as default };',
      },
    ]);

    expect(extractRegistryPackageFile(archiveBuffer, "./dist/index.js")).toBe(
      'export { plugin as default };',
    );
  });
});
