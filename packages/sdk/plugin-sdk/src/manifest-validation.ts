/**
 * Self-contained runtime validation for PluginManifest objects.
 * All errors are accumulated (not short-circuited).
 */

import type { PluginManifest, PluginTrustTier } from "./types";


export interface ManifestValidationError {
  field: string;
  message: string;
}

export interface ManifestValidationResult {
  valid: boolean;
  errors: ManifestValidationError[];
}


const VALID_TRUST_TIERS: PluginTrustTier[] = ["internal", "community", "mcp"];

const SEMVER_PATTERN = /^\d+\.\d+\.\d+/;

const SHA256_HEX_PATTERN = /^[0-9a-fA-F]{64}$/;


function isNonNullObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function requireString(
  obj: Record<string, unknown>,
  field: string,
  errors: ManifestValidationError[],
  prefix?: string,
): void {
  const path = prefix ? `${prefix}.${field}` : field;
  const value = obj[field];
  if (typeof value !== "string" || value.length === 0) {
    errors.push({
      field: path,
      message: `"${path}" is required and must be a non-empty string`,
    });
  }
}

function requireArray(
  obj: Record<string, unknown>,
  field: string,
  errors: ManifestValidationError[],
  prefix?: string,
): void {
  const path = prefix ? `${prefix}.${field}` : field;
  const value = obj[field];
  if (!Array.isArray(value)) {
    errors.push({
      field: path,
      message: `"${path}" is required and must be an array`,
    });
  }
}


function validateGuardContributions(
  guards: unknown[],
  errors: ManifestValidationError[],
): void {
  for (let i = 0; i < guards.length; i++) {
    const guard = guards[i];
    if (!isNonNullObject(guard)) {
      errors.push({
        field: `guards[${i}]`,
        message: `guards[${i}] must be an object`,
      });
      continue;
    }
    requireString(guard, "id", errors, `guards[${i}]`);
    requireString(guard, "name", errors, `guards[${i}]`);
    requireString(guard, "category", errors, `guards[${i}]`);
    requireArray(guard, "configFields", errors, `guards[${i}]`);
  }
}

function validateCommandContributions(
  commands: unknown[],
  errors: ManifestValidationError[],
): void {
  for (let i = 0; i < commands.length; i++) {
    const command = commands[i];
    if (!isNonNullObject(command)) {
      errors.push({
        field: `commands[${i}]`,
        message: `commands[${i}] must be an object`,
      });
      continue;
    }
    requireString(command, "id", errors, `commands[${i}]`);
    requireString(command, "title", errors, `commands[${i}]`);
  }
}

function validateFileTypeContributions(
  fileTypes: unknown[],
  errors: ManifestValidationError[],
): void {
  for (let i = 0; i < fileTypes.length; i++) {
    const fileType = fileTypes[i];
    if (!isNonNullObject(fileType)) {
      errors.push({
        field: `fileTypes[${i}]`,
        message: `fileTypes[${i}] must be an object`,
      });
      continue;
    }
    requireString(fileType, "id", errors, `fileTypes[${i}]`);
    requireString(fileType, "label", errors, `fileTypes[${i}]`);
    if (!isStringArray(fileType.extensions)) {
      errors.push({
        field: `fileTypes[${i}].extensions`,
        message: `fileTypes[${i}].extensions must be an array of strings`,
      });
    }
  }
}

function validateContributions(
  contributions: unknown,
  errors: ManifestValidationError[],
): void {
  if (!isNonNullObject(contributions)) {
    return;
  }

  if (Array.isArray(contributions.guards)) {
    validateGuardContributions(contributions.guards as unknown[], errors);
  }
  if (Array.isArray(contributions.commands)) {
    validateCommandContributions(contributions.commands as unknown[], errors);
  }
  if (Array.isArray(contributions.fileTypes)) {
    validateFileTypeContributions(contributions.fileTypes as unknown[], errors);
  }
}

function validateInstallation(
  installation: unknown,
  errors: ManifestValidationError[],
): void {
  if (!isNonNullObject(installation)) {
    errors.push({
      field: "installation",
      message: '"installation" must be an object',
    });
    return;
  }

  requireString(installation, "downloadUrl", errors, "installation");

  if (typeof installation.size !== "number" || installation.size <= 0) {
    errors.push({
      field: "installation.size",
      message: '"installation.size" must be a positive number',
    });
  }

  if (typeof installation.checksum !== "string" || !SHA256_HEX_PATTERN.test(installation.checksum)) {
    errors.push({
      field: "installation.checksum",
      message: '"installation.checksum" must be a 64-character hex string (SHA-256)',
    });
  }

  requireString(installation, "signature", errors, "installation");

  if (
    installation.publisherKey !== undefined &&
    (typeof installation.publisherKey !== "string" ||
      installation.publisherKey.length === 0)
  ) {
    errors.push({
      field: "installation.publisherKey",
      message: '"installation.publisherKey" must be a non-empty string when provided',
    });
  }
}


export function validateManifest(input: unknown): ManifestValidationResult {
  const errors: ManifestValidationError[] = [];

  if (!isNonNullObject(input)) {
    errors.push({
      field: "(root)",
      message: "Manifest must be a non-null object",
    });
    return { valid: false, errors };
  }

  requireString(input, "id", errors);
  requireString(input, "name", errors);
  requireString(input, "displayName", errors);
  requireString(input, "description", errors);
  requireString(input, "publisher", errors);

  if (typeof input.version !== "string" || input.version.length === 0) {
    errors.push({
      field: "version",
      message: '"version" is required and must be a non-empty string',
    });
  } else if (!SEMVER_PATTERN.test(input.version)) {
    errors.push({
      field: "version",
      message: '"version" must be a valid semver string (e.g. "1.0.0")',
    });
  }

  if (!VALID_TRUST_TIERS.includes(input.trust as PluginTrustTier)) {
    errors.push({
      field: "trust",
      message: `"trust" must be one of: ${VALID_TRUST_TIERS.join(", ")}`,
    });
  }

  if (input.categories !== undefined && !isStringArray(input.categories)) {
    errors.push({
      field: "categories",
      message: '"categories" must be an array of strings',
    });
  }

  if (input.activationEvents === undefined) {
    errors.push({
      field: "activationEvents",
      message: '"activationEvents" is required and must be an array of strings',
    });
  } else if (!isStringArray(input.activationEvents)) {
    errors.push({
      field: "activationEvents",
      message: '"activationEvents" must be an array of strings',
    });
  }

  if (input.contributions !== undefined) {
    validateContributions(input.contributions, errors);
  }

  if (input.installation !== undefined) {
    validateInstallation(input.installation, errors);
  }

  return { valid: errors.length === 0, errors };
}


export function createTestManifest(overrides?: Partial<PluginManifest>): PluginManifest {
  return {
    id: "test.plugin",
    name: "Test Plugin",
    displayName: "Test Plugin",
    description: "A test plugin",
    version: "1.0.0",
    publisher: "test",
    categories: ["guards"],
    trust: "internal",
    activationEvents: ["onStartup"],
    ...overrides,
  };
}
