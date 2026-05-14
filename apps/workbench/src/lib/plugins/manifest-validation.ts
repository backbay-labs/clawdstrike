/**
 * Plugin Manifest Validation
 *
 * Runtime validation for PluginManifest objects. Uses manual type guards
 * (no Zod or io-ts) for zero-dependency lightweight validation.
 *
 * All errors are accumulated — validation does not short-circuit on the first
 * error, so callers see the full list of issues to fix.
 */

import type { PluginManifest, PluginTrustTier } from "./types";
import { KNOWN_PERMISSIONS } from "./bridge/permissions";

// ---- Validation Types ----

/** A single validation error with the field path and a descriptive message. */
export interface ManifestValidationError {
  /** Dot-path to the invalid field (e.g. "guards[0].id", "installation.checksum"). */
  field: string;
  /** Human-readable description of the validation failure. */
  message: string;
}

/** Result of manifest validation. */
export interface ManifestValidationResult {
  /** True if the manifest is valid (no errors). */
  valid: boolean;
  /** List of validation errors. Empty if valid. */
  errors: ManifestValidationError[];
}

// ---- Constants ----

const VALID_TRUST_TIERS: PluginTrustTier[] = ["internal", "community", "mcp"];

/** Basic semver pattern: MAJOR.MINOR.PATCH with optional pre-release suffix. */
const SEMVER_PATTERN = /^\d+\.\d+\.\d+/;

/** SHA-256 hex digest: exactly 64 hexadecimal characters. */
const SHA256_HEX_PATTERN = /^[0-9a-fA-F]{64}$/;

// ---- Helpers ----

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

// ---- Contribution Validators ----

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

function validatePermissions(
  permissions: unknown,
  errors: ManifestValidationError[],
): void {
  if (!Array.isArray(permissions)) {
    errors.push({
      field: "permissions",
      message: '"permissions" must be an array',
    });
    return;
  }

  for (let i = 0; i < permissions.length; i++) {
    const entry = permissions[i];

    if (typeof entry === "string") {
      // String permission -- check against KNOWN_PERMISSIONS
      if (!KNOWN_PERMISSIONS.has(entry)) {
        errors.push({
          field: `permissions[${i}]`,
          message: `unknown permission "${entry}" -- valid permissions: ${[...KNOWN_PERMISSIONS].join(", ")}`,
        });
      }
    } else if (
      entry !== null &&
      typeof entry === "object" &&
      !Array.isArray(entry)
    ) {
      // Object permission -- validate NetworkPermission shape
      const obj = entry as Record<string, unknown>;

      if (obj.type !== "network:fetch") {
        errors.push({
          field: `permissions[${i}].type`,
          message: `unknown permission type "${String(obj.type)}" -- only "network:fetch" is supported`,
        });
        continue;
      }

      if (!Array.isArray(obj.allowedDomains)) {
        errors.push({
          field: `permissions[${i}].allowedDomains`,
          message: `"permissions[${i}].allowedDomains" must be a non-empty array of strings`,
        });
      } else if (obj.allowedDomains.length === 0) {
        errors.push({
          field: `permissions[${i}].allowedDomains`,
          message: `"permissions[${i}].allowedDomains" must not be empty -- specify at least one domain`,
        });
      } else if (
        !obj.allowedDomains.every((d: unknown) => typeof d === "string")
      ) {
        errors.push({
          field: `permissions[${i}].allowedDomains`,
          message: `"permissions[${i}].allowedDomains" must be an array of strings`,
        });
      }
    } else {
      errors.push({
        field: `permissions[${i}]`,
        message: `permissions[${i}] must be a string permission or NetworkPermission object`,
      });
    }
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

// ---- Main Validator ----

/**
 * Validate a PluginManifest at runtime.
 *
 * Checks all required fields, validates the version is semver,
 * validates the trust tier, and recursively validates contribution
 * points and installation metadata if present.
 *
 * All errors are accumulated (not short-circuited).
 *
 * @param input - The value to validate (typically parsed JSON or a manifest object)
 * @returns Validation result with `valid` flag and accumulated `errors`
 */
export function validateManifest(input: unknown): ManifestValidationResult {
  const errors: ManifestValidationError[] = [];

  // Must be a non-null object
  if (!isNonNullObject(input)) {
    errors.push({
      field: "(root)",
      message: "Manifest must be a non-null object",
    });
    return { valid: false, errors };
  }

  // Required string fields
  requireString(input, "id", errors);
  requireString(input, "name", errors);
  requireString(input, "displayName", errors);
  requireString(input, "description", errors);
  requireString(input, "publisher", errors);

  // Version: must be a non-empty string matching semver
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

  // Trust tier
  if (!VALID_TRUST_TIERS.includes(input.trust as PluginTrustTier)) {
    errors.push({
      field: "trust",
      message: `"trust" must be one of: ${VALID_TRUST_TIERS.join(", ")}`,
    });
  }

  // Categories (optional but if present must be string array)
  if (input.categories !== undefined && !isStringArray(input.categories)) {
    errors.push({
      field: "categories",
      message: '"categories" must be an array of strings',
    });
  }

  // Activation events
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

  // Contributions (optional, validate recursively if present)
  if (input.contributions !== undefined) {
    validateContributions(input.contributions, errors);
  }

  // Permissions (optional, validate if present)
  if (input.permissions !== undefined) {
    validatePermissions(input.permissions, errors);
  }

  // Installation metadata (optional, validate recursively if present)
  if (input.installation !== undefined) {
    validateInstallation(input.installation, errors);
  }

  return { valid: errors.length === 0, errors };
}

// ---- Test Helper ----

/**
 * Create a valid minimal PluginManifest for testing purposes.
 * Override any field by passing partial overrides.
 */
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
