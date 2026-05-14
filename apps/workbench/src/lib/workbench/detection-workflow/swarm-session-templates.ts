/**
 * Swarm session templates for detection workflow operations.
 *
 * Provides pre-configured session templates that map to common detection
 * engineering workflows: review, harden, publish, and convert.
 */

import type { FileType } from "../file-type-registry";
import { FILE_TYPE_REGISTRY } from "../file-type-registry";
import type { DetectionArtifactKind } from "../swarm-board-types";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SwarmSessionTemplate {
  id: string;
  name: string;
  description: string;
  kind: "review" | "harden" | "publish" | "convert";
  commands: string[];
  artifactKinds: DetectionArtifactKind[];
}

// ---------------------------------------------------------------------------
// Template definitions
// ---------------------------------------------------------------------------

function reviewTemplate(format: FileType): SwarmSessionTemplate {
  const desc = FILE_TYPE_REGISTRY[format];
  return {
    id: `review-${format}`,
    name: `Review ${desc.shortLabel}`,
    description: `Open and validate a ${desc.label} file, checking for syntax errors and best practice violations.`,
    kind: "review",
    commands: [
      `echo "=== ${desc.label} Review ==="`,
      `echo "Validating ${desc.shortLabel.toLowerCase()} syntax..."`,
    ],
    artifactKinds: ["detection_rule"],
  };
}

function hardenTemplate(format: FileType): SwarmSessionTemplate {
  const desc = FILE_TYPE_REGISTRY[format];
  return {
    id: `harden-${format}`,
    name: `Harden ${desc.shortLabel}`,
    description: `Run lab tests against a ${desc.label} and suggest improvements to reduce false positives.`,
    kind: "harden",
    commands: [
      `echo "=== ${desc.label} Hardening ==="`,
      `echo "Running evidence pack tests..."`,
      `echo "Analyzing false positive rate..."`,
    ],
    artifactKinds: ["detection_rule", "evidence_pack", "lab_run"],
  };
}

function publishTemplate(format: FileType): SwarmSessionTemplate {
  const desc = FILE_TYPE_REGISTRY[format];
  return {
    id: `publish-${format}`,
    name: `Publish ${desc.shortLabel}`,
    description: `Validate, run lab gate, and publish a ${desc.label} to the target platform.`,
    kind: "publish",
    commands: [
      `echo "=== ${desc.label} Publication ==="`,
      `echo "Step 1: Validating..."`,
      `echo "Step 2: Running lab gate..."`,
      `echo "Step 3: Building publication manifest..."`,
    ],
    artifactKinds: ["detection_rule", "publication_manifest"],
  };
}

function convertTemplate(sourceFormat: FileType): SwarmSessionTemplate {
  const desc = FILE_TYPE_REGISTRY[sourceFormat];
  const targets = desc.convertibleTo;
  const targetNames = targets.map((t) => FILE_TYPE_REGISTRY[t].shortLabel).join(", ");

  return {
    id: `convert-${sourceFormat}`,
    name: `Convert ${desc.shortLabel}`,
    description: `Convert a ${desc.label} to another format (${targetNames || "none available"}).`,
    kind: "convert",
    commands: [
      `echo "=== ${desc.label} Conversion ==="`,
      `echo "Available targets: ${targetNames || "none"}"`,
    ],
    artifactKinds: ["detection_rule", "conversion_output"],
  };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Get all session templates applicable to a given artifact kind.
 */
export function getSessionTemplates(artifactKind: DetectionArtifactKind): SwarmSessionTemplate[] {
  const allFormats: FileType[] = ["clawdstrike_policy", "sigma_rule", "yara_rule", "ocsf_event"];
  const allTemplates: SwarmSessionTemplate[] = [];

  for (const format of allFormats) {
    allTemplates.push(
      reviewTemplate(format),
      hardenTemplate(format),
      publishTemplate(format),
    );
    // Only add convert template if the format has conversion targets
    if (FILE_TYPE_REGISTRY[format].convertibleTo.length > 0) {
      allTemplates.push(convertTemplate(format));
    }
  }

  return allTemplates.filter((t) => t.artifactKinds.includes(artifactKind));
}

/**
 * Get the review template for a specific file type.
 */
export function getReviewTemplate(format: FileType): SwarmSessionTemplate {
  return reviewTemplate(format);
}

/**
 * Get the publish template for a specific file type.
 */
export function getPublishTemplate(format: FileType): SwarmSessionTemplate {
  return publishTemplate(format);
}

/**
 * Get the harden template for a specific file type.
 */
export function getHardenTemplate(format: FileType): SwarmSessionTemplate {
  return hardenTemplate(format);
}

/**
 * Get the convert template for a specific file type.
 */
export function getConvertTemplate(format: FileType): SwarmSessionTemplate {
  return convertTemplate(format);
}
