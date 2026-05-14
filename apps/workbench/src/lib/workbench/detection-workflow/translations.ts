import type { FileType } from "../file-type-registry";
import type { TranslationProvider, TranslationRequest, TranslationResult } from "./shared-types";
import { getRegisteredFileTypes } from "./adapters";


const providers: TranslationProvider[] = [];

/**
 * Register a translation provider.
 * Returns a dispose function that removes the provider from the registry.
 */
export function registerTranslationProvider(provider: TranslationProvider): () => void {
  providers.push(provider);
  return () => {
    const idx = providers.indexOf(provider);
    if (idx !== -1) {
      providers.splice(idx, 1);
    }
  };
}

/**
 * Find a translation provider that can translate from one file type to another.
 * Returns the first matching provider, or null if none can handle the pair.
 */
export function getTranslationPath(
  from: FileType,
  to: FileType,
): TranslationProvider | null {
  for (const provider of providers) {
    if (provider.canTranslate(from, to)) {
      return provider;
    }
  }
  return null;
}

/**
 * Get all registered translation providers (shallow copy for enumeration).
 */
export function getAllTranslationProviders(): readonly TranslationProvider[] {
  return [...providers];
}

/**
 * Get all file types that can be translated from the given source file type.
 *
 * @param from - The source file type to translate from.
 * @param allFileTypes - Optional list of file types to check against.
 *   Defaults to all file types with registered adapters.
 * @returns Array of file types that at least one provider can translate to.
 */
export function getTranslatableTargets(
  from: FileType,
  allFileTypes?: FileType[],
): FileType[] {
  const candidates = allFileTypes ?? getRegisteredFileTypes();
  const targets: FileType[] = [];
  for (const to of candidates) {
    if (to === from) continue;
    if (getTranslationPath(from, to) !== null) {
      targets.push(to);
    }
  }
  return targets;
}

/**
 * Chain translation through Sigma as hub for multi-hop routing.
 * If a direct provider exists for (from, to), uses it directly.
 * Otherwise, tries two-hop: from -> sigma_rule -> to.
 * Returns the combined TranslationResult with merged diagnostics,
 * fieldMappings, and untranslatableFeatures from both hops.
 */
export async function chainTranslation(
  request: TranslationRequest,
): Promise<TranslationResult> {
  const { source, sourceFileType, targetFileType } = request;

  // Try direct path first
  const direct = getTranslationPath(sourceFileType, targetFileType);
  if (direct) {
    return direct.translate(request);
  }

  // Try two-hop through Sigma: source -> sigma_rule -> target
  const SIGMA: FileType = "sigma_rule";
  if (sourceFileType === SIGMA || targetFileType === SIGMA) {
    // One side is already Sigma but no direct provider found
    return {
      success: false,
      output: null,
      diagnostics: [{ severity: "error", message: `No translation provider for ${sourceFileType} -> ${targetFileType}` }],
      fieldMappings: [],
      untranslatableFeatures: [],
    };
  }

  const hop1Provider = getTranslationPath(sourceFileType, SIGMA);
  const hop2Provider = getTranslationPath(SIGMA, targetFileType);

  if (!hop1Provider || !hop2Provider) {
    const missing = !hop1Provider ? `${sourceFileType} -> sigma_rule` : `sigma_rule -> ${targetFileType}`;
    return {
      success: false,
      output: null,
      diagnostics: [{ severity: "error", message: `No translation path: missing provider for ${missing}` }],
      fieldMappings: [],
      untranslatableFeatures: [],
    };
  }

  // Hop 1: source -> Sigma
  const hop1Result = await hop1Provider.translate({
    source,
    sourceFileType,
    targetFileType: SIGMA,
  });

  if (!hop1Result.success || !hop1Result.output) {
    return {
      success: false,
      output: null,
      diagnostics: [
        { severity: "info", message: `Multi-hop: ${sourceFileType} -> sigma_rule -> ${targetFileType}` },
        ...hop1Result.diagnostics,
      ],
      fieldMappings: hop1Result.fieldMappings,
      untranslatableFeatures: hop1Result.untranslatableFeatures,
    };
  }

  // Hop 2: Sigma -> target
  const hop2Result = await hop2Provider.translate({
    source: hop1Result.output,
    sourceFileType: SIGMA,
    targetFileType,
  });

  // Merge results from both hops
  return {
    success: hop2Result.success,
    output: hop2Result.output,
    diagnostics: [
      { severity: "info", message: `Routed via Sigma: ${sourceFileType} -> sigma_rule -> ${targetFileType}` },
      ...hop1Result.diagnostics.map(d => ({ ...d, message: `[hop 1] ${d.message}` })),
      ...hop2Result.diagnostics.map(d => ({ ...d, message: `[hop 2] ${d.message}` })),
    ],
    fieldMappings: [...hop1Result.fieldMappings, ...hop2Result.fieldMappings],
    untranslatableFeatures: [...hop1Result.untranslatableFeatures, ...hop2Result.untranslatableFeatures],
  };
}
