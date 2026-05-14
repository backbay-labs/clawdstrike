import { useState, useCallback } from "react";
import type { FileType } from "../file-type-registry";
import type { TranslationResult } from "./shared-types";
import { chainTranslation, getTranslatableTargets } from "./translations";

export interface UseTranslationReturn {
  /** Invoke a translation from source text to target format. */
  translate(source: string, sourceFileType: FileType, targetFileType: FileType): Promise<TranslationResult>;
  /** Whether a translation is currently in progress. */
  translating: boolean;
  /** The most recent translation result, or null. */
  result: TranslationResult | null;
  /** Clear the current result. */
  clearResult(): void;
  /** Get all formats the given file type can be translated to. */
  getTargets(fileType: FileType): FileType[];
}

export function useTranslation(): UseTranslationReturn {
  const [translating, setTranslating] = useState(false);
  const [result, setResult] = useState<TranslationResult | null>(null);

  const translate = useCallback(
    async (source: string, sourceFileType: FileType, targetFileType: FileType): Promise<TranslationResult> => {
      setTranslating(true);
      try {
        const translationResult = await chainTranslation({
          source,
          sourceFileType,
          targetFileType,
        });
        setResult(translationResult);
        return translationResult;
      } catch (err) {
        const errorResult: TranslationResult = {
          success: false,
          output: null,
          diagnostics: [{
            severity: "error",
            message: err instanceof Error ? err.message : "Translation failed",
          }],
          fieldMappings: [],
          untranslatableFeatures: [],
        };
        setResult(errorResult);
        return errorResult;
      } finally {
        setTranslating(false);
      }
    },
    [],
  );

  const clearResult = useCallback(() => setResult(null), []);

  const getTargets = useCallback(
    (fileType: FileType): FileType[] => getTranslatableTargets(fileType),
    [],
  );

  return { translate, translating, result, clearResult, getTargets };
}
