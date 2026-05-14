import type { ScaffoldOptions } from "../types";
import { guardSourceTemplate } from "./guard";
import { detectionSourceTemplate } from "./detection";
import { uiSourceTemplate } from "./ui";
import { intelSourceTemplate } from "./intel";
import { complianceSourceTemplate } from "./compliance";
import { fullSourceTemplate } from "./full";

// Re-export test template for single import path
export { getTestTemplate } from "./test";

export function getSourceTemplate(options: ScaffoldOptions): string {
  switch (options.type) {
    case "guard":
      return guardSourceTemplate(options);
    case "detection":
      return detectionSourceTemplate(options);
    case "ui":
      return uiSourceTemplate(options);
    case "intel":
      return intelSourceTemplate(options);
    case "compliance":
      return complianceSourceTemplate(options);
    case "full":
      return fullSourceTemplate(options);
    default:
      throw new Error(`Unknown plugin type: ${options.type}`);
  }
}
