const SAFE_SVG_TAGS = new Set([
  "clippath",
  "circle",
  "defs",
  "desc",
  "ellipse",
  "feblend",
  "fecolormatrix",
  "fecomponenttransfer",
  "fecomposite",
  "fediffuselighting",
  "fedisplacementmap",
  "fedistantlight",
  "fedropshadow",
  "feflood",
  "fefunca",
  "fefuncb",
  "fefuncg",
  "fefuncr",
  "fegaussianblur",
  "femerge",
  "femergenode",
  "femorphology",
  "feoffset",
  "fepointlight",
  "fespecularlighting",
  "fespotlight",
  "fetile",
  "feturbulence",
  "filter",
  "g",
  "line",
  "lineargradient",
  "marker",
  "mask",
  "path",
  "pattern",
  "polygon",
  "polyline",
  "radialgradient",
  "rect",
  "svg",
  "stop",
  "text",
  "title",
  "tspan",
]);

const LOCAL_REFERENCE_ATTRS = new Set([
  "clip-path",
  "fill",
  "filter",
  "marker-end",
  "marker-mid",
  "marker-start",
  "mask",
  "stroke",
]);

const LINK_ATTRS = new Set(["href", "xlink:href"]);
const BLOCKED_PROTOCOLS = ["javascript:", "vbscript:", "data:text/html"];

function containsBlockedProtocol(value: string): boolean {
  const normalized = value.replace(/\s+/g, "").toLowerCase();
  return BLOCKED_PROTOCOLS.some((protocol) => normalized.includes(protocol));
}

function isSafeLocalReference(value: string): boolean {
  return /^url\(\s*#[^)]+\s*\)$/i.test(value.trim());
}

function hasOnlySafeLocalStyleReferences(value: string): boolean {
  if (!value.toLowerCase().includes("url(")) {
    return true;
  }

  const references = value.match(/url\(([^)]+)\)/gi);
  return references !== null && references.every((reference) => isSafeLocalReference(reference));
}

function splitStyleDeclarations(styleText: string): string[] {
  const declarations: string[] = [];
  let current = "";
  let quote: '"' | "'" | null = null;
  let parenthesisDepth = 0;
  let escaped = false;

  for (const char of styleText) {
    if (escaped) {
      current += char;
      escaped = false;
      continue;
    }

    if (quote) {
      current += char;
      if (char === "\\") {
        escaped = true;
      } else if (char === quote) {
        quote = null;
      }
      continue;
    }

    if (char === '"' || char === "'") {
      quote = char;
      current += char;
      continue;
    }

    if (char === "(") {
      parenthesisDepth += 1;
      current += char;
      continue;
    }

    if (char === ")" && parenthesisDepth > 0) {
      parenthesisDepth -= 1;
      current += char;
      continue;
    }

    if (char === ";" && parenthesisDepth === 0) {
      const declaration = current.trim();
      if (declaration) {
        declarations.push(declaration);
      }
      current = "";
      continue;
    }

    current += char;
  }

  const trailingDeclaration = current.trim();
  if (trailingDeclaration) {
    declarations.push(trailingDeclaration);
  }

  return declarations;
}

function sanitizeStyle(styleText: string): string | null {
  const safeDeclarations = splitStyleDeclarations(styleText)
    .map((declaration) => declaration.trim())
    .filter(Boolean)
    .flatMap((declaration) => {
      const separatorIndex = declaration.indexOf(":");
      if (separatorIndex === -1) {
        return [];
      }

      const value = declaration.slice(separatorIndex + 1).trim();
      const normalizedValue = value.toLowerCase();

      if (
        containsBlockedProtocol(value) ||
        !hasOnlySafeLocalStyleReferences(value) ||
        normalizedValue.includes("expression(")
      ) {
        return [];
      }

      const property = declaration.slice(0, separatorIndex).trim();
      return [`${property}: ${value}`];
    });

  return safeDeclarations.length > 0 ? safeDeclarations.join("; ") : null;
}

function sanitizeSvgElement(element: Element): boolean {
  const tagName = element.tagName.toLowerCase();
  if (!SAFE_SVG_TAGS.has(tagName)) {
    element.remove();
    return false;
  }

  for (const attribute of Array.from(element.attributes)) {
    const name = attribute.name.toLowerCase();
    const value = attribute.value.trim();

    if (name.startsWith("on") || containsBlockedProtocol(value)) {
      element.removeAttribute(attribute.name);
      continue;
    }

    if (name === "src") {
      element.removeAttribute(attribute.name);
      continue;
    }

    if (LINK_ATTRS.has(name) && value !== "" && !value.startsWith("#")) {
      element.removeAttribute(attribute.name);
      continue;
    }

    if (LOCAL_REFERENCE_ATTRS.has(name) && value.includes("url(") && !isSafeLocalReference(value)) {
      element.removeAttribute(attribute.name);
      continue;
    }

    if (name === "style") {
      const sanitizedStyle = sanitizeStyle(value);
      if (sanitizedStyle) {
        element.setAttribute(attribute.name, sanitizedStyle);
      } else {
        element.removeAttribute(attribute.name);
      }
    }
  }

  return true;
}

function sanitizeSvgSubtree(element: Element) {
  if (!sanitizeSvgElement(element)) {
    return;
  }

  for (const child of Array.from(element.children)) {
    sanitizeSvgSubtree(child);
  }
}

export function sanitizeDelegationSvgForExport(svgElement: SVGSVGElement): SVGSVGElement {
  const sanitized = svgElement.cloneNode(true) as SVGSVGElement;
  sanitizeSvgSubtree(sanitized);

  return sanitized;
}
