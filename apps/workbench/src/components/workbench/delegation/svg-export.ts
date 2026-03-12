const SAFE_SVG_TAGS = new Set([
  "circle",
  "defs",
  "desc",
  "ellipse",
  "g",
  "line",
  "marker",
  "path",
  "pattern",
  "polygon",
  "polyline",
  "rect",
  "svg",
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

function sanitizeStyle(styleText: string): string | null {
  const safeDeclarations = styleText
    .split(";")
    .map((declaration) => declaration.trim())
    .filter(Boolean)
    .flatMap((declaration) => {
      const separatorIndex = declaration.indexOf(":");
      if (separatorIndex === -1) {
        return [];
      }

      const property = declaration.slice(0, separatorIndex).trim();
      const value = declaration.slice(separatorIndex + 1).trim();
      const normalizedValue = value.toLowerCase();

      if (
        containsBlockedProtocol(value) ||
        normalizedValue.includes("url(") ||
        normalizedValue.includes("expression(")
      ) {
        return [];
      }

      return [`${property}: ${value}`];
    });

  return safeDeclarations.length > 0 ? safeDeclarations.join("; ") : null;
}

function sanitizeSvgElement(element: Element) {
  const tagName = element.tagName.toLowerCase();
  if (!SAFE_SVG_TAGS.has(tagName)) {
    element.remove();
    return;
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
}

export function sanitizeDelegationSvgForExport(svgElement: SVGSVGElement): SVGSVGElement {
  const sanitized = svgElement.cloneNode(true) as SVGSVGElement;

  for (const element of [sanitized, ...Array.from(sanitized.querySelectorAll("*"))]) {
    sanitizeSvgElement(element);
  }

  return sanitized;
}
