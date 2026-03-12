import { describe, expect, it } from "vitest";

import { sanitizeDelegationSvgForExport } from "../svg-export";

function makeSvg(markup: string): SVGSVGElement {
  const container = document.createElement("div");
  container.innerHTML = markup.trim();
  return container.firstElementChild as SVGSVGElement;
}

describe("sanitizeDelegationSvgForExport", () => {
  it("removes unsafe elements and attributes while keeping safe local refs", () => {
    const input = makeSvg(`
      <svg xmlns="http://www.w3.org/2000/svg" style="background: #05060a">
        <defs>
          <marker id="arrow"><path d="M0 0 L6 3 L0 6 Z" /></marker>
        </defs>
        <script>alert(1)</script>
        <g id="safe-group" onclick="alert(1)" style="opacity: 0.8; background-image: url(javascript:alert(1))">
          <path id="safe-edge" marker-end="url(#arrow)" />
          <path id="unsafe-edge" marker-start="url(https://evil.example/marker.svg)" />
          <a href="javascript:alert(1)">
            <text>Hello</text>
          </a>
          <use xlink:href="https://evil.example/icon.svg" />
        </g>
        <foreignObject><div>bad</div></foreignObject>
      </svg>
    `);

    const sanitized = sanitizeDelegationSvgForExport(input);

    expect(sanitized.querySelector("script")).toBeNull();
    expect(sanitized.querySelector("foreignObject")).toBeNull();

    const group = sanitized.querySelector("#safe-group");
    expect(group?.getAttribute("onclick")).toBeNull();

    const safePath = sanitized.querySelector("#safe-edge");
    const unsafePath = sanitized.querySelector("#unsafe-edge");
    expect(safePath?.getAttribute("marker-end")).toBe("url(#arrow)");
    expect(unsafePath?.getAttribute("marker-start")).toBeNull();

    const link = sanitized.querySelector("a");
    expect(link).toBeNull();

    const use = sanitized.querySelector("use");
    expect(use).toBeNull();

    expect(sanitized.outerHTML.toLowerCase()).not.toContain("javascript:");
    expect(sanitized.outerHTML.toLowerCase()).not.toContain("onclick");
  });
});
