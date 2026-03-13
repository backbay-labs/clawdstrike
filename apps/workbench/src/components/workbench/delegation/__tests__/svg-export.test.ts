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

  it("preserves safe local url() references inside inline styles", () => {
    const input = makeSvg(`
      <svg xmlns="http://www.w3.org/2000/svg">
        <defs>
          <linearGradient id="gradient">
            <stop offset="0%" stop-color="#fff" />
            <stop offset="100%" stop-color="#000" />
          </linearGradient>
          <filter id="glow">
            <feGaussianBlur stdDeviation="2" />
          </filter>
        </defs>
        <rect
          id="safe-fill"
          style="fill: url(#gradient); filter: url(#glow); stroke: url(https://evil.example/stroke.svg); opacity: 0.8"
          width="10"
          height="10"
        />
      </svg>
    `);

    const sanitized = sanitizeDelegationSvgForExport(input);
    const rect = sanitized.querySelector("#safe-fill");

    expect(rect?.getAttribute("style")).toContain("fill: url(#gradient)");
    expect(rect?.getAttribute("style")).toContain("filter: url(#glow)");
    expect(rect?.getAttribute("style")).toContain("opacity: 0.8");
    expect(rect?.getAttribute("style")).not.toContain("https://evil.example");
    expect(sanitized.querySelector("linearGradient")).not.toBeNull();
    expect(sanitized.querySelector("feGaussianBlur")).not.toBeNull();
  });

  it("preserves safe local url() references for non-presentation style properties", () => {
    const input = makeSvg(`
      <svg xmlns="http://www.w3.org/2000/svg">
        <defs>
          <pattern id="grid" width="4" height="4" patternUnits="userSpaceOnUse">
            <path d="M 4 0 L 0 0 0 4" fill="none" stroke="#333" stroke-width="1" />
          </pattern>
        </defs>
        <rect
          id="safe-background"
          style="background-image: url(#grid); fill: url(https://evil.example/fill.svg)"
          width="10"
          height="10"
        />
      </svg>
    `);

    const sanitized = sanitizeDelegationSvgForExport(input);
    const rect = sanitized.querySelector("#safe-background");

    expect(rect?.getAttribute("style")).toContain("background-image: url(#grid)");
    expect(rect?.getAttribute("style")).not.toContain("https://evil.example");
    expect(sanitized.querySelector("pattern")).not.toBeNull();
  });

  it("keeps parsing style declarations when url() values contain semicolons", () => {
    const input = makeSvg(`
      <svg xmlns="http://www.w3.org/2000/svg">
        <defs>
          <pattern id="grid" width="4" height="4" patternUnits="userSpaceOnUse">
            <path d="M 4 0 L 0 0 0 4" fill="none" stroke="#333" stroke-width="1" />
          </pattern>
        </defs>
        <rect
          id="semicolon-style"
          style='background-image: url("data:image/svg+xml;base64,PHN2Zz47PC9zdmc+"); fill: url(#grid); opacity: 0.8'
          width="10"
          height="10"
        />
      </svg>
    `);

    const sanitized = sanitizeDelegationSvgForExport(input);
    const rect = sanitized.querySelector("#semicolon-style");
    const style = rect?.getAttribute("style") ?? "";

    expect(style).toContain("fill: url(#grid)");
    expect(style).toContain("opacity: 0.8");
    expect(style).not.toContain("data:image/svg+xml");
  });

  it("drops feImage filter primitives from exported SVGs", () => {
    const input = makeSvg(`
      <svg xmlns="http://www.w3.org/2000/svg">
        <defs>
          <filter id="fx">
            <feImage href="https://evil.example/payload.png" />
            <feGaussianBlur stdDeviation="2" />
          </filter>
        </defs>
      </svg>
    `);

    const sanitized = sanitizeDelegationSvgForExport(input);

    expect(sanitized.querySelector("feImage")).toBeNull();
    expect(sanitized.querySelector("feGaussianBlur")).not.toBeNull();
  });

  it("removes unsafe parent subtrees without disturbing safe siblings", () => {
    const input = makeSvg(`
      <svg xmlns="http://www.w3.org/2000/svg">
        <g id="safe-sibling">
          <path id="safe-path" d="M0 0 L10 10" />
        </g>
        <foreignObject id="unsafe-parent">
          <div xmlns="http://www.w3.org/1999/xhtml">
            <span id="unsafe-child">bad</span>
          </div>
        </foreignObject>
      </svg>
    `);

    const sanitized = sanitizeDelegationSvgForExport(input);

    expect(sanitized.querySelector("#safe-sibling")).not.toBeNull();
    expect(sanitized.querySelector("#safe-path")).not.toBeNull();
    expect(sanitized.querySelector("#unsafe-parent")).toBeNull();
    expect(sanitized.querySelector("#unsafe-child")).toBeNull();
  });
});
