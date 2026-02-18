# 01 Browser Automation & Instrumentation

## Scope

Browser-first control plane for CUA: action execution, telemetry collection, semantic targeting, and deterministic evidence capture.

## What is already solid

- Browser-first MVP sequencing is correct for fast time-to-value.
- CDP-level telemetry and AX tree capture are the right basis for evidence-rich receipts.
- Keeping a strict gateway mediation layer (instead of trusting agent-side browser code) matches Clawdstrike's enforcement model.

## Corrections and caveats (2026-02-18)

- Treat WebDriver BiDi as evolving: design a capability matrix and fallback path per browser/runtime.
- Keep CDP sockets private to gateway internals; exposed CDP is effectively a privileged remote control channel.
- Avoid overfitting to CSS selectors; collect accessible role/name targets and URL/frame assertions for robustness.
- Include deterministic "post-condition checks" for every high-risk action because low-level input APIs can fail silently.

## Clawdstrike-specific integration suggestions

- Reuse existing receipt signing path and attach browser evidence as metadata (`clawdstrike.cua.*`) rather than creating a parallel receipt verifier.
- Map browser navigation/network actions into existing egress guard checks before adding new CUA-only policy syntax.
- Emit browser action/audit decisions via hushd audit pathways so SIEM export stays unified.

## Gaps for agent team to fill

- Capability matrix by browser + protocol (`CDP`, `WebDriver`, `BiDi`) with exact unsupported methods.
- Canonical selector strategy order: AX query -> stable test id -> CSS fallback.
- Failure taxonomy: protocol failure, policy deny, post-condition mismatch, timeout, and replay mismatch.

## Suggested experiments

- Build a "double capture" action wrapper (pre/post screenshot + AX snapshot + hash chain append).
- Add fault injection: intentionally stale selector, changed URL, hidden element, and cross-origin iframe target.
- Benchmark action+evidence overhead across Chromium headless/headed modes.

## Primary references

- https://playwright.dev/docs/intro
- https://pptr.dev/webdriver-bidi
- https://w3c.github.io/webdriver-bidi/
- https://chromedevtools.github.io/devtools-protocol/tot/Accessibility/#method-getFullAXTree

## Pass #3 reviewer notes (2026-02-18)

- REVIEW-P3-CORRECTION: When selector and semantic target disagree, policy should force explicit deny/review rather than silently falling back to coordinates.
- REVIEW-P3-GAP-FILL: Add a deterministic action replay fixture set (same page state, same action, same expected evidence hashes) to detect instrumentation drift.
- REVIEW-P3-CORRECTION: Treat browser trace/screenshot artifacts as potentially sensitive by default; redaction policy must run before persistence and before external transport.

## Pass #3 execution criteria

- Every `computer.use` browser action includes: pre-hash, action record, post-hash, and policy decision id.
- Fallback path order is explicit and auditable (`AX -> stable id -> selector -> coordinate`) with reason codes.
- Protocol transport failures and policy denials emit distinct, machine-parseable audit outcomes.
- Replay test corpus detects nondeterministic evidence generation regressions.

---

> Research document for the Clawdstrike CUA Gateway project.
> Covers browser automation frameworks, browser instrumentation protocols, CDP proxies,
> accessibility capture, and their integration into the CUA evidence and policy pipeline.

---

## Table of Contents

1. [Overview](#overview)
2. [Playwright](#playwright)
   - [Architecture: Browser Server, Contexts, Pages, Frames](#playwright-architecture)
   - [Cross-Engine Support: Chromium, WebKit, Firefox](#playwright-cross-engine)
   - [Tracing API](#playwright-tracing)
   - [Screenshots](#playwright-screenshots)
   - [Accessibility: Snapshots and ARIA Matching](#playwright-accessibility)
   - [Playwright MCP Server](#playwright-mcp-server)
   - [Network Interception](#playwright-network-interception)
   - [Codegen and Test Generation](#playwright-codegen)
   - [Recent Versions (1.49+)](#playwright-recent-versions)
3. [Puppeteer](#puppeteer)
   - [CDP-Native Architecture](#puppeteer-architecture)
   - [WebDriver BiDi Transition](#puppeteer-bidi)
   - [Protocol-Level Telemetry](#puppeteer-telemetry)
   - [Firefox Support via BiDi](#puppeteer-firefox)
   - [Comparison with Playwright](#puppeteer-vs-playwright)
4. [Chrome DevTools Protocol (CDP)](#chrome-devtools-protocol)
   - [Domain Overview](#cdp-domains)
   - [Accessibility.getFullAXTree](#cdp-accessibility)
   - [Page.captureScreenshot](#cdp-screenshot)
   - [Input.dispatchMouseEvent / Input.dispatchKeyEvent](#cdp-input)
   - [Event Streaming and WebSocket Model](#cdp-events)
   - [DOM.getDocument and DOM.querySelector](#cdp-dom)
   - [Security: CDP Socket Exposure](#cdp-security)
5. [WebDriver BiDi (W3C)](#webdriver-bidi)
   - [Specification Status](#bidi-status)
   - [Modules](#bidi-modules)
   - [Bidirectional Event Model](#bidi-events)
   - [Browser Support Matrix](#bidi-browser-support)
   - [Advantages and Limitations](#bidi-tradeoffs)
6. [Selenium 4+](#selenium)
   - [WebDriver BiDi Integration](#selenium-bidi)
   - [Grid 4 Architecture](#selenium-grid)
   - [Cross-Browser Standardization](#selenium-cross-browser)
   - [When Selenium Grid Matters for CUA](#selenium-cua)
7. [chromedp (Go CDP Client)](#chromedp)
   - [Architecture: Context-Based Allocator Pattern](#chromedp-architecture)
   - [Key Operations](#chromedp-operations)
   - [CDP Event Handling in Go](#chromedp-events)
   - [Fit for Go-Based CUA Gateway](#chromedp-fit)
8. [CDP Proxies](#cdp-proxies)
   - [chromedp-proxy](#chromedp-proxy)
   - [cdp-proxy-interceptor](#cdp-proxy-interceptor)
   - [Policy Enforcement at Protocol Boundary](#cdp-proxy-policy)
9. [CUA Gateway Integration](#cua-gateway-integration)
   - [Browser-First Executor Architecture](#cua-executor)
   - [Evidence Capture Pipeline](#cua-evidence)
   - [Selector Strategy](#cua-selectors)
   - [Post-Condition Verification](#cua-postconditions)
   - [Failure Taxonomy](#cua-failures)
   - [Clawdstrike Receipt Integration](#cua-receipts)
   - [Egress Guard Integration](#cua-egress)
10. [Comparison Matrix](#comparison-matrix)
11. [Suggested Experiments (Detailed)](#experiments)
12. [References](#references)

---

## Overview

A CUA gateway that targets browser-based workflows has access to the richest instrumentation surface available to any desktop automation platform. Browsers expose:

1. **Structured DOM context** -- every element has a queryable tree position, attributes, and text content.
2. **Accessibility trees** -- semantic role, name, description, and state for every interactive element.
3. **Deterministic screenshot and tracing APIs** -- pixel-perfect evidence capture at arbitrary points.
4. **Network event streams** -- full request/response visibility for policy enforcement.
5. **Programmatic input dispatch** -- coordinate-level and element-level click, type, and scroll.

The browser-first MVP path leverages all five of these surfaces through a combination of high-level automation frameworks (Playwright, Puppeteer, Selenium) and low-level protocols (CDP, WebDriver BiDi). The gateway sits between the agent and the browser, mediating every action through policy checks and capturing evidence for receipts.

### Architecture Principle

The agent never holds a direct reference to a browser page or CDP socket. All browser interactions flow through the gateway:

```
Agent (untrusted)
    |
    +-- computer.use JSON-RPC request
    |
    v
CUA Gateway (policy + evidence + signing)
    |
    +-- Policy check (egress, action type, target validation)
    |
    +-- Pre-action evidence capture (screenshot + AX snapshot)
    |
    +-- Action execution (Playwright / CDP / chromedp)
    |
    +-- Post-action evidence capture
    |
    +-- Receipt construction (hash chain + metadata)
    |
    v
Browser Instance (Chromium / Firefox / WebKit)
    (controlled exclusively by gateway)
```

---

## Playwright

### Playwright Architecture

Playwright (Apache-2.0, Microsoft) is a browser automation framework with official bindings for TypeScript/JavaScript, Python, Java, and .NET. It controls browsers through a persistent WebSocket connection to browser-specific server processes.

**Layered object model:**

```
Playwright Instance
    |
    +-- Browser (one per engine: Chromium, Firefox, WebKit)
    |       |
    |       +-- BrowserContext (isolated session, equivalent to incognito profile)
    |       |       |
    |       |       +-- Page (single tab/window)
    |       |       |       |
    |       |       |       +-- Frame (main frame + iframes)
    |       |       |       |       |
    |       |       |       |       +-- Locators (element references)
    |       |       |       |
    |       |       |       +-- Request / Response (network events)
    |       |       |
    |       |       +-- Page (another tab)
    |       |
    |       +-- BrowserContext (another isolated session)
    |
    +-- Browser (another engine)
```

**Key architectural properties:**

| Component | Role | Isolation Level |
|-----------|------|-----------------|
| `Browser` | Controls a real browser process (Chromium, Firefox, or WebKit). One process per `Browser` instance. | Process-level |
| `BrowserContext` | Independent session with own cookies, localStorage, cache, permissions, viewport. Equivalent to an incognito profile. | Session-level |
| `Page` | A single tab within a context. Has its own DOM, JavaScript execution context, and network stack. | Tab-level |
| `Frame` | Main frame or iframe within a page. Each frame has its own document and execution context. | Document-level |

**BrowserContext isolation** is the key property for CUA: each agent session gets its own context, preventing cookie/storage leakage between sessions. Contexts are cheap to create (no browser restart) and fast to tear down.

**Browser server mode.** Playwright supports launching a browser server that exposes a WebSocket endpoint for remote connections:

```typescript
import { chromium } from 'playwright';

// Launch a browser server (gateway side)
const server = await chromium.launchServer({
  headless: true,
  port: 0,  // auto-assign
});
const wsEndpoint = server.wsEndpoint();
// wsEndpoint example: ws://127.0.0.1:43567/abc123

// Connect from another process
const browser = await chromium.connect(wsEndpoint);
const context = await browser.newContext();
const page = await context.newPage();
```

This server mode is directly applicable to CUA: the gateway launches the browser server, holds the WebSocket endpoint privately, and never exposes it to the agent.

### Playwright Cross-Engine

Playwright supports three browser engines with a single API:

| Engine | Upstream | Channel Option | CUA Notes |
|--------|----------|----------------|-----------|
| **Chromium** | Chrome for Testing (as of v1.57) | `channel: 'chrome'`, `channel: 'msedge'` | Primary target. Full CDP access. Best tooling. |
| **Firefox** | Custom Firefox build with Playwright patches | N/A (bundled) | Useful for cross-browser validation. No CDP; uses Playwright's internal protocol. |
| **WebKit** | WebKit trunk build | N/A (bundled) | Safari behavior testing. Limited to Playwright's own protocol. |

**Cross-engine caveats for CUA:**

- CDP-specific features (`Accessibility.getFullAXTree`, `Page.captureScreenshot` at protocol level) are only available on Chromium.
- Playwright's high-level APIs (`page.screenshot()`, `page.accessibility.snapshot()`) work across all engines, abstracting protocol differences.
- For the MVP, target Chromium exclusively and use Playwright's cross-engine support as a future extension path.

### Playwright Tracing

Playwright's Tracing API captures a comprehensive record of browser operations, network activity, and visual snapshots during test execution.

**Starting and stopping traces:**

```typescript
const context = await browser.newContext();

// Start tracing with screenshots and DOM snapshots
await context.tracing.start({
  screenshots: true,
  snapshots: true,
  sources: true,   // include source code in trace
});

const page = await context.newPage();
await page.goto('https://example.com');
await page.click('button#submit');

// Stop and save trace
await context.tracing.stop({
  path: 'trace.zip',
});
```

**Trace chunks** allow multiple traces within a single context:

```typescript
await context.tracing.start({ screenshots: true, snapshots: true });

// First action sequence
await context.tracing.startChunk();
await page.goto('https://example.com/step1');
await context.tracing.stopChunk({ path: 'trace-step1.zip' });

// Second action sequence
await context.tracing.startChunk();
await page.click('#next');
await context.tracing.stopChunk({ path: 'trace-step2.zip' });

await context.tracing.stop();
```

**Trace viewer** is a built-in GUI that loads trace files locally in the browser:

```bash
npx playwright show-trace trace.zip
```

The trace viewer provides:
- Timeline of actions with screenshots at each step
- DOM snapshots (before and after each action)
- Network request log with timing
- Console output
- Source code context

**HAR recording** captures network traffic in HTTP Archive format:

```typescript
const context = await browser.newContext({
  recordHar: {
    path: 'network.har',
    mode: 'minimal',  // or 'full' for response bodies
    urlFilter: /api\/.*/,  // optional URL filter
  },
});

// ... perform actions ...

// HAR is saved when context closes
await context.close();
```

**CUA relevance:**

- Traces serve as rich evidence artifacts for receipts (screenshots + DOM snapshots + network log in a single archive).
- Trace chunks align naturally with per-action evidence capture: one chunk per `computer.use` action.
- HAR recordings enable network-level audit without separate tooling.
- Trace artifacts are self-contained zip files that can be hashed for tamper evidence.

### Playwright Screenshots

Playwright provides multiple screenshot capture methods:

**Full-page screenshot:**

```typescript
// Capture the entire scrollable page
await page.screenshot({
  path: 'full-page.png',
  fullPage: true,
});
```

**Viewport screenshot (default):**

```typescript
// Capture only the visible viewport
await page.screenshot({
  path: 'viewport.png',
});
```

**Clipped region:**

```typescript
// Capture a specific rectangular region
await page.screenshot({
  path: 'region.png',
  clip: { x: 100, y: 200, width: 600, height: 400 },
});
```

**Element screenshot:**

```typescript
// Capture a specific element
await page.locator('button#submit').screenshot({
  path: 'submit-button.png',
});
```

**Screenshot options reference:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `path` | string | -- | File path to save the image |
| `type` | `'png'` / `'jpeg'` | `'png'` | Image format |
| `quality` | number (0-100) | -- | JPEG/WebP quality (not applicable to PNG) |
| `fullPage` | boolean | `false` | Capture full scrollable page |
| `clip` | `{x, y, width, height}` | -- | Specific region (mutually exclusive with `fullPage`) |
| `omitBackground` | boolean | `false` | Transparent background (PNG only) |
| `mask` | Locator[] | -- | Elements to mask with pink overlay boxes |
| `maskColor` | string | `'#FF00FF'` | Color for masked regions |
| `scale` | `'css'` / `'device'` | `'device'` | Pixel scale |

**CUA evidence capture pattern:**

```typescript
async function captureEvidence(page: Page): Promise<{
  screenshot: Buffer;
  hash: string;
}> {
  const screenshot = await page.screenshot({ type: 'png' });
  const hash = crypto.createHash('sha256').update(screenshot).digest('hex');
  return { screenshot, hash: `sha256:${hash}` };
}
```

### Playwright Accessibility

Playwright provides two complementary accessibility APIs: programmatic snapshots and ARIA snapshot matching.

**Accessibility snapshot (`page.accessibility.snapshot()`):**

```typescript
const snapshot = await page.accessibility.snapshot();
// Returns a tree structure:
// {
//   role: 'WebArea',
//   name: 'Example Page',
//   children: [
//     { role: 'heading', name: 'Welcome', level: 1 },
//     { role: 'button', name: 'Submit', focused: true },
//     { role: 'textbox', name: 'Email', value: 'user@example.com' },
//     ...
//   ]
// }

// Snapshot rooted at a specific element
const buttonSnapshot = await page.accessibility.snapshot({
  root: page.locator('form#login'),
});
```

**Snapshot properties per node:**

| Property | Type | Description |
|----------|------|-------------|
| `role` | string | ARIA role (`button`, `textbox`, `heading`, `link`, ...) |
| `name` | string | Accessible name (label text, aria-label, etc.) |
| `value` | string | Current value (text fields, sliders) |
| `description` | string | Accessible description |
| `checked` | boolean/`'mixed'` | Checkbox/radio state |
| `disabled` | boolean | Whether element is disabled |
| `expanded` | boolean | Expandable element state |
| `focused` | boolean | Whether element has keyboard focus |
| `level` | number | Heading level (1-6) |
| `pressed` | boolean/`'mixed'` | Toggle button state |
| `selected` | boolean | Selection state |
| `children` | AXNode[] | Child nodes in the accessibility tree |

**ARIA snapshot matching (introduced in v1.49):**

Playwright introduced ARIA snapshot testing that uses a YAML-based template language for asserting accessibility tree structure:

```typescript
// Assert that a form has the expected accessible structure
await expect(page.locator('form#login')).toMatchAriaSnapshot(`
  - textbox "Email"
  - textbox "Password"
  - button "Sign In"
  - link "Forgot password?"
`);
```

**ARIA snapshot features:**

- **Partial matching**: Omit attributes or children to match only what matters.
- **Regex support**: `- button /Submit|Send/` matches either name.
- **Hierarchical nesting**: Indentation represents parent-child relationships.
- **Auto-generation**: Playwright codegen can generate ARIA snapshot assertions automatically.

**CUA receipt value.** The accessibility snapshot serves multiple purposes in the CUA pipeline:

1. **Semantic target resolution**: Find elements by role+name instead of CSS selectors.
2. **Pre-action context**: Hash the AX tree before action for tamper-evident evidence.
3. **Post-condition verification**: After clicking "Submit", verify the AX tree contains "Success" or expected new state.
4. **Anti-clickjacking**: Compare the AX tree target at coordinates (x, y) against the agent's declared intent.

```typescript
// CUA pattern: verify target before clicking
async function verifiedClick(
  page: Page,
  target: { role: string; name: string },
  coordinates: { x: number; y: number }
): Promise<{ axTarget: object; match: boolean }> {
  // Get the AX node at the target coordinates
  const snapshot = await page.accessibility.snapshot();
  const nodeAtCoords = findNodeAtPoint(snapshot, coordinates);

  const match = nodeAtCoords?.role === target.role
             && nodeAtCoords?.name === target.name;

  if (!match) {
    // REVIEW-P3-CORRECTION: deny/review, do not silently fall back
    throw new PolicyDenyError('ax_target_mismatch', {
      expected: target,
      actual: nodeAtCoords,
      coordinates,
    });
  }

  await page.click(`role=${target.role}[name="${target.name}"]`);
  return { axTarget: nodeAtCoords, match };
}
```

### Playwright MCP Server

The Playwright MCP (Model Context Protocol) Server, released by Microsoft in March 2025, exposes Playwright browser automation capabilities as tools for LLM agents via the MCP protocol.

**What it provides:**

- A standardized MCP server that AI agents (Claude, GitHub Copilot, etc.) can connect to.
- Tools for browser navigation, interaction, screenshot capture, and assertion.
- Accessibility-first approach: relies on the browser's accessibility tree rather than screenshot-based visual interpretation.

**Architecture:**

```
LLM Agent (e.g., Claude, Copilot)
    |
    +-- MCP protocol (JSON-RPC over stdio/HTTP)
    |
    v
Playwright MCP Server
    |
    +-- Playwright API calls
    |
    v
Browser Instance (Chromium / Firefox / WebKit)
```

**Key tools exposed:**

| Tool | Description |
|------|-------------|
| `browser_navigate` | Navigate to a URL |
| `browser_click` | Click an element (by accessibility selector) |
| `browser_type` | Type text into an element |
| `browser_screenshot` | Capture a screenshot |
| `browser_snapshot` | Get accessibility tree snapshot |
| `browser_console_messages` | Read console log |
| `browser_tabs` | List and switch between tabs |
| `browser_pdf_save` | Save page as PDF |
| `browser_wait` | Wait for condition |

**Snapshot mode vs vision mode:**

- **Snapshot mode** (default): Agent receives accessibility tree YAML as context. Faster, more structured, lower token cost.
- **Vision mode**: Agent receives screenshots. Works when accessibility tree is incomplete.

**CUA gateway relevance:**

- The Playwright MCP Server demonstrates the accessibility-first interaction pattern recommended for CUA.
- Its tool interface maps closely to `computer.use` action kinds.
- For CUA, the gateway would implement a similar tool boundary but with policy enforcement, evidence capture, and receipt signing that the MCP server does not provide.
- The MCP server should not be exposed directly to untrusted agents; it provides no policy layer.

**Configuration example (Claude Desktop):**

```json
{
  "mcpServers": {
    "playwright": {
      "command": "npx",
      "args": ["@anthropic-ai/playwright-mcp", "--headless"]
    }
  }
}
```

### Playwright Network Interception

Playwright's `page.route()` and `context.route()` methods enable request interception at the browser level, which is directly applicable to CUA policy enforcement.

**Basic route interception:**

```typescript
// Block all requests to analytics domains
await page.route('**/*analytics*', (route) => route.abort());

// Fulfill with mock response
await page.route('**/api/user', (route) => {
  route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ name: 'Test User' }),
  });
});

// Modify request before sending
await page.route('**/api/**', (route) => {
  const headers = {
    ...route.request().headers(),
    'X-CUA-Gateway': 'true',
  };
  route.continue({ headers });
});
```

**CUA policy enforcement via route interception:**

```typescript
// Enforce egress allowlist at the browser level
async function enforceEgressPolicy(
  page: Page,
  allowedDomains: string[]
): Promise<void> {
  await page.route('**/*', (route) => {
    const url = new URL(route.request().url());
    const allowed = allowedDomains.some(
      (domain) => url.hostname === domain || url.hostname.endsWith(`.${domain}`)
    );

    if (!allowed) {
      // Log the denied request for receipt evidence
      auditLog.emit('egress_denied', {
        url: route.request().url(),
        method: route.request().method(),
        hostname: url.hostname,
      });
      route.abort('blockedbyclient');
      return;
    }

    route.continue();
  });
}
```

**Response modification for redaction:**

```typescript
// Redact sensitive fields from API responses before they reach the page
await page.route('**/api/profile', async (route) => {
  const response = await route.fetch();
  const body = await response.json();

  // Redact SSN, credit card, etc.
  body.ssn = '[REDACTED]';
  body.creditCard = '[REDACTED]';

  route.fulfill({
    response,
    body: JSON.stringify(body),
  });
});
```

**Integration with Clawdstrike egress guard:** The route interception layer should delegate domain allowlist decisions to the existing `EgressAllowlistGuard`, ensuring browser navigation and API calls are subject to the same policy as non-CUA network operations.

### Playwright Codegen

Playwright Codegen records browser interactions and generates automation scripts in multiple languages.

**Usage:**

```bash
# Launch codegen with a target URL
npx playwright codegen https://example.com

# Output in specific language
npx playwright codegen --target python https://example.com

# With specific viewport
npx playwright codegen --viewport-size=1280,720 https://example.com
```

**Codegen produces locators prioritized by stability:**

1. `getByRole()` -- accessibility role + name (most stable)
2. `getByText()` -- visible text content
3. `getByLabel()` -- form label association
4. `getByTestId()` -- `data-testid` attribute
5. CSS/XPath selectors -- fallback (least stable)

This locator priority order aligns with the CUA selector strategy: `AX query -> stable test-id -> CSS fallback`.

**ARIA snapshot generation in codegen:**

Playwright codegen can generate `toMatchAriaSnapshot()` assertions through its "Assert snapshot" action in the codegen UI, producing YAML templates for the selected element's accessibility tree structure.

**AI-powered code generation (v1.56+):**

Playwright 1.56 introduced "Playwright Agents" -- AI-powered assistants for automation:

- **Planner**: Analyzes the application and plans test scenarios.
- **Generator**: Creates test code from natural language descriptions.
- **Healer**: Automatically fixes broken selectors when UI changes.

These AI features are relevant to CUA because they demonstrate how accessibility-first targeting can be combined with AI intent to produce robust automation -- the same pattern the CUA gateway uses.

### Playwright Recent Versions

| Version | Date | Key CUA-Relevant Features |
|---------|------|---------------------------|
| **1.49** | Nov 2024 | ARIA snapshot matching (`toMatchAriaSnapshot()`); accessibility-first assertions |
| **1.50** | Jan 2025 | Async fixture support; improved codegen assertions |
| **1.51** | Feb 2025 | `toBeVisible()` auto-assertions in codegen |
| **1.52** | Mar 2025 | Partitioned cookie support (`partitionKey` in `browserContext.cookies()`) |
| **1.53** | Apr 2025 | `--fail-on-flaky-tests` CLI option |
| **1.54** | May 2025 | Performance improvements for large DOM snapshots |
| **1.56** | Jul 2025 | **Playwright Agents** (Planner, Generator, Healer) -- AI-powered test creation |
| **1.57** | Sep 2025 | Switch from Chromium to **Chrome for Testing** builds; both headed and headless use CfT |

**Chrome for Testing transition (v1.57).** Starting with Playwright 1.57, the Chromium channel uses Chrome for Testing (CfT) builds instead of custom Chromium builds. This means Playwright-controlled browsers are closer to production Chrome, which improves fidelity of CUA evidence (screenshots and behavior match what real users see).

---

## Puppeteer

### Puppeteer Architecture

Puppeteer (Apache-2.0, Google) is a Node.js library for controlling Chrome/Chromium and Firefox. It communicates with browsers primarily through the Chrome DevTools Protocol (CDP) via WebSocket.

**Architecture:**

```
Puppeteer Node.js Process
    |
    +-- Connection (WebSocket to browser)
    |       |
    |       +-- CDPSession (per-target CDP channel)
    |       |       |
    |       |       +-- Page (tab control)
    |       |       |       |
    |       |       |       +-- Frame (main + iframes)
    |       |       |       +-- Network events
    |       |       |       +-- Console events
    |       |       |
    |       |       +-- Worker (web worker control)
    |       |
    |       +-- Browser (process lifecycle)
    |       +-- BrowserContext (incognito sessions)
```

**CDP-native advantage.** Puppeteer provides direct access to the underlying CDP session, enabling fine-grained protocol-level control:

```typescript
import puppeteer from 'puppeteer';

const browser = await puppeteer.launch();
const page = await browser.newPage();

// Get the CDP session for low-level protocol access
const client = await page.createCDPSession();

// Enable Accessibility domain
await client.send('Accessibility.enable');

// Fetch the full accessibility tree
const { nodes } = await client.send('Accessibility.getFullAXTree');

// Capture screenshot via CDP directly
const { data } = await client.send('Page.captureScreenshot', {
  format: 'png',
  quality: undefined,  // PNG does not use quality
  fromSurface: true,
});
const screenshot = Buffer.from(data, 'base64');
```

### Puppeteer WebDriver BiDi Transition

Puppeteer is actively transitioning from CDP-only to supporting WebDriver BiDi as a transport protocol.

**Current status (2025-2026):**

| Protocol | Chrome | Firefox | Default Since |
|----------|--------|---------|---------------|
| CDP | Full support | Deprecated (removed from Firefox 129+) | Puppeteer < 24 (Chrome) |
| WebDriver BiDi | Growing support | Full support | Puppeteer 24+ (Firefox) |

**Connecting via BiDi:**

```typescript
import puppeteer from 'puppeteer';

// Launch Firefox with BiDi (default since Puppeteer 24)
const browser = await puppeteer.launch({
  product: 'firefox',
  protocol: 'webdriver-bidi',  // explicit, but default for Firefox
});

// Launch Chrome with BiDi (opt-in)
const chromeBrowser = await puppeteer.launch({
  protocol: 'webdriver-bidi',
});
```

**BiDi readiness tracker:** The Puppeteer team maintains a live dashboard at `puppeteer.github.io/ispuppeteerwebdriverbidiready/` that tracks which Puppeteer APIs are implemented over BiDi.

**CUA implications:** For Chromium-based CUA, CDP remains the primary protocol because it provides deeper access (Accessibility domain, Input domain, etc.). BiDi support is relevant for Firefox cross-browser validation.

### Puppeteer Protocol-Level Telemetry

Puppeteer's direct CDP access enables rich telemetry collection for CUA evidence:

**Network event capture:**

```typescript
const client = await page.createCDPSession();
await client.send('Network.enable');

client.on('Network.requestWillBeSent', (params) => {
  auditLog.emit('network_request', {
    requestId: params.requestId,
    url: params.request.url,
    method: params.request.method,
    timestamp: params.timestamp,
  });
});

client.on('Network.responseReceived', (params) => {
  auditLog.emit('network_response', {
    requestId: params.requestId,
    status: params.response.status,
    url: params.response.url,
    mimeType: params.response.mimeType,
  });
});
```

**DOM mutation observation:**

```typescript
await client.send('DOM.enable');

client.on('DOM.documentUpdated', () => {
  auditLog.emit('dom_document_updated');
});

client.on('DOM.childNodeInserted', (params) => {
  auditLog.emit('dom_child_inserted', {
    parentNodeId: params.parentNodeId,
    nodeId: params.node.nodeId,
    nodeName: params.node.nodeName,
  });
});
```

**Console and exception capture:**

```typescript
await client.send('Runtime.enable');

client.on('Runtime.consoleAPICalled', (params) => {
  auditLog.emit('console', {
    type: params.type,
    args: params.args.map((a) => a.value),
    timestamp: params.timestamp,
  });
});

client.on('Runtime.exceptionThrown', (params) => {
  auditLog.emit('exception', {
    text: params.exceptionDetails.text,
    url: params.exceptionDetails.url,
    lineNumber: params.exceptionDetails.lineNumber,
  });
});
```

### Puppeteer Firefox Support

Firefox support in Puppeteer has reached production readiness via WebDriver BiDi:

- **CDP support removed from Firefox**: Firefox 129+ dropped CDP support entirely. All Puppeteer-Firefox automation must use BiDi.
- **BiDi coverage**: Core page navigation, element interaction, screenshot capture, and console logging work over BiDi.
- **Gaps**: Some CDP-specific features (e.g., `Accessibility.getFullAXTree` at full fidelity, fine-grained network interception) may have reduced coverage over BiDi.

### Puppeteer vs Playwright Comparison

| Aspect | Playwright | Puppeteer |
|--------|-----------|-----------|
| **License** | Apache-2.0 | Apache-2.0 |
| **Language bindings** | TypeScript, Python, Java, .NET | TypeScript/JavaScript only |
| **Browser engines** | Chromium, Firefox, WebKit | Chromium, Firefox |
| **Default protocol** | Internal (per-engine) | CDP (Chrome), BiDi (Firefox) |
| **Direct CDP access** | Via `page.context().newCDPSession()` (Chromium only) | Via `page.createCDPSession()` |
| **Cross-browser AX snapshots** | Yes (`page.accessibility.snapshot()` on all engines) | Yes (BiDi or CDP depending on browser) |
| **Tracing** | Built-in trace viewer with screenshots + DOM snapshots | Chrome Trace via `browser.startTracing()` / `browser.stopTracing()` |
| **Network interception** | `page.route()` with fulfill/continue/abort | `page.setRequestInterception()` + request handlers |
| **Test runner** | Built-in `@playwright/test` | External (Jest, Mocha, etc.) |
| **ARIA snapshot matching** | `toMatchAriaSnapshot()` (v1.49+) | Not built-in |
| **MCP server** | Official Playwright MCP Server | Community MCP servers exist |
| **Browser downloads** | Auto-downloads correct browser builds | Auto-downloads Chrome for Testing |
| **CUA recommendation** | **Primary browser executor** for MVP | **Secondary** / CDP telemetry specialist |

**When to choose Puppeteer over Playwright for CUA:**

- When you need direct, raw CDP access without abstraction layers.
- When building a CDP-native telemetry pipeline that must capture protocol-level detail.
- When the CUA gateway is TypeScript-only and deep CDP integration is the priority.

**When to choose Playwright for CUA:**

- When you need cross-engine support (Chromium + Firefox + WebKit).
- When you want built-in tracing, ARIA snapshots, and network interception.
- When you need Python or Go bindings (Playwright has Python; Go bindings exist via community).
- When the CUA MVP needs rapid development with rich tooling.

---

## Chrome DevTools Protocol (CDP)

### CDP Domain Overview

CDP is a WebSocket-based JSON-RPC protocol that provides direct access to browser internals. It is organized into **domains**, each covering a specific aspect of browser functionality.

**Domains most relevant to CUA:**

| Domain | Key Methods | CUA Role |
|--------|------------|----------|
| **Page** | `captureScreenshot`, `navigate`, `getFrameTree`, `startScreencast` | Screenshot evidence, navigation control |
| **Runtime** | `evaluate`, `callFunctionOn`, `getProperties` | JavaScript execution, state inspection |
| **DOM** | `getDocument`, `querySelector`, `getOuterHTML`, `resolveNode` | DOM tree capture, element targeting |
| **Network** | `enable`, `setRequestInterception`, `getResponseBody` | Egress policy enforcement, network audit |
| **Accessibility** | `enable`, `getFullAXTree`, `getPartialAXTree`, `queryAXTree` | Semantic targeting, receipt evidence |
| **Input** | `dispatchMouseEvent`, `dispatchKeyEvent`, `dispatchTouchEvent` | Programmatic action execution |
| **Overlay** | `highlightNode`, `setShowAccessibilityInfo` | Visual debugging (development only) |
| **Emulation** | `setDeviceMetricsOverride`, `setGeolocationOverride` | Consistent viewport for evidence |
| **Security** | `enable`, `setIgnoreCertificateErrors` | TLS verification control |

### CDP Accessibility Domain

The `Accessibility.getFullAXTree` method returns the complete accessibility tree for a document, providing the richest semantic context available for CUA receipts.

**Raw CDP WebSocket request:**

```json
{
  "id": 1,
  "method": "Accessibility.getFullAXTree",
  "params": {
    "depth": 10,
    "frameId": "main"
  }
}
```

**Response structure:**

```json
{
  "id": 1,
  "result": {
    "nodes": [
      {
        "nodeId": "1",
        "ignored": false,
        "role": { "type": "role", "value": "WebArea" },
        "name": { "type": "computedString", "value": "Example Page" },
        "properties": [
          { "name": "focused", "value": { "type": "boolean", "value": true } }
        ],
        "childIds": ["2", "3", "4"],
        "backendDOMNodeId": 1
      },
      {
        "nodeId": "2",
        "ignored": false,
        "role": { "type": "role", "value": "button" },
        "name": { "type": "computedString", "value": "Submit", "sources": [
          { "type": "contents", "value": { "type": "computedString", "value": "Submit" } }
        ]},
        "properties": [
          { "name": "focusable", "value": { "type": "boolean", "value": true } }
        ],
        "childIds": [],
        "backendDOMNodeId": 42
      }
    ]
  }
}
```

**Key node properties:**

| Property | Description | Receipt Value |
|----------|-------------|---------------|
| `role` | ARIA role (`button`, `textbox`, `link`, `heading`, ...) | Semantic target identification |
| `name` | Computed accessible name (from label, aria-label, text content) | Target verification |
| `name.sources` | How the name was computed (content, attribute, related element) | Audit trail for name resolution |
| `properties` | State properties (focused, disabled, expanded, checked, ...) | Pre/post condition verification |
| `backendDOMNodeId` | Maps to DOM node for cross-referencing | DOM-AX correlation |
| `childIds` | Child node references | Tree structure for hashing |

**Using `queryAXTree` for targeted lookup:**

```json
{
  "id": 2,
  "method": "Accessibility.queryAXTree",
  "params": {
    "nodeId": 1,
    "accessibleName": "Submit",
    "role": "button"
  }
}
```

This returns only matching nodes, which is more efficient than fetching the full tree when you know the target.

### CDP Screenshot Capture

`Page.captureScreenshot` provides direct screenshot control at the protocol level.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `format` | `'jpeg'` / `'png'` / `'webp'` | `'png'` | Image compression format |
| `quality` | integer (0-100) | -- | Compression quality (JPEG/WebP only) |
| `clip` | `{x, y, width, height, scale}` | -- | Capture specific region |
| `fromSurface` | boolean | `true` | Capture from composited surface |
| `captureBeyondViewport` | boolean | `false` | Include content outside viewport |
| `optimizeForSpeed` | boolean | `false` | Speed over size optimization |

**Raw CDP call:**

```json
{
  "id": 3,
  "method": "Page.captureScreenshot",
  "params": {
    "format": "png",
    "fromSurface": true,
    "captureBeyondViewport": false
  }
}
```

**Response:**

```json
{
  "id": 3,
  "result": {
    "data": "iVBORw0KGgoAAAANSUhEUgAA..."
  }
}
```

The `data` field contains a base64-encoded image that can be hashed directly for receipt evidence.

**Go (chromedp) equivalent:**

```go
package main

import (
    "context"
    "crypto/sha256"
    "fmt"

    "github.com/chromedp/chromedp"
)

func captureScreenshotEvidence(ctx context.Context) ([]byte, string, error) {
    var buf []byte
    err := chromedp.Run(ctx,
        chromedp.CaptureScreenshot(&buf),
    )
    if err != nil {
        return nil, "", err
    }

    hash := sha256.Sum256(buf)
    return buf, fmt.Sprintf("sha256:%x", hash), nil
}
```

### CDP Input Dispatch

CDP's Input domain provides programmatic mouse and keyboard control at the browser level, bypassing OS-level input injection entirely.

**Input.dispatchMouseEvent parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `type` | `'mousePressed'` / `'mouseReleased'` / `'mouseMoved'` / `'mouseWheel'` | Event type |
| `x` | number | X coordinate (CSS pixels, relative to viewport) |
| `y` | number | Y coordinate |
| `button` | `'none'` / `'left'` / `'middle'` / `'right'` | Mouse button |
| `clickCount` | integer | Number of clicks (1 = single, 2 = double) |
| `modifiers` | integer | Bitmask: Alt=1, Ctrl=2, Meta=4, Shift=8 |
| `deltaX` / `deltaY` | number | Scroll deltas (for `mouseWheel`) |

**Raw CDP mouse click sequence:**

```json
[
  {
    "id": 10,
    "method": "Input.dispatchMouseEvent",
    "params": {
      "type": "mousePressed",
      "x": 500,
      "y": 300,
      "button": "left",
      "clickCount": 1
    }
  },
  {
    "id": 11,
    "method": "Input.dispatchMouseEvent",
    "params": {
      "type": "mouseReleased",
      "x": 500,
      "y": 300,
      "button": "left",
      "clickCount": 1
    }
  }
]
```

**Input.dispatchKeyEvent parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `type` | `'keyDown'` / `'keyUp'` / `'rawKeyDown'` / `'char'` | Event type |
| `modifiers` | integer | Modifier bitmask (Alt=1, Ctrl=2, Meta=4, Shift=8) |
| `text` | string | Text generated by the key press |
| `key` | string | Key identifier (e.g., `'Enter'`, `'a'`, `'ArrowDown'`) |
| `code` | string | Physical key code (e.g., `'KeyA'`, `'Enter'`) |
| `windowsVirtualKeyCode` | integer | Windows virtual key code |

**Raw CDP key press sequence (typing 'a'):**

```json
[
  {
    "id": 12,
    "method": "Input.dispatchKeyEvent",
    "params": {
      "type": "keyDown",
      "key": "a",
      "code": "KeyA",
      "text": "a",
      "windowsVirtualKeyCode": 65
    }
  },
  {
    "id": 13,
    "method": "Input.dispatchKeyEvent",
    "params": {
      "type": "keyUp",
      "key": "a",
      "code": "KeyA",
      "windowsVirtualKeyCode": 65
    }
  }
]
```

**CUA advantage of CDP input dispatch over OS-level injection:** CDP input events are delivered directly to the browser's rendering engine. They do not pass through the OS input stack, avoiding permission issues (UIPI, macOS Accessibility), focus requirements, and window-manager interference. For browser-first CUA, CDP input is strictly preferred over `SendInput`, XTEST, or Quartz Events.

### CDP Event Streaming

CDP uses a persistent WebSocket connection for bidirectional communication. The client sends commands (with integer `id` fields); the browser sends responses (with matching `id`) and unsolicited events (no `id`, identified by `method`).

**WebSocket connection lifecycle:**

```
1. Client connects: ws://localhost:9222/devtools/page/<target-id>
2. Client sends: { "id": 1, "method": "Page.enable" }
3. Browser sends: { "id": 1, "result": {} }
4. Browser sends: { "method": "Page.frameNavigated", "params": { ... } }  (event)
5. Browser sends: { "method": "Page.loadEventFired", "params": { "timestamp": 1234.5 } }  (event)
```

**Event subscription model:**

| Domain | Enable Method | Key Events |
|--------|--------------|------------|
| `Page` | `Page.enable` | `frameNavigated`, `loadEventFired`, `javascriptDialogOpening` |
| `Network` | `Network.enable` | `requestWillBeSent`, `responseReceived`, `loadingFinished` |
| `DOM` | `DOM.enable` | `documentUpdated`, `childNodeInserted`, `attributeModified` |
| `Runtime` | `Runtime.enable` | `consoleAPICalled`, `exceptionThrown` |
| `Accessibility` | `Accessibility.enable` | `loadComplete`, `nodesUpdated` |

**TypeScript WebSocket client example:**

```typescript
import WebSocket from 'ws';

const ws = new WebSocket('ws://localhost:9222/devtools/page/ABC123');

let nextId = 1;
const pending = new Map<number, { resolve: Function; reject: Function }>();

ws.on('message', (raw) => {
  const msg = JSON.parse(raw.toString());

  if ('id' in msg) {
    // Response to a command
    const handler = pending.get(msg.id);
    if (handler) {
      pending.delete(msg.id);
      if (msg.error) handler.reject(msg.error);
      else handler.resolve(msg.result);
    }
  } else {
    // Unsolicited event
    handleCDPEvent(msg.method, msg.params);
  }
});

function sendCommand(method: string, params?: object): Promise<any> {
  const id = nextId++;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    ws.send(JSON.stringify({ id, method, params }));
  });
}

function handleCDPEvent(method: string, params: any) {
  switch (method) {
    case 'Page.frameNavigated':
      auditLog.emit('navigation', { url: params.frame.url });
      break;
    case 'Network.requestWillBeSent':
      policyEngine.checkEgress(params.request.url);
      break;
  }
}
```

### CDP DOM Access

`DOM.getDocument` and `DOM.querySelector` provide structured DOM access for element targeting and context capture.

**Fetching the document tree:**

```json
{
  "id": 20,
  "method": "DOM.getDocument",
  "params": { "depth": -1 }
}
```

**Querying elements:**

```json
{
  "id": 21,
  "method": "DOM.querySelector",
  "params": {
    "nodeId": 1,
    "selector": "button[data-testid='submit']"
  }
}
```

**Getting element properties for receipts:**

```json
{
  "id": 22,
  "method": "DOM.getOuterHTML",
  "params": { "nodeId": 42 }
}
```

**Resolving DOM node to JavaScript object:**

```json
{
  "id": 23,
  "method": "DOM.resolveNode",
  "params": { "nodeId": 42 }
}
```

This returns a `Runtime.RemoteObject` that can be used with `Runtime.callFunctionOn` for property inspection.

### CDP Security Considerations

**The CDP socket is a full remote-control interface.** Any entity with access to the CDP WebSocket endpoint can:

- Read all page content (including passwords, tokens, cookies)
- Inject arbitrary JavaScript
- Capture screenshots of any page content
- Dispatch input events as if from the user
- Modify network requests and responses
- Access the browser's filesystem through `Page.setDownloadBehavior`

**Security requirements for CUA:**

| Requirement | Implementation |
|-------------|----------------|
| CDP socket must never be exposed to the agent | Bind to `127.0.0.1` only; gateway is sole consumer |
| CDP socket must not be network-accessible | No `--remote-debugging-address=0.0.0.0` |
| Authentication for CDP | Chrome supports `--remote-debugging-pipe` (stdin/stdout) instead of WebSocket for tighter access control |
| CDP method allowlisting | Use a CDP proxy (chromedp-proxy or cdp-proxy-interceptor) to restrict which methods are callable |
| Sensitive response redaction | Redact `Network.getResponseBody` results that contain secrets before logging |

---

## WebDriver BiDi (W3C)

### Specification Status

WebDriver BiDi is a W3C Working Draft (Browser Testing and Tools Working Group) that defines a bidirectional protocol for browser automation. As of February 2026, it remains an active Editor's Draft with ongoing development and monthly working group meetings.

**Key milestone dates:**

| Date | Milestone |
|------|-----------|
| 2021 | Initial specification work begins |
| 2023 | First implementations in Chrome and Firefox |
| 2024 | Puppeteer 23+ stable Firefox support via BiDi |
| 2025 Q1 | Cypress 14.1+ defaults to BiDi for Firefox |
| 2025 Q3 | Cypress 15 removes CDP support for Firefox entirely |
| 2026 | Ongoing W3C Working Draft; not yet a W3C Recommendation |

**Specification URL:** https://www.w3.org/TR/webdriver-bidi/

### WebDriver BiDi Modules

BiDi organizes functionality into modules, each covering a distinct automation domain:

| Module | Description | CDP Equivalent |
|--------|-------------|----------------|
| **Session** | Session lifecycle management | Target domain |
| **Browsing Context** | Tab/window management, navigation, screenshot | Page domain |
| **Script** | JavaScript evaluation, realm management | Runtime domain |
| **Network** | Request interception, auth handling, network events | Network domain |
| **Log** | Console and JavaScript error capture | Runtime (console), Log domain |
| **Input** | Keyboard and pointer actions | Input domain |
| **Browser** | Browser-level management, user context | Browser domain |
| **Storage** | Cookie management | Network (cookies) |

**Module implementation status (simplified, February 2026):**

| Module | Chrome | Firefox | Safari |
|--------|--------|---------|--------|
| Session | Yes | Yes | Partial |
| Browsing Context | Yes | Yes | Partial |
| Script | Yes | Yes | Partial |
| Network | Yes | Yes | No |
| Log | Yes | Yes | No |
| Input | Yes | Yes | No |
| Storage | Yes | Yes | No |

### Bidirectional Event Model

The key architectural difference between BiDi and classic WebDriver is the bidirectional event model:

**Classic WebDriver:** Request-response only. The client sends a command, the server responds. To detect events (navigation, console logs, network requests), the client must poll.

**WebDriver BiDi:** The browser can push events to the client without being asked. Events are subscribed to via `session.subscribe`:

```json
{
  "method": "session.subscribe",
  "params": {
    "events": [
      "log.entryAdded",
      "network.beforeRequestSent",
      "browsingContext.navigationStarted"
    ]
  }
}
```

**Event delivery:**

```json
{
  "type": "event",
  "method": "log.entryAdded",
  "params": {
    "level": "error",
    "source": { "realm": "..." },
    "text": "Uncaught TypeError: ...",
    "timestamp": 1708300000000,
    "type": "console"
  }
}
```

**CDP vs BiDi event comparison:**

| Aspect | CDP | WebDriver BiDi |
|--------|-----|-----------------|
| Transport | WebSocket JSON-RPC | WebSocket JSON-RPC |
| Event subscription | Per-domain `enable` calls | `session.subscribe` with event list |
| Event scope | Typically per-target (page) | Can scope to browsing context or global |
| Browser coverage | Chromium only | Chrome, Firefox, Safari (growing) |
| Specification | De facto (Chrome-defined) | W3C standard |

### Browser Support Matrix

| Browser | BiDi Support | Implementation | Notes |
|---------|-------------|----------------|-------|
| **Chrome/Chromium** | Yes (growing) | Chromium BiDi (built-in since Chrome 114+) | Also supports CDP simultaneously |
| **Firefox** | Yes (production-ready) | Native implementation | CDP deprecated and removed |
| **Safari/WebKit** | Partial | Safari Technology Preview has initial support | Limited module coverage |
| **Edge** | Yes | Same as Chromium | Follows Chrome implementation |

### BiDi Advantages and Limitations

**Advantages:**

- **Standardized**: W3C specification ensures cross-browser compatibility.
- **Event subscriptions**: Real-time browser events without polling.
- **Future-proof**: The industry is converging on BiDi (Firefox dropped CDP, Cypress dropped CDP for Firefox).
- **Cross-browser**: Single protocol for Chrome, Firefox, and eventually Safari.

**Limitations (as of February 2026):**

- **Incomplete coverage**: Not all CDP domains have BiDi equivalents yet. Notably, the full Accessibility domain (`getFullAXTree`) does not have a BiDi counterpart.
- **Safari gap**: Safari has the least BiDi support of the major browsers.
- **Performance instrumentation**: CDP provides lower-level performance tracing that BiDi does not yet match.
- **Evolving spec**: Breaking changes between spec drafts are still possible.

**CUA recommendation:** Design the gateway's browser protocol layer with a transport abstraction that supports both CDP and BiDi. Use CDP for Chromium (richer Accessibility and Input access), BiDi for Firefox (only option), and plan for BiDi as the unified protocol when coverage matures.

---

## Selenium 4+

### Selenium WebDriver BiDi Integration

Selenium 4 introduced BiDi support as an evolution beyond classic WebDriver, enabling real-time event handling:

```java
// Selenium 4 BiDi event listener example
try (WebDriver driver = new ChromeDriver()) {
    HasLogEvents logEvents = (HasLogEvents) driver;

    // Listen for console log events
    logEvents.onLogEvent(consoleEvent(entry -> {
        System.out.printf("[%s] %s%n", entry.getLevel(), entry.getText());
    }));

    // Listen for JavaScript errors
    logEvents.onLogEvent(jsException(error -> {
        System.err.println("JS Error: " + error.getMessage());
    }));

    driver.get("https://example.com");
}
```

**Selenium 4.30 (March 2025)** and **4.31 (2025)** brought improved BiDi protocol support, including better network interception and log capture.

### Selenium Grid 4 Architecture

Selenium Grid 4 uses a decomposed architecture designed for container/Kubernetes deployment:

```
                   ┌──────────────────┐
                   │     Router       │  (entry point)
                   └────────┬─────────┘
                            │
              ┌─────────────┼──────────────┐
              │             │              │
    ┌─────────▼──────┐  ┌──▼───────┐  ┌──▼──────────┐
    │  Distributor   │  │ Session  │  │ New Session  │
    │  (node mgmt,   │  │  Map     │  │   Queue      │
    │   scheduling)  │  │          │  │              │
    └─────────┬──────┘  └──────────┘  └──────────────┘
              │
    ┌─────────▼──────────────────────────────────┐
    │              Event Bus                      │
    └─────────┬───────────┬───────────┬──────────┘
              │           │           │
    ┌─────────▼──┐  ┌─────▼────┐  ┌──▼─────────┐
    │  Node      │  │  Node    │  │  Node       │
    │  (Chrome)  │  │ (Firefox)│  │  (Edge)     │
    └────────────┘  └──────────┘  └─────────────┘
```

**Key Grid 4 properties:**

| Component | Role | Scaling |
|-----------|------|---------|
| Router | Entry point for all Grid requests | Stateless, horizontally scalable |
| Distributor | Manages nodes, distributes session requests | Single leader |
| Session Map | Tracks which node owns which session | In-memory or external store |
| New Session Queue | Holds pending session requests | Queue with configurable timeout |
| Event Bus | Internal communication between components | Default: in-process; can use external message broker |
| Node | Runs browser instances, executes commands | Horizontally scalable |

**Kubernetes deployment with KEDA autoscaling:**

```yaml
apiVersion: keda.sh/v1alpha1
kind: ScaledObject
metadata:
  name: selenium-grid-chrome
spec:
  scaleTargetRef:
    name: selenium-chrome-node
  triggers:
  - type: selenium-grid
    metadata:
      url: 'http://selenium-hub:4444/graphql'
      browserName: 'chrome'
      sessionBrowserName: 'chrome'
      activationThreshold: '0'
  minReplicaCount: 0
  maxReplicaCount: 10
```

### Cross-Browser Standardization

Selenium's primary value proposition is cross-browser standardization via the W3C WebDriver specification:

- All major browsers implement WebDriver endpoints.
- Session creation uses W3C capabilities negotiation.
- Grid distributes sessions across browser types transparently.
- BiDi adds real-time events on top of the standard.

### When Selenium Grid Matters for CUA

Selenium Grid is relevant to CUA in specific scenarios:

| Scenario | Grid Value |
|----------|------------|
| **Multi-browser policy testing** | Run the same CUA workflow against Chrome, Firefox, and Edge to verify policy enforcement is consistent |
| **Parallel session scaling** | When the CUA gateway needs to manage dozens of concurrent browser sessions |
| **Managed browser lifecycle** | Grid handles browser provisioning, health checks, and session cleanup |
| **Cloud/hybrid deployment** | Grid nodes can run on-prem or in cloud; Helm charts for K8s are mature |

**When Grid is NOT needed for CUA MVP:**

- Single-browser Chromium target with Playwright/Puppeteer managing the browser directly.
- The gateway manages browser lifecycle itself.
- Latency sensitivity: Grid adds a hop between the gateway and the browser.

---

## chromedp (Go CDP Client)

### chromedp Architecture

chromedp (MIT license) is a Go package that drives Chrome/Chromium via CDP without external dependencies. Its architecture is context-based, using Go's `context.Context` for lifecycle management.

**Core architectural concepts:**

```
Allocator (browser lifecycle)
    |
    +-- Context (browser-level: manages browser process)
    |       |
    |       +-- Context (tab-level: manages a single target/page)
    |       |       |
    |       |       +-- Actions (Navigate, Click, Screenshot, etc.)
    |       |       +-- Event Listeners (CDP events)
    |       |
    |       +-- Context (another tab)
```

**Allocator types:**

| Allocator | Use Case |
|-----------|----------|
| `chromedp.NewExecAllocator()` | Launch a new Chrome process (default) |
| `chromedp.NewRemoteAllocator()` | Connect to an already-running Chrome via CDP WebSocket |

**Basic setup:**

```go
package main

import (
    "context"
    "log"

    "github.com/chromedp/chromedp"
)

func main() {
    // Configure allocator with headless Chrome
    allocCtx, cancel := chromedp.NewExecAllocator(
        context.Background(),
        append(chromedp.DefaultExecAllocatorOptions[:],
            chromedp.Flag("headless", true),
            chromedp.Flag("disable-gpu", true),
            chromedp.Flag("no-sandbox", true),
        )...,
    )
    defer cancel()

    // Create browser context
    ctx, cancel := chromedp.NewContext(allocCtx,
        chromedp.WithLogf(log.Printf),
    )
    defer cancel()

    // Execute actions
    var title string
    err := chromedp.Run(ctx,
        chromedp.Navigate("https://example.com"),
        chromedp.Title(&title),
    )
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("Page title: %s", title)
}
```

### chromedp Key Operations

| Operation | Function | Description |
|-----------|----------|-------------|
| Navigate | `chromedp.Navigate(url)` | Navigate to a URL |
| Click | `chromedp.Click(sel)` | Click an element by selector |
| SendKeys | `chromedp.SendKeys(sel, text)` | Type text into an element |
| Screenshot | `chromedp.CaptureScreenshot(&buf)` | Capture viewport screenshot |
| Full Screenshot | `chromedp.FullScreenshot(&buf, quality)` | Capture full page |
| Evaluate | `chromedp.Evaluate(expr, &result)` | Execute JavaScript |
| Nodes | `chromedp.Nodes(sel, &nodes)` | Get DOM nodes matching selector |
| WaitVisible | `chromedp.WaitVisible(sel)` | Wait for element visibility |
| Text | `chromedp.Text(sel, &text)` | Get element text content |
| Value | `chromedp.Value(sel, &value)` | Get input element value |
| Location | `chromedp.Location(&url)` | Get current URL |
| Title | `chromedp.Title(&title)` | Get page title |

**CUA evidence capture in Go:**

```go
func captureActionEvidence(ctx context.Context) (*ActionEvidence, error) {
    var (
        preBuf  []byte
        postBuf []byte
        url     string
        title   string
    )

    // Pre-action capture
    if err := chromedp.Run(ctx,
        chromedp.CaptureScreenshot(&preBuf),
        chromedp.Location(&url),
        chromedp.Title(&title),
    ); err != nil {
        return nil, fmt.Errorf("pre-capture failed: %w", err)
    }

    preHash := sha256.Sum256(preBuf)

    return &ActionEvidence{
        PreScreenshot:  preBuf,
        PreFrameHash:   fmt.Sprintf("sha256:%x", preHash),
        URL:            url,
        Title:          title,
    }, nil
}
```

### chromedp CDP Event Handling

chromedp provides `ListenTarget` and `ListenBrowser` for CDP event subscriptions:

```go
import (
    "github.com/chromedp/cdproto/network"
    "github.com/chromedp/cdproto/page"
    "github.com/chromedp/cdproto/accessibility"
)

// Listen for network requests (for egress policy enforcement)
chromedp.ListenTarget(ctx, func(ev interface{}) {
    switch e := ev.(type) {
    case *network.EventRequestWillBeSent:
        // Check against egress allowlist
        allowed := egressGuard.Check(e.Request.URL)
        if !allowed {
            log.Printf("EGRESS_DENIED: %s", e.Request.URL)
            // Note: CDP cannot block requests via events alone;
            // use Fetch.enable + Fetch.requestPaused for interception
        }

    case *page.EventFrameNavigated:
        log.Printf("NAVIGATED: %s", e.Frame.URL)

    case *page.EventJavascriptDialogOpening:
        log.Printf("DIALOG: %s (type=%s)", e.Message, e.Type)
        // Auto-dismiss dialogs in CUA context
        go chromedp.Run(ctx,
            page.HandleJavaScriptDialog(false),
        )
    }
})
```

**Fetching the full AX tree in Go:**

```go
import "github.com/chromedp/cdproto/accessibility"

func getAccessibilityTree(ctx context.Context) ([]*accessibility.AXNode, error) {
    var nodes []*accessibility.AXNode

    err := chromedp.Run(ctx,
        chromedp.ActionFunc(func(ctx context.Context) error {
            result, err := accessibility.GetFullAXTree().
                WithDepth(10).
                Do(ctx)
            if err != nil {
                return err
            }
            nodes = result
            return nil
        }),
    )

    return nodes, err
}
```

### chromedp Fit for CUA Gateway

chromedp is a strong fit for a Go-based CUA gateway service for several reasons:

| Property | Benefit for CUA |
|----------|-----------------|
| **No external dependencies** | No Node.js runtime needed; single Go binary |
| **Context-based lifecycle** | Natural fit for Go services; `context.WithTimeout` for action deadlines |
| **Direct CDP access** | Full protocol access without abstraction; every CDP domain is available via generated types |
| **Allocator pattern** | Clean separation between browser lifecycle and tab-level operations |
| **Concurrent contexts** | Multiple tabs/sessions managed via Go goroutines + contexts |
| **Small binary footprint** | Lighter deployment than Playwright + Node.js |

**When to choose chromedp for CUA:**

- The gateway is implemented in Go.
- You need direct CDP access without Node.js/TypeScript overhead.
- You want a single binary with no runtime dependencies.
- The target is Chromium-only (no Firefox/WebKit needed).

---

## CDP Proxies

### chromedp-proxy

chromedp-proxy (Go, part of the chromedp project) is a logging proxy that sits between a CDP client and a CDP-enabled browser, capturing and optionally modifying WebSocket messages.

**Architecture:**

```
CDP Client (Playwright / Puppeteer / chromedp)
    |
    +-- WebSocket (ws://localhost:9223)
    |
    v
chromedp-proxy
    |
    +-- Log all CDP messages
    +-- Optional: filter, modify, redirect
    |
    +-- WebSocket (ws://localhost:9222)
    |
    v
Browser (Chrome with --remote-debugging-port=9222)
```

**Usage:**

```bash
# Install
go install github.com/chromedp/chromedp-proxy@latest

# Run: proxy 9223 -> 9222
chromedp-proxy -l localhost:9223 -r localhost:9222

# With file logging
chromedp-proxy -l localhost:9223 -r localhost:9222 -log cdp-log-%s.log
```

**CUA applications:**

1. **CDP method allowlisting**: Modify chromedp-proxy to reject disallowed CDP methods (e.g., block `Runtime.evaluate` while allowing `Page.captureScreenshot`).
2. **Deterministic CDP logging**: Capture every CDP message for receipt evidence.
3. **Sensitive response redaction**: Strip or hash sensitive fields from `Network.getResponseBody` before they reach the log.

**Extending chromedp-proxy for policy enforcement (Go):**

```go
// Conceptual middleware in chromedp-proxy
func policyMiddleware(msg CDPMessage) (CDPMessage, error) {
    // Allowlist of CDP methods the agent/client may invoke
    allowed := map[string]bool{
        "Page.captureScreenshot":     true,
        "Accessibility.getFullAXTree": true,
        "DOM.getDocument":            true,
        "Input.dispatchMouseEvent":   true,
        "Input.dispatchKeyEvent":     true,
    }

    if msg.IsRequest() && !allowed[msg.Method] {
        return CDPMessage{
            ID:    msg.ID,
            Error: &CDPError{Code: -32601, Message: "method_not_allowed"},
        }, nil
    }

    return msg, nil // pass through
}
```

### cdp-proxy-interceptor

cdp-proxy-interceptor (TypeScript/Node.js) is a transparent MITM proxy for CDP that provides a plugin system for intercepting, modifying, injecting, and filtering CDP messages.

**Architecture:**

```
CDP Client
    |
    v
cdp-proxy-interceptor
    |
    +-- Plugin: RequestFilter
    +-- Plugin: ResponseRedactor
    +-- Plugin: AuditLogger
    +-- Plugin: PolicyEnforcer
    |
    v
Browser (CDP)
```

**Plugin interface:**

```typescript
import { BaseCDPPlugin } from 'cdp-proxy-interceptor';

class PolicyEnforcerPlugin extends BaseCDPPlugin {
  name = 'CUAPolicyEnforcer';

  // Intercept outgoing commands (client -> browser)
  async onRequest(message: CDPRequest): Promise<CDPRequest | null> {
    const deniedMethods = ['Page.setDownloadBehavior', 'Browser.close'];

    if (deniedMethods.includes(message.method)) {
      this.logger.warn(`Blocked CDP method: ${message.method}`);
      // Return null to block the message
      return null;
    }

    return message;
  }

  // Intercept responses (browser -> client)
  async onResponse(message: CDPResponse): Promise<CDPResponse | null> {
    // Redact sensitive data from network response bodies
    if (message.method === 'Network.getResponseBody') {
      message.result.body = redactSecrets(message.result.body);
    }

    return message;
  }

  // Intercept events (browser -> client)
  async onEvent(event: CDPEvent): Promise<CDPEvent | null> {
    // Log all events for audit
    this.auditLog.append({
      timestamp: Date.now(),
      method: event.method,
      params: event.params,
    });

    return event;
  }
}
```

**Key features for CUA:**

| Feature | CUA Application |
|---------|-----------------|
| Message blocking (return `null`) | Deny dangerous CDP methods |
| Message modification | Redact sensitive response content |
| Message injection (`sendCDPCommand`) | Insert pre/post-action evidence commands |
| Event filtering | Suppress noisy events; log security-relevant ones |
| Plugin composition | Stack multiple policies (allowlist + redaction + audit) |

### Policy Enforcement at Protocol Boundary

For the CUA gateway, the CDP proxy layer is the ideal enforcement point for browser-level policy:

**Allowlisting CDP methods:**

```
ALLOW:
  - Page.captureScreenshot
  - Page.navigate (with URL policy check)
  - Accessibility.getFullAXTree
  - Accessibility.queryAXTree
  - DOM.getDocument
  - DOM.querySelector
  - Input.dispatchMouseEvent
  - Input.dispatchKeyEvent
  - Emulation.setDeviceMetricsOverride

DENY (default):
  - Runtime.evaluate (agent must not run arbitrary JS)
  - Page.setDownloadBehavior
  - Network.setRequestInterception (gateway controls this)
  - Browser.close
  - Target.createTarget (gateway controls tab creation)
```

**Redaction policy for CDP responses:**

| CDP Response | Redaction Rule |
|-------------|----------------|
| `Network.getResponseBody` | Hash body; store hash in receipt; redact PII patterns |
| `DOM.getOuterHTML` | Redact `input[type=password]` values |
| `Page.captureScreenshot` | Apply region-based blurring for known sensitive areas |
| `Accessibility.getFullAXTree` | Redact `value` properties on password fields |

---

## CUA Gateway Integration

### Browser-First Executor Architecture

The complete browser-first CUA execution path:

```
Agent (untrusted)
    |
    +-- computer.use { action: "click", target: { role: "button", name: "Submit" } }
    |
    v
CUA Gateway API
    |
    +-- 1. Validate request schema
    +-- 2. Resolve target: AX query -> stable test-id -> CSS -> coordinates
    +-- 3. Policy check: egress guard (if navigation), action allowlist, target validation
    |
    v
Evidence Collector
    |
    +-- 4. Pre-action: screenshot + AX snapshot + URL + hash
    |
    v
Action Executor (Playwright / chromedp)
    |
    +-- 5. Execute action via CDP/Playwright high-level API
    |
    v
Evidence Collector
    |
    +-- 6. Post-action: screenshot + AX snapshot + URL + hash
    +-- 7. Post-condition check: URL matches? AX tree changed as expected?
    |
    v
Receipt Builder
    |
    +-- 8. Construct receipt with hash chain
    +-- 9. Sign via Signer trait (Ed25519)
    +-- 10. Store receipt + artifacts
    |
    v
Response to Agent
    |
    +-- { receipt_id, decision, post_state_summary }
```

### Evidence Capture Pipeline

The "double capture" pattern produces tamper-evident evidence for every action:

```typescript
interface ActionEvidence {
  pre: {
    frameHash: string;       // SHA-256 of screenshot PNG
    framePhash: string;      // Perceptual hash for similarity detection
    axTreeHash: string;      // SHA-256 of canonical JSON AX tree
    url: string;
    timestamp: string;       // ISO 8601
  };
  post: {
    frameHash: string;
    framePhash: string;
    axTreeHash: string;
    url: string;
    timestamp: string;
  };
  action: {
    kind: string;            // click, type, navigate, etc.
    target: {
      role?: string;
      name?: string;
      selector?: string;
      coordinates?: { x: number; y: number };
    };
    targetResolutionPath: string;  // "ax_query" | "test_id" | "css" | "coordinate"
  };
  chain: {
    prevEventHash: string;
    eventHash: string;       // SHA-256(pre + post + action + prevEventHash)
  };
}
```

**Implementation:**

```typescript
async function executeWithEvidence(
  page: Page,
  action: CUAAction,
  prevHash: string
): Promise<ActionEvidence> {
  // Pre-capture
  const preScreenshot = await page.screenshot({ type: 'png' });
  const preAxTree = await page.accessibility.snapshot();
  const preUrl = page.url();

  const preFrameHash = hash(preScreenshot);
  const preAxHash = hash(canonicalJson(preAxTree));

  // Execute action
  await executeAction(page, action);

  // Post-capture (with stability wait)
  await page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {});

  const postScreenshot = await page.screenshot({ type: 'png' });
  const postAxTree = await page.accessibility.snapshot();
  const postUrl = page.url();

  const postFrameHash = hash(postScreenshot);
  const postAxHash = hash(canonicalJson(postAxTree));

  // Hash chain
  const eventHash = hash(
    preFrameHash + postFrameHash +
    preAxHash + postAxHash +
    canonicalJson(action) + prevHash
  );

  return {
    pre: {
      frameHash: preFrameHash,
      framePhash: perceptualHash(preScreenshot),
      axTreeHash: preAxHash,
      url: preUrl,
      timestamp: new Date().toISOString(),
    },
    post: {
      frameHash: postFrameHash,
      framePhash: perceptualHash(postScreenshot),
      axTreeHash: postAxHash,
      url: postUrl,
      timestamp: new Date().toISOString(),
    },
    action: {
      kind: action.kind,
      target: action.target,
      targetResolutionPath: action.resolvedVia,
    },
    chain: {
      prevEventHash: prevHash,
      eventHash,
    },
  };
}
```

### Selector Strategy

The canonical selector resolution order, per reviewer notes:

```
1. AX Query (role + name)
   |
   +-- Found unique match? -> Use it
   +-- No match or ambiguous? -> Fall through
   |
2. Stable Test ID (data-testid, data-test, aria-labelledby)
   |
   +-- Found unique match? -> Use it
   +-- No match? -> Fall through
   |
3. CSS Selector (provided by agent)
   |
   +-- Found unique match? -> Use it
   +-- No match? -> Fall through
   |
4. Coordinate Fallback (x, y from agent)
   |
   +-- REVIEW-P3-CORRECTION: When selector and semantic target disagree,
   |   policy MUST force explicit deny/review.
   +-- If coordinates resolve to a different AX node than declared intent:
       -> DENY with reason code "target_mismatch"
```

**Implementation:**

```typescript
type ResolutionResult = {
  element: Locator;
  resolvedVia: 'ax_query' | 'test_id' | 'css' | 'coordinate';
  axNode: AXNode | null;
};

async function resolveTarget(
  page: Page,
  target: CUATarget
): Promise<ResolutionResult> {
  // 1. AX Query
  if (target.ax_query?.role && target.ax_query?.name) {
    const locator = page.getByRole(target.ax_query.role, {
      name: target.ax_query.name,
    });
    if (await locator.count() === 1) {
      return {
        element: locator,
        resolvedVia: 'ax_query',
        axNode: await getAxNodeForLocator(page, locator),
      };
    }
  }

  // 2. Stable Test ID
  if (target.test_id) {
    const locator = page.getByTestId(target.test_id);
    if (await locator.count() === 1) {
      return {
        element: locator,
        resolvedVia: 'test_id',
        axNode: await getAxNodeForLocator(page, locator),
      };
    }
  }

  // 3. CSS Selector
  if (target.css_selector) {
    const locator = page.locator(target.css_selector);
    if (await locator.count() === 1) {
      return {
        element: locator,
        resolvedVia: 'css',
        axNode: await getAxNodeForLocator(page, locator),
      };
    }
  }

  // 4. Coordinate fallback with AX verification
  if (target.coordinates) {
    const axNodeAtPoint = await getAxNodeAtPoint(
      page, target.coordinates.x, target.coordinates.y
    );

    // REVIEW-P3-CORRECTION: deny if semantic target disagrees
    if (target.ax_query && axNodeAtPoint) {
      if (axNodeAtPoint.role !== target.ax_query.role ||
          axNodeAtPoint.name !== target.ax_query.name) {
        throw new PolicyDenyError('target_mismatch', {
          expected: target.ax_query,
          actual: { role: axNodeAtPoint.role, name: axNodeAtPoint.name },
          coordinates: target.coordinates,
          reason: 'coordinate_ax_disagreement',
        });
      }
    }

    return {
      element: page.locator(`xpath=//html`),  // fallback; action uses coordinates
      resolvedVia: 'coordinate',
      axNode: axNodeAtPoint,
    };
  }

  throw new PolicyDenyError('no_target_resolved', {
    target,
    reason: 'all_resolution_strategies_failed',
  });
}
```

### Post-Condition Verification

Every high-risk action should include post-condition checks to detect silent failures:

| Action | Post-Condition | Verification Method |
|--------|---------------|---------------------|
| `navigate` | URL changed to expected value | `page.url()` matches `expect.url_is` |
| `click` (submit) | Form submitted; page state changed | AX tree diff shows new content |
| `type` (input) | Field value updated | `page.inputValue(selector)` matches typed text |
| `click` (link) | Navigation occurred | `page.url()` changed; `Page.frameNavigated` event |
| `click` (dialog) | Dialog dismissed | No `Page.javascriptDialogOpening` pending |

**Post-condition verification implementation:**

```typescript
async function verifyPostConditions(
  page: Page,
  action: CUAAction,
  preState: PreActionState
): Promise<PostConditionResult> {
  const results: PostConditionCheck[] = [];

  // URL assertion
  if (action.expect?.url_is) {
    const currentUrl = page.url();
    results.push({
      check: 'url_is',
      expected: action.expect.url_is,
      actual: currentUrl,
      passed: currentUrl === action.expect.url_is,
    });
  }

  // Visible text assertion
  if (action.expect?.visible_text_contains) {
    const bodyText = await page.textContent('body');
    const contains = bodyText?.includes(action.expect.visible_text_contains) ?? false;
    results.push({
      check: 'visible_text_contains',
      expected: action.expect.visible_text_contains,
      actual: contains ? 'present' : 'absent',
      passed: contains,
    });
  }

  // Frame hash changed (action had visible effect)
  const postScreenshot = await page.screenshot({ type: 'png' });
  const postHash = hash(postScreenshot);
  if (postHash === preState.frameHash) {
    results.push({
      check: 'frame_changed',
      expected: 'different',
      actual: 'same',
      passed: false,  // WARNING: action may have had no visible effect
    });
  }

  const allPassed = results.every((r) => r.passed);
  return { checks: results, allPassed };
}
```

### Failure Taxonomy

Per the reviewer gap-fill requirement, the CUA gateway must emit distinct, machine-parseable failure types:

| Failure Class | Code | Description | Receipt Metadata |
|---------------|------|-------------|------------------|
| **Protocol Failure** | `CUA_PROTOCOL_ERROR` | CDP/BiDi WebSocket disconnected, browser crashed, timeout on CDP response | `error.protocol`, `error.browser_state` |
| **Policy Deny** | `CUA_POLICY_DENY` | Action blocked by egress guard, action allowlist, or target validation | `policy.rule_id`, `policy.reason` |
| **Target Mismatch** | `CUA_TARGET_MISMATCH` | AX node at coordinates does not match declared intent | `target.expected`, `target.actual`, `target.coordinates` |
| **Post-Condition Mismatch** | `CUA_POSTCONDITION_FAIL` | URL, visible text, or frame hash did not change as expected | `postcondition.check`, `postcondition.expected`, `postcondition.actual` |
| **Timeout** | `CUA_TIMEOUT` | Action or evidence capture exceeded deadline | `timeout.deadline_ms`, `timeout.phase` (`pre_capture`, `action`, `post_capture`) |
| **Replay Mismatch** | `CUA_REPLAY_MISMATCH` | Deterministic replay produced different evidence hashes | `replay.expected_hash`, `replay.actual_hash` |

**Failure response format:**

```json
{
  "status": "error",
  "failure": {
    "class": "CUA_TARGET_MISMATCH",
    "code": "target_mismatch",
    "message": "AX node at (500, 300) is 'link/Learn More', expected 'button/Submit'",
    "evidence": {
      "pre_frame_hash": "sha256:abc...",
      "ax_node_at_point": { "role": "link", "name": "Learn More" },
      "expected_target": { "role": "button", "name": "Submit" }
    }
  },
  "receipt_id": "rcpt_01HXYZ...",
  "policy_decision_id": "pd_01HXYZ..."
}
```

### Clawdstrike Receipt Integration

CUA browser evidence integrates with the existing `SignedReceipt` system via namespaced metadata:

```json
{
  "schema_version": "1.0.0",
  "id": "rcpt_01HXYZ...",
  "provenance": {
    "guard": "cua_browser",
    "policy": "browser-strict",
    "action_type": "browser_click"
  },
  "metadata": {
    "clawdstrike.cua.session_id": "sess_01HXYZ...",
    "clawdstrike.cua.action_id": "act_01HXYZ...",
    "clawdstrike.cua.action_kind": "click",
    "clawdstrike.cua.target": {
      "role": "button",
      "name": "Submit",
      "resolved_via": "ax_query",
      "coordinates": { "x": 500, "y": 300 }
    },
    "clawdstrike.cua.evidence.pre_frame_hash": "sha256:...",
    "clawdstrike.cua.evidence.post_frame_hash": "sha256:...",
    "clawdstrike.cua.evidence.pre_ax_hash": "sha256:...",
    "clawdstrike.cua.evidence.post_ax_hash": "sha256:...",
    "clawdstrike.cua.evidence.event_hash": "sha256:...",
    "clawdstrike.cua.evidence.prev_event_hash": "sha256:...",
    "clawdstrike.cua.postcondition.url": "https://example.com/success",
    "clawdstrike.cua.postcondition.all_passed": true,
    "clawdstrike.cua.artifacts.bundle_digest": "sha256:...",
    "clawdstrike.cua.artifacts.storage": "local",
    "clawdstrike.cua.policy_decision_id": "pd_01HXYZ..."
  }
}
```

This preserves compatibility with the existing receipt verification toolchain while adding CUA-specific evidence.

### Egress Guard Integration

Browser navigation and network requests map directly into the existing `EgressAllowlistGuard`:

```typescript
// Bridge: CUA browser navigation -> Clawdstrike egress guard
async function checkNavigationPolicy(
  url: string,
  egressGuard: EgressAllowlistGuard
): Promise<PolicyDecision> {
  const parsed = new URL(url);

  // Map to existing guard action format
  const action = {
    action_type: 'network',
    target: parsed.hostname,
    metadata: {
      protocol: parsed.protocol,
      port: parsed.port || (parsed.protocol === 'https:' ? '443' : '80'),
      path: parsed.pathname,
      source: 'cua_browser_navigation',
    },
  };

  return egressGuard.check(action);
}

// Install as Playwright route handler
await page.route('**/*', async (route) => {
  const decision = await checkNavigationPolicy(
    route.request().url(),
    egressGuard
  );

  if (decision.verdict === 'deny') {
    auditLog.emit('cua_egress_denied', {
      url: route.request().url(),
      rule_id: decision.rule_id,
      reason: decision.reason,
    });
    route.abort('blockedbyclient');
    return;
  }

  route.continue();
});
```

---

## Comparison Matrix

### Browser Automation Tools

| Tool | Language | Protocol | Browser Support | A11y Access | Screenshot | Tracing | License | CUA Fit |
|------|---------|----------|-----------------|-------------|------------|---------|---------|---------|
| **Playwright** | TS, Python, Java, .NET | Internal + CDP | Chromium, Firefox, WebKit | `accessibility.snapshot()` cross-engine; ARIA matching | `page.screenshot()` with clip, fullPage, mask | Built-in trace viewer + HAR | Apache-2.0 | **Primary executor** |
| **Puppeteer** | TypeScript | CDP, BiDi | Chromium, Firefox | CDP `Accessibility.getFullAXTree` | `page.screenshot()` | Chrome trace + BiDi events | Apache-2.0 | Secondary / CDP specialist |
| **Selenium 4** | Multi-language | WebDriver + BiDi | Chrome, Firefox, Edge, Safari | Via browser-specific drivers | Via WebDriver screenshot command | BiDi events; no built-in viewer | Apache-2.0 | Grid scaling; cross-browser compliance |
| **chromedp** | Go | CDP | Chromium | CDP `Accessibility.getFullAXTree` | `chromedp.CaptureScreenshot` | CDP event listeners | MIT | **Go-based gateway** |
| **CDP (raw)** | Any (WebSocket) | CDP | Chromium | Full AX tree, query, partial tree | `Page.captureScreenshot` | All domains; full event stream | N/A (protocol) | Telemetry backbone |
| **WebDriver BiDi** | Any (WebSocket) | BiDi | Chrome, Firefox, Safari (partial) | Emerging (not yet equivalent to CDP) | `browsingContext.captureScreenshot` | Event subscriptions | W3C spec | Future standard; plan for it |
| **chromedp-proxy** | Go | CDP (proxy) | Chromium | Pass-through | Pass-through | Full CDP message log | MIT | CDP method allowlisting |
| **cdp-proxy-interceptor** | TypeScript | CDP (MITM proxy) | Chromium | Pass-through + modification | Pass-through + modification | Plugin-based audit log | MIT | Policy enforcement + redaction |

### Protocol Comparison

| Aspect | CDP | WebDriver BiDi | WebDriver Classic |
|--------|-----|-----------------|-------------------|
| **Transport** | WebSocket JSON-RPC | WebSocket JSON-RPC | HTTP REST |
| **Direction** | Bidirectional (events + commands) | Bidirectional (events + commands) | Request-response only |
| **Browser coverage** | Chromium only | Chrome, Firefox, Safari (growing) | All major browsers |
| **Accessibility access** | Full (`getFullAXTree`, `queryAXTree`) | Emerging | None native |
| **Input dispatch** | `Input.dispatchMouseEvent/KeyEvent` | `input.performActions` | Actions API |
| **Network interception** | `Fetch.requestPaused` / `Network.setRequestInterception` | `network.addIntercept` | Limited |
| **Screenshot** | `Page.captureScreenshot` with clip, format, quality | `browsingContext.captureScreenshot` | `takeScreenshot` |
| **DOM access** | Full (`DOM.getDocument`, `querySelector`, `getOuterHTML`) | Via `script.evaluate` | `findElement` + properties |
| **Standardization** | De facto (Chrome team) | W3C Working Draft | W3C Recommendation |
| **Stability** | Stable but can change between Chrome versions | Evolving; breaking changes possible | Stable |
| **CUA recommendation** | **Primary** for Chromium MVP | **Plan for future**; use for Firefox | Use via Selenium Grid if needed |

---

## Suggested Experiments (Detailed)

### Experiment 1: "Double Capture" Wrapper Benchmarking

**Goal:** Measure the overhead of pre/post screenshot + AX snapshot capture per action.

**Setup:**

```typescript
// Benchmark harness
const actions = [
  { kind: 'click', selector: 'button#submit' },
  { kind: 'type', selector: 'input#email', text: 'test@example.com' },
  { kind: 'navigate', url: 'https://example.com/page2' },
];

// Modes to compare
const modes = {
  'no_capture': async (page, action) => {
    await executeAction(page, action);
  },
  'screenshot_only': async (page, action) => {
    await page.screenshot();
    await executeAction(page, action);
    await page.screenshot();
  },
  'screenshot_plus_ax': async (page, action) => {
    await page.screenshot();
    await page.accessibility.snapshot();
    await executeAction(page, action);
    await page.screenshot();
    await page.accessibility.snapshot();
  },
  'full_evidence': async (page, action) => {
    const pre = await captureEvidence(page);  // screenshot + AX + URL + hash
    await executeAction(page, action);
    const post = await captureEvidence(page);
    buildHashChain(pre, post, action);
  },
};
```

**Metrics to collect:**

| Metric | Unit | Expected Range |
|--------|------|----------------|
| Pre-capture latency | ms | 20-100ms |
| Post-capture latency | ms | 20-100ms |
| AX snapshot latency | ms | 10-50ms |
| SHA-256 hash time | ms | <1ms |
| Total per-action overhead | ms | 50-250ms |
| Screenshot PNG size | KB | 50-500KB |
| AX tree JSON size | KB | 5-100KB |

### Experiment 2: Fault Injection

**Goal:** Verify the failure taxonomy handles all edge cases.

**Scenarios:**

| Scenario | Injection Method | Expected Failure Class |
|----------|-----------------|----------------------|
| Stale selector | Remove element via `page.evaluate`, then attempt click | `CUA_TARGET_MISMATCH` or `CUA_PROTOCOL_ERROR` |
| Changed URL (navigation race) | Navigate away before action completes | `CUA_POSTCONDITION_FAIL` |
| Hidden element | Set `display:none` on target | `CUA_TARGET_MISMATCH` (element not visible) |
| Cross-origin iframe | Target inside iframe with different origin | `CUA_PROTOCOL_ERROR` (frame access denied) |
| Browser crash | Kill browser process mid-action | `CUA_PROTOCOL_ERROR` (WebSocket disconnected) |
| CDP timeout | Delay CDP response beyond deadline | `CUA_TIMEOUT` |
| AX tree disagreement | Overlay a different element at target coordinates | `CUA_TARGET_MISMATCH` (coordinate_ax_disagreement) |

### Experiment 3: Headless vs Headed Performance

**Goal:** Compare action+evidence overhead across Chromium headless and headed modes.

**Variables:**

| Variable | Headless (new) | Headless (old) | Headed |
|----------|---------------|----------------|--------|
| Chrome flag | `--headless=new` | `--headless=old` | (none) |
| GPU acceleration | Software | Software | Hardware (if available) |
| Screenshot fidelity | Full | Reduced | Full |
| Font rendering | May differ | May differ | Native |
| Expected overhead | Baseline | Lower | Higher (GPU sync) |

**What to measure:**

- Screenshot capture time (mean, p95, p99 over 1000 iterations)
- AX tree fetch time
- Visual fidelity: compare screenshot hashes between headless and headed for the same page state
- Memory usage per context
- CPU usage during action execution

**Note:** Playwright 1.57+ uses Chrome for Testing for both headed and headless, which should reduce fidelity differences compared to earlier Chromium builds.

### Experiment 4: Deterministic Replay Corpus

**Goal:** Detect instrumentation drift by replaying the same actions against the same page state and verifying evidence hashes remain identical.

**Setup:**

1. Create a static HTML fixture set (no external resources, no dynamic content).
2. Record a sequence of actions with evidence.
3. Replay the same sequence on a fresh browser instance.
4. Compare all evidence hashes (screenshot, AX tree, event chain).

**Expected outcome:** All hashes match. If they diverge, investigate:
- Font rendering differences (subpixel hinting, antialiasing)
- Timestamp-dependent content
- Non-deterministic element ordering in AX tree
- Browser version differences

**Mitigation for non-determinism:** Use perceptual hashing (pHash) alongside SHA-256 to detect "visually identical but byte-different" screenshots. Set a similarity threshold (e.g., Hamming distance < 5 on pHash) for the replay corpus rather than requiring exact byte equality.

---

## References

### Playwright
- [Playwright Documentation](https://playwright.dev/docs/intro)
- [Playwright GitHub](https://github.com/microsoft/playwright)
- [Playwright Release Notes](https://playwright.dev/docs/release-notes)
- [Playwright Isolation (Browser Contexts)](https://playwright.dev/docs/browser-contexts)
- [Playwright Tracing API](https://playwright.dev/docs/api/class-tracing)
- [Playwright Trace Viewer](https://playwright.dev/docs/trace-viewer)
- [Playwright Screenshots](https://playwright.dev/docs/screenshots)
- [Playwright ARIA Snapshot Testing](https://playwright.dev/docs/aria-snapshots)
- [Playwright Network Interception](https://playwright.dev/docs/network)
- [Playwright Test Generator (Codegen)](https://playwright.dev/docs/codegen)
- [Playwright Agents (AI)](https://playwright.dev/docs/test-agents)
- [Playwright MCP Server GitHub](https://github.com/microsoft/playwright-mcp)
- [Playwright Architecture Explained (BrowserStack)](https://www.browserstack.com/guide/playwright-architecture)

### Puppeteer
- [Puppeteer Documentation](https://pptr.dev)
- [Puppeteer WebDriver BiDi](https://pptr.dev/webdriver-bidi)
- [Puppeteer BiDi Readiness Tracker](https://puppeteer.github.io/ispuppeteerwebdriverbidiready/)
- [WebDriver BiDi production-ready in Firefox, Chrome and Puppeteer](https://developer.chrome.com/blog/firefox-support-in-puppeteer-with-webdriver-bidi)
- [Deprecating CDP Support in Firefox](https://fxdx.dev/deprecating-cdp-support-in-firefox-embracing-the-future-with-webdriver-bidi/)

### Chrome DevTools Protocol
- [CDP Reference (all domains)](https://chromedevtools.github.io/devtools-protocol/)
- [CDP Accessibility Domain](https://chromedevtools.github.io/devtools-protocol/tot/Accessibility/)
- [CDP Page Domain](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [CDP Input Domain](https://chromedevtools.github.io/devtools-protocol/tot/Input/)
- [CDP Network Domain](https://chromedevtools.github.io/devtools-protocol/tot/Network/)
- [Full Accessibility Tree in Chrome DevTools](https://developer.chrome.com/blog/full-accessibility-tree)

### WebDriver BiDi
- [W3C WebDriver BiDi Specification](https://www.w3.org/TR/webdriver-bidi/)
- [WebDriver BiDi GitHub](https://github.com/w3c/webdriver-bidi)
- [Chromium BiDi Implementation](https://github.com/GoogleChromeLabs/chromium-bidi)
- [WebDriver BiDi: The Future of Browser Automation](https://developer.chrome.com/blog/webdriver-bidi)

### Selenium
- [Selenium Documentation](https://www.selenium.dev/documentation/)
- [Selenium BiDi Support](https://www.selenium.dev/documentation/webdriver/bidi/)
- [Selenium Grid Docker](https://github.com/SeleniumHQ/docker-selenium)
- [Selenium Grid KEDA Autoscaling](https://www.selenium.dev/blog/2022/scaling-grid-with-keda/)
- [Selenium 4.30 Release](https://www.selenium.dev/blog/2025/selenium-4-30-released/)

### chromedp
- [chromedp GitHub](https://github.com/chromedp/chromedp)
- [chromedp Go Package Documentation](https://pkg.go.dev/github.com/chromedp/chromedp)
- [cdproto (CDP types for Go)](https://pkg.go.dev/github.com/chromedp/cdproto)
- [chromedp DeepWiki Overview](https://deepwiki.com/chromedp/chromedp/1-overview)

### CDP Proxies
- [chromedp-proxy GitHub](https://github.com/chromedp/chromedp-proxy)
- [cdp-proxy-interceptor GitHub](https://github.com/zackiles/cdp-proxy-interceptor)

### Clawdstrike Integration
- [Clawdstrike CLAUDE.md](../../CLAUDE.md)
- [CUA Deep Research Report](../deep-research-report.md)
- [Sibling: 02 Remote Desktop](./02-remote-desktop.md)
- [Sibling: 03 Input Injection](./03-input-injection.md)
