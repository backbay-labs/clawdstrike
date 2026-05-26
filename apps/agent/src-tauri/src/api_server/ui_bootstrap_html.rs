//! Static HTML templates for the local UI bootstrap fallback and verify pages.
//!
//! These are returned by the agent's local API when the bundled control console
//! is not present (`agent_web_ui_fallback`) and when an operator visits the
//! bootstrap verification endpoint (`ui_bootstrap_page`).

use axum::response::Html;

/// Fallback dashboard served at `/ui` when the control console bundle is missing.
pub(crate) fn agent_web_ui_fallback_html() -> Html<&'static str> {
    Html(
        r##"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Clawdstrike Agent Web UI</title>
  <style>
    :root {
      color-scheme: light dark;
      --bg: #0d1117;
      --fg: #e6edf3;
      --muted: #8b949e;
      --accent: #2f81f7;
      --card: #161b22;
      --line: #30363d;
    }
    body {
      margin: 0;
      padding: 24px;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: var(--bg);
      color: var(--fg);
    }
    main {
      max-width: 760px;
      margin: 0 auto;
      border: 1px solid var(--line);
      background: var(--card);
      border-radius: 10px;
      padding: 20px;
    }
    h1 { margin-top: 0; font-size: 1.4rem; }
    p { color: var(--muted); line-height: 1.5; }
    code {
      background: rgba(255, 255, 255, 0.08);
      border-radius: 6px;
      padding: 2px 6px;
    }
    .tabs {
      display: flex;
      gap: 8px;
      margin: 14px 0 16px;
      flex-wrap: wrap;
    }
    .tab {
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 6px 12px;
      font-size: 0.9rem;
      color: var(--muted);
      text-decoration: none;
    }
    .tab.active {
      border-color: var(--accent);
      color: #d7e8ff;
      background: rgba(47, 129, 247, 0.12);
    }
    .hidden {
      display: none;
    }
    .panel {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 14px;
      background: rgba(255, 255, 255, 0.03);
    }
    h2 {
      margin: 0 0 8px;
      font-size: 1.05rem;
    }
    ul { margin: 0.75rem 0 0; padding-left: 1.2rem; }
    a { color: var(--accent); text-decoration: none; }
    a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <main>
    <h1>Clawdstrike Agent Web UI</h1>
    <p>This is the local fallback UI. If you expected the control console on <code>localhost:3100</code>, start it manually during development.</p>

    <nav class="tabs" aria-label="Agent web UI sections">
      <a href="#/" class="tab" data-route="/">Overview</a>
      <a href="#/settings/siem" class="tab" data-route="/settings/siem">SIEM Export</a>
      <a href="#/settings/webhooks" class="tab" data-route="/settings/webhooks">Webhooks</a>
    </nav>

    <section class="panel" data-view="/">
      <h2>Overview</h2>
      <ul>
        <li>Agent health (auth required): <a href="/api/v1/agent/health"><code>/api/v1/agent/health</code></a></li>
        <li>Agent settings (auth required): <a href="/api/v1/agent/settings"><code>/api/v1/agent/settings</code></a></li>
      </ul>
    </section>

    <section class="panel hidden" data-view="/settings/siem">
      <h2>SIEM Export</h2>
      <p>Configure SIEM providers from the control console when available. This fallback page confirms the requested route and keeps agent diagnostics available.</p>
      <ul>
        <li>Requested route: <code>#/settings/siem</code></li>
        <li>Preferred full dashboard URL: <code>http://127.0.0.1:3100/settings/siem</code></li>
      </ul>
    </section>

    <section class="panel hidden" data-view="/settings/webhooks">
      <h2>Webhooks</h2>
      <p>Configure webhook forwarding from the control console when available. This fallback page confirms the requested route and keeps agent diagnostics available.</p>
      <ul>
        <li>Requested route: <code>#/settings/webhooks</code></li>
        <li>Preferred full dashboard URL: <code>http://127.0.0.1:3100/settings/webhooks</code></li>
      </ul>
    </section>
  </main>
  <script>
    function normalizeRoute(hash) {
      if (!hash || hash === "#") return "/";
      const raw = hash.startsWith("#") ? hash.slice(1) : hash;
      return raw.startsWith("/") ? raw : `/${raw}`;
    }

    function renderRoute() {
      const route = normalizeRoute(window.location.hash);
      const tabs = document.querySelectorAll("[data-route]");
      const views = document.querySelectorAll("[data-view]");
      const knownRoutes = new Set(["/", "/settings/siem", "/settings/webhooks"]);
      const activeRoute = knownRoutes.has(route) ? route : "/";

      tabs.forEach((tab) => {
        tab.classList.toggle("active", tab.dataset.route === activeRoute);
      });
      views.forEach((view) => {
        view.classList.toggle("hidden", view.dataset.view !== activeRoute);
      });
    }

    window.addEventListener("hashchange", renderRoute);
    renderRoute();
  </script>
</body>
</html>"##,
    )
}

/// Bootstrap-code entry page rendered when a valid `session_id` query param is supplied.
pub(crate) fn ui_bootstrap_page_html() -> Html<&'static str> {
    Html(
        r##"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Clawdstrike Agent Login</title>
  <style>
    body {
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #0f172a;
      color: #e2e8f0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      padding: 24px;
      box-sizing: border-box;
    }
    .card {
      width: 100%;
      max-width: 420px;
      background: #111827;
      border: 1px solid #334155;
      border-radius: 12px;
      padding: 20px;
      box-shadow: 0 12px 28px rgba(2, 6, 23, 0.35);
    }
    h1 {
      margin: 0 0 10px 0;
      font-size: 1.25rem;
    }
    p {
      margin: 0 0 14px 0;
      color: #94a3b8;
      line-height: 1.4;
    }
    label {
      display: block;
      font-weight: 600;
      margin-bottom: 8px;
    }
    input[type="text"] {
      width: 100%;
      box-sizing: border-box;
      border: 1px solid #475569;
      background: #0b1220;
      color: #e2e8f0;
      border-radius: 8px;
      font-size: 1rem;
      padding: 10px 12px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }
    button {
      margin-top: 14px;
      width: 100%;
      border: 0;
      border-radius: 8px;
      padding: 10px 12px;
      font-size: 0.95rem;
      font-weight: 600;
      background: #2563eb;
      color: #f8fafc;
      cursor: pointer;
    }
    .hint {
      margin-top: 12px;
      font-size: 0.85rem;
      color: #64748b;
    }
  </style>
</head>
<body>
  <main class="card">
    <h1>Verify Local Browser Session</h1>
    <p>Enter the one-time code shown by the agent tray to sign in.</p>
    <form method="post" action="/ui/bootstrap">
      <input id="session_id" type="hidden" name="session_id" />
      <label for="user_code">One-time code</label>
      <input id="user_code" name="user_code" type="text" required autocomplete="one-time-code" inputmode="latin-prose" />
      <button type="submit">Continue to Dashboard</button>
    </form>
    <div class="hint">Codes expire after 60 seconds and can only be used once.</div>
  </main>
  <script>
    const params = new URLSearchParams(window.location.search);
    const sessionId = params.get("session_id") || "";
    const field = document.getElementById("session_id");
    if (field) field.value = sessionId;
  </script>
</body>
</html>"##,
    )
}
