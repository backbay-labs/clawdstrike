import { NavLink, Outlet } from "react-router-dom";
import { useSharedSSE } from "../context/SSEContext";

const links = [
  { to: "/", label: "Dashboard" },
  { to: "/events", label: "Events" },
  { to: "/audit", label: "Audit Log" },
  { to: "/policies", label: "Policies" },
  { to: "/settings", label: "Settings" },
];

export function Layout() {
  const { status, error, reconnect } = useSharedSSE();
  const statusClass = {
    connected: "border-green-800 bg-green-950/30 text-green-300",
    connecting: "border-blue-800 bg-blue-950/30 text-blue-300",
    disconnected: "border-yellow-800 bg-yellow-950/30 text-yellow-300",
    unauthorized: "border-orange-800 bg-orange-950/30 text-orange-300",
    network_error: "border-red-800 bg-red-950/30 text-red-300",
  }[status];

  const statusLabel = {
    connected: "Connected",
    connecting: "Connecting",
    disconnected: "Disconnected",
    unauthorized: "Unauthorized",
    network_error: "Network Error",
  }[status];

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100">
      <nav className="border-b border-gray-800 bg-gray-900">
        <div className="mx-auto flex max-w-7xl items-center gap-8 px-6 py-3">
          <span className="text-lg font-bold tracking-tight text-white">
            ClawdStrike
          </span>
          <div className="flex gap-1">
            {links.map((link) => (
              <NavLink
                key={link.to}
                to={link.to}
                end={link.to === "/"}
                className={({ isActive }) =>
                  `rounded px-3 py-1.5 text-sm font-medium transition-colors ${
                    isActive
                      ? "bg-gray-800 text-white"
                      : "text-gray-400 hover:bg-gray-800/50 hover:text-gray-200"
                  }`
                }
              >
                {link.label}
              </NavLink>
            ))}
          </div>
        </div>
      </nav>
      <div className="mx-auto mt-3 max-w-7xl px-6">
        <div
          data-testid="sse-connection-banner"
          className={`flex flex-wrap items-center gap-3 rounded border px-3 py-2 text-sm ${statusClass}`}
        >
          <span data-testid="sse-connection-status" className="font-medium">
            SSE: {statusLabel}
          </span>
          {error && <span className="opacity-90">{error}</span>}
          <button
            type="button"
            data-testid="sse-reconnect-button"
            onClick={reconnect}
            className="ml-auto rounded border border-current/40 px-2.5 py-1 text-xs hover:bg-white/5"
          >
            Reconnect
          </button>
        </div>
      </div>
      <main className="mx-auto max-w-7xl px-6 py-8">
        <Outlet />
      </main>
    </div>
  );
}
