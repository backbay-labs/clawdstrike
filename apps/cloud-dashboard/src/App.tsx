import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { SharedSSEProvider } from "./context/SSEContext";
import { Dashboard } from "./pages/Dashboard";
import { Events } from "./pages/Events";
import { AuditLog } from "./pages/AuditLog";
import { Policies } from "./pages/Policies";
import { Settings } from "./pages/Settings";

function routerBasename(): string | undefined {
  const baseUrl = import.meta.env.BASE_URL || "/";
  if (baseUrl === "/") {
    return undefined;
  }
  return baseUrl.endsWith("/") ? baseUrl.slice(0, -1) : baseUrl;
}

export function App() {
  return (
    <SharedSSEProvider>
      <BrowserRouter basename={routerBasename()}>
        <Routes>
          <Route element={<Layout />}>
            <Route path="/" element={<Dashboard />} />
            <Route path="/events" element={<Events />} />
            <Route path="/audit" element={<AuditLog />} />
            <Route path="/policies" element={<Policies />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/settings/siem" element={<Settings initialSection="siem" />} />
            <Route path="/settings/webhooks" element={<Settings initialSection="webhooks" />} />
          </Route>
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </SharedSSEProvider>
  );
}
