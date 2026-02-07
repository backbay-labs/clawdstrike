import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { Dashboard } from "./pages/Dashboard";
import { Agents } from "./pages/Agents";
import { Events } from "./pages/Events";
import { Policies } from "./pages/Policies";
import { Alerts } from "./pages/Alerts";
import { Compliance } from "./pages/Compliance";
import { Settings } from "./pages/Settings";
import { Login } from "./pages/Login";

export function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/" element={<Dashboard />} />
        <Route path="/agents" element={<Agents />} />
        <Route path="/events" element={<Events />} />
        <Route path="/policies" element={<Policies />} />
        <Route path="/alerts" element={<Alerts />} />
        <Route path="/compliance" element={<Compliance />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
