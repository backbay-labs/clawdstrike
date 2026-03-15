import React from "react";
import ReactDOM from "react-dom/client";
import { App } from "./App";
import "./globals.css";
import "@/lib/workbench/detection-workflow/index";


window.addEventListener("unhandledrejection", (event) => {
  console.error("[unhandled-rejection]", event.reason);
});

window.onerror = (message, source, lineno, colno, error) => {
  console.error("[uncaught-error]", { message, source, lineno, colno, error });
};

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
