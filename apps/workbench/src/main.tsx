import React from "react";
import ReactDOM from "react-dom/client";
import { App } from "./App";
import "./globals.css";
import "@/lib/workbench/detection-workflow/index";
import { logger } from "@/lib/logger";


window.addEventListener("unhandledrejection", (event) => {
  logger.error("[unhandled-rejection]", event.reason);
});

window.onerror = (message, source, lineno, colno, error) => {
  logger.error("[uncaught-error]", { message, source, lineno, colno, error });
};

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
