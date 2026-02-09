import * as React from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

const rootElement = document.getElementById("root");
if (!rootElement) throw new Error("Root element not found");
const root = rootElement;

function registerSdrRequireShim() {
  const globalWithRegistry = globalThis as typeof globalThis & {
    __sdr_require__?: Record<string, unknown>;
  };

  const registry =
    globalWithRegistry.__sdr_require__ ??
    (globalWithRegistry.__sdr_require__ = Object.create(null));

  // Ensure any `__require("react")` calls resolve to the same React instance the app renders with.
  const reactExports = (React as unknown as { default?: unknown }).default ?? React;
  registry["react"] = reactExports;
}

async function bootstrap() {
  registerSdrRequireShim();

  // Import UI only after the require registry exists, so glia can safely `__require("react")`.
  const { App } = await import("./App");

  createRoot(root).render(
    <React.StrictMode>
      <App />
    </React.StrictMode>
  );
}

bootstrap();
