/**
 * ShellApp - Root application with a data router for Tauri
 *
 * Routes:
 * - /:appId - Direct app access
 * - / - Redirects to Nexus (default)
 */

import { UiThemeProvider } from "@backbay/glia/theme";
import { Suspense, useMemo } from "react";
import { createHashRouter, Navigate, RouterProvider } from "react-router-dom";
import { ConnectionProvider } from "@/context/ConnectionContext";
import { OpenClawProvider } from "@/context/OpenClawContext";
import { PolicyProvider } from "@/context/PolicyContext";
import { SwarmProvider } from "@/context/SwarmContext";
import { MarketplaceDiscoveryBootstrap } from "./MarketplaceDiscoveryBootstrap";
import { getPlugins } from "./plugins";
import { ShellLayout } from "./ShellLayout";

export function ShellApp() {
  const router = useMemo(() => {
    const plugins = getPlugins();
    const loadingFallback = (
      <div className="flex h-full items-center justify-center text-sdr-text-secondary">
        Loading...
      </div>
    );

    return createHashRouter([
      {
        path: "/",
        element: <ShellLayout />,
        children: [
          {
            index: true,
            element: <Navigate to={`/${plugins[0]?.id ?? "nexus"}`} replace />,
          },
          ...plugins.map((plugin) => ({
            path: plugin.id,
            children: plugin.routes.map((route, idx) => ({
              id: `${plugin.id}-${idx}`,
              index: route.index,
              path: route.index ? undefined : route.path,
              element: <Suspense fallback={loadingFallback}>{route.element}</Suspense>,
            })),
          })),
        ],
      },
    ]);
  }, []);

  return (
    <UiThemeProvider themeId="nebula">
      <ConnectionProvider>
        <OpenClawProvider>
          <PolicyProvider>
            <SwarmProvider>
              <MarketplaceDiscoveryBootstrap />
              <RouterProvider router={router} />
            </SwarmProvider>
          </PolicyProvider>
        </OpenClawProvider>
      </ConnectionProvider>
    </UiThemeProvider>
  );
}
