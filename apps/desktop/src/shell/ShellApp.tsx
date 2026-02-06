/**
 * ShellApp - Root application with HashRouter for Tauri
 *
 * Routes:
 * - /:appId - Direct app access
 * - / - Redirects to Event Stream (default)
 */
import { Suspense } from "react";
import { HashRouter, Routes, Route, Navigate } from "react-router-dom";
import { ShellLayout } from "./ShellLayout";
import { getPlugins } from "./plugins";
import { ConnectionProvider } from "@/context/ConnectionContext";
import { PolicyProvider } from "@/context/PolicyContext";
import { SwarmProvider } from "@/context/SwarmContext";
import { MarketplaceDiscoveryBootstrap } from "./MarketplaceDiscoveryBootstrap";

export function ShellApp() {
  const plugins = getPlugins();

  return (
    <ConnectionProvider>
      <PolicyProvider>
        <SwarmProvider>
          <MarketplaceDiscoveryBootstrap />
          <HashRouter>
            <Routes>
              {/* Main shell with navigation */}
              <Route path="/" element={<ShellLayout />}>
                {/* Default redirect to events view */}
                <Route
                  index
                  element={<Navigate to={`/${plugins[0]?.id ?? "events"}`} replace />}
                />

                {/* Dynamic plugin routes */}
                {plugins.map((plugin) => (
                  <Route key={plugin.id} path={plugin.id}>
                    {plugin.routes.map((route, idx) => (
                      <Route
                        key={`${plugin.id}-${idx}`}
                        index={route.index}
                        path={route.index ? undefined : route.path}
                        element={
                          <Suspense
                            fallback={
                              <div className="flex items-center justify-center h-full text-sdr-text-secondary">
                                Loading...
                              </div>
                            }
                          >
                            {route.element}
                          </Suspense>
                        }
                      />
                    ))}
                  </Route>
                ))}
              </Route>
            </Routes>
          </HashRouter>
        </SwarmProvider>
      </PolicyProvider>
    </ConnectionProvider>
  );
}
