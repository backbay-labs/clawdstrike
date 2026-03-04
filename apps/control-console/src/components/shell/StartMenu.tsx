import { useDesktopOS } from "@backbay/glia-desktop";
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ChangeEvent,
  type CSSProperties,
} from "react";
import { useSharedSSE } from "../../context/SSEContext";
import {
  allApps,
  desktopIconGroups,
  PROCESS_ICONS,
  startMenuDefaultPinnedIds,
  type DesktopIconConfig,
} from "../../state/processRegistry";

const START_MENU_PINS_KEY = "cs.startmenu.pins.v1";
const START_MENU_RECENTS_KEY = "cs.startmenu.recents.v1";
const MAX_RECENTS = 8;

type StartMenuView = "home" | "all";

function readStoredIds(key: string, fallback: string[]): string[] {
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return fallback;
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return fallback;
    const values = parsed.filter((value): value is string => typeof value === "string");
    return values.length > 0 ? values : fallback;
  } catch {
    return fallback;
  }
}

function writeStoredIds(key: string, values: string[]) {
  localStorage.setItem(key, JSON.stringify(values));
}

function latestSecurityEvents(events: Array<{ event_type: string; target?: string; timestamp: string }>) {
  return events
    .filter((event) => event.event_type === "violation" || event.event_type === "policy_updated")
    .slice(0, 5);
}

function appDescriptionFor(
  app: DesktopIconConfig,
  processes: ReturnType<typeof useDesktopOS>["processes"],
): string {
  const def = processes.getDefinition(app.processId);
  return def?.description ?? "";
}

export function StartMenu() {
  const [open, setOpen] = useState(false);
  const [view, setView] = useState<StartMenuView>("home");
  const [searchQuery, setSearchQuery] = useState("");
  const [pinnedIds, setPinnedIds] = useState<string[]>(() =>
    readStoredIds(START_MENU_PINS_KEY, startMenuDefaultPinnedIds),
  );
  const [recentIds, setRecentIds] = useState<string[]>(() => readStoredIds(START_MENU_RECENTS_KEY, []));
  const menuRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const layoutImportRef = useRef<HTMLInputElement>(null);
  const { processes } = useDesktopOS();
  const { events } = useSharedSSE();

  const quickFeed = useMemo(() => latestSecurityEvents(events), [events]);

  const runningProcessIds = useMemo(
    () => new Set(processes.instances.map((instance) => instance.processId)),
    [processes.instances],
  );

  const appById = useMemo(() => {
    const map = new Map<string, DesktopIconConfig>();
    for (const app of allApps) {
      map.set(app.id, app);
    }
    return map;
  }, []);

  const pinnedApps = useMemo(
    () => pinnedIds.map((id) => appById.get(id)).filter((app): app is DesktopIconConfig => Boolean(app)),
    [appById, pinnedIds],
  );

  const recentApps = useMemo(
    () => recentIds.map((id) => appById.get(id)).filter((app): app is DesktopIconConfig => Boolean(app)),
    [appById, recentIds],
  );

  const filteredApps = useMemo(() => {
    if (!searchQuery.trim()) return allApps;
    const query = searchQuery.trim().toLowerCase();
    return allApps.filter((app) => {
      const def = processes.getDefinition(app.processId);
      return (
        app.label.toLowerCase().includes(query) ||
        app.processId.toLowerCase().includes(query) ||
        (def?.description?.toLowerCase().includes(query) ?? false)
      );
    });
  }, [processes, searchQuery]);

  const toggle = useCallback(() => {
    setOpen((current) => !current);
  }, []);

  const closeMenu = useCallback(() => {
    setOpen(false);
    setSearchQuery("");
    setView("home");
  }, []);

  const markRecent = useCallback((appId: string) => {
    setRecentIds((current) => {
      const next = [appId, ...current.filter((value) => value !== appId)].slice(0, MAX_RECENTS);
      writeStoredIds(START_MENU_RECENTS_KEY, next);
      return next;
    });
  }, []);

  const togglePin = useCallback((appId: string) => {
    setPinnedIds((current) => {
      const next = current.includes(appId)
        ? current.filter((value) => value !== appId)
        : [appId, ...current].slice(0, 8);
      writeStoredIds(START_MENU_PINS_KEY, next);
      return next;
    });
  }, []);

  const launchApp = useCallback(
    (app: DesktopIconConfig) => {
      processes.launch(app.processId);
      markRecent(app.id);
      closeMenu();
    },
    [closeMenu, markRecent, processes],
  );

  const exportLayout = useCallback(() => {
    const payload = {
      version: 1,
      exported_at: new Date().toISOString(),
      pinned_ids: pinnedIds,
      recent_ids: recentIds,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "clawdstrike-start-layout.json";
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    setTimeout(() => URL.revokeObjectURL(url), 100);
  }, [pinnedIds, recentIds]);

  const importLayout = useCallback((rawText: string) => {
    const parsed = JSON.parse(rawText);
    const importedPinned = Array.isArray(parsed?.pinned_ids)
      ? parsed.pinned_ids.filter((value: unknown): value is string => typeof value === "string")
      : [];
    const importedRecent = Array.isArray(parsed?.recent_ids)
      ? parsed.recent_ids.filter((value: unknown): value is string => typeof value === "string")
      : [];

    const nextPinned = importedPinned.slice(0, 8);
    const nextRecent = importedRecent.slice(0, MAX_RECENTS);

    if (nextPinned.length > 0) {
      setPinnedIds(nextPinned);
      writeStoredIds(START_MENU_PINS_KEY, nextPinned);
    }
    if (nextRecent.length > 0) {
      setRecentIds(nextRecent);
      writeStoredIds(START_MENU_RECENTS_KEY, nextRecent);
    }
  }, []);

  const onLayoutImportSelected = useCallback(
    async (event: ChangeEvent<HTMLInputElement>) => {
      const file = event.target.files?.[0];
      if (!file) return;
      try {
        importLayout(await file.text());
      } catch {
        // Ignore malformed imports to avoid breaking the menu.
      } finally {
        event.target.value = "";
      }
    },
    [importLayout],
  );

  useEffect(() => {
    if (!open) return;
    const onMouseDown = (event: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        closeMenu();
      }
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        closeMenu();
      }
    };
    document.addEventListener("mousedown", onMouseDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("mousedown", onMouseDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [closeMenu, open]);

  useEffect(() => {
    if (!open) return;
    const timer = window.setTimeout(() => inputRef.current?.focus(), 80);
    return () => window.clearTimeout(timer);
  }, [open]);

  return (
    <div ref={menuRef} style={{ position: "relative", height: "100%", zIndex: 100 }}>
      <button
        type="button"
        onClick={toggle}
        className="start-menu-btn"
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          height: "100%",
          padding: "0 16px",
          border: "none",
          background: open
            ? "linear-gradient(180deg, rgba(214,177,90,0.14) 0%, rgba(214,177,90,0.06) 100%)"
            : "transparent",
          borderRight: "1px solid rgba(27,34,48,0.5)",
          cursor: "pointer",
          transition: "all 0.2s ease",
          position: "relative",
        }}
      >
        <img
          src={`${import.meta.env.BASE_URL}clawdstrike-logo.png`}
          alt="ClawdStrike"
          draggable={false}
          style={{
            height: 42,
            width: "auto",
            opacity: open ? 1 : 0.8,
            transition: "all 0.2s ease",
            filter: open ? "brightness(1.2)" : "brightness(1)",
          }}
        />
        {open && (
          <div
            style={{
              position: "absolute",
              bottom: 0,
              left: 16,
              right: 16,
              height: 2,
              borderRadius: 1,
              background: "var(--gold)",
              opacity: 0.5,
            }}
          />
        )}
      </button>

      {open && (
        <div
          style={{
            position: "absolute",
            bottom: "100%",
            left: 0,
            marginBottom: 6,
            width: 610,
            maxWidth: "80vw",
            height: 560,
            background: "rgba(11,13,16,0.97)",
            border: "1px solid var(--gold-edge)",
            borderRadius: "var(--radius-window)",
            boxShadow:
              "0 -8px 32px rgba(0,0,0,0.6), 0 0 1px rgba(214,177,90,0.2), inset 0 1px 0 rgba(255,255,255,0.03)",
            backdropFilter: "blur(16px)",
            display: "grid",
            gridTemplateColumns: "170px 1fr",
            overflow: "hidden",
          }}
        >
          <aside
            style={{
              borderRight: "1px solid rgba(27,34,48,0.7)",
              background: "rgba(4,6,10,0.45)",
              padding: 10,
              display: "flex",
              flexDirection: "column",
              gap: 8,
            }}
          >
            <button
              type="button"
              onClick={() => setView("home")}
              style={sidebarButtonStyle(view === "home")}
            >
              Home
            </button>
            <button
              type="button"
              onClick={() => setView("all")}
              style={sidebarButtonStyle(view === "all")}
            >
              All Apps
            </button>

            <div
              className="font-mono"
              style={{
                marginTop: 6,
                fontSize: 10,
                letterSpacing: "0.12em",
                textTransform: "uppercase",
                color: "rgba(154,167,181,0.5)",
                padding: "0 6px",
              }}
            >
              Pinned
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
              {pinnedApps.length === 0 && (
                <div
                  className="font-mono"
                  style={{
                    fontSize: 10,
                    color: "rgba(154,167,181,0.4)",
                    padding: "6px",
                  }}
                >
                  Pin apps from search or all apps.
                </div>
              )}
              {pinnedApps.map((app) => (
                <button
                  key={app.id}
                  type="button"
                  onClick={() => launchApp(app)}
                  style={{
                    ...sidebarButtonStyle(false),
                    justifyContent: "space-between",
                    gap: 6,
                  }}
                >
                  <span style={{ display: "flex", alignItems: "center", gap: 6, minWidth: 0 }}>
                    <span style={{ display: "flex" }}>{PROCESS_ICONS[app.processId]}</span>
                    <span
                      className="font-mono"
                      style={{ fontSize: 11, color: "var(--text)", overflow: "hidden", textOverflow: "ellipsis" }}
                    >
                      {app.label}
                    </span>
                  </span>
                  {runningProcessIds.has(app.processId) && (
                    <span
                      style={{
                        width: 6,
                        height: 6,
                        borderRadius: "50%",
                        background: "var(--gold)",
                        boxShadow: "0 0 8px var(--gold-bloom)",
                        flexShrink: 0,
                      }}
                    />
                  )}
                </button>
              ))}
            </div>

            <div style={{ marginTop: "auto", display: "grid", gap: 6, paddingTop: 8 }}>
              <button type="button" onClick={exportLayout} style={sidebarButtonStyle(false)}>
                Export Layout
              </button>
              <button
                type="button"
                onClick={() => layoutImportRef.current?.click()}
                style={sidebarButtonStyle(false)}
              >
                Import Layout
              </button>
              <input
                ref={layoutImportRef}
                type="file"
                accept="application/json"
                style={{ display: "none" }}
                onChange={onLayoutImportSelected}
              />
            </div>
          </aside>

          <section style={{ display: "flex", flexDirection: "column", minWidth: 0 }}>
            <div style={{ padding: "12px 14px", borderBottom: "1px solid rgba(27,34,48,0.7)" }}>
              <input
                ref={inputRef}
                type="text"
                value={searchQuery}
                onChange={(event) => setSearchQuery(event.target.value)}
                placeholder="Search apps..."
                className="glass-input font-mono"
                style={{
                  width: "100%",
                  borderRadius: 8,
                  padding: "9px 10px",
                  fontSize: 12,
                  letterSpacing: "0.04em",
                  color: "var(--text)",
                }}
              />
            </div>

            <div style={{ padding: "12px 14px", overflow: "auto", flex: 1 }}>
              {searchQuery.trim() ? (
                <AppList
                  apps={filteredApps}
                  pinnedIds={pinnedIds}
                  runningProcessIds={runningProcessIds}
                  processes={processes}
                  onLaunch={launchApp}
                  onTogglePin={togglePin}
                />
              ) : view === "all" ? (
                <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                  {desktopIconGroups.map((group) => (
                    <div key={group.id}>
                      <div
                        className="font-mono"
                        style={{
                          fontSize: 10,
                          textTransform: "uppercase",
                          letterSpacing: "0.14em",
                          color: "rgba(154,167,181,0.5)",
                          marginBottom: 6,
                        }}
                      >
                        {group.label}
                      </div>
                      <AppList
                        apps={group.icons}
                        pinnedIds={pinnedIds}
                        runningProcessIds={runningProcessIds}
                        processes={processes}
                        onLaunch={launchApp}
                        onTogglePin={togglePin}
                      />
                    </div>
                  ))}
                </div>
              ) : (
                <div style={{ display: "grid", gap: 12 }}>
                  <div>
                    <div
                      className="font-mono"
                      style={{
                        fontSize: 10,
                        textTransform: "uppercase",
                        letterSpacing: "0.14em",
                        color: "rgba(154,167,181,0.5)",
                        marginBottom: 6,
                      }}
                    >
                      Recent
                    </div>
                    {recentApps.length > 0 ? (
                      <AppList
                        apps={recentApps}
                        pinnedIds={pinnedIds}
                        runningProcessIds={runningProcessIds}
                        processes={processes}
                        onLaunch={launchApp}
                        onTogglePin={togglePin}
                      />
                    ) : (
                      <div
                        className="font-mono"
                        style={{ fontSize: 11, color: "rgba(154,167,181,0.45)", padding: "6px 0" }}
                      >
                        Launch apps to build your recent list.
                      </div>
                    )}
                  </div>

                  <div>
                    <div
                      className="font-mono"
                      style={{
                        fontSize: 10,
                        textTransform: "uppercase",
                        letterSpacing: "0.14em",
                        color: "rgba(154,167,181,0.5)",
                        marginBottom: 6,
                      }}
                    >
                      Security Feed
                    </div>
                    <div
                      style={{
                        border: "1px solid rgba(27,34,48,0.7)",
                        borderRadius: 10,
                        overflow: "hidden",
                      }}
                    >
                      {quickFeed.length === 0 && (
                        <div
                          className="font-mono"
                          style={{ fontSize: 11, color: "rgba(154,167,181,0.45)", padding: 10 }}
                        >
                          Waiting for policy events...
                        </div>
                      )}
                      {quickFeed.map((event, idx) => (
                        <div
                          key={`${event.timestamp}-${event.target ?? "none"}-${idx}`}
                          style={{
                            padding: "8px 10px",
                            borderTop: idx === 0 ? "none" : "1px solid rgba(27,34,48,0.55)",
                            display: "flex",
                            alignItems: "center",
                            gap: 8,
                          }}
                        >
                          <span
                            style={{
                              width: 6,
                              height: 6,
                              borderRadius: "50%",
                              background: event.event_type === "violation" ? "var(--crimson)" : "var(--gold)",
                              flexShrink: 0,
                            }}
                          />
                          <span
                            className="font-mono"
                            style={{ fontSize: 10, color: "var(--text)", textTransform: "uppercase" }}
                          >
                            {event.event_type}
                          </span>
                          <span
                            className="font-body"
                            style={{
                              fontSize: 11,
                              color: "rgba(154,167,181,0.7)",
                              overflow: "hidden",
                              textOverflow: "ellipsis",
                              whiteSpace: "nowrap",
                            }}
                          >
                            {event.target ?? "Policy update"}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          </section>
        </div>
      )}
    </div>
  );
}

function sidebarButtonStyle(active: boolean): CSSProperties {
  return {
    display: "flex",
    alignItems: "center",
    justifyContent: "flex-start",
    width: "100%",
    borderRadius: 8,
    border: active ? "1px solid var(--gold-edge)" : "1px solid transparent",
    background: active ? "var(--gold-bloom)" : "transparent",
    color: active ? "var(--gold)" : "var(--muted)",
    fontFamily: '"JetBrains Mono", monospace',
    letterSpacing: "0.06em",
    textTransform: "uppercase",
    fontSize: 10,
    padding: "8px 8px",
    cursor: "pointer",
  };
}

function AppList({
  apps,
  pinnedIds,
  runningProcessIds,
  processes,
  onLaunch,
  onTogglePin,
}: {
  apps: DesktopIconConfig[];
  pinnedIds: string[];
  runningProcessIds: Set<string>;
  processes: ReturnType<typeof useDesktopOS>["processes"];
  onLaunch: (app: DesktopIconConfig) => void;
  onTogglePin: (appId: string) => void;
}) {
  if (apps.length === 0) {
    return (
      <div className="font-mono" style={{ fontSize: 11, color: "rgba(154,167,181,0.45)", padding: "6px 0" }}>
        No matching apps.
      </div>
    );
  }

  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: 8 }}>
      {apps.map((app) => {
        const description = appDescriptionFor(app, processes);
        return (
          <button
            key={app.id}
            type="button"
            onClick={() => onLaunch(app)}
            onContextMenu={(event) => {
              event.preventDefault();
              onTogglePin(app.id);
            }}
            className="hover-row"
            title="Right-click to pin/unpin"
            style={{
              display: "flex",
              alignItems: "flex-start",
              gap: 8,
              border: "1px solid rgba(27,34,48,0.75)",
              borderRadius: 10,
              background: "rgba(4,6,10,0.5)",
              padding: "9px 10px",
              cursor: "pointer",
              textAlign: "left",
              minWidth: 0,
              position: "relative",
            }}
          >
            <span style={{ width: 26, height: 26, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
              {PROCESS_ICONS[app.processId]}
            </span>
            <span style={{ minWidth: 0, display: "grid" }}>
              <span className="font-mono" style={{ fontSize: 11, color: "var(--text)", letterSpacing: "0.04em" }}>
                {app.label}
              </span>
              {description && (
                <span
                  className="font-body"
                  style={{
                    fontSize: 10,
                    color: "rgba(154,167,181,0.6)",
                    whiteSpace: "nowrap",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                  }}
                >
                  {description}
                </span>
              )}
            </span>
            {pinnedIds.includes(app.id) && (
              <span
                style={{
                  position: "absolute",
                  top: 5,
                  right: 5,
                  width: 6,
                  height: 6,
                  borderRadius: "50%",
                  background: "var(--gold)",
                  opacity: 0.75,
                }}
              />
            )}
            {runningProcessIds.has(app.processId) && (
              <span
                style={{
                  position: "absolute",
                  bottom: 5,
                  right: 5,
                  width: 6,
                  height: 6,
                  borderRadius: "50%",
                  background: "var(--teal)",
                  boxShadow: "0 0 8px var(--teal-bloom)",
                }}
              />
            )}
          </button>
        );
      })}
    </div>
  );
}
