import { useEffect } from "react";
import { isTauri, startMarketplaceDiscovery } from "@/services/tauri";
import { loadMarketplaceDiscoverySettings } from "@/services/marketplaceDiscoverySettings";

export function MarketplaceDiscoveryBootstrap() {
  useEffect(() => {
    if (!isTauri()) return;
    const settings = loadMarketplaceDiscoverySettings();
    if (!settings.enabled) return;

    startMarketplaceDiscovery({
      listen_port: settings.listenPort,
      bootstrap: settings.bootstrap,
      topic: settings.topic,
    }).catch(() => {
      // Ignore (status will show in settings if the user opens it)
    });
  }, []);

  return null;
}

