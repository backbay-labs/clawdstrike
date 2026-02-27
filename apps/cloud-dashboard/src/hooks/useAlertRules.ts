import { useCallback, useEffect, useRef, useState } from "react";
import type { SSEEvent } from "./useSSE";

export interface AlertRule {
  id: string;
  threshold: number;
  windowMinutes: number;
  webhookUrl?: string;
  enabled: boolean;
}

const STORAGE_KEY = "cs_alert_rules";
const RULES_CHANGED_EVENT = "clawdstrike:alert-rules-changed";

function loadRules(): AlertRule[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch (err) {
    console.warn("[AlertRules] failed to load rules:", err);
    return [];
  }
}

function persistRules(rules: AlertRule[]) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(rules));
  window.dispatchEvent(new Event(RULES_CHANGED_EVENT));
}

function generateId(): string {
  return `rule_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
}

export function useAlertRules(events: SSEEvent[], options?: { evaluate?: boolean }) {
  const shouldFireSideEffects = options?.evaluate ?? true;
  const [rules, setRules] = useState<AlertRule[]>(loadRules);
  const [triggered, setTriggered] = useState(false);

  // Sync rules from other hook instances (e.g. Settings editing while desktop evaluates)
  useEffect(() => {
    const handler = () => setRules(loadRules());
    window.addEventListener(RULES_CHANGED_EVENT, handler);
    return () => window.removeEventListener(RULES_CHANGED_EVENT, handler);
  }, []);

  const addRule = useCallback((rule: Omit<AlertRule, "id">) => {
    setRules((prev) => {
      const next = [...prev, { ...rule, id: generateId() }];
      persistRules(next);
      return next;
    });
  }, []);

  const removeRule = useCallback((id: string) => {
    setRules((prev) => {
      const next = prev.filter((r) => r.id !== id);
      persistRules(next);
      return next;
    });
  }, []);

  const updateRule = useCallback((id: string, updates: Partial<AlertRule>) => {
    setRules((prev) => {
      const next = prev.map((r) => (r.id === id ? { ...r, ...updates } : r));
      persistRules(next);
      return next;
    });
  }, []);

  // Track last notification timestamp per rule to avoid repeated alerts
  const lastAlertRef = useRef<Record<string, number>>({});

  useEffect(() => {
    const now = Date.now();
    let anyTriggered = false;

    for (const rule of rules) {
      if (!rule.enabled) continue;

      const windowMs = rule.windowMinutes * 60 * 1000;
      const cutoff = now - windowMs;
      const violations = events.filter(
        (e) => e.allowed === false && new Date(e.timestamp).getTime() >= cutoff,
      );

      if (violations.length >= rule.threshold) {
        anyTriggered = true;

        // Skip notifications/webhooks when evaluate is false (e.g. Settings UI)
        if (!shouldFireSideEffects) continue;

        // Debounce: only alert once per window period per rule
        const lastAlert = lastAlertRef.current[rule.id] ?? 0;
        if (now - lastAlert < windowMs) continue;
        lastAlertRef.current[rule.id] = now;

        if (typeof Notification !== "undefined" && Notification.permission === "granted") {
          new Notification("ClawdStrike Alert", {
            body: `${violations.length} violations in the last ${rule.windowMinutes}min (threshold: ${rule.threshold})`,
          });
        } else if (typeof Notification !== "undefined" && Notification.permission !== "denied") {
          void Notification.requestPermission();
        }

        if (rule.webhookUrl) {
          void fetch(rule.webhookUrl, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              alert: "violation_threshold",
              count: violations.length,
              threshold: rule.threshold,
              windowMinutes: rule.windowMinutes,
              timestamp: new Date().toISOString(),
            }),
          })
            .then((res) => {
              if (!res.ok)
                console.warn(
                  `[AlertRules] webhook returned ${res.status} for ${rule.webhookUrl}`,
                );
            })
            .catch((err) => {
              console.warn(
                "[AlertRules] webhook delivery failed:",
                rule.webhookUrl,
                err,
              );
            });
        }
      }
    }

    setTriggered(anyTriggered);
  }, [events, rules, shouldFireSideEffects]);

  return { rules, addRule, removeRule, updateRule, triggered };
}
