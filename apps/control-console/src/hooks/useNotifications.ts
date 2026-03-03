import { useCallback, useState } from "react";

export interface AppNotification {
  id: string;
  message: string;
  type: "info" | "warning" | "error";
  timestamp: string;
  read: boolean;
}

let _notifId = 1;

export function useNotifications() {
  const [notifications, setNotifications] = useState<AppNotification[]>([]);

  const add = useCallback((message: string, type: AppNotification["type"] = "info") => {
    setNotifications((prev) => {
      const next = [
        { id: String(_notifId++), message, type, timestamp: new Date().toISOString(), read: false },
        ...prev,
      ];
      return next.slice(0, 100);
    });
  }, []);

  const markRead = useCallback((id: string) => {
    setNotifications((prev) => prev.map((n) => (n.id === id ? { ...n, read: true } : n)));
  }, []);

  const markAllRead = useCallback(() => {
    setNotifications((prev) => prev.map((n) => ({ ...n, read: true })));
  }, []);

  const clear = useCallback(() => setNotifications([]), []);

  const unreadCount = notifications.filter((n) => !n.read).length;

  return { notifications, add, markRead, markAllRead, clear, unreadCount };
}
