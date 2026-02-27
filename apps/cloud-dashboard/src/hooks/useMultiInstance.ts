import { useCallback, useState } from "react";
import { notifySSEConfigChanged } from "./useSSE";

export interface HushdInstance {
  id: string;
  name: string;
  url: string;
  apiKey: string;
}

const INSTANCES_KEY = "cs_instances";
const ACTIVE_KEY = "cs_active_instance";

function loadInstances(): HushdInstance[] {
  try {
    const raw = localStorage.getItem(INSTANCES_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch (err) {
    console.warn("[MultiInstance] failed to load instances:", err);
    return [];
  }
}

function persistInstances(instances: HushdInstance[]) {
  localStorage.setItem(INSTANCES_KEY, JSON.stringify(instances));
}

function generateId(): string {
  return `inst_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
}

export function useMultiInstance() {
  const [instances, setInstances] = useState<HushdInstance[]>(loadInstances);
  const [activeId, setActiveId] = useState<string>(
    () => localStorage.getItem(ACTIVE_KEY) || "",
  );

  const addInstance = useCallback((inst: Omit<HushdInstance, "id">) => {
    setInstances((prev) => {
      const next = [...prev, { ...inst, id: generateId() }];
      persistInstances(next);
      return next;
    });
  }, []);

  const removeInstance = useCallback(
    (id: string) => {
      setInstances((prev) => {
        const next = prev.filter((i) => i.id !== id);
        persistInstances(next);
        return next;
      });
      if (activeId === id) {
        setActiveId("");
        localStorage.removeItem(ACTIVE_KEY);
      }
    },
    [activeId],
  );

  const switchTo = useCallback(
    (id: string) => {
      const inst = instances.find((i) => i.id === id);
      if (!inst) return;
      setActiveId(id);
      localStorage.setItem(ACTIVE_KEY, id);
      localStorage.setItem("hushd_url", inst.url);
      if (inst.apiKey) {
        localStorage.setItem("hushd_api_key", inst.apiKey);
      } else {
        localStorage.removeItem("hushd_api_key");
      }
      notifySSEConfigChanged();
    },
    [instances],
  );

  const activeInstance = instances.find((i) => i.id === activeId) ?? null;

  return { instances, activeId, addInstance, removeInstance, switchTo, activeInstance };
}
