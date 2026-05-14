import {
  createContext,
  useContext,
  useCallback,
  useState,
  useEffect,
  useRef,
  type ReactNode,
} from "react";
import { AnimatePresence, motion } from "motion/react";
import {
  IconCheck,
  IconX,
  IconAlertTriangle,
  IconInfoCircle,
} from "@tabler/icons-react";

// ---- Types ----

export interface Toast {
  id: string;
  type: "success" | "error" | "warning" | "info";
  title: string;
  description?: string;
  duration?: number;
}

type ToastInput = Omit<Toast, "id">;

interface ToastContextValue {
  toast: (t: ToastInput) => void;
  dismiss: (id: string) => void;
}

// ---- Context ----

const ToastContext = createContext<ToastContextValue | null>(null);

export function useToast(): ToastContextValue {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error("useToast must be used within ToastProvider");
  return ctx;
}

// ---- Styling maps ----

const BORDER_COLORS: Record<Toast["type"], string> = {
  success: "#3dbf84",
  error: "#c45c5c",
  warning: "#d4a84b",
  info: "#6f7f9a",
};

const ICONS: Record<Toast["type"], typeof IconCheck> = {
  success: IconCheck,
  error: IconX,
  warning: IconAlertTriangle,
  info: IconInfoCircle,
};

const MAX_VISIBLE = 3;
const DEFAULT_DURATION = 3000;

// ---- Provider ----

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const timersRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(
    new Map(),
  );

  const dismiss = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
    const timer = timersRef.current.get(id);
    if (timer) {
      clearTimeout(timer);
      timersRef.current.delete(id);
    }
  }, []);

  const toast = useCallback(
    (input: ToastInput) => {
      const id = crypto.randomUUID();
      const duration = input.duration ?? DEFAULT_DURATION;
      const newToast: Toast = { ...input, id, duration };

      setToasts((prev) => {
        const next = [...prev, newToast];
        // Auto-dismiss oldest if over max
        if (next.length > MAX_VISIBLE) {
          const overflow = next.slice(0, next.length - MAX_VISIBLE);
          for (const old of overflow) {
            const timer = timersRef.current.get(old.id);
            if (timer) {
              clearTimeout(timer);
              timersRef.current.delete(old.id);
            }
          }
          return next.slice(-MAX_VISIBLE);
        }
        return next;
      });

      // Schedule auto-dismiss
      const timer = setTimeout(() => {
        dismiss(id);
      }, duration);
      timersRef.current.set(id, timer);
    },
    [dismiss],
  );

  // Cleanup on unmount
  useEffect(() => {
    const timers = timersRef.current;
    return () => {
      for (const timer of timers.values()) {
        clearTimeout(timer);
      }
      timers.clear();
    };
  }, []);

  return (
    <ToastContext.Provider value={{ toast, dismiss }}>
      {children}
      <ToastContainer toasts={toasts} onDismiss={dismiss} />
    </ToastContext.Provider>
  );
}

// ---- Toast container ----

function ToastContainer({
  toasts,
  onDismiss,
}: {
  toasts: Toast[];
  onDismiss: (id: string) => void;
}) {
  return (
    <div className="fixed bottom-4 right-4 z-[40] flex flex-col-reverse gap-2 pointer-events-none">
      <AnimatePresence mode="popLayout">
        {toasts.map((t) => (
          <ToastItem key={t.id} toast={t} onDismiss={onDismiss} />
        ))}
      </AnimatePresence>
    </div>
  );
}

// ---- Single toast ----

function ToastItem({
  toast: t,
  onDismiss,
}: {
  toast: Toast;
  onDismiss: (id: string) => void;
}) {
  const Icon = ICONS[t.type];
  const borderColor = BORDER_COLORS[t.type];

  return (
    <motion.div
      layout
      initial={{ opacity: 0, x: 80, scale: 0.95 }}
      animate={{ opacity: 1, x: 0, scale: 1 }}
      exit={{ opacity: 0, x: 80, scale: 0.95 }}
      transition={{ type: "spring", stiffness: 400, damping: 30 }}
      onClick={() => onDismiss(t.id)}
      className="pointer-events-auto cursor-pointer w-80 bg-[#0b0d13] border border-[#2d3240] rounded-lg shadow-lg shadow-black/30 overflow-hidden"
      style={{ borderLeftWidth: 3, borderLeftColor: borderColor }}
    >
      <div className="flex items-start gap-3 px-3 py-3">
        {/* Icon */}
        <div className="shrink-0 mt-0.5" style={{ color: borderColor }}>
          <Icon size={16} stroke={2} />
        </div>

        {/* Text */}
        <div className="flex-1 min-w-0">
          <p className="text-xs font-medium text-[#ece7dc] leading-tight">
            {t.title}
          </p>
          {t.description && (
            <p className="text-[11px] text-[#6f7f9a] mt-0.5 leading-snug">
              {t.description}
            </p>
          )}
        </div>

        {/* Close */}
        <button
          onClick={(e) => {
            e.stopPropagation();
            onDismiss(t.id);
          }}
          className="shrink-0 text-[#6f7f9a] hover:text-[#ece7dc] transition-colors mt-0.5"
        >
          <IconX size={14} stroke={1.5} />
        </button>
      </div>
    </motion.div>
  );
}
