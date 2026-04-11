import { createContext, useCallback, useContext, useMemo, useState, type PropsWithChildren } from "react";
import type { ToastMessage, ToastVariant } from "../types/common";

interface ToastContextValue {
  pushToast: (message: string, variant?: ToastVariant, title?: string, durationMs?: number) => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

const TONE_MAP: Record<ToastVariant, string> = {
  success: "border-emerald-300/35 bg-emerald-950/30 text-emerald-100",
  error: "border-rose-300/35 bg-rose-900/35 text-rose-100",
  info: "border-violet-300/35 bg-violet-950/40 text-violet-100",
  warning: "border-amber-300/30 bg-amber-950/35 text-amber-100",
};

export function ToastProvider({ children }: PropsWithChildren) {
  const [toasts, setToasts] = useState<ToastMessage[]>([]);

  const pushToast = useCallback((message: string, variant: ToastVariant = "info", title?: string, durationMs = 4200) => {
    const id = `${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
    const toast: ToastMessage = {
      id,
      title,
      message,
      variant,
      durationMs,
    };

    setToasts((prev) => [...prev, toast]);

    window.setTimeout(() => {
      setToasts((prev) => prev.filter((item) => item.id !== id));
    }, durationMs);
  }, []);

  const dismiss = useCallback((id: string) => {
    setToasts((prev) => prev.filter((item) => item.id !== id));
  }, []);

  const value = useMemo<ToastContextValue>(() => ({ pushToast }), [pushToast]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="pointer-events-none fixed right-4 top-4 z-[90] flex w-full max-w-sm flex-col gap-2 sm:right-6 sm:top-6">
        {toasts.map((toast) => (
          <div
            key={toast.id}
            className={`pointer-events-auto rounded-xl border px-4 py-3 shadow-xl backdrop-blur toast-in ${TONE_MAP[toast.variant]}`}
            role="status"
            aria-live="polite"
          >
            <div className="flex items-start gap-3">
              <div className="min-w-0 flex-1">
                {toast.title ? <p className="text-xs font-semibold uppercase tracking-[0.14em] opacity-90">{toast.title}</p> : null}
                <p className="mt-0.5 text-sm leading-relaxed">{toast.message}</p>
              </div>
              <button
                type="button"
                onClick={() => dismiss(toast.id)}
                className="rounded-md border border-white/20 px-2 py-1 text-[11px] uppercase tracking-[0.12em] text-white/80 transition hover:border-white/40 hover:text-white"
              >
                Close
              </button>
            </div>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  const context = useContext(ToastContext);

  if (!context) {
    throw new Error("useToast must be used inside ToastProvider");
  }

  return context;
}
