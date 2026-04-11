import { createContext, useCallback, useContext, useMemo, useState, type PropsWithChildren } from "react";
import type { ConfirmOptions } from "../types/common";

interface PendingConfirm {
  options: ConfirmOptions;
  resolve: (value: boolean) => void;
}

interface ConfirmContextValue {
  confirm: (options: ConfirmOptions) => Promise<boolean>;
}

const ConfirmContext = createContext<ConfirmContextValue | null>(null);

const defaultOptions: Partial<ConfirmOptions> = {
  confirmText: "Confirm",
  cancelText: "Cancel",
  danger: false,
};

export function ConfirmProvider({ children }: PropsWithChildren) {
  const [pending, setPending] = useState<PendingConfirm | null>(null);

  const close = useCallback((value: boolean) => {
    setPending((current) => {
      if (current) {
        current.resolve(value);
      }
      return null;
    });
  }, []);

  const confirm = useCallback((options: ConfirmOptions) => {
    return new Promise<boolean>((resolve) => {
      setPending({
        options: {
          ...defaultOptions,
          ...options,
        },
        resolve,
      });
    });
  }, []);

  const contextValue = useMemo<ConfirmContextValue>(() => ({ confirm }), [confirm]);

  return (
    <ConfirmContext.Provider value={contextValue}>
      {children}
      {pending ? (
        <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 px-4 py-6 backdrop-blur-sm">
          <div className="w-full max-w-md rounded-2xl border border-white/15 bg-slate-950/96 p-5 shadow-2xl">
            <h2 className="font-display text-xl text-zinc-100">{pending.options.title}</h2>
            <p className="mt-2 whitespace-pre-wrap text-sm leading-relaxed text-slate-200">{pending.options.message}</p>
            <div className="mt-5 flex items-center justify-end gap-2">
              <button
                type="button"
                onClick={() => close(false)}
                className="rounded-lg border border-white/25 px-3 py-2 text-xs uppercase tracking-[0.12em] text-slate-200 transition hover:border-white/40"
              >
                {pending.options.cancelText}
              </button>
              <button
                type="button"
                onClick={() => close(true)}
                className={`rounded-lg border px-3 py-2 text-xs uppercase tracking-[0.12em] transition ${
                  pending.options.danger
                    ? "border-rose-300/45 bg-rose-500/18 text-rose-100 hover:border-rose-200/70"
                    : "border-violet-300/35 bg-violet-950/45 text-zinc-100 hover:border-violet-200/65"
                }`}
              >
                {pending.options.confirmText}
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </ConfirmContext.Provider>
  );
}

export function useConfirm() {
  const context = useContext(ConfirmContext);

  if (!context) {
    throw new Error("useConfirm must be used inside ConfirmProvider");
  }

  return context;
}
