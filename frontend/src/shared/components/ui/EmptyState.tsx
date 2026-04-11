import type { PropsWithChildren } from "react";

interface EmptyStateProps {
  title: string;
  hint?: string;
}

export function EmptyState({ title, hint, children }: PropsWithChildren<EmptyStateProps>) {
  return (
    <div className="rounded-xl border border-dashed border-white/18 bg-black/20 px-4 py-6 text-center">
      <p className="font-display text-lg text-slate-100">{title}</p>
      {hint ? <p className="mt-1 text-sm text-slate-400">{hint}</p> : null}
      {children ? <div className="mt-3">{children}</div> : null}
    </div>
  );
}
