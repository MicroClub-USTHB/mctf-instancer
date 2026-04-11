import type { PropsWithChildren, ReactNode } from "react";

interface PageShellProps {
  title: string;
  subtitle: string;
  eyebrow?: string;
  actions?: ReactNode;
}

export function PageShell({ title, subtitle, eyebrow = "MCTF 5.0 · MICRO CLUB", actions, children }: PropsWithChildren<PageShellProps>) {
  return (
    <div className="app-canvas min-h-screen">
      <div className="pointer-events-none fixed inset-0 bg-grid-overlay opacity-40" aria-hidden="true" />
      <main className="relative z-10 mx-auto w-full max-w-7xl px-4 pb-10 pt-6 sm:px-8 sm:pt-8">
        <header className="hero-frame mb-7 rounded-3xl border border-white/15 p-5 sm:p-7">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div className="space-y-2">
              <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-zinc-400">{eyebrow}</p>
              <h1 className="font-display text-3xl tracking-[0.04em] text-zinc-100 sm:text-5xl">{title}</h1>
              <p className="max-w-3xl text-sm text-zinc-300 sm:text-base">{subtitle}</p>
            </div>
            {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
          </div>
        </header>
        <div className="space-y-5">{children}</div>
      </main>
    </div>
  );
}
