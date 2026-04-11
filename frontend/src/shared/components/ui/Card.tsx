import type { HTMLAttributes, PropsWithChildren } from "react";
import { classNames } from "../../utils/format";

interface CardProps extends HTMLAttributes<HTMLDivElement> {
  muted?: boolean;
}

export function Card({ children, className, muted = false, ...props }: PropsWithChildren<CardProps>) {
  return (
    <section
      className={classNames(
        "rounded-2xl border p-4 sm:p-5",
        muted
          ? "border-white/8 bg-slate-950/40"
          : "border-white/12 bg-gradient-to-br from-slate-900/90 via-slate-950/92 to-slate-900/88 shadow-xl",
        className,
      )}
      {...props}
    >
      {children}
    </section>
  );
}
