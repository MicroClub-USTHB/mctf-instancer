import type { PropsWithChildren } from "react";
import { classNames } from "../../utils/format";

type BadgeTone = "neutral" | "success" | "warning" | "danger" | "info";

interface BadgeProps {
  tone?: BadgeTone;
  className?: string;
}

const toneStyles: Record<BadgeTone, string> = {
  neutral: "border-zinc-300/25 bg-zinc-800/35 text-zinc-100",
  success: "border-emerald-300/30 bg-emerald-950/30 text-emerald-100",
  warning: "border-amber-300/30 bg-amber-950/30 text-amber-100",
  danger: "border-rose-300/35 bg-rose-900/30 text-rose-100",
  info: "border-violet-300/35 bg-violet-950/35 text-violet-100",
};

export function Badge({ children, tone = "neutral", className }: PropsWithChildren<BadgeProps>) {
  return (
    <span
      className={classNames(
        "inline-flex items-center rounded-full border px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.12em]",
        toneStyles[tone],
        className,
      )}
    >
      {children}
    </span>
  );
}
