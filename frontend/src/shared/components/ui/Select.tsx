import type { SelectHTMLAttributes } from "react";
import { classNames } from "../../utils/format";

interface SelectProps extends SelectHTMLAttributes<HTMLSelectElement> {
  label?: string;
}

export function Select({ label, className, children, ...props }: SelectProps) {
  return (
    <label className="block space-y-1.5">
      {label ? <span className="text-xs font-semibold uppercase tracking-[0.14em] text-slate-300">{label}</span> : null}
      <select
        className={classNames(
          "w-full rounded-lg border border-zinc-300/20 bg-zinc-900/55 px-3 py-2.5 text-sm text-zinc-100 outline-none transition focus:border-violet-300/55",
          className,
        )}
        {...props}
      >
        {children}
      </select>
    </label>
  );
}
