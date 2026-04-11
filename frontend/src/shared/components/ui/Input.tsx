import type { InputHTMLAttributes } from "react";
import { classNames } from "../../utils/format";

interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  hint?: string;
}

export function Input({ label, hint, className, id, ...props }: InputProps) {
  return (
    <label className="block space-y-1.5">
      {label ? <span className="text-xs font-semibold uppercase tracking-[0.14em] text-slate-300">{label}</span> : null}
      <input
        id={id}
        className={classNames(
          "w-full rounded-lg border border-zinc-300/20 bg-zinc-900/55 px-3 py-2.5 text-sm text-zinc-100 outline-none transition placeholder:text-zinc-500 focus:border-violet-300/55",
          className,
        )}
        {...props}
      />
      {hint ? <span className="text-xs text-slate-400">{hint}</span> : null}
    </label>
  );
}
