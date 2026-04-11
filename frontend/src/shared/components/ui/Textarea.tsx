import type { TextareaHTMLAttributes } from "react";
import { classNames } from "../../utils/format";

interface TextareaProps extends TextareaHTMLAttributes<HTMLTextAreaElement> {
  label?: string;
}

export function Textarea({ label, className, ...props }: TextareaProps) {
  return (
    <label className="block space-y-1.5">
      {label ? <span className="text-xs font-semibold uppercase tracking-[0.14em] text-slate-300">{label}</span> : null}
      <textarea
        className={classNames(
          "w-full rounded-lg border border-zinc-300/20 bg-zinc-900/55 px-3 py-2.5 text-sm text-zinc-100 outline-none transition placeholder:text-zinc-500 focus:border-violet-300/55",
          className,
        )}
        {...props}
      />
    </label>
  );
}
