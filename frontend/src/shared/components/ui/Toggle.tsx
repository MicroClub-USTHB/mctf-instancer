import { classNames } from "../../utils/format";

export interface ToggleProps {
  enabled: boolean;
  onChange: (enabled: boolean) => void;
  label?: string;
  size?: "sm" | "md";
}

export function Toggle({ enabled, onChange, label, size = "sm" }: ToggleProps) {
  const knob = size === "sm" ? "h-4 w-4" : "h-5 w-5";
  const translate = size === "sm" ? "translate-x-4" : "translate-x-5";
  const track = size === "sm" ? "h-5 w-9" : "h-6 w-11";

  return (
    <label className="inline-flex cursor-pointer items-center gap-2 select-none">
      <button
        type="button"
        role="switch"
        aria-checked={enabled}
        onClick={() => onChange(!enabled)}
        className={classNames(
          "relative inline-flex shrink-0 rounded-full border-2 border-transparent transition-colors focus:outline-none",
          track,
          enabled ? "bg-violet-600" : "bg-white/15",
        )}
      >
        <span
          className={classNames(
            "pointer-events-none inline-block rounded-full bg-white shadow transition-transform",
            knob,
            enabled ? translate : "translate-x-0",
          )}
        />
      </button>
      {label ? <span className="text-xs text-slate-300">{label}</span> : null}
    </label>
  );
}
