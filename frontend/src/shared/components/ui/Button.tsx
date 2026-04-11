import type { ButtonHTMLAttributes, PropsWithChildren } from "react";
import { classNames } from "../../utils/format";

type ButtonVariant = "primary" | "secondary" | "danger" | "ghost";

type ButtonSize = "sm" | "md";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
}

const variantStyles: Record<ButtonVariant, string> = {
  primary: "border-violet-300/35 bg-violet-950/45 text-zinc-100 hover:border-violet-200/65 hover:bg-violet-900/55",
  secondary: "border-zinc-300/25 bg-zinc-800/35 text-zinc-100 hover:border-zinc-200/45 hover:bg-zinc-700/35",
  danger: "border-rose-300/35 bg-rose-900/35 text-rose-100 hover:border-rose-200/55 hover:bg-rose-900/50",
  ghost: "border-transparent bg-transparent text-zinc-300 hover:border-zinc-300/20 hover:bg-zinc-700/25",
};

const sizeStyles: Record<ButtonSize, string> = {
  sm: "px-3 py-2 text-xs tracking-[0.12em]",
  md: "px-4 py-2.5 text-sm tracking-[0.09em]",
};

export function Button({
  children,
  className,
  variant = "secondary",
  size = "sm",
  type = "button",
  ...props
}: PropsWithChildren<ButtonProps>) {
  return (
    <button
      type={type}
      className={classNames(
        "rounded-lg border font-semibold uppercase transition disabled:cursor-not-allowed disabled:opacity-50",
        variantStyles[variant],
        sizeStyles[size],
        className,
      )}
      {...props}
    >
      {children}
    </button>
  );
}
