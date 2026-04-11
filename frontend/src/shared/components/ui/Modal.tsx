import type { PropsWithChildren, ReactNode } from "react";
import { Button } from "./Button";

interface ModalProps {
  open: boolean;
  title: string;
  onClose: () => void;
  footer?: ReactNode;
  maxWidthClass?: string;
}

export function Modal({ open, title, onClose, footer, maxWidthClass = "max-w-3xl", children }: PropsWithChildren<ModalProps>) {
  if (!open) {
    return null;
  }

  return (
    <div className="fixed inset-0 z-[95] flex items-center justify-center bg-black/70 px-4 py-6 backdrop-blur-sm" onClick={onClose}>
      <div
        className={`w-full ${maxWidthClass} rounded-2xl border border-white/15 bg-slate-950/96 shadow-2xl`}
        onClick={(event) => event.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-white/10 px-5 py-4">
          <h2 className="font-display text-xl text-zinc-100">{title}</h2>
          <Button variant="ghost" onClick={onClose}>
            Close
          </Button>
        </div>
        <div className="max-h-[72vh] overflow-auto px-5 py-4">{children}</div>
        <div className="flex items-center justify-end gap-2 border-t border-white/10 px-5 py-4">
          {footer || (
            <Button variant="secondary" onClick={onClose}>
              Close
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}
