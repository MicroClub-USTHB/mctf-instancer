export type ToastVariant = "success" | "error" | "info" | "warning";

export interface ToastMessage {
  id: string;
  title?: string;
  message: string;
  variant: ToastVariant;
  durationMs?: number;
}

export interface ConfirmOptions {
  title: string;
  message: string;
  confirmText?: string;
  cancelText?: string;
  danger?: boolean;
}

export type ApiRecord = Record<string, unknown>;
