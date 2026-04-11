import type { PropsWithChildren } from "react";
import { ConfirmProvider } from "../../hooks/useConfirm";
import { ToastProvider } from "../../hooks/useToast";
import { ErrorBoundary } from "./ErrorBoundary";

export function AppProviders({ children }: PropsWithChildren) {
  return (
    <ErrorBoundary>
      <ConfirmProvider>
        <ToastProvider>{children}</ToastProvider>
      </ConfirmProvider>
    </ErrorBoundary>
  );
}
