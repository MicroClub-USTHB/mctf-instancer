import { Component, type ErrorInfo, type ReactNode } from "react";
import { Button } from "../ui/Button";

interface ErrorBoundaryProps {
  children: ReactNode;
}

interface ErrorBoundaryState {
  hasError: boolean;
  message: string;
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = {
    hasError: false,
    message: "",
  };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return {
      hasError: true,
      message: error.message || "Unexpected runtime error",
    };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error("UI crash:", error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="mx-auto mt-12 w-full max-w-3xl rounded-2xl border border-rose-300/45 bg-rose-500/10 p-6 text-rose-100">
          <h1 className="font-display text-2xl">Frontend crashed</h1>
          <p className="mt-2 text-sm leading-relaxed text-rose-100/90">{this.state.message}</p>
          <Button className="mt-4" variant="danger" onClick={() => window.location.reload()}>
            Reload page
          </Button>
        </div>
      );
    }

    return this.props.children;
  }
}
