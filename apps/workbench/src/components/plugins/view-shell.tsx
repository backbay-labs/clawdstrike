import { Component, type ErrorInfo, type ReactNode } from "react";

export interface PluginViewStorage {
  get(key: string): unknown;
  set(key: string, value: unknown): void;
}

export const NO_OP_VIEW_STORAGE: PluginViewStorage = {
  get: (_key: string): unknown => undefined,
  set: (_key: string, _value: unknown): void => {},
};

function ViewErrorFallback({
  error,
  resetError,
}: {
  error: Error;
  resetError: () => void;
}) {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-2 p-4">
      <span className="text-sm font-medium text-[#c45c5c]">
        Plugin view crashed
      </span>
      <span className="max-w-md truncate text-xs text-[#6f7f9a]">
        {error.message}
      </span>
      <button
        onClick={resetError}
        className="mt-1 text-xs text-[#d4a84b] hover:underline"
      >
        Reload View
      </button>
    </div>
  );
}

interface ViewErrorBoundaryProps {
  children: ReactNode;
}

interface ViewErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
  resetKey: number;
}

export class ViewErrorBoundary extends Component<
  ViewErrorBoundaryProps,
  ViewErrorBoundaryState
> {
  constructor(props: ViewErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false, error: null, resetKey: 0 };
  }

  static getDerivedStateFromError(error: Error): Partial<ViewErrorBoundaryState> {
    return { hasError: true, error };
  }

  componentDidCatch(_error: Error, _errorInfo: ErrorInfo): void {
    // Error is already captured via getDerivedStateFromError.
    // Could log to an external service here in the future.
  }

  private handleReset = () => {
    this.setState((prev) => ({
      hasError: false,
      error: null,
      resetKey: prev.resetKey + 1,
    }));
  };

  render() {
    const { hasError, error, resetKey } = this.state;
    const { children } = this.props;

    if (hasError && error) {
      return (
        <ViewErrorFallback
          error={error}
          resetError={this.handleReset}
        />
      );
    }

    return <div key={resetKey}>{children}</div>;
  }
}
