import { Component, type ReactNode } from "react";

interface Canvas3DErrorBoundaryProps {
  children: ReactNode;
  /** When true, renders nothing on error (useful for background scenes) */
  silent?: boolean;
}

interface Canvas3DErrorBoundaryState {
  error: Error | null;
}

export class Canvas3DErrorBoundary extends Component<
  Canvas3DErrorBoundaryProps,
  Canvas3DErrorBoundaryState
> {
  state: Canvas3DErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: Error): Canvas3DErrorBoundaryState {
    return { error };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error("[Canvas3DErrorBoundary]", error, info.componentStack);
  }

  private resetErrorBoundary = () => {
    this.setState({ error: null });
  };

  render() {
    if (this.state.error) {
      if (this.props.silent) {
        return null;
      }

      return (
        <div className="flex flex-col items-center justify-center h-full gap-3 bg-zinc-900 text-zinc-400 border border-zinc-700 rounded-lg p-6">
          <p className="text-sm font-medium text-zinc-300">3D view failed to render</p>
          <p className="text-xs text-zinc-500 max-w-xs text-center">
            {this.state.error.message}
          </p>
          <button
            onClick={this.resetErrorBoundary}
            className="mt-2 px-3 py-1.5 text-xs font-medium rounded border border-zinc-600 bg-zinc-800 text-zinc-300 hover:bg-zinc-700 transition-colors"
          >
            Retry
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}
