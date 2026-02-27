import { Component, type ErrorInfo, type ReactNode } from "react";

interface ErrorBoundaryProps {
  children: ReactNode;
  fallback?: (error: Error, reset: () => void) => ReactNode;
  onReset?: () => void;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { hasError: false, error: null };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("[ErrorBoundary]", error, info.componentStack);
  }

  reset = () => {
    this.props.onReset?.();
    this.setState({ hasError: false, error: null });
  };

  render() {
    if (this.state.hasError && this.state.error) {
      if (this.props.fallback) {
        return this.props.fallback(this.state.error, this.reset);
      }

      return (
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
            height: "100%",
            minHeight: 200,
            padding: 32,
            background: "rgba(15,20,30,0.95)",
            color: "#e7edf6",
            fontFamily: '"Inter", sans-serif',
          }}
        >
          <div
            style={{
              maxWidth: 420,
              padding: 24,
              borderRadius: 14,
              background: "rgba(11,13,16,0.85)",
              border: "1px solid rgba(27,34,48,0.8)",
              backdropFilter: "blur(12px)",
              textAlign: "center",
            }}
          >
            <div
              style={{
                fontSize: 13,
                fontFamily: '"JetBrains Mono", monospace',
                letterSpacing: "0.12em",
                textTransform: "uppercase" as const,
                color: "#c23b3b",
                marginBottom: 12,
              }}
            >
              RUNTIME ERROR
            </div>
            <div
              style={{
                fontSize: 13,
                lineHeight: 1.5,
                color: "rgba(154,167,181,0.8)",
                marginBottom: 20,
                wordBreak: "break-word",
              }}
            >
              {this.state.error.message || "An unexpected error occurred"}
            </div>
            <button
              type="button"
              onClick={this.reset}
              style={{
                padding: "8px 20px",
                borderRadius: 10,
                border: "1px solid rgba(214,177,90,0.35)",
                background: "rgba(214,177,90,0.1)",
                color: "#d6b15a",
                fontSize: 12,
                fontFamily: '"JetBrains Mono", monospace',
                letterSpacing: "0.08em",
                textTransform: "uppercase" as const,
                cursor: "pointer",
              }}
            >
              Reload
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
