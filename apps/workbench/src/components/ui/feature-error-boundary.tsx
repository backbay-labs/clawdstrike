import { Component } from "react";
import type { ErrorInfo, ReactNode } from "react";

interface FeatureErrorBoundaryProps {
  /** Human-readable feature name shown in the error card (e.g. "Swarm Board"). */
  feature: string;
  children: ReactNode;
}

interface FeatureErrorBoundaryState {
  error: Error | null;
}

/**
 * Scoped error boundary for individual workbench features.
 *
 * Catches render errors in children and displays a dark-themed error card
 * with the feature name, error message, and a reload button -- instead of
 * crashing the entire application to a white screen.
 */
export class FeatureErrorBoundary extends Component<
  FeatureErrorBoundaryProps,
  FeatureErrorBoundaryState
> {
  state: FeatureErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: Error): FeatureErrorBoundaryState {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error(
      `[feature-error-boundary][${this.props.feature}]`,
      error,
      info.componentStack,
    );
  }

  private handleReload = () => {
    this.setState({ error: null });
  };

  render() {
    if (this.state.error) {
      return (
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            height: "100%",
            width: "100%",
            padding: 32,
            backgroundColor: "#0a0c11",
          }}
        >
          <div
            style={{
              maxWidth: 480,
              width: "100%",
              padding: 24,
              borderRadius: 6,
              border: "1px solid #2d3240",
              backgroundColor: "#0e1018",
              textAlign: "center",
              fontFamily:
                '"JetBrains Mono", ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace',
            }}
          >
            {/* Accent bar */}
            <div
              style={{
                width: 36,
                height: 2,
                backgroundColor: "#b85450",
                borderRadius: 1,
                margin: "0 auto 16px",
              }}
            />

            {/* Feature label */}
            <div
              style={{
                fontSize: "0.65rem",
                fontWeight: 600,
                letterSpacing: "0.1em",
                textTransform: "uppercase",
                color: "#6f7f9a",
                marginBottom: 8,
              }}
            >
              {this.props.feature}
            </div>

            {/* Error heading */}
            <h2
              style={{
                fontSize: "0.85rem",
                fontWeight: 600,
                color: "#b85450",
                marginBottom: 10,
                letterSpacing: "0.03em",
              }}
            >
              Something went wrong
            </h2>

            {/* Error message */}
            <p
              style={{
                fontSize: "0.75rem",
                color: "#6f7f9a",
                lineHeight: 1.6,
                marginBottom: 20,
                wordBreak: "break-word",
              }}
            >
              {this.state.error.message || "An unexpected error occurred."}
            </p>

            {/* Reload button */}
            <button
              type="button"
              onClick={this.handleReload}
              style={{
                padding: "6px 20px",
                fontSize: "0.7rem",
                fontFamily: "inherit",
                fontWeight: 600,
                letterSpacing: "0.08em",
                textTransform: "uppercase",
                color: "#0a0c11",
                backgroundColor: "#d4a84b",
                border: "none",
                borderRadius: 4,
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
