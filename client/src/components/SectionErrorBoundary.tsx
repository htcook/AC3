/**
 * Section-level Error Boundary
 *
 * Wraps individual dashboard sections so a crash in one section
 * (e.g., ZeroDayFeed, threat actors, scan results) doesn't take
 * down the entire page. Shows a compact inline retry UI instead
 * of the full-page error screen.
 */

import React, { Component, type ReactNode } from "react";
import { AlertTriangle, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";

interface SectionErrorBoundaryProps {
  children: ReactNode;
  /** Section name for the error message */
  sectionName?: string;
  /** Optional compact mode — shows a single-line error */
  compact?: boolean;
}

interface SectionErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
  retryCount: number;
}

export class SectionErrorBoundary extends Component<
  SectionErrorBoundaryProps,
  SectionErrorBoundaryState
> {
  constructor(props: SectionErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false, error: null, retryCount: 0 };
  }

  static getDerivedStateFromError(error: Error): Partial<SectionErrorBoundaryState> {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error): void {
    console.warn(
      `[SectionErrorBoundary] ${this.props.sectionName ?? "Section"} crashed:`,
      error.message
    );
  }

  private handleRetry = (): void => {
    this.setState((prev) => ({
      hasError: false,
      error: null,
      retryCount: prev.retryCount + 1,
    }));
  };

  render(): ReactNode {
    if (this.state.hasError) {
      const { sectionName = "This section", compact } = this.props;

      if (compact) {
        return (
          <div className="flex items-center gap-2 py-2 px-3 text-xs text-muted-foreground bg-muted/30 border border-border rounded">
            <AlertTriangle className="w-3.5 h-3.5 text-yellow-500 shrink-0" />
            <span>{sectionName} failed to load.</span>
            <button
              onClick={this.handleRetry}
              className="text-primary hover:underline ml-auto shrink-0"
            >
              Retry
            </button>
          </div>
        );
      }

      return (
        <div className="bg-card border border-border p-4 text-center space-y-2">
          <div className="flex items-center justify-center gap-2 text-muted-foreground">
            <AlertTriangle className="w-4 h-4 text-yellow-500" />
            <span className="text-sm font-display tracking-wider">
              {sectionName.toUpperCase()} UNAVAILABLE
            </span>
          </div>
          <p className="text-xs text-muted-foreground">
            This section encountered an error while loading.
            {this.state.retryCount > 0 && (
              <span className="ml-1">
                ({this.state.retryCount} {this.state.retryCount === 1 ? "retry" : "retries"})
              </span>
            )}
          </p>
          <Button
            variant="outline"
            size="sm"
            onClick={this.handleRetry}
            className="text-xs"
          >
            <RefreshCw className="w-3 h-3 mr-1.5" />
            Retry
          </Button>
          {this.state.error && (
            <p className="text-[10px] text-muted-foreground/60 font-mono mt-1 truncate max-w-md mx-auto">
              {this.state.error.message}
            </p>
          )}
        </div>
      );
    }

    return this.props.children;
  }
}

export default SectionErrorBoundary;
