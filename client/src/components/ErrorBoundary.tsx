/**
 * Global Error Boundary with Incident Reporting
 *
 * Catches unhandled React errors at the layout level, preventing a single
 * broken page from crashing the entire operator session. Logs error details
 * to the server for post-incident analysis.
 */

import React, { Component, type ErrorInfo, type ReactNode } from "react";
import { AlertTriangle, RefreshCw, Home, Copy, ChevronDown, ChevronUp } from "lucide-react";
import { Button } from "@/components/ui/button";

// ─── Types ────────────────────────────────────────────────────────────

interface ErrorBoundaryProps {
  children: ReactNode;
  /** Optional fallback component. If not provided, uses the built-in error UI. */
  fallback?: ReactNode;
  /** Scope label for incident reports (e.g., "AgentManager", "FIPSCompliance") */
  scope?: string;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
  incidentId: string | null;
  showDetails: boolean;
  reportSent: boolean;
  copied: boolean;
}

// ─── Incident ID Generator ───────────────────────────────────────────

function generateIncidentId(): string {
  const ts = Date.now().toString(36);
  const rand = Math.random().toString(36).substring(2, 8);
  return `INC-${ts}-${rand}`.toUpperCase();
}

// ─── Error Boundary Component ─────────────────────────────────────────

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
      incidentId: null,
      showDetails: false,
      reportSent: false,
      copied: false,
    };
  }

  static getDerivedStateFromError(error: Error): Partial<ErrorBoundaryState> {
    return {
      hasError: true,
      error,
      incidentId: generateIncidentId(),
    };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo): void {
    this.setState({ errorInfo });
    this.reportIncident(error, errorInfo);
  }

  private async reportIncident(error: Error, errorInfo: ErrorInfo): Promise<void> {
    try {
      const payload = {
        incidentId: this.state.incidentId,
        scope: this.props.scope ?? "global",
        error: {
          name: error.name,
          message: error.message,
          stack: error.stack?.split("\n").slice(0, 15).join("\n"),
        },
        componentStack: errorInfo.componentStack?.split("\n").slice(0, 10).join("\n"),
        url: window.location.href,
        userAgent: navigator.userAgent,
        timestamp: new Date().toISOString(),
        viewport: {
          width: window.innerWidth,
          height: window.innerHeight,
        },
      };

      // Attempt to send to server — fire-and-forget, don't block UI
      await fetch("/api/trpc/system.reportError", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ json: payload }),
        signal: AbortSignal.timeout(5000),
      }).catch(() => {});

      // Also log to platform error tracking DB
      await fetch("/api/trpc/errorLog.logClientError", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ json: {
          source: "react_boundary",
          severity: "critical",
          message: `${error.name}: ${error.message}`,
          stack: error.stack?.slice(0, 10000),
          page: window.location.pathname,
          clientMeta: {
            incidentId: this.state.incidentId,
            scope: this.props.scope,
            viewport: payload.viewport,
            userAgent: navigator.userAgent,
            componentStack: errorInfo.componentStack?.split("\n").slice(0, 5).join("\n"),
          },
        } }),
        signal: AbortSignal.timeout(5000),
      }).catch(() => {});

      // Also log to console for developer visibility
      console.error(
        `[ErrorBoundary] Incident ${this.state.incidentId}`,
        "\nScope:", this.props.scope ?? "global",
        "\nError:", error,
        "\nComponent Stack:", errorInfo.componentStack
      );

      this.setState({ reportSent: true });
    } catch {
      // Reporting itself failed — don't throw from error boundary
      console.error("[ErrorBoundary] Failed to report incident");
    }
  }

  private handleReload = (): void => {
    window.location.reload();
  };

  private handleGoHome = (): void => {
    window.location.href = "/dashboard";
  };

  private handleRetry = (): void => {
    this.setState({
      hasError: false,
      error: null,
      errorInfo: null,
      incidentId: null,
      showDetails: false,
      reportSent: false,
      copied: false,
    });
  };

  private handleCopyDetails = (): void => {
    const { error, errorInfo, incidentId } = this.state;
    const details = [
      `Incident ID: ${incidentId}`,
      `Scope: ${this.props.scope ?? "global"}`,
      `URL: ${window.location.href}`,
      `Time: ${new Date().toISOString()}`,
      `Error: ${error?.name}: ${error?.message}`,
      `Stack:\n${error?.stack ?? "N/A"}`,
      `Component Stack:\n${errorInfo?.componentStack ?? "N/A"}`,
    ].join("\n\n");

    navigator.clipboard.writeText(details).then(() => {
      this.setState({ copied: true });
      setTimeout(() => this.setState({ copied: false }), 2000);
    });
  };

  render(): ReactNode {
    if (this.state.hasError) {
      // If a custom fallback is provided, use it
      if (this.props.fallback) {
        return this.props.fallback;
      }

      const { error, incidentId, showDetails, reportSent, copied } = this.state;

      return (
        <div className="min-h-screen bg-background flex items-center justify-center p-6">
          <div className="max-w-lg w-full space-y-6">
            {/* Header */}
            <div className="flex flex-col items-center text-center space-y-4">
              <div className="w-16 h-16 rounded-full bg-destructive/10 flex items-center justify-center">
                <AlertTriangle className="w-8 h-8 text-destructive" />
              </div>
              <div>
                <h1 className="text-xl font-semibold text-foreground">
                  Something went wrong
                </h1>
                <p className="text-sm text-muted-foreground mt-1">
                  An unexpected error occurred in{" "}
                  <span className="font-mono text-xs bg-muted px-1.5 py-0.5 rounded">
                    {this.props.scope ?? "the application"}
                  </span>
                </p>
              </div>
            </div>

            {/* Incident ID */}
            <div className="bg-muted/50 border border-border rounded-lg p-4 text-center">
              <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">
                Incident ID
              </p>
              <p className="font-mono text-sm text-foreground font-medium">
                {incidentId}
              </p>
              {reportSent && (
                <p className="text-xs text-emerald-500 mt-1">
                  Incident reported to server
                </p>
              )}
            </div>

            {/* Error Summary */}
            <div className="bg-destructive/5 border border-destructive/20 rounded-lg p-4">
              <p className="text-sm font-medium text-destructive">
                {error?.name}: {error?.message}
              </p>
            </div>

            {/* Action Buttons */}
            <div className="flex gap-3">
              <Button
                variant="default"
                className="flex-1"
                onClick={this.handleRetry}
              >
                <RefreshCw className="w-4 h-4 mr-2" />
                Try Again
              </Button>
              <Button
                variant="outline"
                className="flex-1"
                onClick={this.handleGoHome}
              >
                <Home className="w-4 h-4 mr-2" />
                Dashboard
              </Button>
            </div>

            {/* Expand Details */}
            <div>
              <button
                className="w-full flex items-center justify-center gap-2 text-xs text-muted-foreground hover:text-foreground transition-colors py-2"
                onClick={() => this.setState({ showDetails: !showDetails })}
              >
                {showDetails ? (
                  <>
                    <ChevronUp className="w-3 h-3" /> Hide technical details
                  </>
                ) : (
                  <>
                    <ChevronDown className="w-3 h-3" /> Show technical details
                  </>
                )}
              </button>

              {showDetails && (
                <div className="mt-2 space-y-3">
                  <div className="bg-muted rounded-lg p-3 max-h-48 overflow-auto">
                    <pre className="text-xs text-muted-foreground whitespace-pre-wrap font-mono">
                      {error?.stack ?? "No stack trace available"}
                    </pre>
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    className="w-full"
                    onClick={this.handleCopyDetails}
                  >
                    <Copy className="w-3 h-3 mr-2" />
                    {copied ? "Copied!" : "Copy error details"}
                  </Button>
                </div>
              )}
            </div>

            {/* Reload hint */}
            <p className="text-xs text-center text-muted-foreground">
              If the problem persists, try{" "}
              <button
                className="underline hover:text-foreground"
                onClick={this.handleReload}
              >
                reloading the page
              </button>
              .
            </p>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

/**
 * Page-level error boundary wrapper.
 * Use this to wrap individual page components so a crash in one page
 * doesn't take down the sidebar or navigation.
 */
export function PageErrorBoundary({
  children,
  pageName,
}: {
  children: ReactNode;
  pageName: string;
}) {
  return (
    <ErrorBoundary scope={pageName}>
      {children}
    </ErrorBoundary>
  );
}

export default ErrorBoundary;
