/**
 * Global client-side error capture hook.
 * Catches unhandled errors and promise rejections, logs them to the platform error DB.
 * Mount once at the app root level.
 */
import { useEffect } from "react";

function sendErrorToServer(payload: {
  source: string;
  severity: string;
  message: string;
  stack?: string;
  page?: string;
  clientMeta?: Record<string, unknown>;
  autoRecovered?: boolean;
}) {
  fetch("/api/trpc/errorLog.logClientError", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ json: payload }),
    signal: AbortSignal.timeout(5000),
  }).catch(() => {
    // Server might be down — silently fail
  });
}

export function useErrorCapture() {
  useEffect(() => {
    // Capture unhandled JS errors
    const handleError = (event: ErrorEvent) => {
      sendErrorToServer({
        source: "client",
        severity: "error",
        message: event.message || "Unknown error",
        stack: event.error?.stack?.slice(0, 10000),
        page: window.location.pathname,
        clientMeta: {
          filename: event.filename,
          lineno: event.lineno,
          colno: event.colno,
          userAgent: navigator.userAgent,
        },
      });
    };

    // Capture unhandled promise rejections
    const handleRejection = (event: PromiseRejectionEvent) => {
      const reason = event.reason;
      const message = reason instanceof Error ? reason.message : String(reason);
      const stack = reason instanceof Error ? reason.stack?.slice(0, 10000) : undefined;

      // Don't log tRPC query errors (they're expected during loading states)
      if (message.includes("TRPCClientError") && message.includes("UNAUTHORIZED")) return;

      sendErrorToServer({
        source: "unhandled_rejection",
        severity: "error",
        message,
        stack,
        page: window.location.pathname,
        clientMeta: {
          userAgent: navigator.userAgent,
        },
      });
    };

    window.addEventListener("error", handleError);
    window.addEventListener("unhandledrejection", handleRejection);

    return () => {
      window.removeEventListener("error", handleError);
      window.removeEventListener("unhandledrejection", handleRejection);
    };
  }, []);
}
