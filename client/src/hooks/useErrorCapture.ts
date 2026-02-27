/**
 * Global client-side error capture hook.
 * Catches unhandled errors and promise rejections, logs them to the platform error DB.
 * Automatically tags errors with the active engagement context.
 * Mount once at the app root level.
 */
import { useEffect } from "react";

const ENGAGEMENT_STORAGE_KEY = "ace-c3-active-engagement";

/** Read the active engagement from localStorage (same key as EngagementContext) */
function getEngagementContext(): { engagementId?: number; engagementName?: string; clientName?: string } | undefined {
  try {
    const stored = localStorage.getItem(ENGAGEMENT_STORAGE_KEY);
    if (stored) {
      const parsed = JSON.parse(stored);
      if (parsed && typeof parsed.id === "number") {
        return {
          engagementId: parsed.id,
          engagementName: parsed.name,
          clientName: parsed.customerName,
        };
      }
    }
  } catch {
    // ignore
  }
  return undefined;
}

function sendErrorToServer(payload: {
  source: string;
  severity: string;
  message: string;
  stack?: string;
  page?: string;
  clientMeta?: Record<string, unknown>;
  autoRecovered?: boolean;
  engagementContext?: { engagementId?: number; engagementName?: string; clientName?: string };
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
        engagementContext: getEngagementContext(),
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
        engagementContext: getEngagementContext(),
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
