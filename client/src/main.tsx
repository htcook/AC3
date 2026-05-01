import { trpc } from "@/lib/trpc";
import { UNAUTHED_ERR_MSG } from '@shared/const';
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { httpBatchLink, httpLink, splitLink, TRPCClientError } from "@trpc/client";
import { createRoot } from "react-dom/client";
import superjson from "superjson";
import App from "./App";
import "./index.css";

// Global handler for Vite preload errors (stale chunks after deployment)
// This catches errors that happen outside of React.lazy boundaries
window.addEventListener('vite:preloadError', (event) => {
  const reloadKey = '__ac3_chunk_reload';
  const lastReload = sessionStorage.getItem(reloadKey);
  const now = Date.now();
  if (!lastReload || now - parseInt(lastReload, 10) > 30000) {
    sessionStorage.setItem(reloadKey, String(now));
    console.warn('[AC3] Vite preload error, reloading...', (event as any).payload);
    window.location.reload();
  }
});

const queryClient = new QueryClient();

// Public routes that should never auto-redirect to login on auth errors
const PUBLIC_ROUTES = ["/", "/overview", "/login", "/customer-login"];

/**
 * Debounced redirect guard.
 * When multiple queries fire UNAUTHORIZED simultaneously (e.g., EngagementOps has 57 hooks
 * with aggressive refetchIntervals), each one triggers this handler. Without debouncing,
 * multiple rapid `window.location.href = "/login"` assignments cause the page to appear
 * frozen as React tries to unmount everything while the browser navigates.
 *
 * The guard ensures only ONE redirect happens within a 2-second window, and cancels all
 * in-flight queries to stop the cascade.
 */
let redirectPending = false;
let redirectTimer: ReturnType<typeof setTimeout> | null = null;

const redirectToLoginIfUnauthorized = (error: unknown) => {
  if (!(error instanceof TRPCClientError)) return;
  if (typeof window === "undefined") return;

  // Already redirecting — don't queue another
  if (redirectPending) return;

  // Don't redirect on public-facing pages — prospective customers must see the homepage
  const currentPath = window.location.pathname;
  const isPublicRoute = PUBLIC_ROUTES.includes(currentPath) ||
    currentPath.startsWith("/portal/") ||
    currentPath.startsWith("/customer-");
  if (isPublicRoute) return;

  // Detect unauthorized errors by message OR by HTTP status code
  const isUnauthorized =
    error.message === UNAUTHED_ERR_MSG ||
    (error.data as any)?.httpStatus === 401 ||
    (error.data as any)?.code === 'UNAUTHORIZED' ||
    error.message?.includes('UNAUTHORIZED');

  if (!isUnauthorized) return;

  if (currentPath !== "/login") {
    // Mark redirect as pending to block duplicate redirects
    redirectPending = true;

    // Cancel all in-flight queries immediately to stop the UNAUTHORIZED cascade
    queryClient.cancelQueries();

    // Clear any existing timer (shouldn't happen, but defensive)
    if (redirectTimer) clearTimeout(redirectTimer);

    // Small delay to let React settle before navigating
    redirectTimer = setTimeout(() => {
      console.warn("[AC3] Session expired — redirecting to /login");
      window.location.href = "/login";
    }, 100);
  }
};

queryClient.getQueryCache().subscribe(event => {
  if (event.type === "updated" && event.action.type === "error") {
    const error = event.query.state.error;
    redirectToLoginIfUnauthorized(error);
    // Only log if we're not already redirecting (reduces console spam)
    if (!redirectPending) {
      console.error("[API Query Error]", error);
    }
  }
});

queryClient.getMutationCache().subscribe(event => {
  if (event.type === "updated" && event.action.type === "error") {
    const error = event.mutation.state.error;
    redirectToLoginIfUnauthorized(error);
    if (!redirectPending) {
      console.error("[API Mutation Error]", error);
    }
  }
});

/**
 * Fetch wrapper with automatic retry on HTTP 429 (rate limited).
 * The Manus/Cloudflare proxy enforces 200 requests per 60-second window.
 * When the limit is hit, we back off exponentially instead of failing.
 */
const MAX_RETRIES = 5;
const INITIAL_BACKOFF_MS = 1000;

async function fetchWithRetry(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  let lastResponse: Response | undefined;
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    const response = await globalThis.fetch(input, {
      ...(init ?? {}),
      credentials: "include",
    });
    if (response.status !== 429) return response;
    lastResponse = response;

    // Parse Retry-After or ratelimit-reset header if available
    const retryAfter = response.headers.get('retry-after');
    const rlReset = response.headers.get('ratelimit-reset');
    let waitMs: number;
    if (retryAfter) {
      waitMs = (parseInt(retryAfter, 10) || 1) * 1000;
    } else if (rlReset) {
      waitMs = (parseInt(rlReset, 10) || 1) * 1000;
    } else {
      waitMs = INITIAL_BACKOFF_MS * Math.pow(2, attempt);
    }
    // Add jitter (±25%) to prevent thundering herd
    waitMs = waitMs * (0.75 + Math.random() * 0.5);
    console.warn(`[AC3] Rate limited (429), retry ${attempt + 1}/${MAX_RETRIES} in ${Math.round(waitMs)}ms`);
    await new Promise(resolve => setTimeout(resolve, waitMs));
  }
  // All retries exhausted — return a synthetic JSON error response so tRPC can parse it
  // instead of the raw HTML "Rate exceeded" body that causes "String doesn't match expected pattern"
  const syntheticBody = JSON.stringify({
    error: {
      json: {
        message: "Rate limited — too many requests. Please wait a moment and try again.",
        code: -32029,
        data: { code: "TOO_MANY_REQUESTS", httpStatus: 429 }
      }
    }
  });
  return new Response(syntheticBody, {
    status: 429,
    headers: { "Content-Type": "application/json" },
  });
}

// Long-running operations (report export, engagement generation) need their own
// non-batched link with extended timeout to avoid being killed by batch timeouts
const LONG_RUNNING_OPERATIONS = [
  'reports.exportPdf', 'reports.exportDocx', 'reports.generate',
  'ac3Reports.exportDocx', 'ac3Reports.exportPdf',
  'engagementOps.runFullEngagement', 'engagementOps.runDomainIntel',
];

function fetchWithTimeout(timeoutMs: number) {
  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      return await fetchWithRetry(input, { ...init, signal: controller.signal });
    } finally {
      clearTimeout(timer);
    }
  };
}

const trpcClient = trpc.createClient({
  links: [
    splitLink({
      condition: (op) => LONG_RUNNING_OPERATIONS.includes(`${op.path}`),
      true: httpLink({
        url: "/api/trpc",
        transformer: superjson,
        fetch: fetchWithTimeout(300_000), // 5 min timeout for exports
      }),
      false: httpBatchLink({
        url: "/api/trpc",
        transformer: superjson,
        fetch: fetchWithRetry,
      }),
    }),
  ],
});

createRoot(document.getElementById("root")!).render(
  <trpc.Provider client={trpcClient} queryClient={queryClient}>
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>
  </trpc.Provider>
);
