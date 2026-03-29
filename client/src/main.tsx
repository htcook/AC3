import { trpc } from "@/lib/trpc";
import { UNAUTHED_ERR_MSG } from '@shared/const';
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { httpBatchLink, TRPCClientError } from "@trpc/client";
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

const trpcClient = trpc.createClient({
  links: [
    httpBatchLink({
      url: "/api/trpc",
      transformer: superjson,
      fetch(input, init) {
        return globalThis.fetch(input, {
          ...(init ?? {}),
          credentials: "include",
        });
      },
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
