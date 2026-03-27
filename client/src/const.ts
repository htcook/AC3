export { COOKIE_NAME, ONE_YEAR_MS } from "@shared/const";

// Generate login URL at runtime so redirect URI reflects the current origin.
// Gracefully handles missing VITE_OAUTH_PORTAL_URL (e.g., in external deployments
// where Manus OAuth env vars are not injected) by returning a fallback "/login" path.
export const getLoginUrl = () => {
  const oauthPortalUrl = import.meta.env.VITE_OAUTH_PORTAL_URL;
  const appId = import.meta.env.VITE_APP_ID;

  // Guard: if the OAuth portal URL is not configured, fall back to local login route
  if (!oauthPortalUrl) {
    console.warn(
      "[auth] VITE_OAUTH_PORTAL_URL is not set — falling back to /login"
    );
    return "/login";
  }

  try {
    const redirectUri = `${window.location.origin}/api/oauth/callback`;
    const state = btoa(redirectUri);

    const url = new URL(`${oauthPortalUrl}/app-auth`);
    url.searchParams.set("appId", appId);
    url.searchParams.set("redirectUri", redirectUri);
    url.searchParams.set("state", state);
    url.searchParams.set("type", "signIn");

    return url.toString();
  } catch (err) {
    console.error("[auth] Failed to construct login URL:", err);
    return "/login";
  }
};
