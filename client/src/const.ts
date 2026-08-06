export { COOKIE_NAME, ONE_YEAR_MS } from "@shared/const";

/**
 * Known Manus-hosted domains where Manus OAuth is the correct auth flow.
 * On any other domain (e.g., aceofcloud.io on DigitalOcean), we use the
 * local AC3 login page (/login) instead.
 */
const MANUS_HOSTED_DOMAINS = [
  ".manus.space",
  ".manusvm.computer",
  ".manus.computer",
];

/**
 * Detect whether the current deployment is Manus-hosted.
 * Returns true only when running on a known Manus domain.
 */
const isManusHosted = (): boolean => {
  try {
    const hostname = window.location.hostname;
    return MANUS_HOSTED_DOMAINS.some((d) => hostname.endsWith(d));
  } catch {
    return false;
  }
};

/**
 * Generate login URL at runtime.
 *
 * - On Manus-hosted deployments: returns the Manus OAuth portal URL
 * - On external deployments (DO, self-hosted): always returns "/login"
 *   to use the AC3 email/service-account login page.
 *
 * This prevents production users from ever seeing the Manus OAuth flow,
 * even if VITE_OAUTH_PORTAL_URL was baked into the client bundle at build time.
 */
export const getLoginUrl = (): string => {
  // External deployments (DO, self-hosted) always use local AC3 login
  if (!isManusHosted()) {
    return "/login";
  }

  // Manus-hosted: use Manus OAuth if configured
  const oauthPortalUrl = import.meta.env.VITE_OAUTH_PORTAL_URL;
  const appId = import.meta.env.VITE_APP_ID;

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
