// ─── Resolve GoPhish URL ────────────────────────────────────────────────────
// The platform env may inject stale values pointing to the app server (134.199.213.248)
// which has an empty GoPhish instance. The real GoPhish with 130 templates is on the
// mail server (137.184.7.224:3333). Override any URL that doesn't point there.
function resolveGophishUrl(): string {
  const env = process.env.GOPHISH_BASE_URL;
  // Only accept if it explicitly points to the mail server
  if (env && env.includes("137.184.7.224")) return env;
  return "https://137.184.7.224:3333";
}

// ─── Resolve Caldera URL ────────────────────────────────────────────────────
// The platform env may inject http://134.199.213.248:8888 which is behind a firewall.
// The correct path is through the nginx HTTPS reverse proxy on the app server.
function resolveCalderaUrl(): string {
  const env = process.env.CALDERA_BASE_URL;
  // Accept if it's the HTTPS domain proxy
  if (env && env.includes("caldera.aceofcloud.io")) return env;
  return "https://caldera.aceofcloud.io";
}

// ─── Resolve Caldera API Key ────────────────────────────────────────────────
// The default ADMIN123 was rotated. Override if the env still has the old key.
function resolveCalderaApiKey(): string {
  const env = process.env.CALDERA_API_KEY;
  if (env && env !== "ADMIN123" && env.length > 10) return env;
  return "kmpJNkws7KXEdyIc2K8FYAGdMoRgrZ4c3hvJ1F9SI94";
}

export const ENV = {
  appId: process.env.VITE_APP_ID ?? "",
  cookieSecret: process.env.JWT_SECRET ?? "",
  databaseUrl: process.env.DATABASE_URL ?? "",
  oAuthServerUrl: process.env.OAUTH_SERVER_URL ?? "",
  ownerOpenId: process.env.OWNER_OPEN_ID ?? "",
  isProduction: process.env.NODE_ENV === "production",
  forgeApiUrl: process.env.BUILT_IN_FORGE_API_URL ?? "",
  forgeApiKey: process.env.BUILT_IN_FORGE_API_KEY ?? "",
  // Caldera
  calderaBaseUrl: resolveCalderaUrl(),
  calderaApiKey: resolveCalderaApiKey(),
  calderaUsername: process.env.CALDERA_USERNAME ?? "red",
  calderaPassword: process.env.CALDERA_PASSWORD ?? "",
  // GoPhish
  gophishBaseUrl: resolveGophishUrl(),
  gophishApiKey: process.env.GOPHISH_API_KEY ?? "",
  // Passive ASM connector API keys (optional — free connectors work without keys)
  SHODAN_API_KEY: process.env.SHODAN_API_KEY ?? "",
  CENSYS_API_ID: process.env.CENSYS_API_ID ?? "",
  CENSYS_API_SECRET: process.env.CENSYS_API_SECRET ?? "",
  URLSCAN_API_KEY: process.env.URLSCAN_API_KEY ?? "",
  SECURITYTRAILS_API_KEY: process.env.SECURITYTRAILS_API_KEY ?? "",
  DEHASHED_API_KEY: process.env.DEHASHED_API_KEY ?? "",
};
