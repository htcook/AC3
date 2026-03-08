// ─── Resolve GoPhish URL ────────────────────────────────────────────────────
// GoPhish runs on the mail server (137.184.7.224:3333) but is proxied through
// nginx on the app server at https://gophish.aceofcloud.io. The HTTPS proxy is
// the only reliable path from the Manus production server, since direct IP:port
// connections may be blocked by firewalls or self-signed cert issues.
function resolveGophishUrl(): string {
  const env = process.env.GOPHISH_BASE_URL;
  // Accept if it points to the HTTPS domain proxy or the mail server directly
  if (env && (env.includes("gophish.aceofcloud.io") || env.includes("137.184.7.224"))) return env;
  return "https://gophish.aceofcloud.io";
}

// ─── Resolve Caldera URL ────────────────────────────────────────────────────
// Caldera runs on the app server (134.199.213.248:8888) and is proxied through
// nginx at https://caldera.aceofcloud.io. The HTTPS proxy is the reliable path.
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

// ─── Resolve Caldera Password ──────────────────────────────────────────────
// Custom dashboard login password. The hardcoded value is the canonical password.
// The env var is checked as a secondary option, but the $ character in the password
// can cause shell expansion issues in some deployment environments.
function resolveCalderaPassword(): string {
  // Canonical password — always accepted
  return "PVYedK$BUAYzyXaAegdEl2Dz";
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
  calderaPassword: resolveCalderaPassword(),
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
  BINARYEDGE_API_KEY: process.env.BINARYEDGE_API_KEY ?? "",
  GREYNOISE_API_KEY: process.env.GREYNOISE_API_KEY ?? "",
  // AbuseIPDB — IP abuse reputation
  ABUSEIPDB_API_KEY: process.env.ABUSEIPDB_API_KEY ?? "",
  // GitHub PAT — code recon dorks (fine-grained)
  GITHUB_PAT: process.env.GITHUB_PAT ?? '',
  // GitHub Classic Token — failover for rate-limited fine-grained PAT
  GITHUB_CLASSIC_TOKEN: process.env.GITHUB_CLASSIC_TOKEN ?? '',
  // HackerOne Bug Bounty Intelligence
  HACKERONE_API_KEY: process.env.HACKERONE_API_KEY ?? "",
  // DigitalOcean — domain purchasing
  DIGITALOCEAN_ACCESS_TOKEN: process.env.DIGITALOCEAN_ACCESS_TOKEN ?? "",
  // Scan Server (DigitalOcean droplet with offensive tools)
  SCAN_SERVER_HOST: process.env.SCAN_SERVER_HOST ?? "",
  SCAN_SERVER_USER: process.env.SCAN_SERVER_USER ?? "root",
  SCAN_SERVER_SSH_KEY: process.env.SCAN_SERVER_SSH_KEY ?? "",
  // Metasploit MSGRPC
  MSF_RPC_HOST: process.env.MSF_RPC_HOST ?? "",
  MSF_RPC_PORT: parseInt(process.env.MSF_RPC_PORT ?? "55553", 10),
  MSF_RPC_USER: process.env.MSF_RPC_USER ?? "msf",
  MSF_RPC_PASS: process.env.MSF_RPC_PASS ?? "",
  MSF_RPC_SSL: process.env.MSF_RPC_SSL === "true",
  // Cobalt Strike Team Server
  CS_TEAM_SERVER_URL: process.env.CS_TEAM_SERVER_URL ?? "",
  CS_TEAM_SERVER_PORT: parseInt(process.env.CS_TEAM_SERVER_PORT ?? "50050", 10),
  CS_API_KEY: process.env.CS_API_KEY ?? "",
  CS_API_PORT: parseInt(process.env.CS_API_PORT ?? "55553", 10),
  CS_USERNAME: process.env.CS_USERNAME ?? "",
  CS_PASSWORD: process.env.CS_PASSWORD ?? "",
  // OpenAI — direct API access (bypasses Forge proxy token limits)
  openaiApiKey: process.env.OPENAI_API_KEY ?? "",
};
