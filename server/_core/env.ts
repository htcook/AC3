// ─── Resolve GoPhish URL ────────────────────────────────────────────────────
// GoPhish runs as an internal ECS service in the C2 subnet.
// Resolved via CloudMap service discovery: gophish.ac3-dev.local:3333
// The gophish-client.ts uses an undici dispatcher with TLS override to handle
// the self-signed cert, so direct connections work reliably.
function resolveGophishUrl(): string {
  const env = process.env.GOPHISH_BASE_URL;
  if (env) return env;
  // Fallback: construct from MAIL_SERVER_IP if available (legacy)
  const mailIp = process.env.MAIL_SERVER_IP;
  if (mailIp) return `https://${mailIp}:3333`;
  // Default: internal service discovery DNS
  return "https://gophish.ac3-dev.local:3333";
}

// ─── Resolve Cyber C2 URL ────────────────────────────────────────────────────
// Caldera runs as an internal ECS service in the C2 subnet.
// Resolved via CloudMap service discovery: caldera.ac3-dev.local:8888
// The AC3 app communicates with Caldera over the internal VPC network.
function resolveCalderaUrl(): string {
  const env = process.env.CALDERA_BASE_URL;
  // Accept any explicitly configured URL (internal DNS, IP, or domain)
  if (env) return env;
  // Default: internal service discovery DNS
  return "http://caldera.ac3-dev.local:8888";
}

// ─── Resolve Cyber C2 API Key ────────────────────────────────────────────────
// With --insecure flag, Caldera uses default.yml which sets API key to ADMIN123.
// In production, a strong custom key should be configured via CALDERA_API_KEY env var.
function resolveCalderaApiKey(): string {
  const env = process.env.CALDERA_API_KEY;
  if (!env || env.length < 3) {
    if (process.env.NODE_ENV === "production") {
      console.warn("[SECURITY] CALDERA_API_KEY not configured. C2 features will fail.");
    }
    return "ADMIN123"; // Default for --insecure mode
  }
  return env;
}

// ─── Resolve Cyber C2 Password ──────────────────────────────────────────────
// Caldera 'red' service account password — read from CALDERA_PASSWORD secret.
// Never hardcode credentials; the password is managed via webdev_request_secrets.
function resolveCalderaPassword(): string {
  return process.env.CALDERA_PASSWORD ?? "";
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
  // Cyber C2
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
  // OSINT Pipeline Expansion — additional connector API keys
  VIRUSTOTAL_API_KEY: process.env.VIRUSTOTAL_API_KEY ?? "",
  HIBP_API_KEY: process.env.HIBP_API_KEY ?? "",
  WHOISXML_API_KEY: process.env.WHOISXML_API_KEY ?? "",
  LEAKIX_API_KEY: process.env.LEAKIX_API_KEY ?? "",
  FULLHUNT_API_KEY: process.env.FULLHUNT_API_KEY ?? "",
  NETLAS_API_KEY: process.env.NETLAS_API_KEY ?? "",
  HUNTER_API_KEY: process.env.HUNTER_API_KEY ?? "",
  PASSIVETOTAL_API_KEY: process.env.PASSIVETOTAL_API_KEY ?? "",
  INTELX_API_KEY: process.env.INTELX_API_KEY ?? "",
  HUDSON_ROCK_API_KEY: process.env.HUDSON_ROCK_API_KEY ?? "",
  LEAKCHECK_API_KEY: process.env.LEAKCHECK_API_KEY ?? "",
  // GitHub PAT — code recon dorks (fine-grained)
  GITHUB_PAT: process.env.GITHUB_PAT ?? '',
  // GitHub Classic Token — failover for rate-limited fine-grained PAT
  GITHUB_CLASSIC_TOKEN: process.env.GITHUB_CLASSIC_TOKEN ?? '',
  // HackerOne Bug Bounty Intelligence
  HACKERONE_API_KEY: process.env.HACKERONE_API_KEY ?? "",
  HACKERONE_API_USERNAME: process.env.HACKERONE_API_USERNAME ?? "",
  // DigitalOcean — domain purchasing (legacy, being replaced by AWS)
  DIGITALOCEAN_ACCESS_TOKEN: process.env.DIGITALOCEAN_ACCESS_TOKEN ?? "",
  // Namecheap — domain registration & DNS management
  NAMECHEAP_API_KEY: process.env.NAMECHEAP_API_KEY ?? "",
  NAMECHEAP_API_USER: process.env.NAMECHEAP_API_USER ?? "",
  NAMECHEAP_CLIENT_IP: process.env.NAMECHEAP_CLIENT_IP ?? "",
  NAMECHEAP_SANDBOX: process.env.NAMECHEAP_SANDBOX ?? "false",
  // GoDaddy — domain registration & DNS management
  GODADDY_API_KEY: process.env.GODADDY_API_KEY ?? "",
  GODADDY_API_SECRET: process.env.GODADDY_API_SECRET ?? "",
  GODADDY_SANDBOX: process.env.GODADDY_SANDBOX ?? "false",
  GODADDY_SHOPPER_ID: process.env.GODADDY_SHOPPER_ID ?? "",
  // Mail Server IP — used for phishing DNS configuration (MX, SPF)
  MAIL_SERVER_IP: process.env.MAIL_SERVER_IP ?? "",
  // AC3-Plus Compliance Service
  AC3_PLUS_COMPLIANCE_URL: process.env.AC3_PLUS_COMPLIANCE_URL ?? "https://compliance.aceofcloud.io",
  AC3_PLUS_SERVICE_SECRET: process.env.AC3_PLUS_SERVICE_SECRET ?? "",
  // AWS EC2 — MSF server provisioning & scan infrastructure
  AWS_ACCESS_KEY_ID: process.env.AWS_ACCESS_KEY_ID || process.env.AWS_USERNAME || "",
  AWS_SECRET_ACCESS_KEY: process.env.AWS_SECRET_ACCESS_KEY || process.env.AWS_PASSWORD || "",
  AWS_REGION: process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION || "us-east-1",
  AWS_SESSION_TOKEN: process.env.AWS_SESSION_TOKEN || "",
  AWS_VPC_ID: process.env.AWS_VPC_ID || "",
  AWS_SUBNET_ID: process.env.AWS_SUBNET_ID || "",
  AWS_SECURITY_GROUP_ID: process.env.AWS_SECURITY_GROUP_ID || "",
  AWS_KEY_PAIR_NAME: process.env.AWS_KEY_PAIR_NAME || "ac3-scan-infra",
  AWS_MSF_AMI_ID: process.env.AWS_MSF_AMI_ID || "", // Custom AMI with MSF pre-installed (optional)
  // S3-Compatible Storage (generic — preferred for new deployments)
  // Set these to use AWS S3, MinIO, or any S3-compatible provider.
  // If not set, falls back to DO_SPACES_* vars below.
  S3_ENDPOINT: process.env.S3_ENDPOINT ?? "",
  S3_REGION: process.env.S3_REGION ?? "",
  S3_ACCESS_KEY: process.env.S3_ACCESS_KEY ?? "",
  S3_SECRET_KEY: process.env.S3_SECRET_KEY ?? "",
  S3_BUCKET: process.env.S3_BUCKET ?? "",
  S3_SESSION_TOKEN: process.env.S3_SESSION_TOKEN ?? "",  // STS session token for temporary credentials (AssumeRole, ECS task role)
  S3_FORCE_PATH_STYLE: process.env.S3_FORCE_PATH_STYLE ?? "false",
  S3_PUBLIC_URL_BASE: process.env.S3_PUBLIC_URL_BASE ?? "",
  // Server-Side Encryption (FIPS 140-3 compliance for GovCloud / High-impact)
  S3_SSE_ALGORITHM: process.env.S3_SSE_ALGORITHM ?? "",           // "AES256" | "aws:kms" | "aws:kms:dsse"
  S3_SSE_KMS_KEY_ID: process.env.S3_SSE_KMS_KEY_ID ?? "",        // KMS Key ARN
  S3_BUCKET_KEY_ENABLED: process.env.S3_BUCKET_KEY_ENABLED ?? "false",  // Reduce KMS API calls
  S3_PRIVATE_MODE: process.env.S3_PRIVATE_MODE ?? "false",       // Force presigned URLs (auto-enabled with SSE)
  S3_USE_FIPS: process.env.S3_USE_FIPS ?? "",                    // "true" to force FIPS endpoints (auto for us-gov-* regions)
  // Client-Side Encryption (CSE) — envelope encryption for highest-sensitivity artifacts
  S3_CSE_KEY_ARN: process.env.S3_CSE_KEY_ARN ?? "",              // KMS CMK ARN for data key encryption (or local key ID)
  S3_CSE_ENABLED: process.env.S3_CSE_ENABLED ?? "false",         // "true" to enable CSE for doStoragePutEncrypted/GetDecrypted
  // DigitalOcean Spaces — legacy storage config (backward compat)
  // These are used if S3_* vars above are not set.
  DO_SPACES_KEY: process.env.DO_SPACES_KEY ?? "",
  DO_SPACES_SECRET: process.env.DO_SPACES_SECRET ?? "",
  DO_SPACES_BUCKET: process.env.DO_SPACES_BUCKET ?? "aceofcloud-reports",
  DO_SPACES_REGION: process.env.DO_SPACES_REGION ?? "nyc3",
  DO_SPACES_ENDPOINT: process.env.DO_SPACES_ENDPOINT ?? "https://nyc3.digitaloceanspaces.com",
  // Scan Server (AWS EC2 instance with offensive tools)
  SCAN_SERVER_HOST: process.env.SCAN_SERVER_HOST ?? "",
  SCAN_SERVER_USER: process.env.SCAN_SERVER_USER ?? "root",
  SCAN_SERVER_INSTANCE_ID: process.env.SCANFORGE_INSTANCE_ID ?? process.env.SCAN_SERVER_INSTANCE_ID ?? "",
  // SCAN_SERVER_SSH_KEY removed — multi-line PEM breaks Docker build command
  // SSH key is loaded at runtime via S3 fallback in scan-server-executor.ts
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
  // Empire C2 (REST API — Starkiller/BC Security)
  EMPIRE_BASE_URL: process.env.EMPIRE_BASE_URL ?? "",
  EMPIRE_API_KEY: process.env.EMPIRE_API_KEY ?? "",
  EMPIRE_USERNAME: process.env.EMPIRE_USERNAME ?? "empireadmin",
  EMPIRE_PASSWORD: process.env.EMPIRE_PASSWORD ?? "",
  // Sliver C2 (gRPC operator API)
  SLIVER_SERVER_URL: process.env.SLIVER_SERVER_URL ?? "",
  SLIVER_OPERATOR_TOKEN: process.env.SLIVER_OPERATOR_TOKEN ?? "",
  SLIVER_OPERATOR_CONFIG: process.env.SLIVER_OPERATOR_CONFIG ?? "", // Base64-encoded operator config JSON
  // Manjusaka C2 (REST API) — DEPRECATED per security review (REC-LEGAL-001)
  // Adapter is no longer auto-registered in C2Registry. Env vars retained for backward compat.
  MANJUSAKA_SERVER_URL: process.env.MANJUSAKA_SERVER_URL ?? "",
  MANJUSAKA_API_TOKEN: process.env.MANJUSAKA_API_TOKEN ?? "",
  MANJUSAKA_ADMIN_PASSWORD: process.env.MANJUSAKA_ADMIN_PASSWORD ?? "",
  // OpenAI — direct API access (bypasses Forge proxy token limits)
  openaiApiKey: process.env.OPENAI_API_KEY ?? "",
};
