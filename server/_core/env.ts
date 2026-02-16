export const ENV = {
  appId: process.env.VITE_APP_ID ?? "",
  cookieSecret: process.env.JWT_SECRET ?? "",
  databaseUrl: process.env.DATABASE_URL ?? "",
  oAuthServerUrl: process.env.OAUTH_SERVER_URL ?? "",
  ownerOpenId: process.env.OWNER_OPEN_ID ?? "",
  isProduction: process.env.NODE_ENV === "production",
  forgeApiUrl: process.env.BUILT_IN_FORGE_API_URL ?? "",
  forgeApiKey: process.env.BUILT_IN_FORGE_API_KEY ?? "",
  // Caldera - resolve to remote server if env points to localhost
  calderaBaseUrl: (process.env.CALDERA_BASE_URL && !process.env.CALDERA_BASE_URL.includes('127.0.0.1') && !process.env.CALDERA_BASE_URL.includes('localhost'))
    ? process.env.CALDERA_BASE_URL
    : "http://137.184.7.224:8888",
  calderaApiKey: process.env.CALDERA_API_KEY ?? "",
  calderaUsername: process.env.CALDERA_USERNAME ?? "red",
  calderaPassword: process.env.CALDERA_PASSWORD ?? "",
  // GoPhish - resolve to remote server if env points to localhost
  gophishBaseUrl: (process.env.GOPHISH_BASE_URL && !process.env.GOPHISH_BASE_URL.includes('127.0.0.1') && !process.env.GOPHISH_BASE_URL.includes('localhost'))
    ? process.env.GOPHISH_BASE_URL
    : "https://137.184.7.224:3333",
  gophishApiKey: process.env.GOPHISH_API_KEY ?? "",
  // Passive ASM connector API keys (optional — free connectors work without keys)
  SHODAN_API_KEY: process.env.SHODAN_API_KEY ?? "",
  CENSYS_API_ID: process.env.CENSYS_API_ID ?? "",
  CENSYS_API_SECRET: process.env.CENSYS_API_SECRET ?? "",
  URLSCAN_API_KEY: process.env.URLSCAN_API_KEY ?? "",
  SECURITYTRAILS_API_KEY: process.env.SECURITYTRAILS_API_KEY ?? "",
};
