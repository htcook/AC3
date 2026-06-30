/**
 * Redirector Management Service
 * 
 * Manages the lifecycle of red team redirectors (SMTP, HTTP/S, DNS, C2).
 * Based on Red Team Infrastructure Wiki principles:
 *   - Every backend asset should have a redirector in front of it
 *   - Functional segregation: separate assets by function
 *   - Resilience: rolling fresh redirectors without rebuilding team servers
 * 
 * Redirector types:
 *   - SMTP: Sendmail/Postfix catch-all relays that strip internal headers
 *   - HTTP(S): Apache mod_rewrite conditional filtering, socat pipes, nginx reverse proxies
 *   - DNS: socat UDP forwarding, iptables NAT rules
 *   - C2: Protocol-aware proxies that filter real C2 from investigative traffic
 */

export type RedirectorType = "smtp" | "http" | "https" | "dns" | "c2";
export type RedirectorStatus = "provisioning" | "active" | "degraded" | "down" | "decommissioned";
export type RedirectorEngine = "socat" | "apache_mod_rewrite" | "nginx_proxy" | "iptables_nat" | "ssh_tunnel" | "caddy" | "haproxy";

export interface RedirectorConfig {
  id: string;
  name: string;
  type: RedirectorType;
  engine: RedirectorEngine;
  /** Public-facing IP/hostname */
  frontendHost: string;
  frontendPort: number;
  /** Backend team server IP/hostname */
  backendHost: string;
  backendPort: number;
  /** Associated engagement ID */
  engagementId?: string;
  /** Associated domain (for HTTP/HTTPS redirectors) */
  domain?: string;
  /** SSL certificate status */
  sslEnabled: boolean;
  sslCertExpiry?: string;
  /** Filtering rules (mod_rewrite conditions, IP allowlists, etc.) */
  filterRules: FilterRule[];
  /** Health check configuration */
  healthCheck: HealthCheckConfig;
  status: RedirectorStatus;
  createdAt: number;
  lastHealthCheck?: number;
  lastHealthStatus?: string;
  metadata: Record<string, string>;
}

export interface FilterRule {
  id: string;
  type: "ip_allowlist" | "ip_blocklist" | "ua_filter" | "uri_pattern" | "header_match" | "geo_block" | "time_window";
  description: string;
  /** The rule value (CIDR, regex, header name=value, etc.) */
  value: string;
  action: "allow" | "block" | "redirect_to_decoy";
  enabled: boolean;
}

export interface HealthCheckConfig {
  enabled: boolean;
  intervalSeconds: number;
  method: "tcp_connect" | "http_get" | "dns_resolve" | "smtp_ehlo";
  endpoint?: string;
  expectedStatus?: number;
  timeoutMs: number;
}

export interface HealthCheckResult {
  redirectorId: string;
  timestamp: number;
  status: "healthy" | "unhealthy" | "timeout" | "error";
  latencyMs: number;
  details: string;
  responseCode?: number;
}

export interface RedirectorTopology {
  /** All redirectors grouped by engagement */
  engagements: Record<string, RedirectorConfig[]>;
  /** Topology edges: redirector -> backend mapping */
  edges: Array<{ from: string; to: string; type: RedirectorType; status: RedirectorStatus }>;
  /** Summary statistics */
  stats: {
    total: number;
    active: number;
    degraded: number;
    down: number;
    byType: Record<RedirectorType, number>;
    byEngine: Record<RedirectorEngine, number>;
  };
}

// ── In-memory store (production would use DB) ──────────────────────────

const redirectors = new Map<string, RedirectorConfig>();
const healthHistory = new Map<string, HealthCheckResult[]>();

let nextId = 1;

function generateId(): string {
  return `rdr-${Date.now()}-${nextId++}`;
}

// ── Redirector CRUD ────────────────────────────────────────────────────

export function createRedirector(input: {
  name: string;
  type: RedirectorType;
  engine: RedirectorEngine;
  frontendHost: string;
  frontendPort: number;
  backendHost: string;
  backendPort: number;
  engagementId?: string;
  domain?: string;
  sslEnabled?: boolean;
  filterRules?: FilterRule[];
  healthCheck?: Partial<HealthCheckConfig>;
  metadata?: Record<string, string>;
}): RedirectorConfig {
  const id = generateId();
  
  const defaultHealthCheck: HealthCheckConfig = {
    enabled: true,
    intervalSeconds: 60,
    method: input.type === "smtp" ? "smtp_ehlo"
          : input.type === "dns" ? "dns_resolve"
          : input.type === "http" || input.type === "https" ? "http_get"
          : "tcp_connect",
    timeoutMs: 5000,
    ...input.healthCheck,
  };

  const config: RedirectorConfig = {
    id,
    name: input.name,
    type: input.type,
    engine: input.engine,
    frontendHost: input.frontendHost,
    frontendPort: input.frontendPort,
    backendHost: input.backendHost,
    backendPort: input.backendPort,
    engagementId: input.engagementId,
    domain: input.domain,
    sslEnabled: input.sslEnabled ?? false,
    filterRules: input.filterRules ?? [],
    healthCheck: defaultHealthCheck,
    status: "provisioning",
    createdAt: Date.now(),
    metadata: input.metadata ?? {},
  };

  redirectors.set(id, config);
  return config;
}

export function getRedirector(id: string): RedirectorConfig | undefined {
  return redirectors.get(id);
}

export function listRedirectors(filters?: {
  type?: RedirectorType;
  status?: RedirectorStatus;
  engagementId?: string;
}): RedirectorConfig[] {
  let results = Array.from(redirectors.values());
  if (filters?.type) results = results.filter(r => r.type === filters.type);
  if (filters?.status) results = results.filter(r => r.status === filters.status);
  if (filters?.engagementId) results = results.filter(r => r.engagementId === filters.engagementId);
  return results.sort((a, b) => b.createdAt - a.createdAt);
}

export function updateRedirector(id: string, updates: Partial<Omit<RedirectorConfig, "id" | "createdAt">>): RedirectorConfig | null {
  const existing = redirectors.get(id);
  if (!existing) return null;
  const updated = { ...existing, ...updates };
  redirectors.set(id, updated);
  return updated;
}

export function deleteRedirector(id: string): boolean {
  return redirectors.delete(id);
}

export function activateRedirector(id: string): RedirectorConfig | null {
  return updateRedirector(id, { status: "active" });
}

export function decommissionRedirector(id: string): RedirectorConfig | null {
  return updateRedirector(id, { status: "decommissioned" });
}

// ── Filter Rule Management ─────────────────────────────────────────────

export function addFilterRule(redirectorId: string, rule: Omit<FilterRule, "id">): FilterRule | null {
  const rdr = redirectors.get(redirectorId);
  if (!rdr) return null;
  const newRule: FilterRule = { ...rule, id: `rule-${Date.now()}-${Math.random().toString(36).slice(2, 8)}` };
  rdr.filterRules.push(newRule);
  return newRule;
}

export function removeFilterRule(redirectorId: string, ruleId: string): boolean {
  const rdr = redirectors.get(redirectorId);
  if (!rdr) return false;
  const idx = rdr.filterRules.findIndex(r => r.id === ruleId);
  if (idx === -1) return false;
  rdr.filterRules.splice(idx, 1);
  return true;
}

export function toggleFilterRule(redirectorId: string, ruleId: string): FilterRule | null {
  const rdr = redirectors.get(redirectorId);
  if (!rdr) return null;
  const rule = rdr.filterRules.find(r => r.id === ruleId);
  if (!rule) return null;
  rule.enabled = !rule.enabled;
  return rule;
}

// ── Health Checking ────────────────────────────────────────────────────

export async function performHealthCheck(id: string): Promise<HealthCheckResult> {
  const rdr = redirectors.get(id);
  if (!rdr) {
    return {
      redirectorId: id,
      timestamp: Date.now(),
      status: "error",
      latencyMs: 0,
      details: "Redirector not found",
    };
  }

  const start = Date.now();
  
  // Simulate health check based on method
  const result: HealthCheckResult = await simulateHealthCheck(rdr, start);
  
  // Update redirector status based on health
  if (result.status === "healthy") {
    if (rdr.status === "degraded" || rdr.status === "down") {
      rdr.status = "active";
    }
  } else if (result.status === "unhealthy" || result.status === "timeout") {
    rdr.status = "degraded";
  } else {
    rdr.status = "down";
  }
  
  rdr.lastHealthCheck = result.timestamp;
  rdr.lastHealthStatus = result.status;

  // Store history
  const history = healthHistory.get(id) ?? [];
  history.push(result);
  if (history.length > 100) history.shift();
  healthHistory.set(id, history);

  return result;
}

async function simulateHealthCheck(rdr: RedirectorConfig, startTime: number): Promise<HealthCheckResult> {
  // In production, this would make real TCP/HTTP/DNS/SMTP connections
  // For the platform, we simulate based on configuration
  const latency = Math.floor(Math.random() * 150) + 10;
  const isHealthy = rdr.status !== "decommissioned" && Math.random() > 0.1;

  if (rdr.healthCheck.method === "http_get") {
    return {
      redirectorId: rdr.id,
      timestamp: startTime,
      status: isHealthy ? "healthy" : "unhealthy",
      latencyMs: latency,
      details: isHealthy
        ? `HTTP GET ${rdr.frontendHost}:${rdr.frontendPort} → 200 OK`
        : `HTTP GET ${rdr.frontendHost}:${rdr.frontendPort} → Connection refused`,
      responseCode: isHealthy ? 200 : undefined,
    };
  }

  if (rdr.healthCheck.method === "smtp_ehlo") {
    return {
      redirectorId: rdr.id,
      timestamp: startTime,
      status: isHealthy ? "healthy" : "unhealthy",
      latencyMs: latency,
      details: isHealthy
        ? `SMTP EHLO ${rdr.frontendHost}:${rdr.frontendPort} → 250 OK`
        : `SMTP EHLO ${rdr.frontendHost}:${rdr.frontendPort} → timeout`,
    };
  }

  if (rdr.healthCheck.method === "dns_resolve") {
    return {
      redirectorId: rdr.id,
      timestamp: startTime,
      status: isHealthy ? "healthy" : "unhealthy",
      latencyMs: latency,
      details: isHealthy
        ? `DNS resolve via ${rdr.frontendHost}:${rdr.frontendPort} → A record returned`
        : `DNS resolve via ${rdr.frontendHost}:${rdr.frontendPort} → SERVFAIL`,
    };
  }

  return {
    redirectorId: rdr.id,
    timestamp: startTime,
    status: isHealthy ? "healthy" : "unhealthy",
    latencyMs: latency,
    details: isHealthy
      ? `TCP connect ${rdr.frontendHost}:${rdr.frontendPort} → established`
      : `TCP connect ${rdr.frontendHost}:${rdr.frontendPort} → refused`,
  };
}

export function getHealthHistory(id: string, limit = 20): HealthCheckResult[] {
  const history = healthHistory.get(id) ?? [];
  return history.slice(-limit);
}

// ── Topology Builder ───────────────────────────────────────────────────

export function buildTopology(): RedirectorTopology {
  const all = Array.from(redirectors.values());
  
  const engagements: Record<string, RedirectorConfig[]> = {};
  const edges: RedirectorTopology["edges"] = [];
  const byType: Record<RedirectorType, number> = { smtp: 0, http: 0, https: 0, dns: 0, c2: 0 };
  const byEngine: Record<RedirectorEngine, number> = {
    socat: 0, apache_mod_rewrite: 0, nginx_proxy: 0, iptables_nat: 0,
    ssh_tunnel: 0, caddy: 0, haproxy: 0,
  };

  let active = 0, degraded = 0, down = 0;

  for (const rdr of all) {
    const engId = rdr.engagementId ?? "unassigned";
    if (!engagements[engId]) engagements[engId] = [];
    engagements[engId].push(rdr);

    edges.push({
      from: `${rdr.frontendHost}:${rdr.frontendPort}`,
      to: `${rdr.backendHost}:${rdr.backendPort}`,
      type: rdr.type,
      status: rdr.status,
    });

    byType[rdr.type]++;
    byEngine[rdr.engine]++;
    if (rdr.status === "active") active++;
    else if (rdr.status === "degraded") degraded++;
    else if (rdr.status === "down") down++;
  }

  return {
    engagements,
    edges,
    stats: {
      total: all.length,
      active,
      degraded,
      down,
      byType,
      byEngine,
    },
  };
}

// ── Configuration Generators ───────────────────────────────────────────

export function generateRedirectorConfig(id: string): string | null {
  const rdr = redirectors.get(id);
  if (!rdr) return null;

  switch (rdr.engine) {
    case "apache_mod_rewrite":
      return generateApacheConfig(rdr);
    case "nginx_proxy":
      return generateNginxConfig(rdr);
    case "socat":
      return generateSocatConfig(rdr);
    case "iptables_nat":
      return generateIptablesConfig(rdr);
    case "caddy":
      return generateCaddyConfig(rdr);
    case "haproxy":
      return generateHaproxyConfig(rdr);
    case "ssh_tunnel":
      return generateSshTunnelConfig(rdr);
    default:
      return `# Unknown engine: ${rdr.engine}`;
  }
}

function generateApacheConfig(rdr: RedirectorConfig): string {
  const rules = rdr.filterRules.filter(r => r.enabled);
  const blockRules = rules.filter(r => r.action === "block");
  const allowRules = rules.filter(r => r.action === "allow");

  let config = `# Apache mod_rewrite Redirector Configuration
# Generated by AC3 — ${rdr.name}
# Type: ${rdr.type} | Frontend: ${rdr.frontendHost}:${rdr.frontendPort}

<VirtualHost *:${rdr.frontendPort}>
    ServerName ${rdr.domain || rdr.frontendHost}

    RewriteEngine On
    RewriteOptions inherit

    # Log all requests for operational awareness
    LogLevel rewrite:trace3
`;

  // Add IP blocklist rules
  for (const rule of blockRules) {
    if (rule.type === "ip_blocklist") {
      config += `
    # Block: ${rule.description}
    RewriteCond %{REMOTE_ADDR} ^${rule.value.replace(/\./g, "\\.")}
    RewriteRule ^(.*)$ https://www.google.com/ [L,R=302]
`;
    }
    if (rule.type === "ua_filter") {
      config += `
    # Block UA: ${rule.description}
    RewriteCond %{HTTP_USER_AGENT} "${rule.value}" [NC]
    RewriteRule ^(.*)$ https://www.google.com/ [L,R=302]
`;
    }
  }

  // Add URI pattern filtering
  for (const rule of rules.filter(r => r.type === "uri_pattern" && r.action === "allow")) {
    config += `
    # Allow URI: ${rule.description}
    RewriteCond %{REQUEST_URI} ${rule.value}
    RewriteRule ^(.*)$ http://${rdr.backendHost}:${rdr.backendPort}%{REQUEST_URI} [P]
`;
  }

  config += `
    # Default: redirect to decoy
    RewriteRule ^(.*)$ https://www.google.com/ [L,R=302]

    # Proxy settings
    SSLProxyEngine On
    ProxyPreserveHost On
</VirtualHost>
`;
  return config;
}

function generateNginxConfig(rdr: RedirectorConfig): string {
  const rules = rdr.filterRules.filter(r => r.enabled);
  let config = `# Nginx Reverse Proxy Redirector
# Generated by AC3 — ${rdr.name}

upstream backend_${rdr.id.replace(/-/g, "_")} {
    server ${rdr.backendHost}:${rdr.backendPort};
}

server {
    listen ${rdr.frontendPort}${rdr.sslEnabled ? " ssl" : ""};
    server_name ${rdr.domain || rdr.frontendHost};
`;

  if (rdr.sslEnabled) {
    config += `
    ssl_certificate /etc/letsencrypt/live/${rdr.domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${rdr.domain}/privkey.pem;
`;
  }

  // Add IP filtering
  for (const rule of rules.filter(r => r.type === "ip_blocklist" && r.action === "block")) {
    config += `    deny ${rule.value}; # ${rule.description}\n`;
  }
  for (const rule of rules.filter(r => r.type === "ip_allowlist" && r.action === "allow")) {
    config += `    allow ${rule.value}; # ${rule.description}\n`;
  }

  config += `
    # Strip server headers for OpSec
    proxy_hide_header X-Powered-By;
    proxy_hide_header Server;
    more_clear_headers Server;

    location / {
        proxy_pass http://backend_${rdr.id.replace(/-/g, "_")};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # Default: return decoy page
    error_page 403 =302 https://www.google.com/;
}
`;
  return config;
}

function generateSocatConfig(rdr: RedirectorConfig): string {
  if (rdr.type === "dns") {
    return `#!/bin/bash
# socat DNS Redirector
# Generated by AC3 — ${rdr.name}
# Forwards UDP DNS traffic from frontend to backend

socat UDP4-LISTEN:${rdr.frontendPort},fork UDP4:${rdr.backendHost}:${rdr.backendPort}
`;
  }
  return `#!/bin/bash
# socat TCP Redirector (dumb pipe)
# Generated by AC3 — ${rdr.name}
# Forwards all TCP traffic from frontend to backend

socat TCP4-LISTEN:${rdr.frontendPort},fork TCP4:${rdr.backendHost}:${rdr.backendPort}
`;
}

function generateIptablesConfig(rdr: RedirectorConfig): string {
  const proto = rdr.type === "dns" ? "udp" : "tcp";
  return `#!/bin/bash
# iptables NAT Redirector
# Generated by AC3 — ${rdr.name}

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# DNAT: forward incoming traffic to backend
iptables -t nat -A PREROUTING -p ${proto} --dport ${rdr.frontendPort} \\
  -j DNAT --to-destination ${rdr.backendHost}:${rdr.backendPort}

# SNAT: masquerade return traffic
iptables -t nat -A POSTROUTING -p ${proto} -d ${rdr.backendHost} --dport ${rdr.backendPort} \\
  -j MASQUERADE

# Allow forwarded traffic
iptables -A FORWARD -p ${proto} -d ${rdr.backendHost} --dport ${rdr.backendPort} \\
  -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
`;
}

function generateCaddyConfig(rdr: RedirectorConfig): string {
  return `# Caddy Reverse Proxy Redirector
# Generated by AC3 — ${rdr.name}
# Automatic HTTPS with Let's Encrypt

${rdr.domain || rdr.frontendHost}:${rdr.frontendPort} {
    reverse_proxy ${rdr.backendHost}:${rdr.backendPort}
    
    header -Server
    header -X-Powered-By
    
    log {
        output file /var/log/caddy/${rdr.name}.log
        format json
    }
}
`;
}

function generateHaproxyConfig(rdr: RedirectorConfig): string {
  return `# HAProxy Redirector
# Generated by AC3 — ${rdr.name}

frontend ${rdr.name}_frontend
    bind *:${rdr.frontendPort}
    mode ${rdr.type === "smtp" ? "tcp" : "http"}
    default_backend ${rdr.name}_backend

backend ${rdr.name}_backend
    mode ${rdr.type === "smtp" ? "tcp" : "http"}
    server backend1 ${rdr.backendHost}:${rdr.backendPort} check
`;
}

function generateSshTunnelConfig(rdr: RedirectorConfig): string {
  return `#!/bin/bash
# SSH Tunnel Redirector
# Generated by AC3 — ${rdr.name}
# Useful when behind NAT or when other methods aren't available

# Remote forward: expose backend port through frontend
ssh -N -R ${rdr.frontendPort}:${rdr.backendHost}:${rdr.backendPort} \\
  root@${rdr.frontendHost} \\
  -o ServerAliveInterval=60 \\
  -o ServerAliveCountMax=3 \\
  -o ExitOnForwardFailure=yes
`;
}

// ── Preset Templates ───────────────────────────────────────────────────

export interface RedirectorTemplate {
  id: string;
  name: string;
  description: string;
  type: RedirectorType;
  engine: RedirectorEngine;
  defaultPort: number;
  defaultFilterRules: Omit<FilterRule, "id">[];
  tags: string[];
}

export const REDIRECTOR_TEMPLATES: RedirectorTemplate[] = [
  {
    id: "smtp-postfix-relay",
    name: "SMTP Postfix Relay",
    description: "Catch-all Postfix relay that strips internal headers and forwards to phishing mail server",
    type: "smtp",
    engine: "socat",
    defaultPort: 25,
    defaultFilterRules: [
      { type: "ip_blocklist", description: "Block known mail scanners", value: "0.0.0.0/0", action: "block", enabled: false },
    ],
    tags: ["phishing", "email", "postfix"],
  },
  {
    id: "http-apache-c2",
    name: "HTTP C2 Redirector (Apache)",
    description: "Apache mod_rewrite redirector that filters C2 traffic from IR investigation traffic",
    type: "http",
    engine: "apache_mod_rewrite",
    defaultPort: 80,
    defaultFilterRules: [
      { type: "ua_filter", description: "Block curl/wget scanners", value: "(curl|wget|python-requests)", action: "block", enabled: true },
      { type: "ip_blocklist", description: "Block Shodan scanners", value: "71.6.146.0/24", action: "block", enabled: true },
      { type: "ip_blocklist", description: "Block Censys scanners", value: "162.142.125.0/24", action: "block", enabled: true },
    ],
    tags: ["c2", "cobalt-strike", "apache"],
  },
  {
    id: "https-nginx-payload",
    name: "HTTPS Payload Redirector (Nginx)",
    description: "Nginx reverse proxy for payload hosting with SSL and URI filtering",
    type: "https",
    engine: "nginx_proxy",
    defaultPort: 443,
    defaultFilterRules: [
      { type: "uri_pattern", description: "Only serve specific payload paths", value: "^/update/.*$", action: "allow", enabled: true },
      { type: "ua_filter", description: "Block security scanners", value: "(Nmap|Nikto|Burp|ZAP)", action: "block", enabled: true },
    ],
    tags: ["payload", "hosting", "ssl"],
  },
  {
    id: "dns-socat-forward",
    name: "DNS Redirector (socat)",
    description: "Simple UDP DNS forwarder for DNS-based C2 exfiltration channels",
    type: "dns",
    engine: "socat",
    defaultPort: 53,
    defaultFilterRules: [],
    tags: ["dns", "exfiltration", "c2"],
  },
  {
    id: "c2-haproxy-lb",
    name: "C2 Load Balancer (HAProxy)",
    description: "HAProxy load balancer distributing C2 callbacks across multiple team servers",
    type: "c2",
    engine: "haproxy",
    defaultPort: 443,
    defaultFilterRules: [
      { type: "ip_blocklist", description: "Block known IR ranges", value: "0.0.0.0/0", action: "block", enabled: false },
      { type: "geo_block", description: "Block non-target countries", value: "RU,CN,KP", action: "block", enabled: false },
    ],
    tags: ["c2", "load-balancer", "resilience"],
  },
  {
    id: "https-caddy-fronting",
    name: "HTTPS Domain Fronting (Caddy)",
    description: "Caddy-based HTTPS redirector with automatic Let's Encrypt for domain fronting",
    type: "https",
    engine: "caddy",
    defaultPort: 443,
    defaultFilterRules: [
      { type: "header_match", description: "Only forward matching Host header", value: "Host: legitimate-domain.com", action: "allow", enabled: true },
    ],
    tags: ["domain-fronting", "ssl", "caddy"],
  },
];

export function getTemplates(): RedirectorTemplate[] {
  return REDIRECTOR_TEMPLATES;
}

export function createFromTemplate(templateId: string, overrides: {
  name: string;
  frontendHost: string;
  backendHost: string;
  backendPort: number;
  engagementId?: string;
  domain?: string;
}): RedirectorConfig | null {
  const template = REDIRECTOR_TEMPLATES.find(t => t.id === templateId);
  if (!template) return null;

  return createRedirector({
    name: overrides.name,
    type: template.type,
    engine: template.engine,
    frontendHost: overrides.frontendHost,
    frontendPort: template.defaultPort,
    backendHost: overrides.backendHost,
    backendPort: overrides.backendPort,
    engagementId: overrides.engagementId,
    domain: overrides.domain,
    sslEnabled: template.type === "https",
    filterRules: template.defaultFilterRules.map(r => ({
      ...r,
      id: `rule-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    })),
  });
}

// ── Bulk Operations ────────────────────────────────────────────────────

export async function healthCheckAll(): Promise<HealthCheckResult[]> {
  const active = listRedirectors({ status: "active" });
  const degraded = listRedirectors({ status: "degraded" });
  const toCheck = [...active, ...degraded];
  
  const results: HealthCheckResult[] = [];
  for (const rdr of toCheck) {
    results.push(await performHealthCheck(rdr.id));
  }
  return results;
}

export function decommissionByEngagement(engagementId: string): number {
  const rdrs = listRedirectors({ engagementId });
  let count = 0;
  for (const rdr of rdrs) {
    if (decommissionRedirector(rdr.id)) count++;
  }
  return count;
}

// ── Reset (for testing) ────────────────────────────────────────────────

export function _resetForTesting(): void {
  redirectors.clear();
  healthHistory.clear();
  nextId = 1;
}
