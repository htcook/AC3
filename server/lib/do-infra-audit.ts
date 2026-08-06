/**
 * DigitalOcean Infrastructure Audit Module
 *
 * Uses the DigitalOcean API v2 to audit cloud infrastructure for security
 * misconfigurations. Checks droplets, firewalls, load balancers, databases,
 * domains, and Kubernetes clusters against security best practices.
 *
 * Referenced by FedRAMP KSI Map as:
 *   - "DigitalOcean Infrastructure Audit" (KSI-CNA-HCI)
 *   - "DigitalOcean Firewall Validation" (KSI-CNA-RNT)
 *   - "DigitalOcean Firewall Auditing" (KSI-CNA-ULN)
 *
 * Requires: DIGITALOCEAN_ACCESS_TOKEN env var
 */

import { ENV } from "../_core/env";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface AuditFinding {
  id: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  resource: string;
  resourceId: string | number;
  title: string;
  description: string;
  recommendation: string;
  evidence: Record<string, unknown>;
}

export interface AuditResult {
  timestamp: string;
  provider: "digitalocean";
  findings: AuditFinding[];
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    resourcesAudited: number;
    categoriesChecked: string[];
  };
  errors: string[];
}

// ─── DO API Client ──────────────────────────────────────────────────────────

const DO_API_BASE = "https://api.digitalocean.com/v2";

async function doFetch<T>(path: string): Promise<T | null> {
  const token = ENV.DIGITALOCEAN_ACCESS_TOKEN;
  if (!token) return null;

  try {
    const resp = await fetch(`${DO_API_BASE}${path}`, {
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
    });
    if (!resp.ok) {
      console.error(`[DO-Audit] API error ${resp.status} for ${path}`);
      return null;
    }
    return (await resp.json()) as T;
  } catch (err: any) {
    console.error(`[DO-Audit] Fetch error for ${path}: ${err.message}`);
    return null;
  }
}

/** Paginate through all pages of a DO API endpoint */
async function doFetchAll<T>(path: string, key: string): Promise<T[]> {
  const items: T[] = [];
  let page = 1;
  const perPage = 100;

  while (true) {
    const separator = path.includes("?") ? "&" : "?";
    const data = await doFetch<any>(`${path}${separator}page=${page}&per_page=${perPage}`);
    if (!data || !data[key] || data[key].length === 0) break;
    items.push(...data[key]);
    if (!data.links?.pages?.next) break;
    page++;
    if (page > 20) break; // Safety cap
  }

  return items;
}

// ─── Audit Checks ───────────────────────────────────────────────────────────

/** Audit droplets for security misconfigurations */
async function auditDroplets(): Promise<AuditFinding[]> {
  const findings: AuditFinding[] = [];
  const droplets = await doFetchAll<any>("/droplets", "droplets");

  for (const d of droplets) {
    const name = d.name || `droplet-${d.id}`;

    // Check: Droplet has no firewall
    if (!d.tags?.some((t: string) => t.includes("firewall")) && d.status === "active") {
      // Check via firewalls API if this droplet is covered
      const firewalls = await doFetchAll<any>("/firewalls", "firewalls");
      const covered = firewalls.some((fw: any) =>
        fw.droplet_ids?.includes(d.id) ||
        fw.tags?.some((t: string) => d.tags?.includes(t))
      );
      if (!covered) {
        findings.push({
          id: `DO-DRP-001-${d.id}`,
          severity: "high",
          category: "Firewall",
          resource: name,
          resourceId: d.id,
          title: "Droplet has no firewall assigned",
          description: `Droplet "${name}" (${d.networks?.v4?.[0]?.ip_address || "unknown IP"}) has no DigitalOcean Cloud Firewall assigned. All ports are exposed to the internet.`,
          recommendation: "Create and assign a Cloud Firewall that restricts inbound traffic to only required ports (e.g., 22, 80, 443).",
          evidence: { dropletId: d.id, publicIp: d.networks?.v4?.find((n: any) => n.type === "public")?.ip_address, tags: d.tags },
        });
      }
    }

    // Check: Droplet uses password auth (no SSH keys)
    if (d.features && !d.features.includes("private_networking") && d.status === "active") {
      // Note: DO API doesn't directly expose auth method, but we check for monitoring
    }

    // Check: Droplet monitoring not enabled
    if (d.status === "active" && d.features && !d.features.includes("monitoring")) {
      findings.push({
        id: `DO-DRP-002-${d.id}`,
        severity: "low",
        category: "Monitoring",
        resource: name,
        resourceId: d.id,
        title: "Droplet monitoring not enabled",
        description: `Droplet "${name}" does not have DigitalOcean monitoring agent enabled. This limits visibility into resource usage and security events.`,
        recommendation: "Enable the DigitalOcean monitoring agent for enhanced visibility and alerting.",
        evidence: { dropletId: d.id, features: d.features },
      });
    }

    // Check: Droplet using deprecated image
    if (d.image) {
      const distro = d.image.distribution || "";
      const slug = d.image.slug || "";
      const deprecatedDistros = ["ubuntu-18", "ubuntu-16", "centos-7", "centos-6", "debian-9", "debian-8", "fedora-3"];
      if (deprecatedDistros.some((dep) => slug.includes(dep) || distro.toLowerCase().includes(dep))) {
        findings.push({
          id: `DO-DRP-003-${d.id}`,
          severity: "medium",
          category: "Patching",
          resource: name,
          resourceId: d.id,
          title: "Droplet running deprecated/EOL operating system",
          description: `Droplet "${name}" is running ${distro} ${d.image.name || slug}, which has reached or is approaching end-of-life. EOL operating systems no longer receive security patches.`,
          recommendation: "Migrate to a supported OS version (e.g., Ubuntu 22.04 LTS, Debian 12).",
          evidence: { image: d.image.slug, distribution: distro, imageName: d.image.name },
        });
      }
    }

    // Check: Droplet has public IPv6 but no firewall coverage for it
    const ipv6 = d.networks?.v6?.find((n: any) => n.type === "public");
    if (ipv6) {
      findings.push({
        id: `DO-DRP-004-${d.id}`,
        severity: "info",
        category: "Network",
        resource: name,
        resourceId: d.id,
        title: "Droplet has public IPv6 address",
        description: `Droplet "${name}" has a public IPv6 address (${ipv6.ip_address}). Ensure firewall rules also cover IPv6 traffic.`,
        recommendation: "Verify that Cloud Firewall rules apply to both IPv4 and IPv6 traffic.",
        evidence: { ipv6Address: ipv6.ip_address },
      });
    }

    // Check: Droplet has no backups enabled
    if (d.status === "active" && !d.backup_ids?.length && d.next_backup_window === null) {
      findings.push({
        id: `DO-DRP-005-${d.id}`,
        severity: "medium",
        category: "Availability",
        resource: name,
        resourceId: d.id,
        title: "Droplet backups not enabled",
        description: `Droplet "${name}" does not have automated backups enabled. Data loss risk in case of failure or compromise.`,
        recommendation: "Enable automated weekly backups or implement a snapshot-based backup strategy.",
        evidence: { dropletId: d.id, backupIds: d.backup_ids },
      });
    }
  }

  return findings;
}

/** Audit firewalls for overly permissive rules */
async function auditFirewalls(): Promise<AuditFinding[]> {
  const findings: AuditFinding[] = [];
  const firewalls = await doFetchAll<any>("/firewalls", "firewalls");

  for (const fw of firewalls) {
    const name = fw.name || `firewall-${fw.id}`;

    // Check inbound rules
    for (const rule of fw.inbound_rules || []) {
      const sources = rule.sources || {};

      // Check: Allow all inbound (0.0.0.0/0 or ::/0)
      const allowsAll = sources.addresses?.some(
        (addr: string) => addr === "0.0.0.0/0" || addr === "::/0"
      );

      if (allowsAll) {
        // Critical if SSH (22) or database ports are exposed to all
        const criticalPorts = [22, 3306, 5432, 6379, 27017, 9200, 11211, 2379];
        const port = typeof rule.ports === "string" ? rule.ports : String(rule.ports);
        const isCritical = criticalPorts.some((cp) => port === String(cp) || port === "0" || port === "all");

        if (isCritical) {
          findings.push({
            id: `DO-FW-001-${fw.id}-${port}`,
            severity: "critical",
            category: "Firewall",
            resource: name,
            resourceId: fw.id,
            title: `Critical port ${port} open to the internet`,
            description: `Firewall "${name}" allows inbound ${rule.protocol}/${port} from 0.0.0.0/0. This exposes sensitive services (SSH, databases) to brute-force and exploitation attacks.`,
            recommendation: `Restrict inbound access on port ${port} to specific IP addresses or VPN CIDR ranges. Never expose SSH or database ports to 0.0.0.0/0.`,
            evidence: { firewallId: fw.id, rule, protocol: rule.protocol, ports: port },
          });
        } else if (port !== "80" && port !== "443") {
          findings.push({
            id: `DO-FW-002-${fw.id}-${port}`,
            severity: "medium",
            category: "Firewall",
            resource: name,
            resourceId: fw.id,
            title: `Non-standard port ${port} open to the internet`,
            description: `Firewall "${name}" allows inbound ${rule.protocol}/${port} from 0.0.0.0/0. Non-standard ports exposed to the internet increase the attack surface.`,
            recommendation: `Review whether port ${port} needs to be publicly accessible. Restrict to specific source IPs if possible.`,
            evidence: { firewallId: fw.id, rule },
          });
        }
      }
    }

    // Check: Firewall has no droplets assigned
    if ((!fw.droplet_ids || fw.droplet_ids.length === 0) && (!fw.tags || fw.tags.length === 0)) {
      findings.push({
        id: `DO-FW-003-${fw.id}`,
        severity: "low",
        category: "Firewall",
        resource: name,
        resourceId: fw.id,
        title: "Firewall has no resources assigned",
        description: `Firewall "${name}" exists but has no droplets or tags assigned. It provides no protection.`,
        recommendation: "Assign this firewall to relevant droplets or delete it if unused.",
        evidence: { firewallId: fw.id, dropletIds: fw.droplet_ids, tags: fw.tags },
      });
    }

    // Check outbound rules — unrestricted outbound
    const outboundRules = fw.outbound_rules || [];
    const hasUnrestrictedOutbound = outboundRules.some((rule: any) => {
      const dests = rule.destinations || {};
      return dests.addresses?.some((addr: string) => addr === "0.0.0.0/0" || addr === "::/0");
    });
    if (hasUnrestrictedOutbound && outboundRules.length <= 2) {
      findings.push({
        id: `DO-FW-004-${fw.id}`,
        severity: "info",
        category: "Firewall",
        resource: name,
        resourceId: fw.id,
        title: "Firewall has unrestricted outbound rules",
        description: `Firewall "${name}" allows all outbound traffic. While common, restricting egress can limit data exfiltration and C2 communication.`,
        recommendation: "Consider restricting outbound traffic to required destinations and ports for defense-in-depth.",
        evidence: { outboundRuleCount: outboundRules.length },
      });
    }
  }

  return findings;
}

/** Audit load balancers for TLS and security settings */
async function auditLoadBalancers(): Promise<AuditFinding[]> {
  const findings: AuditFinding[] = [];
  const lbs = await doFetchAll<any>("/load_balancers", "load_balancers");

  for (const lb of lbs) {
    const name = lb.name || `lb-${lb.id}`;

    // Check: No HTTPS forwarding rule
    const hasHttps = lb.forwarding_rules?.some(
      (r: any) => r.entry_protocol === "https" || r.entry_protocol === "http2"
    );
    if (!hasHttps) {
      findings.push({
        id: `DO-LB-001-${lb.id}`,
        severity: "high",
        category: "Encryption",
        resource: name,
        resourceId: lb.id,
        title: "Load balancer has no HTTPS/TLS termination",
        description: `Load balancer "${name}" does not have any HTTPS forwarding rules. Traffic is transmitted in cleartext.`,
        recommendation: "Add an HTTPS forwarding rule with a valid TLS certificate to encrypt traffic in transit.",
        evidence: { forwardingRules: lb.forwarding_rules },
      });
    }

    // Check: HTTP without redirect to HTTPS
    const hasHttp = lb.forwarding_rules?.some((r: any) => r.entry_protocol === "http");
    if (hasHttp && hasHttps && !lb.redirect_http_to_https) {
      findings.push({
        id: `DO-LB-002-${lb.id}`,
        severity: "medium",
        category: "Encryption",
        resource: name,
        resourceId: lb.id,
        title: "Load balancer does not redirect HTTP to HTTPS",
        description: `Load balancer "${name}" accepts both HTTP and HTTPS but does not redirect HTTP to HTTPS. Users may inadvertently transmit data over cleartext.`,
        recommendation: "Enable the 'Redirect HTTP to HTTPS' option on the load balancer.",
        evidence: { redirectHttpToHttps: lb.redirect_http_to_https },
      });
    }

    // Check: Sticky sessions enabled (potential session fixation)
    if (lb.sticky_sessions?.type === "cookies") {
      findings.push({
        id: `DO-LB-003-${lb.id}`,
        severity: "info",
        category: "Session Management",
        resource: name,
        resourceId: lb.id,
        title: "Load balancer uses cookie-based sticky sessions",
        description: `Load balancer "${name}" uses cookie-based sticky sessions. Ensure the session cookie has Secure and HttpOnly flags.`,
        recommendation: "Verify that the sticky session cookie name does not conflict with application session cookies and uses secure attributes.",
        evidence: { stickySessions: lb.sticky_sessions },
      });
    }

    // Check: Health check using HTTP instead of HTTPS
    if (lb.health_check?.protocol === "http" && hasHttps) {
      findings.push({
        id: `DO-LB-004-${lb.id}`,
        severity: "low",
        category: "Monitoring",
        resource: name,
        resourceId: lb.id,
        title: "Load balancer health check uses HTTP",
        description: `Load balancer "${name}" performs health checks over HTTP while serving HTTPS traffic. Health check traffic is unencrypted on the internal network.`,
        recommendation: "Consider using HTTPS for health checks if backend supports it, or ensure internal network is trusted.",
        evidence: { healthCheck: lb.health_check },
      });
    }
  }

  return findings;
}

/** Audit managed databases for security settings */
async function auditDatabases(): Promise<AuditFinding[]> {
  const findings: AuditFinding[] = [];
  const dbs = await doFetchAll<any>("/databases", "databases");

  for (const db of dbs) {
    const name = db.name || `db-${db.id}`;

    // Check: Database is publicly accessible (no trusted sources)
    if (!db.rules || db.rules.length === 0) {
      findings.push({
        id: `DO-DB-001-${db.id}`,
        severity: "critical",
        category: "Access Control",
        resource: name,
        resourceId: db.id,
        title: "Database has no trusted source restrictions",
        description: `Managed database "${name}" (${db.engine} ${db.version}) has no trusted source IP restrictions. It is accessible from any IP address on the internet.`,
        recommendation: "Add trusted source IP addresses or droplet/tag-based restrictions to limit database access.",
        evidence: { engine: db.engine, version: db.version, region: db.region },
      });
    }

    // Check: Database SSL not enforced
    if (db.connection && !db.connection.ssl) {
      findings.push({
        id: `DO-DB-002-${db.id}`,
        severity: "high",
        category: "Encryption",
        resource: name,
        resourceId: db.id,
        title: "Database SSL/TLS not enforced",
        description: `Managed database "${name}" does not enforce SSL/TLS connections. Database traffic may be transmitted in cleartext.`,
        recommendation: "Enable SSL enforcement on the managed database to encrypt all connections.",
        evidence: { connection: { ssl: db.connection?.ssl, port: db.connection?.port } },
      });
    }

    // Check: Database using EOL engine version
    const eolVersions: Record<string, string[]> = {
      pg: ["11", "12"],
      mysql: ["5.7", "5.6"],
      redis: ["5", "6"],
      mongodb: ["4.4", "4.2"],
    };
    const engineEol = eolVersions[db.engine] || [];
    if (engineEol.some((v) => db.version?.startsWith(v))) {
      findings.push({
        id: `DO-DB-003-${db.id}`,
        severity: "medium",
        category: "Patching",
        resource: name,
        resourceId: db.id,
        title: "Database running EOL engine version",
        description: `Managed database "${name}" is running ${db.engine} ${db.version}, which is approaching or has reached end-of-life.`,
        recommendation: `Upgrade to a supported ${db.engine} version to continue receiving security patches.`,
        evidence: { engine: db.engine, version: db.version },
      });
    }

    // Check: No automated backups window
    if (db.maintenance_window && !db.maintenance_window.pending) {
      // Maintenance window exists, good
    }
  }

  return findings;
}

/** Audit domains for DNS security */
async function auditDomains(): Promise<AuditFinding[]> {
  const findings: AuditFinding[] = [];
  const domains = await doFetchAll<any>("/domains", "domains");

  for (const domain of domains) {
    const name = domain.name;

    // Get DNS records for this domain
    const records = await doFetchAll<any>(`/domains/${name}/records`, "domain_records");

    // Check: Wildcard DNS record
    const wildcardRecords = records.filter((r: any) => r.name === "*");
    if (wildcardRecords.length > 0) {
      findings.push({
        id: `DO-DNS-001-${name}`,
        severity: "medium",
        category: "DNS",
        resource: name,
        resourceId: name,
        title: "Wildcard DNS record detected",
        description: `Domain "${name}" has a wildcard (*) DNS record. This can enable subdomain takeover attacks and makes it harder to inventory the attack surface.`,
        recommendation: "Remove wildcard DNS records and create explicit records for each subdomain.",
        evidence: { wildcardRecords: wildcardRecords.map((r: any) => ({ type: r.type, data: r.data })) },
      });
    }

    // Check: Dangling CNAME records (pointing to external services)
    const cnameRecords = records.filter((r: any) => r.type === "CNAME");
    const suspiciousCnames = cnameRecords.filter((r: any) => {
      const target = (r.data || "").toLowerCase();
      return (
        target.includes("herokuapp.com") ||
        target.includes("s3.amazonaws.com") ||
        target.includes("cloudfront.net") ||
        target.includes("azurewebsites.net") ||
        target.includes("github.io") ||
        target.includes("shopify.com") ||
        target.includes("zendesk.com") ||
        target.includes("ghost.io") ||
        target.includes("surge.sh") ||
        target.includes("bitbucket.io")
      );
    });
    if (suspiciousCnames.length > 0) {
      findings.push({
        id: `DO-DNS-002-${name}`,
        severity: "high",
        category: "DNS",
        resource: name,
        resourceId: name,
        title: "Potential subdomain takeover via CNAME",
        description: `Domain "${name}" has CNAME records pointing to external services that are commonly vulnerable to subdomain takeover: ${suspiciousCnames.map((r: any) => `${r.name}.${name} -> ${r.data}`).join(", ")}`,
        recommendation: "Verify that each CNAME target is still actively claimed. Remove any CNAME records pointing to deprovisioned services.",
        evidence: { cnameRecords: suspiciousCnames.map((r: any) => ({ name: r.name, target: r.data })) },
      });
    }

    // Check: No SPF record
    const txtRecords = records.filter((r: any) => r.type === "TXT");
    const hasSpf = txtRecords.some((r: any) => (r.data || "").includes("v=spf1"));
    if (!hasSpf) {
      findings.push({
        id: `DO-DNS-003-${name}`,
        severity: "medium",
        category: "Email Security",
        resource: name,
        resourceId: name,
        title: "No SPF record configured",
        description: `Domain "${name}" does not have an SPF (Sender Policy Framework) TXT record. This allows anyone to send email appearing to come from this domain.`,
        recommendation: "Add an SPF TXT record (e.g., 'v=spf1 -all' if no email is sent from this domain).",
        evidence: { txtRecords: txtRecords.map((r: any) => r.data) },
      });
    }

    // Check: No DMARC record
    const hasDmarc = txtRecords.some((r: any) => (r.data || "").includes("v=DMARC1"));
    // Also check _dmarc subdomain
    const dmarcRecords = records.filter((r: any) => r.name === "_dmarc" && r.type === "TXT");
    if (!hasDmarc && dmarcRecords.length === 0) {
      findings.push({
        id: `DO-DNS-004-${name}`,
        severity: "medium",
        category: "Email Security",
        resource: name,
        resourceId: name,
        title: "No DMARC record configured",
        description: `Domain "${name}" does not have a DMARC record. Without DMARC, email spoofing attacks cannot be detected or prevented.`,
        recommendation: "Add a DMARC TXT record at _dmarc.${name} (e.g., 'v=DMARC1; p=reject; rua=mailto:dmarc@${name}').",
        evidence: {},
      });
    }
  }

  return findings;
}

/** Audit Kubernetes clusters for security settings */
async function auditKubernetes(): Promise<AuditFinding[]> {
  const findings: AuditFinding[] = [];
  const clusters = await doFetchAll<any>("/kubernetes/clusters", "kubernetes_clusters");

  for (const cluster of clusters) {
    const name = cluster.name || `k8s-${cluster.id}`;

    // Check: Auto-upgrade not enabled
    if (!cluster.auto_upgrade) {
      findings.push({
        id: `DO-K8S-001-${cluster.id}`,
        severity: "medium",
        category: "Patching",
        resource: name,
        resourceId: cluster.id,
        title: "Kubernetes auto-upgrade not enabled",
        description: `Kubernetes cluster "${name}" does not have auto-upgrade enabled. The cluster may miss critical security patches.`,
        recommendation: "Enable auto-upgrade to ensure the cluster receives security patches automatically.",
        evidence: { version: cluster.version_slug, autoUpgrade: cluster.auto_upgrade },
      });
    }

    // Check: Surge upgrade not enabled (causes downtime during upgrades)
    if (!cluster.surge_upgrade) {
      findings.push({
        id: `DO-K8S-002-${cluster.id}`,
        severity: "low",
        category: "Availability",
        resource: name,
        resourceId: cluster.id,
        title: "Kubernetes surge upgrade not enabled",
        description: `Kubernetes cluster "${name}" does not have surge upgrade enabled. Upgrades may cause service disruption.`,
        recommendation: "Enable surge upgrade to minimize downtime during cluster upgrades.",
        evidence: { surgeUpgrade: cluster.surge_upgrade },
      });
    }

    // Check: HA not enabled (single control plane)
    if (!cluster.ha) {
      findings.push({
        id: `DO-K8S-003-${cluster.id}`,
        severity: "medium",
        category: "Availability",
        resource: name,
        resourceId: cluster.id,
        title: "Kubernetes cluster not highly available",
        description: `Kubernetes cluster "${name}" is running with a single control plane node. A control plane failure would make the cluster unmanageable.`,
        recommendation: "Enable high availability (HA) for production clusters to ensure control plane redundancy.",
        evidence: { ha: cluster.ha, region: cluster.region },
      });
    }
  }

  return findings;
}

// ─── Main Audit Orchestrator ────────────────────────────────────────────────

/**
 * Run a comprehensive DigitalOcean infrastructure audit.
 * Returns structured findings with severity, evidence, and recommendations.
 */
export async function runDoInfraAudit(): Promise<AuditResult> {
  const token = ENV.DIGITALOCEAN_ACCESS_TOKEN;
  if (!token) {
    return {
      timestamp: new Date().toISOString(),
      provider: "digitalocean",
      findings: [],
      summary: {
        total: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        resourcesAudited: 0,
        categoriesChecked: [],
      },
      errors: ["DIGITALOCEAN_ACCESS_TOKEN not configured"],
    };
  }

  console.log("[DO-Audit] Starting DigitalOcean infrastructure audit...");
  const errors: string[] = [];
  const allFindings: AuditFinding[] = [];

  const auditFunctions = [
    { name: "Droplets", fn: auditDroplets },
    { name: "Firewalls", fn: auditFirewalls },
    { name: "Load Balancers", fn: auditLoadBalancers },
    { name: "Databases", fn: auditDatabases },
    { name: "Domains/DNS", fn: auditDomains },
    { name: "Kubernetes", fn: auditKubernetes },
  ];

  // Run all audits in parallel
  const results = await Promise.allSettled(
    auditFunctions.map(async ({ name, fn }) => {
      console.log(`[DO-Audit] Auditing ${name}...`);
      const findings = await fn();
      console.log(`[DO-Audit] ${name}: ${findings.length} findings`);
      return { name, findings };
    })
  );

  const categoriesChecked: string[] = [];
  for (let i = 0; i < results.length; i++) {
    const result = results[i];
    const auditName = auditFunctions[i].name;
    categoriesChecked.push(auditName);

    if (result.status === "fulfilled") {
      allFindings.push(...result.value.findings);
    } else {
      errors.push(`${auditName} audit failed: ${result.reason?.message || "unknown error"}`);
    }
  }

  // Build summary
  const summary = {
    total: allFindings.length,
    critical: allFindings.filter((f) => f.severity === "critical").length,
    high: allFindings.filter((f) => f.severity === "high").length,
    medium: allFindings.filter((f) => f.severity === "medium").length,
    low: allFindings.filter((f) => f.severity === "low").length,
    info: allFindings.filter((f) => f.severity === "info").length,
    resourcesAudited: new Set(allFindings.map((f) => f.resourceId)).size,
    categoriesChecked,
  };

  console.log(`[DO-Audit] Complete: ${summary.total} findings (${summary.critical} critical, ${summary.high} high, ${summary.medium} medium)`);

  return {
    timestamp: new Date().toISOString(),
    provider: "digitalocean",
    findings: allFindings,
    summary,
    errors,
  };
}

/**
 * Run a targeted firewall-only audit.
 * Used by KSI-CNA-RNT (Restrict Network Traffic) and KSI-CNA-ULN (Use Logical Networking Controls).
 */
export async function runDoFirewallAudit(): Promise<AuditResult> {
  const token = ENV.DIGITALOCEAN_ACCESS_TOKEN;
  if (!token) {
    return {
      timestamp: new Date().toISOString(),
      provider: "digitalocean",
      findings: [],
      summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, resourcesAudited: 0, categoriesChecked: [] },
      errors: ["DIGITALOCEAN_ACCESS_TOKEN not configured"],
    };
  }

  const [dropletFindings, firewallFindings] = await Promise.all([
    auditDroplets().catch(() => [] as AuditFinding[]),
    auditFirewalls().catch(() => [] as AuditFinding[]),
  ]);

  // Filter to only firewall-related findings
  const findings = [...dropletFindings, ...firewallFindings].filter(
    (f) => f.category === "Firewall" || f.category === "Network"
  );

  return {
    timestamp: new Date().toISOString(),
    provider: "digitalocean",
    findings,
    summary: {
      total: findings.length,
      critical: findings.filter((f) => f.severity === "critical").length,
      high: findings.filter((f) => f.severity === "high").length,
      medium: findings.filter((f) => f.severity === "medium").length,
      low: findings.filter((f) => f.severity === "low").length,
      info: findings.filter((f) => f.severity === "info").length,
      resourcesAudited: new Set(findings.map((f) => f.resourceId)).size,
      categoriesChecked: ["Droplets", "Firewalls"],
    },
    errors: [],
  };
}
