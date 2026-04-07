/**
 * Service-to-Template Mapper
 *
 * Maps fingerprinted service identities (protocol, product, version) to
 * nuclei template tags and severity filters. This enables targeted
 * vulnerability scanning — only running MySQL templates against MySQL
 * ports, SSH templates against SSH ports, etc.
 *
 * Three mapping tiers:
 *   1. Protocol-based  → broad category (e.g., ssh → ssh,openssh)
 *   2. Product-based   → specific product (e.g., OpenSSH → openssh)
 *   3. Version-based   → version-specific CVE tags (e.g., OpenSSH 7.x → cve-2018-15473)
 *
 * Also generates per-port nuclei scan commands so the orchestrator can
 * run service-specific scans alongside the existing web-focused scans.
 */

import type { FingerprintResult, ServiceProtocol } from "./service-fingerprinter";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface TemplateMapping {
  /** Nuclei template tags to include */
  tags: string[];
  /** Additional severity levels to scan (beyond the default) */
  extraSeverities?: string[];
  /** Specific template IDs to run (for version-matched CVEs) */
  specificTemplates?: string[];
  /** Whether to run network-level templates (not just HTTP) */
  networkScan: boolean;
  /** Scan priority (1=highest, 5=lowest) */
  priority: number;
  /** Human-readable reason for this mapping */
  rationale: string;
}

export interface ServiceScanTask {
  host: string;
  port: number;
  protocol: ServiceProtocol | string;
  product: string | null;
  version: string | null;
  mapping: TemplateMapping;
  /** Pre-built nuclei args for this service */
  nucleiArgs: string;
}

// ─── Protocol → Tag Mapping ─────────────────────────────────────────────────

const PROTOCOL_TAG_MAP: Record<string, TemplateMapping> = {
  ssh: {
    tags: ["ssh", "openssh", "network", "default-login"],
    networkScan: true,
    priority: 2,
    rationale: "SSH service detected — scan for weak configs, default creds, known CVEs",
  },
  ftp: {
    tags: ["ftp", "network", "default-login", "anonymous"],
    networkScan: true,
    priority: 2,
    rationale: "FTP service detected — check anonymous access, weak creds, known vulns",
  },
  smtp: {
    tags: ["smtp", "mail", "network"],
    networkScan: true,
    priority: 3,
    rationale: "SMTP service detected — check open relay, auth bypass, version vulns",
  },
  mysql: {
    tags: ["mysql", "database", "default-login", "network"],
    networkScan: true,
    priority: 1,
    rationale: "MySQL service detected — check default creds, exposed management, CVEs",
  },
  mssql: {
    tags: ["mssql", "database", "default-login", "network"],
    networkScan: true,
    priority: 1,
    rationale: "MSSQL service detected — check default creds, xp_cmdshell, CVEs",
  },
  postgresql: {
    tags: ["postgres", "postgresql", "database", "default-login", "network"],
    networkScan: true,
    priority: 1,
    rationale: "PostgreSQL service detected — check default creds, trust auth, CVEs",
  },
  redis: {
    tags: ["redis", "database", "network", "unauth"],
    networkScan: true,
    priority: 1,
    rationale: "Redis service detected — check unauthenticated access, RCE via SLAVEOF",
  },
  mongodb: {
    tags: ["mongodb", "database", "network", "unauth"],
    networkScan: true,
    priority: 1,
    rationale: "MongoDB service detected — check unauthenticated access, exposed management",
  },
  rdp: {
    tags: ["rdp", "network", "default-login"],
    networkScan: true,
    priority: 2,
    rationale: "RDP service detected — check BlueKeep, NLA bypass, weak creds",
  },
  smb: {
    tags: ["smb", "network", "default-login", "eternalblue"],
    networkScan: true,
    priority: 1,
    rationale: "SMB service detected — check EternalBlue, null sessions, shares",
  },
  ldap: {
    tags: ["ldap", "network", "default-login"],
    networkScan: true,
    priority: 2,
    rationale: "LDAP service detected — check anonymous bind, info disclosure",
  },
  snmp: {
    tags: ["snmp", "network"],
    networkScan: true,
    priority: 3,
    rationale: "SNMP service detected — check default community strings, info leak",
  },
  vnc: {
    tags: ["vnc", "network", "default-login"],
    networkScan: true,
    priority: 2,
    rationale: "VNC service detected — check no-auth, weak passwords",
  },
  telnet: {
    tags: ["telnet", "network", "default-login"],
    networkScan: true,
    priority: 2,
    rationale: "Telnet service detected — check default creds, cleartext auth",
  },
  dns: {
    tags: ["dns", "network"],
    networkScan: true,
    priority: 3,
    rationale: "DNS service detected — check zone transfer, cache poisoning",
  },
  pop3: {
    tags: ["pop3", "mail", "network"],
    networkScan: true,
    priority: 3,
    rationale: "POP3 service detected — check cleartext auth, known vulns",
  },
  imap: {
    tags: ["imap", "mail", "network"],
    networkScan: true,
    priority: 3,
    rationale: "IMAP service detected — check cleartext auth, known vulns",
  },
};

// ─── Product → Tag Augmentation ─────────────────────────────────────────────

interface ProductMapping {
  /** Regex to match product name (case-insensitive) */
  pattern: RegExp;
  /** Additional tags to add */
  tags: string[];
  /** Boost priority by this amount (negative = higher priority) */
  priorityBoost: number;
}

const PRODUCT_MAPPINGS: ProductMapping[] = [
  // SSH products
  { pattern: /openssh/i, tags: ["openssh"], priorityBoost: 0 },
  { pattern: /dropbear/i, tags: ["dropbear", "iot"], priorityBoost: -1 },
  { pattern: /libssh/i, tags: ["libssh"], priorityBoost: -1 },

  // Web servers (in case fingerprinted on non-standard ports)
  { pattern: /nginx/i, tags: ["nginx"], priorityBoost: 0 },
  { pattern: /apache/i, tags: ["apache"], priorityBoost: 0 },
  { pattern: /iis/i, tags: ["iis", "microsoft"], priorityBoost: 0 },
  { pattern: /lighttpd/i, tags: ["lighttpd"], priorityBoost: 0 },
  { pattern: /tomcat/i, tags: ["tomcat", "java"], priorityBoost: -1 },

  // Databases
  { pattern: /mariadb/i, tags: ["mariadb", "mysql"], priorityBoost: 0 },
  { pattern: /percona/i, tags: ["percona", "mysql"], priorityBoost: 0 },
  { pattern: /cockroachdb/i, tags: ["cockroachdb"], priorityBoost: 0 },

  // Message queues
  { pattern: /rabbitmq/i, tags: ["rabbitmq", "default-login"], priorityBoost: -1 },
  { pattern: /kafka/i, tags: ["kafka"], priorityBoost: 0 },
  { pattern: /activemq/i, tags: ["activemq", "default-login"], priorityBoost: -1 },

  // Monitoring/management
  { pattern: /elasticsearch/i, tags: ["elasticsearch", "elastic", "unauth"], priorityBoost: -1 },
  { pattern: /kibana/i, tags: ["kibana", "elastic"], priorityBoost: -1 },
  { pattern: /grafana/i, tags: ["grafana", "default-login"], priorityBoost: -1 },
  { pattern: /prometheus/i, tags: ["prometheus", "unauth"], priorityBoost: -1 },
  { pattern: /consul/i, tags: ["consul", "hashicorp"], priorityBoost: -1 },
  { pattern: /vault/i, tags: ["vault", "hashicorp"], priorityBoost: -1 },
  { pattern: /etcd/i, tags: ["etcd", "unauth"], priorityBoost: -1 },
  { pattern: /zookeeper/i, tags: ["zookeeper"], priorityBoost: 0 },

  // Container/orchestration
  { pattern: /docker/i, tags: ["docker", "container"], priorityBoost: -1 },
  { pattern: /kubernetes|k8s/i, tags: ["kubernetes", "k8s"], priorityBoost: -1 },

  // CI/CD
  { pattern: /jenkins/i, tags: ["jenkins", "default-login"], priorityBoost: -1 },
  { pattern: /gitlab/i, tags: ["gitlab"], priorityBoost: -1 },
  { pattern: /sonarqube/i, tags: ["sonarqube", "default-login"], priorityBoost: -1 },

  // Misc
  { pattern: /memcached/i, tags: ["memcached", "unauth"], priorityBoost: -1 },
  { pattern: /couchdb/i, tags: ["couchdb", "default-login"], priorityBoost: -1 },
  { pattern: /cassandra/i, tags: ["cassandra"], priorityBoost: 0 },
  { pattern: /proftpd/i, tags: ["proftpd"], priorityBoost: 0 },
  { pattern: /vsftpd/i, tags: ["vsftpd"], priorityBoost: 0 },
  { pattern: /pure-ftpd/i, tags: ["pureftpd"], priorityBoost: 0 },
  { pattern: /postfix/i, tags: ["postfix"], priorityBoost: 0 },
  { pattern: /exim/i, tags: ["exim"], priorityBoost: -1 },
  { pattern: /sendmail/i, tags: ["sendmail"], priorityBoost: 0 },
  { pattern: /dovecot/i, tags: ["dovecot"], priorityBoost: 0 },
];

// ─── Version → CVE Tag Mapping ──────────────────────────────────────────────

interface VersionCveMapping {
  product: RegExp;
  versionRange: { min?: string; max?: string };
  cves: string[];
  tags: string[];
}

const VERSION_CVE_MAPPINGS: VersionCveMapping[] = [
  // OpenSSH user enumeration
  {
    product: /openssh/i,
    versionRange: { min: "2.3", max: "7.7" },
    cves: ["CVE-2018-15473"],
    tags: ["cve-2018-15473"],
  },
  // OpenSSH regreSSHion
  {
    product: /openssh/i,
    versionRange: { min: "8.5", max: "9.7" },
    cves: ["CVE-2024-6387"],
    tags: ["cve-2024-6387", "regresshion"],
  },
  // ProFTPD RCE
  {
    product: /proftpd/i,
    versionRange: { min: "1.3.0", max: "1.3.5" },
    cves: ["CVE-2015-3306"],
    tags: ["cve-2015-3306"],
  },
  // vsftpd backdoor
  {
    product: /vsftpd/i,
    versionRange: { min: "2.3.4", max: "2.3.4" },
    cves: ["CVE-2011-2523"],
    tags: ["cve-2011-2523"],
  },
  // Redis unauthenticated RCE
  {
    product: /redis/i,
    versionRange: { min: "2.0", max: "5.0.5" },
    cves: ["CVE-2022-0543"],
    tags: ["cve-2022-0543"],
  },
  // Exim RCE
  {
    product: /exim/i,
    versionRange: { min: "4.87", max: "4.91" },
    cves: ["CVE-2019-10149"],
    tags: ["cve-2019-10149"],
  },
  // SMB EternalBlue
  {
    product: /samba|smb/i,
    versionRange: { min: "1.0", max: "3.5.22" },
    cves: ["CVE-2017-7494"],
    tags: ["cve-2017-7494", "sambacry"],
  },
  // Elasticsearch RCE
  {
    product: /elasticsearch/i,
    versionRange: { min: "1.0", max: "1.4.2" },
    cves: ["CVE-2015-1427"],
    tags: ["cve-2015-1427"],
  },
  // MongoDB unauthenticated
  {
    product: /mongodb/i,
    versionRange: { min: "2.0", max: "3.6" },
    cves: [],
    tags: ["mongodb-unauth"],
  },
];

// ─── Core Mapping Functions ─────────────────────────────────────────────────

/**
 * Compare semver-like version strings. Returns:
 *  -1 if a < b, 0 if a == b, 1 if a > b
 */
function compareVersions(a: string, b: string): number {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const na = pa[i] || 0;
    const nb = pb[i] || 0;
    if (na < nb) return -1;
    if (na > nb) return 1;
  }
  return 0;
}

function isVersionInRange(version: string, range: { min?: string; max?: string }): boolean {
  // Extract numeric version from strings like "8.9p1" or "5.0.5-ubuntu1"
  const numericVersion = version.match(/^[\d.]+/)?.[0];
  if (!numericVersion) return false;

  if (range.min && compareVersions(numericVersion, range.min) < 0) return false;
  if (range.max && compareVersions(numericVersion, range.max) > 0) return false;
  return true;
}

/**
 * Map a single fingerprint result to nuclei template tags.
 */
export function mapServiceToTemplates(fp: FingerprintResult): TemplateMapping {
  // Start with protocol-level mapping
  const baseMapping = PROTOCOL_TAG_MAP[fp.protocol] || {
    tags: ["network"],
    networkScan: true,
    priority: 3,
    rationale: `Unknown protocol ${fp.protocol} — running broad network scan`,
  };

  const tags = [...baseMapping.tags];
  let priority = baseMapping.priority;
  const specificTemplates: string[] = [];
  const rationale: string[] = [baseMapping.rationale];

  // Augment with product-specific tags
  if (fp.product) {
    for (const pm of PRODUCT_MAPPINGS) {
      if (pm.pattern.test(fp.product)) {
        for (const tag of pm.tags) {
          if (!tags.includes(tag)) tags.push(tag);
        }
        priority = Math.max(1, priority + pm.priorityBoost);
        rationale.push(`Product match: ${fp.product}`);
        break; // First match wins
      }
    }
  }

  // Check version-specific CVE mappings
  if (fp.product && fp.version) {
    for (const vcm of VERSION_CVE_MAPPINGS) {
      if (vcm.product.test(fp.product) && isVersionInRange(fp.version, vcm.versionRange)) {
        for (const tag of vcm.tags) {
          if (!tags.includes(tag)) tags.push(tag);
        }
        specificTemplates.push(...vcm.cves);
        priority = 1; // Version-matched CVEs are highest priority
        rationale.push(`Version-matched CVEs: ${vcm.cves.join(", ") || "known vulnerable range"}`);
      }
    }
  }

  // Boost priority for services with security flags
  if (fp.securityFlags) {
    if (fp.securityFlags.anonymousAccess) {
      if (!tags.includes("unauth")) tags.push("unauth");
      priority = 1;
      rationale.push("Anonymous access detected");
    }
    if (fp.securityFlags.defaultCredentials) {
      if (!tags.includes("default-login")) tags.push("default-login");
      priority = 1;
      rationale.push("Default credentials detected");
    }
    if (!fp.securityFlags.tlsSupported && !fp.securityFlags.encryptionEnabled) {
      rationale.push("No encryption — cleartext protocol");
    }
  }

  // Add CVE tag if we have potential CVEs from fingerprinting
  if (fp.potentialCves && fp.potentialCves.length > 0) {
    if (!tags.includes("cve")) tags.push("cve");
    specificTemplates.push(...fp.potentialCves);
    priority = 1;
    rationale.push(`Fingerprint-detected CVEs: ${fp.potentialCves.slice(0, 5).join(", ")}`);
  }

  return {
    tags: [...new Set(tags)], // Deduplicate
    networkScan: baseMapping.networkScan,
    priority,
    rationale: rationale.join(" | "),
    specificTemplates: specificTemplates.length > 0 ? [...new Set(specificTemplates)] : undefined,
  };
}

/**
 * Generate service-specific nuclei scan tasks from fingerprint results.
 * These run alongside the existing web-focused scans.
 */
export function generateServiceScanTasks(
  host: string,
  fingerprintResults: FingerprintResult[],
  options?: {
    rateLimit?: number;
    evasionHeaders?: string;
    maxTasks?: number;
  },
): ServiceScanTask[] {
  const rateLimit = options?.rateLimit || 100;
  const evasionHeaders = options?.evasionHeaders || "";
  const maxTasks = options?.maxTasks || 20;

  const tasks: ServiceScanTask[] = [];

  for (const fp of fingerprintResults) {
    if (fp.error) continue; // Skip failed probes

    const mapping = mapServiceToTemplates(fp);

    // Build nuclei args for this service
    const tagArgs = mapping.tags.length > 0 ? `-tags ${mapping.tags.join(",")}` : "";
    const severityArg = "-severity critical,high,medium";
    const target = `${host}:${fp.port}`;
    const nucleiArgs = `-target ${target} ${severityArg} ${tagArgs} -jsonl -nc -duc -ni -timeout 10 -retries 1 -rate-limit ${rateLimit}${evasionHeaders}`;

    tasks.push({
      host,
      port: fp.port,
      protocol: fp.protocol,
      product: fp.product,
      version: fp.version,
      mapping,
      nucleiArgs,
    });
  }

  // Sort by priority (1=highest) and limit
  tasks.sort((a, b) => a.mapping.priority - b.mapping.priority);
  return tasks.slice(0, maxTasks);
}

/**
 * Extract service-based nuclei tags from fingerprint results to augment
 * the existing technology-based tag list in the orchestrator.
 *
 * This is the primary integration point — call this alongside the existing
 * httpx tech-to-tag mapping to add service-aware tags.
 */
export function getServiceBasedTags(
  fingerprintResults: FingerprintResult[] | undefined,
): { tags: string[]; rationale: string[] } {
  if (!fingerprintResults || fingerprintResults.length === 0) {
    return { tags: [], rationale: [] };
  }

  const allTags = new Set<string>();
  const rationale: string[] = [];

  for (const fp of fingerprintResults) {
    if (fp.error) continue;
    const mapping = mapServiceToTemplates(fp);
    for (const tag of mapping.tags) {
      allTags.add(tag);
    }
    if (fp.product || fp.version) {
      rationale.push(
        `${fp.port}/${fp.protocol}: ${fp.product || "unknown"} ${fp.version || ""}`.trim(),
      );
    }
  }

  return {
    tags: [...allTags],
    rationale,
  };
}

/**
 * Get a summary of service-to-template mappings for logging.
 */
export function getTemplateMappingSummary(
  fingerprintResults: FingerprintResult[],
): {
  totalMapped: number;
  highPriority: number;
  uniqueTags: string[];
  versionMatchedCves: string[];
  serviceBreakdown: Array<{ port: number; protocol: string; product: string | null; tags: string[]; priority: number }>;
} {
  const serviceBreakdown: Array<{ port: number; protocol: string; product: string | null; tags: string[]; priority: number }> = [];
  const allTags = new Set<string>();
  const allCves: string[] = [];
  let highPriority = 0;

  for (const fp of fingerprintResults) {
    if (fp.error) continue;
    const mapping = mapServiceToTemplates(fp);
    serviceBreakdown.push({
      port: fp.port,
      protocol: fp.protocol,
      product: fp.product,
      tags: mapping.tags,
      priority: mapping.priority,
    });
    for (const tag of mapping.tags) allTags.add(tag);
    if (mapping.specificTemplates) allCves.push(...mapping.specificTemplates);
    if (mapping.priority === 1) highPriority++;
  }

  return {
    totalMapped: serviceBreakdown.length,
    highPriority,
    uniqueTags: [...allTags],
    versionMatchedCves: [...new Set(allCves)],
    serviceBreakdown,
  };
}
