/**
 * Signal Classifier — Risk Signal Detection Engine
 * 
 * Analyzes AssetObservations for risk signals using regex-based pattern matching
 * and heuristic rules. Produces typed RiskSignal objects with severity and confidence.
 * 
 * Signal Categories:
 * - Exposed admin/management interfaces
 * - Default credentials / known-vulnerable services
 * - Expired or misconfigured TLS certificates
 * - Sensitive data exposure (API keys, tokens in URLs)
 * - Historical attack surface (forgotten staging/dev environments)
 * - Missing security headers (SPF, DMARC, DNSSEC)
 * - Open database/cache ports
 */

import { createHash } from "crypto";
import type { AssetObservation, RiskSignal, SignalSeverity } from "./types";
import { getNistControlsForSignal, calculateFedrampDeadline } from "../nist-control-mapper";

interface SignalRule {
  id: string;
  name: string;
  severity: SignalSeverity;
  confidence: number;
  match: (obs: AssetObservation) => boolean;
  rationale: (obs: AssetObservation) => string;
  /** Optional: extract credential evidence from the observation for UI display */
  credentialEvidence?: (obs: AssetObservation) => RiskSignal['credentialEvidence'];
}

const SIGNAL_RULES: SignalRule[] = [
  // ─── Exposed Admin Interfaces ──────────────────────────────────
  {
    id: "admin_panel_exposed",
    name: "Exposed Admin/Management Interface",
    severity: "high",
    confidence: 0.85,
    match: (obs) => {
      // Only match if the observation is already tagged as admin_path (by wayback/commoncrawl)
      // OR if it's a port/service observation with admin-specific product names
      if (obs.tags.includes("admin_path")) return true;
      // For non-URL observations (service banners, port scans), check product names
      if (obs.assetType === "service" || obs.assetType === "port") {
        const name = (obs.name || "").toLowerCase();
        return /cpanel|phpmyadmin|webmin|cockpit|adminer|tomcat.*manager/i.test(name);
      }
      // For URL observations, use path-segment matching (not broad regex on full URL)
      if (obs.assetType === "url" && obs.name) {
        try {
          const url = obs.name.startsWith("http") ? obs.name : `https://${obs.name}`;
          const path = new URL(url).pathname.toLowerCase();
          const segments = path.split("/").filter(Boolean);
          const ADMIN_SEGMENTS = [
            "admin", "administrator", "wp-admin", "wp-login",
            "console", "mgmt", "cpanel", "phpmyadmin", "webmin",
            "cockpit", "adminer", "_admin",
          ];
          return segments.some(seg => ADMIN_SEGMENTS.includes(seg.replace(/\.(php|asp|aspx|jsp|html|htm)$/i, "")));
        } catch { return false; }
      }
      return false;
    },
    rationale: (obs) => `Admin/management interface detected at ${obs.name}. These interfaces are high-value targets for attackers and should not be publicly accessible.`,
  },

  // ─── Open Database Ports ───────────────────────────────────────
  {
    id: "open_db_port",
    name: "Open Database/Cache Port",
    severity: "critical",
    confidence: 0.9,
    match: (obs) => {
      const portTag = obs.tags.find(t => t.startsWith("port:"));
      if (!portTag) return false;
      const port = parseInt(portTag.split(":")[1], 10);
      return [3306, 5432, 27017, 6379, 9200, 11211, 5984, 8529].includes(port);
    },
    rationale: (obs) => {
      const portTag = obs.tags.find(t => t.startsWith("port:"))!;
      const portMap: Record<string, string> = {
        "3306": "MySQL", "5432": "PostgreSQL", "27017": "MongoDB",
        "6379": "Redis", "9200": "Elasticsearch", "11211": "Memcached",
        "5984": "CouchDB", "8529": "ArangoDB",
      };
      const port = portTag.split(":")[1];
      return `Open ${portMap[port] || "database"} port (${port}) detected on ${obs.ip || obs.name}. Database ports should never be directly exposed to the internet.`;
    },
  },

  // ─── Expired TLS Certificates ──────────────────────────────────
  {
    id: "expired_cert",
    name: "Expired TLS Certificate",
    severity: "medium",
    confidence: 0.95,
    match: (obs) => {
      const notAfter = obs.evidence?.not_after;
      if (!notAfter) return false;
      return new Date(notAfter) < new Date();
    },
    rationale: (obs) => `TLS certificate for ${obs.name} expired on ${obs.evidence.not_after}. Expired certificates cause browser warnings and may indicate abandoned infrastructure.`,
  },

  // ─── Staging/Dev Environments ──────────────────────────────────
  {
    id: "staging_env_exposed",
    name: "Exposed Staging/Development Environment",
    severity: "high",
    confidence: 0.75,
    match: (obs) => {
      const name = (obs.name || "").toLowerCase();
      return /^(dev|test|staging|stage|qa|uat|sandbox|demo|beta|preview)\./i.test(name) ||
             obs.tags.includes("staging_path");
    },
    rationale: (obs) => `Staging/development environment detected at ${obs.name}. These environments often have weaker security controls and may contain sensitive test data.`,
  },

  // ─── API Endpoints ─────────────────────────────────────────────
  {
    id: "api_endpoint_exposed",
    name: "Exposed API Endpoint",
    severity: "medium",
    confidence: 0.7,
    match: (obs) => {
      const name = (obs.name || "").toLowerCase();
      return /api\.|graphql|swagger|openapi|\/api\/|\/v[0-9]+\//i.test(name) ||
             obs.tags.includes("api_path");
    },
    rationale: (obs) => `API endpoint detected at ${obs.name}. Exposed API endpoints should be reviewed for proper authentication and rate limiting.`,
  },

  // ─── Sensitive Data in URLs ────────────────────────────────────
  {
    id: "sensitive_data_url",
    name: "Potential Sensitive Data in URL",
    severity: "high",
    confidence: 0.6,
    match: (obs) => {
      if (obs.assetType !== "url") return false;
      const name = (obs.name || "").toLowerCase();
      return /[?&](api_key|apikey|token|secret|password|passwd|auth|access_token|private_key)=/i.test(name);
    },
    rationale: (obs) => `URL contains potential sensitive data (API key, token, or credential) in query parameters: ${obs.name?.substring(0, 100)}...`,
  },

  // ─── Missing SPF Record ────────────────────────────────────────
  {
    id: "missing_spf",
    name: "Missing or Weak SPF Record",
    severity: "low",
    confidence: 0.8,
    match: (obs) => {
      if (obs.assetType !== "txt") return false;
      const txt = (obs.evidence?.value || "").toLowerCase();
      return txt.includes("v=spf") && (txt.includes("+all") || txt.includes("?all"));
    },
    rationale: (obs) => `Weak SPF record detected for ${obs.domain}: ${obs.evidence?.value}. A permissive SPF policy (+all or ?all) allows anyone to send email on behalf of the domain.`,
  },

  // ─── Known Vulnerable Software ─────────────────────────────────
  {
    id: "known_vuln_software",
    name: "Potentially Vulnerable Software Version",
    severity: "high",
    confidence: 0.65,
    match: (obs) => {
      const product = (obs.evidence?.product || "").toLowerCase();
      const version = obs.evidence?.version || "";
      if (!product || !version) return false;
      // Flag very old versions of common web servers
      const vulnPatterns: [RegExp, RegExp][] = [
        [/apache/i, /^[12]\.[0-3]\./],
        [/nginx/i, /^1\.[0-9]\./],
        [/openssh/i, /^[1-6]\./],
        [/php/i, /^[5-7]\.[0-2]\./],
        [/iis/i, /^[5-7]\./],
      ];
      return vulnPatterns.some(([prodRe, verRe]) => prodRe.test(product) && verRe.test(version));
    },
    rationale: (obs) => `Potentially vulnerable software detected: ${obs.evidence.product} ${obs.evidence.version} on ${obs.ip || obs.name}. Older versions may have known CVEs.`,
  },

  // ─── Historical Admin Paths ────────────────────────────────────
  {
    id: "historical_admin_path",
    name: "Historical Admin Path in Web Archive",
    severity: "medium",
    confidence: 0.55,
    match: (obs) => {
      return obs.source === "wayback" && obs.tags.includes("admin_path");
    },
    rationale: (obs) => `Historical admin path found in Wayback Machine archive: ${obs.name}. Even if no longer active, this reveals the application's admin URL pattern.`,
  },

  // ─── Credential Exposure (Breach Data) ────────────────────────
  {
    id: "credential_exposure",
    name: "Credentials Exposed in Data Breach",
    severity: "critical",
    confidence: 0.95,
    match: (obs) => {
      return obs.source === "dehashed" && obs.assetType === "breach" &&
             obs.tags.includes("credentials_exposed");
    },
    rationale: (obs) => {
      const creds = obs.evidence?.credentials_exposed || 0;
      const dbName = obs.evidence?.database_name || obs.name;
      return `${creds} credentials (passwords/hashes) for ${obs.domain} exposed in the "${dbName}" data breach. Exposed credentials enable password spraying and credential stuffing attacks.`;
    },
    credentialEvidence: (obs) => {
      const ev = obs.evidence || {};
      return {
        breachName: ev.database_name || obs.name || undefined,
        breachDate: ev.breach_date || undefined,
        totalRecords: ev.credentials_exposed || ev.total_records || undefined,
        emails: ev.sample_emails?.slice(0, 10) || (ev.email ? [ev.email] : undefined),
        usernames: ev.sample_usernames?.slice(0, 10) || (ev.username ? [ev.username] : undefined),
        hashTypes: ev.hash_types || (ev.hash_type ? [ev.hash_type] : undefined),
        hasPlaintextPasswords: ev.has_plaintext === true || ev.password_count > 0 || undefined,
        sources: ['dehashed'],
        domain: obs.domain,
      };
    },
  },

  // ─── High-Volume Breach Exposure ──────────────────────────────
  {
    id: "high_volume_breach",
    name: "High-Volume Breach Exposure",
    severity: "high",
    confidence: 0.9,
    match: (obs) => {
      return obs.source === "dehashed" && obs.assetType === "breach" &&
             obs.tags.includes("breach_summary") &&
             (obs.evidence?.total_records || 0) > 100;
    },
    rationale: (obs) => {
      const total = obs.evidence?.total_records || 0;
      const breaches = obs.evidence?.unique_breaches || 0;
      return `${total} breach records found across ${breaches} data breaches for ${obs.domain}. High-volume exposure significantly increases the risk of credential stuffing and account takeover attacks.`;
    },
    credentialEvidence: (obs) => {
      const ev = obs.evidence || {};
      return {
        totalRecords: ev.total_records || undefined,
        uniqueBreaches: ev.unique_breaches || undefined,
        emails: ev.sample_emails?.slice(0, 10) || undefined,
        usernames: ev.sample_usernames?.slice(0, 10) || undefined,
        hashTypes: ev.hash_types || undefined,
        hasPlaintextPasswords: ev.has_plaintext === true || ev.password_count > 0 || undefined,
        breachName: ev.top_breaches?.join(', ') || ev.database_name || undefined,
        sources: ['dehashed'],
        domain: obs.domain,
      };
    },
  },

  // ─── Breach-Derived Subdomain Discovery ───────────────────────
  {
    id: "breach_subdomain",
    name: "Subdomain Discovered via Breach Data",
    severity: "info",
    confidence: 0.8,
    match: (obs) => {
      return obs.source === "dehashed" && obs.assetType === "subdomain" &&
             obs.tags.includes("breach_derived");
    },
    rationale: (obs) => `Subdomain ${obs.name} discovered through email addresses found in breach records. This subdomain may host services with compromised user accounts.`,
  },

  // ─── GreyNoise: Active Attack Detection ────────────────────────
  {
    id: "greynoise_malicious",
    name: "IP Under Active Attack (GreyNoise)",
    severity: "critical",
    confidence: 0.95,
    match: (obs) => {
      return obs.source === "greynoise" && obs.tags.includes("UNDER_ACTIVE_ATTACK");
    },
    rationale: (obs) => {
      const actor = obs.evidence?.actor || "unknown";
      const cves = obs.evidence?.cves_exploited || [];
      const cveStr = cves.length > 0 ? ` CVEs being exploited: ${cves.join(", ")}.` : "";
      return `GreyNoise classifies ${obs.ip || obs.name} as MALICIOUS — this IP is being actively targeted by threat actors${actor !== "unknown" ? ` (actor: ${actor})` : ""}.${cveStr} Immediate investigation recommended.`;
    },
  },

  // ─── GreyNoise: Mass Scanning Target ──────────────────────────
  {
    id: "greynoise_noise",
    name: "IP Targeted by Mass Scanning (GreyNoise)",
    severity: "medium",
    confidence: 0.85,
    match: (obs) => {
      return obs.source === "greynoise" && obs.tags.includes("internet_noise") &&
             !obs.tags.includes("UNDER_ACTIVE_ATTACK");
    },
    rationale: (obs) => `GreyNoise detects mass-scanning activity targeting ${obs.ip || obs.name}. While this is common internet background noise, it indicates the IP is visible to automated scanners.`,
  },

  // ─── GreyNoise: Active CVE Exploitation ───────────────────────
  {
    id: "greynoise_cve_exploit",
    name: "CVE Actively Exploited Against IP (GreyNoise)",
    severity: "critical",
    confidence: 0.95,
    match: (obs) => {
      return obs.source === "greynoise" && obs.tags.includes("actively_exploited") &&
             obs.tags.some(t => t.startsWith("cve:"));
    },
    rationale: (obs) => {
      const cve = obs.tags.find(t => t.startsWith("cve:"))?.split(":")[1] || "unknown";
      return `GreyNoise sensor network confirms ${cve} is being actively exploited against ${obs.ip || obs.name}. This is ground-truth exploitation data from passive traffic analysis.`;
    },
  },

  // ─── BinaryEdge: CVE Detected ─────────────────────────────────
  {
    id: "binaryedge_cve",
    name: "CVE Detected by BinaryEdge",
    severity: "high",
    confidence: 0.85,
    match: (obs) => {
      return obs.source === "binaryedge" && obs.tags.includes("binaryedge_cve") &&
             obs.tags.some(t => t.startsWith("cve:"));
    },
    rationale: (obs) => {
      const cve = obs.tags.find(t => t.startsWith("cve:"))?.split(":")[1] || "unknown";
      return `BinaryEdge independently confirms ${cve} on ${obs.ip || obs.name}. Cross-validated with Shodan data for higher confidence.`;
    },
  },

  // ─── BinaryEdge: Exposed Service ──────────────────────────────
  {
    id: "binaryedge_exposed_service",
    name: "Exposed Service (BinaryEdge Independent Validation)",
    severity: "medium",
    confidence: 0.8,
    match: (obs) => {
      return obs.source === "binaryedge" && obs.assetType === "ip" &&
             obs.tags.includes("binaryedge_host") &&
             (obs.evidence?.open_ports?.length || 0) > 5;
    },
    rationale: (obs) => {
      const ports = obs.evidence?.open_ports || [];
      return `BinaryEdge detects ${ports.length} open ports on ${obs.ip || obs.name}: ${ports.slice(0, 10).join(", ")}${ports.length > 10 ? "..." : ""}. Large attack surface independently confirmed.`;
    },
  },

  // ─── Shodan InternetDB: Fast CVE Match ────────────────────────
  {
    id: "internetdb_cve",
    name: "CVE Detected by Shodan InternetDB (Free)",
    severity: "high",
    confidence: 0.8,
    match: (obs) => {
      return obs.source === "shodan_internetdb" && obs.tags.includes("internetdb_cve") &&
             obs.tags.some(t => t.startsWith("cve:"));
    },
    rationale: (obs) => {
      const cve = obs.tags.find(t => t.startsWith("cve:"))?.split(":")[1] || "unknown";
      return `Shodan InternetDB (free fast-path) detects ${cve} on ${obs.ip || obs.name}. This is pre-computed data from Shodan's internet-wide scanning.`;
    },
  },

  // ─── Dangling CNAME / Subdomain Takeover ──────────────────────
  {
    id: "subdomain_takeover",
    name: "Potential Subdomain Takeover (Dangling CNAME)",
    severity: "critical",
    confidence: 0.80,
    match: (obs) => {
      if (obs.assetType !== "cname" && obs.assetType !== "subdomain") return false;
      const name = (obs.name || "").toLowerCase();
      const cname = (obs.evidence?.cname || obs.evidence?.value || "").toLowerCase();
      // Check if CNAME points to a cloud provider that could be claimed
      const takeoverTargets = [
        /\.s3\.amazonaws\.com$/,
        /\.s3-website[.-].*\.amazonaws\.com$/,
        /\.cloudfront\.net$/,
        /\.herokuapp\.com$/,
        /\.herokudns\.com$/,
        /\.azurewebsites\.net$/,
        /\.blob\.core\.windows\.net$/,
        /\.cloudapp\.azure\.com$/,
        /\.trafficmanager\.net$/,
        /\.ghost\.io$/,
        /\.myshopify\.com$/,
        /\.surge\.sh$/,
        /\.bitbucket\.io$/,
        /\.pantheonsite\.io$/,
        /\.zendesk\.com$/,
        /\.github\.io$/,
        /\.gitlab\.io$/,
        /\.netlify\.app$/,
        /\.fly\.dev$/,
        /\.vercel\.app$/,
        /\.render\.com$/,
        /\.unbouncepages\.com$/,
        /\.wordpress\.com$/,
        /\.wpengine\.com$/,
        /\.fastly\.net$/,
      ];
      const hasTakeoverTarget = takeoverTargets.some(re => re.test(cname));
      // Also check if the observation has NXDOMAIN or error tags
      const hasNxdomain = obs.tags.some(t => t.includes("nxdomain") || t.includes("dangling") || t.includes("unresolved"));
      return hasTakeoverTarget || hasNxdomain;
    },
    rationale: (obs) => {
      const cname = obs.evidence?.cname || obs.evidence?.value || "unknown";
      return `Potential subdomain takeover: ${obs.name} has a CNAME pointing to ${cname}, which may be unclaimed. An attacker could register this resource and serve malicious content under your domain.`;
    },
  },

  // ─── Cloud Storage Exposure ───────────────────────────────────
  {
    id: "cloud_storage_exposed",
    name: "Publicly Accessible Cloud Storage",
    severity: "critical",
    confidence: 0.85,
    match: (obs) => {
      const name = (obs.name || "").toLowerCase();
      const tags = obs.tags.join(" ").toLowerCase();
      const evidence = obs.evidence || {};
      // Check for cloud storage indicators
      const isCloudStorage = /s3\.amazonaws|blob\.core\.windows|storage\.googleapis|storage\.cloud\.google/i.test(name) ||
                             tags.includes("s3_bucket") || tags.includes("azure_blob") || tags.includes("gcp_bucket") ||
                             tags.includes("cloud_storage") || tags.includes("public_bucket");
      // Check for public access indicators
      const isPublic = tags.includes("public") || tags.includes("open_bucket") ||
                       evidence.public === true || evidence.publicAccess === true ||
                       evidence.acl === "public-read" || evidence.acl === "public-read-write" ||
                       evidence.listable === true;
      return isCloudStorage && isPublic;
    },
    rationale: (obs) => {
      const provider = /s3|amazonaws/i.test(obs.name || "") ? "AWS S3" :
                       /blob\.core\.windows/i.test(obs.name || "") ? "Azure Blob" :
                       /storage\.google/i.test(obs.name || "") ? "Google Cloud Storage" : "cloud storage";
      return `Publicly accessible ${provider} bucket detected: ${obs.name}. Public cloud storage can expose sensitive data, backups, credentials, and internal documents.`;
    },
  },

  // ─── API Key Leakage ──────────────────────────────────────────
  {
    id: "api_key_leak",
    name: "API Key or Secret Leaked in Public Source",
    severity: "critical",
    confidence: 0.75,
    match: (obs) => {
      const tags = obs.tags.join(" ").toLowerCase();
      const evidence = obs.evidence || {};
      // Check for API key leak indicators from GitHub leaks, code scanning, etc.
      const hasLeakTag = tags.includes("api_key_leak") || tags.includes("secret_leak") ||
                         tags.includes("credential_leak") || tags.includes("hardcoded_secret") ||
                         tags.includes("exposed_key") || tags.includes("token_leak");
      // Check evidence for common API key patterns
      const hasKeyPattern = evidence.secret_type && /api.key|token|secret|password|credential/i.test(evidence.secret_type);
      return hasLeakTag || hasKeyPattern;
    },
    rationale: (obs) => {
      const secretType = obs.evidence?.secret_type || "API key/secret";
      const location = obs.evidence?.file_path || obs.evidence?.url || obs.name;
      return `${secretType} leaked in public source: ${location}. Exposed API keys and secrets can grant unauthorized access to internal systems, cloud resources, and third-party services.`;
    },
  },

  // ─── Certificate Transparency Anomalies ───────────────────────
  {
    id: "cert_anomaly",
    name: "Certificate Transparency Anomaly",
    severity: "high",
    confidence: 0.70,
    match: (obs) => {
      if (obs.assetType !== "certificate") return false;
      const evidence = obs.evidence || {};
      // Check for suspicious certificate characteristics
      const issuer = (evidence.issuer || "").toLowerCase();
      const subject = (evidence.subject || evidence.commonName || "").toLowerCase();
      // Self-signed certs on production domains
      const isSelfSigned = issuer === subject || evidence.selfSigned === true;
      // Wildcard certs from unexpected issuers
      const isWildcard = subject.startsWith("*.");
      const suspiciousIssuer = /let.*encrypt/i.test(issuer) === false &&
                               /digicert|comodo|sectigo|globalsign|entrust|godaddy|amazon|google|microsoft|cloudflare/i.test(issuer) === false &&
                               issuer.length > 0;
      // Very short validity period (< 30 days) or very long (> 2 years)
      const notBefore = evidence.not_before ? new Date(evidence.not_before).getTime() : 0;
      const notAfter = evidence.not_after ? new Date(evidence.not_after).getTime() : 0;
      const validityDays = notAfter && notBefore ? (notAfter - notBefore) / (1000 * 60 * 60 * 24) : 0;
      const unusualValidity = validityDays > 0 && (validityDays < 30 || validityDays > 825);
      return isSelfSigned || (isWildcard && suspiciousIssuer) || unusualValidity;
    },
    rationale: (obs) => {
      const evidence = obs.evidence || {};
      const issuer = evidence.issuer || "unknown";
      const subject = evidence.subject || evidence.commonName || obs.name;
      if (evidence.selfSigned) {
        return `Self-signed certificate detected for ${subject}. Self-signed certificates on production systems indicate misconfiguration or potential MITM setup.`;
      }
      return `Certificate anomaly detected for ${subject} (issuer: ${issuer}). Unexpected certificate characteristics may indicate domain hijacking, MITM, or misconfiguration.`;
    },
  },

  // ─── Shadow IT / Unauthorized Services ────────────────────────
  {
    id: "shadow_it_service",
    name: "Potential Shadow IT / Unauthorized Service",
    severity: "medium",
    confidence: 0.65,
    match: (obs) => {
      const portTag = obs.tags.find(t => t.startsWith("port:"));
      if (!portTag) return false;
      const port = parseInt(portTag.split(":")[1], 10);
      // Non-standard web ports that often indicate unauthorized or forgotten services
      const shadowPorts = [
        8080, 8443, 8888, 9090, 9443, 3000, 4000, 5000, 7000, 7443,
        8000, 8001, 8008, 8081, 8082, 8083, 8084, 8085, 8181, 8282,
        8383, 8484, 8585, 8686, 8787, 8880, 8881, 8882, 8883, 8884,
        9000, 9001, 9002, 9003, 9080, 9443, 10000, 10443,
      ];
      // Exclude well-known standard ports
      const standardPorts = [22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 5432, 27017, 6379, 9200, 3389, 5900, 5901];
      return shadowPorts.includes(port) || (port > 1024 && port < 65535 && !standardPorts.includes(port) && obs.evidence?.product);
    },
    rationale: (obs) => {
      const portTag = obs.tags.find(t => t.startsWith("port:"))!;
      const port = portTag.split(":")[1];
      const product = obs.evidence?.product || "unknown service";
      return `Potential shadow IT service detected: ${product} on port ${port} at ${obs.ip || obs.name}. Non-standard ports often host unauthorized, unpatched, or forgotten services that bypass normal security controls.`;
    },
  },

  // ─── Missing DMARC Record ─────────────────────────────────────
  {
    id: "missing_dmarc",
    name: "Missing or Weak DMARC Record",
    severity: "medium",
    confidence: 0.85,
    match: (obs) => {
      if (obs.source !== "email-security") return false;
      const tags = obs.tags.join(" ").toLowerCase();
      return tags.includes("no_dmarc") || tags.includes("dmarc_none") ||
             (obs.evidence?.dmarc_policy === "none") ||
             (obs.evidence?.hasDmarc === false);
    },
    rationale: (obs) => `Missing or weak DMARC policy for ${obs.domain || obs.name}. Without DMARC enforcement (quarantine/reject), attackers can spoof emails from this domain for phishing campaigns.`,
  },

  // ─── Open Remote Access Ports ──────────────────────────────────
  {
    id: "open_remote_access",
    name: "Open Remote Access Port",
    severity: "high",
    confidence: 0.85,
    match: (obs) => {
      const portTag = obs.tags.find(t => t.startsWith("port:"));
      if (!portTag) return false;
      const port = parseInt(portTag.split(":")[1], 10);
      return [22, 23, 3389, 5900, 5901].includes(port);
    },
    rationale: (obs) => {
      const portTag = obs.tags.find(t => t.startsWith("port:"))!;
      const portMap: Record<string, string> = {
        "22": "SSH", "23": "Telnet", "3389": "RDP",
        "5900": "VNC", "5901": "VNC",
      };
      const port = portTag.split(":")[1];
      return `Open ${portMap[port] || "remote access"} port (${port}) detected on ${obs.ip || obs.name}. Remote access services should be restricted via VPN or IP allowlisting.`;
    },
  },
];

function makeSignalId(assetId: string, ruleId: string): string {
  return createHash("sha256").update(`${assetId}|${ruleId}`).digest("hex").slice(0, 20);
}

/**
 * Classify observations into risk signals
 */
export function classifySignals(observations: AssetObservation[]): RiskSignal[] {
  const signals: RiskSignal[] = [];
  const seen = new Set<string>();

  for (const obs of observations) {
    for (const rule of SIGNAL_RULES) {
      try {
        if (rule.match(obs)) {
          const signalId = makeSignalId(obs.assetId, rule.id);
          if (seen.has(signalId)) continue;
          seen.add(signalId);

          const signal: RiskSignal = {
            signalId,
            assetId: obs.assetId,
            signalType: rule.id,
            severity: rule.severity,
            confidence: rule.confidence,
            observedAt: obs.observedAt,
            rationale: rule.rationale(obs),
            evidenceRefs: [obs.assetId],
          };
          // Attach NIST 800-53 control references
          try {
            const nistControls = getNistControlsForSignal(rule.id);
            if (nistControls.length > 0) {
              signal.nistControls = nistControls.map(c => ({
                controlId: c.controlId,
                controlName: c.controlName,
                family: c.family,
              }));
            }
            // Calculate FedRAMP remediation deadline
            const deadline = calculateFedrampDeadline(obs.observedAt, rule.severity);
            signal.fedrampDeadline = deadline.toISOString();
          } catch {
            // Non-fatal: skip NIST mapping on error
          }
          // Attach credential evidence for breach/credential signals
          if (rule.credentialEvidence) {
            try {
              signal.credentialEvidence = rule.credentialEvidence(obs);
            } catch {
              // Non-fatal: skip evidence extraction on error
            }
          }
          signals.push(signal);
        }
      } catch {
        // Skip rules that error on specific observations
      }
    }
  }

  return signals;
}

/**
 * Get all available signal rule descriptions for transparency
 */
export function getSignalRuleDescriptions(): { id: string; name: string; severity: SignalSeverity }[] {
  return SIGNAL_RULES.map(r => ({ id: r.id, name: r.name, severity: r.severity }));
}
