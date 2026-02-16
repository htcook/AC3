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

interface SignalRule {
  id: string;
  name: string;
  severity: SignalSeverity;
  confidence: number;
  match: (obs: AssetObservation) => boolean;
  rationale: (obs: AssetObservation) => string;
}

const SIGNAL_RULES: SignalRule[] = [
  // ─── Exposed Admin Interfaces ──────────────────────────────────
  {
    id: "admin_panel_exposed",
    name: "Exposed Admin/Management Interface",
    severity: "high",
    confidence: 0.85,
    match: (obs) => {
      const name = (obs.name || "").toLowerCase();
      const tags = obs.tags.join(" ");
      return /admin|console|mgmt|management|cpanel|phpmyadmin|webmin|cockpit/i.test(name) ||
             tags.includes("admin_path");
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

          signals.push({
            signalId,
            assetId: obs.assetId,
            signalType: rule.id,
            severity: rule.severity,
            confidence: rule.confidence,
            observedAt: obs.observedAt,
            rationale: rule.rationale(obs),
            evidenceRefs: [obs.assetId],
          });
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
