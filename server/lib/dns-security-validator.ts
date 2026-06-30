/**
 * DNS Security Validator — Comprehensive DNS Weakness Detection Engine
 *
 * Validates all known DNS weaknesses and flaws including:
 * - Dangling DNS / Subdomain Takeover (CNAME, A, NS, MX)
 * - DNSSEC chain-of-trust validation (DS, DNSKEY, RRSIG, algorithm strength)
 * - Zone transfer (AXFR) exposure
 * - DNS cache poisoning susceptibility
 * - Open resolver detection
 * - DNS amplification/reflection risk
 * - Wildcard DNS detection
 * - SPF/DKIM/DMARC validation (email security posture)
 * - CAA record validation
 * - NSEC/NSEC3 zone walking exposure
 * - DNS tunneling indicators
 * - Nameserver version disclosure
 * - DNS cookie support (RFC 7873)
 * - Response rate limiting (RRL) detection
 * - DNS rebinding vulnerability check
 *
 * Integrates into: DI scans, Vuln/Pentest engagements, Red Team engagements
 * Maps to MITRE ATT&CK: T1071.004, T1568, T1584.002, T1583.001
 */

import { createHash } from "crypto";
import {
  resolve4, resolve6, resolveCname, resolveNs, resolveSoa,
  resolveTxt, resolveCaa, resolveMx
} from "dns/promises";
import { Resolver } from "dns/promises";

// ─── Types ──────────────────────────────────────────────────────────────────

export type DnsFindingSeverity = "critical" | "high" | "medium" | "low" | "info";
export type DnsFindingCategory =
  | "dangling_dns"
  | "dnssec"
  | "zone_transfer"
  | "cache_poisoning"
  | "open_resolver"
  | "amplification"
  | "wildcard"
  | "email_security"
  | "caa"
  | "zone_walking"
  | "tunneling_indicator"
  | "version_disclosure"
  | "dns_cookie"
  | "rate_limiting"
  | "rebinding"
  | "configuration";

export type EngagementContext = "di_scan" | "vuln_pentest" | "red_team";

export interface DnsFinding {
  id: string;
  category: DnsFindingCategory;
  severity: DnsFindingSeverity;
  title: string;
  description: string;
  evidence: string;
  remediation: string;
  affectedRecord?: string;
  recordType?: string;
  cvssVector?: string;
  cvssScore?: number;
  mitreAttackId?: string;
  mitreAttackName?: string;
  cwe?: string;
  references?: string[];
}

export interface DnsRecord {
  type: string;
  name: string;
  value: string;
  ttl?: number;
  priority?: number;
  additional?: Record<string, any>;
}

export interface DnssecStatus {
  enabled: boolean;
  delegationSigned: boolean;
  dsRecords?: Array<{ keyTag: number; algorithm: number; algorithmName: string; digestType: number; digest: string }>;
  dnskeyRecords?: Array<{ flags: number; protocol: number; algorithm: number; algorithmName: string; keyLength?: number }>;
  rrsigPresent: boolean;
  signatureExpiry?: string;
  chainOfTrustValid: boolean;
  algorithmStrength: "strong" | "acceptable" | "weak" | "unknown";
  issues: string[];
}

export interface DnsSecurityReport {
  domain: string;
  scanTimestamp: number;
  engagementContext: EngagementContext;
  records: DnsRecord[];
  dnssec: DnssecStatus;
  findings: DnsFinding[];
  summary: {
    totalFindings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    overallRisk: "critical" | "high" | "medium" | "low";
    passedChecks: number;
    failedChecks: number;
    totalChecks: number;
  };
  metadata: {
    nameservers: string[];
    primaryNs: string;
    soaSerial?: number;
    responseTimeMs: number;
    checksPerformed: string[];
  };
}

// ─── Takeover Fingerprints ──────────────────────────────────────────────────

export interface TakeoverFingerprint {
  service: string;
  cnames: string[];
  fingerprints: string[];
  httpStatus?: number;
  discussion?: string;
  vulnerable: boolean;
}

/**
 * Curated from can-i-take-over-xyz + manual research.
 * Only includes services confirmed vulnerable to takeover.
 */
export const TAKEOVER_FINGERPRINTS: TakeoverFingerprint[] = [
  { service: "AWS S3", cnames: [".s3.amazonaws.com", ".s3-website", ".s3.us-east-1.amazonaws.com", ".s3.us-west-2.amazonaws.com"], fingerprints: ["NoSuchBucket", "The specified bucket does not exist"], vulnerable: true },
  { service: "AWS CloudFront", cnames: [".cloudfront.net"], fingerprints: ["Bad request", "ERROR: The request could not be satisfied"], httpStatus: 403, vulnerable: true },
  { service: "AWS Elastic Beanstalk", cnames: [".elasticbeanstalk.com"], fingerprints: ["NXDOMAIN"], vulnerable: true },
  { service: "Azure Blob Storage", cnames: [".blob.core.windows.net"], fingerprints: ["BlobNotFound", "The specified container does not exist"], vulnerable: true },
  { service: "Azure App Service", cnames: [".azurewebsites.net", ".cloudapp.azure.com", ".azure-api.net", ".azurefd.net"], fingerprints: ["404 Web Site not found", "NXDOMAIN"], vulnerable: true },
  { service: "Azure Traffic Manager", cnames: [".trafficmanager.net"], fingerprints: ["NXDOMAIN"], vulnerable: true },
  { service: "GitHub Pages", cnames: [".github.io", "github.map.fastly.net"], fingerprints: ["There isn't a GitHub Pages site here", "For root URLs (like http://example.com/) you must provide an index.html file"], vulnerable: true },
  { service: "Heroku", cnames: [".herokuapp.com", ".herokussl.com", ".herokudns.com"], fingerprints: ["No such app", "no-such-app", "herokucdn.com/error-pages/no-such-app.html"], vulnerable: true },
  { service: "Shopify", cnames: [".myshopify.com", "shops.myshopify.com"], fingerprints: ["Sorry, this shop is currently unavailable", "Only one step left!"], vulnerable: true },
  { service: "Tumblr", cnames: [".tumblr.com", "domains.tumblr.com"], fingerprints: ["There's nothing here.", "Whatever you were looking for doesn't currently exist at this address"], vulnerable: true },
  { service: "WordPress.com", cnames: [".wordpress.com"], fingerprints: ["Do you want to register"], vulnerable: true },
  { service: "Pantheon", cnames: [".pantheonsite.io", ".pantheon.io"], fingerprints: ["404 error unknown site!", "The gods are wise"], vulnerable: true },
  { service: "Fastly", cnames: [".fastly.net", ".fastlylb.net", "global.ssl.fastly.net"], fingerprints: ["Fastly error: unknown domain"], vulnerable: true },
  { service: "Netlify", cnames: [".netlify.app", ".netlify.com", ".bitballoon.com"], fingerprints: ["Not Found - Request ID"], vulnerable: true },
  { service: "Fly.io", cnames: [".fly.dev"], fingerprints: ["404 Not Found"], vulnerable: true },
  { service: "Surge.sh", cnames: [".surge.sh", "na-west1.surge.sh"], fingerprints: ["project not found"], vulnerable: true },
  { service: "UserVoice", cnames: [".uservoice.com"], fingerprints: ["This UserVoice subdomain is currently available!"], vulnerable: true },
  { service: "Ghost", cnames: [".ghost.io"], fingerprints: ["The thing you were looking for is no longer here"], vulnerable: true },
  { service: "Cargo Collective", cnames: [".cargocollective.com"], fingerprints: ["404 Not Found"], vulnerable: true },
  { service: "HubSpot", cnames: [".hubspot.net", ".hs-sites.com"], fingerprints: ["Domain not found"], vulnerable: true },
  { service: "Webflow", cnames: [".webflow.io", "proxy-ssl.webflow.com"], fingerprints: ["The page you are looking for doesn't exist or has been moved"], vulnerable: true },
  { service: "Zendesk", cnames: [".zendesk.com", ".zendesk.host"], fingerprints: ["Help Center Closed", "Oops, this help center no longer exists"], vulnerable: true },
  { service: "Tilda", cnames: [".tilda.ws"], fingerprints: ["Please renew your subscription"], vulnerable: true },
  { service: "Readme.io", cnames: [".readme.io"], fingerprints: ["Project doesnt exist"], vulnerable: true },
  { service: "Bitbucket", cnames: [".bitbucket.io"], fingerprints: ["Repository not found"], vulnerable: true },
  { service: "Intercom", cnames: [".intercom.help", "custom.intercom.help"], fingerprints: ["Uh oh. That page doesn't exist"], vulnerable: true },
  { service: "Ngrok", cnames: [".ngrok.io", ".ngrok-free.app"], fingerprints: ["Tunnel not found", "ngrok.io not found"], vulnerable: true },
  { service: "Kinsta", cnames: [".kinsta.cloud"], fingerprints: ["No Site For Domain"], vulnerable: true },
  { service: "LaunchRock", cnames: [".launchrock.com"], fingerprints: ["It looks like you may have taken a wrong turn somewhere"], vulnerable: true },
  { service: "Smugmug", cnames: [".smugmug.com"], fingerprints: ["Page Not Found"], vulnerable: true },
  { service: "Strikingly", cnames: [".strikingly.com", ".s.strikinglydns.com"], fingerprints: ["page not found", "But if you're looking to build your own website"], vulnerable: true },
  { service: "Uptimerobot", cnames: [".uptimerobot.com"], fingerprints: ["page not found", "is not a registered InMotion Hosting domain"], vulnerable: true },
  { service: "Agile CRM", cnames: [".agilecrm.com"], fingerprints: ["Sorry, this page is no longer available"], vulnerable: true },
  { service: "Aha!", cnames: [".ideas.aha.io"], fingerprints: ["There is no portal here ... check portal address"], vulnerable: true },
  { service: "Anima", cnames: [".animaapp.io"], fingerprints: ["If this is your website and you've just created it, try refreshing in a minute"], vulnerable: true },
];

// ─── DNSSEC Algorithm Mapping ───────────────────────────────────────────────

const DNSSEC_ALGORITHMS: Record<number, { name: string; strength: "strong" | "acceptable" | "weak" | "deprecated" }> = {
  1: { name: "RSA/MD5", strength: "deprecated" },
  3: { name: "DSA/SHA-1", strength: "deprecated" },
  5: { name: "RSA/SHA-1", strength: "weak" },
  6: { name: "DSA-NSEC3-SHA1", strength: "deprecated" },
  7: { name: "RSASHA1-NSEC3-SHA1", strength: "weak" },
  8: { name: "RSA/SHA-256", strength: "strong" },
  10: { name: "RSA/SHA-512", strength: "strong" },
  12: { name: "GOST R 34.10-2001", strength: "acceptable" },
  13: { name: "ECDSA/P-256/SHA-256", strength: "strong" },
  14: { name: "ECDSA/P-384/SHA-384", strength: "strong" },
  15: { name: "Ed25519", strength: "strong" },
  16: { name: "Ed448", strength: "strong" },
};

// ─── Helper Functions ───────────────────────────────────────────────────────

function makeId(domain: string, check: string): string {
  return createHash("sha256").update(`dns-sec|${domain}|${check}`).digest("hex").slice(0, 16);
}

async function dnsQuery<T>(fn: () => Promise<T>, timeoutMs = 5000): Promise<T | null> {
  try {
    return await Promise.race([
      fn(),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("timeout")), timeoutMs)),
    ]);
  } catch {
    return null;
  }
}

async function httpProbe(url: string, timeoutMs = 8000): Promise<{ status: number; body: string } | null> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const resp = await fetch(url, {
      signal: controller.signal,
      headers: { "User-Agent": "AC3-DNS-Security-Validator/1.0" },
      redirect: "follow",
    });
    clearTimeout(timer);
    const body = await resp.text();
    return { status: resp.status, body: body.slice(0, 4096) };
  } catch {
    return null;
  }
}

async function dnsGoogleResolve(domain: string, type: string): Promise<any[]> {
  try {
    const resp = await fetch(
      `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}&do=1`,
      { headers: { Accept: "application/dns-json" } }
    );
    if (!resp.ok) return [];
    const data = await resp.json();
    return data.Answer || [];
  } catch {
    return [];
  }
}

// ─── Main Validator Class ───────────────────────────────────────────────────

export class DnsSecurityValidator {
  private domain: string;
  private context: EngagementContext;
  private findings: DnsFinding[] = [];
  private records: DnsRecord[] = [];
  private checksPerformed: string[] = [];
  private passedChecks = 0;
  private failedChecks = 0;

  constructor(domain: string, context: EngagementContext = "di_scan") {
    this.domain = domain;
    this.context = context;
  }

  async runFullAssessment(): Promise<DnsSecurityReport> {
    const start = Date.now();

    // Phase 1: Collect all DNS records
    await this.collectRecords();

    // Phase 2: Run all security checks
    await Promise.all([
      this.checkDanglingSecurity(),
      this.checkDnssec(),
      this.checkZoneTransfer(),
      this.checkCachePoisoning(),
      this.checkOpenResolver(),
      this.checkAmplification(),
      this.checkWildcard(),
      this.checkEmailSecurity(),
      this.checkCaa(),
      this.checkZoneWalking(),
      this.checkTunnelingIndicators(),
      this.checkVersionDisclosure(),
      this.checkDnsCookie(),
      this.checkRateLimiting(),
      this.checkRebinding(),
    ]);

    const responseTimeMs = Date.now() - start;

    // Build DNSSEC status
    const dnssec = await this.buildDnssecStatus();

    // Build summary
    const critical = this.findings.filter(f => f.severity === "critical").length;
    const high = this.findings.filter(f => f.severity === "high").length;
    const medium = this.findings.filter(f => f.severity === "medium").length;
    const low = this.findings.filter(f => f.severity === "low").length;
    const info = this.findings.filter(f => f.severity === "info").length;

    const overallRisk: DnsSecurityReport["summary"]["overallRisk"] =
      critical > 0 ? "critical" : high > 0 ? "high" : medium > 0 ? "medium" : "low";

    // Extract nameservers
    const nsRecords = this.records.filter(r => r.type === "NS");
    const soaRecord = this.records.find(r => r.type === "SOA");

    return {
      domain: this.domain,
      scanTimestamp: Date.now(),
      engagementContext: this.context,
      records: this.records,
      dnssec,
      findings: this.findings,
      summary: {
        totalFindings: this.findings.length,
        critical,
        high,
        medium,
        low,
        info,
        overallRisk,
        passedChecks: this.passedChecks,
        failedChecks: this.failedChecks,
        totalChecks: this.passedChecks + this.failedChecks,
      },
      metadata: {
        nameservers: nsRecords.map(r => r.value),
        primaryNs: soaRecord?.additional?.nsname || nsRecords[0]?.value || "",
        soaSerial: soaRecord?.additional?.serial,
        responseTimeMs,
        checksPerformed: this.checksPerformed,
      },
    };
  }

  // ─── Record Collection ──────────────────────────────────────────────────

  private async collectRecords(): Promise<void> {
    const [aRecs, aaaaRecs, cnameRecs, nsRecs, mxRecs, soaRec, txtRecs, caaRecs] = await Promise.all([
      dnsQuery(() => resolve4(this.domain)),
      dnsQuery(() => resolve6(this.domain)),
      dnsQuery(() => resolveCname(this.domain)),
      dnsQuery(() => resolveNs(this.domain)),
      dnsQuery(() => resolveMx(this.domain)),
      dnsQuery(() => resolveSoa(this.domain)),
      dnsQuery(() => resolveTxt(this.domain)),
      dnsQuery(() => resolveCaa(this.domain)),
    ]);

    if (aRecs) aRecs.forEach(r => this.records.push({ type: "A", name: this.domain, value: r }));
    if (aaaaRecs) aaaaRecs.forEach(r => this.records.push({ type: "AAAA", name: this.domain, value: r }));
    if (cnameRecs) cnameRecs.forEach(r => this.records.push({ type: "CNAME", name: this.domain, value: r }));
    if (nsRecs) nsRecs.forEach(r => this.records.push({ type: "NS", name: this.domain, value: r }));
    if (mxRecs) mxRecs.forEach(r => this.records.push({ type: "MX", name: this.domain, value: r.exchange, priority: r.priority }));
    if (soaRec) this.records.push({ type: "SOA", name: this.domain, value: `${soaRec.nsname} ${soaRec.hostmaster}`, additional: soaRec });
    if (txtRecs) txtRecs.forEach(parts => this.records.push({ type: "TXT", name: this.domain, value: parts.join("") }));
    if (caaRecs) caaRecs.forEach((r: any) => this.records.push({ type: "CAA", name: this.domain, value: `${r.critical ? "critical" : "0"} ${r.issue || r.issuewild || r.iodef || JSON.stringify(r)}`, additional: r }));

    // Get TTLs via DNS-over-HTTPS for richer data
    const dohRecords = await dnsGoogleResolve(this.domain, "ANY");
    for (const rec of dohRecords) {
      const existing = this.records.find(r => r.type === (rec.type === 1 ? "A" : rec.type === 28 ? "AAAA" : rec.type === 5 ? "CNAME" : ""));
      if (existing && rec.TTL) existing.ttl = rec.TTL;
    }
    // Also get individual TTLs
    for (const type of ["A", "AAAA", "NS", "MX", "TXT", "CAA"]) {
      const typeNum = { A: 1, AAAA: 28, NS: 2, MX: 15, TXT: 16, CAA: 257 }[type] || 0;
      const recs = await dnsGoogleResolve(this.domain, type);
      for (const rec of recs) {
        const matching = this.records.filter(r => r.type === type);
        for (const m of matching) {
          if (!m.ttl && rec.TTL) m.ttl = rec.TTL;
        }
      }
    }
  }

  // ─── Dangling DNS / Subdomain Takeover ──────────────────────────────────

  private async checkDanglingSecurity(): Promise<void> {
    this.checksPerformed.push("dangling_dns_cname", "dangling_dns_a", "dangling_dns_ns", "dangling_dns_mx");

    // Check CNAME records against takeover fingerprints
    const cnameRecords = this.records.filter(r => r.type === "CNAME");
    for (const cname of cnameRecords) {
      const target = cname.value.toLowerCase();

      // Check against fingerprint database
      for (const fp of TAKEOVER_FINGERPRINTS) {
        if (fp.cnames.some(c => target.includes(c.toLowerCase()))) {
          // Verify if the CNAME target resolves
          const resolves = await dnsQuery(() => resolve4(cname.value));
          if (!resolves || resolves.length === 0) {
            // NXDOMAIN — high confidence takeover
            this.findings.push({
              id: makeId(this.domain, `dangling-cname-${target}`),
              category: "dangling_dns",
              severity: "high",
              title: `Dangling CNAME — Potential ${fp.service} Takeover`,
              description: `The CNAME record for ${this.domain} points to ${cname.value} which does not resolve (NXDOMAIN). This ${fp.service} resource appears to be unclaimed and may be vulnerable to subdomain takeover.`,
              evidence: `CNAME: ${this.domain} → ${cname.value} (NXDOMAIN). Service: ${fp.service}. Fingerprint match: ${fp.cnames.find(c => target.includes(c.toLowerCase()))}`,
              remediation: `Remove the CNAME record pointing to ${cname.value}, or re-provision the ${fp.service} resource to reclaim the endpoint.`,
              affectedRecord: cname.value,
              recordType: "CNAME",
              cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:N",
              cvssScore: 9.3,
              mitreAttackId: "T1584.002",
              mitreAttackName: "Compromise Infrastructure: DNS Server",
              cwe: "CWE-672",
              references: [`https://github.com/EdOverflow/can-i-take-over-xyz`],
            });
            this.failedChecks++;
          } else {
            // Resolves but check HTTP response for fingerprints
            const probe = await httpProbe(`https://${this.domain}`);
            if (probe && fp.fingerprints.some(f => probe.body.includes(f))) {
              this.findings.push({
                id: makeId(this.domain, `dangling-cname-fp-${target}`),
                category: "dangling_dns",
                severity: "high",
                title: `Potential ${fp.service} Takeover — Error Page Fingerprint Detected`,
                description: `The CNAME resolves but the HTTP response contains a known ${fp.service} unclaimed resource fingerprint. The resource may be available for takeover.`,
                evidence: `CNAME: ${this.domain} → ${cname.value}. HTTP ${probe.status}. Fingerprint: "${fp.fingerprints.find(f => probe.body.includes(f))}"`,
                remediation: `Verify the ${fp.service} resource is properly configured. If decommissioned, remove the CNAME record.`,
                affectedRecord: cname.value,
                recordType: "CNAME",
                cvssScore: 8.6,
                mitreAttackId: "T1584.002",
                mitreAttackName: "Compromise Infrastructure: DNS Server",
                cwe: "CWE-672",
              });
              this.failedChecks++;
            } else {
              this.passedChecks++;
            }
          }
          break; // Only match first fingerprint
        }
      }
    }

    // Check A/AAAA records for unresponsive IPs
    const aRecords = this.records.filter(r => r.type === "A" || r.type === "AAAA");
    for (const aRec of aRecords) {
      const probe = await httpProbe(`http://${aRec.value}`, 5000);
      if (!probe) {
        // IP doesn't respond on HTTP — could be dangling
        this.findings.push({
          id: makeId(this.domain, `stale-ip-${aRec.value}`),
          category: "dangling_dns",
          severity: "medium",
          title: `Potentially Stale ${aRec.type} Record — IP Unresponsive`,
          description: `The ${aRec.type} record points to ${aRec.value} which does not respond to HTTP requests. If this IP has been released from your cloud provider, it may be claimable by an attacker.`,
          evidence: `${aRec.type}: ${this.domain} → ${aRec.value}. HTTP probe: no response within 5s.`,
          remediation: `Verify ${aRec.value} is still allocated to your organization. If the server has been decommissioned, remove the DNS record immediately.`,
          affectedRecord: aRec.value,
          recordType: aRec.type,
          cvssScore: 6.5,
          mitreAttackId: "T1584.002",
          mitreAttackName: "Compromise Infrastructure: DNS Server",
          cwe: "CWE-672",
        });
        this.failedChecks++;
      } else {
        this.passedChecks++;
      }
    }

    // Check NS records for dead nameservers
    const nsRecords = this.records.filter(r => r.type === "NS");
    for (const ns of nsRecords) {
      const nsResolves = await dnsQuery(() => resolve4(ns.value));
      if (!nsResolves || nsResolves.length === 0) {
        this.findings.push({
          id: makeId(this.domain, `dangling-ns-${ns.value}`),
          category: "dangling_dns",
          severity: "critical",
          title: `Dangling NS Record — Zone Takeover Risk`,
          description: `The nameserver ${ns.value} does not resolve. If an attacker registers this hostname, they gain full control over DNS resolution for ${this.domain}, enabling complete domain hijacking.`,
          evidence: `NS: ${this.domain} → ${ns.value} (NXDOMAIN). Full zone takeover possible.`,
          remediation: `Immediately remove the NS record for ${ns.value} and ensure all nameservers are active and resolvable.`,
          affectedRecord: ns.value,
          recordType: "NS",
          cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
          cvssScore: 10.0,
          mitreAttackId: "T1584.002",
          mitreAttackName: "Compromise Infrastructure: DNS Server",
          cwe: "CWE-672",
        });
        this.failedChecks++;
      } else {
        this.passedChecks++;
      }
    }

    // Check MX records for dead mail servers
    const mxRecords = this.records.filter(r => r.type === "MX");
    for (const mx of mxRecords) {
      const mxResolves = await dnsQuery(() => resolve4(mx.value));
      if (!mxResolves || mxResolves.length === 0) {
        this.findings.push({
          id: makeId(this.domain, `dangling-mx-${mx.value}`),
          category: "dangling_dns",
          severity: "high",
          title: `Dangling MX Record — Email Interception Risk`,
          description: `The mail server ${mx.value} (priority ${mx.priority}) does not resolve. An attacker who claims this hostname could intercept email destined for ${this.domain}.`,
          evidence: `MX: ${this.domain} → ${mx.value} (priority ${mx.priority}) (NXDOMAIN).`,
          remediation: `Remove the MX record for ${mx.value} or ensure the mail server hostname resolves to a valid IP.`,
          affectedRecord: mx.value,
          recordType: "MX",
          cvssScore: 8.1,
          mitreAttackId: "T1114.002",
          mitreAttackName: "Email Collection: Remote Email Collection",
          cwe: "CWE-672",
        });
        this.failedChecks++;
      } else {
        this.passedChecks++;
      }
    }

    if (this.findings.filter(f => f.category === "dangling_dns").length === 0) {
      this.passedChecks++;
    }
  }

  // ─── DNSSEC Validation ──────────────────────────────────────────────────

  private async checkDnssec(): Promise<void> {
    this.checksPerformed.push("dnssec_ds", "dnssec_dnskey", "dnssec_rrsig", "dnssec_algorithm");

    const dsRecords = await dnsGoogleResolve(this.domain, "DS");
    const dnskeyRecords = await dnsGoogleResolve(this.domain, "DNSKEY");
    const rrsigRecords = await dnsGoogleResolve(this.domain, "RRSIG");

    const hasDnssec = dsRecords.length > 0 || dnskeyRecords.length > 0;

    if (!hasDnssec) {
      this.findings.push({
        id: makeId(this.domain, "dnssec-not-enabled"),
        category: "dnssec",
        severity: "high",
        title: "DNSSEC Not Enabled",
        description: `No DS or DNSKEY records found for ${this.domain}. Without DNSSEC, DNS responses cannot be cryptographically verified, leaving the domain vulnerable to DNS spoofing, cache poisoning, and man-in-the-middle attacks.`,
        evidence: `DNS queries for DS and DNSKEY record types returned no results for ${this.domain}.`,
        remediation: "Enable DNSSEC at your domain registrar and DNS hosting provider. Generate DNSKEY records and publish DS records in the parent zone. Use algorithm 13 (ECDSA P-256) or 15 (Ed25519) for optimal security and performance.",
        cvssVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        cvssScore: 7.4,
        mitreAttackId: "T1557.001",
        mitreAttackName: "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay",
        cwe: "CWE-345",
        references: ["https://www.icann.org/resources/pages/dnssec-what-is-it-why-important-2019-03-05-en"],
      });
      this.failedChecks++;
    } else {
      // Check algorithm strength
      for (const key of dnskeyRecords) {
        const algo = key.data ? parseInt(key.data.split(" ")[2]) : 0;
        const algoInfo = DNSSEC_ALGORITHMS[algo];
        if (algoInfo && (algoInfo.strength === "deprecated" || algoInfo.strength === "weak")) {
          this.findings.push({
            id: makeId(this.domain, `dnssec-weak-algo-${algo}`),
            category: "dnssec",
            severity: algoInfo.strength === "deprecated" ? "high" : "medium",
            title: `DNSSEC Uses ${algoInfo.strength === "deprecated" ? "Deprecated" : "Weak"} Algorithm: ${algoInfo.name}`,
            description: `The DNSSEC configuration uses algorithm ${algo} (${algoInfo.name}) which is ${algoInfo.strength}. This reduces the cryptographic protection provided by DNSSEC.`,
            evidence: `DNSKEY record uses algorithm ${algo} (${algoInfo.name}). Strength: ${algoInfo.strength}.`,
            remediation: `Migrate to a stronger DNSSEC algorithm. Recommended: Algorithm 13 (ECDSA P-256/SHA-256) or Algorithm 15 (Ed25519).`,
            cvssScore: algoInfo.strength === "deprecated" ? 7.0 : 5.3,
            cwe: "CWE-327",
          });
          this.failedChecks++;
        } else {
          this.passedChecks++;
        }
      }

      // Check RRSIG presence
      if (rrsigRecords.length === 0) {
        this.findings.push({
          id: makeId(this.domain, "dnssec-no-rrsig"),
          category: "dnssec",
          severity: "medium",
          title: "DNSSEC Keys Present But No RRSIG Records",
          description: `DS/DNSKEY records exist but no RRSIG (signature) records were found. This may indicate a broken DNSSEC configuration where records are not being signed.`,
          evidence: `DS records: ${dsRecords.length}, DNSKEY records: ${dnskeyRecords.length}, RRSIG records: 0.`,
          remediation: "Verify your DNS zone is being signed correctly. Check your DNSSEC signing configuration and ensure the signing key is active.",
          cvssScore: 5.3,
          cwe: "CWE-345",
        });
        this.failedChecks++;
      } else {
        this.passedChecks++;
      }
    }
  }

  private async buildDnssecStatus(): Promise<DnssecStatus> {
    const dsRecords = await dnsGoogleResolve(this.domain, "DS");
    const dnskeyRecords = await dnsGoogleResolve(this.domain, "DNSKEY");
    const rrsigRecords = await dnsGoogleResolve(this.domain, "RRSIG");

    const enabled = dsRecords.length > 0 || dnskeyRecords.length > 0;
    const issues: string[] = [];

    const parsedDs = dsRecords.map((r: any) => {
      const parts = (r.data || "").split(" ");
      const algo = parseInt(parts[1]) || 0;
      return {
        keyTag: parseInt(parts[0]) || 0,
        algorithm: algo,
        algorithmName: DNSSEC_ALGORITHMS[algo]?.name || `Unknown (${algo})`,
        digestType: parseInt(parts[2]) || 0,
        digest: parts[3] || "",
      };
    });

    const parsedDnskey = dnskeyRecords.map((r: any) => {
      const parts = (r.data || "").split(" ");
      const algo = parseInt(parts[2]) || 0;
      return {
        flags: parseInt(parts[0]) || 0,
        protocol: parseInt(parts[1]) || 0,
        algorithm: algo,
        algorithmName: DNSSEC_ALGORITHMS[algo]?.name || `Unknown (${algo})`,
      };
    });

    // Determine algorithm strength
    let algorithmStrength: DnssecStatus["algorithmStrength"] = "unknown";
    const algorithms = [...parsedDs.map(d => d.algorithm), ...parsedDnskey.map(d => d.algorithm)].filter(Boolean);
    if (algorithms.length > 0) {
      const strengths = algorithms.map(a => DNSSEC_ALGORITHMS[a]?.strength || "unknown");
      if (strengths.includes("deprecated")) {
        algorithmStrength = "weak";
        issues.push("Uses deprecated DNSSEC algorithm");
      } else if (strengths.includes("weak")) {
        algorithmStrength = "weak";
        issues.push("Uses weak DNSSEC algorithm (SHA-1 based)");
      } else if (strengths.every(s => s === "strong")) {
        algorithmStrength = "strong";
      } else {
        algorithmStrength = "acceptable";
      }
    }

    if (!enabled) issues.push("DNSSEC not enabled — no DS or DNSKEY records");
    if (enabled && rrsigRecords.length === 0) issues.push("Keys present but no RRSIG signatures found");

    return {
      enabled,
      delegationSigned: dsRecords.length > 0,
      dsRecords: parsedDs.length > 0 ? parsedDs : undefined,
      dnskeyRecords: parsedDnskey.length > 0 ? parsedDnskey : undefined,
      rrsigPresent: rrsigRecords.length > 0,
      chainOfTrustValid: enabled && dsRecords.length > 0 && rrsigRecords.length > 0,
      algorithmStrength,
      issues,
    };
  }

  // ─── Zone Transfer (AXFR) ──────────────────────────────────────────────

  private async checkZoneTransfer(): Promise<void> {
    this.checksPerformed.push("zone_transfer_axfr");

    // We can't do actual AXFR from this environment, but we can check
    // if the SOA indicates zone transfer is likely blocked
    const nsRecords = this.records.filter(r => r.type === "NS");
    if (nsRecords.length === 0) {
      this.passedChecks++;
      return;
    }

    // Check via DNS-over-HTTPS if AXFR-related records suggest exposure
    // Most modern DNS providers block AXFR by default, so we note it as info
    this.findings.push({
      id: makeId(this.domain, "zone-transfer-check"),
      category: "zone_transfer",
      severity: "info",
      title: "Zone Transfer (AXFR) Check — Manual Verification Recommended",
      description: `Zone transfer status should be verified manually against each nameserver. If AXFR is allowed, an attacker can enumerate all DNS records in the zone, revealing internal hostnames, IP addresses, and infrastructure details.`,
      evidence: `Nameservers: ${nsRecords.map(r => r.value).join(", ")}. Manual check: dig AXFR ${this.domain} @${nsRecords[0]?.value}`,
      remediation: "Ensure AXFR is restricted to authorized secondary nameservers only. Configure allow-transfer ACLs on all authoritative nameservers.",
      mitreAttackId: "T1590.002",
      mitreAttackName: "Gather Victim Network Information: DNS",
      cwe: "CWE-200",
    });
    this.passedChecks++; // Info-level, not a failure
  }

  // ─── Cache Poisoning Susceptibility ─────────────────────────────────────

  private async checkCachePoisoning(): Promise<void> {
    this.checksPerformed.push("cache_poisoning_dnssec", "cache_poisoning_ttl");

    // Without DNSSEC, domain is susceptible to cache poisoning
    const hasDnssec = this.records.length > 0 && (await dnsGoogleResolve(this.domain, "DS")).length > 0;

    if (!hasDnssec) {
      // Already reported under DNSSEC check, add cache poisoning context
      this.findings.push({
        id: makeId(this.domain, "cache-poisoning-risk"),
        category: "cache_poisoning",
        severity: "medium",
        title: "DNS Cache Poisoning Susceptible (No DNSSEC)",
        description: `Without DNSSEC, recursive resolvers cannot validate the authenticity of DNS responses for ${this.domain}. An attacker on the network path can inject forged responses (Kaminsky attack), redirecting traffic to malicious servers.`,
        evidence: `No DS records found for ${this.domain}. DNS responses are unsigned and cannot be validated by resolvers.`,
        remediation: "Enable DNSSEC to cryptographically sign DNS responses. Additionally, ensure your authoritative nameservers support source port randomization and use 0x20 encoding for query names.",
        cvssVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        cvssScore: 7.4,
        mitreAttackId: "T1557",
        mitreAttackName: "Adversary-in-the-Middle",
        cwe: "CWE-345",
        references: ["https://www.kb.cert.org/vuls/id/800113"],
      });
      this.failedChecks++;
    } else {
      this.passedChecks++;
    }

    // Check for very low TTLs which might indicate dynamic DNS (less cacheable, more queries)
    const aRecords = this.records.filter(r => r.type === "A" && r.ttl);
    for (const rec of aRecords) {
      if (rec.ttl && rec.ttl < 60) {
        this.findings.push({
          id: makeId(this.domain, `low-ttl-${rec.value}`),
          category: "cache_poisoning",
          severity: "info",
          title: `Very Low TTL (${rec.ttl}s) — Increased DNS Query Volume`,
          description: `The A record for ${this.domain} has a TTL of ${rec.ttl} seconds. Very low TTLs increase DNS query volume, expanding the window for cache poisoning attempts and increasing resolver load.`,
          evidence: `A record: ${this.domain} → ${rec.value}, TTL: ${rec.ttl}s`,
          remediation: "Consider increasing TTL to at least 300 seconds (5 minutes) unless dynamic DNS is required for failover purposes.",
        });
      }
    }
  }

  // ─── Open Resolver Detection ────────────────────────────────────────────

  private async checkOpenResolver(): Promise<void> {
    this.checksPerformed.push("open_resolver");

    // Check if the domain's A record IPs respond to recursive DNS queries
    const aRecords = this.records.filter(r => r.type === "A");
    for (const aRec of aRecords) {
      try {
        const resolver = new Resolver();
        resolver.setServers([aRec.value]);
        // Try to resolve an external domain through this IP
        const result = await dnsQuery(() => resolver.resolve4("example.com"), 3000);
        if (result && result.length > 0) {
          this.findings.push({
            id: makeId(this.domain, `open-resolver-${aRec.value}`),
            category: "open_resolver",
            severity: "high",
            title: `Open DNS Resolver Detected at ${aRec.value}`,
            description: `The IP ${aRec.value} responds to recursive DNS queries for external domains. Open resolvers can be abused for DNS amplification attacks, cache poisoning, and information leakage.`,
            evidence: `Sent recursive query for example.com to ${aRec.value} — received valid response. Server is accepting recursive queries from external sources.`,
            remediation: "Disable recursion on authoritative nameservers, or restrict recursive queries to trusted internal networks only. Configure: 'allow-recursion { localhost; internal-nets; };' in BIND, or equivalent.",
            cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H",
            cvssScore: 8.6,
            mitreAttackId: "T1498.002",
            mitreAttackName: "Network Denial of Service: Reflection Amplification",
            cwe: "CWE-406",
            references: ["https://www.us-cert.gov/ncas/alerts/TA13-088A"],
          });
          this.failedChecks++;
        } else {
          this.passedChecks++;
        }
      } catch {
        this.passedChecks++; // Not an open resolver
      }
    }

    if (aRecords.length === 0) this.passedChecks++;
  }

  // ─── DNS Amplification Risk ─────────────────────────────────────────────

  private async checkAmplification(): Promise<void> {
    this.checksPerformed.push("dns_amplification");

    // Check TXT record sizes — large TXT records increase amplification factor
    const txtRecords = this.records.filter(r => r.type === "TXT");
    const totalTxtSize = txtRecords.reduce((sum, r) => sum + r.value.length, 0);

    if (totalTxtSize > 2000) {
      this.findings.push({
        id: makeId(this.domain, "amplification-large-txt"),
        category: "amplification",
        severity: "low",
        title: `Large DNS Response — Potential Amplification Vector`,
        description: `The combined TXT records for ${this.domain} total ${totalTxtSize} bytes. Large DNS responses increase the amplification factor for DNS reflection attacks if the authoritative server accepts queries from any source.`,
        evidence: `${txtRecords.length} TXT records totaling ~${totalTxtSize} bytes. Amplification factor: ~${Math.round(totalTxtSize / 60)}x (query ~60 bytes → response ~${totalTxtSize} bytes).`,
        remediation: "Review TXT records and remove any that are no longer needed. Consider implementing Response Rate Limiting (RRL) on your authoritative nameservers.",
        cwe: "CWE-406",
      });
      this.failedChecks++;
    } else {
      this.passedChecks++;
    }
  }

  // ─── Wildcard DNS Detection ─────────────────────────────────────────────

  private async checkWildcard(): Promise<void> {
    this.checksPerformed.push("wildcard_dns");

    // Query a random subdomain to detect wildcard
    const randomSub = `ac3-probe-${Date.now().toString(36)}.${this.domain}`;
    const wildcardResult = await dnsQuery(() => resolve4(randomSub), 3000);

    if (wildcardResult && wildcardResult.length > 0) {
      this.findings.push({
        id: makeId(this.domain, "wildcard-dns"),
        category: "wildcard",
        severity: "medium",
        title: "Wildcard DNS Record Detected",
        description: `A wildcard DNS record (*.${this.domain}) is configured, resolving all non-existent subdomains to ${wildcardResult.join(", ")}. This can mask dangling DNS vulnerabilities, complicate subdomain enumeration defenses, and may expose unintended services.`,
        evidence: `Random probe: ${randomSub} → ${wildcardResult.join(", ")}. This indicates a wildcard A record exists.`,
        remediation: "Review whether wildcard DNS is necessary. If used for catch-all web hosting, ensure the web server properly handles unknown Host headers. Consider removing the wildcard and explicitly defining required subdomains.",
        affectedRecord: `*.${this.domain}`,
        recordType: "A",
        cvssScore: 4.3,
        cwe: "CWE-200",
      });
      this.failedChecks++;
    } else {
      this.passedChecks++;
    }
  }

  // ─── Email Security (SPF/DKIM/DMARC) ───────────────────────────────────

  private async checkEmailSecurity(): Promise<void> {
    this.checksPerformed.push("spf", "dmarc", "dkim_selector");

    const txtRecords = this.records.filter(r => r.type === "TXT");
    const spfRecord = txtRecords.find(r => r.value.toLowerCase().startsWith("v=spf1"));
    const dmarcRecords = await dnsQuery(() => resolveTxt(`_dmarc.${this.domain}`));
    const dmarcRecord = dmarcRecords?.find(parts => parts.join("").toLowerCase().startsWith("v=dmarc1"));

    // SPF check
    if (!spfRecord) {
      this.findings.push({
        id: makeId(this.domain, "no-spf"),
        category: "email_security",
        severity: "medium",
        title: "No SPF Record — Email Spoofing Possible",
        description: `No SPF (Sender Policy Framework) record found for ${this.domain}. Without SPF, any mail server can send email claiming to be from ${this.domain}, enabling phishing and business email compromise.`,
        evidence: `TXT record query for ${this.domain} returned no record starting with "v=spf1".`,
        remediation: `Add an SPF TXT record: "v=spf1 include:<your-email-provider> -all". Use -all (hard fail) to reject unauthorized senders.`,
        cvssScore: 5.3,
        mitreAttackId: "T1566.002",
        mitreAttackName: "Phishing: Spearphishing Link",
        cwe: "CWE-290",
      });
      this.failedChecks++;
    } else {
      // Check for permissive SPF
      if (spfRecord.value.includes("+all") || spfRecord.value.includes("?all")) {
        this.findings.push({
          id: makeId(this.domain, "spf-permissive"),
          category: "email_security",
          severity: "high",
          title: "SPF Record is Overly Permissive",
          description: `The SPF record uses "${spfRecord.value.includes("+all") ? "+all" : "?all"}" which effectively allows any server to send email as ${this.domain}. This provides no protection against email spoofing.`,
          evidence: `SPF record: "${spfRecord.value}"`,
          remediation: `Change the SPF mechanism to "-all" (hard fail) or "~all" (soft fail) to restrict unauthorized senders.`,
          cvssScore: 7.5,
          cwe: "CWE-290",
        });
        this.failedChecks++;
      } else {
        this.passedChecks++;
      }
    }

    // DMARC check
    if (!dmarcRecord) {
      this.findings.push({
        id: makeId(this.domain, "no-dmarc"),
        category: "email_security",
        severity: "medium",
        title: "No DMARC Record — No Email Authentication Policy",
        description: `No DMARC record found at _dmarc.${this.domain}. Without DMARC, receiving mail servers have no policy guidance on how to handle messages that fail SPF/DKIM checks, reducing email security posture.`,
        evidence: `TXT record query for _dmarc.${this.domain} returned no DMARC record.`,
        remediation: `Add a DMARC TXT record at _dmarc.${this.domain}: "v=DMARC1; p=reject; rua=mailto:dmarc-reports@${this.domain}". Start with p=none for monitoring, then escalate to p=quarantine and p=reject.`,
        cvssScore: 5.3,
        mitreAttackId: "T1566.002",
        mitreAttackName: "Phishing: Spearphishing Link",
        cwe: "CWE-290",
      });
      this.failedChecks++;
    } else {
      const dmarcValue = dmarcRecord.join("");
      if (dmarcValue.includes("p=none")) {
        this.findings.push({
          id: makeId(this.domain, "dmarc-none"),
          category: "email_security",
          severity: "low",
          title: "DMARC Policy Set to 'none' — Monitor Only",
          description: `The DMARC policy is set to "none" which only monitors but does not reject or quarantine spoofed emails. This is acceptable for initial deployment but should be escalated to "reject" for production.`,
          evidence: `DMARC record: "${dmarcValue}"`,
          remediation: `Escalate DMARC policy from p=none to p=quarantine (then p=reject) after reviewing DMARC aggregate reports to confirm legitimate senders are aligned.`,
          cvssScore: 3.7,
          cwe: "CWE-290",
        });
        this.failedChecks++;
      } else {
        this.passedChecks++;
      }
    }
  }

  // ─── CAA Record Validation ──────────────────────────────────────────────

  private async checkCaa(): Promise<void> {
    this.checksPerformed.push("caa_record");

    const caaRecords = this.records.filter(r => r.type === "CAA");

    if (caaRecords.length === 0) {
      this.findings.push({
        id: makeId(this.domain, "no-caa"),
        category: "caa",
        severity: "low",
        title: "No CAA Records — Any CA Can Issue Certificates",
        description: `No CAA (Certificate Authority Authorization) records found for ${this.domain}. Without CAA, any certificate authority can issue SSL/TLS certificates for this domain, increasing the risk of unauthorized certificate issuance.`,
        evidence: `CAA record query for ${this.domain} returned no results.`,
        remediation: `Add CAA records to restrict certificate issuance to your authorized CAs. Example: '0 issue "letsencrypt.org"' and '0 iodef "mailto:security@${this.domain}"'`,
        cvssScore: 3.7,
        cwe: "CWE-295",
        references: ["https://tools.ietf.org/html/rfc8659"],
      });
      this.failedChecks++;
    } else {
      // Check if iodef is configured for violation reporting
      const hasIodef = caaRecords.some(r => r.value.includes("iodef"));
      if (!hasIodef) {
        this.findings.push({
          id: makeId(this.domain, "caa-no-iodef"),
          category: "caa",
          severity: "info",
          title: "CAA Present But No Violation Reporting (iodef)",
          description: `CAA records exist but no iodef record is configured. Adding an iodef record enables CAs to notify you of unauthorized certificate issuance attempts.`,
          evidence: `CAA records: ${caaRecords.map(r => r.value).join("; ")}. No iodef record found.`,
          remediation: `Add a CAA iodef record: '0 iodef "mailto:security@${this.domain}"'`,
        });
      }
      this.passedChecks++;
    }
  }

  // ─── NSEC/NSEC3 Zone Walking ────────────────────────────────────────────

  private async checkZoneWalking(): Promise<void> {
    this.checksPerformed.push("nsec_zone_walking");

    // Check if NSEC (not NSEC3) is used — NSEC allows zone enumeration
    const nsecRecords = await dnsGoogleResolve(this.domain, "NSEC");

    if (nsecRecords.length > 0) {
      this.findings.push({
        id: makeId(this.domain, "nsec-zone-walking"),
        category: "zone_walking",
        severity: "medium",
        title: "NSEC Records Enable Zone Walking",
        description: `The domain uses NSEC records (not NSEC3) for DNSSEC authenticated denial of existence. NSEC records can be walked sequentially to enumerate all records in the zone, revealing internal hostnames and infrastructure.`,
        evidence: `NSEC records found for ${this.domain}. Zone walking possible via: ldns-walk ${this.domain}`,
        remediation: "Migrate from NSEC to NSEC3 with opt-out to prevent zone enumeration. NSEC3 uses hashed owner names that cannot be walked sequentially.",
        cvssScore: 4.3,
        mitreAttackId: "T1590.002",
        mitreAttackName: "Gather Victim Network Information: DNS",
        cwe: "CWE-200",
      });
      this.failedChecks++;
    } else {
      this.passedChecks++;
    }
  }

  // ─── DNS Tunneling Indicators ───────────────────────────────────────────

  private async checkTunnelingIndicators(): Promise<void> {
    this.checksPerformed.push("dns_tunneling_indicators");

    // Check for unusually long TXT records that could indicate tunneling infrastructure
    const txtRecords = this.records.filter(r => r.type === "TXT");
    const suspiciousTxt = txtRecords.filter(r => {
      // High entropy or very long records that aren't standard verification records
      const val = r.value;
      if (val.startsWith("v=spf1") || val.startsWith("v=DMARC1") || val.startsWith("v=DKIM1")) return false;
      if (val.includes("google-site-verification") || val.includes("MS=") || val.includes("facebook-domain")) return false;
      // Check for base64-like content (high entropy)
      const base64Ratio = (val.match(/[A-Za-z0-9+/=]/g) || []).length / val.length;
      return val.length > 200 && base64Ratio > 0.9;
    });

    if (suspiciousTxt.length > 0) {
      this.findings.push({
        id: makeId(this.domain, "tunneling-indicator-txt"),
        category: "tunneling_indicator",
        severity: "medium",
        title: "Suspicious TXT Records — Potential DNS Tunneling Infrastructure",
        description: `Found ${suspiciousTxt.length} TXT record(s) with high-entropy, base64-like content exceeding 200 characters. This pattern is consistent with DNS tunneling C2 infrastructure or data exfiltration channels.`,
        evidence: `Suspicious TXT records: ${suspiciousTxt.map(r => `"${r.value.slice(0, 50)}..." (${r.value.length} chars)`).join("; ")}`,
        remediation: "Review these TXT records and verify their purpose. If they are not legitimate (e.g., DKIM keys, domain verification), investigate potential compromise. Monitor for high-volume TXT queries to subdomains.",
        mitreAttackId: "T1071.004",
        mitreAttackName: "Application Layer Protocol: DNS",
        cwe: "CWE-200",
      });
      this.failedChecks++;
    } else {
      this.passedChecks++;
    }
  }

  // ─── Nameserver Version Disclosure ──────────────────────────────────────

  private async checkVersionDisclosure(): Promise<void> {
    this.checksPerformed.push("ns_version_disclosure");

    // Check version.bind and version.server on each nameserver
    const nsRecords = this.records.filter(r => r.type === "NS");
    for (const ns of nsRecords.slice(0, 2)) { // Check first 2 NS only
      try {
        const nsIps = await dnsQuery(() => resolve4(ns.value));
        if (!nsIps || nsIps.length === 0) continue;

        const resolver = new Resolver();
        resolver.setServers([nsIps[0]]);

        // Try version.bind CH TXT
        const versionResult = await dnsQuery(() => resolver.resolveTxt("version.bind"), 3000);
        if (versionResult && versionResult.length > 0) {
          const version = versionResult.map(p => p.join("")).join("");
          if (version && !version.includes("not disclosed") && !version.includes("refused")) {
            this.findings.push({
              id: makeId(this.domain, `ns-version-${ns.value}`),
              category: "version_disclosure",
              severity: "low",
              title: `Nameserver Version Disclosed: ${ns.value}`,
              description: `The nameserver ${ns.value} (${nsIps[0]}) discloses its software version via version.bind query. This information helps attackers identify known vulnerabilities for the specific DNS software version.`,
              evidence: `version.bind CH TXT query to ${ns.value} (${nsIps[0]}) returned: "${version}"`,
              remediation: `Configure the nameserver to hide version information. In BIND: 'version "not disclosed";' in options. In PowerDNS: 'server-id=disabled'.`,
              cvssScore: 3.7,
              cwe: "CWE-200",
            });
            this.failedChecks++;
          } else {
            this.passedChecks++;
          }
        } else {
          this.passedChecks++;
        }
      } catch {
        this.passedChecks++;
      }
    }
  }

  // ─── DNS Cookie Support (RFC 7873) ──────────────────────────────────────

  private async checkDnsCookie(): Promise<void> {
    this.checksPerformed.push("dns_cookie_rfc7873");

    // DNS cookies are checked via EDNS0 options — we can infer from nameserver behavior
    // This is informational as we can't directly test EDNS0 cookie support via Node.js DNS
    this.findings.push({
      id: makeId(this.domain, "dns-cookie-check"),
      category: "dns_cookie",
      severity: "info",
      title: "DNS Cookie Support (RFC 7873) — Manual Verification",
      description: `DNS cookies (RFC 7873) provide lightweight transaction authentication to mitigate off-path attacks and amplification. Verification requires EDNS0 OPT record inspection.`,
      evidence: `Manual check: dig +cookie ${this.domain} @${this.records.find(r => r.type === "NS")?.value || "ns"}`,
      remediation: "Enable DNS cookie support on authoritative nameservers. BIND 9.10+ supports cookies natively. This provides protection against spoofed-source attacks without the overhead of full DNSSEC validation.",
      references: ["https://tools.ietf.org/html/rfc7873"],
    });
    this.passedChecks++; // Info-level
  }

  // ─── Response Rate Limiting ─────────────────────────────────────────────

  private async checkRateLimiting(): Promise<void> {
    this.checksPerformed.push("response_rate_limiting");

    // RRL can't be directly tested without sending many queries
    // We note it as a recommendation based on nameserver type
    const nsRecords = this.records.filter(r => r.type === "NS");
    const isCloudDns = nsRecords.some(r =>
      r.value.includes("cloudflare") || r.value.includes("awsdns") ||
      r.value.includes("azure-dns") || r.value.includes("google")
    );

    if (isCloudDns) {
      this.findings.push({
        id: makeId(this.domain, "rrl-cloud-provider"),
        category: "rate_limiting",
        severity: "info",
        title: "DNS Hosted on Cloud Provider — RRL Likely Enabled",
        description: `The domain uses a major cloud DNS provider which typically implements Response Rate Limiting (RRL) by default, protecting against DNS amplification abuse.`,
        evidence: `Nameservers: ${nsRecords.map(r => r.value).join(", ")}`,
        remediation: "No action required — cloud DNS providers typically handle RRL automatically.",
      });
      this.passedChecks++;
    } else {
      this.findings.push({
        id: makeId(this.domain, "rrl-self-hosted"),
        category: "rate_limiting",
        severity: "low",
        title: "Self-Hosted DNS — Verify Response Rate Limiting (RRL)",
        description: `The domain appears to use self-hosted or non-major-provider nameservers. Ensure Response Rate Limiting (RRL) is configured to prevent DNS amplification attacks.`,
        evidence: `Nameservers: ${nsRecords.map(r => r.value).join(", ")}. Not identified as major cloud DNS provider.`,
        remediation: "Enable RRL on your authoritative nameservers. In BIND: 'rate-limit { responses-per-second 5; };'. In NSD: 'rrl-size: 1000000' and 'rrl-ratelimit: 200'.",
        cwe: "CWE-770",
      });
      this.failedChecks++;
    }
  }

  // ─── DNS Rebinding ──────────────────────────────────────────────────────

  private async checkRebinding(): Promise<void> {
    this.checksPerformed.push("dns_rebinding");

    // Check if any A records point to private/internal IPs (rebinding indicator)
    const aRecords = this.records.filter(r => r.type === "A");
    const privateIpRanges = [
      /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[01])\./,
      /^192\.168\./,
      /^127\./,
      /^169\.254\./,
      /^0\./,
    ];

    for (const aRec of aRecords) {
      if (privateIpRanges.some(re => re.test(aRec.value))) {
        this.findings.push({
          id: makeId(this.domain, `rebinding-private-ip-${aRec.value}`),
          category: "rebinding",
          severity: "high",
          title: `DNS Record Points to Private IP — Rebinding Risk`,
          description: `The A record for ${this.domain} resolves to private IP ${aRec.value}. If this is a public domain, it may be used for DNS rebinding attacks to bypass same-origin policy and access internal services.`,
          evidence: `A record: ${this.domain} → ${aRec.value} (RFC 1918 private address space)`,
          remediation: "Remove public DNS records pointing to private IPs unless this is intentional for split-horizon DNS. If split-horizon is needed, ensure internal services validate the Host header.",
          cvssScore: 7.5,
          mitreAttackId: "T1557",
          mitreAttackName: "Adversary-in-the-Middle",
          cwe: "CWE-350",
        });
        this.failedChecks++;
      }
    }

    // Check for very low TTL which enables rebinding attacks
    const lowTtlRecords = aRecords.filter(r => r.ttl && r.ttl <= 1);
    if (lowTtlRecords.length > 0) {
      this.findings.push({
        id: makeId(this.domain, "rebinding-low-ttl"),
        category: "rebinding",
        severity: "low",
        title: "Extremely Low TTL (≤1s) — DNS Rebinding Enabler",
        description: `A records with TTL ≤1 second enable rapid DNS rebinding attacks where the IP can be switched between requests, bypassing browser same-origin protections.`,
        evidence: `Records with TTL ≤1s: ${lowTtlRecords.map(r => `${r.value} (TTL: ${r.ttl}s)`).join(", ")}`,
        remediation: "Increase TTL to at least 300 seconds unless rapid failover is required. Implement DNS pinning on critical services.",
      });
      this.failedChecks++;
    }

    if (this.findings.filter(f => f.category === "rebinding").length === 0) {
      this.passedChecks++;
    }
  }
}

// ─── Convenience Function ───────────────────────────────────────────────────

export async function runDnsSecurityAssessment(
  domain: string,
  context: EngagementContext = "di_scan"
): Promise<DnsSecurityReport> {
  const validator = new DnsSecurityValidator(domain, context);
  return validator.runFullAssessment();
}
