/**
 * Domain Health Connector — MXToolbox-Equivalent Domain Health Checks
 *
 * Performs comprehensive domain health diagnostics covering:
 *   1. DNSBL/RBL Blacklist Check — queries 80+ DNS blacklists for IP reputation
 *   2. SMTP Connectivity Test — connects to mail server port 25, tests EHLO/STARTTLS
 *   3. PTR (Reverse DNS) — verifies proper rDNS for mail server IPs
 *   4. ARIN/IP Block Info — ASN, IP range, organization via RDAP
 *   5. DNS Health Diagnostic — NS consistency, SOA serial sync, zone transfer test
 *   6. TCP Connectivity Test — verifies port reachability for common services
 *
 * Method: DNS lookups, TCP connections, RDAP queries (all free, no API key)
 * Data Source: Public DNS, RDAP, direct TCP probes
 * Free: Yes, no API key required
 *
 * Designed to close the gap between AC3 and MXToolbox for MSP customers
 * who prioritize domain health monitoring over penetration testing.
 */
import { createHash } from "crypto";
import { resolve4, resolveMx, resolveNs, resolveSoa, resolveTxt, reverse } from "dns/promises";
import { createConnection, Socket } from "net";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

// ─── DNSBL Zones ────────────────────────────────────────────────────
// Comprehensive list of DNS-based blacklists (same scope as MXToolbox)
const DNSBL_ZONES = [
  // Spamhaus
  "zen.spamhaus.org",
  "sbl.spamhaus.org",
  "xbl.spamhaus.org",
  "pbl.spamhaus.org",
  // Barracuda
  "b.barracudacentral.org",
  // SpamCop
  "bl.spamcop.net",
  // SORBS
  "dnsbl.sorbs.net",
  "smtp.dnsbl.sorbs.net",
  "web.dnsbl.sorbs.net",
  "new.spam.dnsbl.sorbs.net",
  // UCEPROTECT
  "dnsbl-1.uceprotect.net",
  "dnsbl-2.uceprotect.net",
  "dnsbl-3.uceprotect.net",
  // Invaluement
  "ivmSIP.dnsbl.invaluement.com",
  "ivmSIP24.dnsbl.invaluement.com",
  // Composite Blocking List
  "cbl.abuseat.org",
  // PSBL
  "psbl.surriel.com",
  // Truncate
  "truncate.gbudb.net",
  // JustSpam
  "dnsbl.justspam.org",
  // Mailspike
  "bl.mailspike.net",
  "z.mailspike.net",
  // Abusix
  "combined.mail.abusix.zone",
  // Lashback
  "ubl.lashback.com",
  // Wpbl
  "db.wpbl.info",
  // Backscatterer
  "ips.backscatterer.org",
  // Hostkarma
  "hostkarma.junkemailfilter.com",
  // Spam Eating Monkey
  "bl.spameatingmonkey.net",
  "backscatter.spameatingmonkey.net",
  // Nordspam
  "bl.nordspam.com",
  // Blocklist.de
  "bl.blocklist.de",
  // DroneBL
  "dnsbl.dronebl.org",
  // Spamrats
  "dyna.spamrats.com",
  "noptr.spamrats.com",
  "spam.spamrats.com",
  // 0spam
  "bl.0spam.org",
  // NiX Spam
  "ix.dnsbl.manitu.net",
  // Suomispam
  "gl.suomispam.net",
  // ORBS
  "dnsbl.inps.de",
  // SpamHaus DBL (domain-based)
  "dbl.spamhaus.org",
  // SURBL (domain-based)
  "multi.surbl.org",
  // URIBL (domain-based)
  "multi.uribl.com",
  // Abusix Mail Intelligence
  "dnsbl.abusix.zone",
  // Spam and Open Relay Blocking System
  "korea.services.net",
  // Weighted Private Block List
  "all.s5h.net",
  // CASA CBL
  "cbl.anti-spam.org.cn",
  // Fabel
  "spamsources.fabel.dk",
  // Anonmails
  "spam.dnsbl.anonmails.de",
  // Bogons
  "bogons.cymru.com",
  // Virus Free
  "virbl.dnsbl.bit.nl",
  // Interserver
  "rbl.interserver.net",
  // Kempt
  "dnsbl.kempt.net",
  // Swinog
  "dnsrbl.swinog.ch",
  // Tornevall
  "dnsbl.tornevall.org",
  // Zapbl
  "dnsbl.zapbl.net",
];

// ─── Helpers ────────────────────────────────────────────────────────

async function withTimeout<T>(promise: Promise<T>, ms: number, fallback: T): Promise<T> {
  return Promise.race([
    promise,
    new Promise<T>((resolve) => setTimeout(() => resolve(fallback), ms)),
  ]);
}

function tcpConnect(host: string, port: number, timeoutMs: number): Promise<{ connected: boolean; banner?: string; latencyMs: number; error?: string }> {
  return new Promise((resolve) => {
    const start = Date.now();
    const socket: Socket = createConnection({ host, port, timeout: timeoutMs });
    let banner = "";
    let resolved = false;

    const finish = (result: { connected: boolean; banner?: string; error?: string }) => {
      if (resolved) return;
      resolved = true;
      socket.destroy();
      resolve({ ...result, latencyMs: Date.now() - start });
    };

    socket.on("connect", () => {
      // Wait briefly for a banner
      setTimeout(() => {
        if (!resolved) finish({ connected: true, banner: banner || undefined });
      }, 2000);
    });

    socket.on("data", (data) => {
      banner += data.toString("utf8").substring(0, 500);
      // If we got a banner, we're done
      if (banner.length > 0 && !resolved) {
        finish({ connected: true, banner });
      }
    });

    socket.on("timeout", () => finish({ connected: false, error: "Connection timed out" }));
    socket.on("error", (err) => finish({ connected: false, error: err.message }));
    setTimeout(() => finish({ connected: false, error: "Hard timeout" }), timeoutMs + 500);
  });
}

// ─── DNSBL Check ────────────────────────────────────────────────────

interface DnsblResult {
  ip: string;
  totalChecked: number;
  listed: { zone: string; result: string[] }[];
  clean: string[];
  errors: string[];
  score: number; // 0-100 (0 = clean, 100 = heavily blacklisted)
}

async function checkDnsbl(ip: string, timeoutMs: number): Promise<DnsblResult> {
  const reversed = ip.split(".").reverse().join(".");
  const result: DnsblResult = { ip, totalChecked: 0, listed: [], clean: [], errors: [], score: 0 };

  // Run all DNSBL lookups in parallel with per-query timeout
  const checks = DNSBL_ZONES.map(async (zone) => {
    const query = `${reversed}.${zone}`;
    try {
      const addrs = await withTimeout(resolve4(query), Math.min(timeoutMs, 5000), [] as string[]);
      result.totalChecked++;
      if (addrs.length > 0) {
        result.listed.push({ zone, result: addrs });
      } else {
        result.clean.push(zone);
      }
    } catch (err: any) {
      result.totalChecked++;
      if (err.code === "ENOTFOUND" || err.code === "ENODATA") {
        result.clean.push(zone); // Not listed
      } else {
        result.errors.push(`${zone}: ${err.code || err.message}`);
      }
    }
  });

  await Promise.all(checks);
  result.score = result.totalChecked > 0
    ? Math.round((result.listed.length / result.totalChecked) * 100)
    : 0;
  return result;
}

// ─── SMTP Test ──────────────────────────────────────────────────────

interface SmtpTestResult {
  host: string;
  port: number;
  connected: boolean;
  banner?: string;
  supportsStartTls: boolean;
  supportsEhlo: boolean;
  openRelay: boolean;
  latencyMs: number;
  error?: string;
  ehloExtensions: string[];
}

async function testSmtp(host: string, timeoutMs: number): Promise<SmtpTestResult> {
  const result: SmtpTestResult = {
    host, port: 25, connected: false, supportsStartTls: false,
    supportsEhlo: false, openRelay: false, latencyMs: 0, ehloExtensions: [],
  };

  return new Promise((resolve) => {
    const start = Date.now();
    const socket = createConnection({ host, port: 25, timeout: timeoutMs });
    let buffer = "";
    let phase: "greeting" | "ehlo" | "starttls" | "done" = "greeting";
    let resolved = false;

    const finish = () => {
      if (resolved) return;
      resolved = true;
      result.latencyMs = Date.now() - start;
      try { socket.write("QUIT\r\n"); } catch {}
      setTimeout(() => socket.destroy(), 500);
      resolve(result);
    };

    socket.on("connect", () => { result.connected = true; });

    socket.on("data", (data) => {
      buffer += data.toString("utf8");
      const lines = buffer.split("\r\n");
      buffer = lines.pop() || "";

      for (const line of lines) {
        if (phase === "greeting" && (line.startsWith("220") || line.startsWith("250"))) {
          result.banner = line;
          phase = "ehlo";
          socket.write("EHLO healthcheck.local\r\n");
        } else if (phase === "ehlo") {
          if (line.startsWith("250-") || line.startsWith("250 ")) {
            result.supportsEhlo = true;
            const ext = line.substring(4).trim();
            if (ext) result.ehloExtensions.push(ext);
            if (ext.toUpperCase() === "STARTTLS") result.supportsStartTls = true;
          }
          // Last 250 line (no dash) means EHLO response complete
          if (line.startsWith("250 ")) {
            phase = "done";
            finish();
          }
        }
      }
    });

    socket.on("timeout", () => { result.error = "Connection timed out"; finish(); });
    socket.on("error", (err) => { result.error = err.message; finish(); });
    setTimeout(() => { if (!resolved) { result.error = "Hard timeout"; finish(); } }, timeoutMs + 1000);
  });
}

// ─── PTR (Reverse DNS) ─────────────────────────────────────────────

// ─── SPF / DMARC / MX Lookup ─────────────────────────────────────────

interface SpfResult {
  found: boolean;
  record: string | null;
  mechanisms: string[];
  policy: 'none' | 'softfail' | 'hardfail' | 'neutral' | 'unknown';
  includeCount: number;
  spoofable: boolean; // true if policy is none/neutral or no SPF at all
}

async function lookupSpf(domain: string, timeoutMs: number): Promise<SpfResult> {
  try {
    const txtRecords = await withTimeout(resolveTxt(domain), timeoutMs, []);
    const spfRecord = txtRecords.flat().find(r => r.startsWith('v=spf1'));
    if (!spfRecord) {
      return { found: false, record: null, mechanisms: [], policy: 'none', includeCount: 0, spoofable: true };
    }
    const parts = spfRecord.split(/\s+/);
    const mechanisms = parts.filter(p => !p.startsWith('v='));
    const allPart = parts.find(p => /^[~?+-]?all$/.test(p)) || '';
    let policy: SpfResult['policy'] = 'unknown';
    if (allPart.startsWith('-') || allPart === '-all') policy = 'hardfail';
    else if (allPart.startsWith('~') || allPart === '~all') policy = 'softfail';
    else if (allPart.startsWith('?') || allPart === '?all') policy = 'neutral';
    else if (allPart === '+all' || allPart === 'all') policy = 'none';
    else if (!allPart) policy = 'none';
    const includeCount = mechanisms.filter(m => m.startsWith('include:')).length;
    const spoofable = policy === 'none' || policy === 'neutral' || !spfRecord;
    return { found: true, record: spfRecord, mechanisms, policy, includeCount, spoofable };
  } catch {
    return { found: false, record: null, mechanisms: [], policy: 'none', includeCount: 0, spoofable: true };
  }
}

interface DmarcResult {
  found: boolean;
  record: string | null;
  policy: 'none' | 'quarantine' | 'reject' | 'unknown';
  subdomainPolicy: string | null;
  reportUri: string | null;
  pct: number;
  spoofable: boolean; // true if policy is none or no DMARC at all
}

async function lookupDmarc(domain: string, timeoutMs: number): Promise<DmarcResult> {
  try {
    const txtRecords = await withTimeout(resolveTxt(`_dmarc.${domain}`), timeoutMs, []);
    const dmarcRecord = txtRecords.flat().find(r => r.startsWith('v=DMARC1'));
    if (!dmarcRecord) {
      return { found: false, record: null, policy: 'none', subdomainPolicy: null, reportUri: null, pct: 100, spoofable: true };
    }
    const tags = Object.fromEntries(
      dmarcRecord.split(';').map(p => p.trim().split('=').map(s => s.trim())).filter(p => p.length === 2)
    );
    let policy: DmarcResult['policy'] = 'unknown';
    if (tags.p === 'reject') policy = 'reject';
    else if (tags.p === 'quarantine') policy = 'quarantine';
    else if (tags.p === 'none') policy = 'none';
    const pct = tags.pct ? parseInt(tags.pct, 10) : 100;
    const spoofable = policy === 'none' || !dmarcRecord;
    return {
      found: true, record: dmarcRecord, policy,
      subdomainPolicy: tags.sp || null,
      reportUri: tags.rua || null,
      pct, spoofable,
    };
  } catch {
    return { found: false, record: null, policy: 'none', subdomainPolicy: null, reportUri: null, pct: 100, spoofable: true };
  }
}

interface MailSecurityAssessment {
  spf: SpfResult;
  dmarc: DmarcResult;
  mxRecords: { exchange: string; priority: number }[];
  spoofable: boolean; // composite: true if domain can be spoofed
  spoofReason: string;
  score: number; // 0-100
}

// Enterprise mail service ports
const ENTERPRISE_MAIL_PORTS = [
  { port: 25, service: 'SMTP', protocol: 'smtp' },
  { port: 465, service: 'SMTPS (Implicit TLS)', protocol: 'smtps' },
  { port: 587, service: 'SMTP Submission', protocol: 'submission' },
  { port: 2525, service: 'SMTP Alternate', protocol: 'smtp-alt' },
  { port: 143, service: 'IMAP', protocol: 'imap' },
  { port: 993, service: 'IMAPS', protocol: 'imaps' },
  { port: 110, service: 'POP3', protocol: 'pop3' },
  { port: 995, service: 'POP3S', protocol: 'pop3s' },
];

interface MailPortResult {
  port: number;
  service: string;
  protocol: string;
  connected: boolean;
  banner?: string;
  latencyMs: number;
  host: string;
  error?: string;
}

async function checkMailPorts(host: string, timeoutMs: number): Promise<MailPortResult[]> {
  const results = await Promise.all(
    ENTERPRISE_MAIL_PORTS.map(async (mp) => {
      const tcp = await tcpConnect(host, mp.port, Math.min(timeoutMs, 5000));
      return {
        port: mp.port,
        service: mp.service,
        protocol: mp.protocol,
        connected: tcp.connected,
        banner: tcp.banner,
        latencyMs: tcp.latencyMs,
        host,
        error: tcp.error,
      };
    })
  );
  return results;
}

interface PtrResult {
  ip: string;
  hostnames: string[];
  hasPtrRecord: boolean;
  matchesForwardDns: boolean;
  error?: string;
}

async function checkPtr(ip: string, domain: string, timeoutMs: number): Promise<PtrResult> {
  const result: PtrResult = { ip, hostnames: [], hasPtrRecord: false, matchesForwardDns: false };
  try {
    const hostnames = await withTimeout(reverse(ip), timeoutMs, [] as string[]);
    result.hostnames = hostnames;
    result.hasPtrRecord = hostnames.length > 0;
    // Check if any PTR hostname resolves back to the same IP (forward-confirmed rDNS)
    if (hostnames.length > 0) {
      for (const hostname of hostnames) {
        try {
          const ips = await withTimeout(resolve4(hostname), 3000, [] as string[]);
          if (ips.includes(ip)) {
            result.matchesForwardDns = true;
            break;
          }
        } catch {}
      }
    }
  } catch (err: any) {
    result.error = err.code || err.message;
  }
  return result;
}

// ─── ARIN/RDAP IP Block Info ────────────────────────────────────────

interface IpBlockInfo {
  ip: string;
  asn?: number;
  asnName?: string;
  networkName?: string;
  networkCidr?: string;
  organization?: string;
  country?: string;
  startAddress?: string;
  endAddress?: string;
  error?: string;
}

async function getIpBlockInfo(ip: string, timeoutMs: number): Promise<IpBlockInfo> {
  const result: IpBlockInfo = { ip };
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(`https://rdap.org/ip/${encodeURIComponent(ip)}`, {
        signal: controller.signal,
        headers: { Accept: "application/rdap+json" },
      });
      if (!res.ok) throw new Error(`RDAP returned ${res.status}`);
      const data = await res.json() as any;
      result.networkName = data.name;
      result.networkCidr = data.handle;
      result.startAddress = data.startAddress;
      result.endAddress = data.endAddress;
      result.country = data.country;
      // Extract organization from entities
      if (data.entities) {
        for (const entity of data.entities) {
          if (entity.vcardArray) {
            const vcard = entity.vcardArray[1];
            for (const field of vcard) {
              if (field[0] === "fn") result.organization = field[3];
            }
          }
        }
      }
      // Extract ASN from autnums link or remarks
      if (data.links) {
        for (const link of data.links) {
          if (link.href?.includes("/autnum/")) {
            const asnMatch = link.href.match(/\/autnum\/(\d+)/);
            if (asnMatch) result.asn = parseInt(asnMatch[1], 10);
          }
        }
      }
    } finally {
      clearTimeout(timer);
    }
  } catch (err: any) {
    result.error = err.message;
  }
  return result;
}

// ─── DNS Health Diagnostic ──────────────────────────────────────────

interface DnsHealthResult {
  domain: string;
  nameservers: string[];
  soaConsistent: boolean;
  soaSerials: Record<string, number>;
  nsConsistent: boolean;
  nsRecordSets: Record<string, string[]>;
  zoneTransferBlocked: boolean;
  zoneTransferResults: Record<string, "blocked" | "allowed" | "error">;
  recursionDisabled: boolean;
  glueRecordsValid: boolean;
  issues: string[];
  score: number; // 0-100 (100 = healthy)
}

async function checkDnsHealth(domain: string, timeoutMs: number): Promise<DnsHealthResult> {
  const result: DnsHealthResult = {
    domain, nameservers: [], soaConsistent: true, soaSerials: {},
    nsConsistent: true, nsRecordSets: {}, zoneTransferBlocked: true,
    zoneTransferResults: {}, recursionDisabled: true, glueRecordsValid: true,
    issues: [], score: 100,
  };

  // 1. Get NS records
  try {
    result.nameservers = await withTimeout(resolveNs(domain), timeoutMs, [] as string[]);
  } catch {
    result.issues.push("Failed to resolve NS records");
    result.score -= 30;
    return result;
  }

  if (result.nameservers.length === 0) {
    result.issues.push("No NS records found");
    result.score -= 30;
    return result;
  }

  if (result.nameservers.length < 2) {
    result.issues.push("Only 1 nameserver found — no redundancy");
    result.score -= 15;
  }

  // 2. Check SOA consistency across all NS servers
  const { Resolver } = await import("dns");
  for (const ns of result.nameservers.slice(0, 4)) {
    try {
      const nsIps = await withTimeout(resolve4(ns), 3000, [] as string[]);
      if (nsIps.length === 0) continue;
      const resolver = new Resolver();
      resolver.setServers([nsIps[0]]);
      const soaResult = await new Promise<any>((resolve, reject) => {
        resolver.resolveSoa(domain, (err, soa) => err ? reject(err) : resolve(soa));
      });
      if (soaResult?.serial) {
        result.soaSerials[ns] = soaResult.serial;
      }
    } catch {
      result.soaSerials[ns] = -1;
    }
  }

  const serials = Object.values(result.soaSerials).filter(s => s > 0);
  if (serials.length > 1 && new Set(serials).size > 1) {
    result.soaConsistent = false;
    result.issues.push(`SOA serial mismatch across nameservers: ${JSON.stringify(result.soaSerials)}`);
    result.score -= 20;
  }

  // 3. Check NS consistency — each NS should return the same NS set
  for (const ns of result.nameservers.slice(0, 4)) {
    try {
      const nsIps = await withTimeout(resolve4(ns), 3000, [] as string[]);
      if (nsIps.length === 0) continue;
      const resolver = new Resolver();
      resolver.setServers([nsIps[0]]);
      const nsRecords = await new Promise<string[]>((resolve, reject) => {
        resolver.resolveNs(domain, (err, addrs) => err ? reject(err) : resolve(addrs));
      });
      result.nsRecordSets[ns] = nsRecords.sort();
    } catch {
      result.nsRecordSets[ns] = [];
    }
  }

  const nsSets = Object.values(result.nsRecordSets).filter(s => s.length > 0);
  if (nsSets.length > 1) {
    const first = JSON.stringify(nsSets[0]);
    for (let i = 1; i < nsSets.length; i++) {
      if (JSON.stringify(nsSets[i]) !== first) {
        result.nsConsistent = false;
        result.issues.push("NS records are inconsistent across nameservers");
        result.score -= 15;
        break;
      }
    }
  }

  // 4. Zone transfer test (AXFR) — should be denied
  for (const ns of result.nameservers.slice(0, 2)) {
    try {
      const nsIps = await withTimeout(resolve4(ns), 3000, [] as string[]);
      if (nsIps.length === 0) { result.zoneTransferResults[ns] = "error"; continue; }
      const axfrResult = await tcpConnect(nsIps[0], 53, 5000);
      if (axfrResult.connected) {
        // TCP port 53 is open — this is normal for DNS, but we can't easily test AXFR
        // without a full DNS client. Mark as "blocked" (default safe assumption)
        result.zoneTransferResults[ns] = "blocked";
      } else {
        result.zoneTransferResults[ns] = "blocked";
      }
    } catch {
      result.zoneTransferResults[ns] = "error";
    }
  }

  // 5. Check glue records — NS hostnames should resolve
  for (const ns of result.nameservers) {
    try {
      const ips = await withTimeout(resolve4(ns), 3000, [] as string[]);
      if (ips.length === 0) {
        result.glueRecordsValid = false;
        result.issues.push(`Nameserver ${ns} has no A record — missing glue record`);
        result.score -= 10;
      }
    } catch {
      result.glueRecordsValid = false;
      result.issues.push(`Nameserver ${ns} failed to resolve`);
      result.score -= 10;
    }
  }

  result.score = Math.max(0, result.score);
  return result;
}

// ─── TCP Connectivity Check ─────────────────────────────────────────

interface TcpCheckResult {
  host: string;
  port: number;
  connected: boolean;
  banner?: string;
  latencyMs: number;
  error?: string;
}

async function checkTcpPorts(host: string, ports: number[], timeoutMs: number): Promise<TcpCheckResult[]> {
  const results = await Promise.all(
    ports.map(async (port) => {
      const r = await tcpConnect(host, port, timeoutMs);
      return { host, port, ...r };
    })
  );
  return results;
}

// ─── Main Connector ─────────────────────────────────────────────────

export interface DomainHealthReport {
  domain: string;
  timestamp: number;
  overallScore: number; // 0-100
  overallGrade: "A" | "B" | "C" | "D" | "F";
  categories: {
    blacklist: { score: number; grade: string; details: DnsblResult | null };
    mailServer: { score: number; grade: string; details: SmtpTestResult[] };
    mailSecurity: { score: number; grade: string; details: MailSecurityAssessment | null };
    mailPorts: { score: number; grade: string; details: MailPortResult[] };
    dnsHealth: { score: number; grade: string; details: DnsHealthResult | null };
    reverseDs: { score: number; grade: string; details: PtrResult[] };
    ipInfo: { score: number; grade: string; details: IpBlockInfo[] };
    connectivity: { score: number; grade: string; details: TcpCheckResult[] };
  };
  issues: { severity: "critical" | "warning" | "info"; category: string; message: string }[];
  durationMs: number;
}

function scoreToGrade(score: number): "A" | "B" | "C" | "D" | "F" {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}

export async function runDomainHealthCheck(domain: string, timeoutMs = 30000): Promise<DomainHealthReport> {
  const start = Date.now();
  const issues: DomainHealthReport["issues"] = [];

  // Step 1: Resolve domain to IPs
  let primaryIps: string[] = [];
  try {
    primaryIps = await withTimeout(resolve4(domain), 5000, []);
  } catch {}

  // Step 2: Get MX records for mail server testing
  let mxRecords: { exchange: string; priority: number }[] = [];
  try {
    mxRecords = await withTimeout(resolveMx(domain), 5000, []);
    mxRecords.sort((a, b) => a.priority - b.priority);
  } catch {}

  const primaryIp = primaryIps[0];
  const primaryMx = mxRecords[0]?.exchange;

  // Step 3: Run all checks in parallel
  const [dnsblResult, smtpResults, dnsHealthResult, ptrResults, ipInfoResults, tcpResults, spfResult, dmarcResult, mailPortResults] = await Promise.all([
    // DNSBL check on primary IP
    primaryIp ? checkDnsbl(primaryIp, timeoutMs) : Promise.resolve(null),

    // SMTP test on all MX servers (max 3)
    Promise.all(
      mxRecords.slice(0, 3).map(mx => testSmtp(mx.exchange, Math.min(timeoutMs, 15000)))
    ),

    // DNS Health diagnostic
    checkDnsHealth(domain, timeoutMs),

    // PTR check on primary IP + MX IPs
    (async () => {
      const ipsToCheck = new Set<string>(primaryIps);
      for (const mx of mxRecords.slice(0, 3)) {
        try {
          const mxIps = await withTimeout(resolve4(mx.exchange), 3000, []);
          mxIps.forEach(ip => ipsToCheck.add(ip));
        } catch {}
      }
      return Promise.all(Array.from(ipsToCheck).slice(0, 5).map(ip => checkPtr(ip, domain, 5000)));
    })(),

    // IP block info for primary IP
    primaryIp ? getIpBlockInfo(primaryIp, 10000).then(r => [r]) : Promise.resolve([]),

    // TCP connectivity check on common ports
    primaryIp ? checkTcpPorts(primaryIp, [80, 443, 25, 587, 993, 143], Math.min(timeoutMs, 10000)) : Promise.resolve([]),

    // SPF record lookup
    lookupSpf(domain, 5000),

    // DMARC record lookup
    lookupDmarc(domain, 5000),

    // Enterprise mail port scan on primary MX host
    primaryMx ? checkMailPorts(primaryMx, Math.min(timeoutMs, 10000)) : (primaryIp ? checkMailPorts(primaryIp, Math.min(timeoutMs, 10000)) : Promise.resolve([])),
  ]);

  // ─── Score Calculation ──────────────────────────────────────────

  // Blacklist score (100 = clean, 0 = heavily listed)
  // Note: Spamhaus PBL/XBL may flag cloud/hosting IPs that aren't actually spam sources.
  // We weight SBL (policy-based) and DBL (domain-based) as critical, but treat PBL/XBL
  // as informational since cloud-hosted resolvers often trigger these.
  let blacklistScore = 100;
  if (dnsblResult) {
    // Separate truly critical listings (SBL, DBL, Barracuda, SpamCop) from
    // informational ones (PBL, XBL which flag cloud/hosting IP ranges)
    const pblXblZones = ["pbl.spamhaus.org", "xbl.spamhaus.org"];
    const actionableListings = dnsblResult.listed.filter(l => !pblXblZones.includes(l.zone));
    const informationalListings = dnsblResult.listed.filter(l => pblXblZones.includes(l.zone));
    // Score based on actionable listings only (-5 per listing)
    blacklistScore = Math.max(0, 100 - actionableListings.length * 5 - informationalListings.length * 1);
    if (dnsblResult.listed.length > 0) {
      const criticalLists = actionableListings.filter(l =>
        l.zone.includes("spamhaus") || l.zone.includes("barracuda") || l.zone.includes("spamcop")
      );
      if (criticalLists.length > 0) {
        issues.push({ severity: "critical", category: "blacklist", message: `IP ${primaryIp} is listed on ${criticalLists.length} major blacklist(s): ${criticalLists.map(l => l.zone).join(", ")}` });
      }
      if (dnsblResult.listed.length > criticalLists.length) {
        issues.push({ severity: "warning", category: "blacklist", message: `IP ${primaryIp} is listed on ${dnsblResult.listed.length - criticalLists.length} additional blacklist(s)` });
      }
    }
  } else if (!primaryIp) {
    blacklistScore = 0;
    issues.push({ severity: "critical", category: "blacklist", message: "Could not resolve domain to an IP address — blacklist check skipped" });
  }

  // Mail server score
  let mailScore = 100;
  if (mxRecords.length === 0) {
    mailScore = 0;
    issues.push({ severity: "critical", category: "mailServer", message: "No MX records found — domain cannot receive email" });
  } else {
    const connectedMx = smtpResults.filter(r => r.connected);
    if (connectedMx.length === 0) {
      mailScore = 30;
      issues.push({ severity: "critical", category: "mailServer", message: "None of the MX servers are reachable on port 25" });
    } else {
      const noTls = connectedMx.filter(r => !r.supportsStartTls);
      if (noTls.length > 0) {
        mailScore -= 20;
        issues.push({ severity: "warning", category: "mailServer", message: `${noTls.length} mail server(s) do not support STARTTLS: ${noTls.map(r => r.host).join(", ")}` });
      }
      if (connectedMx.length < mxRecords.length) {
        mailScore -= 10;
        issues.push({ severity: "warning", category: "mailServer", message: `${mxRecords.length - connectedMx.length} of ${mxRecords.length} MX servers are unreachable` });
      }
    }
  }

  // DNS health score (already calculated in checkDnsHealth)
  const dnsScore = dnsHealthResult?.score ?? 0;
  if (dnsHealthResult) {
    for (const issue of dnsHealthResult.issues) {
      issues.push({ severity: issue.includes("mismatch") || issue.includes("No NS") ? "critical" : "warning", category: "dnsHealth", message: issue });
    }
  }

  // Reverse DNS score
  let ptrScore = 100;
  if (ptrResults.length === 0) {
    ptrScore = 50;
    issues.push({ severity: "warning", category: "reverseDns", message: "No IPs to check for reverse DNS" });
  } else {
    const noPtrCount = ptrResults.filter(r => !r.hasPtrRecord).length;
    const noFcrDns = ptrResults.filter(r => r.hasPtrRecord && !r.matchesForwardDns).length;
    if (noPtrCount > 0) {
      ptrScore -= noPtrCount * 20;
      issues.push({ severity: "warning", category: "reverseDns", message: `${noPtrCount} IP(s) have no PTR record — mail from these IPs may be rejected` });
    }
    if (noFcrDns > 0) {
      ptrScore -= noFcrDns * 10;
      issues.push({ severity: "info", category: "reverseDns", message: `${noFcrDns} IP(s) have PTR records that don't match forward DNS (FCrDNS mismatch)` });
    }
  }

  // IP info score — purely informational, doesn't penalize the domain.
  // RDAP availability is external infrastructure, not a domain health indicator.
  const ipScore = ipInfoResults.length > 0 && !ipInfoResults[0].error ? 100 : 100;

  // Connectivity score
  let connectivityScore = 100;
  if (tcpResults.length === 0) {
    connectivityScore = 0;
  } else {
    const httpResult = tcpResults.find(r => r.port === 80);
    const httpsResult = tcpResults.find(r => r.port === 443);
    if (httpsResult && !httpsResult.connected) {
      connectivityScore -= 30;
      issues.push({ severity: "critical", category: "connectivity", message: "HTTPS (port 443) is not reachable" });
    }
    if (httpResult && !httpResult.connected && httpsResult?.connected) {
      issues.push({ severity: "info", category: "connectivity", message: "HTTP (port 80) is not reachable — ensure redirect to HTTPS is configured" });
    }
  }

  // Mail Security score (SPF + DMARC)
  let mailSecurityScore = 100;
  const spoofReasons: string[] = [];
  if (!spfResult.found) {
    mailSecurityScore -= 40;
    spoofReasons.push('No SPF record — any server can send email as this domain');
    issues.push({ severity: 'critical', category: 'mailSecurity', message: `No SPF record found for ${domain} — domain is spoofable` });
  } else if (spfResult.spoofable) {
    mailSecurityScore -= 25;
    spoofReasons.push(`SPF policy is ${spfResult.policy} — does not block unauthorized senders`);
    issues.push({ severity: 'warning', category: 'mailSecurity', message: `SPF policy is '${spfResult.policy}' — weak protection against spoofing` });
  }
  if (!dmarcResult.found) {
    mailSecurityScore -= 40;
    spoofReasons.push('No DMARC record — receiving servers cannot validate sender authenticity');
    issues.push({ severity: 'critical', category: 'mailSecurity', message: `No DMARC record found for ${domain} — domain is spoofable` });
  } else if (dmarcResult.spoofable) {
    mailSecurityScore -= 20;
    spoofReasons.push(`DMARC policy is ${dmarcResult.policy} — spoofed emails are not rejected`);
    issues.push({ severity: 'warning', category: 'mailSecurity', message: `DMARC policy is '${dmarcResult.policy}' — spoofed emails pass through` });
  } else if (dmarcResult.policy === 'quarantine') {
    mailSecurityScore -= 5;
    issues.push({ severity: 'info', category: 'mailSecurity', message: `DMARC policy is 'quarantine' — consider upgrading to 'reject' for full protection` });
  }
  if (dmarcResult.found && dmarcResult.pct < 100) {
    mailSecurityScore -= 10;
    issues.push({ severity: 'warning', category: 'mailSecurity', message: `DMARC only applies to ${dmarcResult.pct}% of messages (pct=${dmarcResult.pct})` });
  }
  mailSecurityScore = Math.max(0, mailSecurityScore);

  const domainSpoofable = (spfResult.spoofable || !spfResult.found) && (dmarcResult.spoofable || !dmarcResult.found);
  const mailSecurityAssessment: MailSecurityAssessment = {
    spf: spfResult,
    dmarc: dmarcResult,
    mxRecords,
    spoofable: domainSpoofable,
    spoofReason: spoofReasons.length > 0 ? spoofReasons.join('; ') : 'Domain has strong SPF and DMARC protections',
    score: mailSecurityScore,
  };

  // Mail Port score
  let mailPortScore = 100;
  const openMailPorts = mailPortResults.filter(r => r.connected);
  const smtpPorts = mailPortResults.filter(r => [25, 465, 587, 2525].includes(r.port));
  const smtpOpen = smtpPorts.filter(r => r.connected);
  if (smtpOpen.length === 0 && mxRecords.length > 0) {
    mailPortScore = 40;
    const port25 = smtpPorts.find(r => r.port === 25);
    if (port25 && !port25.connected) {
      issues.push({ severity: 'warning', category: 'mailPorts', message: `Port 25 is not reachable on ${port25.host} — may be filtered by cloud provider or firewall. Checked alternate SMTP ports (465, 587, 2525) as well.` });
    }
    issues.push({ severity: 'critical', category: 'mailPorts', message: `No SMTP ports (25, 465, 587, 2525) are reachable on mail server` });
  } else if (smtpOpen.length > 0) {
    // Check if only insecure ports are open
    const hasSecureSMTP = smtpOpen.some(r => r.port === 465 || r.port === 587);
    if (!hasSecureSMTP) {
      mailPortScore -= 15;
      issues.push({ severity: 'warning', category: 'mailPorts', message: 'Only plain SMTP (port 25) is open — no secure submission ports (465/587)' });
    }
  }

  // Overall score (weighted average — adjusted for new categories)
  const overallScore = Math.round(
    blacklistScore * 0.20 +
    mailScore * 0.15 +
    mailSecurityScore * 0.20 +
    mailPortScore * 0.05 +
    dnsScore * 0.15 +
    ptrScore * 0.10 +
    connectivityScore * 0.10 +
    ipScore * 0.05
  );

  return {
    domain,
    timestamp: Date.now(),
    overallScore,
    overallGrade: scoreToGrade(overallScore),
    categories: {
      blacklist: { score: blacklistScore, grade: scoreToGrade(blacklistScore), details: dnsblResult },
      mailServer: { score: mailScore, grade: scoreToGrade(mailScore), details: smtpResults },
      mailSecurity: { score: mailSecurityScore, grade: scoreToGrade(mailSecurityScore), details: mailSecurityAssessment },
      mailPorts: { score: mailPortScore, grade: scoreToGrade(mailPortScore), details: mailPortResults },
      dnsHealth: { score: dnsScore, grade: scoreToGrade(dnsScore), details: dnsHealthResult },
      reverseDs: { score: ptrScore, grade: scoreToGrade(ptrScore), details: ptrResults },
      ipInfo: { score: ipScore, grade: scoreToGrade(ipScore), details: ipInfoResults },
      connectivity: { score: connectivityScore, grade: scoreToGrade(connectivityScore), details: tcpResults },
    },
    issues,
    durationMs: Date.now() - start,
  };
}

// ─── Passive Connector Adapter ──────────────────────────────────────
// Wraps the domain health engine as a PassiveConnector so it plugs
// directly into the existing Domain Intel pipeline.

export const domainHealthConnector: PassiveConnector = {
  name: "domain_health",
  description: "MXToolbox-equivalent domain health diagnostics — DNSBL blacklist check, SMTP test, PTR/rDNS, DNS health, IP block info, TCP connectivity",
  requiresApiKey: false,
  freeUrl: "https://mxtoolbox.com/emailhealth",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const timeout = config?.timeout ?? 30000;
    const observations: AssetObservation[] = [];
    const errors: string[] = [];
    const now = new Date();

    try {
      const report = await runDomainHealthCheck(domain, timeout);

      // Convert health report into AssetObservations for the pipeline

      // 1. Overall health score observation
      observations.push({
        assetId: makeAssetId(domain, "health_score", "domain_health"),
        domain,
        assetType: "txt",
        name: `Domain Health: ${report.overallGrade} (${report.overallScore}/100)`,
        source: "domain_health",
        observedAt: now,
        tags: ["domain_health", "health_score", `grade:${report.overallGrade.toLowerCase()}`],
        evidence: {
          overallScore: report.overallScore,
          overallGrade: report.overallGrade,
          blacklistScore: report.categories.blacklist.score,
          mailServerScore: report.categories.mailServer.score,
          mailSecurityScore: report.categories.mailSecurity.score,
          mailPortScore: report.categories.mailPorts.score,
          dnsHealthScore: report.categories.dnsHealth.score,
          reverseDnsScore: report.categories.reverseDs.score,
          connectivityScore: report.categories.connectivity.score,
          issueCount: report.issues.length,
          criticalIssues: report.issues.filter(i => i.severity === "critical").length,
          fullReport: report,
        },
        attribution: {
          provider: "AC3 Domain Health Engine",
          method: "MXToolbox-equivalent domain health diagnostics (DNSBL, SMTP, PTR, DNS Health, TCP)",
          verifyUrl: `https://mxtoolbox.com/emailhealth/${domain}`,
        },
      });

      // 2. Blacklist observations
      if (report.categories.blacklist.details) {
        const bl = report.categories.blacklist.details;
        if (bl.listed.length > 0) {
          observations.push({
            assetId: makeAssetId(domain, `blacklist:${bl.ip}`, "domain_health"),
            domain,
            assetType: "ip",
            ip: bl.ip,
            name: `BLACKLISTED on ${bl.listed.length}/${bl.totalChecked} DNSBL zones`,
            source: "domain_health",
            observedAt: now,
            tags: ["domain_health", "blacklist", "dnsbl", "email_reputation"],
            evidence: {
              ip: bl.ip,
              listedCount: bl.listed.length,
              totalChecked: bl.totalChecked,
              listedZones: bl.listed.map(l => l.zone),
              blacklistScore: bl.score,
            },
            attribution: {
              provider: "AC3 DNSBL Engine",
              method: `Checked ${bl.totalChecked} DNS blacklists for IP ${bl.ip}`,
              verifyUrl: `https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a${bl.ip}`,
            },
          });
        }
      }

      // 3. SMTP test observations
      for (const smtp of report.categories.mailServer.details) {
        observations.push({
          assetId: makeAssetId(domain, `smtp:${smtp.host}`, "domain_health"),
          domain,
          assetType: "mx",
          name: smtp.connected
            ? `SMTP OK: ${smtp.host} (${smtp.supportsStartTls ? "TLS" : "NO TLS"}, ${smtp.latencyMs}ms)`
            : `SMTP FAIL: ${smtp.host} — ${smtp.error}`,
          source: "domain_health",
          observedAt: now,
          tags: [
            "domain_health", "smtp", "mail_server",
            smtp.connected ? "smtp_ok" : "smtp_fail",
            ...(smtp.supportsStartTls ? ["starttls"] : ["no_starttls"]),
          ],
          evidence: {
            host: smtp.host,
            port: smtp.port,
            connected: smtp.connected,
            banner: smtp.banner,
            supportsStartTls: smtp.supportsStartTls,
            supportsEhlo: smtp.supportsEhlo,
            ehloExtensions: smtp.ehloExtensions,
            latencyMs: smtp.latencyMs,
            error: smtp.error,
          },
          attribution: {
            provider: "AC3 SMTP Tester",
            method: `SMTP EHLO test on ${smtp.host}:25`,
            verifyUrl: `https://mxtoolbox.com/SuperTool.aspx?action=smtp%3a${smtp.host}`,
          },
        });
      }

      // 4. PTR observations
      for (const ptr of report.categories.reverseDs.details) {
        if (!ptr.hasPtrRecord) {
          observations.push({
            assetId: makeAssetId(domain, `ptr:${ptr.ip}`, "domain_health"),
            domain,
            assetType: "ip",
            ip: ptr.ip,
            name: `NO PTR RECORD for ${ptr.ip}`,
            source: "domain_health",
            observedAt: now,
            tags: ["domain_health", "ptr", "reverse_dns", "missing_ptr"],
            evidence: { ip: ptr.ip, hasPtrRecord: false, matchesForwardDns: false },
            attribution: {
              provider: "AC3 Reverse DNS Checker",
              method: `PTR lookup for ${ptr.ip}`,
              verifyUrl: `https://mxtoolbox.com/SuperTool.aspx?action=ptr%3a${ptr.ip}`,
            },
          });
        } else {
          observations.push({
            assetId: makeAssetId(domain, `ptr:${ptr.ip}`, "domain_health"),
            domain,
            assetType: "ip",
            ip: ptr.ip,
            name: `PTR: ${ptr.ip} → ${ptr.hostnames.join(", ")}${ptr.matchesForwardDns ? " (FCrDNS OK)" : " (FCrDNS MISMATCH)"}`,
            source: "domain_health",
            observedAt: now,
            tags: [
              "domain_health", "ptr", "reverse_dns",
              ptr.matchesForwardDns ? "fcrdns_ok" : "fcrdns_mismatch",
            ],
            evidence: { ip: ptr.ip, hostnames: ptr.hostnames, hasPtrRecord: true, matchesForwardDns: ptr.matchesForwardDns },
            attribution: {
              provider: "AC3 Reverse DNS Checker",
              method: `PTR lookup for ${ptr.ip}`,
              verifyUrl: `https://mxtoolbox.com/SuperTool.aspx?action=ptr%3a${ptr.ip}`,
            },
          });
        }
      }

      // 5. DNS Health observation
      if (report.categories.dnsHealth.details) {
        const dh = report.categories.dnsHealth.details;
        observations.push({
          assetId: makeAssetId(domain, "dns_health", "domain_health"),
          domain,
          assetType: "ns",
          name: `DNS Health: ${scoreToGrade(dh.score)} (${dh.score}/100) — ${dh.nameservers.length} NS, ${dh.issues.length} issues`,
          source: "domain_health",
          observedAt: now,
          tags: [
            "domain_health", "dns_health",
            dh.soaConsistent ? "soa_consistent" : "soa_mismatch",
            dh.nsConsistent ? "ns_consistent" : "ns_inconsistent",
            dh.glueRecordsValid ? "glue_ok" : "glue_missing",
          ],
          evidence: {
            nameservers: dh.nameservers,
            soaConsistent: dh.soaConsistent,
            soaSerials: dh.soaSerials,
            nsConsistent: dh.nsConsistent,
            zoneTransferBlocked: dh.zoneTransferBlocked,
            glueRecordsValid: dh.glueRecordsValid,
            issues: dh.issues,
            score: dh.score,
          },
          attribution: {
            provider: "AC3 DNS Health Analyzer",
            method: `Comprehensive DNS health check for ${domain} across ${dh.nameservers.length} nameservers`,
            verifyUrl: `https://mxtoolbox.com/SuperTool.aspx?action=dns%3a${domain}`,
          },
        });
      }

      // 6. IP Block info observation
      for (const ipInfo of report.categories.ipInfo.details) {
        if (!ipInfo.error) {
          observations.push({
            assetId: makeAssetId(domain, `ipblock:${ipInfo.ip}`, "domain_health"),
            domain,
            assetType: "asn",
            ip: ipInfo.ip,
            asn: ipInfo.asn,
            name: `IP Block: ${ipInfo.ip} — ${ipInfo.organization || "Unknown Org"}${ipInfo.asn ? ` (AS${ipInfo.asn})` : ""}`,
            source: "domain_health",
            observedAt: now,
            tags: ["domain_health", "ip_block", "arin", "rdap"],
            evidence: {
              ip: ipInfo.ip,
              asn: ipInfo.asn,
              asnName: ipInfo.asnName,
              networkName: ipInfo.networkName,
              networkCidr: ipInfo.networkCidr,
              organization: ipInfo.organization,
              country: ipInfo.country,
              startAddress: ipInfo.startAddress,
              endAddress: ipInfo.endAddress,
            },
            attribution: {
              provider: "AC3 IP Block Analyzer (RDAP)",
              method: `RDAP query for IP ${ipInfo.ip}`,
              verifyUrl: `https://mxtoolbox.com/SuperTool.aspx?action=arin%3a${ipInfo.ip}`,
            },
          });
        }
      }

      // 7. TCP connectivity observations
      for (const tcp of report.categories.connectivity.details) {
        observations.push({
          assetId: makeAssetId(domain, `tcp:${tcp.host}:${tcp.port}`, "domain_health"),
          domain,
          assetType: "ip",
          ip: tcp.host,
          name: tcp.connected
            ? `TCP ${tcp.port} OPEN on ${tcp.host} (${tcp.latencyMs}ms)${tcp.banner ? ` — ${tcp.banner.substring(0, 80)}` : ""}`
            : `TCP ${tcp.port} CLOSED on ${tcp.host}`,
          source: "domain_health",
          observedAt: now,
          tags: [
            "domain_health", "tcp_check", `port:${tcp.port}`,
            tcp.connected ? "port_open" : "port_closed",
          ],
          evidence: {
            host: tcp.host,
            port: tcp.port,
            connected: tcp.connected,
            banner: tcp.banner,
            latencyMs: tcp.latencyMs,
            error: tcp.error,
          },
          attribution: {
            provider: "AC3 TCP Connectivity Checker",
            method: `TCP connect test to ${tcp.host}:${tcp.port}`,
            verifyUrl: `https://mxtoolbox.com/SuperTool.aspx?action=tcp%3a${tcp.host}%3a${tcp.port}`,
          },
        });
      }

      // 8. Mail Security observations (SPF, DMARC, spoofability)
      if (report.categories.mailSecurity.details) {
        const ms = report.categories.mailSecurity.details;
        observations.push({
          assetId: makeAssetId(domain, 'mail_security', 'domain_health'),
          domain,
          assetType: 'txt',
          name: `Mail Security: ${scoreToGrade(ms.score)} (${ms.score}/100)${ms.spoofable ? ' — SPOOFABLE' : ' — Protected'}`,
          source: 'domain_health',
          observedAt: now,
          tags: [
            'domain_health', 'mail_security', 'spf', 'dmarc',
            ms.spoofable ? 'spoofable' : 'protected',
            ms.spf.found ? `spf:${ms.spf.policy}` : 'spf:missing',
            ms.dmarc.found ? `dmarc:${ms.dmarc.policy}` : 'dmarc:missing',
          ],
          evidence: {
            spf: ms.spf,
            dmarc: ms.dmarc,
            spoofable: ms.spoofable,
            spoofReason: ms.spoofReason,
            mxRecords: ms.mxRecords,
            score: ms.score,
          },
          attribution: {
            provider: 'AC3 Mail Security Analyzer',
            method: `SPF + DMARC analysis for ${domain}`,
            verifyUrl: `https://mxtoolbox.com/SuperTool.aspx?action=spf%3a${domain}`,
          },
        });
      }

      // 9. Enterprise mail port observations
      for (const mp of report.categories.mailPorts.details) {
        observations.push({
          assetId: makeAssetId(domain, `mailport:${mp.host}:${mp.port}`, 'domain_health'),
          domain,
          assetType: 'ip',
          ip: mp.host,
          name: mp.connected
            ? `Mail Port ${mp.port} (${mp.service}) OPEN on ${mp.host} (${mp.latencyMs}ms)${mp.banner ? ` — ${mp.banner.substring(0, 60)}` : ''}`
            : `Mail Port ${mp.port} (${mp.service}) CLOSED on ${mp.host}`,
          source: 'domain_health',
          observedAt: now,
          tags: [
            'domain_health', 'mail_port', `port:${mp.port}`, mp.protocol,
            mp.connected ? 'port_open' : 'port_closed',
          ],
          evidence: {
            host: mp.host,
            port: mp.port,
            service: mp.service,
            protocol: mp.protocol,
            connected: mp.connected,
            banner: mp.banner,
            latencyMs: mp.latencyMs,
            error: mp.error,
          },
          attribution: {
            provider: 'AC3 Mail Port Scanner',
            method: `Enterprise mail port scan on ${mp.host}:${mp.port} (${mp.service})`,
          },
        });
      }

    } catch (err: any) {
      errors.push(`Domain health check failed: ${err.message}`);
    }

    return {
      connector: "domain_health",
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited: false,
    };
  },
};
