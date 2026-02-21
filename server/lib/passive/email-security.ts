/**
 * Email Security Connector — DMARC / SPF / DKIM / MX Analysis
 *
 * Queries DNS TXT, MX, and DMARC records to assess email security posture.
 * Identifies missing or misconfigured email authentication (SPF, DKIM, DMARC),
 * which directly impacts phishing susceptibility — Red Team Top-10 #5 & #9.
 *
 * Method: DNS TXT/MX record lookups (fully passive)
 * Data Source: Public DNS records
 * Free: Yes, no API key required
 */

import { createHash } from "crypto";
import { resolveMx, resolveTxt } from "dns/promises";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

interface EmailSecurityResult {
  spf: { found: boolean; record?: string; policy?: string; issues: string[] };
  dmarc: { found: boolean; record?: string; policy?: string; pct?: number; rua?: string; issues: string[] };
  dkim: { selectorsChecked: string[]; found: string[]; issues: string[] };
  mx: { records: { exchange: string; priority: number }[]; issues: string[] };
}

async function queryDns(domain: string, _timeout: number): Promise<EmailSecurityResult> {
  const result: EmailSecurityResult = {
    spf: { found: false, issues: [] },
    dmarc: { found: false, issues: [] },
    dkim: { selectorsChecked: [], found: [], issues: [] },
    mx: { records: [], issues: [] },
  };

  // SPF
  try {
    const txtRecords = await resolveTxt(domain);
    for (const parts of txtRecords) {
      const record = parts.join("");
      if (record.toLowerCase().startsWith("v=spf1")) {
        result.spf.found = true;
        result.spf.record = record;
        if (record.includes("-all")) result.spf.policy = "hard_fail";
        else if (record.includes("~all")) result.spf.policy = "soft_fail";
        else if (record.includes("?all")) result.spf.policy = "neutral";
        else if (record.includes("+all")) {
          result.spf.policy = "pass_all";
          result.spf.issues.push("SPF uses +all which allows any sender — effectively no protection");
        }
        const includeCount = (record.match(/include:/g) || []).length;
        if (includeCount > 10) {
          result.spf.issues.push(`SPF has ${includeCount} includes — may exceed DNS lookup limit (10)`);
        }
      }
    }
  } catch { /* No TXT records */ }
  if (!result.spf.found) {
    result.spf.issues.push("No SPF record found — email spoofing is trivial");
  }

  // DMARC
  try {
    const dmarcRecords = await resolveTxt(`_dmarc.${domain}`);
    for (const parts of dmarcRecords) {
      const record = parts.join("");
      if (record.toLowerCase().startsWith("v=dmarc1")) {
        result.dmarc.found = true;
        result.dmarc.record = record;
        const pMatch = record.match(/;\s*p=(\w+)/i);
        if (pMatch) result.dmarc.policy = pMatch[1].toLowerCase();
        const pctMatch = record.match(/;\s*pct=(\d+)/i);
        if (pctMatch) result.dmarc.pct = parseInt(pctMatch[1], 10);
        const ruaMatch = record.match(/;\s*rua=([^;]+)/i);
        if (ruaMatch) result.dmarc.rua = ruaMatch[1].trim();
        if (result.dmarc.policy === "none") {
          result.dmarc.issues.push("DMARC policy is 'none' — spoofed emails are not blocked");
        }
        if (result.dmarc.pct !== undefined && result.dmarc.pct < 100) {
          result.dmarc.issues.push(`DMARC only applies to ${result.dmarc.pct}% of messages`);
        }
      }
    }
  } catch { /* No DMARC record */ }
  if (!result.dmarc.found) {
    result.dmarc.issues.push("No DMARC record found — email spoofing protection is absent");
  }

  // DKIM — check common selectors
  const commonSelectors = ["default", "google", "selector1", "selector2", "k1", "k2", "mail", "dkim", "s1", "s2"];
  result.dkim.selectorsChecked = commonSelectors;
  for (const sel of commonSelectors) {
    try {
      const dkimRecords = await resolveTxt(`${sel}._domainkey.${domain}`);
      for (const parts of dkimRecords) {
        const record = parts.join("");
        if (record.includes("v=DKIM1") || record.includes("p=")) {
          result.dkim.found.push(sel);
          break;
        }
      }
    } catch { /* Selector not found */ }
  }
  if (result.dkim.found.length === 0) {
    result.dkim.issues.push("No DKIM selectors found among common selectors — email authentication may be weak");
  }

  // MX records
  try {
    const mxRecords = await resolveMx(domain);
    result.mx.records = mxRecords.map(r => ({ exchange: r.exchange, priority: r.priority }));
    if (mxRecords.length === 0) {
      result.mx.issues.push("No MX records found — domain may not receive email");
    }
  } catch {
    result.mx.issues.push("MX lookup failed — domain may not receive email");
  }

  return result;
}

export const emailSecurityConnector: PassiveConnector = {
  name: "email_security",
  description: "Email security posture analysis — DMARC, SPF, DKIM, and MX record assessment for phishing susceptibility",
  requiresApiKey: false,
  freeUrl: "https://mxtoolbox.com",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const errors: string[] = [];
    const observations: AssetObservation[] = [];
    const timeout = config?.timeout ?? 15000;
    const now = new Date();

    try {
      const result = await queryDns(domain, timeout);

      // SPF observation
      observations.push({
        assetId: makeAssetId(domain, `spf:${domain}`, "email_security"),
        domain, assetType: "txt",
        name: `SPF: ${result.spf.found ? result.spf.policy || "present" : "MISSING"}`,
        source: "email_security", observedAt: now,
        tags: ["email_security", "spf", ...(result.spf.found ? ["spf_present"] : ["spf_missing", "phishing_risk"]), ...(result.spf.policy === "pass_all" ? ["spf_permissive", "critical_misconfiguration"] : [])],
        evidence: { record: result.spf.record, policy: result.spf.policy, issues: result.spf.issues },
        attribution: { provider: "DNS TXT Record Lookup", method: "Queried DNS TXT records for SPF (v=spf1) policy on " + domain, verifyUrl: `https://mxtoolbox.com/SuperTool.aspx?action=spf%3a${domain}&run=toolpage` },
      });

      // DMARC observation
      observations.push({
        assetId: makeAssetId(domain, `dmarc:${domain}`, "email_security"),
        domain, assetType: "txt",
        name: `DMARC: ${result.dmarc.found ? result.dmarc.policy || "present" : "MISSING"}`,
        source: "email_security", observedAt: now,
        tags: ["email_security", "dmarc", ...(result.dmarc.found ? ["dmarc_present"] : ["dmarc_missing", "phishing_risk"]), ...(result.dmarc.policy === "none" ? ["dmarc_monitor_only"] : [])],
        evidence: { record: result.dmarc.record, policy: result.dmarc.policy, pct: result.dmarc.pct, rua: result.dmarc.rua, issues: result.dmarc.issues },
        attribution: { provider: "DNS TXT Record Lookup", method: `Queried DNS TXT records for DMARC (v=DMARC1) policy at _dmarc.${domain}`, verifyUrl: `https://mxtoolbox.com/SuperTool.aspx?action=dmarc%3a${domain}&run=toolpage` },
      });

      // DKIM observation
      observations.push({
        assetId: makeAssetId(domain, `dkim:${domain}`, "email_security"),
        domain, assetType: "txt",
        name: result.dkim.found.length > 0 ? `DKIM: selectors found (${result.dkim.found.join(", ")})` : "DKIM: no common selectors found",
        source: "email_security", observedAt: now,
        tags: ["email_security", "dkim", ...(result.dkim.found.length > 0 ? ["dkim_present"] : ["dkim_missing"])],
        evidence: { selectorsFound: result.dkim.found, selectorsChecked: result.dkim.selectorsChecked, issues: result.dkim.issues },
        attribution: { provider: "DNS TXT Record Lookup", method: `Checked ${result.dkim.selectorsChecked.length} common DKIM selectors at <selector>._domainkey.${domain}` },
      });

      // MX records observation
      if (result.mx.records.length > 0) {
        const providers: string[] = [];
        for (const mx of result.mx.records) {
          const ex = mx.exchange.toLowerCase();
          if (ex.includes("google") || ex.includes("gmail")) providers.push("Google Workspace");
          else if (ex.includes("outlook") || ex.includes("microsoft")) providers.push("Microsoft 365");
          else if (ex.includes("protonmail")) providers.push("ProtonMail");
          else if (ex.includes("mimecast")) providers.push("Mimecast");
          else if (ex.includes("pphosted") || ex.includes("proofpoint")) providers.push("Proofpoint");
        }
        observations.push({
          assetId: makeAssetId(domain, `mx:${domain}`, "email_security"),
          domain, assetType: "mx",
          name: result.mx.records.map(r => r.exchange).join(", "),
          source: "email_security", observedAt: now,
          tags: ["email_security", "mx", ...(providers.length > 0 ? providers.map(p => `provider:${p.toLowerCase().replace(/\s+/g, "_")}`) : [])],
          evidence: { records: result.mx.records, detectedProviders: Array.from(new Set(providers)) },
          attribution: { provider: "DNS MX Record Lookup", method: `Queried DNS MX records for ${domain} to identify email infrastructure`, verifyUrl: `https://mxtoolbox.com/SuperTool.aspx?action=mx%3a${domain}&run=toolpage` },
        });
      }
    } catch (err: any) {
      errors.push(`Email security check error: ${err.message}`);
    }

    return { connector: "email_security", domain, observations, errors, durationMs: Date.now() - start, rateLimited: false };
  },
};
