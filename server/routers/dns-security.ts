/**
 * DNS Security Validator — tRPC Router
 * Provides procedures for running DNS security assessments across engagement types
 */
import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import { runDnsSecurityAssessment, TAKEOVER_FINGERPRINTS } from "../lib/dns-security-validator";
import type { DnsSecurityReport, EngagementContext } from "../lib/dns-security-validator";
import {
  persistDnsSecurityAssessment,
  getDnsAssessmentHistory,
  getLatestDnsAssessment,
  getOpenDnsFindings,
  getOrCreateMonitoringConfig,
  updateMonitoringConfig,
  getMonitoredDomains,
} from "../lib/dns-security-persistence";

export const dnsSecurityRouter = router({
  /**
   * Run a full DNS security assessment for a domain
   * Used by DI scans, Vuln/Pentest, and Red Team engagements
   */
  runAssessment: protectedProcedure
    .input(z.object({
      domain: z.string().min(1).max(253),
      context: z.enum(["di_scan", "vuln_pentest", "red_team"]).default("di_scan"),
      engagementId: z.number().optional(),
    }))
    .mutation(async ({ input }): Promise<DnsSecurityReport> => {
      const { domain, context } = input;
      // Strip protocol/path if accidentally included
      const cleanDomain = domain.replace(/^https?:\/\//, "").replace(/\/.*$/, "").trim();
      return runDnsSecurityAssessment(cleanDomain, context as EngagementContext);
    }),

  /**
   * Get the fingerprint database info (for UI display)
   */
  getFingerprints: protectedProcedure
    .query(() => {
      return {
        totalServices: TAKEOVER_FINGERPRINTS.length,
        services: TAKEOVER_FINGERPRINTS.map(fp => ({
          service: fp.service,
          cnames: fp.cnames,
          vulnerable: fp.vulnerable,
        })),
      };
    }),

  /**
   * Quick dangling DNS check only (lighter than full assessment)
   */
  quickDanglingCheck: protectedProcedure
    .input(z.object({
      domain: z.string().min(1).max(253),
      subdomains: z.array(z.string()).optional(),
    }))
    .mutation(async ({ input }) => {
      const { domain, subdomains } = input;
      const cleanDomain = domain.replace(/^https?:\/\//, "").replace(/\/.*$/, "").trim();

      // Run assessment on main domain
      const mainReport = await runDnsSecurityAssessment(cleanDomain, "di_scan");
      const danglingFindings = mainReport.findings.filter(f => f.category === "dangling_dns");

      // If subdomains provided, check those too
      const subdomainFindings: Array<{ subdomain: string; findings: typeof danglingFindings }> = [];
      if (subdomains && subdomains.length > 0) {
        // Limit to 20 subdomains per request to avoid timeout
        const toCheck = subdomains.slice(0, 20);
        for (const sub of toCheck) {
          try {
            const subReport = await runDnsSecurityAssessment(sub, "di_scan");
            const subDangling = subReport.findings.filter(f => f.category === "dangling_dns");
            if (subDangling.length > 0) {
              subdomainFindings.push({ subdomain: sub, findings: subDangling });
            }
          } catch {
            // Skip failed subdomain checks
          }
        }
      }

      return {
        domain: cleanDomain,
        mainDomainFindings: danglingFindings,
        subdomainFindings,
        totalDangling: danglingFindings.length + subdomainFindings.reduce((sum, s) => sum + s.findings.length, 0),
        checkedAt: Date.now(),
      };
    }),

  /**
   * Get MITRE ATT&CK mapping for DNS findings
   */
  getMitreMapping: protectedProcedure
    .query(() => {
      return [
        { id: "T1071.004", name: "Application Layer Protocol: DNS", tactic: "Command and Control", dnsRelevance: "DNS tunneling for C2 communication" },
        { id: "T1568", name: "Dynamic Resolution", tactic: "Command and Control", dnsRelevance: "Fast-flux DNS, domain generation algorithms" },
        { id: "T1584.002", name: "Compromise Infrastructure: DNS Server", tactic: "Resource Development", dnsRelevance: "Subdomain takeover, dangling DNS exploitation" },
        { id: "T1583.001", name: "Acquire Infrastructure: Domains", tactic: "Resource Development", dnsRelevance: "Domain squatting, expired domain registration" },
        { id: "T1557", name: "Adversary-in-the-Middle", tactic: "Credential Access", dnsRelevance: "DNS spoofing, cache poisoning" },
        { id: "T1557.001", name: "LLMNR/NBT-NS Poisoning", tactic: "Credential Access", dnsRelevance: "Local DNS poisoning attacks" },
        { id: "T1498.002", name: "Network DoS: Reflection Amplification", tactic: "Impact", dnsRelevance: "DNS amplification attacks via open resolvers" },
        { id: "T1590.002", name: "Gather Victim Network Info: DNS", tactic: "Reconnaissance", dnsRelevance: "Zone transfer, zone walking, DNS enumeration" },
        { id: "T1114.002", name: "Email Collection: Remote Email Collection", tactic: "Collection", dnsRelevance: "MX record takeover for email interception" },
        { id: "T1566.002", name: "Phishing: Spearphishing Link", tactic: "Initial Access", dnsRelevance: "Subdomain takeover for credential harvesting" },
      ];
    }),

  /**
   * Run assessment AND persist results to database
   */
  runAndPersist: protectedProcedure
    .input(z.object({
      domain: z.string().min(1).max(253),
      context: z.enum(["di_scan", "vuln_pentest", "red_team"]).default("di_scan"),
      engagementId: z.number().optional(),
      scanId: z.number().optional(),
    }))
    .mutation(async ({ input }) => {
      const cleanDomain = input.domain.replace(/^https?:\/\//, "").replace(/\/.*$/, "").trim();
      const report = await runDnsSecurityAssessment(cleanDomain, input.context as EngagementContext);
      const { assessmentId, changes } = await persistDnsSecurityAssessment({
        domain: cleanDomain,
        scanId: input.scanId,
        engagementId: input.engagementId,
        report,
      });
      return { report, assessmentId, changes };
    }),

  /**
   * Get assessment history for a domain
   */
  getHistory: protectedProcedure
    .input(z.object({
      domain: z.string().min(1).max(253),
      limit: z.number().min(1).max(100).default(20),
    }))
    .query(async ({ input }) => {
      return getDnsAssessmentHistory(input.domain, input.limit);
    }),

  /**
   * Get the latest assessment for a domain (full report)
   */
  getLatest: protectedProcedure
    .input(z.object({ domain: z.string().min(1).max(253) }))
    .query(async ({ input }) => {
      return getLatestDnsAssessment(input.domain);
    }),

  /**
   * Get all open findings for a domain
   */
  getOpenFindings: protectedProcedure
    .input(z.object({ domain: z.string().min(1).max(253) }))
    .query(async ({ input }) => {
      return getOpenDnsFindings(input.domain);
    }),

  /**
   * Get or create monitoring config for a domain
   */
  getMonitoringConfig: protectedProcedure
    .input(z.object({ domain: z.string().min(1).max(253) }))
    .query(async ({ input }) => {
      return getOrCreateMonitoringConfig(input.domain);
    }),

  /**
   * Update monitoring config for a domain
   */
  updateMonitoringConfig: protectedProcedure
    .input(z.object({
      domain: z.string().min(1).max(253),
      enabled: z.boolean().optional(),
      intervalHours: z.number().min(1).max(168).optional(),
      alertOnNewCritical: z.boolean().optional(),
      alertOnNewHigh: z.boolean().optional(),
      alertOnDnsChange: z.boolean().optional(),
    }))
    .mutation(async ({ input }) => {
      const { domain, ...updates } = input;
      await updateMonitoringConfig(domain, updates);
      return { success: true };
    }),

  /**
   * Get all monitored domains
   */
  getMonitoredDomains: protectedProcedure
    .query(async () => {
      return getMonitoredDomains();
    }),

  /**
   * Get check categories and descriptions (for UI)
   */
  getCheckCategories: protectedProcedure
    .query(() => {
      return [
        { id: "dangling_dns", name: "Dangling DNS / Subdomain Takeover", icon: "🔗", description: "Detects DNS records pointing to unclaimed or deprovisioned resources" },
        { id: "dnssec", name: "DNSSEC Validation", icon: "🔐", description: "Validates DNSSEC chain-of-trust, algorithm strength, and signature status" },
        { id: "zone_transfer", name: "Zone Transfer (AXFR)", icon: "📋", description: "Checks if zone transfers are improperly allowed to unauthorized parties" },
        { id: "cache_poisoning", name: "Cache Poisoning", icon: "💉", description: "Assesses susceptibility to DNS cache poisoning (Kaminsky-style) attacks" },
        { id: "open_resolver", name: "Open Resolver", icon: "🌐", description: "Detects DNS servers accepting recursive queries from any source" },
        { id: "amplification", name: "DNS Amplification", icon: "📡", description: "Evaluates potential for DNS reflection/amplification abuse" },
        { id: "wildcard", name: "Wildcard DNS", icon: "✳️", description: "Detects wildcard records that may mask vulnerabilities" },
        { id: "email_security", name: "Email Security (SPF/DKIM/DMARC)", icon: "📧", description: "Validates email authentication records to prevent spoofing" },
        { id: "caa", name: "CAA Records", icon: "📜", description: "Checks Certificate Authority Authorization restrictions" },
        { id: "zone_walking", name: "NSEC Zone Walking", icon: "🚶", description: "Detects NSEC records that allow zone enumeration" },
        { id: "tunneling_indicator", name: "DNS Tunneling", icon: "🕳️", description: "Identifies patterns consistent with DNS tunneling infrastructure" },
        { id: "version_disclosure", name: "Version Disclosure", icon: "🏷️", description: "Checks if nameservers reveal software version information" },
        { id: "dns_cookie", name: "DNS Cookies (RFC 7873)", icon: "🍪", description: "Verifies DNS cookie support for transaction authentication" },
        { id: "rate_limiting", name: "Response Rate Limiting", icon: "⏱️", description: "Checks for RRL configuration to prevent amplification abuse" },
        { id: "rebinding", name: "DNS Rebinding", icon: "🔄", description: "Detects conditions enabling DNS rebinding attacks" },
      ];
    }),
});
