/**
 * @deprecated — Nmap has been removed. Use scanforge-discovery endpoints instead.
 * This router is not imported anywhere and is retained for reference only.
 *
 * Nmap Router (DEPRECATED)
 *
 * Previously provided tRPC endpoints for Nmap network scanning:
 * - Full scan with configurable profiles (quick/standard/deep/stealth/service/udp/vuln/custom)
 * - Quick scan (top 100 ports, fast turnaround)
 * - Service version detection (-sV with configurable intensity)
 * - OS detection (-O with fingerprinting)
 * - NSE script scanning (vuln, auth, discovery, brute, etc.)
 * - Vulnerability scan profile (--script vuln)
 * - Scan history and result retrieval
 * - Predefined scan profiles query
 * - Preflight server checks
 *
 * Nmap runs on operator scan servers via SSH (same pattern as Amass engine).
 * All operations enforce ROE scope boundaries before execution.
 */
import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { protectedProcedure, router } from "../_core/trpc";
import {
  executeNmapScan,
  scanWithScopeEnforcement,
  preflightCheck,
  parseNmapXml,
  toNmapRawResults,
  getAllAdminPorts,
  ADMIN_SERVICE_PORTS,
  type NmapScanConfig,
  type NmapScanResult,
  type NmapScanProfile,
  type ScanServerConfig,
} from "../lib/nmap-orchestrator";
import { enforceMultiTargetScope } from "../lib/scope-enforcement-middleware";

// ─── In-Memory Scan Store ───────────────────────────────────────────────────

interface ScanHistoryEntry {
  id: string;
  engagementId: number;
  targets: string[];
  profile: NmapScanProfile;
  status: "queued" | "running" | "completed" | "failed" | "timeout";
  startedAt: number;
  completedAt?: number;
  durationMs?: number;
  hostsUp?: number;
  openPorts?: number;
  command?: string;
  error?: string;
  operatorId: string;
  operatorName?: string;
}

const scanResults: Map<string, NmapScanResult> = new Map();
const scanHistory: ScanHistoryEntry[] = [];

// ─── Shared Schemas ─────────────────────────────────────────────────────────

const serverSchema = z.object({
  host: z.string().min(1),
  port: z.number().int().min(1).max(65535).optional(),
  username: z.string().min(1),
  privateKey: z.string().optional(),
  privateKeyPath: z.string().optional(),
  nmapPath: z.string().optional(),
});

const profileSchema = z.enum([
  "quick", "standard", "deep", "stealth", "service", "udp", "vuln", "custom",
]);

// ─── Scan Profile Descriptions ──────────────────────────────────────────────

const SCAN_PROFILE_DESCRIPTIONS: Record<NmapScanProfile, {
  name: string;
  description: string;
  flags: string;
  estimatedDuration: string;
  useCase: string;
  portsScanned: string;
  requiresSudo: boolean;
}> = {
  quick: {
    name: "Quick Scan",
    description: "Fast SYN scan of top 100 ports with lightweight service detection",
    flags: "-sS -T4 --top-ports 100 -sV --version-intensity 2",
    estimatedDuration: "30s - 2min per host",
    useCase: "Initial reconnaissance, large target ranges, time-constrained engagements",
    portsScanned: "Top 100 TCP",
    requiresSudo: true,
  },
  standard: {
    name: "Standard Scan",
    description: "SYN scan of top 1000 ports with service detection, default scripts, and OS detection",
    flags: "-sS -sV -sC -T3 --top-ports 1000 -O --osscan-limit",
    estimatedDuration: "2 - 10min per host",
    useCase: "General-purpose scanning, most engagements",
    portsScanned: "Top 1000 TCP",
    requiresSudo: true,
  },
  deep: {
    name: "Deep Scan",
    description: "Full port range scan with aggressive service detection, scripts, and OS fingerprinting",
    flags: "-sS -sV -sC -A -T2 -p-",
    estimatedDuration: "15 - 60min per host",
    useCase: "Thorough enumeration, high-value targets, compliance audits",
    portsScanned: "All 65535 TCP",
    requiresSudo: true,
  },
  stealth: {
    name: "Stealth Scan",
    description: "Low-and-slow SYN scan with randomized hosts and rate limiting to evade IDS/IPS",
    flags: "-sS -T1 --randomize-hosts --max-rate 50 --top-ports 1000 -sV --version-intensity 1",
    estimatedDuration: "30 - 120min per host",
    useCase: "Evasion testing, IDS/IPS validation, red team operations",
    portsScanned: "Top 1000 TCP",
    requiresSudo: true,
  },
  service: {
    name: "Service Version Scan",
    description: "Targeted service detection on specific ports with default scripts and OS detection",
    flags: "-sV -O -p <ports> -sC",
    estimatedDuration: "1 - 5min per host",
    useCase: "Known service enumeration, admin port fingerprinting, post-discovery deep dive",
    portsScanned: "User-specified or default admin ports",
    requiresSudo: true,
  },
  udp: {
    name: "UDP Scan",
    description: "Top 50 UDP ports with service detection — catches DNS, SNMP, TFTP, NTP, SSDP",
    flags: "-sU --top-ports 50 -sV --version-intensity 2",
    estimatedDuration: "5 - 30min per host",
    useCase: "UDP service discovery, SNMP enumeration, DNS/NTP amplification checks",
    portsScanned: "Top 50 UDP",
    requiresSudo: true,
  },
  vuln: {
    name: "Vulnerability Scan",
    description: "NSE vuln category scripts against top 1000 ports — checks for known CVEs and misconfigs",
    flags: "--script vuln -sV -T3 --top-ports 1000",
    estimatedDuration: "10 - 45min per host",
    useCase: "Vulnerability assessment, CVE detection, pre-exploitation reconnaissance",
    portsScanned: "Top 1000 TCP",
    requiresSudo: false,
  },
  custom: {
    name: "Custom Scan",
    description: "User-defined Nmap arguments for specialized scanning needs",
    flags: "<user-defined>",
    estimatedDuration: "Varies",
    useCase: "Specialized scans, specific NSE scripts, custom port ranges",
    portsScanned: "User-defined",
    requiresSudo: false,
  },
};

// ─── NSE Script Categories ──────────────────────────────────────────────────

const NSE_SCRIPT_CATEGORIES: Record<string, {
  name: string;
  description: string;
  scripts: string[];
  useCase: string;
}> = {
  auth: {
    name: "Authentication",
    description: "Check for default credentials, anonymous access, and auth bypasses",
    scripts: [
      "ftp-anon", "ssh-auth-methods", "smtp-open-relay",
      "http-default-accounts", "mysql-empty-password",
      "ms-sql-empty-password", "mongodb-databases",
      "redis-info", "vnc-info", "telnet-ntlm-info",
    ],
    useCase: "Credential testing, default password checks",
  },
  discovery: {
    name: "Discovery",
    description: "Enumerate services, shares, databases, and infrastructure details",
    scripts: [
      "smb-enum-shares", "smb-enum-users", "smb-os-discovery",
      "dns-zone-transfer", "dns-brute", "http-enum",
      "http-title", "http-headers", "http-methods",
      "ssl-enum-ciphers", "ssl-cert", "snmp-info",
      "snmp-brute", "ldap-rootdse", "ntp-info",
    ],
    useCase: "Service enumeration, infrastructure mapping",
  },
  vuln: {
    name: "Vulnerability",
    description: "Check for known CVEs, misconfigurations, and exploitable conditions",
    scripts: [
      "smb-vuln-ms17-010", "smb-vuln-ms08-067",
      "ssl-heartbleed", "ssl-poodle", "ssl-dh-params",
      "http-shellshock", "http-vuln-cve2017-5638",
      "http-vuln-cve2014-3120", "rdp-vuln-ms12-020",
      "ftp-vsftpd-backdoor", "smtp-vuln-cve2010-4344",
    ],
    useCase: "CVE detection, exploit validation",
  },
  brute: {
    name: "Brute Force",
    description: "Password brute-force against common services",
    scripts: [
      "ssh-brute", "ftp-brute", "smtp-brute",
      "http-brute", "mysql-brute", "ms-sql-brute",
      "rdp-brute", "vnc-brute", "telnet-brute",
      "snmp-brute", "ldap-brute", "pop3-brute",
    ],
    useCase: "Password testing, credential validation",
  },
  safe_recon: {
    name: "Safe Reconnaissance",
    description: "Non-intrusive information gathering scripts safe for initial enumeration",
    scripts: [
      "banner", "http-title", "http-headers",
      "http-server-header", "ssl-cert", "ssh-hostkey",
      "dns-nsid", "whois-ip", "nbstat",
      "smb-os-discovery", "ntp-info", "snmp-sysdescr",
    ],
    useCase: "Initial enumeration, passive information gathering",
  },
  web: {
    name: "Web Application",
    description: "Web server and application enumeration scripts",
    scripts: [
      "http-enum", "http-title", "http-headers",
      "http-methods", "http-robots.txt", "http-sitemap-generator",
      "http-git", "http-svn-enum", "http-backup-finder",
      "http-config-backup", "http-php-version",
      "http-wordpress-enum", "http-drupal-enum",
    ],
    useCase: "Web application reconnaissance, CMS detection",
  },
  smb: {
    name: "SMB/Windows",
    description: "Windows and SMB-specific enumeration and vulnerability checks",
    scripts: [
      "smb-enum-shares", "smb-enum-users", "smb-enum-domains",
      "smb-enum-groups", "smb-os-discovery", "smb-protocols",
      "smb-security-mode", "smb-vuln-ms17-010",
      "smb-vuln-ms08-067", "smb2-security-mode",
    ],
    useCase: "Active Directory reconnaissance, Windows enumeration",
  },
};

// ─── Helper ─────────────────────────────────────────────────────────────────

function generateScanId(): string {
  return `nmap-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;
}

function addToHistory(entry: ScanHistoryEntry): void {
  scanHistory.unshift(entry);
  // Keep last 500 entries
  if (scanHistory.length > 500) {
    const removed = scanHistory.pop();
    if (removed) scanResults.delete(removed.id);
  }
}

// ─── Router ─────────────────────────────────────────────────────────────────

export const nmapRouter = router({

  /**
   * Execute a full Nmap scan with any profile.
   * All targets are validated against ROE scope before execution.
   */
  scan: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      targets: z.array(z.string().min(1)).min(1).max(256),
      profile: profileSchema,
      server: serverSchema,
      ports: z.string().optional(),
      customArgs: z.string().optional(),
      scripts: z.array(z.string()).optional(),
      excludeHosts: z.array(z.string()).optional(),
      timeoutSeconds: z.number().int().min(30).max(7200).optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      // Enforce ROE scope on all targets
      await enforceMultiTargetScope(
        input.engagementId,
        input.targets,
        `nmap_${input.profile}`,
        ctx,
      );

      const scanId = generateScanId();
      const historyEntry: ScanHistoryEntry = {
        id: scanId,
        engagementId: input.engagementId,
        targets: input.targets,
        profile: input.profile,
        status: "running",
        startedAt: Date.now(),
        operatorId: String(ctx.user.id),
        operatorName: ctx.user.name || undefined,
      };
      addToHistory(historyEntry);

      try {
        const result = await executeNmapScan({
          targets: input.targets,
          profile: input.profile,
          ports: input.ports,
          customArgs: input.customArgs,
          scripts: input.scripts,
          excludeHosts: input.excludeHosts,
          timeoutSeconds: input.timeoutSeconds,
          engagementId: input.engagementId,
          operatorId: String(ctx.user.id),
          operatorName: ctx.user.name || undefined,
          server: input.server,
        });

        scanResults.set(scanId, result);
        historyEntry.status = result.status === "completed" ? "completed" : result.status === "timeout" ? "timeout" : "failed";
        historyEntry.completedAt = result.completedAt;
        historyEntry.durationMs = result.durationMs;
        historyEntry.hostsUp = result.summary.hostsUp;
        historyEntry.openPorts = result.summary.openPorts;
        historyEntry.command = result.command;
        historyEntry.error = result.error;

        return {
          scanId,
          status: result.status,
          durationMs: result.durationMs,
          summary: result.summary,
          hostsCount: result.hosts.length,
          hosts: result.hosts.map(h => ({
            ip: h.ip,
            hostnames: h.hostnames,
            status: h.status,
            os: h.os,
            portsCount: h.ports.length,
            openPorts: h.ports.filter(p => p.state === "open").length,
            vendor: h.vendor,
          })),
        };
      } catch (err: any) {
        historyEntry.status = "failed";
        historyEntry.completedAt = Date.now();
        historyEntry.error = err.message;
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: `Nmap scan failed: ${err.message}`,
        });
      }
    }),

  /**
   * Quick scan — top 100 ports, fast turnaround.
   * Convenience wrapper around the "quick" profile.
   */
  quickScan: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      targets: z.array(z.string().min(1)).min(1).max(256),
      server: serverSchema,
      timeoutSeconds: z.number().int().min(30).max(600).optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      await enforceMultiTargetScope(
        input.engagementId,
        input.targets,
        "nmap_quick",
        ctx,
      );

      const scanId = generateScanId();
      const historyEntry: ScanHistoryEntry = {
        id: scanId,
        engagementId: input.engagementId,
        targets: input.targets,
        profile: "quick",
        status: "running",
        startedAt: Date.now(),
        operatorId: String(ctx.user.id),
        operatorName: ctx.user.name || undefined,
      };
      addToHistory(historyEntry);

      try {
        const result = await executeNmapScan({
          targets: input.targets,
          profile: "quick",
          engagementId: input.engagementId,
          operatorId: String(ctx.user.id),
          operatorName: ctx.user.name || undefined,
          server: input.server,
          timeoutSeconds: input.timeoutSeconds || 120,
        });

        scanResults.set(scanId, result);
        historyEntry.status = result.status === "completed" ? "completed" : "failed";
        historyEntry.completedAt = result.completedAt;
        historyEntry.durationMs = result.durationMs;
        historyEntry.hostsUp = result.summary.hostsUp;
        historyEntry.openPorts = result.summary.openPorts;
        historyEntry.command = result.command;

        return {
          scanId,
          status: result.status,
          durationMs: result.durationMs,
          summary: result.summary,
          hosts: result.hosts,
        };
      } catch (err: any) {
        historyEntry.status = "failed";
        historyEntry.completedAt = Date.now();
        historyEntry.error = err.message;
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: `Quick scan failed: ${err.message}`,
        });
      }
    }),

  /**
   * Service version scan — targeted -sV on specific ports.
   * Ideal for deep-diving into discovered services after a quick scan.
   */
  serviceScan: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      targets: z.array(z.string().min(1)).min(1).max(256),
      server: serverSchema,
      ports: z.string().min(1).describe("Port specification, e.g. '22,80,443' or '1-1024'"),
      timeoutSeconds: z.number().int().min(30).max(3600).optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      await enforceMultiTargetScope(
        input.engagementId,
        input.targets,
        "nmap_service",
        ctx,
      );

      const scanId = generateScanId();
      const historyEntry: ScanHistoryEntry = {
        id: scanId,
        engagementId: input.engagementId,
        targets: input.targets,
        profile: "service",
        status: "running",
        startedAt: Date.now(),
        operatorId: String(ctx.user.id),
        operatorName: ctx.user.name || undefined,
      };
      addToHistory(historyEntry);

      try {
        const result = await executeNmapScan({
          targets: input.targets,
          profile: "service",
          ports: input.ports,
          engagementId: input.engagementId,
          operatorId: String(ctx.user.id),
          operatorName: ctx.user.name || undefined,
          server: input.server,
          timeoutSeconds: input.timeoutSeconds || 300,
        });

        scanResults.set(scanId, result);
        historyEntry.status = result.status === "completed" ? "completed" : "failed";
        historyEntry.completedAt = result.completedAt;
        historyEntry.durationMs = result.durationMs;
        historyEntry.hostsUp = result.summary.hostsUp;
        historyEntry.openPorts = result.summary.openPorts;
        historyEntry.command = result.command;

        return {
          scanId,
          status: result.status,
          durationMs: result.durationMs,
          summary: result.summary,
          hosts: result.hosts,
        };
      } catch (err: any) {
        historyEntry.status = "failed";
        historyEntry.completedAt = Date.now();
        historyEntry.error = err.message;
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: `Service scan failed: ${err.message}`,
        });
      }
    }),

  /**
   * OS detection scan — -O with fingerprinting.
   * Requires sudo/root on the scan server.
   */
  osScan: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      targets: z.array(z.string().min(1)).min(1).max(64),
      server: serverSchema,
      timeoutSeconds: z.number().int().min(60).max(3600).optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      await enforceMultiTargetScope(
        input.engagementId,
        input.targets,
        "nmap_os_detection",
        ctx,
      );

      const scanId = generateScanId();
      const historyEntry: ScanHistoryEntry = {
        id: scanId,
        engagementId: input.engagementId,
        targets: input.targets,
        profile: "standard",
        status: "running",
        startedAt: Date.now(),
        operatorId: String(ctx.user.id),
        operatorName: ctx.user.name || undefined,
      };
      addToHistory(historyEntry);

      try {
        const result = await executeNmapScan({
          targets: input.targets,
          profile: "standard", // standard includes -O
          engagementId: input.engagementId,
          operatorId: String(ctx.user.id),
          operatorName: ctx.user.name || undefined,
          server: input.server,
          timeoutSeconds: input.timeoutSeconds || 600,
        });

        scanResults.set(scanId, result);
        historyEntry.status = result.status === "completed" ? "completed" : "failed";
        historyEntry.completedAt = result.completedAt;
        historyEntry.durationMs = result.durationMs;
        historyEntry.hostsUp = result.summary.hostsUp;
        historyEntry.openPorts = result.summary.openPorts;
        historyEntry.command = result.command;

        // Extract OS info specifically
        const osResults = result.hosts
          .filter(h => h.os)
          .map(h => ({
            ip: h.ip,
            hostnames: h.hostnames,
            os: h.os!,
            openPorts: h.ports.filter(p => p.state === "open").length,
          }));

        return {
          scanId,
          status: result.status,
          durationMs: result.durationMs,
          summary: result.summary,
          osResults,
          hosts: result.hosts,
        };
      } catch (err: any) {
        historyEntry.status = "failed";
        historyEntry.completedAt = Date.now();
        historyEntry.error = err.message;
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: `OS detection scan failed: ${err.message}`,
        });
      }
    }),

  /**
   * NSE script scan — run specific NSE script categories or individual scripts.
   * Supports auth, discovery, vuln, brute, safe_recon, web, smb categories.
   */
  scriptScan: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      targets: z.array(z.string().min(1)).min(1).max(128),
      server: serverSchema,
      /** Use a predefined script category */
      category: z.enum(["auth", "discovery", "vuln", "brute", "safe_recon", "web", "smb"]).optional(),
      /** Or specify individual scripts */
      scripts: z.array(z.string()).optional(),
      ports: z.string().optional(),
      timeoutSeconds: z.number().int().min(60).max(7200).optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      if (!input.category && (!input.scripts || input.scripts.length === 0)) {
        throw new TRPCError({
          code: "BAD_REQUEST",
          message: "Must specify either a script category or individual scripts",
        });
      }

      await enforceMultiTargetScope(
        input.engagementId,
        input.targets,
        `nmap_script_${input.category || "custom"}`,
        ctx,
      );

      // Resolve scripts from category or use individual scripts
      let resolvedScripts: string[];
      if (input.category) {
        const cat = NSE_SCRIPT_CATEGORIES[input.category];
        if (!cat) {
          throw new TRPCError({ code: "BAD_REQUEST", message: `Unknown script category: ${input.category}` });
        }
        resolvedScripts = cat.scripts;
      } else {
        resolvedScripts = input.scripts!;
      }

      const scanId = generateScanId();
      const historyEntry: ScanHistoryEntry = {
        id: scanId,
        engagementId: input.engagementId,
        targets: input.targets,
        profile: "custom",
        status: "running",
        startedAt: Date.now(),
        operatorId: String(ctx.user.id),
        operatorName: ctx.user.name || undefined,
      };
      addToHistory(historyEntry);

      try {
        const result = await executeNmapScan({
          targets: input.targets,
          profile: "custom",
          customArgs: [
            "--script", resolvedScripts.join(","),
            "-sV",
            input.ports ? `-p ${input.ports}` : "--top-ports 1000",
            "--open",
            "-oX", "-",
          ].join(" "),
          engagementId: input.engagementId,
          operatorId: String(ctx.user.id),
          operatorName: ctx.user.name || undefined,
          server: input.server,
          timeoutSeconds: input.timeoutSeconds || 900,
        });

        scanResults.set(scanId, result);
        historyEntry.status = result.status === "completed" ? "completed" : "failed";
        historyEntry.completedAt = result.completedAt;
        historyEntry.durationMs = result.durationMs;
        historyEntry.hostsUp = result.summary.hostsUp;
        historyEntry.openPorts = result.summary.openPorts;
        historyEntry.command = result.command;

        // Extract script results specifically
        const scriptFindings = result.hosts.flatMap(h =>
          h.ports.flatMap(p =>
            (p.scripts || []).map(s => ({
              host: h.ip,
              port: p.port,
              protocol: p.protocol,
              service: p.service,
              scriptId: s.id,
              output: s.output,
              elements: s.elements,
            }))
          ).concat(
            (h.scripts || []).map(s => ({
              host: h.ip,
              port: 0,
              protocol: "tcp" as const,
              service: "host",
              scriptId: s.id,
              output: s.output,
              elements: s.elements,
            }))
          )
        );

        return {
          scanId,
          status: result.status,
          durationMs: result.durationMs,
          summary: result.summary,
          scriptsUsed: resolvedScripts,
          category: input.category || "custom",
          findings: scriptFindings,
          findingsCount: scriptFindings.length,
          hosts: result.hosts,
        };
      } catch (err: any) {
        historyEntry.status = "failed";
        historyEntry.completedAt = Date.now();
        historyEntry.error = err.message;
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: `Script scan failed: ${err.message}`,
        });
      }
    }),

  /**
   * Vulnerability scan — dedicated --script vuln profile.
   * Checks for known CVEs, misconfigurations, and exploitable conditions.
   */
  vulnScan: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      targets: z.array(z.string().min(1)).min(1).max(64),
      server: serverSchema,
      ports: z.string().optional(),
      timeoutSeconds: z.number().int().min(120).max(7200).optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      await enforceMultiTargetScope(
        input.engagementId,
        input.targets,
        "nmap_vuln",
        ctx,
      );

      const scanId = generateScanId();
      const historyEntry: ScanHistoryEntry = {
        id: scanId,
        engagementId: input.engagementId,
        targets: input.targets,
        profile: "vuln",
        status: "running",
        startedAt: Date.now(),
        operatorId: String(ctx.user.id),
        operatorName: ctx.user.name || undefined,
      };
      addToHistory(historyEntry);

      try {
        const result = await executeNmapScan({
          targets: input.targets,
          profile: "vuln",
          ports: input.ports,
          engagementId: input.engagementId,
          operatorId: String(ctx.user.id),
          operatorName: ctx.user.name || undefined,
          server: input.server,
          timeoutSeconds: input.timeoutSeconds || 1800,
        });

        scanResults.set(scanId, result);
        historyEntry.status = result.status === "completed" ? "completed" : "failed";
        historyEntry.completedAt = result.completedAt;
        historyEntry.durationMs = result.durationMs;
        historyEntry.hostsUp = result.summary.hostsUp;
        historyEntry.openPorts = result.summary.openPorts;
        historyEntry.command = result.command;

        // Extract vulnerability findings from script output
        const vulnFindings = result.hosts.flatMap(h =>
          h.ports.flatMap(p =>
            (p.scripts || [])
              .filter(s => s.output.toLowerCase().includes("vulnerable") || s.output.toLowerCase().includes("cve-"))
              .map(s => ({
                host: h.ip,
                port: p.port,
                protocol: p.protocol,
                service: p.service,
                product: p.product,
                version: p.version,
                scriptId: s.id,
                output: s.output,
                cves: extractCVEs(s.output),
                isVulnerable: s.output.toLowerCase().includes("vulnerable"),
              }))
          )
        );

        return {
          scanId,
          status: result.status,
          durationMs: result.durationMs,
          summary: result.summary,
          vulnFindings,
          vulnCount: vulnFindings.length,
          vulnerableHosts: Array.from(new Set(vulnFindings.map(f => f.host))).length,
          hosts: result.hosts,
        };
      } catch (err: any) {
        historyEntry.status = "failed";
        historyEntry.completedAt = Date.now();
        historyEntry.error = err.message;
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: `Vulnerability scan failed: ${err.message}`,
        });
      }
    }),

  /**
   * Admin port scan — scan all known administrative service ports.
   * Uses the ADMIN_SERVICE_PORTS catalog from the Nmap orchestrator.
   */
  adminPortScan: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      targets: z.array(z.string().min(1)).min(1).max(128),
      server: serverSchema,
      timeoutSeconds: z.number().int().min(60).max(3600).optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      await enforceMultiTargetScope(
        input.engagementId,
        input.targets,
        "nmap_admin_ports",
        ctx,
      );

      const scanId = generateScanId();
      const historyEntry: ScanHistoryEntry = {
        id: scanId,
        engagementId: input.engagementId,
        targets: input.targets,
        profile: "service",
        status: "running",
        startedAt: Date.now(),
        operatorId: String(ctx.user.id),
        operatorName: ctx.user.name || undefined,
      };
      addToHistory(historyEntry);

      try {
        const result = await executeNmapScan({
          targets: input.targets,
          profile: "service",
          ports: getAllAdminPorts(),
          engagementId: input.engagementId,
          operatorId: String(ctx.user.id),
          operatorName: ctx.user.name || undefined,
          server: input.server,
          timeoutSeconds: input.timeoutSeconds || 600,
        });

        scanResults.set(scanId, result);
        historyEntry.status = result.status === "completed" ? "completed" : "failed";
        historyEntry.completedAt = result.completedAt;
        historyEntry.durationMs = result.durationMs;
        historyEntry.hostsUp = result.summary.hostsUp;
        historyEntry.openPorts = result.summary.openPorts;
        historyEntry.command = result.command;

        // Categorize discovered ports by service type
        const categorizedPorts: Record<string, Array<{
          host: string;
          port: number;
          service: string;
          product?: string;
          version?: string;
        }>> = {};

        for (const [category, ports] of Object.entries(ADMIN_SERVICE_PORTS)) {
          categorizedPorts[category] = [];
          for (const host of result.hosts) {
            for (const p of host.ports) {
              if (p.state === "open" && ports.includes(p.port)) {
                categorizedPorts[category].push({
                  host: host.ip,
                  port: p.port,
                  service: p.service,
                  product: p.product,
                  version: p.version,
                });
              }
            }
          }
        }

        return {
          scanId,
          status: result.status,
          durationMs: result.durationMs,
          summary: result.summary,
          categorizedPorts,
          adminPortCatalog: ADMIN_SERVICE_PORTS,
          hosts: result.hosts,
        };
      } catch (err: any) {
        historyEntry.status = "failed";
        historyEntry.completedAt = Date.now();
        historyEntry.error = err.message;
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: `Admin port scan failed: ${err.message}`,
        });
      }
    }),

  // ─── Query Endpoints ────────────────────────────────────────────────────

  /**
   * Get full scan result by scan ID.
   */
  getResult: protectedProcedure
    .input(z.object({ scanId: z.string() }))
    .query(({ input }) => {
      const result = scanResults.get(input.scanId);
      if (!result) {
        throw new TRPCError({ code: "NOT_FOUND", message: `Scan ${input.scanId} not found` });
      }
      return result;
    }),

  /**
   * Get scan result converted to SSIL-compatible observation format.
   */
  getResultAsObservations: protectedProcedure
    .input(z.object({
      scanId: z.string(),
      policyProfile: z.string().optional(),
    }))
    .query(({ input }) => {
      const result = scanResults.get(input.scanId);
      if (!result) {
        throw new TRPCError({ code: "NOT_FOUND", message: `Scan ${input.scanId} not found` });
      }
      return toNmapRawResults(result, input.policyProfile);
    }),

  /**
   * Get scan history with optional filtering.
   */
  getHistory: protectedProcedure
    .input(z.object({
      engagementId: z.number().optional(),
      profile: profileSchema.optional(),
      status: z.enum(["queued", "running", "completed", "failed", "timeout"]).optional(),
      limit: z.number().int().min(1).max(100).optional(),
      offset: z.number().int().min(0).optional(),
    }).optional())
    .query(({ input }) => {
      let filtered = [...scanHistory];
      if (input?.engagementId) {
        filtered = filtered.filter(e => e.engagementId === input.engagementId);
      }
      if (input?.profile) {
        filtered = filtered.filter(e => e.profile === input.profile);
      }
      if (input?.status) {
        filtered = filtered.filter(e => e.status === input.status);
      }
      const offset = input?.offset || 0;
      const limit = input?.limit || 25;
      return {
        total: filtered.length,
        entries: filtered.slice(offset, offset + limit),
      };
    }),

  /**
   * Get all predefined scan profiles with descriptions.
   */
  getProfiles: protectedProcedure
    .query(() => {
      return Object.entries(SCAN_PROFILE_DESCRIPTIONS).map(([key, desc]) => ({
        id: key as NmapScanProfile,
        ...desc,
      }));
    }),

  /**
   * Get all NSE script categories with their scripts.
   */
  getScriptCategories: protectedProcedure
    .query(() => {
      return Object.entries(NSE_SCRIPT_CATEGORIES).map(([key, cat]) => ({
        id: key,
        ...cat,
        scriptCount: cat.scripts.length,
      }));
    }),

  /**
   * Get the admin service ports catalog.
   */
  getAdminPorts: protectedProcedure
    .query(() => {
      return {
        categories: Object.entries(ADMIN_SERVICE_PORTS).map(([name, ports]) => ({
          name,
          ports,
          portCount: ports.length,
        })),
        totalPorts: Object.values(ADMIN_SERVICE_PORTS).flat().length,
        allPortsString: getAllAdminPorts(),
      };
    }),

  /**
   * Preflight check — verify Nmap is installed and accessible on the scan server.
   */
  preflight: protectedProcedure
    .input(z.object({ server: serverSchema }))
    .mutation(async ({ input }) => {
      return preflightCheck(input.server);
    }),
});

// ─── Helpers ────────────────────────────────────────────────────────────────

function extractCVEs(text: string): string[] {
  const cvePattern = /CVE-\d{4}-\d{4,}/gi;
  const matches = text.match(cvePattern);
  return matches ? Array.from(new Set(matches.map(c => c.toUpperCase()))) : [];
}
