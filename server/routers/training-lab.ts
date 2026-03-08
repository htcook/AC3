/**
 * Training & Test Lab Router
 *
 * Provides a lightweight scan-and-analyze pipeline for operators to test the
 * platform's LLM-driven pentest capabilities against known vulnerable training
 * sites (Juice Shop, DVWA, vulnweb, etc.) without creating a full engagement or ROE.
 *
 * Key features:
 *   - Pre-loaded catalog of training targets
 *   - Quick scan pipeline (recon → enum → vuln detection → LLM analysis)
 *   - Real-time WebSocket progress updates
 *   - LLM vulnerability correlation and attack chain analysis
 *   - Operator feedback loop for rating/correcting LLM findings
 *   - OWASP coverage tracking per session
 */

import { z } from "zod";
import { publicProcedure, protectedProcedure, router } from "../_core/trpc";
import { TRPCError } from "@trpc/server";
import crypto from "crypto";

// ─── Training Target Catalog ───────────────────────────────────────────────

export interface TrainingTarget {
  id: string;
  name: string;
  url: string;
  description: string;
  difficulty: "beginner" | "intermediate" | "advanced";
  category: string;
  knownVulns: string[];
  owaspCategories: string[];
  tags: string[];
}

export const TRAINING_TARGETS: TrainingTarget[] = [
  {
    id: "juice-shop",
    name: "OWASP Juice Shop",
    url: "https://demo.owasp-juice.shop",
    description: "Intentionally insecure web application for security training. Contains 100+ challenges covering the OWASP Top 10 and beyond.",
    difficulty: "beginner",
    category: "Web Application",
    knownVulns: ["SQL Injection", "XSS", "Broken Auth", "SSRF", "XXE", "Insecure Deserialization"],
    owaspCategories: ["A01:2025", "A02:2025", "A03:2025", "A04:2025", "A05:2025", "A06:2025", "A07:2025", "A08:2025"],
    tags: ["nodejs", "angular", "rest-api", "jwt"],
  },
  {
    id: "vulnweb-php",
    name: "Acunetix Vulnweb (PHP)",
    url: "http://testphp.vulnweb.com",
    description: "Classic PHP vulnerable web application maintained by Acunetix. Ideal for testing SQL injection, XSS, and file inclusion vulnerabilities.",
    difficulty: "beginner",
    category: "Web Application",
    knownVulns: ["SQL Injection", "XSS", "File Inclusion", "CSRF", "Directory Traversal"],
    owaspCategories: ["A01:2025", "A03:2025", "A05:2025", "A06:2025"],
    tags: ["php", "mysql", "legacy"],
  },
  {
    id: "vulnweb-asp",
    name: "Acunetix Vulnweb (ASP)",
    url: "http://testasp.vulnweb.com",
    description: "ASP.NET vulnerable web application. Tests IIS-specific vulnerabilities and .NET security misconfigurations.",
    difficulty: "intermediate",
    category: "Web Application",
    knownVulns: ["SQL Injection", "XSS", "Path Traversal", "Information Disclosure"],
    owaspCategories: ["A01:2025", "A03:2025", "A05:2025"],
    tags: ["asp.net", "iis", "mssql"],
  },
  {
    id: "vulnweb-rest",
    name: "Acunetix Vulnweb (REST)",
    url: "http://rest.vulnweb.com",
    description: "REST API vulnerable application for testing API-specific security issues including broken authentication and excessive data exposure.",
    difficulty: "intermediate",
    category: "API",
    knownVulns: ["Broken Auth", "Excessive Data Exposure", "Injection", "BOLA"],
    owaspCategories: ["A01:2025", "A03:2025", "A04:2025"],
    tags: ["rest-api", "json", "oauth"],
  },
  {
    id: "hackazon",
    name: "Hackazon",
    url: "http://hackazon.webscantest.com",
    description: "Modern vulnerable web application mimicking an e-commerce platform. Features REST API, AJAX, and complex business logic vulnerabilities.",
    difficulty: "intermediate",
    category: "E-Commerce",
    knownVulns: ["SQL Injection", "XSS", "CSRF", "Business Logic", "Auth Bypass"],
    owaspCategories: ["A01:2025", "A03:2025", "A04:2025", "A05:2025", "A07:2025"],
    tags: ["php", "rest-api", "ajax", "e-commerce"],
  },
  {
    id: "altoro-mutual",
    name: "Altoro Mutual",
    url: "http://demo.testfire.net",
    description: "IBM's vulnerable banking application. Tests financial application security including authentication, session management, and injection flaws.",
    difficulty: "intermediate",
    category: "Financial",
    knownVulns: ["SQL Injection", "XSS", "Auth Bypass", "Session Fixation", "IDOR"],
    owaspCategories: ["A01:2025", "A03:2025", "A04:2025", "A07:2025"],
    tags: ["java", "banking", "session-mgmt"],
  },
  {
    id: "zero-bank",
    name: "Zero Bank",
    url: "http://zero.webappsecurity.com",
    description: "Vulnerable banking application for testing authentication, authorization, and financial transaction security.",
    difficulty: "beginner",
    category: "Financial",
    knownVulns: ["Broken Auth", "IDOR", "XSS", "CSRF"],
    owaspCategories: ["A01:2025", "A04:2025", "A07:2025"],
    tags: ["banking", "auth", "session"],
  },
  {
    id: "webscantest",
    name: "WebScanTest",
    url: "http://www.webscantest.com",
    description: "General-purpose vulnerable web application with a variety of common web vulnerabilities for scanner testing.",
    difficulty: "beginner",
    category: "Web Application",
    knownVulns: ["XSS", "SQL Injection", "Open Redirect", "Information Disclosure"],
    owaspCategories: ["A03:2025", "A05:2025", "A06:2025"],
    tags: ["general", "scanner-test"],
  },
  {
    id: "broken-crystals",
    name: "Broken Crystals",
    url: "https://brokencrystals.com",
    description: "Modern Node.js/React benchmark app with 30+ vulns including JWT bypass, prototype pollution, GraphQL introspection, SSTI, SSRF, and LDAP injection.",
    difficulty: "advanced",
    category: "Web Application",
    knownVulns: ["JWT Bypass", "SQL Injection", "XSS", "SSRF", "SSTI", "CSRF", "IDOR", "XXE", "LDAP Injection", "OS Command Injection", "Prototype Pollution", "Brute Force", "Cookie Security", "Common Files", "Open Database", "Default Login", "Email Header Injection", "File Upload", "Full Path Disclosure", "Header Security", "HTML Injection", "HTTP Method Tampering", "Mass Assignment", "Secret Tokens", "Unvalidated Redirect", "Version Control", "GraphQL Introspection", "Business Constraint Bypass", "Date Manipulation", "ID Enumeration"],
    owaspCategories: ["A01:2025", "A02:2025", "A03:2025", "A04:2025", "A05:2025", "A06:2025", "A07:2025", "A08:2025", "A10:2025"],
    tags: ["nodejs", "react", "graphql", "jwt", "modern"],
  },
  {
    id: "gin-juice-shop",
    name: "Gin & Juice Shop (PortSwigger)",
    url: "https://ginandjuice.shop",
    description: "PortSwigger's DAST benchmark application. Features 20+ vulnerability classes including HTTP request smuggling, deserialization, and DOM-based attacks.",
    difficulty: "advanced",
    category: "Web Application",
    knownVulns: ["XSS", "SQL Injection", "SSRF", "SSTI", "XXE", "CORS Misconfiguration", "Clickjacking", "DOM-based XSS", "HTTP Request Smuggling", "WebSocket Vulns", "Deserialization", "Path Traversal", "Authentication Bypass", "Access Control", "Information Disclosure"],
    owaspCategories: ["A01:2025", "A02:2025", "A03:2025", "A05:2025", "A08:2025", "A10:2025"],
    tags: ["portswigger", "dast-benchmark", "modern", "aws"],
  },
  {
    id: "google-gruyere",
    name: "Google Gruyere",
    url: "http://google-gruyere.appspot.com/start",
    description: "Google's 'cheesy' vulnerable web app. Built in Python on GAE, features XSS, CSRF, RCE, DoS, and information disclosure vulnerabilities.",
    difficulty: "beginner",
    category: "Web Application",
    knownVulns: ["XSS", "CSRF", "Remote Code Execution", "DoS", "Information Disclosure"],
    owaspCategories: ["A01:2025", "A03:2025", "A05:2025"],
    tags: ["python", "gae", "beginner-friendly"],
  },
  {
    id: "firing-range",
    name: "Google Firing Range",
    url: "https://public-firing-range.appspot.com",
    description: "Google's XSS testbed with 50+ DOM and reflected XSS variants, CORS misconfigurations, reverse clickjacking, and mixed content issues.",
    difficulty: "intermediate",
    category: "XSS Testbed",
    knownVulns: ["DOM XSS", "Reflected XSS", "CORS Misconfiguration", "Reverse Clickjacking", "Mixed Content", "Flash Injection", "Remote Inclusion"],
    owaspCategories: ["A03:2025", "A05:2025"],
    tags: ["google", "xss", "dom", "gae"],
  },
  {
    id: "vulnweb-aspnet",
    name: "Acunetix Vulnweb (ASP.NET)",
    url: "http://testaspnet.vulnweb.com",
    description: "ASP.NET blog application with SQL injection, XSS, and .NET-specific vulnerabilities on IIS/MSSQL stack.",
    difficulty: "intermediate",
    category: "Web Application",
    knownVulns: ["SQL Injection", "XSS", "ASP.NET Misconfigurations", "Information Disclosure"],
    owaspCategories: ["A03:2025", "A05:2025"],
    tags: ["asp.net", "iis", "mssql"],
  },
  {
    id: "vulnweb-html5",
    name: "Acunetix SecurityTweets (HTML5)",
    url: "http://testhtml5.vulnweb.com",
    description: "HTML5 vulnerable application built with Flask and CouchDB. Tests HTML5-specific vulnerabilities and NoSQL injection.",
    difficulty: "intermediate",
    category: "Web Application",
    knownVulns: ["NoSQL Injection", "XSS", "HTML5 Security Issues", "CORS Misconfiguration"],
    owaspCategories: ["A03:2025", "A05:2025"],
    tags: ["html5", "flask", "couchdb", "nosql"],
  },
  {
    id: "hack-yourself-first",
    name: "Hack Yourself First (Troy Hunt)",
    url: "http://hack-yourself-first.com",
    description: "Troy Hunt's training site for developers. ASP.NET app with SQL injection, XSS, CSRF, and insecure direct object references.",
    difficulty: "beginner",
    category: "Web Application",
    knownVulns: ["SQL Injection", "XSS", "CSRF", "IDOR", "Information Disclosure", "Insecure Transport"],
    owaspCategories: ["A01:2025", "A03:2025", "A05:2025"],
    tags: ["asp.net", "iis", "developer-training"],
  },
  {
    id: "testsparker-aspnet",
    name: "Testsparker (ASP.NET)",
    url: "http://aspnet.testsparker.com",
    description: "Invicti/Netsparker test site for ASP.NET. Features SQL injection, XSS, and IIS-specific vulnerabilities.",
    difficulty: "intermediate",
    category: "Web Application",
    knownVulns: ["SQL Injection", "XSS", "Path Traversal", "Information Disclosure", "Authentication Bypass"],
    owaspCategories: ["A01:2025", "A03:2025", "A05:2025"],
    tags: ["asp.net", "iis", "mssql", "netsparker"],
  },
  {
    id: "testsparker-php",
    name: "Testsparker (PHP)",
    url: "http://php.testsparker.com",
    description: "Invicti/Netsparker test site for PHP. Features SQL injection, XSS, file inclusion, and MySQL-specific vulnerabilities.",
    difficulty: "intermediate",
    category: "Web Application",
    knownVulns: ["SQL Injection", "XSS", "File Inclusion", "Command Injection", "Information Disclosure"],
    owaspCategories: ["A01:2025", "A03:2025", "A05:2025"],
    tags: ["php", "mysql", "netsparker"],
  },
  {
    id: "testsparker-angular",
    name: "Testsparker (Angular SPA)",
    url: "http://angular.testsparker.com",
    description: "Invicti/Netsparker test site for Angular single-page applications. Tests SPA-specific vulnerabilities.",
    difficulty: "advanced",
    category: "SPA",
    knownVulns: ["DOM XSS", "Template Injection", "CORS Misconfiguration", "API Security Issues"],
    owaspCategories: ["A03:2025", "A05:2025"],
    tags: ["angular", "spa", "php", "mysql", "netsparker"],
  },
  {
    id: "pentest-ground",
    name: "Pentest-Ground",
    url: "https://pentest-ground.com",
    description: "Free playground with deliberately vulnerable web applications and network services for scanner testing.",
    difficulty: "intermediate",
    category: "Multi-App Platform",
    knownVulns: ["SQL Injection", "XSS", "Command Injection", "File Upload", "Authentication Bypass"],
    owaspCategories: ["A01:2025", "A03:2025", "A05:2025"],
    tags: ["multi-app", "apache", "nginx", "redis"],
  },
  {
    id: "scanme-nmap",
    name: "Nmap ScanMe",
    url: "http://scanme.nmap.org",
    description: "Official Nmap authorized scanning target. Ideal for network reconnaissance and port scanning validation.",
    difficulty: "beginner",
    category: "Network",
    knownVulns: ["Open Ports", "Service Detection", "OS Detection"],
    owaspCategories: [],
    tags: ["network", "nmap", "recon"],
  },
  {
    id: "custom",
    name: "Custom Target",
    url: "",
    description: "Enter a custom URL to test. Ensure you have authorization to scan the target.",
    difficulty: "advanced",
    category: "Custom",
    knownVulns: [],
    owaspCategories: [],
    tags: ["custom"],
  },
];

// ─── Scan Pipeline (lightweight, no engagement/ROE required) ───────────────

interface LabScanState {
  sessionId: string;
  phase: string;
  progress: number;
  isRunning: boolean;
  log: Array<{ ts: number; phase: string; type: string; title: string; detail: string }>;
  assets: Array<{
    hostname: string;
    ip?: string;
    ports: Array<{ port: number; service: string; version?: string }>;
    vulns: Array<{ id: string; severity: string; title: string; cve?: string; tool?: string }>;
    toolResults: Array<{ tool: string; command: string; exitCode: number; durationMs: number; findingCount: number; findings: any[]; outputPreview: string }>;
  }>;
  stats: { hostsScanned: number; portsFound: number; vulnsFound: number; toolsRun: number };
}

const labStates = new Map<string, LabScanState>();

async function addLabLog(state: LabScanState, entry: { phase: string; type: string; title: string; detail: string }) {
  state.log.push({ ts: Date.now(), ...entry });
  if (state.log.length > 300) state.log = state.log.slice(-300);
  // Broadcast via WebSocket
  try {
    const { eventHub } = await import("../lib/ws-event-hub");
    eventHub.broadcast({
      type: "training_lab:progress",
      sessionId: state.sessionId,
      timestamp: Date.now(),
      data: { phase: state.phase, progress: state.progress, log: entry },
    });
  } catch { /* ignore */ }
}

async function runLabScan(sessionId: string, targetUrl: string, scanProfile: string): Promise<void> {
  const state: LabScanState = {
    sessionId,
    phase: "recon",
    progress: 0,
    isRunning: true,
    log: [],
    assets: [],
    stats: { hostsScanned: 0, portsFound: 0, vulnsFound: 0, toolsRun: 0 },
  };
  labStates.set(sessionId, state);

  const { updateTrainingLabSession } = await import("../db");

  try {
    // Parse target URL
    let hostname: string;
    try {
      const parsed = new URL(targetUrl.startsWith("http") ? targetUrl : `https://${targetUrl}`);
      hostname = parsed.hostname;
    } catch {
      hostname = targetUrl.replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
    }

    await updateTrainingLabSession(sessionId, {
      labStatus: "scanning",
      phase: "recon",
      startedAt: Date.now(),
    });

    // Initialize asset
    state.assets.push({
      hostname,
      ports: [],
      vulns: [],
      toolResults: [],
    });

    // ── Phase 1: Recon (httpx probe) ──────────────────────────────────
    state.phase = "recon";
    state.progress = 5;
    addLabLog(state, { phase: "recon", type: "info", title: "Phase 1: Reconnaissance", detail: `Probing ${hostname}` });

    try {
      const { executeToolViaQueue } = await import("../lib/job-queue-bridge");
      
      // httpx probe
      const httpxResult = await executeToolViaQueue({
        tool: "httpx",
        args: `-u ${targetUrl} -json -title -status-code -tech-detect -follow-redirects -content-length -cdn -web-server`,
        target: hostname,
        timeoutSeconds: 60,
      }, { forceLocal: false });

      state.stats.toolsRun++;
      state.assets[0].toolResults.push({
        tool: "httpx",
        command: httpxResult.command,
        exitCode: httpxResult.exitCode,
        durationMs: httpxResult.durationMs,
        findingCount: 0,
        findings: [],
        outputPreview: httpxResult.stdout.slice(0, 2000),
      });

      // Parse httpx output for tech detection
      if (httpxResult.stdout) {
        try {
          const lines = httpxResult.stdout.trim().split("\n").filter(Boolean);
          for (const line of lines) {
            const parsed = JSON.parse(line);
            if (parsed.port) {
              const port = parseInt(parsed.port);
              if (!state.assets[0].ports.find(p => p.port === port)) {
                state.assets[0].ports.push({
                  port,
                  service: port === 443 || port === 8443 ? "https" : "http",
                  version: parsed["web-server"] || undefined,
                });
                state.stats.portsFound++;
              }
            }
          }
        } catch { /* non-JSON output */ }
      }

      addLabLog(state, { phase: "recon", type: "scan_result", title: "httpx Complete", detail: `Detected ${state.assets[0].ports.length} ports` });
    } catch (e: any) {
      addLabLog(state, { phase: "recon", type: "warning", title: "httpx Failed", detail: e.message?.slice(0, 200) || "Unknown error" });
    }

    state.progress = 15;

    // ── Phase 2: Enumeration (nmap) ──────────────────────────────────
    state.phase = "enumeration";
    addLabLog(state, { phase: "enumeration", type: "info", title: "Phase 2: Enumeration", detail: `Running nmap service detection on ${hostname}` });

    try {
      const { executeToolViaQueue } = await import("../lib/job-queue-bridge");
      
      const nmapFlags = scanProfile === "quick"
        ? `-sV -sC --top-ports 100 -T4 --open`
        : scanProfile === "deep"
        ? `-sV -sC -p- -T3 --open -A`
        : `-sV -sC --top-ports 1000 -T4 --open`;

      const nmapResult = await executeToolViaQueue({
        tool: "nmap",
        args: `${nmapFlags} ${hostname}`,
        target: hostname,
        timeoutSeconds: scanProfile === "deep" ? 600 : 300,
      }, { forceLocal: false });

      state.stats.toolsRun++;
      state.stats.hostsScanned++;

      // Parse nmap output for ports
      const portRegex = /(\d+)\/tcp\s+open\s+(\S+)\s*(.*)/g;
      let match;
      while ((match = portRegex.exec(nmapResult.stdout)) !== null) {
        const port = parseInt(match[1]);
        if (!state.assets[0].ports.find(p => p.port === port)) {
          state.assets[0].ports.push({
            port,
            service: match[2],
            version: match[3]?.trim() || undefined,
          });
          state.stats.portsFound++;
        }
      }

      state.assets[0].toolResults.push({
        tool: "nmap",
        command: nmapResult.command,
        exitCode: nmapResult.exitCode,
        durationMs: nmapResult.durationMs,
        findingCount: state.assets[0].ports.length,
        findings: state.assets[0].ports.map(p => ({ severity: "info", title: `Port ${p.port}/${p.service}` })),
        outputPreview: nmapResult.stdout.slice(0, 2000),
      });

      addLabLog(state, { phase: "enumeration", type: "scan_result", title: "nmap Complete", detail: `Found ${state.assets[0].ports.length} open ports` });
    } catch (e: any) {
      addLabLog(state, { phase: "enumeration", type: "warning", title: "nmap Failed", detail: e.message?.slice(0, 200) || "Unknown error" });
    }

    // Ensure we have at least HTTP ports for web scanning
    if (state.assets[0].ports.length === 0) {
      state.assets[0].ports.push({ port: 443, service: "https" }, { port: 80, service: "http" });
      state.stats.portsFound = 2;
    }

    state.progress = 30;

    // ── Phase 3: Vulnerability Detection (nuclei + gobuster) ─────────
    state.phase = "vuln_detection";
    addLabLog(state, { phase: "vuln_detection", type: "info", title: "Phase 3: Vulnerability Detection", detail: "Running nuclei and gobuster scans" });

    // Nuclei scan
    try {
      const { executeToolViaQueue } = await import("../lib/job-queue-bridge");
      
      const nucleiResult = await executeToolViaQueue({
        tool: "nuclei",
        args: `-u ${targetUrl} -severity low,medium,high,critical -jsonl -nc -duc -ni -timeout 10 -retries 1`,
        target: hostname,
        timeoutSeconds: scanProfile === "deep" ? 600 : 300,
      }, { forceLocal: false });

      state.stats.toolsRun++;

      // Parse nuclei JSONL output
      const nucleiFindings: any[] = [];
      if (nucleiResult.stdout) {
        const lines = nucleiResult.stdout.trim().split("\n").filter(Boolean);
        for (const line of lines) {
          try {
            const finding = JSON.parse(line);
            if (finding.info) {
              const vuln = {
                id: `nuclei-${crypto.randomBytes(4).toString("hex")}`,
                severity: (finding.info.severity || "info").toLowerCase(),
                title: `[nuclei] ${finding.info.name || finding["template-id"] || "Unknown"}`,
                cve: finding.info.classification?.["cve-id"]?.[0] || undefined,
                tool: "nuclei",
              };
              nucleiFindings.push(vuln);
              state.assets[0].vulns.push(vuln);
              state.stats.vulnsFound++;
            }
          } catch { /* skip non-JSON lines */ }
        }
      }

      state.assets[0].toolResults.push({
        tool: "nuclei",
        command: nucleiResult.command,
        exitCode: nucleiResult.exitCode,
        durationMs: nucleiResult.durationMs,
        findingCount: nucleiFindings.length,
        findings: nucleiFindings,
        outputPreview: nucleiResult.stdout.slice(0, 2000),
      });

      addLabLog(state, { phase: "vuln_detection", type: "scan_result", title: "nuclei Complete", detail: `Found ${nucleiFindings.length} vulnerabilities` });
    } catch (e: any) {
      addLabLog(state, { phase: "vuln_detection", type: "warning", title: "nuclei Failed", detail: e.message?.slice(0, 200) || "Unknown error" });
    }

    state.progress = 50;

    // Gobuster directory scan
    try {
      const { executeToolViaQueue } = await import("../lib/job-queue-bridge");
      
      const gobusterResult = await executeToolViaQueue({
        tool: "gobuster",
        args: `dir -u ${targetUrl} -w /opt/SecLists/Discovery/Web-Content/common.txt -t 20 -q --no-error`,
        target: hostname,
        timeoutSeconds: 180,
      }, { forceLocal: false });

      state.stats.toolsRun++;

      const dirFindings: any[] = [];
      if (gobusterResult.stdout) {
        const lines = gobusterResult.stdout.trim().split("\n").filter(Boolean);
        for (const line of lines) {
          if (line.includes("Status:")) {
            dirFindings.push({ severity: "info", title: `[gobuster] ${line.trim()}` });
          }
        }
      }

      state.assets[0].toolResults.push({
        tool: "gobuster",
        command: gobusterResult.command,
        exitCode: gobusterResult.exitCode,
        durationMs: gobusterResult.durationMs,
        findingCount: dirFindings.length,
        findings: dirFindings,
        outputPreview: gobusterResult.stdout.slice(0, 2000),
      });

      addLabLog(state, { phase: "vuln_detection", type: "scan_result", title: "gobuster Complete", detail: `Found ${dirFindings.length} directories` });
    } catch (e: any) {
      addLabLog(state, { phase: "vuln_detection", type: "warning", title: "gobuster Failed", detail: e.message?.slice(0, 200) || "Unknown error" });
    }

    state.progress = 65;

    // ── Phase 4: LLM Analysis (with Self-Learning) ────────────────────
    state.phase = "analyzing";
    addLabLog(state, { phase: "analyzing", type: "info", title: "Phase 4: LLM Analysis", detail: "Running AI-powered vulnerability correlation with self-learning context" });

    await updateTrainingLabSession(sessionId, {
      labStatus: "analyzing",
      phase: "analyzing",
      progress: 65,
    });

    // Determine target preset for learning context
    const targetPresetForLearning = TRAINING_TARGETS.find(t => t.url === targetUrl)?.id || "custom";

    let llmAnalysis: any = null;
    try {
      const { invokeLLM } = await import("../_core/llm");
      const { buildLearningContext } = await import("../lib/llm-self-learning");

      // Build learning context from previous sessions and operator feedback
      let learningContext = "";
      try {
        learningContext = await buildLearningContext(targetPresetForLearning);
        if (learningContext) {
          addLabLog(state, { phase: "analyzing", type: "info", title: "Learning Context Loaded", detail: `Injecting correction history and ground truth hints for ${targetPresetForLearning}` });
        }
      } catch (e: any) {
        addLabLog(state, { phase: "analyzing", type: "warning", title: "Learning Context Unavailable", detail: e.message?.slice(0, 200) || "" });
      }

      const findingsSummary = state.assets[0].vulns.map(v =>
        `[${v.severity.toUpperCase()}] ${v.title}${v.cve ? ` (${v.cve})` : ""}`
      ).join("\n");

      const toolOutputSummary = state.assets[0].toolResults.map(t =>
        `=== ${t.tool} (${t.findingCount} findings, ${t.durationMs}ms) ===\n${t.outputPreview}`
      ).join("\n\n");

      const portsSummary = state.assets[0].ports.map(p =>
        `${p.port}/${p.service}${p.version ? ` (${p.version})` : ""}`
      ).join(", ");

      const analysisPrompt = `You are an expert penetration tester analyzing scan results from a TRAINING LAB session against a known vulnerable application.

TARGET: ${hostname} (${targetUrl})
OPEN PORTS: ${portsSummary || "None detected"}

SCAN FINDINGS:
${findingsSummary || "No vulnerabilities detected by automated tools."}

RAW TOOL OUTPUT:
${toolOutputSummary.slice(0, 8000)}

Provide a comprehensive security analysis in the following JSON format:
{
  "executiveSummary": "2-3 sentence overview of the target's security posture",
  "riskScore": <1-10 integer>,
  "riskRating": "critical|high|medium|low|informational",
  "findings": [
    {
      "title": "Finding title",
      "severity": "critical|high|medium|low|info",
      "category": "OWASP category (e.g., A01:2025 Broken Access Control)",
      "description": "Detailed description of the vulnerability",
      "exploitationPath": ["Step 1", "Step 2", "Step 3"],
      "impact": "Business impact description",
      "remediation": "How to fix this vulnerability",
      "cve": "CVE-XXXX-XXXX or null",
      "confidence": "high|medium|low"
    }
  ],
  "attackChains": [
    {
      "name": "Attack chain name",
      "description": "How multiple vulnerabilities can be chained",
      "steps": ["Step 1", "Step 2"],
      "impact": "Combined impact",
      "likelihood": "high|medium|low"
    }
  ],
  "missedAreas": ["Areas that should be tested but weren't covered by automated tools"],
  "recommendations": ["Prioritized list of security improvements"]
}

Be thorough — this is a training environment, so identify as many real vulnerabilities as possible. Include both confirmed findings from the scan data AND likely vulnerabilities based on the technology stack and known issues with this type of application.
${learningContext}`;

      const result = await invokeLLM({
        messages: [
          { role: "system", content: "You are an expert penetration tester providing detailed vulnerability analysis. Always respond with valid JSON." },
          { role: "user", content: analysisPrompt },
        ],
        response_format: {
          type: "json_schema",
          json_schema: {
            name: "security_analysis",
            strict: false,
            schema: {
              type: "object",
              properties: {
                executiveSummary: { type: "string" },
                riskScore: { type: "integer" },
                riskRating: { type: "string" },
                findings: { type: "array", items: {
                  type: "object",
                  properties: {
                    title: { type: "string", description: "Vulnerability title" },
                    severity: { type: "string", description: "critical, high, medium, low, or info" },
                    category: { type: "string", description: "OWASP category or vuln class" },
                    cve: { type: "string", description: "CVE ID if applicable" },
                    description: { type: "string", description: "Detailed description" },
                    evidence: { type: "string", description: "Evidence or proof" },
                    remediation: { type: "string", description: "Fix recommendation" },
                    cvss: { type: "number", description: "CVSS score 0-10" },
                  },
                  required: ["title", "severity", "category", "description"],
                }},
                attackChains: { type: "array", items: {
                  type: "object",
                  properties: {
                    name: { type: "string", description: "Attack chain name" },
                    steps: { type: "array", items: { type: "string" }, description: "Ordered attack steps" },
                    impact: { type: "string", description: "Combined impact" },
                    likelihood: { type: "string", description: "high, medium, or low" },
                  },
                  required: ["name", "steps", "impact", "likelihood"],
                }},
                missedAreas: { type: "array", items: { type: "string" } },
                recommendations: { type: "array", items: { type: "string" } },
              },
              required: ["executiveSummary", "riskScore", "riskRating", "findings", "attackChains", "missedAreas", "recommendations"],
            },
          },
        },
        _caller: "training-lab.llmAnalysis",
      });

      const content = result.choices?.[0]?.message?.content;
      if (typeof content === "string") {
        try {
          llmAnalysis = JSON.parse(content);
        } catch {
          // Try to extract JSON from markdown code block
          const jsonMatch = content.match(/```(?:json)?\s*([\s\S]*?)```/);
          if (jsonMatch) {
            llmAnalysis = JSON.parse(jsonMatch[1]);
          }
        }
      }

      if (llmAnalysis) {
        addLabLog(state, {
          phase: "analyzing", type: "scan_result",
          title: "LLM Analysis Complete",
          detail: `Risk: ${llmAnalysis.riskRating?.toUpperCase()} (${llmAnalysis.riskScore}/10) | ${llmAnalysis.findings?.length || 0} findings | ${llmAnalysis.attackChains?.length || 0} attack chains`,
        });

        // ── Auto-score against ground truth ──
        try {
          const { scoreAgainstGroundTruth, saveAccuracyScore } = await import("../lib/llm-self-learning");
          const llmFindings = (llmAnalysis.findings || []).map((f: any) => ({
            title: f.title || "",
            severity: f.severity || "info",
            category: f.category || "",
            cve: f.cve || undefined,
          }));
          const accuracyScore = scoreAgainstGroundTruth(targetPresetForLearning, llmFindings);
          if (accuracyScore) {
            await saveAccuracyScore(sessionId, targetPresetForLearning, accuracyScore);
            addLabLog(state, {
              phase: "analyzing", type: "scan_result",
              title: "Ground Truth Scoring Complete",
              detail: `F1: ${(accuracyScore.f1Score * 100).toFixed(1)}% | Precision: ${(accuracyScore.precision * 100).toFixed(1)}% | Recall: ${(accuracyScore.recall * 100).toFixed(1)}% | TP: ${accuracyScore.truePositives} FP: ${accuracyScore.falsePositives} FN: ${accuracyScore.falseNegatives}`,
            });
            // Store accuracy score in the session for frontend display
            (llmAnalysis as any).__accuracyScore = accuracyScore;
          }
        } catch (e: any) {
          addLabLog(state, { phase: "analyzing", type: "warning", title: "Ground Truth Scoring Failed", detail: e.message?.slice(0, 200) || "" });
        }
      }
    } catch (e: any) {
      addLabLog(state, { phase: "analyzing", type: "warning", title: "LLM Analysis Failed", detail: e.message?.slice(0, 300) || "Unknown error" });
      llmAnalysis = { error: e.message, executiveSummary: "LLM analysis failed — see error details", riskScore: 0, riskRating: "unknown", findings: [], attackChains: [], missedAreas: [], recommendations: [] };
    }

    state.progress = 90;

    // ── Phase 5: OWASP Coverage ──────────────────────────────────────
    let owaspCoverage: any = null;
    try {
      const { OwaspCoverageTracker } = await import("../lib/owasp-coverage-tracker");
      const tracker = new OwaspCoverageTracker();
      tracker.registerAssetTech(hostname, state.assets[0].ports.map(p => p.service).filter(Boolean));

      // Register tool runs
      for (const tr of state.assets[0].toolResults) {
        tracker.addToolRun({ tool: tr.tool, target: hostname, command: tr.command, exitCode: tr.exitCode });
        for (const f of tr.findings) {
          tracker.addFinding({
            tool: tr.tool,
            target: hostname,
            title: f.title || "",
            severity: f.severity || "info",
            description: f.description || "",
          });
        }
      }

      owaspCoverage = tracker.getEngagementCoverage(state.sessionId || "training-lab");
    } catch (e: any) {
      addLabLog(state, { phase: "analyzing", type: "warning", title: "OWASP Coverage Failed", detail: e.message?.slice(0, 200) || "Unknown error" });
    }

    // ── Complete ─────────────────────────────────────────────────────
    state.phase = "completed";
    state.progress = 100;
    state.isRunning = false;

    addLabLog(state, {
      phase: "completed", type: "info",
      title: "Training Lab Session Complete",
      detail: `${state.stats.toolsRun} tools run | ${state.stats.vulnsFound} vulns found | ${state.assets[0].ports.length} ports discovered`,
    });

    await updateTrainingLabSession(sessionId, {
      labStatus: "completed",
      phase: "completed",
      progress: 100,
      completedAt: Date.now(),
      durationMs: Date.now() - (state.log[0]?.ts || Date.now()),
      assetsJson: state.assets,
      findingsJson: state.assets[0].vulns,
      llmAnalysisJson: llmAnalysis,
      owaspCoverageJson: owaspCoverage,
      statsJson: state.stats,
      scanLogJson: state.log,
    });

  } catch (e: any) {
    state.phase = "failed";
    state.isRunning = false;
    addLabLog(state, { phase: "failed", type: "error", title: "Session Failed", detail: e.message?.slice(0, 500) || "Unknown error" });

    await updateTrainingLabSession(sessionId, {
      labStatus: "failed",
      phase: "failed",
      errorMessage: e.message?.slice(0, 1000),
      completedAt: Date.now(),
      assetsJson: state.assets,
      findingsJson: state.assets[0]?.vulns || [],
      statsJson: state.stats,
      scanLogJson: state.log,
    }).catch(() => {});
  }
}

// ─── tRPC Router ───────────────────────────────────────────────────────────

export const trainingLabRouter = router({
  /** List available training targets */
  targets: publicProcedure.query(() => {
    return TRAINING_TARGETS.filter(t => t.id !== "custom");
  }),

  /** Start a new training lab scan session */
  startSession: protectedProcedure
    .input(z.object({
      targetId: z.string().optional(),
      customUrl: z.string().optional(),
      name: z.string().optional(),
      scanProfile: z.enum(["quick", "standard", "deep"]).default("standard"),
    }))
    .mutation(async ({ input, ctx }) => {
      const sessionId = `lab-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`;

      let targetUrl: string;
      let targetPreset: string | undefined;
      let sessionName: string;

      if (input.targetId && input.targetId !== "custom") {
        const target = TRAINING_TARGETS.find(t => t.id === input.targetId);
        if (!target) throw new TRPCError({ code: "NOT_FOUND", message: "Training target not found" });
        targetUrl = target.url;
        targetPreset = target.id;
        sessionName = input.name || `${target.name} - ${new Date().toLocaleDateString()}`;
      } else if (input.customUrl) {
        targetUrl = input.customUrl;
        targetPreset = "custom";
        sessionName = input.name || `Custom Scan - ${input.customUrl}`;
      } else {
        throw new TRPCError({ code: "BAD_REQUEST", message: "Either targetId or customUrl is required" });
      }

      const { createTrainingLabSession } = await import("../db");
      await createTrainingLabSession({
        sessionId,
        name: sessionName,
        targetUrl,
        targetPreset,
        scanProfile: input.scanProfile,
        labStatus: "queued",
        phase: "idle",
        progress: 0,
        operatorId: ctx.user?.id ? Number(ctx.user.id) : undefined,
        operatorName: ctx.user?.name || "Unknown",
      });

      // Start scan pipeline in background (non-blocking)
      runLabScan(sessionId, targetUrl, input.scanProfile).catch(err => {
        console.error(`[TrainingLab] Session ${sessionId} failed:`, err.message);
      });

      return { sessionId, name: sessionName, targetUrl };
    }),

  /** Get session status and results */
  getSession: publicProcedure
    .input(z.object({ sessionId: z.string() }))
    .query(async ({ input }) => {
      // Check in-memory state first (for live sessions)
      const liveState = labStates.get(input.sessionId);
      if (liveState) {
        return {
          sessionId: input.sessionId,
          phase: liveState.phase,
          progress: liveState.progress,
          isRunning: liveState.isRunning,
          log: liveState.log.slice(-50),
          assets: liveState.assets,
          stats: liveState.stats,
          llmAnalysis: null,
          owaspCoverage: null,
        };
      }

      // Fall back to DB
      const { getTrainingLabSession } = await import("../db");
      const session = await getTrainingLabSession(input.sessionId);
      if (!session) throw new TRPCError({ code: "NOT_FOUND", message: "Session not found" });

      return {
        sessionId: session.sessionId,
        name: session.name,
        targetUrl: session.targetUrl,
        targetPreset: session.targetPreset,
        scanProfile: session.scanProfile,
        phase: session.phase,
        progress: session.progress,
        status: session.labStatus,
        isRunning: session.labStatus === "scanning" || session.labStatus === "analyzing",
        log: (session.scanLogJson as any[]) || [],
        assets: (session.assetsJson as any[]) || [],
        stats: session.statsJson || {},
        llmAnalysis: session.llmAnalysisJson,
        owaspCoverage: session.owaspCoverageJson,
        startedAt: session.startedAt,
        completedAt: session.completedAt,
        durationMs: session.durationMs,
        errorMessage: session.errorMessage,
      };
    }),

  /** List all training lab sessions */
  listSessions: publicProcedure
    .input(z.object({ limit: z.number().min(1).max(100).default(50) }).optional())
    .query(async ({ input }) => {
      const { listTrainingLabSessions } = await import("../db");
      const sessions = await listTrainingLabSessions(input?.limit || 50);
      return sessions.map(s => ({
        sessionId: s.sessionId,
        name: s.name,
        targetUrl: s.targetUrl,
        targetPreset: s.targetPreset,
        scanProfile: s.scanProfile,
        status: s.labStatus,
        phase: s.phase,
        progress: s.progress,
        stats: s.statsJson,
        startedAt: s.startedAt,
        completedAt: s.completedAt,
        durationMs: s.durationMs,
        createdAt: s.createdAt,
      }));
    }),

  /** Re-run LLM analysis on an existing session */
  rerunAnalysis: protectedProcedure
    .input(z.object({ sessionId: z.string() }))
    .mutation(async ({ input }) => {
      const { getTrainingLabSession, updateTrainingLabSession } = await import("../db");
      const session = await getTrainingLabSession(input.sessionId);
      if (!session) throw new TRPCError({ code: "NOT_FOUND", message: "Session not found" });
      if (session.labStatus !== "completed" && session.labStatus !== "failed") {
        throw new TRPCError({ code: "BAD_REQUEST", message: "Session must be completed or failed to re-run analysis" });
      }

      const assets = (session.assetsJson as any[]) || [];
      if (assets.length === 0) throw new TRPCError({ code: "BAD_REQUEST", message: "No scan data available for analysis" });

      await updateTrainingLabSession(input.sessionId, { labStatus: "analyzing", phase: "analyzing" });

      // Run LLM analysis in background (with self-learning)
      (async () => {
        try {
          const { invokeLLM } = await import("../_core/llm");
          const { buildLearningContext, scoreAgainstGroundTruth, saveAccuracyScore } = await import("../lib/llm-self-learning");
          const asset = assets[0];
          const targetPresetForLearning = session.targetPreset || "custom";

          // Build learning context
          let learningContext = "";
          try {
            learningContext = await buildLearningContext(targetPresetForLearning);
          } catch { /* ignore */ }

          const findingsSummary = (asset.vulns || []).map((v: any) =>
            `[${(v.severity || "info").toUpperCase()}] ${v.title}${v.cve ? ` (${v.cve})` : ""}`
          ).join("\n");

          const toolOutputSummary = (asset.toolResults || []).map((t: any) =>
            `=== ${t.tool} (${t.findingCount} findings, ${t.durationMs}ms) ===\n${t.outputPreview}`
          ).join("\n\n");

          const portsSummary = (asset.ports || []).map((p: any) =>
            `${p.port}/${p.service}${p.version ? ` (${p.version})` : ""}`
          ).join(", ");

          // Include operator feedback if available
          const { getTrainingLabFeedbackForSession } = await import("../db");
          const feedback = await getTrainingLabFeedbackForSession(input.sessionId);
          let feedbackContext = "";
          if (feedback.length > 0) {
            feedbackContext = `\n\nOPERATOR FEEDBACK FROM PREVIOUS ANALYSIS:\n${feedback.map(f =>
              `Finding #${f.findingIndex}: ${f.feedbackType}${f.operatorNotes ? ` — ${f.operatorNotes}` : ""}${f.expectedSeverity ? ` (expected severity: ${f.expectedSeverity})` : ""}`
            ).join("\n")}\n\nPlease incorporate this feedback to improve your analysis accuracy.`;
          }

          const result = await invokeLLM({
            messages: [
              { role: "system", content: "You are an expert penetration tester providing detailed vulnerability analysis. Always respond with valid JSON." },
              { role: "user", content: `Analyze the following scan results from a training lab session.

TARGET: ${asset.hostname} (${session.targetUrl})
OPEN PORTS: ${portsSummary || "None detected"}

SCAN FINDINGS:
${findingsSummary || "No vulnerabilities detected by automated tools."}

RAW TOOL OUTPUT:
${toolOutputSummary.slice(0, 8000)}${feedbackContext}
${learningContext}
Respond with a JSON object containing: executiveSummary, riskScore (1-10), riskRating, findings (array with title, severity, category, description, exploitationPath, impact, remediation, cve, confidence), attackChains (array with name, description, steps, impact, likelihood), missedAreas (array of strings), recommendations (array of strings).` },
            ],
            response_format: { type: "json_schema", json_schema: { name: "security_analysis", strict: false, schema: { type: "object", properties: { executiveSummary: { type: "string" }, riskScore: { type: "integer" }, riskRating: { type: "string" }, findings: { type: "array", items: { type: "object", properties: { title: { type: "string" }, severity: { type: "string" }, category: { type: "string" }, cve: { type: "string" }, description: { type: "string" }, evidence: { type: "string" }, remediation: { type: "string" }, cvss: { type: "number" } }, required: ["title", "severity", "category", "description"] } }, attackChains: { type: "array", items: { type: "object", properties: { name: { type: "string" }, steps: { type: "array", items: { type: "string" } }, impact: { type: "string" }, likelihood: { type: "string" } }, required: ["name", "steps", "impact", "likelihood"] } }, missedAreas: { type: "array", items: { type: "string" } }, recommendations: { type: "array", items: { type: "string" } } }, required: ["executiveSummary", "riskScore", "riskRating", "findings", "attackChains", "missedAreas", "recommendations"] } } },
            _caller: "training-lab.rerunAnalysis",
          });

          const content = result.choices?.[0]?.message?.content;
          let llmAnalysis: any = null;
          if (typeof content === "string") {
            try { llmAnalysis = JSON.parse(content); } catch {
              const jsonMatch = content.match(/```(?:json)?\s*([\s\S]*?)```/);
              if (jsonMatch) llmAnalysis = JSON.parse(jsonMatch[1]);
            }
          }

          // Auto-score against ground truth
          if (llmAnalysis && targetPresetForLearning !== "custom") {
            try {
              const llmFindings = (llmAnalysis.findings || []).map((f: any) => ({
                title: f.title || "",
                severity: f.severity || "info",
                category: f.category || "",
                cve: f.cve || undefined,
              }));
              const accuracyScore = scoreAgainstGroundTruth(targetPresetForLearning, llmFindings);
              if (accuracyScore) {
                await saveAccuracyScore(input.sessionId, targetPresetForLearning, accuracyScore);
                (llmAnalysis as any).__accuracyScore = accuracyScore;
              }
            } catch { /* ignore scoring errors */ }
          }

          await updateTrainingLabSession(input.sessionId, {
            labStatus: "completed",
            phase: "completed",
            llmAnalysisJson: llmAnalysis,
          });
        } catch (e: any) {
          await updateTrainingLabSession(input.sessionId, {
            labStatus: "completed",
            phase: "completed",
            llmAnalysisJson: { error: e.message, executiveSummary: "Re-analysis failed", riskScore: 0, riskRating: "unknown", findings: [], attackChains: [], missedAreas: [], recommendations: [] },
          });
        }
      })();

      return { success: true, message: "LLM re-analysis started" };
    }),

  /** Submit operator feedback on LLM findings — also stores learning entries for self-learning */
  submitFeedback: protectedProcedure
    .input(z.object({
      sessionId: z.string(),
      findingIndex: z.number(),
      feedbackType: z.enum(["correct", "incorrect", "partial", "missed_finding", "false_positive"]),
      operatorNotes: z.string().optional(),
      expectedSeverity: z.string().optional(),
      expectedCategory: z.string().optional(),
      findingTitle: z.string().optional(),
      llmSeverity: z.string().optional(),
      llmCategory: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const { insertTrainingLabFeedbackEntry, getTrainingLabSession } = await import("../db");
      await insertTrainingLabFeedbackEntry({
        sessionId: input.sessionId,
        findingIndex: input.findingIndex,
        feedbackType: input.feedbackType,
        operatorNotes: input.operatorNotes,
        expectedSeverity: input.expectedSeverity,
        expectedCategory: input.expectedCategory,
        operatorId: ctx.user?.id ? Number(ctx.user.id) : undefined,
      });

      // Also store as a learning entry for the self-learning engine
      try {
        const { storeLearningEntry } = await import("../lib/llm-self-learning");
        const session = await getTrainingLabSession(input.sessionId);
        if (session) {
          await storeLearningEntry({
            targetPreset: session.targetPreset || "custom",
            targetUrl: session.targetUrl,
            sessionId: input.sessionId,
            findingTitle: input.findingTitle || `Finding #${input.findingIndex}`,
            llmSeverity: input.llmSeverity,
            correctSeverity: input.expectedSeverity,
            llmCategory: input.llmCategory,
            correctCategory: input.expectedCategory,
            feedbackType: input.feedbackType,
            operatorNotes: input.operatorNotes,
            operatorId: ctx.user?.id ? Number(ctx.user.id) : undefined,
          });
        }
      } catch (e: any) {
        console.error("[TrainingLab] Failed to store learning entry:", e.message);
      }

      return { success: true };
    }),

  /** Get feedback for a session */
  getFeedback: publicProcedure
    .input(z.object({ sessionId: z.string() }))
    .query(async ({ input }) => {
      const { getTrainingLabFeedbackForSession } = await import("../db");
      return getTrainingLabFeedbackForSession(input.sessionId);
    }),

  /** Cancel a running session */
  cancelSession: protectedProcedure
    .input(z.object({ sessionId: z.string() }))
    .mutation(async ({ input }) => {
      const liveState = labStates.get(input.sessionId);
      if (liveState) {
        liveState.isRunning = false;
        liveState.phase = "cancelled";
      }
      const { updateTrainingLabSession } = await import("../db");
      await updateTrainingLabSession(input.sessionId, {
        labStatus: "cancelled",
        phase: "cancelled",
        completedAt: Date.now(),
      });
      return { success: true };
    }),

  // ─── Self-Learning Endpoints ─────────────────────────────────────────────

  /** Get learning stats dashboard data */
  learningStats: publicProcedure.query(async () => {
    const { getLearningStats } = await import("../lib/llm-self-learning");
    return getLearningStats();
  }),

  /** Get accuracy trend data for a target or all targets */
  accuracyTrend: publicProcedure
    .input(z.object({ targetPreset: z.string().optional(), limit: z.number().default(50) }).optional())
    .query(async ({ input }) => {
      const { getAccuracyTrend } = await import("../lib/llm-self-learning");
      return getAccuracyTrend(input?.targetPreset, input?.limit || 50);
    }),

  /** Get ground truth for a target */
  groundTruth: publicProcedure
    .input(z.object({ targetPreset: z.string() }))
    .query(async ({ input }) => {
      const { GROUND_TRUTH_LIBRARY } = await import("../lib/llm-self-learning");
      return GROUND_TRUTH_LIBRARY[input.targetPreset] || [];
    }),

  /** Get all available ground truth targets */
  groundTruthTargets: publicProcedure.query(async () => {
    const { GROUND_TRUTH_LIBRARY } = await import("../lib/llm-self-learning");
    return Object.entries(GROUND_TRUTH_LIBRARY).map(([key, vulns]: [string, any]) => ({
      targetPreset: key,
      vulnCount: vulns.length,
      categories: [...new Set(vulns.map((v: any) => v.category))],
      severities: [...new Set(vulns.map((v: any) => v.severity))],
    }));
  }),

  /** Add a missed finding to the learning knowledge base */
  addMissedFinding: protectedProcedure
    .input(z.object({
      sessionId: z.string(),
      findingTitle: z.string(),
      severity: z.string(),
      category: z.string().optional(),
      description: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const { storeLearningEntry } = await import("../lib/llm-self-learning");
      const { getTrainingLabSession } = await import("../db");
      const session = await getTrainingLabSession(input.sessionId);
      if (!session) throw new TRPCError({ code: "NOT_FOUND", message: "Session not found" });

      await storeLearningEntry({
        targetPreset: session.targetPreset || "custom",
        targetUrl: session.targetUrl,
        sessionId: input.sessionId,
        findingTitle: input.findingTitle,
        correctSeverity: input.severity,
        correctCategory: input.category,
        feedbackType: "missed_finding",
        operatorNotes: input.description,
        operatorId: ctx.user?.id ? Number(ctx.user.id) : undefined,
      });

      return { success: true };
    }),

  /** Get learning entries for a target */
  learningEntries: publicProcedure
    .input(z.object({ targetPreset: z.string() }))
    .query(async ({ input }) => {
      const { getLearningEntries } = await import("../lib/llm-self-learning");
      return getLearningEntries(input.targetPreset);
    }),

  /** Get accuracy score for a specific session */
  sessionAccuracy: publicProcedure
    .input(z.object({ sessionId: z.string() }))
    .query(async ({ input }) => {
      const mysql = await import("mysql2/promise");
      const conn = await mysql.createConnection(process.env.DATABASE_URL);
      try {
        const [rows] = await conn.execute(
          `SELECT * FROM llm_accuracy_scores WHERE session_id = ? ORDER BY scored_at DESC LIMIT 1`,
          [input.sessionId]
        );
        const r = (rows as any[])[0];
        if (!r) return null;
        return {
          totalGroundTruth: r.total_ground_truth,
          truePositives: r.true_positives,
          falsePositives: r.false_positives,
          falseNegatives: r.false_negatives,
          precision: Number(r.precision_score),
          recall: Number(r.recall_score),
          f1Score: Number(r.f1_score),
          severityAccuracy: Number(r.severity_accuracy),
          overallScore: Number(r.overall_score),
          scoredAt: Number(r.scored_at),
        };
      } finally {
        await conn.end();
      }
    }),
});
