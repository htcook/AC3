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

export interface TrainingTargetRoE {
  provider: string;
  termsUrl: string | null;
  summary: string;
  allowed: string[];
  prohibited: string[];
  rateLimit: string | null;
  requiresOwnInstance: boolean;
  noBruteForce: boolean;
  noDoS: boolean;
  noExfiltration: boolean;
  maxScansPerDay: number | null;
  notes: string | null;
}

export interface TrainingTarget {
  id: string;
  name: string;
  url: string;
  liveInstanceUrl?: string;
  description: string;
  difficulty: "beginner" | "intermediate" | "advanced";
  category: string;
  knownVulns: string[];
  owaspCategories: string[];
  tags: string[];
  roe: TrainingTargetRoE;
}

export const TRAINING_TARGETS: TrainingTarget[] = [
  {
    id: "juice-shop",
    name: "OWASP Juice Shop",
    url: "https://demo.owasp-juice.shop",
    liveInstanceUrl: `http://${process.env.SCAN_SERVER_HOST || '159.223.152.190'}:3001`,
    description: "Intentionally insecure web application for security training. Contains 100+ challenges covering the OWASP Top 10 and beyond.",
    difficulty: "beginner",
    category: "Web Application",
    knownVulns: ["SQL Injection", "XSS", "Broken Auth", "SSRF", "XXE", "Insecure Deserialization"],
    owaspCategories: ["A01:2025", "A02:2025", "A03:2025", "A04:2025", "A05:2025", "A06:2025", "A07:2025", "A08:2025"],
    tags: ["nodejs", "angular", "rest-api", "jwt"],
    roe: {
      provider: "OWASP Foundation",
      termsUrl: "https://owasp.org/www-project-juice-shop/",
      summary: "Open-source MIT-licensed training app. Designed to be attacked. All web vulnerability testing is permitted.",
      allowed: ["Web vulnerability scanning", "SQL injection", "XSS", "Auth bypass", "CTF challenges", "Automated DAST"],
      prohibited: [],
      rateLimit: null,
      requiresOwnInstance: false,
      noBruteForce: false,
      noDoS: false,
      noExfiltration: false,
      maxScansPerDay: null,
      notes: "MIT License. Online demo instance resets periodically.",
    },
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
    roe: {
      provider: "Acunetix (Invicti)",
      termsUrl: "http://www.vulnweb.com/",
      summary: "Intentionally vulnerable website designed for testing web vulnerability scanners. Automated scanning is the intended use case.",
      allowed: ["Web vulnerability scanning", "Automated DAST", "SQL injection", "XSS testing", "File inclusion testing"],
      prohibited: ["DDoS attacks"],
      rateLimit: null,
      requiresOwnInstance: false,
      noBruteForce: false,
      noDoS: true,
      noExfiltration: false,
      maxScansPerDay: null,
      notes: "Part of the vulnweb.com family of test sites maintained by Acunetix/Invicti.",
    },
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
    roe: {
      provider: "Acunetix (Invicti)",
      termsUrl: "http://www.vulnweb.com/",
      summary: "Intentionally vulnerable website designed for testing web vulnerability scanners.",
      allowed: ["Web vulnerability scanning", "Automated DAST", "SQL injection", "XSS testing"],
      prohibited: ["DDoS attacks"],
      rateLimit: null,
      requiresOwnInstance: false,
      noBruteForce: false,
      noDoS: true,
      noExfiltration: false,
      maxScansPerDay: null,
      notes: "Part of the vulnweb.com family of test sites.",
    },
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
    roe: {
      provider: "Acunetix (Invicti)",
      termsUrl: "http://www.vulnweb.com/",
      summary: "Intentionally vulnerable REST API designed for testing API security scanners.",
      allowed: ["API security scanning", "Auth testing", "Injection testing", "Automated DAST"],
      prohibited: ["DDoS attacks"],
      rateLimit: null,
      requiresOwnInstance: false,
      noBruteForce: false,
      noDoS: true,
      noExfiltration: false,
      maxScansPerDay: null,
      notes: "Part of the vulnweb.com family of test sites.",
    },
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
    roe: {
      provider: "Rapid7",
      termsUrl: null,
      summary: "Intentionally vulnerable e-commerce application designed for security testing and scanner benchmarking.",
      allowed: ["Web vulnerability scanning", "Business logic testing", "Auth testing", "Automated DAST"],
      prohibited: ["DDoS attacks"],
      rateLimit: null,
      requiresOwnInstance: false,
      noBruteForce: false,
      noDoS: true,
      noExfiltration: false,
      maxScansPerDay: null,
      notes: "Hosted at webscantest.com. Designed for scanner benchmarking.",
    },
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
    roe: {
      provider: "HCL Technologies (formerly IBM)",
      termsUrl: "https://www.hcl-software.com/appscan/",
      summary: "Published for the sole purpose of demonstrating the effectiveness of HCL products in detecting web application vulnerabilities. Not a real banking site. Provided 'as is' without warranty.",
      allowed: ["Web vulnerability scanning", "SQL injection testing", "XSS testing", "Auth testing", "Automated DAST"],
      prohibited: ["DDoS attacks"],
      rateLimit: null,
      requiresOwnInstance: false,
      noBruteForce: false,
      noDoS: true,
      noExfiltration: false,
      maxScansPerDay: null,
      notes: "Open source on GitHub. Copyright HCL Technologies 2017-2026.",
    },
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
    roe: {
      provider: "Micro Focus / OpenText (Fortify)",
      termsUrl: "https://www.microfocus.com/about/legal/#privacy",
      summary: "Designed for Fortify WebInspect testing. Use indicates agreement to Micro Focus Terms of Use.",
      allowed: ["Web vulnerability scanning", "Auth testing", "Automated DAST"],
      prohibited: ["DDoS attacks"],
      rateLimit: null,
      requiresOwnInstance: false,
      noBruteForce: false,
      noDoS: true,
      noExfiltration: false,
      maxScansPerDay: null,
      notes: "Subject to Micro Focus Fortify Terms of Use.",
    },
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
    roe: {
      provider: "Community",
      termsUrl: null,
      summary: "General-purpose vulnerable web application designed for scanner benchmarking.",
      allowed: ["Web vulnerability scanning", "Automated DAST"],
      prohibited: ["DDoS attacks"],
      rateLimit: null,
      requiresOwnInstance: false,
      noBruteForce: false,
      noDoS: true,
      noExfiltration: false,
      maxScansPerDay: null,
      notes: null,
    },
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
    roe: {
      provider: "Bright Security (NeuraLegion)",
      termsUrl: "https://github.com/NeuraLegion/brokencrystals",
      summary: "MIT-licensed benchmark app. Only scan instances you own or have explicit permission to test. Do not disrupt service. Respect rate limits. No destructive operations without permission.",
      allowed: ["Web vulnerability scanning", "API testing", "GraphQL testing", "Automated DAST"],
      prohibited: ["DDoS attacks", "Service disruption", "Destructive operations without permission"],
      rateLimit: "Respect rate limits",
      requiresOwnInstance: false,
      noBruteForce: false,
      noDoS: true,
      noExfiltration: false,
      maxScansPerDay: null,
      notes: "MIT License. Hosted instance at brokencrystals.com. Self-hosting also available via Docker.",
    },
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
    roe: {
      provider: "PortSwigger",
      termsUrl: "https://portswigger.net/web-security/certification/terms-and-conditions/website-terms-of-use",
      summary: "PortSwigger's DAST benchmark application. Designed for Burp Suite and scanner testing. Subject to PortSwigger Terms of Use.",
      allowed: ["Web vulnerability scanning", "Automated DAST", "Manual penetration testing"],
      prohibited: ["DDoS attacks"],
      rateLimit: null,
      requiresOwnInstance: false,
      noBruteForce: false,
      noDoS: true,
      noExfiltration: false,
      maxScansPerDay: null,
      notes: "PortSwigger's official benchmark site for DAST tool validation.",
    },
  },
  {
    id: "google-gruyere",
    name: "Google Gruyere",
    url: "http://google-gruyere.appspot.com/start",
    liveInstanceUrl: "https://google-gruyere.appspot.com/447779178481370595027386738577077166232/",
    description: "Google's 'cheesy' vulnerable web app. Built in Python on GAE, features XSS, CSRF, RCE, DoS, and information disclosure vulnerabilities.",
    difficulty: "beginner",
    category: "Web Application",
    knownVulns: ["XSS", "CSRF", "Remote Code Execution", "DoS", "Information Disclosure"],
    owaspCategories: ["A01:2025", "A03:2025", "A05:2025"],
    tags: ["python", "gae", "beginner-friendly"],
    roe: {
      provider: "Google",
      termsUrl: "https://google-gruyere.appspot.com/",
      summary: "You are specifically granted authorization to attack the Gruyere application AS DIRECTED in the codelab. You may NOT attack App Engine directly or any other Google service. Each user gets a sandboxed instance via /start.",
      allowed: ["XSS testing", "CSRF testing", "Path traversal", "Info disclosure", "DoS (own instance only)", "RCE (own instance only)"],
      prohibited: ["Attacking App Engine infrastructure", "Attacking other Google services", "Attacks not described in the codelab", "Brute-force attacks"],
      rateLimit: null,
      requiresOwnInstance: true,
      noBruteForce: true,
      noDoS: false,
      noExfiltration: true,
      maxScansPerDay: null,
      notes: "IMPORTANT: Must use /start to get your own sandboxed instance. Do NOT scan the main domain directly. Google Terms of Service apply.",
    },
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
    roe: {
      provider: "Google",
      termsUrl: "https://github.com/google/firing-range",
      summary: "Google's XSS testbed under Apache 2.0 license. Designed specifically for automated web application security scanner testing.",
      allowed: ["XSS testing", "DOM testing", "CORS testing", "Automated scanning"],
      prohibited: ["Attacking App Engine infrastructure", "Attacking other Google services"],
      rateLimit: null,
      requiresOwnInstance: false,
      noBruteForce: true,
      noDoS: true,
      noExfiltration: true,
      maxScansPerDay: null,
      notes: "Apache 2.0 License. Focus on XSS variants only — not a general-purpose vuln app.",
    },
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
    roe: {
      provider: "Acunetix (Invicti)",
      termsUrl: "http://www.vulnweb.com/",
      summary: "Intentionally vulnerable website designed for testing web vulnerability scanners.",
      allowed: ["Web vulnerability scanning", "Automated DAST", "SQL injection", "XSS testing"],
      prohibited: ["DDoS attacks"],
      rateLimit: null,
      requiresOwnInstance: false,
      noBruteForce: false,
      noDoS: true,
      noExfiltration: false,
      maxScansPerDay: null,
      notes: "Part of the vulnweb.com family of test sites.",
    },
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
    roe: {
      provider: "Acunetix (Invicti)",
      termsUrl: "http://www.vulnweb.com/",
      summary: "Intentionally vulnerable website designed for testing web vulnerability scanners.",
      allowed: ["Web vulnerability scanning", "Automated DAST", "NoSQL injection testing", "XSS testing"],
      prohibited: ["DDoS attacks"],
      rateLimit: null,
      requiresOwnInstance: false,
      noBruteForce: false,
      noDoS: true,
      noExfiltration: false,
      maxScansPerDay: null,
      notes: "Part of the vulnweb.com family of test sites.",
    },
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
    roe: {
      provider: "Troy Hunt",
      termsUrl: "https://www.troyhunt.com/hack-yourself-first-how-to-go-on/",
      summary: "Troy Hunt's training site for developers to learn offensive security. Designed to be attacked as part of the Hack Yourself First methodology.",
      allowed: ["SQL injection", "XSS", "CSRF testing", "IDOR testing", "Automated DAST"],
      prohibited: ["DDoS attacks"],
      rateLimit: null,
      requiresOwnInstance: false,
      noBruteForce: false,
      noDoS: true,
      noExfiltration: false,
      maxScansPerDay: null,
      notes: "Associated with Troy Hunt's Pluralsight course.",
    },
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
    roe: {
      provider: "Invicti (formerly Netsparker)",
      termsUrl: "https://www.invicti.com/legal/ssa",
      summary: "Test site for Invicti/Netsparker scanner validation. Designed for automated scanner testing.",
      allowed: ["Web vulnerability scanning", "Automated DAST"],
      prohibited: ["DDoS attacks"],
      rateLimit: null,
      requiresOwnInstance: false,
      noBruteForce: false,
      noDoS: true,
      noExfiltration: false,
      maxScansPerDay: null,
      notes: "Maintained by Invicti for scanner benchmarking.",
    },
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
    roe: {
      provider: "Invicti (formerly Netsparker)",
      termsUrl: "https://www.invicti.com/legal/ssa",
      summary: "Test site for Invicti/Netsparker scanner validation. Designed for automated scanner testing.",
      allowed: ["Web vulnerability scanning", "Automated DAST"],
      prohibited: ["DDoS attacks"],
      rateLimit: null,
      requiresOwnInstance: false,
      noBruteForce: false,
      noDoS: true,
      noExfiltration: false,
      maxScansPerDay: null,
      notes: "Maintained by Invicti for scanner benchmarking.",
    },
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
    roe: {
      provider: "Invicti (formerly Netsparker)",
      termsUrl: "https://www.invicti.com/legal/ssa",
      summary: "Test site for Invicti/Netsparker scanner validation. Tests SPA-specific vulnerabilities.",
      allowed: ["Web vulnerability scanning", "Automated DAST", "SPA testing"],
      prohibited: ["DDoS attacks"],
      rateLimit: null,
      requiresOwnInstance: false,
      noBruteForce: false,
      noDoS: true,
      noExfiltration: false,
      maxScansPerDay: null,
      notes: "Maintained by Invicti for scanner benchmarking.",
    },
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
    roe: {
      provider: "Community",
      termsUrl: "https://pentest-ground.com",
      summary: "Free playground with deliberately vulnerable web applications and network services for scanner testing.",
      allowed: ["Web vulnerability scanning", "Network scanning", "Automated DAST"],
      prohibited: ["DDoS attacks"],
      rateLimit: null,
      requiresOwnInstance: false,
      noBruteForce: false,
      noDoS: true,
      noExfiltration: false,
      maxScansPerDay: null,
      notes: "Community-maintained playground.",
    },
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
    roe: {
      provider: "Nmap Project (Fyodor)",
      termsUrl: "http://scanme.nmap.org/",
      summary: "Authorized for port scanning with Nmap or other port scanners. A few scans per day is fine. Do NOT scan 100+ times per day. Do NOT use for SSH brute-force password cracking.",
      allowed: ["Port scanning", "Service detection", "OS detection", "Nmap scripts"],
      prohibited: ["SSH brute-force", "Password cracking", "Excessive scanning (>100/day)", "DDoS attacks"],
      rateLimit: "A few scans per day. Do not exceed 100 scans/day.",
      requiresOwnInstance: false,
      noBruteForce: true,
      noDoS: true,
      noExfiltration: false,
      maxScansPerDay: 10,
      notes: "Explicitly stated: 'don't scan 100 times a day or use this site to test your ssh brute-force password cracking tool.'",
    },
  },
  {
    id: "dvwa",
    name: "Damn Vulnerable Web Application (DVWA)",
    url: "https://github.com/digininja/DVWA",
    liveInstanceUrl: `http://${process.env.SCAN_SERVER_HOST || '159.223.152.190'}:3002`,
    description: "PHP/MySQL web application that is intentionally vulnerable. Covers SQL injection, XSS, CSRF, file inclusion, command injection, brute force, and more. Multiple security levels (low/medium/high/impossible).",
    difficulty: "beginner",
    category: "Web Application",
    knownVulns: ["SQL Injection", "XSS (Reflected)", "XSS (Stored)", "XSS (DOM)", "CSRF", "File Inclusion", "File Upload", "Command Injection", "Brute Force", "Insecure CAPTCHA", "Weak Session IDs", "Open HTTP Redirect", "Content Security Policy Bypass", "JavaScript Attacks"],
    owaspCategories: ["A01:2025", "A02:2025", "A03:2025", "A04:2025", "A05:2025", "A06:2025", "A07:2025"],
    tags: ["php", "mysql", "beginner-friendly", "multi-level", "classic"],
    roe: {
      provider: "DVWA Project (digininja)",
      termsUrl: "https://github.com/digininja/DVWA",
      summary: "Open-source GPL-licensed training app. Designed to be attacked. Self-hosted instance — you own it, full permission to test.",
      allowed: ["All web vulnerability testing", "SQL injection", "XSS", "Command injection", "File upload attacks", "Brute force", "CSRF", "Automated DAST"],
      prohibited: [],
      rateLimit: null,
      requiresOwnInstance: false,
      noBruteForce: false,
      noDoS: false,
      noExfiltration: false,
      maxScansPerDay: null,
      notes: "Self-hosted on scan server. Default credentials: admin/password. Set security level via DVWA Security page.",
    },
  },
  {
    id: "vampi",
    name: "VAmPI (Vulnerable REST API)",
    url: "https://github.com/NeuraLegion/VAmPI",
    liveInstanceUrl: `http://${process.env.SCAN_SERVER_HOST || '159.223.152.190'}:5000`,
    description: "Intentionally vulnerable REST API built with Flask. Based on OWASP API Top 10 vulnerabilities. Features token-based auth, Swagger UI, and a global switch to toggle vulnerable/secure mode. Ideal for testing API-specific security issues.",
    difficulty: "intermediate",
    category: "API",
    knownVulns: ["SQL Injection", "Unauthorized Password Change", "Broken Object Level Authorization (BOLA)", "Mass Assignment", "Excessive Data Exposure", "User and Password Enumeration", "RegexDOS", "Lack of Resources & Rate Limiting", "JWT Authentication Bypass"],
    owaspCategories: ["A01:2025", "A02:2025", "A03:2025", "A04:2025", "A06:2025", "A07:2025"],
    tags: ["python", "flask", "rest-api", "openapi3", "jwt", "owasp-api-top10"],
    roe: {
      provider: "NeuraLegion (Bright Security)",
      termsUrl: "https://github.com/NeuraLegion/VAmPI",
      summary: "Open-source MIT-licensed vulnerable API. Self-hosted instance — you own it, full permission to test. Designed specifically for API security scanner validation.",
      allowed: ["API vulnerability scanning", "SQL injection", "Auth bypass", "BOLA testing", "Mass assignment", "JWT attacks", "Rate limit testing", "Automated DAST"],
      prohibited: [],
      rateLimit: null,
      requiresOwnInstance: false,
      noBruteForce: false,
      noDoS: false,
      noExfiltration: false,
      maxScansPerDay: null,
      notes: "Self-hosted on scan server. Swagger UI at /ui/. Initialize DB via GET /createdb. Vulnerable mode enabled by default.",
    },
  },
  {
    id: "dvga",
    name: "Damn Vulnerable GraphQL Application (DVGA)",
    url: "https://github.com/NeuraLegion/Damn-Vulnerable-GraphQL-Application",
    liveInstanceUrl: `http://${process.env.SCAN_SERVER_HOST || '159.223.152.190'}:5013`,
    description: "Intentionally vulnerable GraphQL implementation for learning and practicing GraphQL security. Supports queries, mutations, and subscriptions with 20+ vulnerability scenarios including injections, code execution, DoS, and authorization bypass.",
    difficulty: "advanced",
    category: "API",
    knownVulns: ["GraphQL Introspection", "GraphiQL Interface Exposure", "GraphQL Field Suggestions", "Batch Query Attack", "Deep Recursion Query Attack", "Resource Intensive Query Attack", "Field Duplication Attack", "Aliases-based Attack", "OS Command Injection", "SQL Injection", "Stored XSS", "HTML Injection", "Log Injection", "SSRF", "Stack Trace Errors", "GraphQL JWT Token Forge", "Interface Protection Bypass", "Query Deny List Bypass", "Weak Password Protection", "Arbitrary File Write", "Path Traversal"],
    owaspCategories: ["A01:2025", "A03:2025", "A04:2025", "A05:2025", "A06:2025", "A08:2025", "A10:2025"],
    tags: ["python", "graphql", "graphene", "flask", "nosql", "websockets"],
    roe: {
      provider: "NeuraLegion (Bright Security) / Dolev Farhi",
      termsUrl: "https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application",
      summary: "MIT-licensed vulnerable GraphQL app. Self-hosted instance — full permission to test. Supports Beginner and Expert difficulty modes.",
      allowed: ["GraphQL security testing", "Introspection attacks", "Injection testing", "DoS testing (own instance)", "Auth bypass", "Code execution testing", "Automated DAST"],
      prohibited: [],
      rateLimit: null,
      requiresOwnInstance: false,
      noBruteForce: false,
      noDoS: false,
      noExfiltration: false,
      maxScansPerDay: null,
      notes: "Self-hosted on scan server. Web UI at root path. Supports Beginner and Expert game modes.",
    },
  },
  {
    id: "webgoat",
    name: "OWASP WebGoat",
    url: "https://github.com/WebGoat/WebGoat",
    liveInstanceUrl: `http://${process.env.SCAN_SERVER_HOST || '159.223.152.190'}:8080/WebGoat`,
    description: "OWASP's flagship deliberately insecure web application for teaching web application security. Includes guided lessons covering the full OWASP Top 10, with hands-on exercises for SQL injection, XSS, CSRF, XXE, insecure deserialization, and more. WebWolf companion app on port 9090.",
    difficulty: "beginner",
    category: "Web Application",
    knownVulns: ["SQL Injection", "XSS", "CSRF", "XXE", "Insecure Deserialization", "Broken Access Control", "Security Misconfiguration", "Sensitive Data Exposure", "Insufficient Logging", "SSRF", "Authentication Flaws", "JWT Vulnerabilities", "Path Traversal", "Insecure Direct Object References", "Cryptographic Failures"],
    owaspCategories: ["A01:2025", "A02:2025", "A03:2025", "A04:2025", "A05:2025", "A06:2025", "A07:2025", "A08:2025", "A09:2025", "A10:2025"],
    tags: ["java", "spring-boot", "owasp", "educational", "guided-lessons"],
    roe: {
      provider: "OWASP Foundation",
      termsUrl: "https://github.com/WebGoat/WebGoat",
      summary: "Open-source GPL-licensed OWASP training app. Self-hosted instance — full permission to test. Designed for learning web application security through guided lessons.",
      allowed: ["All web vulnerability testing", "SQL injection", "XSS", "CSRF", "XXE", "Deserialization attacks", "Auth bypass", "JWT attacks", "Path traversal", "Automated DAST"],
      prohibited: [],
      rateLimit: null,
      requiresOwnInstance: false,
      noBruteForce: false,
      noDoS: false,
      noExfiltration: false,
      maxScansPerDay: null,
      notes: "Self-hosted on scan server. WebGoat at :8080/WebGoat/, WebWolf at :9090/WebWolf/. Register an account to start lessons.",
    },
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
    roe: {
      provider: "User-provided",
      termsUrl: null,
      summary: "Custom target. YOU must ensure you have written authorization (ROE) before scanning. The platform will not enforce rules for custom targets — all responsibility lies with the operator.",
      allowed: [],
      prohibited: [],
      rateLimit: null,
      requiresOwnInstance: false,
      noBruteForce: false,
      noDoS: false,
      noExfiltration: false,
      maxScansPerDay: null,
      notes: "WARNING: Scanning without authorization is illegal. Ensure you have a signed ROE before proceeding.",
    },
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

  // Helper to yield the event loop between tool executions
  // This prevents the server from becoming unresponsive during long scans
  const yieldEventLoop = () => new Promise<void>(resolve => setImmediate(resolve));

  // Helper to update DB with current progress (non-blocking)
  // IMPORTANT: Strip heavy tool output to prevent JSON.stringify from blocking the event loop.
  // The full data is saved only at the end of the scan.
  const syncProgress = async () => {
    try {
      // Create lightweight copies — strip outputPreview from toolResults to avoid
      // serializing hundreds of KB of nmap/nuclei/nikto/gobuster raw output every sync.
      const lightAssets = state.assets.map((a: any) => ({
        ...a,
        toolResults: (a.toolResults || []).map((tr: any) => ({
          tool: tr.tool,
          status: tr.status,
          exitCode: tr.exitCode,
          findingCount: tr.findingCount,
          duration: tr.duration,
          // Truncate outputPreview to 200 chars for progress display
          outputPreview: (tr.outputPreview || '').slice(0, 200),
          findings: (tr.findings || []).slice(0, 20),
        })),
        // Keep vulns but cap at 30
        vulns: (a.vulns || []).slice(0, 30),
      }));
      // Cap log entries to last 50
      const lightLog = (state.log || []).slice(-50);
      await updateTrainingLabSession(sessionId, {
        labStatus: "scanning",
        phase: state.phase,
        progress: state.progress,
        statsJson: state.stats,
        assetsJson: lightAssets,
        findingsJson: (state.assets[0]?.vulns || []).slice(0, 30),
        scanLogJson: lightLog,
      });
    } catch { /* non-critical */ }
  };

  try {
    // Parse target URL — preserve full URL with port for tool commands
    let hostname: string;
    let targetPort: number | null = null;
    let targetScheme = "http";
    try {
      const parsed = new URL(targetUrl.startsWith("http") ? targetUrl : `https://${targetUrl}`);
      hostname = parsed.hostname;
      targetPort = parsed.port ? parseInt(parsed.port) : null;
      targetScheme = parsed.protocol.replace(":", "");
    } catch {
      hostname = targetUrl.replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
      const portMatch = targetUrl.match(/:(\d+)/);
      if (portMatch) targetPort = parseInt(portMatch[1]);
    }

    // The full URL to scan (preserving port)
    const fullTargetUrl = targetUrl.startsWith("http") ? targetUrl : `${targetScheme}://${targetUrl}`;

    // When the scan server scans its own IP, Docker-published ports appear "filtered".
    // Detect self-hosted targets and rewrite to 127.0.0.1 for all tools.
    const scanServerHost = process.env.SCAN_SERVER_HOST || '';
    const isSelfHosted = (hostname === scanServerHost || hostname === '159.223.152.190');
    const scanUrl = isSelfHosted ? fullTargetUrl.replace(hostname, '127.0.0.1') : fullTargetUrl;
    const scanHostname = isSelfHosted ? '127.0.0.1' : hostname;

    await updateTrainingLabSession(sessionId, {
      labStatus: "scanning",
      phase: "recon",
      startedAt: Date.now(),
    });

    // ── Load RoE for this target (if it's a known training target) ──
    let targetRoE: import("../lib/training-roe-guard").RoECheckResult | null = null;
    const matchedTarget = TRAINING_TARGETS.find(t => t.url === targetUrl || t.liveInstanceUrl === targetUrl || hostname.includes(new URL(t.url.startsWith("http") ? t.url : `https://${t.url}`).hostname));
    if (matchedTarget) {
      const { enforceTrainingRoE } = await import("../lib/training-roe-guard");
      targetRoE = enforceTrainingRoE(matchedTarget, { targetId: matchedTarget.id, scanProfile: scanProfile as any });
      if (targetRoE.enforcedRules.length > 0) {
        addLabLog(state, { phase: "recon", type: "info", title: "RoE Guardrails Active", detail: `Enforcing: ${targetRoE.enforcedRules.join(", ")}` });
      }
      if (targetRoE.warnings.length > 0) {
        for (const w of targetRoE.warnings) {
          addLabLog(state, { phase: "recon", type: "warning", title: "RoE Warning", detail: w.message });
        }
      }
    }

    // Initialize asset
    state.assets.push({
      hostname,
      ports: [],
      vulns: [],
      toolResults: [],
    });

    // ── Phase 1: Recon (httpx probe + curl headers) ──────────────────
    state.phase = "recon";
    state.progress = 5;
    addLabLog(state, { phase: "recon", type: "info", title: "Phase 1: Reconnaissance", detail: `Probing ${fullTargetUrl}` });

    // httpx probe — MUST use stdin piping (httpx -u flag hangs without TTY)
    try {
      const { executeRawCommandViaQueue } = await import("../lib/job-queue-bridge");
      
      const httpxCmd = `echo '${scanUrl}' | httpx -silent -nc -json -follow-redirects -tech-detect -status-code -title -web-server -content-length -content-type`;
      const httpxResult = await executeRawCommandViaQueue(httpxCmd, 60);

      state.stats.toolsRun++;
      state.assets[0].toolResults.push({
        tool: "httpx",
        command: httpxCmd,
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
            // Store httpx metadata for LLM context
            if (parsed.title) (state.assets[0] as any).httpxTitle = parsed.title;
            if (parsed.tech) (state.assets[0] as any).httpxTech = parsed.tech;
            if (parsed.content_type) (state.assets[0] as any).httpxContentType = parsed.content_type;
          }
        } catch { /* non-JSON output */ }
      }

      addLabLog(state, { phase: "recon", type: "scan_result", title: "httpx Complete", detail: `Detected ${state.assets[0].ports.length} ports` });
    } catch (e: any) {
      addLabLog(state, { phase: "recon", type: "warning", title: "httpx Failed", detail: e.message?.slice(0, 200) || "Unknown error" });
    }

    await yieldEventLoop();
    await syncProgress();

    // curl header probe — lightweight fallback for additional signal
    try {
      const { executeRawCommandViaQueue } = await import("../lib/job-queue-bridge");
      const curlCmd = `curl -sI -m 15 -L '${scanUrl}' 2>&1 | head -50`;
      const curlResult = await executeRawCommandViaQueue(curlCmd, 20);
      state.stats.toolsRun++;

      const headerFindings: any[] = [];
      if (curlResult.stdout) {
        const headers = curlResult.stdout.toLowerCase();
        // Check for security-relevant headers
        if (!headers.includes("content-security-policy")) headerFindings.push({ severity: "low", title: "[headers] Missing Content-Security-Policy" });
        if (!headers.includes("strict-transport-security")) headerFindings.push({ severity: "low", title: "[headers] Missing Strict-Transport-Security" });
        if (headers.includes("access-control-allow-origin: *")) headerFindings.push({ severity: "medium", title: "[headers] Permissive CORS: Access-Control-Allow-Origin: *" });
        if (headers.includes("server:")) {
          const serverMatch = curlResult.stdout.match(/[Ss]erver:\s*(.+)/i);
          if (serverMatch) headerFindings.push({ severity: "info", title: `[headers] Server: ${serverMatch[1].trim()}` });
        }
      }

      state.assets[0].toolResults.push({
        tool: "curl",
        command: curlCmd,
        exitCode: curlResult.exitCode,
        durationMs: curlResult.durationMs,
        findingCount: headerFindings.length,
        findings: headerFindings,
        outputPreview: curlResult.stdout.slice(0, 2000),
      });

      addLabLog(state, { phase: "recon", type: "scan_result", title: "Header Probe Complete", detail: `Found ${headerFindings.length} header issues` });
    } catch (e: any) {
      addLabLog(state, { phase: "recon", type: "warning", title: "Header Probe Failed", detail: e.message?.slice(0, 200) || "Unknown error" });
    }

    state.progress = 15;
    await yieldEventLoop();
    await syncProgress();

    // ── Phase 2: Enumeration (nmap) ──────────────────────────────────
    state.phase = "enumeration";
    addLabLog(state, { phase: "enumeration", type: "info", title: "Phase 2: Enumeration", detail: `Running nmap service detection on ${hostname}` });

    try {
      const { executeToolViaQueue } = await import("../lib/job-queue-bridge");
      
      // For non-standard ports (e.g., 3001, 3002), target those ports specifically
      // instead of scanning top-N ports which might miss them
      let nmapFlags: string;
      if (targetPort && targetPort > 1024) {
        // Non-standard port: scan the specific port + common web ports
        nmapFlags = scanProfile === "quick"
          ? `-sV -sC -p ${targetPort},80,443 -T4 --open`
          : scanProfile === "deep"
          ? `-sV -sC -p ${targetPort},80,443,8080,8443,8000,3000,5000,9090 -T3 --open -A`
          : `-sV -sC -p ${targetPort},80,443,8080,8443,8000,3000,5000,9090 -T4 --open`;
      } else {
        nmapFlags = scanProfile === "quick"
          ? `-sV -sC --top-ports 100 -T4 --open`
          : scanProfile === "deep"
          ? `-sV -sC -p- -T3 --open -A`
          : `-sV -sC --top-ports 1000 -T4 --open`;
      }

      // Sanitize nmap flags based on target RoE
      if (matchedTarget) {
        const { sanitizeNmapFlags } = await import("../lib/training-roe-guard");
        const original = nmapFlags;
        nmapFlags = sanitizeNmapFlags(nmapFlags, matchedTarget.roe);
        if (nmapFlags !== original) {
          addLabLog(state, { phase: "enumeration", type: "info", title: "RoE: Nmap Flags Sanitized", detail: `Adjusted flags to comply with ${matchedTarget.name} RoE` });
        }
      }

      const nmapTarget = scanHostname;
      // Always add -Pn to skip host discovery (avoids filtered port issues)
      const nmapFlagsWithPn = nmapFlags.includes('-Pn') ? nmapFlags : `${nmapFlags} -Pn`;

      const nmapResult = await executeToolViaQueue({
        tool: "nmap",
        args: `${nmapFlagsWithPn} ${nmapTarget}`,
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
        outputPreview: nmapResult.stdout.replace(/\| fingerprint-strings:[\s\S]*?(?=\n\w|\nNmap|$)/g, '| [fingerprint data omitted]').slice(0, 1500),
      });

      addLabLog(state, { phase: "enumeration", type: "scan_result", title: "nmap Complete", detail: `Found ${state.assets[0].ports.length} open ports` });
    } catch (e: any) {
      addLabLog(state, { phase: "enumeration", type: "warning", title: "nmap Failed", detail: e.message?.slice(0, 200) || "Unknown error" });
    }

    // Ensure we have at least the target port for web scanning
    if (state.assets[0].ports.length === 0) {
      if (targetPort) {
        state.assets[0].ports.push({ port: targetPort, service: targetScheme });
        state.stats.portsFound = 1;
      } else {
        state.assets[0].ports.push({ port: 443, service: "https" }, { port: 80, service: "http" });
        state.stats.portsFound = 2;
      }
    }

    state.progress = 30;
    await yieldEventLoop();
    await syncProgress();

    // ── Phase 3: Vulnerability Detection (nuclei + nikto + gobuster) ──
    state.phase = "vuln_detection";
    addLabLog(state, { phase: "vuln_detection", type: "info", title: "Phase 3: Vulnerability Detection", detail: "Running nuclei, nikto, and gobuster scans" });

    // ── Nuclei: Technology-Aware Sequential Multi-Pass Scanning ──
    // Instead of running all tags (5000+ templates, 10+ min), we run 3 focused sequential
    // passes with event loop yields between them. Each pass has a short timeout (25-40s).
    // Total time ≈ 75-120s with full coverage of DAST + tech-specific + exposure checks.
    const nucleiFindings: any[] = [];
    const seenTemplates = new Set<string>();
    let totalNucleiDurationMs = 0;

    // Helper to parse nuclei JSONL output and deduplicate findings
    function parseNucleiOutput(output: string) {
      const lines = output.trim().split("\n").filter(Boolean);
      for (const line of lines) {
        try {
          const finding = JSON.parse(line);
          if (finding.info) {
            const dedupKey = `${finding["template-id"]}:${finding["matched-at"] || ''}`;
            if (seenTemplates.has(dedupKey)) continue;
            seenTemplates.add(dedupKey);
            const vuln = {
              id: `nuclei-${crypto.randomBytes(4).toString("hex")}`,
              severity: (finding.info.severity || "info").toLowerCase(),
              title: `[nuclei] ${finding.info.name || finding["template-id"] || "Unknown"}`,
              cve: finding.info.classification?.["cve-id"]?.[0] || undefined,
              tool: "nuclei",
              matchedAt: finding["matched-at"] || undefined,
              description: finding.info.description || undefined,
            };
            nucleiFindings.push(vuln);
            state.assets[0].vulns.push(vuln);
            state.stats.vulnsFound++;
          }
        } catch { /* skip non-JSON lines */ }
      }
    }

    // Build technology-specific template args based on httpx detection
    const httpxTech: string[] = ((state.assets[0] as any).httpxTech || []).map((t: string) => t.toLowerCase());
    const httpxTitle: string = ((state.assets[0] as any).httpxTitle || '').toLowerCase();
    const techStr = httpxTech.join(' ') + ' ' + httpxTitle;
    const techTemplatePaths: string[] = [];
    if (techStr.includes('php') || techStr.includes('apache')) {
      techTemplatePaths.push('-t http/misconfiguration/php*', '-t http/vulnerabilities/php*', '-t http/misconfiguration/apache*');
    }
    if (techStr.includes('node') || techStr.includes('express') || techStr.includes('next')) {
      techTemplatePaths.push('-t http/misconfiguration/node*', '-t http/exposures/configs/node*');
    }
    if (techStr.includes('nginx')) {
      techTemplatePaths.push('-t http/misconfiguration/nginx*', '-t http/vulnerabilities/nginx*');
    }
    if (techStr.includes('wordpress') || techStr.includes('wp-')) {
      techTemplatePaths.push('-t http/misconfiguration/wordpress*', '-t http/vulnerabilities/wordpress*');
    }
    // Always include generic web security misconfigs
    techTemplatePaths.push(
      '-t http/misconfiguration/cors*', '-t http/misconfiguration/csp*',
      '-t http/misconfiguration/security-header*', '-t http/misconfiguration/directory-listing*',
      '-t http/misconfiguration/cookie*', '-t http/misconfiguration/x-frame*',
    );

    const nucleiBase = `-jsonl -nc -or -ot -ni -timeout 8 -retries 0 -rate-limit 200 -silent -concurrency 15`;
    const { executeRawCommandViaQueue: execNucleiCmd } = await import("../lib/job-queue-bridge");

    // Pass 1: DAST active vulnerability testing (XSS, SQLi, LFI, SSRF, SSTI, etc.)
    // These 237 templates actively fuzz for vulns — highest value for ground truth matching
    try {
      const dastTimeout = scanProfile === 'deep' ? 60 : 40;
      const dastCmd = `timeout ${dastTimeout} bash -c "echo '${scanUrl}' | nuclei ${nucleiBase} -t dast/vulnerabilities/ -severity low,medium,high,critical" 2>&1`;
      addLabLog(state, { phase: "vuln_detection", type: "info", title: "nuclei Pass 1/3", detail: "DAST active testing (XSS, SQLi, LFI, SSRF, SSTI)" });
      const r1 = await execNucleiCmd(dastCmd, dastTimeout + 15);
      totalNucleiDurationMs += r1.durationMs;
      parseNucleiOutput((r1.stdout || '') + '\n' + (r1.stderr || ''));
      addLabLog(state, { phase: "vuln_detection", type: "scan_result", title: "nuclei Pass 1 Done", detail: `+${nucleiFindings.length} findings (${Math.round(r1.durationMs/1000)}s)` });
    } catch (e: any) {
      addLabLog(state, { phase: "vuln_detection", type: "warning", title: "nuclei Pass 1 Failed", detail: e.message?.slice(0, 150) });
    }
    await yieldEventLoop();

    // Pass 2: Technology-specific misconfiguration checks
    try {
      const techTimeout = scanProfile === 'deep' ? 45 : 30;
      const techArgs = techTemplatePaths.join(' ');
      const techCmd = `timeout ${techTimeout} bash -c "echo '${scanUrl}' | nuclei ${nucleiBase} ${techArgs}" 2>&1`;
      addLabLog(state, { phase: "vuln_detection", type: "info", title: "nuclei Pass 2/3", detail: `Tech-specific checks (${httpxTech.slice(0,3).join(', ') || 'generic'})` });
      const r2 = await execNucleiCmd(techCmd, techTimeout + 15);
      totalNucleiDurationMs += r2.durationMs;
      const beforeCount = nucleiFindings.length;
      parseNucleiOutput((r2.stdout || '') + '\n' + (r2.stderr || ''));
      addLabLog(state, { phase: "vuln_detection", type: "scan_result", title: "nuclei Pass 2 Done", detail: `+${nucleiFindings.length - beforeCount} findings (${Math.round(r2.durationMs/1000)}s)` });
    } catch (e: any) {
      addLabLog(state, { phase: "vuln_detection", type: "warning", title: "nuclei Pass 2 Failed", detail: e.message?.slice(0, 150) });
    }
    await yieldEventLoop();

    // Pass 3: Exposure checks (leaked configs, API keys, backups, exposed panels)
    try {
      const expTimeout = scanProfile === 'deep' ? 45 : 30;
      const expCmd = `timeout ${expTimeout} bash -c "echo '${scanUrl}' | nuclei ${nucleiBase} -t http/exposures/ -t http/exposed-panels/ -severity info,low,medium,high,critical" 2>&1`;
      addLabLog(state, { phase: "vuln_detection", type: "info", title: "nuclei Pass 3/3", detail: "Exposure & panel checks" });
      const r3 = await execNucleiCmd(expCmd, expTimeout + 15);
      totalNucleiDurationMs += r3.durationMs;
      const beforeCount = nucleiFindings.length;
      parseNucleiOutput((r3.stdout || '') + '\n' + (r3.stderr || ''));
      addLabLog(state, { phase: "vuln_detection", type: "scan_result", title: "nuclei Pass 3 Done", detail: `+${nucleiFindings.length - beforeCount} findings (${Math.round(r3.durationMs/1000)}s)` });
    } catch (e: any) {
      addLabLog(state, { phase: "vuln_detection", type: "warning", title: "nuclei Pass 3 Failed", detail: e.message?.slice(0, 150) });
    }

    state.stats.toolsRun++; // Count nuclei as 1 tool (3 passes)
    state.assets[0].toolResults.push({
      tool: "nuclei",
      command: `nuclei [3 passes: DAST + tech(${httpxTech.slice(0,3).join(',')}) + exposures]`,
      exitCode: 0,
      durationMs: totalNucleiDurationMs,
      findingCount: nucleiFindings.length,
      findings: nucleiFindings,
      outputPreview: nucleiFindings.length > 0 
        ? nucleiFindings.map(f => `[${f.severity}] ${f.title}${f.matchedAt ? ' @ ' + f.matchedAt : ''}`).join('\n')
        : '(no findings from 3 passes)',
    });
    addLabLog(state, { phase: "vuln_detection", type: "scan_result", title: "nuclei Complete", detail: `Total: ${nucleiFindings.length} findings across 3 passes (${Math.round(totalNucleiDurationMs/1000)}s)` });

    state.progress = 45;
    await yieldEventLoop();
    await syncProgress();

    // Nikto web vulnerability scan
    try {
      const { executeRawCommandViaQueue } = await import("../lib/job-queue-bridge");
      
      const niktoTimeout = scanProfile === "deep" ? 180 : 60;
      const niktoCmd = `timeout ${niktoTimeout} nikto -h ${scanUrl} -Tuning 1234567890abc 2>&1`;
      const niktoResult = await executeRawCommandViaQueue(niktoCmd, niktoTimeout + 30);

      state.stats.toolsRun++;

      const niktoFindings: any[] = [];
      // Nikto output may be in stdout or stderr depending on the execution context
      const niktoOutput = (niktoResult.stdout || '') + '\n' + (niktoResult.stderr || '');
      if (niktoOutput.trim()) {
        const lines = niktoOutput.trim().split("\n").filter(Boolean);
        for (const line of lines) {
          // Nikto findings start with "+" or "- " and contain useful info
          const isNiktoFinding = (line.startsWith("+") || line.startsWith("- ")) && 
            !line.includes("Target IP:") && !line.includes("Target Hostname:") && 
            !line.includes("Target Port:") && !line.includes("Start Time:") && 
            !line.includes("End Time:") && !line.includes("host(s) tested") && 
            !line.includes("items checked:") && !line.includes("Nikto v");
          if (isNiktoFinding) {
            const cleanLine = line.replace(/^[+\-]\s*/, "").trim();
            if (cleanLine.length > 10) {
              // Determine severity based on content
              let severity = "info";
              if (cleanLine.toLowerCase().includes("vulnerability") || cleanLine.toLowerCase().includes("injection") || cleanLine.toLowerCase().includes("xss") || cleanLine.toLowerCase().includes("rce")) severity = "high";
              else if (cleanLine.toLowerCase().includes("directory") || cleanLine.toLowerCase().includes("listing") || cleanLine.toLowerCase().includes("found") || cleanLine.toLowerCase().includes("indexing")) severity = "medium";
              else if (cleanLine.toLowerCase().includes("header") || cleanLine.toLowerCase().includes("leak") || cleanLine.toLowerCase().includes("disclosure") || cleanLine.toLowerCase().includes("etag") || cleanLine.toLowerCase().includes("cors")) severity = "low";
              
              niktoFindings.push({
                id: `nikto-${crypto.randomBytes(4).toString("hex")}`,
                severity,
                title: `[nikto] ${cleanLine.slice(0, 200)}`,
                tool: "nikto",
              });
            }
          }
        }
        // Add nikto findings as vulns
        for (const nf of niktoFindings) {
          state.assets[0].vulns.push(nf);
          state.stats.vulnsFound++;
        }
      }

      state.assets[0].toolResults.push({
        tool: "nikto",
        command: niktoCmd,
        exitCode: niktoResult.exitCode,
        durationMs: niktoResult.durationMs,
        findingCount: niktoFindings.length,
        findings: niktoFindings,
        outputPreview: niktoOutput.slice(0, 3000),
      });

      addLabLog(state, { phase: "vuln_detection", type: "scan_result", title: "nikto Complete", detail: `Found ${niktoFindings.length} findings` });
    } catch (e: any) {
      addLabLog(state, { phase: "vuln_detection", type: "warning", title: "nikto Failed", detail: e.message?.slice(0, 200) || "Unknown error" });
    }

    state.progress = 55;
    await yieldEventLoop();
    await syncProgress();

    // Gobuster directory scan — with SPA wildcard detection
    try {
      const { executeRawCommandViaQueue } = await import("../lib/job-queue-bridge");
      
      // First, detect SPA wildcard response length
      const probeCmd = `curl -s -o /dev/null -w '%{size_download}' '${scanUrl}/nonexistent-path-${Date.now()}' 2>&1`;
      const probeResult = await executeRawCommandViaQueue(probeCmd, 15);
      const wildcardLength = probeResult.stdout?.trim();
      
      let gobusterArgs = `dir -u ${scanUrl} -w /opt/SecLists/Discovery/Web-Content/common.txt -t 20 -q --no-error --timeout 5s`;
      if (wildcardLength && parseInt(wildcardLength) > 0) {
        // SPA detected — exclude the wildcard response length
        gobusterArgs += ` --exclude-length ${wildcardLength}`;
        addLabLog(state, { phase: "vuln_detection", type: "info", title: "SPA Detected", detail: `Excluding wildcard response length ${wildcardLength} bytes` });
      }

      const gobusterResult = await executeRawCommandViaQueue(`timeout 90 gobuster ${gobusterArgs}`, 120);

      state.stats.toolsRun++;

      const dirFindings: any[] = [];
      if (gobusterResult.stdout) {
        // Cap output to first 500 lines to prevent blocking
        const rawOutput = gobusterResult.stdout.slice(0, 50000); // 50KB max
        const lines = rawOutput.trim().split("\n").filter(Boolean).slice(0, 500);
        for (const line of lines) {
          if (dirFindings.length >= 100) break; // Cap at 100 findings
          // Skip error/wildcard messages
          if (line.includes("the server returns a status code") || line.includes("Please exclude") || line.includes("To continue")) continue;
          if (line.includes("OUTPUT TRUNCATED")) continue;
          if (line.includes("Status:") || line.match(/^\//)) {
            dirFindings.push({ severity: "info", title: `[gobuster] ${line.trim().slice(0, 200)}` });
          }
        }
      }

      state.assets[0].toolResults.push({
        tool: "gobuster",
        command: `gobuster ${gobusterArgs}`,
        exitCode: gobusterResult.exitCode,
        durationMs: gobusterResult.durationMs,
        findingCount: dirFindings.length,
        findings: dirFindings,
        outputPreview: gobusterResult.stdout.slice(0, 3000),
      });

      addLabLog(state, { phase: "vuln_detection", type: "scan_result", title: "gobuster Complete", detail: `Found ${dirFindings.length} directories` });
    } catch (e: any) {
      addLabLog(state, { phase: "vuln_detection", type: "warning", title: "gobuster Failed", detail: e.message?.slice(0, 200) || "Unknown error" });
    }

    state.progress = 65;
    await yieldEventLoop();
    await syncProgress();

    // ── Phase 4: LLM Analysis (with Self-Learning) ────────────────────
    state.phase = "analyzing";
    addLabLog(state, { phase: "analyzing", type: "info", title: "Phase 4: LLM Analysis", detail: "Running AI-powered vulnerability correlation with self-learning context" });

    await yieldEventLoop();
    await updateTrainingLabSession(sessionId, {
      labStatus: "analyzing",
      phase: "analyzing",
      progress: 65,
    });
    await yieldEventLoop();

    // Determine target preset for learning context
    const targetPresetForLearning = TRAINING_TARGETS.find(t => t.url === targetUrl || t.liveInstanceUrl === targetUrl)?.id || "custom";

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

      await yieldEventLoop();
      // ── Build Structured Intelligence Brief for LLM ──
      // Instead of dumping raw tool output, we build a categorized intelligence brief
      // that helps the LLM reason about relationships between findings.

      // 1. Technology Fingerprint Summary
      const httpxMeta = state.assets[0] as any;
      const techFingerprint: string[] = [];
      if (httpxMeta.httpxTitle) techFingerprint.push(`Page Title: ${httpxMeta.httpxTitle}`);
      if (httpxMeta.httpxTech?.length) techFingerprint.push(`Detected Stack: ${httpxMeta.httpxTech.join(', ')}`);
      if (httpxMeta.httpxContentType) techFingerprint.push(`Content-Type: ${httpxMeta.httpxContentType}`);
      const portsSummary = state.assets[0].ports.map(p =>
        `${p.port}/${p.service}${p.version ? ` (${p.version})` : ''}`
      ).join(', ');
      if (portsSummary) techFingerprint.push(`Open Ports: ${portsSummary}`);

      // 2. Categorize tool findings by evidence type
      const confirmedVulns = state.assets[0].vulns.filter(v => v.tool === 'nuclei');
      const headerIssues = state.assets[0].vulns.filter(v => (v.title || '').includes('[headers]'));
      const niktoFindings = state.assets[0].toolResults.find(t => t.tool === 'nikto');
      const gobusterResults = state.assets[0].toolResults.find(t => t.tool === 'gobuster');
      const nmapResults = state.assets[0].toolResults.find(t => t.tool === 'nmap');
      const curlResults = state.assets[0].toolResults.find(t => t.tool === 'curl');

      // 3. Build technology-aware inference context
      const techStack = (httpxMeta.httpxTech || []).map((t: string) => t.toLowerCase()).join(' ');
      const techInferences: string[] = [];
      if (techStack.includes('express') || techStack.includes('node')) {
        techInferences.push('Node.js/Express apps are commonly vulnerable to: prototype pollution, NoSQL injection, SSRF via request libraries, insecure deserialization, JWT misconfig, path traversal via path.join, XSS in template engines');
      }
      if (techStack.includes('php') || techStack.includes('apache')) {
        techInferences.push('PHP/Apache apps are commonly vulnerable to: SQL injection, file inclusion (LFI/RFI), command injection via exec/system, file upload bypass, session fixation, XSS, CSRF, directory traversal');
      }
      if (techStack.includes('angular') || techStack.includes('react') || techStack.includes('vue')) {
        techInferences.push('SPA frameworks may have: DOM-based XSS, client-side routing bypass, exposed API endpoints, CORS misconfiguration, sensitive data in client bundles');
      }
      if (techStack.includes('mysql') || techStack.includes('mariadb') || techStack.includes('sqlite')) {
        techInferences.push('SQL databases suggest: SQL injection vectors, credential exposure in config files, database backup exposure');
      }

      // 4. Build directory intelligence
      const discoveredPaths = gobusterResults?.findings?.map((f: any) => f.title?.replace('[gobuster] ', '') || '') || [];
      const interestingPaths = discoveredPaths.filter((p: string) => 
        /api|admin|config|backup|upload|login|register|debug|test|swagger|phpinfo|phpmyadmin|wp-|git|env|sql|db|ftp/i.test(p)
      );

      // 5. Build target-specific context
      let targetContext = '';
      if (matchedTarget) {
        targetContext = `\n## TARGET INTELLIGENCE\nThis is "${matchedTarget.name}" — ${matchedTarget.description}
Tech Stack: ${matchedTarget.tags.join(', ')}
Known Vulnerability Categories: ${matchedTarget.knownVulns.join(', ')}
OWASP Categories: ${matchedTarget.owaspCategories.join(', ')}
Difficulty: ${matchedTarget.difficulty}`;
      }

      // 6. Build concise tool output (only the most relevant parts)
      const toolEvidence: string[] = [];
      if (confirmedVulns.length > 0) {
        toolEvidence.push(`### Nuclei Confirmed Vulnerabilities (${confirmedVulns.length})\n` +
          confirmedVulns.map(v => `- [${v.severity.toUpperCase()}] ${v.title}${(v as any).matchedAt ? ' @ ' + (v as any).matchedAt : ''}${(v as any).description ? ' — ' + (v as any).description.slice(0, 120) : ''}`).join('\n'));
      }
      if (niktoFindings && niktoFindings.findingCount > 0) {
        toolEvidence.push(`### Nikto Web Scanner Findings (${niktoFindings.findingCount})\n` +
          niktoFindings.findings.slice(0, 20).map((f: any) => `- [${f.severity}] ${f.title}`).join('\n'));
      }
      if (headerIssues.length > 0) {
        toolEvidence.push(`### Security Header Issues (${headerIssues.length})\n` +
          headerIssues.map(v => `- ${v.title}`).join('\n'));
      }
      if (interestingPaths.length > 0) {
        toolEvidence.push(`### Interesting Directories/Endpoints (${interestingPaths.length} of ${discoveredPaths.length} total)\n` +
          interestingPaths.map((p: string) => `- ${p}`).join('\n'));
      }
      if (nmapResults?.outputPreview) {
        const nmapClean = nmapResults.outputPreview
          .replace(/\| fingerprint-strings:[\s\S]*?(?=\n\w|$)/g, '')
          .replace(/SF-Port[\s\S]*?(?=\n\w|$)/g, '')
          .slice(0, 800);
        if (nmapClean.trim()) toolEvidence.push(`### Nmap Service Detection\n${nmapClean}`);
      }
      if (curlResults?.outputPreview) {
        toolEvidence.push(`### HTTP Response Headers\n${curlResults.outputPreview.slice(0, 600)}`);
      }

      const analysisPrompt = `You are an expert penetration tester and red team operator analyzing reconnaissance and vulnerability scan results from a TRAINING LAB session.

# RECONNAISSANCE INTELLIGENCE BRIEF

## TARGET: ${hostname} (${fullTargetUrl})
${techFingerprint.join('\n')}
${targetContext}

## SCAN EVIDENCE
${toolEvidence.join('\n\n') || 'No significant findings from automated tools.'}

${techInferences.length > 0 ? `## TECHNOLOGY-AWARE INFERENCE CONTEXT\n${techInferences.join('\n')}` : ''}

# ANALYSIS INSTRUCTIONS

You must perform THREE levels of analysis:

## Level 1: CONFIRMED VULNERABILITIES
List all vulnerabilities directly confirmed by scan tools (nuclei DAST findings, nikto findings). These have the highest confidence.

## Level 2: EVIDENCE-BASED INFERENCE
Based on the technology fingerprint, discovered directories, HTTP headers, and service versions, infer vulnerabilities that are HIGHLY LIKELY to exist. For example:
- If gobuster found /api/ and /swagger → likely API security issues (broken auth, mass assignment, IDOR)
- If nikto found directory listing → likely information disclosure
- If httpx detected PHP + Apache → likely SQL injection, file inclusion, command injection
- If missing security headers (CSP, HSTS) → likely XSS, clickjacking
- If /admin or /login found → likely brute force, default credentials, broken access control

## Level 3: EXPLOIT METHOD SELECTION
For EACH finding, you MUST decide the optimal exploitation approach and provide ready-to-execute CLI commands.

Decision framework (evaluate in order):
1. **Does a reliable Metasploit module exist?** → Use "metasploit" (e.g., exploit/unix/webapp/dvwa_exec for DVWA command injection)
2. **Does a public PoC exist on ExploitDB?** → Use "exploitdb" (searchsploit to find and download)
3. **Is it a web app vuln requiring custom payload?** → Use "custom" (sqlmap, curl, python3, bash)
4. **Is it a misconfiguration to verify?** → Use "manual_verification" (curl -I, check headers/files)

For Metasploit: provide full msfconsole commands or resource scripts
For ExploitDB: provide searchsploit search + download + execution commands
For Custom: provide the exact curl/sqlmap/python3 commands with proper payloads
For Manual Verification: provide curl/grep commands to confirm the issue

## Level 4: EXPLOIT CHAIN PLANNING
Identify multi-step attack chains that combine individual findings into realistic attack scenarios. Map each step to a MITRE ATT&CK technique. For example:
- "Directory listing (T1083) → Config file exposure (T1552.001) → Credential theft (T1078) → Admin access (T1078.004)"
- "SQL Injection (T1190) → Database dump (T1005) → Credential reuse (T1078) → Lateral movement"

## CRITICAL RULES:
1. Each finding MUST have a SPECIFIC, DESCRIPTIVE title (e.g., "Reflected XSS in Search Parameter", NOT "XSS Vulnerability")
2. For known vulnerable training apps, be EXHAUSTIVE — these apps are DESIGNED to have many vulnerabilities
3. Distinguish between confirmed (tool-verified) and inferred (context-based) findings using the evidence field
4. Map every finding to an OWASP 2025 category AND a MITRE ATT&CK technique
5. Generate at least 2-3 realistic exploit chains that a red team operator would actually execute
6. Do NOT generate vague or generic findings — every finding must be actionable
7. If the target is a known vulnerable app (DVWA, Juice Shop, etc.), you MUST identify the classic vulnerabilities it's known for

Provide your analysis in the following JSON format:
{
  "executiveSummary": "2-3 sentence overview of the target's security posture",
  "riskScore": <1-10 integer>,
  "riskRating": "critical|high|medium|low|informational",
  "findings": [
    {
      "title": "Specific vulnerability title (e.g., SQL Injection in Login Form)",
      "severity": "critical|high|medium|low|info",
      "category": "OWASP category (e.g., A03:2025 Injection)",
      "confidence": "confirmed|high|medium|low (confirmed = tool-verified, high = strong evidence, medium = inferred from tech stack, low = possible)",
      "mitre_attack": "MITRE ATT&CK technique ID (e.g., T1190, T1059.007)",
      "description": "Detailed description including WHERE the vulnerability exists and HOW it can be exploited",
      "evidence": "Specific evidence: tool name + output that confirms this, or reasoning chain for inferred findings",
      "remediation": "How to fix this vulnerability",
      "cve": "CVE-XXXX-XXXX or null",
      "cvss": 0.0,
      "exploitMethod": {
        "method": "metasploit|exploitdb|custom|manual_verification",
        "reasoning": "Why this method was chosen",
        "primaryTool": "msfconsole|searchsploit|sqlmap|curl|python3|bash",
        "cliCommands": [
          {
            "order": 1,
            "tool": "tool_name",
            "command": "full CLI command ready to copy-paste and execute",
            "description": "what this step does",
            "expectedOutput": "what success looks like"
          }
        ],
        "alternativeMethod": {
          "method": "fallback_method",
          "reasoning": "when to use this instead"
        },
        "preConditions": ["conditions that must be true"],
        "expectedOutcome": "what successful exploitation achieves",
        "opsecNotes": "detection risk and evasion tips"
      }
    }
  ],
  "attackChains": [
    {
      "name": "Descriptive attack chain name (e.g., 'SQL Injection to Database Exfiltration')",
      "steps": ["T1190: Exploit SQL injection in login form", "T1005: Dump user credentials from database", "T1078: Use stolen credentials for admin access"],
      "impact": "Combined impact of the full chain",
      "likelihood": "high|medium|low",
      "mitre_tactics": ["Initial Access", "Collection", "Privilege Escalation"]
    }
  ],
  "missedAreas": ["Areas that should be tested but weren't covered by automated tools"],
  "recommendations": ["Prioritized list of security improvements"]
}

CRITICAL: Your accuracy is being measured against ground truth. This is a training environment with KNOWN vulnerabilities.
- Be EXHAUSTIVE: identify every vulnerability the application is known to have
- Be SPECIFIC: use descriptive titles that name the exact vulnerability type and location
- Be EVIDENCE-BASED: cite specific tool output or reasoning for each finding
- Generate 15-25 findings for known-vulnerable apps (they have many vulns by design)
- Include BOTH confirmed (tool-verified) AND inferred (context-based) findings
${learningContext}`;

      // Log prompt size for debugging 403 errors
      const promptSize = analysisPrompt.length;
      console.log(`[TrainingLab] LLM prompt size: ${promptSize} chars for ${hostname}`);
      addLabLog(state, { phase: "analyzing", type: "info", title: "LLM Prompt Size", detail: `${promptSize} characters` });

      const llmPayload = {
        messages: [
          { role: "system" as const, content: "You are an expert red team operator and penetration tester with deep knowledge of OWASP Top 10, MITRE ATT&CK, and common web application vulnerabilities. You analyze reconnaissance data from multiple tools (nmap, httpx, nuclei, nikto, gobuster, curl) and synthesize findings into actionable intelligence. You excel at inferring vulnerabilities from technology fingerprints and correlating evidence across tools. Always respond with valid JSON." },
          { role: "user" as const, content: analysisPrompt },
        ],
        response_format: {
          type: "json_schema" as const,
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
                    confidence: { type: "string", description: "confirmed, high, medium, or low" },
                    mitre_attack: { type: "string", description: "MITRE ATT&CK technique ID" },
                    evidence: { type: "string", description: "Evidence or proof" },
                    remediation: { type: "string", description: "Fix recommendation" },
                    cvss: { type: "number", description: "CVSS score 0-10" },
                    exploitMethod: { type: "object", description: "Exploit method selection", properties: {
                      method: { type: "string", description: "metasploit, exploitdb, custom, or manual_verification" },
                      reasoning: { type: "string", description: "Why this method was chosen" },
                      primaryTool: { type: "string", description: "Primary CLI tool: msfconsole, searchsploit, sqlmap, curl, python3, bash" },
                      cliCommands: { type: "array", items: { type: "object", properties: {
                        order: { type: "integer" },
                        tool: { type: "string" },
                        command: { type: "string", description: "Full CLI command ready to execute" },
                        description: { type: "string" },
                        expectedOutput: { type: "string" },
                      }, required: ["order", "tool", "command", "description"] }},
                      alternativeMethod: { type: "object", properties: {
                        method: { type: "string" },
                        reasoning: { type: "string" },
                      }},
                      preConditions: { type: "array", items: { type: "string" } },
                      expectedOutcome: { type: "string" },
                      opsecNotes: { type: "string" },
                    }, required: ["method", "reasoning", "primaryTool", "cliCommands"] },
                  },
                  required: ["title", "severity", "category", "description", "confidence", "exploitMethod"],
                }},
                attackChains: { type: "array", items: {
                  type: "object",
                  properties: {
                    name: { type: "string", description: "Attack chain name" },
                    steps: { type: "array", items: { type: "string" }, description: "Ordered attack steps" },
                    impact: { type: "string", description: "Combined impact" },
                    likelihood: { type: "string", description: "high, medium, or low" },
                    mitre_tactics: { type: "array", items: { type: "string" }, description: "MITRE ATT&CK tactics involved" },
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
      };

      await yieldEventLoop();

      // Retry up to 2 times on 403 errors (may be rate limiting)
      let result: any;
      for (let attempt = 0; attempt < 3; attempt++) {
        try {
          if (attempt > 0) {
            console.log(`[TrainingLab] LLM retry #${attempt} for ${hostname}`);
            await new Promise(r => setTimeout(r, 3000 * attempt)); // backoff
          }
          result = await invokeLLM(llmPayload);
          break; // success
        } catch (retryErr: any) {
          if (attempt === 2 || !retryErr.message?.includes('403')) throw retryErr;
          addLabLog(state, { phase: "analyzing", type: "warning", title: "LLM Rate Limited", detail: `Attempt ${attempt + 1} failed with 403, retrying...` });
        }
      }

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

        // ── Exploit Selection Scoring ──
        try {
          const { scoreExploitSelection } = await import("../lib/exploit-selection-intelligence");
          const { getExploitMethodGroundTruth } = await import("../lib/exploit-method-ground-truth");
          const exploitGroundTruth = getExploitMethodGroundTruth(targetPresetForLearning);
          if (exploitGroundTruth && exploitGroundTruth.length > 0) {
            const llmFindingsWithExploit = (llmAnalysis.findings || []).map((f: any) => ({
              title: f.title || "",
              category: f.category || "",
              exploitMethod: f.exploitMethod || undefined,
            }));
            const exploitScore = scoreExploitSelection(exploitGroundTruth, llmFindingsWithExploit);
            addLabLog(state, {
              phase: "analyzing", type: "scan_result",
              title: "Exploit Selection Scoring Complete",
              detail: `Overall: ${(exploitScore.overallScore * 100).toFixed(1)}% | Method Accuracy: ${(exploitScore.methodAccuracy * 100).toFixed(1)}% | CLI Tool: ${(exploitScore.cliToolAccuracy * 100).toFixed(1)}% | CLI Pattern: ${(exploitScore.cliPatternAccuracy * 100).toFixed(1)}% | Scored: ${exploitScore.scoredFindings}/${exploitScore.totalFindings}`,
            });
            (llmAnalysis as any).__exploitSelectionScore = exploitScore;
          }
        } catch (e: any) {
          addLabLog(state, { phase: "analyzing", type: "warning", title: "Exploit Selection Scoring Failed", detail: e.message?.slice(0, 200) || "" });
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

        // ── RoE Enforcement ──
        const { enforceTrainingRoE, recordScanLaunch } = await import("../lib/training-roe-guard");
        const roeCheck = enforceTrainingRoE(target, {
          targetId: target.id,
          scanProfile: input.scanProfile,
        });
        if (!roeCheck.allowed) {
          const violationMessages = roeCheck.violations.map(v => v.message).join(" | ");
          throw new TRPCError({
            code: "PRECONDITION_FAILED",
            message: `[ROE VIOLATION] Scan blocked for ${target.name}: ${violationMessages}`,
          });
        }
        // Record the scan launch for rate limiting
        recordScanLaunch(target.id);

        // Prefer live instance URL (self-hosted) over canonical URL
        targetUrl = target.liveInstanceUrl || target.url;
        targetPreset = target.id;
        sessionName = input.name || `${target.name} - ${new Date().toLocaleDateString()}`;
        if (target.liveInstanceUrl) {
          console.log(`[TrainingLab] Using live instance: ${target.liveInstanceUrl} (canonical: ${target.url})`);
        }
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

  /** Pre-check RoE for a target before launching a scan */
  checkRoE: publicProcedure
    .input(z.object({
      targetId: z.string(),
      scanProfile: z.enum(["quick", "standard", "deep"]).default("standard"),
      enableBruteForce: z.boolean().optional(),
      enableDoS: z.boolean().optional(),
      enableExfiltration: z.boolean().optional(),
    }))
    .query(async ({ input }) => {
      const target = TRAINING_TARGETS.find(t => t.id === input.targetId);
      if (!target) throw new TRPCError({ code: "NOT_FOUND", message: "Training target not found" });

      const { enforceTrainingRoE } = await import("../lib/training-roe-guard");
      return enforceTrainingRoE(target, {
        targetId: target.id,
        scanProfile: input.scanProfile,
        enableBruteForce: input.enableBruteForce,
        enableDoS: input.enableDoS,
        enableExfiltration: input.enableExfiltration,
      });
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
For EACH finding, you MUST also select the optimal exploit method:
- "metasploit" if a reliable MSF module exists (provide full msfconsole commands)
- "exploitdb" if a public PoC exists on ExploitDB (provide searchsploit + execution commands)
- "custom" if it needs a tailored exploit (provide sqlmap/curl/python3/bash commands)
- "manual_verification" for misconfigurations (provide curl/grep verification commands)

Respond with a JSON object containing: executiveSummary, riskScore (1-10), riskRating, findings (array with title, severity, category, description, confidence, evidence, remediation, cve, cvss, exploitMethod object with method, reasoning, primaryTool, cliCommands array), attackChains, missedAreas, recommendations.` },
            ],
            response_format: { type: "json_schema", json_schema: { name: "security_analysis", strict: false, schema: { type: "object", properties: { executiveSummary: { type: "string" }, riskScore: { type: "integer" }, riskRating: { type: "string" }, findings: { type: "array", items: { type: "object", properties: { title: { type: "string" }, severity: { type: "string" }, category: { type: "string" }, cve: { type: "string" }, description: { type: "string" }, confidence: { type: "string" }, evidence: { type: "string" }, remediation: { type: "string" }, cvss: { type: "number" }, exploitMethod: { type: "object", properties: { method: { type: "string" }, reasoning: { type: "string" }, primaryTool: { type: "string" }, cliCommands: { type: "array", items: { type: "object", properties: { order: { type: "integer" }, tool: { type: "string" }, command: { type: "string" }, description: { type: "string" }, expectedOutput: { type: "string" } }, required: ["order", "tool", "command", "description"] } }, alternativeMethod: { type: "object", properties: { method: { type: "string" }, reasoning: { type: "string" } } }, preConditions: { type: "array", items: { type: "string" } }, expectedOutcome: { type: "string" }, opsecNotes: { type: "string" } }, required: ["method", "reasoning", "primaryTool", "cliCommands"] } }, required: ["title", "severity", "category", "description", "exploitMethod"] } }, attackChains: { type: "array", items: { type: "object", properties: { name: { type: "string" }, steps: { type: "array", items: { type: "string" } }, impact: { type: "string" }, likelihood: { type: "string" } }, required: ["name", "steps", "impact", "likelihood"] } }, missedAreas: { type: "array", items: { type: "string" } }, recommendations: { type: "array", items: { type: "string" } } }, required: ["executiveSummary", "riskScore", "riskRating", "findings", "attackChains", "missedAreas", "recommendations"] } } },
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

          // Exploit selection scoring for rerun
          if (llmAnalysis && targetPresetForLearning !== "custom") {
            try {
              const { scoreExploitSelection } = await import("../lib/exploit-selection-intelligence");
              const { getExploitMethodGroundTruth } = await import("../lib/exploit-method-ground-truth");
              const exploitGroundTruth = getExploitMethodGroundTruth(targetPresetForLearning);
              if (exploitGroundTruth && exploitGroundTruth.length > 0) {
                const llmFindingsWithExploit = (llmAnalysis.findings || []).map((f: any) => ({
                  title: f.title || "",
                  category: f.category || "",
                  exploitMethod: f.exploitMethod || undefined,
                }));
                const exploitScore = scoreExploitSelection(exploitGroundTruth, llmFindingsWithExploit);
                (llmAnalysis as any).__exploitSelectionScore = exploitScore;
              }
            } catch { /* ignore exploit scoring errors */ }
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

  /** Log RoE acknowledgment before scan launch */
  acknowledgeRoE: protectedProcedure
    .input(z.object({
      targetId: z.string(),
      scanProfile: z.string(),
    }))
    .mutation(async ({ input, ctx }) => {
      const mysql = await import("mysql2/promise");
      const conn = await mysql.createConnection(process.env.DATABASE_URL!);
      try {
        const target = TRAINING_TARGETS.find(t => t.id === input.targetId);
        const targetName = target?.name || "Custom Target";
        const targetUrl = target?.url || "custom";
        const rulesAccepted = target?.roe ? {
          noBruteForce: target.roe.noBruteForce,
          noDoS: target.roe.noDoS,
          noExfiltration: target.roe.noExfiltration,
          requiresOwnInstance: target.roe.requiresOwnInstance,
          maxScansPerDay: target.roe.maxScansPerDay,
          prohibited: target.roe.prohibited,
          allowed: target.roe.allowed,
        } : { customTarget: true, requiresAuthorization: true };

        const enforcedRules: string[] = [];
        if (target?.roe) {
          if (target.roe.noBruteForce) enforcedRules.push("no-brute-force");
          if (target.roe.noDoS) enforcedRules.push("no-dos");
          if (target.roe.noExfiltration) enforcedRules.push("no-exfiltration");
          if (target.roe.requiresOwnInstance) enforcedRules.push("requires-own-instance");
          if (target.roe.maxScansPerDay) enforcedRules.push(`max-${target.roe.maxScansPerDay}-scans-per-day`);
        } else {
          enforcedRules.push("custom-target-authorization-required");
        }

        await conn.execute(
          `INSERT INTO roe_acknowledgments (operator_id, operator_name, target_id, target_name, target_url, rules_accepted, enforced_rules, scan_profile) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            ctx.user?.id ? Number(ctx.user.id) : 0,
            ctx.user?.name || "Unknown Operator",
            input.targetId,
            targetName,
            targetUrl,
            JSON.stringify(rulesAccepted),
            JSON.stringify(enforcedRules),
            input.scanProfile,
          ]
        );

        return { success: true, enforcedRules };
      } finally {
        await conn.end();
      }
    }),

  /** Get RoE acknowledgment audit log */
  roeAuditLog: protectedProcedure
    .input(z.object({
      limit: z.number().min(1).max(100).default(50),
      targetId: z.string().optional(),
    }))
    .query(async ({ input }) => {
      const mysql = await import("mysql2/promise");
      const conn = await mysql.createConnection(process.env.DATABASE_URL!);
      try {
        let query = `SELECT * FROM roe_acknowledgments ORDER BY acknowledged_at DESC LIMIT ${Number(input.limit)}`;
        let params: any[] = [];
        if (input.targetId) {
          query = `SELECT * FROM roe_acknowledgments WHERE target_id = ? ORDER BY acknowledged_at DESC LIMIT ${Number(input.limit)}`;
          params = [input.targetId];
        }
        const [rows] = await conn.execute(query, params);
        return (rows as any[]).map(r => ({
          id: r.id,
          operatorId: r.operator_id,
          operatorName: r.operator_name,
          targetId: r.target_id,
          targetName: r.target_name,
          targetUrl: r.target_url,
          rulesAccepted: typeof r.rules_accepted === "string" ? JSON.parse(r.rules_accepted) : r.rules_accepted,
          enforcedRules: typeof r.enforced_rules === "string" ? JSON.parse(r.enforced_rules) : r.enforced_rules,
          scanProfile: r.scan_profile,
          sessionId: r.session_id,
          acknowledgedAt: r.acknowledged_at,
        }));
      } finally {
        await conn.end();
      }
    }),

  // ─── Continuous Training Loop Endpoints ─────────────────────────────────

  /** Start a continuous training loop on an existing completed session */
  startContinuousTraining: protectedProcedure
    .input(z.object({
      sessionId: z.string(),
      maxIterations: z.number().min(1).max(50).default(10),
      targetF1: z.number().min(0).max(1).default(1.0),
      targetRecall: z.number().min(0).max(1).default(1.0),
      targetPrecision: z.number().min(0).max(1).default(0.9),
    }))
    .mutation(async ({ input }) => {
      const { getTrainingLabSession, updateTrainingLabSession } = await import("../db");
      const session = await getTrainingLabSession(input.sessionId);
      if (!session) throw new TRPCError({ code: "NOT_FOUND", message: "Session not found" });
      if (session.labStatus !== "completed" && session.labStatus !== "failed") {
        throw new TRPCError({ code: "BAD_REQUEST", message: "Session must be completed to start continuous training" });
      }

      const assets = (session.assetsJson as any[]) || [];
      if (assets.length === 0) throw new TRPCError({ code: "BAD_REQUEST", message: "No scan data available" });

      const { getActiveLoop, runContinuousTrainingLoop } = await import("../lib/continuous-training");
      if (getActiveLoop(input.sessionId)?.isRunning) {
        throw new TRPCError({ code: "CONFLICT", message: "Continuous training already running for this session" });
      }

      const targetPreset = session.targetPreset || "custom";
      if (targetPreset === "custom") {
        throw new TRPCError({ code: "BAD_REQUEST", message: "Continuous training requires a known target with ground truth" });
      }

      // Run in background
      const config = {
        sessionId: input.sessionId,
        targetPreset,
        targetUrl: session.targetUrl,
        maxIterations: input.maxIterations,
        targetF1: input.targetF1,
        targetRecall: input.targetRecall,
        targetPrecision: input.targetPrecision,
        delayBetweenIterations: 2000,
      };

      runContinuousTrainingLoop(config, assets, async (iteration) => {
        // Broadcast progress via WebSocket
        try {
          const { eventHub } = await import("../lib/ws-event-hub");
          eventHub.broadcast({
            type: "continuous_training:progress",
            sessionId: input.sessionId,
            timestamp: Date.now(),
            data: iteration,
          });
        } catch { /* ignore */ }
      }).then(async (result) => {
        // Save final result to the session
        try {
          await updateTrainingLabSession(input.sessionId, {
            llmAnalysisJson: {
              ...(session.llmAnalysisJson as any || {}),
              __continuousTraining: result,
            },
          });
          // Broadcast completion
          const { eventHub } = await import("../lib/ws-event-hub");
          eventHub.broadcast({
            type: "continuous_training:complete",
            sessionId: input.sessionId,
            timestamp: Date.now(),
            data: result,
          });
        } catch (e: any) {
          console.error("[ContinuousTraining] Failed to save result:", e.message);
        }
      }).catch((err) => {
        console.error("[ContinuousTraining] Loop failed:", err.message);
      });

      return { success: true, message: `Continuous training started (max ${input.maxIterations} iterations, target F1=${(input.targetF1 * 100).toFixed(0)}%)` };
    }),

  /** Cancel a running continuous training loop */
  cancelContinuousTraining: protectedProcedure
    .input(z.object({ sessionId: z.string() }))
    .mutation(async ({ input }) => {
      const { cancelLoop, getActiveLoop } = await import("../lib/continuous-training");
      const loop = getActiveLoop(input.sessionId);
      if (!loop || !loop.isRunning) {
        throw new TRPCError({ code: "NOT_FOUND", message: "No active continuous training loop for this session" });
      }
      cancelLoop(input.sessionId);
      return { success: true, message: "Continuous training cancelled" };
    }),

  /** Get continuous training loop status */
  continuousTrainingStatus: publicProcedure
    .input(z.object({ sessionId: z.string() }))
    .query(async ({ input }) => {
      const { getActiveLoop } = await import("../lib/continuous-training");
      const loop = getActiveLoop(input.sessionId);
      if (!loop) {
        // Check if there's a saved result in the session
        const { getTrainingLabSession } = await import("../db");
        const session = await getTrainingLabSession(input.sessionId);
        const saved = (session?.llmAnalysisJson as any)?.__continuousTraining;
        if (saved) {
          return { isRunning: false, result: saved, currentIteration: saved.totalIterations, iterations: saved.iterations };
        }
        return null;
      }
      return {
        isRunning: loop.isRunning,
        currentIteration: loop.currentIteration,
        maxIterations: loop.config.maxIterations,
        targetPreset: loop.config.targetPreset,
        iterations: loop.iterations,
        latestF1: loop.iterations.length > 0
          ? loop.iterations[loop.iterations.length - 1].f1Score
          : 0,
        latestRecall: loop.iterations.length > 0
          ? loop.iterations[loop.iterations.length - 1].recall
          : 0,
        latestPrecision: loop.iterations.length > 0
          ? loop.iterations[loop.iterations.length - 1].precision
          : 0,
      };
    }),

  /** List all active continuous training loops */
  activeContinuousTraining: publicProcedure.query(async () => {
    const { listActiveLoops } = await import("../lib/continuous-training");
    return listActiveLoops();
  }),
});
