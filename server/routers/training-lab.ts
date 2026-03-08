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
      
      let nmapFlags = scanProfile === "quick"
        ? `-sV -sC --top-ports 100 -T4 --open`
        : scanProfile === "deep"
        ? `-sV -sC -p- -T3 --open -A`
        : `-sV -sC --top-ports 1000 -T4 --open`;

      // Sanitize nmap flags based on target RoE
      if (matchedTarget) {
        const { sanitizeNmapFlags } = await import("../lib/training-roe-guard");
        const original = nmapFlags;
        nmapFlags = sanitizeNmapFlags(nmapFlags, matchedTarget.roe);
        if (nmapFlags !== original) {
          addLabLog(state, { phase: "enumeration", type: "info", title: "RoE: Nmap Flags Sanitized", detail: `Adjusted flags to comply with ${matchedTarget.name} RoE` });
        }
      }

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
});
