import {
  init_trpc,
  protectedProcedure,
  publicProcedure,
  router
} from "./chunk-KMYXRJTU.js";
import {
  SCAN_SERVICE_URL,
  init_scan_service_url
} from "./chunk-JPJQZXKW.js";

// server/routers/training-lab.ts
init_trpc();
init_scan_service_url();
import { z } from "zod";
import { TRPCError } from "@trpc/server";
import crypto from "crypto";
var TRAINING_TARGETS = [
  {
    id: "juice-shop",
    name: "OWASP Juice Shop",
    url: "https://demo.owasp-juice.shop",
    liveInstanceUrl: `${SCAN_SERVICE_URL}/lab/juice-shop/`,
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
      notes: "MIT License. Online demo instance resets periodically."
    }
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
      notes: "Part of the vulnweb.com family of test sites maintained by Acunetix/Invicti."
    }
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
      notes: "Part of the vulnweb.com family of test sites."
    }
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
      notes: "Part of the vulnweb.com family of test sites."
    }
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
      notes: "Hosted at webscantest.com. Designed for scanner benchmarking."
    }
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
      notes: "Open source on GitHub. Copyright HCL Technologies 2017-2026."
    }
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
      notes: "Subject to Micro Focus Fortify Terms of Use."
    }
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
      notes: null
    }
  },
  {
    id: "broken-crystals",
    name: "Broken Crystals",
    url: "https://brokencrystals.com",
    liveInstanceUrl: `${SCAN_SERVICE_URL}/lab/broken-crystals/`,
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
      requiresOwnInstance: true,
      noBruteForce: false,
      noDoS: true,
      noExfiltration: false,
      maxScansPerDay: null,
      notes: "MIT License. Public instance at brokencrystals.com lacks explicit scanning authorization \u2014 use self-hosted instance only. Live lab at scan.aceofcloud.io/lab/broken-crystals/."
    }
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
      notes: "PortSwigger's official benchmark site for DAST tool validation."
    }
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
      notes: "IMPORTANT: Must use /start to get your own sandboxed instance. Do NOT scan the main domain directly. Google Terms of Service apply."
    }
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
      notes: "Apache 2.0 License. Focus on XSS variants only \u2014 not a general-purpose vuln app."
    }
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
      notes: "Part of the vulnweb.com family of test sites."
    }
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
      notes: "Part of the vulnweb.com family of test sites."
    }
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
      notes: "Associated with Troy Hunt's Pluralsight course."
    }
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
      notes: "Maintained by Invicti for scanner benchmarking."
    }
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
      notes: "Maintained by Invicti for scanner benchmarking."
    }
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
      notes: "Maintained by Invicti for scanner benchmarking."
    }
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
      notes: "Community-maintained playground."
    }
  },
  {
    id: "scanme-target",
    name: "ScanForge ScanMe",
    url: "http://scanme.nmap.org",
    description: "Official ScanForge authorized scanning target. Ideal for network reconnaissance and port scanning validation.",
    difficulty: "beginner",
    category: "Network",
    knownVulns: ["Open Ports", "Service Detection", "OS Detection"],
    owaspCategories: [],
    tags: ["network", "scanforge-discovery", "recon"],
    roe: {
      provider: "ScanForge Project (Fyodor)",
      termsUrl: "http://scanme.nmap.org/",
      summary: "Authorized for port scanning with ScanForge or other port scanners. A few scans per day is fine. Do NOT scan 100+ times per day. Do NOT use for SSH brute-force password cracking.",
      allowed: ["Port scanning", "Service detection", "OS detection", "ScanForge scripts"],
      prohibited: ["SSH brute-force", "Password cracking", "Excessive scanning (>100/day)", "DDoS attacks"],
      rateLimit: "A few scans per day. Do not exceed 100 scans/day.",
      requiresOwnInstance: false,
      noBruteForce: true,
      noDoS: true,
      noExfiltration: false,
      maxScansPerDay: 10,
      notes: "Explicitly stated: 'don't scan 100 times a day or use this site to test your ssh brute-force password cracking tool.'"
    }
  },
  {
    id: "dvwa",
    name: "Damn Vulnerable Web Application (DVWA)",
    url: "https://github.com/digininja/DVWA",
    liveInstanceUrl: `${SCAN_SERVICE_URL}/lab/dvwa/`,
    description: "PHP/MySQL web application that is intentionally vulnerable. Covers SQL injection, XSS, CSRF, file inclusion, command injection, brute force, and more. Multiple security levels (low/medium/high/impossible).",
    difficulty: "beginner",
    category: "Web Application",
    knownVulns: ["SQL Injection", "XSS (Reflected)", "XSS (Stored)", "XSS (DOM)", "CSRF", "File Inclusion", "File Upload", "Command Injection", "Brute Force", "Insecure CAPTCHA", "Weak Session IDs", "Open HTTP Redirect", "Content Security Policy Bypass", "JavaScript Attacks"],
    owaspCategories: ["A01:2025", "A02:2025", "A03:2025", "A04:2025", "A05:2025", "A06:2025", "A07:2025"],
    tags: ["php", "mysql", "beginner-friendly", "multi-level", "classic"],
    roe: {
      provider: "DVWA Project (digininja)",
      termsUrl: "https://github.com/digininja/DVWA",
      summary: "Open-source GPL-licensed training app. Designed to be attacked. Self-hosted instance \u2014 you own it, full permission to test.",
      allowed: ["All web vulnerability testing", "SQL injection", "XSS", "Command injection", "File upload attacks", "Brute force", "CSRF", "Automated DAST"],
      prohibited: [],
      rateLimit: null,
      requiresOwnInstance: false,
      noBruteForce: false,
      noDoS: false,
      noExfiltration: false,
      maxScansPerDay: null,
      notes: "Self-hosted on scan server. Default credentials: admin/password. Set security level via DVWA Security page."
    }
  },
  {
    id: "vampi",
    name: "VAmPI (Vulnerable REST API)",
    url: "https://github.com/NeuraLegion/VAmPI",
    liveInstanceUrl: `${SCAN_SERVICE_URL}/lab/vampi/`,
    description: "Intentionally vulnerable REST API built with Flask. Based on OWASP API Top 10 vulnerabilities. Features token-based auth, Swagger UI, and a global switch to toggle vulnerable/secure mode. Ideal for testing API-specific security issues.",
    difficulty: "intermediate",
    category: "API",
    knownVulns: ["SQL Injection", "Unauthorized Password Change", "Broken Object Level Authorization (BOLA)", "Mass Assignment", "Excessive Data Exposure", "User and Password Enumeration", "RegexDOS", "Lack of Resources & Rate Limiting", "JWT Authentication Bypass"],
    owaspCategories: ["A01:2025", "A02:2025", "A03:2025", "A04:2025", "A06:2025", "A07:2025"],
    tags: ["python", "flask", "rest-api", "openapi3", "jwt", "owasp-api-top10"],
    roe: {
      provider: "NeuraLegion (Bright Security)",
      termsUrl: "https://github.com/NeuraLegion/VAmPI",
      summary: "Open-source MIT-licensed vulnerable API. Self-hosted instance \u2014 you own it, full permission to test. Designed specifically for API security scanner validation.",
      allowed: ["API vulnerability scanning", "SQL injection", "Auth bypass", "BOLA testing", "Mass assignment", "JWT attacks", "Rate limit testing", "Automated DAST"],
      prohibited: [],
      rateLimit: null,
      requiresOwnInstance: false,
      noBruteForce: false,
      noDoS: false,
      noExfiltration: false,
      maxScansPerDay: null,
      notes: "Self-hosted on scan server. Swagger UI at /ui/. Initialize DB via GET /createdb. Vulnerable mode enabled by default."
    }
  },
  {
    id: "dvga",
    name: "Damn Vulnerable GraphQL Application (DVGA)",
    url: "https://github.com/NeuraLegion/Damn-Vulnerable-GraphQL-Application",
    liveInstanceUrl: `${SCAN_SERVICE_URL}/lab/dvga/`,
    description: "Intentionally vulnerable GraphQL implementation for learning and practicing GraphQL security. Supports queries, mutations, and subscriptions with 20+ vulnerability scenarios including injections, code execution, DoS, and authorization bypass.",
    difficulty: "advanced",
    category: "API",
    knownVulns: ["GraphQL Introspection", "GraphiQL Interface Exposure", "GraphQL Field Suggestions", "Batch Query Attack", "Deep Recursion Query Attack", "Resource Intensive Query Attack", "Field Duplication Attack", "Aliases-based Attack", "OS Command Injection", "SQL Injection", "Stored XSS", "HTML Injection", "Log Injection", "SSRF", "Stack Trace Errors", "GraphQL JWT Token Forge", "Interface Protection Bypass", "Query Deny List Bypass", "Weak Password Protection", "Arbitrary File Write", "Path Traversal"],
    owaspCategories: ["A01:2025", "A03:2025", "A04:2025", "A05:2025", "A06:2025", "A08:2025", "A10:2025"],
    tags: ["python", "graphql", "graphene", "flask", "nosql", "websockets"],
    roe: {
      provider: "NeuraLegion (Bright Security) / Dolev Farhi",
      termsUrl: "https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application",
      summary: "MIT-licensed vulnerable GraphQL app. Self-hosted instance \u2014 full permission to test. Supports Beginner and Expert difficulty modes.",
      allowed: ["GraphQL security testing", "Introspection attacks", "Injection testing", "DoS testing (own instance)", "Auth bypass", "Code execution testing", "Automated DAST"],
      prohibited: [],
      rateLimit: null,
      requiresOwnInstance: false,
      noBruteForce: false,
      noDoS: false,
      noExfiltration: false,
      maxScansPerDay: null,
      notes: "Self-hosted on scan server. Web UI at root path. Supports Beginner and Expert game modes."
    }
  },
  {
    id: "webgoat",
    name: "OWASP WebGoat",
    url: "https://github.com/WebGoat/WebGoat",
    liveInstanceUrl: `${SCAN_SERVICE_URL}/lab/webgoat/`,
    description: "OWASP's flagship deliberately insecure web application for teaching web application security. Includes guided lessons covering the full OWASP Top 10, with hands-on exercises for SQL injection, XSS, CSRF, XXE, insecure deserialization, and more. WebWolf companion app on port 9090.",
    difficulty: "beginner",
    category: "Web Application",
    knownVulns: ["SQL Injection", "XSS", "CSRF", "XXE", "Insecure Deserialization", "Broken Access Control", "Security Misconfiguration", "Sensitive Data Exposure", "Insufficient Logging", "SSRF", "Authentication Flaws", "JWT Vulnerabilities", "Path Traversal", "Insecure Direct Object References", "Cryptographic Failures"],
    owaspCategories: ["A01:2025", "A02:2025", "A03:2025", "A04:2025", "A05:2025", "A06:2025", "A07:2025", "A08:2025", "A09:2025", "A10:2025"],
    tags: ["java", "spring-boot", "owasp", "educational", "guided-lessons"],
    roe: {
      provider: "OWASP Foundation",
      termsUrl: "https://github.com/WebGoat/WebGoat",
      summary: "Open-source GPL-licensed OWASP training app. Self-hosted instance \u2014 full permission to test. Designed for learning web application security through guided lessons.",
      allowed: ["All web vulnerability testing", "SQL injection", "XSS", "CSRF", "XXE", "Deserialization attacks", "Auth bypass", "JWT attacks", "Path traversal", "Automated DAST"],
      prohibited: [],
      rateLimit: null,
      requiresOwnInstance: false,
      noBruteForce: false,
      noDoS: false,
      noExfiltration: false,
      maxScansPerDay: null,
      notes: "Self-hosted on scan server. WebGoat at :8080/WebGoat/, WebWolf at :9090/WebWolf/. Register an account to start lessons."
    }
  },
  {
    id: "bwapp",
    name: "bWAPP (buggy Web Application)",
    url: "https://github.com/raesene/bWAPP",
    liveInstanceUrl: `${SCAN_SERVICE_URL}/lab/bwapp/`,
    description: "Extremely buggy PHP web application with 100+ vulnerabilities covering all OWASP Top 10 categories. Includes SQL injection, XSS, CSRF, SSRF, XXE, command injection, LDAP injection, file upload, and more. Uses MySQL backend.",
    difficulty: "beginner",
    category: "Web Application",
    knownVulns: ["SQL Injection", "XSS", "Command Injection", "LDAP Injection", "SSRF", "XXE", "CSRF", "Insecure File Upload", "Directory Traversal", "Broken Auth", "Session Fixation", "Clickjacking", "HTTP Parameter Pollution", "Insecure Direct Object References"],
    owaspCategories: ["A01:2025", "A02:2025", "A03:2025", "A04:2025", "A05:2025", "A06:2025", "A07:2025", "A08:2025", "A09:2025", "A10:2025"],
    tags: ["php", "mysql", "owasp", "100-vulns", "beginner-friendly"],
    roe: {
      provider: "OWASP / ITSEC GAMES",
      termsUrl: "https://github.com/raesene/bWAPP",
      summary: "Open-source GPL-licensed training app. Self-hosted instance \u2014 full permission to test. Contains 100+ intentional vulnerabilities.",
      allowed: ["All web vulnerability testing", "SQL injection", "XSS", "Command injection", "LDAP injection", "File upload attacks", "CSRF", "XXE", "Automated DAST"],
      prohibited: [],
      rateLimit: null,
      requiresOwnInstance: false,
      noBruteForce: false,
      noDoS: false,
      noExfiltration: false,
      maxScansPerDay: null,
      notes: "Self-hosted on scan server at port 3003. Default credentials: bee/bug. Login at /login.php."
    }
  },
  {
    id: "mutillidae",
    name: "OWASP Mutillidae II",
    url: "https://github.com/webpwnized/mutillidae",
    liveInstanceUrl: `${SCAN_SERVICE_URL}/lab/mutillidae/`,
    description: "OWASP Mutillidae II is a free, open-source, deliberately vulnerable web application providing a target for web-security training. Contains 40+ vulnerabilities with hints and guided exploitation. Covers OWASP Top 10 and SANS Top 25.",
    difficulty: "beginner",
    category: "Web Application",
    knownVulns: ["SQL Injection", "XSS", "Command Injection", "LDAP Injection", "HTTP Parameter Pollution", "CSRF", "Open Redirect", "Directory Traversal", "Clickjacking", "HTML Injection", "JavaScript Injection", "JSON Injection", "XML Injection", "XPath Injection", "Buffer Overflow", "Privilege Escalation"],
    owaspCategories: ["A01:2025", "A02:2025", "A03:2025", "A04:2025", "A05:2025", "A06:2025", "A07:2025", "A08:2025", "A09:2025", "A10:2025"],
    tags: ["php", "mysql", "owasp", "guided", "sans-top-25"],
    roe: {
      provider: "OWASP Foundation / webpwnized",
      termsUrl: "https://github.com/webpwnized/mutillidae",
      summary: "Open-source GPL-licensed OWASP training app. Self-hosted instance \u2014 full permission to test. Designed for web security education with guided hints.",
      allowed: ["All web vulnerability testing", "SQL injection", "XSS", "Command injection", "LDAP injection", "Parameter pollution", "Automated DAST"],
      prohibited: [],
      rateLimit: null,
      requiresOwnInstance: false,
      noBruteForce: false,
      noDoS: false,
      noExfiltration: false,
      maxScansPerDay: null,
      notes: "Self-hosted on scan server at port 3004. Provides 3 security levels (0=hosed, 1=medium, 5=secure). Toggle hints via top menu."
    }
  },
  {
    id: "crapi",
    name: "OWASP crAPI (Completely Ridiculous API)",
    url: "https://github.com/OWASP/crAPI",
    liveInstanceUrl: `${SCAN_SERVICE_URL}/lab/crapi/`,
    description: "OWASP crAPI is a deliberately vulnerable API application designed to demonstrate the OWASP API Security Top 10 risks. Features a modern microservices architecture with Java, Python, and Go backends. Includes vehicle service, community forum, and shop modules.",
    difficulty: "intermediate",
    category: "API",
    knownVulns: ["BOLA/IDOR", "Broken Auth", "Excessive Data Exposure", "Lack of Resources & Rate Limiting", "Broken Function Level Authorization", "Mass Assignment", "Security Misconfiguration", "Injection", "Improper Assets Management", "Insufficient Logging & Monitoring", "SSRF", "JWT Vulnerabilities", "Race Condition", "NoSQL Injection"],
    owaspCategories: ["A01:2025", "A02:2025", "A03:2025", "A04:2025", "A05:2025", "A06:2025", "A07:2025", "A08:2025", "A09:2025", "A10:2025"],
    tags: ["api", "microservices", "java", "python", "go", "jwt", "owasp-api-top-10"],
    roe: {
      provider: "OWASP Foundation",
      termsUrl: "https://github.com/OWASP/crAPI",
      summary: "Open-source Apache 2.0 licensed OWASP API security training app. Self-hosted instance \u2014 full permission to test. Covers all OWASP API Security Top 10 risks.",
      allowed: ["All API security testing", "BOLA/IDOR", "Auth bypass", "JWT attacks", "Mass assignment", "Rate limit testing", "SSRF", "Injection", "Automated DAST"],
      prohibited: [],
      rateLimit: null,
      requiresOwnInstance: false,
      noBruteForce: false,
      noDoS: false,
      noExfiltration: false,
      maxScansPerDay: null,
      notes: "Self-hosted on scan server at port 8888. Register at /signup. API docs at /api-docs. Mailhog at port 8025 for email verification."
    }
  },
  {
    id: "altoro-mutual",
    name: "Altoro Mutual Banking (AltoroJ)",
    url: "https://demo.testfire.net",
    liveInstanceUrl: `${SCAN_SERVICE_URL}/lab/altoro/`,
    description: "Intentionally vulnerable banking application by IBM. Features online banking with accounts, transfers, loans, and bill pay. Contains SQL injection, XSS, IDOR, CSRF, and path traversal vulnerabilities targeting financial transaction flows.",
    difficulty: "intermediate",
    category: "Financial / Banking",
    knownVulns: ["SQL Injection (Login Bypass)", "Reflected XSS (Search)", "IDOR (Account Access)", "CSRF (Fund Transfer)", "Path Traversal", "Information Disclosure", "Broken Authentication"],
    owaspCategories: ["A01:2025", "A03:2025", "A04:2025", "A05:2025", "A07:2025"],
    tags: ["java", "tomcat", "banking", "financial", "ibm"],
    roe: {
      provider: "IBM Security (Self-hosted instance)",
      termsUrl: "https://github.com/HCL-TECH-SOFTWARE/AltoroJ",
      summary: "Open-source intentionally vulnerable banking app. Self-hosted on AC3 scan server. Full permission to test all vulnerability types including financial transaction manipulation.",
      allowed: ["SQL injection", "XSS", "IDOR", "CSRF", "Path traversal", "Auth bypass", "Session hijacking", "Automated DAST", "Fund transfer manipulation"],
      prohibited: [],
      rateLimit: null,
      requiresOwnInstance: false,
      noBruteForce: false,
      noDoS: false,
      noExfiltration: false,
      maxScansPerDay: null,
      notes: "Self-hosted on scan server at port 3005. Default credentials: jsmith/demo1234, admin/admin. Tomcat context path: /altoromutual/."
    }
  },
  {
    id: "vulnbank-63sats",
    name: "63Sats VulnBank",
    url: "https://scan.aceofcloud.io/lab/vulnbank/",
    liveInstanceUrl: `${SCAN_SERVICE_URL}/lab/vulnbank/`,
    description: "Modern vulnerable banking application with dashboard, money transfers, account statements, and news. Contains SQL injection, stored XSS, CSRF, IDOR, and file upload vulnerabilities targeting banking workflows.",
    difficulty: "intermediate",
    category: "Financial / Banking",
    knownVulns: ["SQL Injection (Auth Bypass)", "Stored XSS (Transaction Notes)", "CSRF (Money Transfer)", "IDOR (Account Statements)", "Unrestricted File Upload", "Broken Authentication"],
    owaspCategories: ["A01:2025", "A02:2025", "A03:2025", "A04:2025", "A05:2025", "A07:2025"],
    tags: ["nodejs", "banking", "financial", "mongodb"],
    roe: {
      provider: "hacksudo / 63Sats (Self-hosted instance)",
      termsUrl: "https://hub.docker.com/r/hacksudo/63satsvulnbank",
      summary: "Open-source intentionally vulnerable banking app. Self-hosted on AC3 scan server. Full permission to test all vulnerability types including financial transaction manipulation.",
      allowed: ["SQL injection", "XSS", "CSRF", "IDOR", "File upload", "Auth bypass", "Session hijacking", "Automated DAST", "Money transfer manipulation"],
      prohibited: [],
      rateLimit: null,
      requiresOwnInstance: false,
      noBruteForce: false,
      noDoS: false,
      noExfiltration: false,
      maxScansPerDay: null,
      notes: "Self-hosted on scan server at port 3006. Has registration, login, dashboard, transfer, and statement features."
    }
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
      summary: "Custom target. YOU must ensure you have written authorization (ROE) before scanning. The platform will not enforce rules for custom targets \u2014 all responsibility lies with the operator.",
      allowed: [],
      prohibited: [],
      rateLimit: null,
      requiresOwnInstance: false,
      noBruteForce: false,
      noDoS: false,
      noExfiltration: false,
      maxScansPerDay: null,
      notes: "WARNING: Scanning without authorization is illegal. Ensure you have a signed ROE before proceeding."
    }
  }
];
var labStates = /* @__PURE__ */ new Map();
async function addLabLog(state, entry) {
  state.log.push({ ts: Date.now(), ...entry });
  if (state.log.length > 300) state.log = state.log.slice(-300);
  try {
    const { eventHub } = await import("./ws-event-hub-GYTLNKYI.js");
    eventHub.broadcast({
      type: "training_lab:progress",
      sessionId: state.sessionId,
      timestamp: Date.now(),
      data: { phase: state.phase, progress: state.progress, log: entry }
    });
  } catch {
  }
}
async function runLabScan(sessionId, targetUrl, scanProfile) {
  const state = {
    sessionId,
    phase: "recon",
    progress: 0,
    isRunning: true,
    log: [],
    assets: [],
    stats: { hostsScanned: 0, portsFound: 0, vulnsFound: 0, toolsRun: 0 }
  };
  labStates.set(sessionId, state);
  const { updateTrainingLabSession } = await import("./db-FQGKASI3.js");
  const yieldEventLoop = () => new Promise((resolve) => setImmediate(resolve));
  const syncProgress = async () => {
    try {
      const lightAssets = state.assets.map((a) => ({
        ...a,
        toolResults: (a.toolResults || []).map((tr) => ({
          tool: tr.tool,
          status: tr.status,
          exitCode: tr.exitCode,
          findingCount: tr.findingCount,
          duration: tr.duration,
          // Truncate outputPreview to 200 chars for progress display
          outputPreview: (tr.outputPreview || "").slice(0, 200),
          findings: (tr.findings || []).slice(0, 20)
        })),
        // Keep vulns but cap at 30
        vulns: (a.vulns || []).slice(0, 30)
      }));
      const lightLog = (state.log || []).slice(-50);
      await updateTrainingLabSession(sessionId, {
        labStatus: "scanning",
        phase: state.phase,
        progress: state.progress,
        statsJson: state.stats,
        assetsJson: lightAssets,
        findingsJson: (state.assets[0]?.vulns || []).slice(0, 30),
        scanLogJson: lightLog
      });
    } catch {
    }
  };
  try {
    let parseNucleiOutput2 = function(output) {
      const lines = output.trim().split("\n").filter(Boolean);
      for (const line of lines) {
        try {
          const finding = JSON.parse(line);
          if (finding.info) {
            const dedupKey = `${finding["template-id"]}:${finding["matched-at"] || ""}`;
            if (seenTemplates.has(dedupKey)) continue;
            seenTemplates.add(dedupKey);
            const vuln = {
              id: `nuclei-${crypto.randomBytes(4).toString("hex")}`,
              severity: (finding.info.severity || "info").toLowerCase(),
              title: `[nuclei] ${finding.info.name || finding["template-id"] || "Unknown"}`,
              cve: finding.info.classification?.["cve-id"]?.[0] || void 0,
              tool: "nuclei",
              matchedAt: finding["matched-at"] || void 0,
              description: finding.info.description || void 0
            };
            nucleiFindings.push(vuln);
            state.assets[0].vulns.push(vuln);
            state.stats.vulnsFound++;
          }
        } catch {
        }
      }
    };
    var parseNucleiOutput = parseNucleiOutput2;
    let hostname;
    let targetPort = null;
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
    const fullTargetUrl = targetUrl.startsWith("http") ? targetUrl : `${targetScheme}://${targetUrl}`;
    const scanServerHost = process.env.SCAN_SERVER_HOST || "";
    const isSelfHosted = hostname === scanServerHost || hostname === "137.184.211.238" || hostname === "scan.aceofcloud.io";
    const scanUrl = isSelfHosted ? fullTargetUrl.replace(hostname, "127.0.0.1") : fullTargetUrl;
    const scanHostname = isSelfHosted ? "127.0.0.1" : hostname;
    await updateTrainingLabSession(sessionId, {
      labStatus: "scanning",
      phase: "recon",
      startedAt: Date.now()
    });
    let targetRoE = null;
    const matchedTarget = TRAINING_TARGETS.find((t) => t.url === targetUrl || t.liveInstanceUrl === targetUrl || hostname.includes(new URL(t.url.startsWith("http") ? t.url : `https://${t.url}`).hostname));
    if (matchedTarget) {
      const { enforceTrainingRoE } = await import("./training-roe-guard-32FKNDU7.js");
      targetRoE = enforceTrainingRoE(matchedTarget, { targetId: matchedTarget.id, scanProfile });
      if (targetRoE.enforcedRules.length > 0) {
        addLabLog(state, { phase: "recon", type: "info", title: "RoE Guardrails Active", detail: `Enforcing: ${targetRoE.enforcedRules.join(", ")}` });
      }
      if (targetRoE.warnings.length > 0) {
        for (const w of targetRoE.warnings) {
          addLabLog(state, { phase: "recon", type: "warning", title: "RoE Warning", detail: w.message });
        }
      }
    }
    state.assets.push({
      hostname,
      ports: [],
      vulns: [],
      toolResults: []
    });
    state.phase = "recon";
    state.progress = 5;
    addLabLog(state, { phase: "recon", type: "info", title: "Phase 1: Reconnaissance", detail: `Probing ${fullTargetUrl}` });
    try {
      const { executeRawCommandViaQueue } = await import("./job-queue-bridge-D5A5ERCQ.js");
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
        outputPreview: httpxResult.stdout.slice(0, 2e3)
      });
      if (httpxResult.stdout) {
        try {
          const lines = httpxResult.stdout.trim().split("\n").filter(Boolean);
          for (const line of lines) {
            const parsed = JSON.parse(line);
            if (parsed.port) {
              const port = parseInt(parsed.port);
              if (!state.assets[0].ports.find((p) => p.port === port)) {
                state.assets[0].ports.push({
                  port,
                  service: port === 443 || port === 8443 ? "https" : "http",
                  version: parsed["web-server"] || void 0
                });
                state.stats.portsFound++;
              }
            }
            if (parsed.title) state.assets[0].httpxTitle = parsed.title;
            if (parsed.tech) state.assets[0].httpxTech = parsed.tech;
            if (parsed.content_type) state.assets[0].httpxContentType = parsed.content_type;
          }
        } catch {
        }
      }
      addLabLog(state, { phase: "recon", type: "scan_result", title: "httpx Complete", detail: `Detected ${state.assets[0].ports.length} ports` });
    } catch (e) {
      addLabLog(state, { phase: "recon", type: "warning", title: "httpx Failed", detail: e.message?.slice(0, 200) || "Unknown error" });
    }
    await yieldEventLoop();
    await syncProgress();
    try {
      const { executeRawCommandViaQueue } = await import("./job-queue-bridge-D5A5ERCQ.js");
      const curlCmd = `curl -sI -m 15 -L '${scanUrl}' 2>&1 | head -50`;
      const curlResult = await executeRawCommandViaQueue(curlCmd, 20);
      state.stats.toolsRun++;
      const headerFindings = [];
      if (curlResult.stdout) {
        const headers = curlResult.stdout.toLowerCase();
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
        outputPreview: curlResult.stdout.slice(0, 2e3)
      });
      addLabLog(state, { phase: "recon", type: "scan_result", title: "Header Probe Complete", detail: `Found ${headerFindings.length} header issues` });
    } catch (e) {
      addLabLog(state, { phase: "recon", type: "warning", title: "Header Probe Failed", detail: e.message?.slice(0, 200) || "Unknown error" });
    }
    state.progress = 15;
    await yieldEventLoop();
    await syncProgress();
    state.phase = "enumeration";
    addLabLog(state, { phase: "enumeration", type: "info", title: "Phase 2: Enumeration", detail: `Running ScanForge discovery service detection on ${hostname}` });
    try {
      const { executeToolViaQueue } = await import("./job-queue-bridge-D5A5ERCQ.js");
      let discoveryFlags;
      if (targetPort && targetPort > 1024) {
        discoveryFlags = scanProfile === "quick" ? `-sV -sC -p ${targetPort},80,443 -T4 --open` : scanProfile === "deep" ? `-sV -sC -p ${targetPort},80,443,8080,8443,8000,3000,5000,9090 -T3 --open -A` : `-sV -sC -p ${targetPort},80,443,8080,8443,8000,3000,5000,9090 -T4 --open`;
      } else {
        discoveryFlags = scanProfile === "quick" ? `-sV -sC --top-ports 100 -T4 --open` : scanProfile === "deep" ? `-sV -sC -p- -T3 --open -A` : `-sV -sC --top-ports 1000 -T4 --open`;
      }
      if (matchedTarget) {
        const { sanitizeScanForgeFlags } = await import("./training-roe-guard-32FKNDU7.js");
        const original = discoveryFlags;
        discoveryFlags = sanitizeScanForgeFlags(discoveryFlags, matchedTarget.roe);
        if (discoveryFlags !== original) {
          addLabLog(state, { phase: "enumeration", type: "info", title: "RoE: ScanForge Flags Sanitized", detail: `Adjusted flags to comply with ${matchedTarget.name} RoE` });
        }
      }
      const discoveryTarget = scanHostname;
      const discoveryFlagsWithPn = discoveryFlags.includes("-Pn") ? discoveryFlags : `${discoveryFlags} -Pn`;
      const discoveryResult = await executeToolViaQueue({
        tool: "scanforge-discovery",
        args: `${discoveryFlagsWithPn} ${discoveryTarget}`,
        target: hostname,
        timeoutSeconds: scanProfile === "deep" ? 600 : 300
      }, { forceLocal: false });
      state.stats.toolsRun++;
      state.stats.hostsScanned++;
      const portRegex = /(\d+)\/tcp\s+open\s+(\S+)\s*(.*)/g;
      let match;
      while ((match = portRegex.exec(discoveryResult.stdout)) !== null) {
        const port = parseInt(match[1]);
        if (!state.assets[0].ports.find((p) => p.port === port)) {
          state.assets[0].ports.push({
            port,
            service: match[2],
            version: match[3]?.trim() || void 0
          });
          state.stats.portsFound++;
        }
      }
      state.assets[0].toolResults.push({
        tool: "scanforge-discovery",
        command: discoveryResult.command,
        exitCode: discoveryResult.exitCode,
        durationMs: discoveryResult.durationMs,
        findingCount: state.assets[0].ports.length,
        findings: state.assets[0].ports.map((p) => ({ severity: "info", title: `Port ${p.port}/${p.service}` })),
        outputPreview: discoveryResult.stdout.replace(/\| fingerprint-strings:[\s\S]*?(?=\n\w|\nScanForge|$)/g, "| [fingerprint data omitted]").slice(0, 1500)
      });
      addLabLog(state, { phase: "enumeration", type: "scan_result", title: "ScanForge Discovery Complete", detail: `Found ${state.assets[0].ports.length} open ports` });
    } catch (e) {
      addLabLog(state, { phase: "enumeration", type: "warning", title: "ScanForge Discovery Failed", detail: e.message?.slice(0, 200) || "Unknown error" });
    }
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
    state.phase = "vuln_detection";
    addLabLog(state, { phase: "vuln_detection", type: "info", title: "Phase 3: Vulnerability Detection", detail: "Running nuclei, nikto, and gobuster scans" });
    const nucleiFindings = [];
    const seenTemplates = /* @__PURE__ */ new Set();
    let totalNucleiDurationMs = 0;
    const httpxTech = (state.assets[0].httpxTech || []).map((t) => t.toLowerCase());
    const httpxTitle = (state.assets[0].httpxTitle || "").toLowerCase();
    const techStr = httpxTech.join(" ") + " " + httpxTitle;
    const techTemplatePaths = [];
    if (techStr.includes("php") || techStr.includes("apache")) {
      techTemplatePaths.push("-t http/misconfiguration/php*", "-t http/vulnerabilities/php*", "-t http/misconfiguration/apache*");
    }
    if (techStr.includes("node") || techStr.includes("express") || techStr.includes("next")) {
      techTemplatePaths.push("-t http/misconfiguration/node*", "-t http/exposures/configs/node*");
    }
    if (techStr.includes("nginx")) {
      techTemplatePaths.push("-t http/misconfiguration/nginx*", "-t http/vulnerabilities/nginx*");
    }
    if (techStr.includes("wordpress") || techStr.includes("wp-")) {
      techTemplatePaths.push("-t http/misconfiguration/wordpress*", "-t http/vulnerabilities/wordpress*");
    }
    techTemplatePaths.push(
      "-t http/misconfiguration/cors*",
      "-t http/misconfiguration/csp*",
      "-t http/misconfiguration/security-header*",
      "-t http/misconfiguration/directory-listing*",
      "-t http/misconfiguration/cookie*",
      "-t http/misconfiguration/x-frame*"
    );
    const nucleiBase = `-jsonl -nc -or -ot -ni -timeout 8 -retries 0 -rate-limit 200 -silent -concurrency 15`;
    const { executeRawCommandViaQueue: execNucleiCmd } = await import("./job-queue-bridge-D5A5ERCQ.js");
    try {
      const dastTimeout = scanProfile === "deep" ? 60 : 40;
      const dastCmd = `timeout ${dastTimeout} bash -c "echo '${scanUrl}' | nuclei ${nucleiBase} -t dast/vulnerabilities/ -severity low,medium,high,critical" 2>&1`;
      addLabLog(state, { phase: "vuln_detection", type: "info", title: "nuclei Pass 1/3", detail: "DAST active testing (XSS, SQLi, LFI, SSRF, SSTI)" });
      const r1 = await execNucleiCmd(dastCmd, dastTimeout + 15);
      totalNucleiDurationMs += r1.durationMs;
      parseNucleiOutput2((r1.stdout || "") + "\n" + (r1.stderr || ""));
      addLabLog(state, { phase: "vuln_detection", type: "scan_result", title: "nuclei Pass 1 Done", detail: `+${nucleiFindings.length} findings (${Math.round(r1.durationMs / 1e3)}s)` });
    } catch (e) {
      addLabLog(state, { phase: "vuln_detection", type: "warning", title: "nuclei Pass 1 Failed", detail: e.message?.slice(0, 150) });
    }
    await yieldEventLoop();
    try {
      const techTimeout = scanProfile === "deep" ? 45 : 30;
      const techArgs = techTemplatePaths.join(" ");
      const techCmd = `timeout ${techTimeout} bash -c "echo '${scanUrl}' | nuclei ${nucleiBase} ${techArgs}" 2>&1`;
      addLabLog(state, { phase: "vuln_detection", type: "info", title: "nuclei Pass 2/3", detail: `Tech-specific checks (${httpxTech.slice(0, 3).join(", ") || "generic"})` });
      const r2 = await execNucleiCmd(techCmd, techTimeout + 15);
      totalNucleiDurationMs += r2.durationMs;
      const beforeCount = nucleiFindings.length;
      parseNucleiOutput2((r2.stdout || "") + "\n" + (r2.stderr || ""));
      addLabLog(state, { phase: "vuln_detection", type: "scan_result", title: "nuclei Pass 2 Done", detail: `+${nucleiFindings.length - beforeCount} findings (${Math.round(r2.durationMs / 1e3)}s)` });
    } catch (e) {
      addLabLog(state, { phase: "vuln_detection", type: "warning", title: "nuclei Pass 2 Failed", detail: e.message?.slice(0, 150) });
    }
    await yieldEventLoop();
    try {
      const expTimeout = scanProfile === "deep" ? 45 : 30;
      const expCmd = `timeout ${expTimeout} bash -c "echo '${scanUrl}' | nuclei ${nucleiBase} -t http/exposures/ -t http/exposed-panels/ -severity info,low,medium,high,critical" 2>&1`;
      addLabLog(state, { phase: "vuln_detection", type: "info", title: "nuclei Pass 3/3", detail: "Exposure & panel checks" });
      const r3 = await execNucleiCmd(expCmd, expTimeout + 15);
      totalNucleiDurationMs += r3.durationMs;
      const beforeCount = nucleiFindings.length;
      parseNucleiOutput2((r3.stdout || "") + "\n" + (r3.stderr || ""));
      addLabLog(state, { phase: "vuln_detection", type: "scan_result", title: "nuclei Pass 3 Done", detail: `+${nucleiFindings.length - beforeCount} findings (${Math.round(r3.durationMs / 1e3)}s)` });
    } catch (e) {
      addLabLog(state, { phase: "vuln_detection", type: "warning", title: "nuclei Pass 3 Failed", detail: e.message?.slice(0, 150) });
    }
    let autoSelectorFindings = 0;
    try {
      const { resolveNucleiTemplate } = await import("./nuclei-template-auto-selector-RHTVSP7N.js");
      const targetPreset = TRAINING_TARGETS.find((t) => t.url === targetUrl || t.liveInstanceUrl === targetUrl);
      const discoveredCves = nucleiFindings.map((f) => f.cve).filter((c) => !!c && c.startsWith("CVE-"));
      const vulnClasses = targetPreset?.knownVulns || [];
      const targetedTemplateArgs = [];
      const resolvedSources = [];
      for (const cve of [...new Set(discoveredCves)]) {
        const resolution = await resolveNucleiTemplate({ cve });
        if (resolution.templatePath) {
          targetedTemplateArgs.push(`-t ${resolution.templatePath}`);
          resolvedSources.push(`${cve}\u2192${resolution.source}`);
        } else if (resolution.tags.length > 0) {
          targetedTemplateArgs.push(`-tags ${resolution.tags.join(",")}`);
          resolvedSources.push(`${cve}\u2192tags:${resolution.tags.join(",")}`);
        }
      }
      const vulnClassMap = {
        "SQL Injection": "sqli",
        "XSS": "xss",
        "SSRF": "ssrf",
        "SSTI": "ssti",
        "File Inclusion": "lfi",
        "Command Injection": "command_injection",
        "Auth Bypass": "auth_bypass",
        "Insecure Deserialization": "deserialization",
        "File Upload": "file_upload",
        "Path Traversal": "lfi",
        "XXE": "xxe",
        "CSRF": "csrf",
        "IDOR": "idor",
        "Open Redirect": "redirect"
      };
      for (const vuln of vulnClasses) {
        const vc = vulnClassMap[vuln];
        if (vc) {
          const resolution = await resolveNucleiTemplate({ vulnClass: vc });
          if (resolution.tags.length > 0 && !targetedTemplateArgs.some((a) => a.includes(resolution.tags[0]))) {
            targetedTemplateArgs.push(`-tags ${resolution.tags.join(",")}`);
            resolvedSources.push(`${vuln}\u2192${resolution.source}`);
          }
        }
      }
      if (targetedTemplateArgs.length > 0) {
        const cveTimeout = scanProfile === "deep" ? 45 : 30;
        const uniqueArgs = [...new Set(targetedTemplateArgs)].slice(0, 15).join(" ");
        const cveCmd = `timeout ${cveTimeout} bash -c "echo '${scanUrl}' | nuclei ${nucleiBase} ${uniqueArgs} -severity low,medium,high,critical" 2>&1`;
        addLabLog(state, { phase: "vuln_detection", type: "info", title: "nuclei Pass 4/4", detail: `CVE-targeted scan (${resolvedSources.length} resolutions: ${resolvedSources.slice(0, 3).join(", ")}${resolvedSources.length > 3 ? "..." : ""})` });
        const r4 = await execNucleiCmd(cveCmd, cveTimeout + 15);
        totalNucleiDurationMs += r4.durationMs;
        const beforeCount = nucleiFindings.length;
        parseNucleiOutput2((r4.stdout || "") + "\n" + (r4.stderr || ""));
        autoSelectorFindings = nucleiFindings.length - beforeCount;
        addLabLog(state, { phase: "vuln_detection", type: "scan_result", title: "nuclei Pass 4 Done", detail: `+${autoSelectorFindings} findings from auto-selector (${Math.round(r4.durationMs / 1e3)}s)` });
      } else {
        addLabLog(state, { phase: "vuln_detection", type: "info", title: "nuclei Pass 4 Skipped", detail: "No CVEs or vuln classes resolved to targeted templates" });
      }
    } catch (e) {
      addLabLog(state, { phase: "vuln_detection", type: "warning", title: "nuclei Pass 4 Failed", detail: e.message?.slice(0, 150) });
    }
    await yieldEventLoop();
    state.stats.toolsRun++;
    state.assets[0].toolResults.push({
      tool: "nuclei",
      command: `nuclei [4 passes: DAST + tech(${httpxTech.slice(0, 3).join(",")}) + exposures + CVE-targeted]`,
      exitCode: 0,
      durationMs: totalNucleiDurationMs,
      findingCount: nucleiFindings.length,
      findings: nucleiFindings,
      outputPreview: nucleiFindings.length > 0 ? nucleiFindings.map((f) => `[${f.severity}] ${f.title}${f.matchedAt ? " @ " + f.matchedAt : ""}`).join("\n") : "(no findings from 4 passes)"
    });
    addLabLog(state, { phase: "vuln_detection", type: "scan_result", title: "nuclei Complete", detail: `Total: ${nucleiFindings.length} findings across 4 passes (${autoSelectorFindings} from auto-selector) (${Math.round(totalNucleiDurationMs / 1e3)}s)` });
    try {
      const { persistNucleiFindings: persistFindings } = await import("./nuclei-findings-persistence-EOYZWFBQ.js");
      const { parseNucleiJsonOutput } = await import("./nuclei-output-parser-EKF7IYYK.js");
      const syntheticFindings = nucleiFindings.map((f) => ({
        "template-id": f.title?.replace("[nuclei] ", "") || "unknown",
        host: scanUrl,
        "matched-at": f.matchedAt || scanUrl,
        type: "http",
        info: {
          id: f.title?.replace("[nuclei] ", "") || "unknown",
          name: f.title?.replace("[nuclei] ", "") || "Unknown",
          severity: f.severity || "info",
          description: f.description || "",
          classification: f.cve ? { "cve-id": [f.cve] } : void 0
        }
      }));
      if (syntheticFindings.length > 0) {
        await persistFindings({
          target: scanUrl,
          parseResult: { findings: syntheticFindings, stats: { total: syntheticFindings.length, critical: 0, high: 0, medium: 0, low: 0, info: 0 }, rawOutput: "" },
          executionContext: "direct",
          nucleiCommand: "training-lab-pipeline"
        });
        addLabLog(state, { phase: "vuln_detection", type: "info", title: "Nuclei Findings Persisted", detail: `${syntheticFindings.length} findings saved to DB for effectiveness tracking` });
      }
    } catch (e) {
      addLabLog(state, { phase: "vuln_detection", type: "warning", title: "Nuclei Persistence Skipped", detail: e.message?.slice(0, 100) });
    }
    state.progress = 45;
    await yieldEventLoop();
    await syncProgress();
    try {
      const { executeRawCommandViaQueue } = await import("./job-queue-bridge-D5A5ERCQ.js");
      const niktoTimeout = scanProfile === "deep" ? 180 : 60;
      const niktoSslFlag = scanUrl.startsWith("https://") ? " -ssl" : "";
      const niktoCmd = `timeout ${niktoTimeout} nikto -h ${scanUrl}${niktoSslFlag} -Tuning 1234567890abc 2>&1`;
      const niktoResult = await executeRawCommandViaQueue(niktoCmd, niktoTimeout + 30);
      state.stats.toolsRun++;
      const niktoFindings = [];
      const niktoOutput = (niktoResult.stdout || "") + "\n" + (niktoResult.stderr || "");
      if (niktoOutput.trim()) {
        const lines = niktoOutput.trim().split("\n").filter(Boolean);
        for (const line of lines) {
          const isNiktoFinding = (line.startsWith("+") || line.startsWith("- ")) && !line.includes("Target IP:") && !line.includes("Target Hostname:") && !line.includes("Target Port:") && !line.includes("Start Time:") && !line.includes("End Time:") && !line.includes("host(s) tested") && !line.includes("items checked:") && !line.includes("Nikto v");
          if (isNiktoFinding) {
            const cleanLine = line.replace(/^[+\-]\s*/, "").trim();
            if (cleanLine.length > 10) {
              let severity = "info";
              if (cleanLine.toLowerCase().includes("vulnerability") || cleanLine.toLowerCase().includes("injection") || cleanLine.toLowerCase().includes("xss") || cleanLine.toLowerCase().includes("rce")) severity = "high";
              else if (cleanLine.toLowerCase().includes("directory") || cleanLine.toLowerCase().includes("listing") || cleanLine.toLowerCase().includes("found") || cleanLine.toLowerCase().includes("indexing")) severity = "medium";
              else if (cleanLine.toLowerCase().includes("header") || cleanLine.toLowerCase().includes("leak") || cleanLine.toLowerCase().includes("disclosure") || cleanLine.toLowerCase().includes("etag") || cleanLine.toLowerCase().includes("cors")) severity = "low";
              niktoFindings.push({
                id: `nikto-${crypto.randomBytes(4).toString("hex")}`,
                severity,
                title: `[nikto] ${cleanLine.slice(0, 200)}`,
                tool: "nikto"
              });
            }
          }
        }
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
        outputPreview: niktoOutput.slice(0, 3e3)
      });
      addLabLog(state, { phase: "vuln_detection", type: "scan_result", title: "nikto Complete", detail: `Found ${niktoFindings.length} findings` });
    } catch (e) {
      addLabLog(state, { phase: "vuln_detection", type: "warning", title: "nikto Failed", detail: e.message?.slice(0, 200) || "Unknown error" });
    }
    state.progress = 55;
    await yieldEventLoop();
    await syncProgress();
    try {
      const { executeRawCommandViaQueue } = await import("./job-queue-bridge-D5A5ERCQ.js");
      const probeCmd = `curl -s -o /dev/null -w '%{size_download}' '${scanUrl}/nonexistent-path-${Date.now()}' 2>&1`;
      const probeResult = await executeRawCommandViaQueue(probeCmd, 15);
      const wildcardLength = probeResult.stdout?.trim();
      let gobusterArgs = `dir -u ${scanUrl} -w /opt/SecLists/Discovery/Web-Content/common.txt -t 20 -q --no-error --timeout 5s`;
      if (wildcardLength && parseInt(wildcardLength) > 0) {
        gobusterArgs += ` --exclude-length ${wildcardLength}`;
        addLabLog(state, { phase: "vuln_detection", type: "info", title: "SPA Detected", detail: `Excluding wildcard response length ${wildcardLength} bytes` });
      }
      const gobusterResult = await executeRawCommandViaQueue(`timeout 90 gobuster ${gobusterArgs}`, 120);
      state.stats.toolsRun++;
      const dirFindings = [];
      if (gobusterResult.stdout) {
        const rawOutput = gobusterResult.stdout.slice(0, 5e4);
        const lines = rawOutput.trim().split("\n").filter(Boolean).slice(0, 500);
        for (const line of lines) {
          if (dirFindings.length >= 100) break;
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
        outputPreview: gobusterResult.stdout.slice(0, 3e3)
      });
      addLabLog(state, { phase: "vuln_detection", type: "scan_result", title: "gobuster Complete", detail: `Found ${dirFindings.length} directories` });
    } catch (e) {
      addLabLog(state, { phase: "vuln_detection", type: "warning", title: "gobuster Failed", detail: e.message?.slice(0, 200) || "Unknown error" });
    }
    state.progress = 65;
    await yieldEventLoop();
    await syncProgress();
    state.phase = "analyzing";
    addLabLog(state, { phase: "analyzing", type: "info", title: "Phase 4: LLM Analysis", detail: "Running AI-powered vulnerability correlation with self-learning context" });
    await yieldEventLoop();
    await updateTrainingLabSession(sessionId, {
      labStatus: "analyzing",
      phase: "analyzing",
      progress: 65
    });
    await yieldEventLoop();
    const targetPresetForLearning = TRAINING_TARGETS.find((t) => t.url === targetUrl || t.liveInstanceUrl === targetUrl)?.id || "custom";
    let llmAnalysis = null;
    try {
      const { invokeLLM } = await import("./llm-IHYY5FA6.js");
      const { buildLearningContext } = await import("./llm-self-learning-H3OKCPQI.js");
      let learningContext = "";
      try {
        learningContext = await buildLearningContext(targetPresetForLearning);
        if (learningContext) {
          addLabLog(state, { phase: "analyzing", type: "info", title: "Learning Context Loaded", detail: `Injecting correction history and ground truth hints for ${targetPresetForLearning}` });
        }
      } catch (e) {
        addLabLog(state, { phase: "analyzing", type: "warning", title: "Learning Context Unavailable", detail: e.message?.slice(0, 200) || "" });
      }
      await yieldEventLoop();
      const httpxMeta = state.assets[0];
      const techFingerprint = [];
      if (httpxMeta.httpxTitle) techFingerprint.push(`Page Title: ${httpxMeta.httpxTitle}`);
      if (httpxMeta.httpxTech?.length) techFingerprint.push(`Detected Stack: ${httpxMeta.httpxTech.join(", ")}`);
      if (httpxMeta.httpxContentType) techFingerprint.push(`Content-Type: ${httpxMeta.httpxContentType}`);
      const portsSummary = state.assets[0].ports.map(
        (p) => `${p.port}/${p.service}${p.version ? ` (${p.version})` : ""}`
      ).join(", ");
      if (portsSummary) techFingerprint.push(`Open Ports: ${portsSummary}`);
      const confirmedVulns = state.assets[0].vulns.filter((v) => v.tool === "nuclei");
      const headerIssues = state.assets[0].vulns.filter((v) => (v.title || "").includes("[headers]"));
      const niktoFindings = state.assets[0].toolResults.find((t) => t.tool === "nikto");
      const gobusterResults = state.assets[0].toolResults.find((t) => t.tool === "gobuster");
      const discoveryResults = state.assets[0].toolResults.find((t) => t.tool === "scanforge-discovery");
      const curlResults = state.assets[0].toolResults.find((t) => t.tool === "curl");
      const techStack = (httpxMeta.httpxTech || []).map((t) => t.toLowerCase()).join(" ");
      const techInferences = [];
      if (techStack.includes("express") || techStack.includes("node")) {
        techInferences.push("Node.js/Express apps are commonly vulnerable to: prototype pollution, NoSQL injection, SSRF via request libraries, insecure deserialization, JWT misconfig, path traversal via path.join, XSS in template engines");
      }
      if (techStack.includes("php") || techStack.includes("apache")) {
        techInferences.push("PHP/Apache apps are commonly vulnerable to: SQL injection, file inclusion (LFI/RFI), command injection via exec/system, file upload bypass, session fixation, XSS, CSRF, directory traversal");
      }
      if (techStack.includes("angular") || techStack.includes("react") || techStack.includes("vue")) {
        techInferences.push("SPA frameworks may have: DOM-based XSS, client-side routing bypass, exposed API endpoints, CORS misconfiguration, sensitive data in client bundles");
      }
      if (techStack.includes("mysql") || techStack.includes("mariadb") || techStack.includes("sqlite")) {
        techInferences.push("SQL databases suggest: SQL injection vectors, credential exposure in config files, database backup exposure");
      }
      const discoveredPaths = gobusterResults?.findings?.map((f) => f.title?.replace("[gobuster] ", "") || "") || [];
      const interestingPaths = discoveredPaths.filter(
        (p) => /api|admin|config|backup|upload|login|register|debug|test|swagger|phpinfo|phpmyadmin|wp-|git|env|sql|db|ftp/i.test(p)
      );
      let targetContext = "";
      if (matchedTarget) {
        targetContext = `
## TARGET INTELLIGENCE
This is "${matchedTarget.name}" \u2014 ${matchedTarget.description}
Tech Stack: ${matchedTarget.tags.join(", ")}
Known Vulnerability Categories: ${matchedTarget.knownVulns.join(", ")}
OWASP Categories: ${matchedTarget.owaspCategories.join(", ")}
Difficulty: ${matchedTarget.difficulty}`;
      }
      const toolEvidence = [];
      if (confirmedVulns.length > 0) {
        toolEvidence.push(`### Nuclei Confirmed Vulnerabilities (${confirmedVulns.length})
` + confirmedVulns.map((v) => `- [${v.severity.toUpperCase()}] ${v.title}${v.matchedAt ? " @ " + v.matchedAt : ""}${v.description ? " \u2014 " + v.description.slice(0, 120) : ""}`).join("\n"));
      }
      if (niktoFindings && niktoFindings.findingCount > 0) {
        toolEvidence.push(`### Nikto Web Scanner Findings (${niktoFindings.findingCount})
` + niktoFindings.findings.slice(0, 20).map((f) => `- [${f.severity}] ${f.title}`).join("\n"));
      }
      if (headerIssues.length > 0) {
        toolEvidence.push(`### Security Header Issues (${headerIssues.length})
` + headerIssues.map((v) => `- ${v.title}`).join("\n"));
      }
      if (interestingPaths.length > 0) {
        toolEvidence.push(`### Interesting Directories/Endpoints (${interestingPaths.length} of ${discoveredPaths.length} total)
` + interestingPaths.map((p) => `- ${p}`).join("\n"));
      }
      if (discoveryResults?.outputPreview) {
        const discoveryClean = discoveryResults.outputPreview.replace(/\| fingerprint-strings:[\s\S]*?(?=\n\w|$)/g, "").replace(/SF-Port[\s\S]*?(?=\n\w|$)/g, "").slice(0, 800);
        if (discoveryClean.trim()) toolEvidence.push(`### ScanForge Service Detection
${discoveryClean}`);
      }
      if (curlResults?.outputPreview) {
        toolEvidence.push(`### HTTP Response Headers
${curlResults.outputPreview.slice(0, 600)}`);
      }
      const analysisPrompt = `You are an expert penetration tester and red team operator analyzing reconnaissance and vulnerability scan results from a TRAINING LAB session.

# RECONNAISSANCE INTELLIGENCE BRIEF

## TARGET: ${hostname} (${fullTargetUrl})
${techFingerprint.join("\n")}
${targetContext}

## SCAN EVIDENCE
${toolEvidence.join("\n\n") || "No significant findings from automated tools."}

${techInferences.length > 0 ? `## TECHNOLOGY-AWARE INFERENCE CONTEXT
${techInferences.join("\n")}` : ""}

# ANALYSIS INSTRUCTIONS

You must perform THREE levels of analysis:

## Level 1: CONFIRMED VULNERABILITIES
List all vulnerabilities directly confirmed by scan tools (nuclei DAST findings, nikto findings). These have the highest confidence.

## Level 2: EVIDENCE-BASED INFERENCE
Based on the technology fingerprint, discovered directories, HTTP headers, and service versions, infer vulnerabilities that are HIGHLY LIKELY to exist. For example:
- If gobuster found /api/ and /swagger \u2192 likely API security issues (broken auth, mass assignment, IDOR)
- If nikto found directory listing \u2192 likely information disclosure
- If httpx detected PHP + Apache \u2192 likely SQL injection, file inclusion, command injection
- If missing security headers (CSP, HSTS) \u2192 likely XSS, clickjacking
- If /admin or /login found \u2192 likely brute force, default credentials, broken access control

## Level 3: EXPLOIT METHOD SELECTION
For EACH finding, you MUST decide the optimal exploitation approach and provide ready-to-execute CLI commands.

Decision framework (evaluate in order):
1. **Does a reliable Metasploit module exist?** \u2192 Use "metasploit" (e.g., exploit/unix/webapp/dvwa_exec for DVWA command injection)
2. **Does a public PoC exist on ExploitDB?** \u2192 Use "exploitdb" (searchsploit to find and download)
3. **Is it a web app vuln requiring custom payload?** \u2192 Use "custom" (sqlmap, curl, python3, bash)
4. **Is it a misconfiguration to verify?** \u2192 Use "manual_verification" (curl -I, check headers/files)

For Metasploit: provide full msfconsole commands or resource scripts
For ExploitDB: provide searchsploit search + download + execution commands
For Custom: provide the exact curl/sqlmap/python3 commands with proper payloads
For Manual Verification: provide curl/grep commands to confirm the issue

## Level 4: EXPLOIT CHAIN PLANNING
Identify multi-step attack chains that combine individual findings into realistic attack scenarios. Map each step to a MITRE ATT&CK technique. For example:
- "Directory listing (T1083) \u2192 Config file exposure (T1552.001) \u2192 Credential theft (T1078) \u2192 Admin access (T1078.004)"
- "SQL Injection (T1190) \u2192 Database dump (T1005) \u2192 Credential reuse (T1078) \u2192 Lateral movement"

## CRITICAL RULES:
1. Each finding MUST have a SPECIFIC, DESCRIPTIVE title (e.g., "Reflected XSS in Search Parameter", NOT "XSS Vulnerability")
2. For known vulnerable training apps, be EXHAUSTIVE \u2014 these apps are DESIGNED to have many vulnerabilities
3. Distinguish between confirmed (tool-verified) and inferred (context-based) findings using the evidence field
4. Map every finding to an OWASP 2025 category AND a MITRE ATT&CK technique
5. Generate at least 2-3 realistic exploit chains that a red team operator would actually execute
6. Do NOT generate vague or generic findings \u2014 every finding must be actionable
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
      const promptSize = analysisPrompt.length;
      console.log(`[TrainingLab] LLM prompt size: ${promptSize} chars for ${hostname}`);
      addLabLog(state, { phase: "analyzing", type: "info", title: "LLM Prompt Size", detail: `${promptSize} characters` });
      const llmPayload = {
        messages: [
          { role: "system", content: "You are an expert red team operator and penetration tester with deep knowledge of OWASP Top 10, MITRE ATT&CK, and common web application vulnerabilities. You analyze reconnaissance data from multiple tools (Masscan/Naabu, httpx, nuclei, nikto, gobuster, curl) and synthesize findings into actionable intelligence. You excel at inferring vulnerabilities from technology fingerprints and correlating evidence across tools. Always respond with valid JSON." },
          { role: "user", content: analysisPrompt }
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
                        expectedOutput: { type: "string" }
                      }, required: ["order", "tool", "command", "description"] } },
                      alternativeMethod: { type: "object", properties: {
                        method: { type: "string" },
                        reasoning: { type: "string" }
                      } },
                      preConditions: { type: "array", items: { type: "string" } },
                      expectedOutcome: { type: "string" },
                      opsecNotes: { type: "string" }
                    }, required: ["method", "reasoning", "primaryTool", "cliCommands"] }
                  },
                  required: ["title", "severity", "category", "description", "confidence", "exploitMethod"]
                } },
                attackChains: { type: "array", items: {
                  type: "object",
                  properties: {
                    name: { type: "string", description: "Attack chain name" },
                    steps: { type: "array", items: { type: "string" }, description: "Ordered attack steps" },
                    impact: { type: "string", description: "Combined impact" },
                    likelihood: { type: "string", description: "high, medium, or low" },
                    mitre_tactics: { type: "array", items: { type: "string" }, description: "MITRE ATT&CK tactics involved" }
                  },
                  required: ["name", "steps", "impact", "likelihood"]
                } },
                missedAreas: { type: "array", items: { type: "string" } },
                recommendations: { type: "array", items: { type: "string" } }
              },
              required: ["executiveSummary", "riskScore", "riskRating", "findings", "attackChains", "missedAreas", "recommendations"]
            }
          }
        },
        _caller: "training-lab.llmAnalysis"
      };
      await yieldEventLoop();
      let result;
      for (let attempt = 0; attempt < 3; attempt++) {
        try {
          if (attempt > 0) {
            console.log(`[TrainingLab] LLM retry #${attempt} for ${hostname}`);
            await new Promise((r) => setTimeout(r, 3e3 * attempt));
          }
          result = await invokeLLM({ ...llmPayload, _caller: "training-lab.execute" });
          break;
        } catch (retryErr) {
          if (attempt === 2 || !retryErr.message?.includes("403")) throw retryErr;
          addLabLog(state, { phase: "analyzing", type: "warning", title: "LLM Rate Limited", detail: `Attempt ${attempt + 1} failed with 403, retrying...` });
        }
      }
      const content = result.choices?.[0]?.message?.content;
      if (typeof content === "string") {
        try {
          llmAnalysis = JSON.parse(content);
        } catch {
          const jsonMatch = content.match(/```(?:json)?\s*([\s\S]*?)```/);
          if (jsonMatch) {
            llmAnalysis = JSON.parse(jsonMatch[1]);
          }
        }
      }
      if (llmAnalysis) {
        addLabLog(state, {
          phase: "analyzing",
          type: "scan_result",
          title: "LLM Analysis Complete",
          detail: `Risk: ${llmAnalysis.riskRating?.toUpperCase()} (${llmAnalysis.riskScore}/10) | ${llmAnalysis.findings?.length || 0} findings | ${llmAnalysis.attackChains?.length || 0} attack chains`
        });
        try {
          const { scoreAgainstGroundTruth, saveAccuracyScore } = await import("./llm-self-learning-H3OKCPQI.js");
          const llmFindings = (llmAnalysis.findings || []).map((f) => ({
            title: f.title || "",
            severity: f.severity || "info",
            category: f.category || "",
            cve: f.cve || void 0
          }));
          const accuracyScore = scoreAgainstGroundTruth(targetPresetForLearning, llmFindings);
          if (accuracyScore) {
            await saveAccuracyScore(sessionId, targetPresetForLearning, accuracyScore);
            addLabLog(state, {
              phase: "analyzing",
              type: "scan_result",
              title: "Ground Truth Scoring Complete",
              detail: `F1: ${(accuracyScore.f1Score * 100).toFixed(1)}% | Precision: ${(accuracyScore.precision * 100).toFixed(1)}% | Recall: ${(accuracyScore.recall * 100).toFixed(1)}% | TP: ${accuracyScore.truePositives} FP: ${accuracyScore.falsePositives} FN: ${accuracyScore.falseNegatives}`
            });
            llmAnalysis.__accuracyScore = accuracyScore;
          }
        } catch (e) {
          addLabLog(state, { phase: "analyzing", type: "warning", title: "Ground Truth Scoring Failed", detail: e.message?.slice(0, 200) || "" });
        }
        try {
          const { scoreExploitSelection } = await import("./exploit-selection-intelligence-HZRINSFL.js");
          const { getExploitMethodGroundTruth } = await import("./exploit-method-ground-truth-H6ARGIY7.js");
          const exploitGroundTruth = getExploitMethodGroundTruth(targetPresetForLearning);
          if (exploitGroundTruth && exploitGroundTruth.length > 0) {
            const llmFindingsWithExploit = (llmAnalysis.findings || []).map((f) => ({
              title: f.title || "",
              category: f.category || "",
              exploitMethod: f.exploitMethod || void 0
            }));
            const exploitScore = scoreExploitSelection(exploitGroundTruth, llmFindingsWithExploit);
            addLabLog(state, {
              phase: "analyzing",
              type: "scan_result",
              title: "Exploit Selection Scoring Complete",
              detail: `Overall: ${(exploitScore.overallScore * 100).toFixed(1)}% | Method Accuracy: ${(exploitScore.methodAccuracy * 100).toFixed(1)}% | CLI Tool: ${(exploitScore.cliToolAccuracy * 100).toFixed(1)}% | CLI Pattern: ${(exploitScore.cliPatternAccuracy * 100).toFixed(1)}% | Scored: ${exploitScore.scoredFindings}/${exploitScore.totalFindings}`
            });
            llmAnalysis.__exploitSelectionScore = exploitScore;
          }
        } catch (e) {
          addLabLog(state, { phase: "analyzing", type: "warning", title: "Exploit Selection Scoring Failed", detail: e.message?.slice(0, 200) || "" });
        }
        try {
          const { resolveNucleiTemplate } = await import("./nuclei-template-auto-selector-RHTVSP7N.js");
          let nucleiHintCount = 0;
          for (const finding of llmAnalysis.findings || []) {
            if (finding.cve && finding.cve.startsWith("CVE-")) {
              const resolution = await resolveNucleiTemplate({
                cve: finding.cve,
                vulnClass: finding.category?.toLowerCase()
              });
              if (resolution.source !== "none") {
                finding.__nucleiHint = {
                  templatePath: resolution.templatePath,
                  tags: resolution.tags,
                  source: resolution.source,
                  confidence: resolution.confidence
                };
                nucleiHintCount++;
              }
            }
          }
          if (nucleiHintCount > 0) {
            addLabLog(state, {
              phase: "analyzing",
              type: "info",
              title: "Nuclei Fast-Path Hints Added",
              detail: `${nucleiHintCount}/${llmAnalysis.findings?.length || 0} findings annotated with Nuclei template hints`
            });
          }
        } catch (e) {
          addLabLog(state, { phase: "analyzing", type: "warning", title: "Nuclei Hints Failed", detail: e.message?.slice(0, 100) || "" });
        }
      }
    } catch (e) {
      addLabLog(state, { phase: "analyzing", type: "warning", title: "LLM Analysis Failed", detail: e.message?.slice(0, 300) || "Unknown error" });
      llmAnalysis = { error: e.message, executiveSummary: "LLM analysis failed \u2014 see error details", riskScore: 0, riskRating: "unknown", findings: [], attackChains: [], missedAreas: [], recommendations: [] };
    }
    state.progress = 90;
    let owaspCoverage = null;
    try {
      const { OwaspCoverageTracker } = await import("./owasp-coverage-tracker-UNGG3LUV.js");
      const tracker = new OwaspCoverageTracker();
      tracker.registerAssetTech(hostname, state.assets[0].ports.map((p) => p.service).filter(Boolean));
      for (const tr of state.assets[0].toolResults) {
        tracker.addToolRun({ tool: tr.tool, target: hostname, command: tr.command, exitCode: tr.exitCode });
        for (const f of tr.findings) {
          tracker.addFinding({
            tool: tr.tool,
            target: hostname,
            title: f.title || "",
            severity: f.severity || "info",
            description: f.description || ""
          });
        }
      }
      owaspCoverage = tracker.getEngagementCoverage(state.sessionId || "training-lab");
    } catch (e) {
      addLabLog(state, { phase: "analyzing", type: "warning", title: "OWASP Coverage Failed", detail: e.message?.slice(0, 200) || "Unknown error" });
    }
    state.phase = "completed";
    state.progress = 100;
    state.isRunning = false;
    addLabLog(state, {
      phase: "completed",
      type: "info",
      title: "Training Lab Session Complete",
      detail: `${state.stats.toolsRun} tools run | ${state.stats.vulnsFound} vulns found | ${state.assets[0].ports.length} ports discovered`
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
      scanLogJson: state.log
    });
  } catch (e) {
    state.phase = "failed";
    state.isRunning = false;
    addLabLog(state, { phase: "failed", type: "error", title: "Session Failed", detail: e.message?.slice(0, 500) || "Unknown error" });
    await updateTrainingLabSession(sessionId, {
      labStatus: "failed",
      phase: "failed",
      errorMessage: e.message?.slice(0, 1e3),
      completedAt: Date.now(),
      assetsJson: state.assets,
      findingsJson: state.assets[0]?.vulns || [],
      statsJson: state.stats,
      scanLogJson: state.log
    }).catch(() => {
    });
  }
}
var trainingLabRouter = router({
  /** List available training targets */
  targets: publicProcedure.query(() => {
    return TRAINING_TARGETS.filter((t) => t.id !== "custom");
  }),
  /** Start a new training lab scan session */
  startSession: protectedProcedure.input(z.object({
    targetId: z.string().optional(),
    customUrl: z.string().optional(),
    name: z.string().optional(),
    scanProfile: z.enum(["quick", "standard", "deep"]).default("standard")
  })).mutation(async ({ input, ctx }) => {
    const sessionId = `lab-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`;
    let targetUrl;
    let targetPreset;
    let sessionName;
    if (input.targetId && input.targetId !== "custom") {
      const target = TRAINING_TARGETS.find((t) => t.id === input.targetId);
      if (!target) throw new TRPCError({ code: "NOT_FOUND", message: "Training target not found" });
      const { enforceTrainingRoE, recordScanLaunch } = await import("./training-roe-guard-32FKNDU7.js");
      const roeCheck = enforceTrainingRoE(target, {
        targetId: target.id,
        scanProfile: input.scanProfile
      });
      if (!roeCheck.allowed) {
        const violationMessages = roeCheck.violations.map((v) => v.message).join(" | ");
        throw new TRPCError({
          code: "PRECONDITION_FAILED",
          message: `[ROE VIOLATION] Scan blocked for ${target.name}: ${violationMessages}`
        });
      }
      recordScanLaunch(target.id);
      targetUrl = target.liveInstanceUrl || target.url;
      targetPreset = target.id;
      sessionName = input.name || `${target.name} - ${(/* @__PURE__ */ new Date()).toLocaleDateString()}`;
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
    const { createTrainingLabSession } = await import("./db-FQGKASI3.js");
    await createTrainingLabSession({
      sessionId,
      name: sessionName,
      targetUrl,
      targetPreset,
      scanProfile: input.scanProfile,
      labStatus: "queued",
      phase: "idle",
      progress: 0,
      operatorId: ctx.user?.id ? Number(ctx.user.id) : void 0,
      operatorName: ctx.user?.name || "Unknown"
    });
    runLabScan(sessionId, targetUrl, input.scanProfile).catch((err) => {
      console.error(`[TrainingLab] Session ${sessionId} failed:`, err.message);
    });
    return { sessionId, name: sessionName, targetUrl };
  }),
  /** Pre-check RoE for a target before launching a scan */
  checkRoE: publicProcedure.input(z.object({
    targetId: z.string(),
    scanProfile: z.enum(["quick", "standard", "deep"]).default("standard"),
    enableBruteForce: z.boolean().optional(),
    enableDoS: z.boolean().optional(),
    enableExfiltration: z.boolean().optional()
  })).query(async ({ input }) => {
    const target = TRAINING_TARGETS.find((t) => t.id === input.targetId);
    if (!target) throw new TRPCError({ code: "NOT_FOUND", message: "Training target not found" });
    const { enforceTrainingRoE } = await import("./training-roe-guard-32FKNDU7.js");
    return enforceTrainingRoE(target, {
      targetId: target.id,
      scanProfile: input.scanProfile,
      enableBruteForce: input.enableBruteForce,
      enableDoS: input.enableDoS,
      enableExfiltration: input.enableExfiltration
    });
  }),
  /** Get session status and results */
  getSession: publicProcedure.input(z.object({ sessionId: z.string() })).query(async ({ input }) => {
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
        owaspCoverage: null
      };
    }
    const { getTrainingLabSession } = await import("./db-FQGKASI3.js");
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
      log: session.scanLogJson || [],
      assets: session.assetsJson || [],
      stats: session.statsJson || {},
      llmAnalysis: session.llmAnalysisJson,
      owaspCoverage: session.owaspCoverageJson,
      startedAt: session.startedAt,
      completedAt: session.completedAt,
      durationMs: session.durationMs,
      errorMessage: session.errorMessage
    };
  }),
  /** List all training lab sessions */
  listSessions: publicProcedure.input(z.object({ limit: z.number().min(1).max(100).default(50) }).optional()).query(async ({ input }) => {
    const { listTrainingLabSessions } = await import("./db-FQGKASI3.js");
    const sessions = await listTrainingLabSessions(input?.limit || 50);
    return sessions.map((s) => ({
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
      createdAt: s.createdAt
    }));
  }),
  /** Re-run LLM analysis on an existing session */
  rerunAnalysis: protectedProcedure.input(z.object({ sessionId: z.string() })).mutation(async ({ input }) => {
    const { getTrainingLabSession, updateTrainingLabSession } = await import("./db-FQGKASI3.js");
    const session = await getTrainingLabSession(input.sessionId);
    if (!session) throw new TRPCError({ code: "NOT_FOUND", message: "Session not found" });
    if (session.labStatus !== "completed" && session.labStatus !== "failed") {
      throw new TRPCError({ code: "BAD_REQUEST", message: "Session must be completed or failed to re-run analysis" });
    }
    const assets = session.assetsJson || [];
    if (assets.length === 0) throw new TRPCError({ code: "BAD_REQUEST", message: "No scan data available for analysis" });
    await updateTrainingLabSession(input.sessionId, { labStatus: "analyzing", phase: "analyzing" });
    (async () => {
      try {
        const { invokeLLM } = await import("./llm-IHYY5FA6.js");
        const { buildLearningContext, scoreAgainstGroundTruth, saveAccuracyScore } = await import("./llm-self-learning-H3OKCPQI.js");
        const asset = assets[0];
        const targetPresetForLearning = session.targetPreset || "custom";
        let learningContext = "";
        try {
          learningContext = await buildLearningContext(targetPresetForLearning);
        } catch {
        }
        const findingsSummary = (asset.vulns || []).map(
          (v) => `[${(v.severity || "info").toUpperCase()}] ${v.title}${v.cve ? ` (${v.cve})` : ""}`
        ).join("\n");
        const toolOutputSummary = (asset.toolResults || []).map(
          (t) => `=== ${t.tool} (${t.findingCount} findings, ${t.durationMs}ms) ===
${t.outputPreview}`
        ).join("\n\n");
        const portsSummary = (asset.ports || []).map(
          (p) => `${p.port}/${p.service}${p.version ? ` (${p.version})` : ""}`
        ).join(", ");
        const { getTrainingLabFeedbackForSession } = await import("./db-FQGKASI3.js");
        const feedback = await getTrainingLabFeedbackForSession(input.sessionId);
        let feedbackContext = "";
        if (feedback.length > 0) {
          feedbackContext = `

OPERATOR FEEDBACK FROM PREVIOUS ANALYSIS:
${feedback.map(
            (f) => `Finding #${f.findingIndex}: ${f.feedbackType}${f.operatorNotes ? ` \u2014 ${f.operatorNotes}` : ""}${f.expectedSeverity ? ` (expected severity: ${f.expectedSeverity})` : ""}`
          ).join("\n")}

Please incorporate this feedback to improve your analysis accuracy.`;
        }
        const result = await invokeLLM({
          _caller: "training-lab.portsSummary",
          messages: [
            { role: "system", content: "You are an expert penetration tester providing detailed vulnerability analysis. Always respond with valid JSON." },
            { role: "user", content: `Analyze the following scan results from a training lab session.

TARGET: ${asset.hostname} (${session.targetUrl})
OPEN PORTS: ${portsSummary || "None detected"}

SCAN FINDINGS:
${findingsSummary || "No vulnerabilities detected by automated tools."}

RAW TOOL OUTPUT:
${toolOutputSummary.slice(0, 8e3)}${feedbackContext}
${learningContext}
For EACH finding, you MUST also select the optimal exploit method:
- "metasploit" if a reliable MSF module exists (provide full msfconsole commands)
- "exploitdb" if a public PoC exists on ExploitDB (provide searchsploit + execution commands)
- "custom" if it needs a tailored exploit (provide sqlmap/curl/python3/bash commands)
- "manual_verification" for misconfigurations (provide curl/grep verification commands)

Respond with a JSON object containing: executiveSummary, riskScore (1-10), riskRating, findings (array with title, severity, category, description, confidence, evidence, remediation, cve, cvss, exploitMethod object with method, reasoning, primaryTool, cliCommands array), attackChains, missedAreas, recommendations.` }
          ],
          response_format: { type: "json_schema", json_schema: { name: "security_analysis", strict: false, schema: { type: "object", properties: { executiveSummary: { type: "string" }, riskScore: { type: "integer" }, riskRating: { type: "string" }, findings: { type: "array", items: { type: "object", properties: { title: { type: "string" }, severity: { type: "string" }, category: { type: "string" }, cve: { type: "string" }, description: { type: "string" }, confidence: { type: "string" }, evidence: { type: "string" }, remediation: { type: "string" }, cvss: { type: "number" }, exploitMethod: { type: "object", properties: { method: { type: "string" }, reasoning: { type: "string" }, primaryTool: { type: "string" }, cliCommands: { type: "array", items: { type: "object", properties: { order: { type: "integer" }, tool: { type: "string" }, command: { type: "string" }, description: { type: "string" }, expectedOutput: { type: "string" } }, required: ["order", "tool", "command", "description"] } }, alternativeMethod: { type: "object", properties: { method: { type: "string" }, reasoning: { type: "string" } } }, preConditions: { type: "array", items: { type: "string" } }, expectedOutcome: { type: "string" }, opsecNotes: { type: "string" } }, required: ["method", "reasoning", "primaryTool", "cliCommands"] } }, required: ["title", "severity", "category", "description", "exploitMethod"] } }, attackChains: { type: "array", items: { type: "object", properties: { name: { type: "string" }, steps: { type: "array", items: { type: "string" } }, impact: { type: "string" }, likelihood: { type: "string" } }, required: ["name", "steps", "impact", "likelihood"] } }, missedAreas: { type: "array", items: { type: "string" } }, recommendations: { type: "array", items: { type: "string" } } }, required: ["executiveSummary", "riskScore", "riskRating", "findings", "attackChains", "missedAreas", "recommendations"] } } }
        });
        const content = result.choices?.[0]?.message?.content;
        let llmAnalysis = null;
        if (typeof content === "string") {
          try {
            llmAnalysis = JSON.parse(content);
          } catch {
            const jsonMatch = content.match(/```(?:json)?\s*([\s\S]*?)```/);
            if (jsonMatch) llmAnalysis = JSON.parse(jsonMatch[1]);
          }
        }
        if (llmAnalysis && targetPresetForLearning !== "custom") {
          try {
            const llmFindings = (llmAnalysis.findings || []).map((f) => ({
              title: f.title || "",
              severity: f.severity || "info",
              category: f.category || "",
              cve: f.cve || void 0
            }));
            const accuracyScore = scoreAgainstGroundTruth(targetPresetForLearning, llmFindings);
            if (accuracyScore) {
              await saveAccuracyScore(input.sessionId, targetPresetForLearning, accuracyScore);
              llmAnalysis.__accuracyScore = accuracyScore;
            }
          } catch {
          }
        }
        if (llmAnalysis && targetPresetForLearning !== "custom") {
          try {
            const { scoreExploitSelection } = await import("./exploit-selection-intelligence-HZRINSFL.js");
            const { getExploitMethodGroundTruth } = await import("./exploit-method-ground-truth-H6ARGIY7.js");
            const exploitGroundTruth = getExploitMethodGroundTruth(targetPresetForLearning);
            if (exploitGroundTruth && exploitGroundTruth.length > 0) {
              const llmFindingsWithExploit = (llmAnalysis.findings || []).map((f) => ({
                title: f.title || "",
                category: f.category || "",
                exploitMethod: f.exploitMethod || void 0
              }));
              const exploitScore = scoreExploitSelection(exploitGroundTruth, llmFindingsWithExploit);
              llmAnalysis.__exploitSelectionScore = exploitScore;
            }
          } catch {
          }
        }
        await updateTrainingLabSession(input.sessionId, {
          labStatus: "completed",
          phase: "completed",
          llmAnalysisJson: llmAnalysis
        });
      } catch (e) {
        await updateTrainingLabSession(input.sessionId, {
          labStatus: "completed",
          phase: "completed",
          llmAnalysisJson: { error: e.message, executiveSummary: "Re-analysis failed", riskScore: 0, riskRating: "unknown", findings: [], attackChains: [], missedAreas: [], recommendations: [] }
        });
      }
    })();
    return { success: true, message: "LLM re-analysis started" };
  }),
  /** Submit operator feedback on LLM findings — also stores learning entries for self-learning */
  submitFeedback: protectedProcedure.input(z.object({
    sessionId: z.string(),
    findingIndex: z.number(),
    feedbackType: z.enum(["correct", "incorrect", "partial", "missed_finding", "false_positive"]),
    operatorNotes: z.string().optional(),
    expectedSeverity: z.string().optional(),
    expectedCategory: z.string().optional(),
    findingTitle: z.string().optional(),
    llmSeverity: z.string().optional(),
    llmCategory: z.string().optional()
  })).mutation(async ({ input, ctx }) => {
    const { insertTrainingLabFeedbackEntry, getTrainingLabSession } = await import("./db-FQGKASI3.js");
    await insertTrainingLabFeedbackEntry({
      sessionId: input.sessionId,
      findingIndex: input.findingIndex,
      feedbackType: input.feedbackType,
      operatorNotes: input.operatorNotes,
      expectedSeverity: input.expectedSeverity,
      expectedCategory: input.expectedCategory,
      operatorId: ctx.user?.id ? Number(ctx.user.id) : void 0
    });
    try {
      const { storeLearningEntry } = await import("./llm-self-learning-H3OKCPQI.js");
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
          operatorId: ctx.user?.id ? Number(ctx.user.id) : void 0
        });
      }
    } catch (e) {
      console.error("[TrainingLab] Failed to store learning entry:", e.message);
    }
    return { success: true };
  }),
  /** Get feedback for a session */
  getFeedback: publicProcedure.input(z.object({ sessionId: z.string() })).query(async ({ input }) => {
    const { getTrainingLabFeedbackForSession } = await import("./db-FQGKASI3.js");
    return getTrainingLabFeedbackForSession(input.sessionId);
  }),
  /** Cancel a running session */
  cancelSession: protectedProcedure.input(z.object({ sessionId: z.string() })).mutation(async ({ input }) => {
    const liveState = labStates.get(input.sessionId);
    if (liveState) {
      liveState.isRunning = false;
      liveState.phase = "cancelled";
    }
    const { updateTrainingLabSession } = await import("./db-FQGKASI3.js");
    await updateTrainingLabSession(input.sessionId, {
      labStatus: "cancelled",
      phase: "cancelled",
      completedAt: Date.now()
    });
    return { success: true };
  }),
  // ─── Self-Learning Endpoints ─────────────────────────────────────────────
  /** Get learning stats dashboard data */
  learningStats: publicProcedure.query(async () => {
    const { getLearningStats } = await import("./llm-self-learning-H3OKCPQI.js");
    return getLearningStats();
  }),
  /** Get accuracy trend data for a target or all targets */
  accuracyTrend: publicProcedure.input(z.object({ targetPreset: z.string().optional(), limit: z.number().default(50) }).optional()).query(async ({ input }) => {
    const { getAccuracyTrend } = await import("./llm-self-learning-H3OKCPQI.js");
    return getAccuracyTrend(input?.targetPreset, input?.limit || 50);
  }),
  /** Get ground truth for a target */
  groundTruth: publicProcedure.input(z.object({ targetPreset: z.string() })).query(async ({ input }) => {
    const { GROUND_TRUTH_LIBRARY } = await import("./llm-self-learning-H3OKCPQI.js");
    return GROUND_TRUTH_LIBRARY[input.targetPreset] || [];
  }),
  /** Get all available ground truth targets */
  groundTruthTargets: publicProcedure.query(async () => {
    const { GROUND_TRUTH_LIBRARY } = await import("./llm-self-learning-H3OKCPQI.js");
    return Object.entries(GROUND_TRUTH_LIBRARY).map(([key, vulns]) => ({
      targetPreset: key,
      vulnCount: vulns.length,
      categories: [...new Set(vulns.map((v) => v.category))],
      severities: [...new Set(vulns.map((v) => v.severity))]
    }));
  }),
  /** Add a missed finding to the learning knowledge base */
  addMissedFinding: protectedProcedure.input(z.object({
    sessionId: z.string(),
    findingTitle: z.string(),
    severity: z.string(),
    category: z.string().optional(),
    description: z.string().optional()
  })).mutation(async ({ input, ctx }) => {
    const { storeLearningEntry } = await import("./llm-self-learning-H3OKCPQI.js");
    const { getTrainingLabSession } = await import("./db-FQGKASI3.js");
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
      operatorId: ctx.user?.id ? Number(ctx.user.id) : void 0
    });
    return { success: true };
  }),
  /** Get learning entries for a target */
  learningEntries: publicProcedure.input(z.object({ targetPreset: z.string() })).query(async ({ input }) => {
    const { getLearningEntries } = await import("./llm-self-learning-H3OKCPQI.js");
    return getLearningEntries(input.targetPreset);
  }),
  /** Get accuracy score for a specific session */
  sessionAccuracy: publicProcedure.input(z.object({ sessionId: z.string() })).query(async ({ input }) => {
    const mysql = await import("mysql2/promise");
    const conn = await mysql.createConnection(process.env.DATABASE_URL);
    try {
      const [rows] = await conn.execute(
        `SELECT * FROM llm_accuracy_scores WHERE session_id = ? ORDER BY scored_at DESC LIMIT 1`,
        [input.sessionId]
      );
      const r = rows[0];
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
        scoredAt: Number(r.scored_at)
      };
    } finally {
      await conn.end();
    }
  }),
  /** Log RoE acknowledgment before scan launch */
  acknowledgeRoE: protectedProcedure.input(z.object({
    targetId: z.string(),
    scanProfile: z.string()
  })).mutation(async ({ input, ctx }) => {
    const mysql = await import("mysql2/promise");
    const conn = await mysql.createConnection(process.env.DATABASE_URL);
    try {
      const target = TRAINING_TARGETS.find((t) => t.id === input.targetId);
      const targetName = target?.name || "Custom Target";
      const targetUrl = target?.url || "custom";
      const rulesAccepted = target?.roe ? {
        noBruteForce: target.roe.noBruteForce,
        noDoS: target.roe.noDoS,
        noExfiltration: target.roe.noExfiltration,
        requiresOwnInstance: target.roe.requiresOwnInstance,
        maxScansPerDay: target.roe.maxScansPerDay,
        prohibited: target.roe.prohibited,
        allowed: target.roe.allowed
      } : { customTarget: true, requiresAuthorization: true };
      const enforcedRules = [];
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
          input.scanProfile
        ]
      );
      return { success: true, enforcedRules };
    } finally {
      await conn.end();
    }
  }),
  /** Get RoE acknowledgment audit log */
  roeAuditLog: protectedProcedure.input(z.object({
    limit: z.number().min(1).max(100).default(50),
    targetId: z.string().optional()
  })).query(async ({ input }) => {
    const mysql = await import("mysql2/promise");
    const conn = await mysql.createConnection(process.env.DATABASE_URL);
    try {
      let query = `SELECT * FROM roe_acknowledgments ORDER BY acknowledged_at DESC LIMIT ${Number(input.limit)}`;
      let params = [];
      if (input.targetId) {
        query = `SELECT * FROM roe_acknowledgments WHERE target_id = ? ORDER BY acknowledged_at DESC LIMIT ${Number(input.limit)}`;
        params = [input.targetId];
      }
      const [rows] = await conn.execute(query, params);
      return rows.map((r) => ({
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
        acknowledgedAt: r.acknowledged_at
      }));
    } finally {
      await conn.end();
    }
  }),
  // ─── Continuous Training Loop Endpoints ─────────────────────────────────
  /** Start a continuous training loop on an existing completed session */
  startContinuousTraining: protectedProcedure.input(z.object({
    sessionId: z.string(),
    maxIterations: z.number().min(1).max(50).default(10),
    targetF1: z.number().min(0).max(1).default(1),
    targetRecall: z.number().min(0).max(1).default(1),
    targetPrecision: z.number().min(0).max(1).default(0.9)
  })).mutation(async ({ input }) => {
    const { getTrainingLabSession, updateTrainingLabSession } = await import("./db-FQGKASI3.js");
    const session = await getTrainingLabSession(input.sessionId);
    if (!session) throw new TRPCError({ code: "NOT_FOUND", message: "Session not found" });
    if (session.labStatus !== "completed" && session.labStatus !== "failed") {
      throw new TRPCError({ code: "BAD_REQUEST", message: "Session must be completed to start continuous training" });
    }
    const assets = session.assetsJson || [];
    if (assets.length === 0) throw new TRPCError({ code: "BAD_REQUEST", message: "No scan data available" });
    const { getActiveLoop, runContinuousTrainingLoop } = await import("./continuous-training-L7AXOORJ.js");
    if (getActiveLoop(input.sessionId)?.isRunning) {
      throw new TRPCError({ code: "CONFLICT", message: "Continuous training already running for this session" });
    }
    const targetPreset = session.targetPreset || "custom";
    if (targetPreset === "custom") {
      throw new TRPCError({ code: "BAD_REQUEST", message: "Continuous training requires a known target with ground truth" });
    }
    const config = {
      sessionId: input.sessionId,
      targetPreset,
      targetUrl: session.targetUrl,
      maxIterations: input.maxIterations,
      targetF1: input.targetF1,
      targetRecall: input.targetRecall,
      targetPrecision: input.targetPrecision,
      delayBetweenIterations: 2e3
    };
    runContinuousTrainingLoop(config, assets, async (iteration) => {
      try {
        const { eventHub } = await import("./ws-event-hub-GYTLNKYI.js");
        eventHub.broadcast({
          type: "continuous_training:progress",
          sessionId: input.sessionId,
          timestamp: Date.now(),
          data: iteration
        });
      } catch {
      }
    }).then(async (result) => {
      try {
        await updateTrainingLabSession(input.sessionId, {
          llmAnalysisJson: {
            ...session.llmAnalysisJson || {},
            __continuousTraining: result
          }
        });
        const { eventHub } = await import("./ws-event-hub-GYTLNKYI.js");
        eventHub.broadcast({
          type: "continuous_training:complete",
          sessionId: input.sessionId,
          timestamp: Date.now(),
          data: result
        });
      } catch (e) {
        console.error("[ContinuousTraining] Failed to save result:", e.message);
      }
    }).catch((err) => {
      console.error("[ContinuousTraining] Loop failed:", err.message);
    });
    return { success: true, message: `Continuous training started (max ${input.maxIterations} iterations, target F1=${(input.targetF1 * 100).toFixed(0)}%)` };
  }),
  /** Cancel a running continuous training loop */
  cancelContinuousTraining: protectedProcedure.input(z.object({ sessionId: z.string() })).mutation(async ({ input }) => {
    const { cancelLoop, getActiveLoop } = await import("./continuous-training-L7AXOORJ.js");
    const loop = getActiveLoop(input.sessionId);
    if (!loop || !loop.isRunning) {
      throw new TRPCError({ code: "NOT_FOUND", message: "No active continuous training loop for this session" });
    }
    cancelLoop(input.sessionId);
    return { success: true, message: "Continuous training cancelled" };
  }),
  /** Get continuous training loop status */
  continuousTrainingStatus: publicProcedure.input(z.object({ sessionId: z.string() })).query(async ({ input }) => {
    const { getActiveLoop } = await import("./continuous-training-L7AXOORJ.js");
    const loop = getActiveLoop(input.sessionId);
    if (!loop) {
      const { getTrainingLabSession } = await import("./db-FQGKASI3.js");
      const session = await getTrainingLabSession(input.sessionId);
      const saved = session?.llmAnalysisJson?.__continuousTraining;
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
      latestF1: loop.iterations.length > 0 ? loop.iterations[loop.iterations.length - 1].f1Score : 0,
      latestRecall: loop.iterations.length > 0 ? loop.iterations[loop.iterations.length - 1].recall : 0,
      latestPrecision: loop.iterations.length > 0 ? loop.iterations[loop.iterations.length - 1].precision : 0
    };
  }),
  /** List all active continuous training loops */
  activeContinuousTraining: publicProcedure.query(async () => {
    const { listActiveLoops } = await import("./continuous-training-L7AXOORJ.js");
    return listActiveLoops();
  }),
  // ─── ExploitDB Integration ──────────────────────────────────────────────────
  /** Search ExploitDB for exploits by keyword, CVE, or service */
  searchExploitDB: protectedProcedure.input(z.object({
    query: z.string().min(2).max(200),
    type: z.enum(["dos", "local", "remote", "webapps", "shellcode", "papers"]).optional(),
    platform: z.string().optional(),
    verifiedOnly: z.boolean().optional(),
    excludeMetasploit: z.boolean().optional(),
    port: z.number().optional(),
    limit: z.number().min(1).max(50).optional()
  })).mutation(async ({ input }) => {
    const { searchExploitDB } = await import("./exploitdb-connector-WCBR6NNJ.js");
    return searchExploitDB(input.query, {
      type: input.type,
      platform: input.platform,
      verifiedOnly: input.verifiedOnly,
      excludeMetasploit: input.excludeMetasploit,
      port: input.port,
      limit: input.limit || 20
    });
  }),
  /** Download exploit code from ExploitDB by ID */
  downloadExploit: protectedProcedure.input(z.object({ edbId: z.number() })).mutation(async ({ input }) => {
    const { downloadExploitById } = await import("./exploitdb-connector-WCBR6NNJ.js");
    const code = await downloadExploitById(input.edbId);
    if (!code) throw new TRPCError({ code: "NOT_FOUND", message: `Exploit EDB-${input.edbId} not found in index` });
    return code;
  }),
  /** Find ExploitDB exploits for a specific vulnerability */
  findExploitsForVuln: protectedProcedure.input(z.object({
    vulnTitle: z.string(),
    cve: z.string().optional(),
    service: z.string().optional(),
    platform: z.string().optional()
  })).mutation(async ({ input }) => {
    const { findExploitsForVuln } = await import("./exploitdb-connector-WCBR6NNJ.js");
    return findExploitsForVuln(input.vulnTitle, input.cve, input.service, input.platform);
  }),
  /** Get ExploitDB index stats (cache age, total exploits, etc.) */
  exploitDBStats: publicProcedure.query(async () => {
    const { getIndexStats } = await import("./exploitdb-connector-WCBR6NNJ.js");
    return getIndexStats();
  }),
  // ─── Regression Test Pipeline ──────────────────────────────────────────────
  /** Run health checks on all self-hosted training labs */
  labHealthCheck: protectedProcedure.query(async () => {
    const scanHost = process.env.SCAN_SERVER_HOST || "scan.aceofcloud.io";
    const selfHostedLabs = TRAINING_TARGETS.filter((t) => t.liveInstanceUrl);
    const results = await Promise.allSettled(
      selfHostedLabs.map(async (lab) => {
        const start = Date.now();
        try {
          const controller = new AbortController();
          const timeout = setTimeout(() => controller.abort(), 1e4);
          const res = await fetch(lab.liveInstanceUrl, {
            signal: controller.signal,
            redirect: "manual"
          });
          clearTimeout(timeout);
          const latencyMs = Date.now() - start;
          return {
            id: lab.id,
            name: lab.name,
            url: lab.liveInstanceUrl,
            status: "up",
            httpStatus: res.status,
            latencyMs,
            checkedAt: Date.now()
          };
        } catch (e) {
          return {
            id: lab.id,
            name: lab.name,
            url: lab.liveInstanceUrl,
            status: "down",
            httpStatus: 0,
            latencyMs: Date.now() - start,
            error: e.message,
            checkedAt: Date.now()
          };
        }
      })
    );
    const labResults = results.map(
      (r) => r.status === "fulfilled" ? r.value : { id: "unknown", name: "unknown", url: "", status: "error", httpStatus: 0, latencyMs: 0, error: String(r.reason), checkedAt: Date.now() }
    );
    let apiHealth = { status: "unknown", uptime: 0 };
    try {
      const res = await fetch(`https://${scanHost}/health`, { signal: AbortSignal.timeout(5e3) });
      if (res.ok) {
        const data = await res.json();
        apiHealth = { status: data.status || "ok", uptime: data.uptime || 0 };
      }
    } catch {
      apiHealth.status = "unreachable";
    }
    return {
      scanServer: {
        host: scanHost,
        apiHealth
      },
      labs: labResults,
      summary: {
        total: labResults.length,
        up: labResults.filter((l) => l.status === "up").length,
        down: labResults.filter((l) => l.status === "down").length,
        avgLatencyMs: Math.round(
          labResults.filter((l) => l.status === "up").reduce((s, l) => s + l.latencyMs, 0) / Math.max(1, labResults.filter((l) => l.status === "up").length)
        ),
        checkedAt: Date.now()
      }
    };
  }),
  /** Run a quick regression test against a specific lab (HTTP probe + basic vuln check) */
  labRegressionTest: protectedProcedure.input(z.object({
    labId: z.string(),
    checks: z.array(z.enum(["http_probe", "login_test", "sqli_canary", "xss_canary", "api_endpoint"])).optional()
  })).mutation(async ({ input }) => {
    const lab = TRAINING_TARGETS.find((t) => t.id === input.labId);
    if (!lab || !lab.liveInstanceUrl) {
      throw new TRPCError({ code: "NOT_FOUND", message: `Lab ${input.labId} not found or has no live instance` });
    }
    const checks = input.checks || ["http_probe"];
    const results = [];
    for (const check of checks) {
      const start = Date.now();
      try {
        switch (check) {
          case "http_probe": {
            const res = await fetch(lab.liveInstanceUrl, { redirect: "manual", signal: AbortSignal.timeout(1e4) });
            results.push({
              check,
              passed: res.status >= 200 && res.status < 400,
              detail: `HTTP ${res.status}`,
              durationMs: Date.now() - start
            });
            break;
          }
          case "api_endpoint": {
            const apiPaths = {
              vampi: "/",
              crapi: "/api/v1/user/login",
              dvga: "/graphql"
            };
            const path = apiPaths[lab.id] || "/";
            const url = lab.liveInstanceUrl.replace(/\/$/, "") + path;
            const res = await fetch(url, {
              method: lab.id === "dvga" ? "POST" : "GET",
              headers: lab.id === "dvga" ? { "Content-Type": "application/json" } : {},
              body: lab.id === "dvga" ? JSON.stringify({ query: "{ __typename }" }) : void 0,
              signal: AbortSignal.timeout(1e4)
            });
            results.push({
              check,
              passed: res.status < 500,
              detail: `API ${path} \u2192 HTTP ${res.status}`,
              durationMs: Date.now() - start
            });
            break;
          }
          case "sqli_canary": {
            const testUrl = lab.liveInstanceUrl.replace(/\/$/, "") + "/?id=1'";
            const res = await fetch(testUrl, { signal: AbortSignal.timeout(1e4) });
            const body = await res.text();
            const hasSqlError = /sql|syntax|mysql|postgres|sqlite|oracle|error in your/i.test(body);
            results.push({
              check,
              passed: true,
              detail: hasSqlError ? "SQL error detected in response (vulnerable)" : "No SQL error in response",
              durationMs: Date.now() - start
            });
            break;
          }
          case "xss_canary": {
            const testUrl = lab.liveInstanceUrl.replace(/\/$/, "") + "/?q=<script>alert(1)</script>";
            const res = await fetch(testUrl, { signal: AbortSignal.timeout(1e4) });
            const body = await res.text();
            const hasReflection = body.includes("<script>alert(1)</script>");
            results.push({
              check,
              passed: true,
              detail: hasReflection ? "XSS payload reflected (vulnerable)" : "XSS payload not reflected",
              durationMs: Date.now() - start
            });
            break;
          }
          default:
            results.push({ check, passed: false, detail: "Unknown check type", durationMs: 0 });
        }
      } catch (e) {
        results.push({
          check,
          passed: false,
          detail: `Error: ${e.message}`,
          durationMs: Date.now() - start
        });
      }
    }
    return {
      labId: lab.id,
      labName: lab.name,
      url: lab.liveInstanceUrl,
      checks: results,
      allPassed: results.every((r) => r.passed),
      testedAt: Date.now()
    };
  }),
  /** Run full regression suite across all self-hosted labs */
  labRegressionSuite: protectedProcedure.input(z.object({
    includeVulnCanaries: z.boolean().optional()
  })).mutation(async ({ input }) => {
    const selfHostedLabs = TRAINING_TARGETS.filter((t) => t.liveInstanceUrl);
    const suiteResults = await Promise.allSettled(
      selfHostedLabs.map(async (lab) => {
        const labChecks = ["http_probe"];
        if (["vampi", "crapi", "dvga"].includes(lab.id)) {
          labChecks.push("api_endpoint");
        }
        const results = [];
        for (const check of labChecks) {
          const start = Date.now();
          try {
            if (check === "http_probe") {
              const res = await fetch(lab.liveInstanceUrl, { redirect: "manual", signal: AbortSignal.timeout(1e4) });
              results.push({
                check,
                passed: res.status >= 200 && res.status < 400,
                detail: `HTTP ${res.status}`,
                durationMs: Date.now() - start
              });
            } else if (check === "api_endpoint") {
              const apiPaths = { vampi: "/", crapi: "/api/v1/user/login", dvga: "/graphql" };
              const path = apiPaths[lab.id] || "/";
              const url = lab.liveInstanceUrl.replace(/\/$/, "") + path;
              const res = await fetch(url, {
                method: lab.id === "dvga" ? "POST" : "GET",
                headers: lab.id === "dvga" ? { "Content-Type": "application/json" } : {},
                body: lab.id === "dvga" ? JSON.stringify({ query: "{ __typename }" }) : void 0,
                signal: AbortSignal.timeout(1e4)
              });
              results.push({
                check,
                passed: res.status < 500,
                detail: `API ${path} \u2192 HTTP ${res.status}`,
                durationMs: Date.now() - start
              });
            }
          } catch (e) {
            results.push({ check, passed: false, detail: `Error: ${e.message}`, durationMs: Date.now() - start });
          }
        }
        return {
          labId: lab.id,
          labName: lab.name,
          url: lab.liveInstanceUrl,
          checks: results,
          allPassed: results.every((r) => r.passed)
        };
      })
    );
    const labResults = suiteResults.map(
      (r, i) => r.status === "fulfilled" ? r.value : { labId: selfHostedLabs[i].id, labName: selfHostedLabs[i].name, url: selfHostedLabs[i].liveInstanceUrl, checks: [], allPassed: false, error: String(r.reason) }
    );
    return {
      results: labResults,
      summary: {
        total: labResults.length,
        passed: labResults.filter((l) => l.allPassed).length,
        failed: labResults.filter((l) => !l.allPassed).length,
        testedAt: Date.now()
      }
    };
  })
});

export {
  TRAINING_TARGETS,
  trainingLabRouter
};
