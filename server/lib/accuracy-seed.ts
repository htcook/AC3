/**
 * Accuracy Seed Module
 * ────────────────────
 * Seeds the accuracy feedback loop with real comparison data by scoring
 * simulated scan findings against the DO learning engine's ground truth.
 *
 * Each "scan wave" represents a different maturity level of the scanner,
 * showing improvement over time as the LLM learns from previous results.
 */

import { runAccuracyComparison } from "./accuracy-feedback-loop";
import { v4 as uuidv4 } from "crypto";

const LOG = "[AccuracySeed]";

// ─── Simulated Findings per Target ─────────────────────────────────────────
// These represent realistic scan findings at different maturity levels.
// Wave 1 = basic scanner, Wave 2 = improved, Wave 3 = advanced

interface SimulatedFinding {
  name: string;
  severity: string;
  cwe?: string;
  owasp?: string;
  endpoint?: string;
  confidence?: number;
}

interface TargetWave {
  targetPreset: string;
  targetUrl?: string;
  waves: SimulatedFinding[][];
}

function generateSessionId(): string {
  const hex = Array.from(crypto.getRandomValues(new Uint8Array(16)))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
  return `seed-${hex.slice(0, 12)}`;
}

const TARGET_WAVES: TargetWave[] = [
  {
    targetPreset: "dvwa",
    targetUrl: "https://scan.aceofcloud.io/dvwa",
    waves: [
      // Wave 1: Basic scanner - catches obvious vulns
      [
        { name: "SQL Injection", severity: "Critical", cwe: "CWE-89", endpoint: "/vulnerabilities/sqli/" },
        { name: "XSS - Reflected", severity: "High", cwe: "CWE-79", endpoint: "/vulnerabilities/xss_r/" },
        { name: "Command Injection", severity: "Critical", cwe: "CWE-78", endpoint: "/vulnerabilities/exec/" },
        { name: "Missing HTTPS", severity: "Low", confidence: 0.5 }, // false positive
      ],
      // Wave 2: Improved - catches more vulns, fewer FPs
      [
        { name: "SQL Injection", severity: "Critical", cwe: "CWE-89", endpoint: "/vulnerabilities/sqli/" },
        { name: "SQL Injection - Blind", severity: "High", cwe: "CWE-89", endpoint: "/vulnerabilities/sqli_blind/" },
        { name: "XSS - Reflected", severity: "High", cwe: "CWE-79", endpoint: "/vulnerabilities/xss_r/" },
        { name: "XSS - Stored", severity: "High", cwe: "CWE-79", endpoint: "/vulnerabilities/xss_s/" },
        { name: "XSS - DOM Based", severity: "High", cwe: "CWE-79", endpoint: "/vulnerabilities/xss_d/" },
        { name: "Command Injection", severity: "Critical", cwe: "CWE-78", endpoint: "/vulnerabilities/exec/" },
        { name: "File Inclusion", severity: "High", cwe: "CWE-98", endpoint: "/vulnerabilities/fi/" },
        { name: "File Upload", severity: "High", cwe: "CWE-434", endpoint: "/vulnerabilities/upload/" },
      ],
      // Wave 3: Advanced - catches most vulns
      [
        { name: "SQL Injection", severity: "Critical", cwe: "CWE-89", endpoint: "/vulnerabilities/sqli/" },
        { name: "SQL Injection - Blind", severity: "High", cwe: "CWE-89", endpoint: "/vulnerabilities/sqli_blind/" },
        { name: "XSS - Reflected", severity: "High", cwe: "CWE-79", endpoint: "/vulnerabilities/xss_r/" },
        { name: "XSS - Stored", severity: "High", cwe: "CWE-79", endpoint: "/vulnerabilities/xss_s/" },
        { name: "XSS - DOM Based", severity: "High", cwe: "CWE-79", endpoint: "/vulnerabilities/xss_d/" },
        { name: "Command Injection", severity: "Critical", cwe: "CWE-78", endpoint: "/vulnerabilities/exec/" },
        { name: "File Inclusion", severity: "High", cwe: "CWE-98", endpoint: "/vulnerabilities/fi/" },
        { name: "File Upload", severity: "High", cwe: "CWE-434", endpoint: "/vulnerabilities/upload/" },
        { name: "CSRF", severity: "Medium", cwe: "CWE-352", endpoint: "/vulnerabilities/csrf/" },
        { name: "Brute Force", severity: "Medium", cwe: "CWE-307", endpoint: "/vulnerabilities/brute/" },
        { name: "Insecure CAPTCHA", severity: "Medium", cwe: "CWE-330", endpoint: "/vulnerabilities/captcha/" },
        { name: "Weak Session IDs", severity: "Medium", cwe: "CWE-330", endpoint: "/vulnerabilities/weak_id/" },
      ],
    ],
  },
  {
    targetPreset: "juice-shop",
    targetUrl: "https://scan.aceofcloud.io/juice-shop",
    waves: [
      // Wave 1: Basic
      [
        { name: "SQL Injection", severity: "Critical", cwe: "CWE-89", endpoint: "/rest/products/search" },
        { name: "XSS - DOM Based", severity: "High", cwe: "CWE-79", endpoint: "/search" },
        { name: "Broken Authentication", severity: "High", cwe: "CWE-287", endpoint: "/rest/user/login" },
        { name: "Information Disclosure", severity: "Low", endpoint: "/ftp" },
        { name: "Outdated jQuery", severity: "Low", confidence: 0.3 }, // FP
      ],
      // Wave 2: Improved
      [
        { name: "SQL Injection", severity: "Critical", cwe: "CWE-89", endpoint: "/rest/products/search" },
        { name: "XSS - DOM Based", severity: "High", cwe: "CWE-79", endpoint: "/search" },
        { name: "XSS - Reflected", severity: "High", cwe: "CWE-79", endpoint: "/track-result" },
        { name: "Broken Authentication", severity: "High", cwe: "CWE-287", endpoint: "/rest/user/login" },
        { name: "Broken Access Control", severity: "High", cwe: "CWE-639", endpoint: "/rest/basket" },
        { name: "Information Disclosure", severity: "Low", endpoint: "/ftp" },
        { name: "Sensitive Data Exposure", severity: "Medium", endpoint: "/api-docs" },
        { name: "Security Misconfiguration", severity: "Medium", endpoint: "/metrics" },
        { name: "IDOR", severity: "High", cwe: "CWE-639", endpoint: "/rest/basket/1" },
        { name: "Directory Traversal", severity: "High", cwe: "CWE-22", endpoint: "/ftp" },
      ],
      // Wave 3: Advanced
      [
        { name: "SQL Injection", severity: "Critical", cwe: "CWE-89", endpoint: "/rest/products/search" },
        { name: "NoSQL Injection", severity: "Critical", cwe: "CWE-943", endpoint: "/rest/products/reviews" },
        { name: "XSS - DOM Based", severity: "High", cwe: "CWE-79", endpoint: "/search" },
        { name: "XSS - Reflected", severity: "High", cwe: "CWE-79", endpoint: "/track-result" },
        { name: "Broken Authentication", severity: "High", cwe: "CWE-287", endpoint: "/rest/user/login" },
        { name: "Broken Access Control", severity: "High", cwe: "CWE-639", endpoint: "/rest/basket" },
        { name: "IDOR", severity: "High", cwe: "CWE-639", endpoint: "/rest/basket/1" },
        { name: "Information Disclosure", severity: "Low", endpoint: "/ftp" },
        { name: "Sensitive Data Exposure", severity: "Medium", endpoint: "/api-docs" },
        { name: "Security Misconfiguration", severity: "Medium", endpoint: "/metrics" },
        { name: "Directory Traversal", severity: "High", cwe: "CWE-22", endpoint: "/ftp" },
        { name: "SSRF", severity: "High", cwe: "CWE-918", endpoint: "/profile/image/url" },
        { name: "XXE", severity: "High", cwe: "CWE-611", endpoint: "/file-upload" },
        { name: "Prototype Pollution", severity: "Medium", cwe: "CWE-1321", endpoint: "/api/Users" },
        { name: "JWT Vulnerability", severity: "High", cwe: "CWE-347", endpoint: "/rest/user/login" },
      ],
    ],
  },
  {
    targetPreset: "bwapp",
    targetUrl: "https://scan.aceofcloud.io/bwapp",
    waves: [
      // Wave 1: Basic
      [
        { name: "SQL Injection", severity: "Critical", cwe: "CWE-89", endpoint: "/sqli_1.php" },
        { name: "Cross-Site Scripting", severity: "High", cwe: "CWE-79", endpoint: "/xss_get.php" },
        { name: "OS Command Injection", severity: "Critical", cwe: "CWE-78", endpoint: "/commandi.php" },
      ],
      // Wave 2: Improved
      [
        { name: "SQL Injection", severity: "Critical", cwe: "CWE-89", endpoint: "/sqli_1.php" },
        { name: "SQL Injection - Blind", severity: "High", cwe: "CWE-89", endpoint: "/sqli_blind.php" },
        { name: "Cross-Site Scripting", severity: "High", cwe: "CWE-79", endpoint: "/xss_get.php" },
        { name: "XSS - Stored", severity: "High", cwe: "CWE-79", endpoint: "/xss_stored_1.php" },
        { name: "OS Command Injection", severity: "Critical", cwe: "CWE-78", endpoint: "/commandi.php" },
        { name: "PHP Code Injection", severity: "Critical", cwe: "CWE-94", endpoint: "/phpi.php" },
        { name: "HTML Injection - Reflected", severity: "Medium", cwe: "CWE-79", endpoint: "/htmli_get.php" },
        { name: "Server-Side Includes Injection", severity: "High", cwe: "CWE-97", endpoint: "/ssii.php" },
        { name: "XML/XPath Injection", severity: "High", cwe: "CWE-643", endpoint: "/xmli_1.php" },
        { name: "File Inclusion", severity: "High", cwe: "CWE-98", endpoint: "/rlfi.php" },
      ],
      // Wave 3: Advanced
      [
        { name: "SQL Injection", severity: "Critical", cwe: "CWE-89", endpoint: "/sqli_1.php" },
        { name: "SQL Injection - Blind", severity: "High", cwe: "CWE-89", endpoint: "/sqli_blind.php" },
        { name: "SQL Injection - Stored", severity: "High", cwe: "CWE-89", endpoint: "/sqli_blog.php" },
        { name: "Cross-Site Scripting", severity: "High", cwe: "CWE-79", endpoint: "/xss_get.php" },
        { name: "XSS - Stored", severity: "High", cwe: "CWE-79", endpoint: "/xss_stored_1.php" },
        { name: "XSS - Reflected (POST)", severity: "High", cwe: "CWE-79", endpoint: "/xss_post.php" },
        { name: "OS Command Injection", severity: "Critical", cwe: "CWE-78", endpoint: "/commandi.php" },
        { name: "OS Command Injection - Blind", severity: "High", cwe: "CWE-78", endpoint: "/commandi_blind.php" },
        { name: "PHP Code Injection", severity: "Critical", cwe: "CWE-94", endpoint: "/phpi.php" },
        { name: "Server-Side Includes Injection", severity: "High", cwe: "CWE-97", endpoint: "/ssii.php" },
        { name: "HTML Injection - Reflected", severity: "Medium", cwe: "CWE-79", endpoint: "/htmli_get.php" },
        { name: "HTML Injection - Stored", severity: "Medium", cwe: "CWE-79", endpoint: "/htmli_stored.php" },
        { name: "iFrame Injection", severity: "Medium", cwe: "CWE-79", endpoint: "/iframei.php" },
        { name: "XML/XPath Injection", severity: "High", cwe: "CWE-643", endpoint: "/xmli_1.php" },
        { name: "LDAP Injection", severity: "High", cwe: "CWE-90", endpoint: "/ldapi.php" },
        { name: "File Inclusion", severity: "High", cwe: "CWE-98", endpoint: "/rlfi.php" },
        { name: "Directory Traversal", severity: "High", cwe: "CWE-22", endpoint: "/directory_traversal_1.php" },
        { name: "SSRF", severity: "High", cwe: "CWE-918", endpoint: "/ssrf.php" },
        { name: "XXE", severity: "High", cwe: "CWE-611", endpoint: "/xxe-1.php" },
        { name: "CSRF", severity: "Medium", cwe: "CWE-352", endpoint: "/csrf_1.php" },
        { name: "Unrestricted File Upload", severity: "High", cwe: "CWE-434", endpoint: "/unrestricted_file_upload.php" },
        { name: "Shellshock", severity: "Critical", cwe: "CWE-78", endpoint: "/cgi-bin/shellshock.sh" },
      ],
    ],
  },
  {
    targetPreset: "crapi",
    targetUrl: "https://scan.aceofcloud.io/crapi",
    waves: [
      // Wave 1: Basic
      [
        { name: "Broken Authentication", severity: "High", cwe: "CWE-287", endpoint: "/identity/api/auth/login" },
        { name: "BOLA/IDOR", severity: "Critical", cwe: "CWE-639", endpoint: "/identity/api/v2/user/dashboard" },
      ],
      // Wave 2: Improved
      [
        { name: "Broken Authentication", severity: "High", cwe: "CWE-287", endpoint: "/identity/api/auth/login" },
        { name: "BOLA/IDOR", severity: "Critical", cwe: "CWE-639", endpoint: "/identity/api/v2/user/dashboard" },
        { name: "Mass Assignment", severity: "High", cwe: "CWE-915", endpoint: "/identity/api/v2/user/videos" },
        { name: "SSRF", severity: "High", cwe: "CWE-918", endpoint: "/identity/api/v2/user/videos" },
        { name: "Excessive Data Exposure", severity: "Medium", cwe: "CWE-200", endpoint: "/community/api/v2/community/posts" },
        { name: "SQL Injection", severity: "Critical", cwe: "CWE-89", endpoint: "/community/api/v2/coupon/validate-coupon" },
      ],
      // Wave 3: Advanced
      [
        { name: "Broken Authentication", severity: "High", cwe: "CWE-287", endpoint: "/identity/api/auth/login" },
        { name: "BOLA/IDOR", severity: "Critical", cwe: "CWE-639", endpoint: "/identity/api/v2/user/dashboard" },
        { name: "Mass Assignment", severity: "High", cwe: "CWE-915", endpoint: "/identity/api/v2/user/videos" },
        { name: "SSRF", severity: "High", cwe: "CWE-918", endpoint: "/identity/api/v2/user/videos" },
        { name: "Excessive Data Exposure", severity: "Medium", cwe: "CWE-200", endpoint: "/community/api/v2/community/posts" },
        { name: "SQL Injection", severity: "Critical", cwe: "CWE-89", endpoint: "/community/api/v2/coupon/validate-coupon" },
        { name: "NoSQL Injection", severity: "Critical", cwe: "CWE-943", endpoint: "/community/api/v2/coupon/validate-coupon" },
        { name: "Broken Object Level Authorization", severity: "High", cwe: "CWE-639", endpoint: "/workshop/api/mechanic" },
        { name: "JWT Token Manipulation", severity: "High", cwe: "CWE-347", endpoint: "/identity/api/auth/login" },
        { name: "Rate Limiting Bypass", severity: "Medium", cwe: "CWE-770", endpoint: "/identity/api/auth/login" },
        { name: "Broken Function Level Authorization", severity: "High", cwe: "CWE-285", endpoint: "/workshop/api/shop/orders" },
      ],
    ],
  },
  {
    targetPreset: "mutillidae",
    targetUrl: "https://scan.aceofcloud.io/mutillidae",
    waves: [
      // Wave 1: Basic
      [
        { name: "SQL Injection", severity: "Critical", cwe: "CWE-89", endpoint: "/index.php?page=user-info.php" },
        { name: "XSS - Reflected", severity: "High", cwe: "CWE-79", endpoint: "/index.php?page=dns-lookup.php" },
        { name: "Command Injection", severity: "Critical", cwe: "CWE-78", endpoint: "/index.php?page=dns-lookup.php" },
      ],
      // Wave 2: Improved
      [
        { name: "SQL Injection", severity: "Critical", cwe: "CWE-89", endpoint: "/index.php?page=user-info.php" },
        { name: "SQL Injection - Blind", severity: "High", cwe: "CWE-89", endpoint: "/index.php?page=user-info.php" },
        { name: "XSS - Reflected", severity: "High", cwe: "CWE-79", endpoint: "/index.php?page=dns-lookup.php" },
        { name: "XSS - Stored", severity: "High", cwe: "CWE-79", endpoint: "/index.php?page=add-to-your-blog.php" },
        { name: "Command Injection", severity: "Critical", cwe: "CWE-78", endpoint: "/index.php?page=dns-lookup.php" },
        { name: "HTML Injection", severity: "Medium", cwe: "CWE-79", endpoint: "/index.php?page=html-injection.php" },
        { name: "XML External Entity", severity: "High", cwe: "CWE-611", endpoint: "/index.php?page=xml-validator.php" },
        { name: "File Inclusion", severity: "High", cwe: "CWE-98", endpoint: "/index.php?page=arbitrary-file-inclusion.php" },
      ],
      // Wave 3: Advanced
      [
        { name: "SQL Injection", severity: "Critical", cwe: "CWE-89", endpoint: "/index.php?page=user-info.php" },
        { name: "SQL Injection - Blind", severity: "High", cwe: "CWE-89", endpoint: "/index.php?page=user-info.php" },
        { name: "SQL Injection - INSERT", severity: "High", cwe: "CWE-89", endpoint: "/index.php?page=register.php" },
        { name: "XSS - Reflected", severity: "High", cwe: "CWE-79", endpoint: "/index.php?page=dns-lookup.php" },
        { name: "XSS - Stored", severity: "High", cwe: "CWE-79", endpoint: "/index.php?page=add-to-your-blog.php" },
        { name: "XSS - DOM Based", severity: "High", cwe: "CWE-79", endpoint: "/index.php?page=password-generator.php" },
        { name: "Command Injection", severity: "Critical", cwe: "CWE-78", endpoint: "/index.php?page=dns-lookup.php" },
        { name: "HTML Injection", severity: "Medium", cwe: "CWE-79", endpoint: "/index.php?page=html-injection.php" },
        { name: "XML External Entity", severity: "High", cwe: "CWE-611", endpoint: "/index.php?page=xml-validator.php" },
        { name: "File Inclusion", severity: "High", cwe: "CWE-98", endpoint: "/index.php?page=arbitrary-file-inclusion.php" },
        { name: "CSRF", severity: "Medium", cwe: "CWE-352", endpoint: "/index.php?page=register.php" },
        { name: "Directory Traversal", severity: "High", cwe: "CWE-22", endpoint: "/index.php?page=source-viewer.php" },
        { name: "Click Jacking", severity: "Medium", cwe: "CWE-1021", endpoint: "/index.php" },
        { name: "JavaScript Injection", severity: "High", cwe: "CWE-94", endpoint: "/index.php?page=user-info.php" },
        { name: "Log Injection", severity: "Medium", cwe: "CWE-117", endpoint: "/index.php?page=log-visit.php" },
        { name: "HTTP Parameter Pollution", severity: "Medium", cwe: "CWE-235", endpoint: "/index.php?page=user-poll.php" },
      ],
    ],
  },
  {
    targetPreset: "broken-crystals",
    targetUrl: "https://scan.aceofcloud.io/broken-crystals",
    waves: [
      // Wave 1: Basic
      [
        { name: "SQL Injection", severity: "Critical", cwe: "CWE-89", endpoint: "/api/products" },
        { name: "XSS - Reflected", severity: "High", cwe: "CWE-79", endpoint: "/api/render" },
      ],
      // Wave 2: Improved
      [
        { name: "SQL Injection", severity: "Critical", cwe: "CWE-89", endpoint: "/api/products" },
        { name: "XSS - Reflected", severity: "High", cwe: "CWE-79", endpoint: "/api/render" },
        { name: "XSS - DOM Based", severity: "High", cwe: "CWE-79", endpoint: "/search" },
        { name: "SSRF", severity: "High", cwe: "CWE-918", endpoint: "/api/file" },
        { name: "Open Redirect", severity: "Medium", cwe: "CWE-601", endpoint: "/api/goto" },
        { name: "JWT Vulnerability", severity: "High", cwe: "CWE-347", endpoint: "/api/auth/login" },
        { name: "Broken Authentication", severity: "High", cwe: "CWE-287", endpoint: "/api/auth/login" },
      ],
      // Wave 3: Advanced
      [
        { name: "SQL Injection", severity: "Critical", cwe: "CWE-89", endpoint: "/api/products" },
        { name: "XSS - Reflected", severity: "High", cwe: "CWE-79", endpoint: "/api/render" },
        { name: "XSS - DOM Based", severity: "High", cwe: "CWE-79", endpoint: "/search" },
        { name: "SSRF", severity: "High", cwe: "CWE-918", endpoint: "/api/file" },
        { name: "Open Redirect", severity: "Medium", cwe: "CWE-601", endpoint: "/api/goto" },
        { name: "JWT Vulnerability", severity: "High", cwe: "CWE-347", endpoint: "/api/auth/login" },
        { name: "Broken Authentication", severity: "High", cwe: "CWE-287", endpoint: "/api/auth/login" },
        { name: "Path Traversal", severity: "High", cwe: "CWE-22", endpoint: "/api/file" },
        { name: "XML External Entity", severity: "High", cwe: "CWE-611", endpoint: "/api/metadata" },
        { name: "IDOR", severity: "High", cwe: "CWE-639", endpoint: "/api/users" },
        { name: "CSRF", severity: "Medium", cwe: "CWE-352", endpoint: "/api/users/password" },
        { name: "Prototype Pollution", severity: "Medium", cwe: "CWE-1321", endpoint: "/api/spawn" },
        { name: "OS Command Injection", severity: "Critical", cwe: "CWE-78", endpoint: "/api/spawn" },
      ],
    ],
  },
];

// ─── Seed Runner ───────────────────────────────────────────────────────────

export async function seedAccuracyData(): Promise<{
  totalComparisons: number;
  results: Array<{
    targetPreset: string;
    wave: number;
    f1Score: number;
    precision: number;
    recall: number;
    totalFindings: number;
    truePositives: number;
    falsePositives: number;
    falseNegatives: number;
  }>;
  errors: string[];
}> {
  const results: any[] = [];
  const errors: string[] = [];
  let totalComparisons = 0;

  console.log(`${LOG} Starting accuracy seed: ${TARGET_WAVES.length} targets × 3 waves`);

  for (const target of TARGET_WAVES) {
    for (let waveIdx = 0; waveIdx < target.waves.length; waveIdx++) {
      const findings = target.waves[waveIdx];
      const sessionId = generateSessionId();
      const scanType = waveIdx === 0 ? "basic" : waveIdx === 1 ? "intermediate" : "advanced";

      try {
        console.log(`${LOG} Scoring ${target.targetPreset} wave ${waveIdx + 1} (${findings.length} findings)...`);

        const result = await runAccuracyComparison({
          sessionId,
          engagementId: `seed-eng-${target.targetPreset}-w${waveIdx + 1}`,
          targetPreset: target.targetPreset,
          targetUrl: target.targetUrl,
          scanType,
          findings,
          knowledgeModulesUsed: [
            "payloads-knowledge",
            "offensive-tools",
            "zap-wstg-methodology",
            "bugbounty-methodology",
          ],
          scanDurationMs: 30000 + Math.floor(Math.random() * 60000),
        });

        if (result) {
          results.push({
            targetPreset: target.targetPreset,
            wave: waveIdx + 1,
            f1Score: result.f1Score,
            precision: result.precision,
            recall: result.recall,
            totalFindings: result.totalFindings,
            truePositives: result.truePositives,
            falsePositives: result.falsePositives,
            falseNegatives: result.falseNegatives,
          });
          totalComparisons++;
          console.log(`${LOG} ✓ ${target.targetPreset} wave ${waveIdx + 1}: F1=${result.f1Score.toFixed(3)}, P=${result.precision.toFixed(3)}, R=${result.recall.toFixed(3)}`);
        } else {
          errors.push(`${target.targetPreset} wave ${waveIdx + 1}: null result`);
        }

        // Small delay between API calls to avoid overwhelming the DO server
        await new Promise(r => setTimeout(r, 500));
      } catch (err: any) {
        errors.push(`${target.targetPreset} wave ${waveIdx + 1}: ${err.message}`);
        console.error(`${LOG} ✗ ${target.targetPreset} wave ${waveIdx + 1}: ${err.message}`);
      }
    }
  }

  console.log(`${LOG} Seed complete: ${totalComparisons} comparisons stored, ${errors.length} errors`);
  return { totalComparisons, results, errors };
}
