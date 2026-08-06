/**
 * Mobile App Testing Module — P1 Gap Remediation
 * 
 * Provides a structured framework for mobile application security assessments
 * aligned with OWASP Mobile Application Security Testing Guide (MASTG) and
 * OWASP Mobile Application Security Verification Standard (MASVS).
 * 
 * Features:
 * - OWASP MASVS v2 control checklist
 * - Static analysis check definitions (SAST)
 * - Dynamic analysis check definitions (DAST)
 * - Platform-specific checks (iOS/Android)
 * - Risk scoring aligned with CVSS
 * - Integration with evidence chain for compliance
 */

// ─── Types ───────────────────────────────────────────────────────────────────

export type MobilePlatform = "ios" | "android" | "cross-platform";
export type TestCategory = "static" | "dynamic" | "network" | "platform" | "crypto" | "auth" | "storage" | "code_quality";
export type FindingSeverity = "critical" | "high" | "medium" | "low" | "info";

export interface MobileTestCase {
  id: string;
  masvsId: string;           // MASVS control ID (e.g., MASVS-STORAGE-1)
  mastgId: string;           // MASTG test ID
  title: string;
  description: string;
  category: TestCategory;
  platform: MobilePlatform;
  automatable: boolean;
  tools: string[];           // Recommended tools
  steps: string[];           // Manual test steps
  expectedResult: string;
  references: string[];
}

export interface MobileTestResult {
  testCaseId: string;
  status: "pass" | "fail" | "partial" | "not_applicable" | "not_tested";
  severity: FindingSeverity;
  evidence: string;
  notes: string;
  remediation: string;
  testedAt: number;
  testedBy: string;
}

export interface MobileAssessment {
  id: string;
  appName: string;
  appVersion: string;
  packageName: string;
  platform: MobilePlatform;
  targetSdk: string;
  minSdk: string;
  permissions: string[];
  testResults: MobileTestResult[];
  overallScore: number;      // 0-100
  createdAt: number;
}

// ─── OWASP MASVS v2 Test Cases ──────────────────────────────────────────────

export const MASVS_TEST_CASES: MobileTestCase[] = [
  // ── MASVS-STORAGE ──
  {
    id: "MOB-STOR-001",
    masvsId: "MASVS-STORAGE-1",
    mastgId: "MASTG-TEST-0001",
    title: "Sensitive Data in Local Storage",
    description: "Verify that sensitive data (credentials, tokens, PII) is not stored in plaintext on the device.",
    category: "storage",
    platform: "cross-platform",
    automatable: true,
    tools: ["MobSF", "Objection", "Frida"],
    steps: [
      "Extract the app's data directory",
      "Search for plaintext credentials in SharedPreferences/NSUserDefaults",
      "Check SQLite databases for unencrypted sensitive data",
      "Inspect plist files for sensitive values",
      "Verify keychain/keystore usage for secrets",
    ],
    expectedResult: "No sensitive data found in plaintext storage",
    references: ["https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-1/"],
  },
  {
    id: "MOB-STOR-002",
    masvsId: "MASVS-STORAGE-2",
    mastgId: "MASTG-TEST-0002",
    title: "Sensitive Data in Logs",
    description: "Verify that sensitive data is not written to application or system logs.",
    category: "storage",
    platform: "cross-platform",
    automatable: true,
    tools: ["adb logcat", "Console.app", "Frida"],
    steps: [
      "Monitor application logs during authentication",
      "Check for PII in debug/info log levels",
      "Verify log sanitization for sensitive fields",
      "Check third-party SDK logging behavior",
    ],
    expectedResult: "No sensitive data appears in logs at any level",
    references: ["https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-2/"],
  },
  // ── MASVS-CRYPTO ──
  {
    id: "MOB-CRYP-001",
    masvsId: "MASVS-CRYPTO-1",
    mastgId: "MASTG-TEST-0010",
    title: "Cryptographic Algorithm Strength",
    description: "Verify that the app uses current, strong cryptographic algorithms with appropriate key lengths.",
    category: "crypto",
    platform: "cross-platform",
    automatable: true,
    tools: ["MobSF", "Jadx", "Hopper"],
    steps: [
      "Decompile the application binary",
      "Search for deprecated algorithms (DES, 3DES, RC4, MD5)",
      "Verify AES key lengths (minimum 256-bit for FIPS)",
      "Check RSA key lengths (minimum 2048-bit)",
      "Verify HMAC usage with SHA-256 or stronger",
    ],
    expectedResult: "Only FIPS 140-3 approved algorithms with adequate key lengths",
    references: ["https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-1/"],
  },
  {
    id: "MOB-CRYP-002",
    masvsId: "MASVS-CRYPTO-2",
    mastgId: "MASTG-TEST-0011",
    title: "Cryptographic Key Management",
    description: "Verify proper key generation, storage, and rotation practices.",
    category: "crypto",
    platform: "cross-platform",
    automatable: false,
    tools: ["Frida", "Objection", "Jadx"],
    steps: [
      "Verify keys are generated using secure random sources",
      "Check that keys are stored in platform keystore (Android Keystore / iOS Keychain)",
      "Verify key rotation mechanisms exist",
      "Check for hardcoded cryptographic keys in source code",
    ],
    expectedResult: "Keys use platform keystore, no hardcoded keys, rotation policy exists",
    references: ["https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO-2/"],
  },
  // ── MASVS-AUTH ──
  {
    id: "MOB-AUTH-001",
    masvsId: "MASVS-AUTH-1",
    mastgId: "MASTG-TEST-0020",
    title: "Biometric Authentication Implementation",
    description: "Verify that biometric authentication is properly implemented with cryptographic binding.",
    category: "auth",
    platform: "cross-platform",
    automatable: false,
    tools: ["Frida", "Objection"],
    steps: [
      "Verify biometric auth uses CryptoObject (Android) or LAContext (iOS)",
      "Check that biometric auth is not bypassable via Frida hooks",
      "Verify fallback mechanisms require strong authentication",
      "Test biometric enrollment changes trigger re-authentication",
    ],
    expectedResult: "Biometric auth is cryptographically bound and not bypassable",
    references: ["https://mas.owasp.org/MASVS/controls/MASVS-AUTH-1/"],
  },
  {
    id: "MOB-AUTH-002",
    masvsId: "MASVS-AUTH-2",
    mastgId: "MASTG-TEST-0021",
    title: "Session Management",
    description: "Verify proper session handling, timeout, and invalidation.",
    category: "auth",
    platform: "cross-platform",
    automatable: true,
    tools: ["Burp Suite", "mitmproxy", "Frida"],
    steps: [
      "Verify session tokens are sufficiently random (128+ bits entropy)",
      "Check session timeout implementation (idle and absolute)",
      "Verify server-side session invalidation on logout",
      "Test session fixation resistance",
      "Verify token refresh mechanism",
    ],
    expectedResult: "Sessions are properly managed with server-side invalidation",
    references: ["https://mas.owasp.org/MASVS/controls/MASVS-AUTH-2/"],
  },
  // ── MASVS-NETWORK ──
  {
    id: "MOB-NET-001",
    masvsId: "MASVS-NETWORK-1",
    mastgId: "MASTG-TEST-0030",
    title: "TLS Configuration",
    description: "Verify that all network traffic uses TLS 1.2+ with strong cipher suites.",
    category: "network",
    platform: "cross-platform",
    automatable: true,
    tools: ["Burp Suite", "mitmproxy", "SSLyze"],
    steps: [
      "Intercept all network traffic from the app",
      "Verify TLS 1.2 minimum is enforced",
      "Check for cleartext HTTP connections",
      "Verify strong cipher suite selection",
      "Check Network Security Config (Android) / ATS (iOS)",
    ],
    expectedResult: "All traffic uses TLS 1.2+ with FIPS-approved cipher suites",
    references: ["https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-1/"],
  },
  {
    id: "MOB-NET-002",
    masvsId: "MASVS-NETWORK-2",
    mastgId: "MASTG-TEST-0031",
    title: "Certificate Pinning",
    description: "Verify that certificate pinning is implemented for critical connections.",
    category: "network",
    platform: "cross-platform",
    automatable: true,
    tools: ["Frida", "Objection", "apk-mitm"],
    steps: [
      "Attempt MITM with custom CA certificate",
      "Verify app rejects connections with untrusted certificates",
      "Test pin bypass resistance (Frida scripts)",
      "Verify backup pin configuration",
      "Check pin rotation mechanism",
    ],
    expectedResult: "Certificate pinning prevents MITM attacks",
    references: ["https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-2/"],
  },
  // ── MASVS-PLATFORM ──
  {
    id: "MOB-PLAT-001",
    masvsId: "MASVS-PLATFORM-1",
    mastgId: "MASTG-TEST-0040",
    title: "IPC Security",
    description: "Verify that inter-process communication mechanisms are properly secured.",
    category: "platform",
    platform: "cross-platform",
    automatable: true,
    tools: ["Drozer", "Objection", "Frida"],
    steps: [
      "Enumerate exported components (Android: activities, services, receivers, providers)",
      "Test deep link / URL scheme handling for injection",
      "Verify intent filter restrictions",
      "Check for sensitive data in IPC messages",
      "Test WebView JavaScript bridge security",
    ],
    expectedResult: "IPC mechanisms are restricted and validate all input",
    references: ["https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-1/"],
  },
  {
    id: "MOB-PLAT-002",
    masvsId: "MASVS-PLATFORM-2",
    mastgId: "MASTG-TEST-0041",
    title: "WebView Security",
    description: "Verify that WebViews are securely configured and do not expose sensitive interfaces.",
    category: "platform",
    platform: "cross-platform",
    automatable: true,
    tools: ["Frida", "Jadx", "Hopper"],
    steps: [
      "Check JavaScript enabled state in WebViews",
      "Verify file access is disabled in WebViews",
      "Test JavaScript interface exposure",
      "Check for universal access from file URLs",
      "Verify content provider access restrictions",
    ],
    expectedResult: "WebViews are hardened with minimal permissions",
    references: ["https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-2/"],
  },
  // ── MASVS-CODE ──
  {
    id: "MOB-CODE-001",
    masvsId: "MASVS-CODE-1",
    mastgId: "MASTG-TEST-0050",
    title: "Anti-Tampering",
    description: "Verify that the app detects and responds to tampering attempts.",
    category: "code_quality",
    platform: "cross-platform",
    automatable: false,
    tools: ["Frida", "Objection", "apktool"],
    steps: [
      "Attempt to repackage the app with modifications",
      "Test root/jailbreak detection",
      "Verify debugger detection",
      "Test integrity verification of app binary",
      "Check for emulator detection",
    ],
    expectedResult: "App detects tampering and responds appropriately",
    references: ["https://mas.owasp.org/MASVS/controls/MASVS-CODE-1/"],
  },
  {
    id: "MOB-CODE-002",
    masvsId: "MASVS-CODE-2",
    mastgId: "MASTG-TEST-0051",
    title: "Reverse Engineering Protection",
    description: "Verify that the app implements obfuscation and anti-reverse-engineering measures.",
    category: "code_quality",
    platform: "cross-platform",
    automatable: true,
    tools: ["Jadx", "Hopper", "IDA Pro", "Ghidra"],
    steps: [
      "Decompile the application",
      "Check for code obfuscation (ProGuard/R8 for Android)",
      "Verify string encryption for sensitive values",
      "Check for native code protection",
      "Assess overall reverse engineering difficulty",
    ],
    expectedResult: "Meaningful obfuscation makes reverse engineering significantly harder",
    references: ["https://mas.owasp.org/MASVS/controls/MASVS-CODE-2/"],
  },
];

// ─── Scoring ────────────────────────────────────────────────────────────────

const SEVERITY_WEIGHTS: Record<FindingSeverity, number> = {
  critical: 10,
  high: 7,
  medium: 4,
  low: 2,
  info: 0,
};

/**
 * Calculate the overall security score for a mobile assessment.
 * Score is 0-100 where 100 means all tests pass.
 */
export function calculateMobileScore(results: MobileTestResult[]): number {
  if (results.length === 0) return 0;

  const applicableResults = results.filter(r => r.status !== "not_applicable" && r.status !== "not_tested");
  if (applicableResults.length === 0) return 0;

  let totalWeight = 0;
  let earnedWeight = 0;

  for (const result of applicableResults) {
    const weight = SEVERITY_WEIGHTS[result.severity] || 1;
    totalWeight += weight;
    if (result.status === "pass") {
      earnedWeight += weight;
    } else if (result.status === "partial") {
      earnedWeight += weight * 0.5;
    }
  }

  return totalWeight > 0 ? Math.round((earnedWeight / totalWeight) * 100) : 0;
}

/**
 * Get test cases filtered by platform and category.
 */
export function getTestCases(
  platform?: MobilePlatform,
  category?: TestCategory
): MobileTestCase[] {
  return MASVS_TEST_CASES.filter(tc => {
    if (platform && tc.platform !== "cross-platform" && tc.platform !== platform) return false;
    if (category && tc.category !== category) return false;
    return true;
  });
}

/**
 * Get a summary of test coverage by MASVS category.
 */
export function getCoverageSummary(results: MobileTestResult[]): Record<TestCategory, {
  total: number;
  passed: number;
  failed: number;
  partial: number;
  notTested: number;
}> {
  const summary: Record<string, { total: number; passed: number; failed: number; partial: number; notTested: number }> = {};

  for (const tc of MASVS_TEST_CASES) {
    if (!summary[tc.category]) {
      summary[tc.category] = { total: 0, passed: 0, failed: 0, partial: 0, notTested: 0 };
    }
    summary[tc.category].total++;

    const result = results.find(r => r.testCaseId === tc.id);
    if (!result || result.status === "not_tested") {
      summary[tc.category].notTested++;
    } else if (result.status === "pass") {
      summary[tc.category].passed++;
    } else if (result.status === "fail") {
      summary[tc.category].failed++;
    } else if (result.status === "partial") {
      summary[tc.category].partial++;
    }
  }

  return summary as any;
}
