/**
 * Engagement Context — Typed Phase-to-Phase Data Contract
 *
 * This module defines the formal interface for data flowing between engagement
 * pipeline phases. It serves as:
 *
 * 1. A documentation contract: each phase declares what it produces
 * 2. A validation boundary: downstream phases can assert required inputs exist
 * 3. A decomposition enabler: extracted phase modules import these types
 *    instead of depending on the monolithic EngagementOpsState
 *
 * ─── Architecture ────────────────────────────────────────────────────────────
 *
 * The engagement pipeline flows through 9 phases:
 *
 *   Phase 1: Passive Recon → produces PassiveReconOutput
 *   Phase 2: Passive Discovery → produces PassiveDiscoveryOutput
 *   Phase 3: Scoping & Test Plan → produces ScopingOutput
 *   Phase 4: Test Plan Approval → produces ApprovalOutput
 *   Phase 5: Active Enumeration → produces EnumerationOutput
 *   Phase 6: Vulnerability Detection → produces VulnDetectionOutput
 *   Phase 6b: Social Engineering → produces SocialEngOutput
 *   Phase 7: Exploitation → produces ExploitationOutput
 *   Phase 8: Post-Exploit → produces PostExploitOutput
 *   Phase 9: Reporting → produces ReportingOutput
 *
 * Each phase's output is accumulated into the EngagementContext, which is
 * the single source of truth for all downstream phases.
 *
 * ─── Usage ───────────────────────────────────────────────────────────────────
 *
 * When extracting a phase into its own module:
 *
 *   import type { EngagementContext, VulnDetectionOutput } from './engagement-context';
 *
 *   export async function executeVulnDetection(
 *     ctx: Pick<EngagementContext, 'passiveRecon' | 'enumeration' | 'scoping'>,
 *     ...
 *   ): Promise<VulnDetectionOutput> { ... }
 *
 * This ensures the phase only accesses data it legitimately needs.
 */

// ─── Shared Primitives ────────────────────────────────────────────────────────

export interface TargetAsset {
  hostname: string;
  ip?: string;
  type: "web_app" | "server" | "network_device" | "database" | "api" | "unknown";
  ports: Array<{ port: number; service: string; version?: string }>;
  wafDetected?: string;
}

export interface Finding {
  id: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  cve?: string;
  description?: string;
  cvss?: number;
  cwe?: string;
  source?: string;
  corroborationTier?: "confirmed" | "corroborated" | "unverified";
  evidenceDetail?: string;
  rawEvidence?: string;
}

export interface ToolExecution {
  tool: string;
  command: string;
  exitCode: number;
  durationMs: number;
  timedOut: boolean;
  findingCount: number;
  outputPreview: string;
  rawOutput?: string;
  executedAt: number;
  phase: string;
}

export interface Credential {
  username: string;
  password: string;
  service: string;
  port: number;
  protocol: string;
  accessLevel?: string;
  source: string;
  confirmedAt: number;
}

// ─── Phase Output Types ───────────────────────────────────────────────────────

/** Phase 1: Passive Recon — OSINT gathering without touching target infrastructure */
export interface PassiveReconOutput {
  completedAt: number;
  /** Per-domain passive recon results */
  domainResults: Record<string, {
    subdomains: string[];
    dnsRecords: Record<string, any[]>;
    certificates: any[];
    technologies: string[];
    cloudProviders: string[];
    wafDetected?: string;
    emailSecurity?: {
      spf?: boolean;
      dkim?: boolean;
      dmarc?: boolean;
      dmarcPolicy?: string;
    };
    emailAddresses: string[];
    breachExposure: any[];
    services: Array<{ port: number; service: string }>;
  }>;
}

/** Phase 2: Passive Discovery — Asset identification from OSINT data */
export interface PassiveDiscoveryOutput {
  completedAt: number;
  subdomains: string[];
  dnsRecords: Record<string, any[]>;
  certificates: any[];
  technologies: string[];
  cloudProviders: string[];
  wafDetected?: string;
  emailAddresses: string[];
  breachExposure: any[];
}

/** Phase 3: Scoping & Test Plan Generation */
export interface ScopingOutput {
  completedAt: number;
  testPlan: {
    id: string;
    generatedAt: number;
    status: "draft" | "pending_approval" | "approved" | "rejected";
    sections: Array<{ title: string; content: string }>;
    attackVectors: string[];
    toolsPlanned: string[];
    estimatedDuration?: string;
  };
  roeScopeGuard: {
    authorizedDomains: string[];
    authorizedIps: string[];
    roeStatus: string;
  };
}

/** Phase 4: Test Plan Approval */
export interface ApprovalOutput {
  approved: boolean;
  approvedAt?: number;
  approvedBy?: string;
  rejectionReason?: string;
}

/** Phase 5: Active Enumeration — Fingerprinting and service discovery */
export interface EnumerationOutput {
  completedAt: number;
  /** Assets discovered/enriched during enumeration */
  assets: TargetAsset[];
  /** Tool executions performed */
  toolExecutions: ToolExecution[];
  /** Target profiles built from httpx/ScanForge data */
  targetProfiles: Record<string, {
    hostname: string;
    ip?: string;
    waf?: string;
    cdn?: string;
    technologies: string[];
    responseTime?: number;
    statusCode?: number;
  }>;
}

/** Phase 6: Vulnerability Detection — Active scanning and analysis */
export interface VulnDetectionOutput {
  completedAt: number;
  /** Analyzed vulnerabilities with LLM-enriched context */
  vulnAnalysis: Array<{
    finding: Finding;
    analysis: {
      riskScore: number;
      technicalAnalysis: string;
      poc?: string;
      exploitability: "trivial" | "moderate" | "complex" | "theoretical";
    };
    attackTechniques: string[];
    controls: string[];
  }>;
  /** Deduplication statistics */
  dedupStats?: {
    totalBefore: number;
    totalAfter: number;
    duplicatesRemoved: number;
  };
  /** Coverage gap report */
  coverageReport?: {
    overallScore: number;
    totalGaps: number;
    criticalGaps: number;
    recommendations: string[];
  };
}

/** Phase 6b: Social Engineering Assessment */
export interface SocialEngOutput {
  executed: boolean;
  skipped: boolean;
  skipReason?: string;
  phishingIntel?: {
    authorized: boolean;
    spoofable: boolean;
    emailSecurity?: {
      spf?: boolean;
      dkim?: boolean;
      dmarc?: boolean;
      dmarcPolicy?: string;
    };
    recommendation: {
      templateCategory?: string;
      pretext?: string;
      domainStrategy?: "spoof_target" | "typosquat" | "owned_domain";
      landingPageType?: string;
      deliveryNotes?: string;
      confidence?: number;
    };
    targetDomain: string;
    assessedAt: number;
  };
}

/** Phase 7: Exploitation — Penetration testing */
export interface ExploitationOutput {
  completedAt: number;
  exploitsAttempted: number;
  exploitsSucceeded: number;
  sessionsOpened: number;
  /** Per-asset exploit attempts */
  attempts: Array<{
    asset: string;
    module: string;
    success: boolean;
    sessionId?: string;
    cve?: string;
    technique?: string;
    confidence?: number;
    durationMs?: number;
  }>;
}

/** Phase 8: Post-Exploitation — Lateral movement, persistence, data exfil */
export interface PostExploitOutput {
  completedAt: number;
  /** Lateral movement paths discovered */
  lateralPaths: Array<{
    from: string;
    to: string;
    method: string;
    success: boolean;
  }>;
  /** Data exfiltration simulations */
  exfilSimulations: Array<{
    type: string;
    target: string;
    success: boolean;
    dataSize?: string;
  }>;
  /** Persistence mechanisms tested */
  persistenceMechanisms: Array<{
    type: string;
    target: string;
    success: boolean;
  }>;
}

/** Phase 9: Reporting — Auto-generated pentest report */
export interface ReportingOutput {
  completedAt: number;
  reportId: string;
  findingsCount: number;
  executiveSummary?: {
    riskStatement: string;
    overallRating: string;
    keyStrengths: string[];
    keyGaps: string[];
    narrative: string;
  };
}

// ─── Aggregate Context ────────────────────────────────────────────────────────

/**
 * The complete engagement context accumulated across all phases.
 * Each field is optional because it's populated progressively as phases complete.
 *
 * When extracting a phase, use `Pick<EngagementContext, 'field1' | 'field2'>` to
 * declare only the dependencies that phase actually needs.
 */
export interface EngagementContext {
  /** Engagement metadata */
  engagementId: number;
  engagementType: "pentest" | "red_team" | "purple_team" | "phishing" | "tabletop";
  targetDomain: string;
  customerName?: string;

  /** Phase outputs (populated progressively) */
  passiveRecon?: PassiveReconOutput;
  passiveDiscovery?: PassiveDiscoveryOutput;
  scoping?: ScopingOutput;
  approval?: ApprovalOutput;
  enumeration?: EnumerationOutput;
  vulnDetection?: VulnDetectionOutput;
  socialEng?: SocialEngOutput;
  exploitation?: ExploitationOutput;
  postExploit?: PostExploitOutput;
  reporting?: ReportingOutput;

  /** Cross-cutting state */
  assets: TargetAsset[];
  findings: Finding[];
  credentials: Credential[];
  toolExecutions: ToolExecution[];

  /** Operational metadata */
  startedAt: number;
  completedAt?: number;
  stats: {
    hostsScanned: number;
    portsFound: number;
    vulnsFound: number;
    exploitsAttempted: number;
    exploitsSucceeded: number;
    sessionsOpened: number;
  };
}

// ─── Phase Contract Helpers ───────────────────────────────────────────────────

/**
 * Assert that a required phase output exists in the context.
 * Throws a clear error if a phase tries to access data from a phase that hasn't run.
 */
export function requirePhaseOutput<K extends keyof EngagementContext>(
  ctx: EngagementContext,
  phase: K,
  callerPhase: string
): NonNullable<EngagementContext[K]> {
  const output = ctx[phase];
  if (output === undefined || output === null) {
    throw new Error(
      `[EngagementContext] Phase "${callerPhase}" requires output from "${phase}" but it has not been populated. ` +
      `This indicates a phase ordering violation.`
    );
  }
  return output as NonNullable<EngagementContext[K]>;
}

/**
 * Create an initial empty context for a new engagement.
 */
export function createEngagementContext(params: {
  engagementId: number;
  engagementType: EngagementContext["engagementType"];
  targetDomain: string;
  customerName?: string;
}): EngagementContext {
  return {
    engagementId: params.engagementId,
    engagementType: params.engagementType,
    targetDomain: params.targetDomain,
    customerName: params.customerName,
    assets: [],
    findings: [],
    credentials: [],
    toolExecutions: [],
    startedAt: Date.now(),
    stats: {
      hostsScanned: 0,
      portsFound: 0,
      vulnsFound: 0,
      exploitsAttempted: 0,
      exploitsSucceeded: 0,
      sessionsOpened: 0,
    },
  };
}
