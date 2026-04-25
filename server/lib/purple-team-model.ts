/**
 * Purple Team Data Model
 * 
 * Detection-centric data model for purple team engagements.
 * Reframes offensive operations as detection validation tests.
 * Includes ROE addendum schema, test plan template, and bilateral evidence model.
 */

// ─── Detection Test Event Model ────────────────────────────────────────────

export interface DetectionTest {
  /** Unique detection test identifier */
  id: string;
  /** Parent engagement ID */
  engagementId: number;
  /** MITRE ATT&CK technique ID being tested */
  mitreId: string;
  /** MITRE ATT&CK technique name */
  mitreName: string;
  /** MITRE ATT&CK tactic */
  tactic: string;
  /** Test description — framed as detection validation, not attack */
  description: string;
  /** Target host or asset */
  targetHost: string;
  /** Operator who initiated the test */
  operatorId: string;
  /** Operator name */
  operatorName: string;
  /** Timestamp of test execution (UTC ms) */
  executedAt: number;
  /** Detection grace period end (UTC ms) — when to evaluate detection */
  detectionWindowEnd: number;
  /** Test status */
  status: "pending" | "executing" | "awaiting_detection" | "detected" | "not_detected" | "partial" | "inconclusive";
  /** The specific tool/command used to execute the TTP */
  executionMethod: string;
  /** Expected indicators that a competent detection should produce */
  expectedIndicators: string[];
  /** Actual detection result from customer SOC/EDR */
  detectionResult?: DetectionResult;
  /** Evidence chain hash for this test */
  evidenceHash?: string;
  /** Whether this test was part of the approved test plan */
  inTestPlan: boolean;
  /** Test plan amendment justification (if added during exercise) */
  amendmentJustification?: string;
  /** Safety engine assessment result */
  safetyAssessment: "approved" | "blocked" | "requires_approval";
  /** ROE authorization reference */
  roeAuthorizationRef: string;
}

export interface DetectionResult {
  /** Was the TTP detected by the customer's stack? */
  detected: boolean;
  /** Time to detection (ms from execution to first alert) */
  timeToDetect?: number;
  /** Time to alert (ms from execution to SOC notification) */
  timeToAlert?: number;
  /** Time to response (ms from execution to containment action) */
  timeToRespond?: number;
  /** Which defensive product(s) detected it */
  detectedBy: string[];
  /** Alert severity assigned by the defensive stack */
  alertSeverity?: "critical" | "high" | "medium" | "low" | "info" | "none";
  /** Alert name/title from the defensive stack */
  alertTitle?: string;
  /** Was the detection automated or manual (SOC analyst)? */
  detectionType: "automated" | "manual" | "hybrid" | "none";
  /** Was a containment action taken? */
  containmentAction?: string;
  /** Customer-provided detection telemetry (raw log entries) */
  telemetryEntries: TelemetryEntry[];
  /** Notes from the customer SOC */
  socNotes?: string;
  /** Evidence of non-detection (negative evidence) */
  negativeEvidenceNotes?: string;
}

export interface TelemetryEntry {
  /** Source system (EDR name, SIEM name, etc.) */
  source: string;
  /** Timestamp from the customer's system (UTC ms) */
  timestamp: number;
  /** Clock skew detected vs platform time (ms) */
  clockSkewMs?: number;
  /** Raw log entry or alert JSON */
  rawData: string;
  /** Parsed alert type */
  alertType?: string;
  /** Host where the detection occurred */
  host?: string;
  /** Provenance: how this telemetry was provided */
  provenance: "api_ingestion" | "manual_upload" | "siem_export" | "edr_export" | "email";
  /** SHA-256 hash of the raw data for evidence chain */
  contentHash: string;
}

// ─── Detection Metrics (Report-Level Aggregation) ──────────────────────────

export interface DetectionMetrics {
  /** Total TTPs tested */
  totalTested: number;
  /** TTPs detected by at least one defensive product */
  totalDetected: number;
  /** TTPs not detected within the grace period */
  totalMissed: number;
  /** TTPs with partial or inconclusive detection */
  totalPartial: number;
  /** Overall detection rate (detected / tested) */
  detectionRate: number;
  /** Mean time to detect (ms) across all detected TTPs */
  meanTimeToDetect: number;
  /** Mean time to alert (ms) */
  meanTimeToAlert: number;
  /** Mean time to respond (ms) */
  meanTimeToRespond: number;
  /** Detection rate by tactic */
  byTactic: Record<string, { tested: number; detected: number; rate: number }>;
  /** Detection rate by product */
  byProduct: Record<string, { detected: number; missed: number; rate: number }>;
  /** Detection rate by severity */
  bySeverity: Record<string, { tested: number; detected: number; rate: number }>;
}

export function computeDetectionMetrics(tests: DetectionTest[]): DetectionMetrics {
  const completed = tests.filter(t => t.status !== "pending" && t.status !== "executing" && t.status !== "awaiting_detection");
  const detected = completed.filter(t => t.status === "detected");
  const missed = completed.filter(t => t.status === "not_detected");
  const partial = completed.filter(t => t.status === "partial" || t.status === "inconclusive");

  const detectTimes = detected
    .map(t => t.detectionResult?.timeToDetect)
    .filter((t): t is number => t !== undefined);
  const alertTimes = detected
    .map(t => t.detectionResult?.timeToAlert)
    .filter((t): t is number => t !== undefined);
  const respondTimes = detected
    .map(t => t.detectionResult?.timeToRespond)
    .filter((t): t is number => t !== undefined);

  const avg = (arr: number[]) => arr.length > 0 ? arr.reduce((a, b) => a + b, 0) / arr.length : 0;

  // By tactic
  const byTactic: Record<string, { tested: number; detected: number; rate: number }> = {};
  for (const t of completed) {
    if (!byTactic[t.tactic]) byTactic[t.tactic] = { tested: 0, detected: 0, rate: 0 };
    byTactic[t.tactic].tested++;
    if (t.status === "detected") byTactic[t.tactic].detected++;
  }
  for (const k of Object.keys(byTactic)) {
    byTactic[k].rate = byTactic[k].tested > 0 ? byTactic[k].detected / byTactic[k].tested : 0;
  }

  // By product
  const byProduct: Record<string, { detected: number; missed: number; rate: number }> = {};
  for (const t of completed) {
    const products = t.detectionResult?.detectedBy || [];
    if (t.status === "detected") {
      for (const p of products) {
        if (!byProduct[p]) byProduct[p] = { detected: 0, missed: 0, rate: 0 };
        byProduct[p].detected++;
      }
    }
  }

  // By severity
  const bySeverity: Record<string, { tested: number; detected: number; rate: number }> = {};

  return {
    totalTested: completed.length,
    totalDetected: detected.length,
    totalMissed: missed.length,
    totalPartial: partial.length,
    detectionRate: completed.length > 0 ? detected.length / completed.length : 0,
    meanTimeToDetect: avg(detectTimes),
    meanTimeToAlert: avg(alertTimes),
    meanTimeToRespond: avg(respondTimes),
    byTactic,
    byProduct,
    bySeverity,
  };
}

// ─── Purple Team ROE Addendum ──────────────────────────────────────────────

export interface PurpleTeamROEAddendum {
  /** Engagement ID this addendum belongs to */
  engagementId: number;

  // --- Defensive Participation ---
  /** SOC/MSSP team name (counterparty, not just notification recipient) */
  defensiveTeamName: string;
  /** SOC/MSSP team lead contact */
  defensiveTeamLead: string;
  /** SOC/MSSP team lead email */
  defensiveTeamEmail: string;
  /** Has the defensive team formally acknowledged participation? */
  defensiveTeamAcknowledged: boolean;
  /** Date of acknowledgment (UTC ms) */
  defensiveTeamAckDate?: number;

  // --- Detection Coordination Protocol ---
  /** Are TTPs disclosed to the SOC in advance? */
  advanceTtpDisclosure: boolean;
  /** Is there a real-time detection confirmation channel? */
  realTimeChannel: boolean;
  /** Channel type (Slack, Teams, phone, radio, etc.) */
  realTimeChannelType?: string;
  /** Separate "stop" signal capability beyond standard ROE termination? */
  separateStopSignal: boolean;
  /** Stop signal mechanism description */
  stopSignalMechanism?: string;

  // --- EDR Vendor Notification ---
  /** Primary EDR product in use */
  edrProduct: string;
  /** EDR vendor name */
  edrVendor: string;
  /** Has the customer confirmed their EDR vendor TOS allows this exercise? */
  edrVendorTosConfirmed: boolean;
  /** EDR vendor's stated purple team policy (if known) */
  edrVendorPurpleTeamPolicy?: string;
  /** Is the EDR vendor's MDR/SOC service active? (will they be triggered?) */
  edrMdrActive: boolean;
  /** Has the EDR vendor's MDR been notified? */
  edrMdrNotified: boolean;

  // --- Technique-Level Authorization ---
  /** Authorized MITRE technique IDs with customer sign-off */
  authorizedTechniques: AuthorizedTechnique[];

  // --- Evasion Scope Bounding ---
  /** Are evasion techniques restricted to the approved test plan only? */
  evasionBoundedToTestPlan: boolean;
  /** Can the operator amend the test plan during the exercise? */
  liveAmendmentAllowed: boolean;
  /** Amendment requires logged justification? */
  amendmentRequiresJustification: boolean;

  // --- Detection Grace Period ---
  /** Exercise execution window start (UTC ms) */
  exerciseWindowStart: number;
  /** Exercise execution window end (UTC ms) */
  exerciseWindowEnd: number;
  /** Detection observation window end (UTC ms) — typically 24-48hrs after execution */
  detectionObservationEnd: number;
  /** Detection grace period for individual TTPs (ms) — default 15 min */
  ttpDetectionGracePeriodMs: number;

  // --- Additional Fields ---
  /** SIEM product in use */
  siemProduct?: string;
  /** MSSP provider name */
  msspProvider?: string;
  /** Customer's documented incident response procedures reference */
  irProcedureRef?: string;
  /** Notes */
  notes?: string;
}

export interface AuthorizedTechnique {
  /** MITRE ATT&CK technique ID */
  mitreId: string;
  /** MITRE ATT&CK technique name */
  mitreName: string;
  /** MITRE ATT&CK tactic */
  tactic: string;
  /** Customer authorized this specific technique */
  authorized: boolean;
  /** Customer representative who authorized */
  authorizedBy?: string;
  /** Authorization date (UTC ms) */
  authorizedDate?: number;
  /** Specific parameters/constraints for this technique */
  constraints?: string;
  /** Expected detection capability being tested */
  detectionCapabilityTested: string;
}

// ─── Purple Team Test Plan Template ────────────────────────────────────────

export interface PurpleTeamTestPlan {
  /** Test plan ID */
  id: string;
  /** Version (for replayability) */
  version: string;
  /** Engagement ID */
  engagementId: number;
  /** Created by */
  createdBy: string;
  /** Created at (UTC ms) */
  createdAt: number;
  /** Last modified (UTC ms) */
  lastModified: number;

  // --- Defensive Stack Inventory ---
  defensiveStack: DefensiveStackInventory;

  // --- Detection Objectives ---
  detectionObjectives: DetectionObjective[];

  // --- Exercise Schedule ---
  exerciseWindow: {
    executionStart: number;
    executionEnd: number;
    detectionObservationEnd: number;
  };

  // --- Technique Enumeration ---
  techniques: PlannedTechnique[];

  // --- Success Criteria ---
  successCriteria: SuccessCriterion[];

  // --- Vendor Notification ---
  vendorNotification: {
    required: boolean;
    confirmed: boolean;
    vendorName?: string;
    confirmationDate?: number;
    confirmationRef?: string;
  };

  // --- Replayability Metadata ---
  replayability: ReplayabilityMetadata;
}

export interface DefensiveStackInventory {
  /** EDR products deployed */
  edrProducts: Array<{ name: string; version?: string; managedBy?: string; coverage?: string }>;
  /** SIEM products */
  siemProducts: Array<{ name: string; version?: string; logSources?: string[] }>;
  /** MSSP/MDR provider */
  msspProvider?: { name: string; serviceLevel?: string; responseTimeSla?: string };
  /** SOC details */
  soc: {
    type: "internal" | "external" | "hybrid";
    staffCount?: number;
    operatingHours?: string;
    escalationProcedure?: string;
  };
  /** Network security products (IDS/IPS, firewall, WAF, etc.) */
  networkSecurity: Array<{ type: string; product: string; coverage?: string }>;
  /** Email security */
  emailSecurity?: { product: string; features?: string[] };
  /** Identity/access management */
  identityProvider?: { product: string; mfaEnabled?: boolean };
  /** Additional defensive capabilities */
  additionalCapabilities?: string[];
}

export interface DetectionObjective {
  /** Objective ID */
  id: string;
  /** Which detection capability is being validated */
  capability: string;
  /** MITRE techniques that exercise this capability */
  relatedTechniques: string[];
  /** Target detection rate (0-1) */
  targetDetectionRate: number;
  /** Target time-to-alert (ms) */
  targetTimeToAlert?: number;
  /** Priority */
  priority: "critical" | "high" | "medium" | "low";
  /** Rationale for testing this capability */
  rationale: string;
}

export interface PlannedTechnique {
  /** MITRE ATT&CK technique ID */
  mitreId: string;
  /** Technique name */
  name: string;
  /** Tactic */
  tactic: string;
  /** Execution method/tool */
  executionMethod: string;
  /** Target host(s) */
  targets: string[];
  /** Expected indicators a competent detection should produce */
  expectedIndicators: string[];
  /** Detection capability being tested */
  detectionCapabilityTested: string;
  /** Customer authorization status */
  authorized: boolean;
  /** Evasion techniques to use (must be from approved set) */
  approvedEvasionTechniques: string[];
  /** Execution order */
  executionOrder: number;
  /** Dependencies (technique IDs that must execute first) */
  dependencies: string[];
  /** Estimated execution duration (ms) */
  estimatedDurationMs: number;
}

export interface SuccessCriterion {
  /** Criterion ID */
  id: string;
  /** Description */
  description: string;
  /** Metric type */
  metricType: "detection_rate" | "time_to_alert" | "time_to_respond" | "containment_action" | "custom";
  /** Target value */
  targetValue: number;
  /** Unit */
  unit: "percentage" | "seconds" | "minutes" | "boolean";
  /** Scope (which techniques this applies to) */
  scope: "all" | string[];
}

export interface ReplayabilityMetadata {
  /** Test plan version at execution time */
  testPlanVersion: string;
  /** EDR catalog version at execution time */
  edrCatalogVersion: string;
  /** Platform version at execution time */
  platformVersion: string;
  /** Technique parameter snapshots */
  techniqueParamSnapshots: Record<string, any>;
  /** Defensive stack snapshot at execution time */
  defensiveStackSnapshot: DefensiveStackInventory;
  /** NTP time source used */
  ntpTimeSource: string;
  /** Clock skew detected (ms) */
  clockSkewDetected: number;
}

// ─── Bilateral Evidence Model ──────────────────────────────────────────────

export interface BilateralEvidenceRecord {
  /** Record ID */
  id: string;
  /** Engagement ID */
  engagementId: number;
  /** Detection test ID this evidence belongs to */
  detectionTestId: string;
  /** Evidence type */
  type: "execution" | "detection" | "negative_detection" | "telemetry" | "timeline_correlation";
  /** Timestamp (UTC ms) */
  timestamp: number;
  /** Source side */
  side: "offensive" | "defensive" | "bilateral";
  /** Content */
  content: string;
  /** SHA-256 hash */
  contentHash: string;
  /** Chain hash (linked to previous record) */
  chainHash: string;
  /** Provenance */
  provenance: string;
  /** Operator/analyst who created this record */
  createdBy: string;
}

export interface UnifiedTimeline {
  /** Engagement ID */
  engagementId: number;
  /** All events sorted by timestamp */
  events: TimelineEvent[];
  /** Time synchronization metadata */
  timeSyncMetadata: {
    ntpSource: string;
    platformClockSkew: number;
    customerClockSkew: number;
    syncVerified: boolean;
  };
}

export interface TimelineEvent {
  /** Event timestamp (UTC ms) */
  timestamp: number;
  /** Event side */
  side: "offensive" | "defensive";
  /** Event type */
  type: "ttp_execution" | "detection_alert" | "soc_response" | "containment" | "escalation" | "negative_observation";
  /** MITRE technique ID (if applicable) */
  mitreId?: string;
  /** Description */
  description: string;
  /** Source system */
  source: string;
  /** Host */
  host?: string;
  /** Detection test ID (links offensive + defensive events) */
  detectionTestId: string;
  /** Evidence hash */
  evidenceHash: string;
}

// ─── Negative Evidence Model ───────────────────────────────────────────────

export interface NegativeEvidence {
  /** Detection test ID */
  detectionTestId: string;
  /** TTP that was executed */
  mitreId: string;
  /** Execution timestamp */
  executedAt: number;
  /** Grace period end */
  gracePeriodEnd: number;
  /** Observation: no detection within grace period */
  observationStatement: string;
  /** What indicators SHOULD have been produced */
  expectedIndicators: string[];
  /** What defensive products were active */
  activeDefensiveProducts: string[];
  /** Whether the customer confirmed no alert was generated */
  customerConfirmedNoAlert: boolean;
  /** Evidence hash */
  evidenceHash: string;
}

export function buildNegativeEvidence(test: DetectionTest, activeProducts: string[]): NegativeEvidence {
  return {
    detectionTestId: test.id,
    mitreId: test.mitreId,
    executedAt: test.executedAt,
    gracePeriodEnd: test.detectionWindowEnd,
    observationStatement: `TTP ${test.mitreId} (${test.mitreName}) was executed at ${new Date(test.executedAt).toISOString()} against ${test.targetHost}. No detection was observed within the ${Math.round((test.detectionWindowEnd - test.executedAt) / 60000)}-minute grace period ending at ${new Date(test.detectionWindowEnd).toISOString()}.`,
    expectedIndicators: test.expectedIndicators,
    activeDefensiveProducts: activeProducts,
    customerConfirmedNoAlert: false,
    evidenceHash: "",
  };
}

// ─── Unified Timeline Builder ──────────────────────────────────────────────

export function buildUnifiedTimeline(
  tests: DetectionTest[],
  ntpSource: string = "pool.ntp.org",
  platformSkew: number = 0,
  customerSkew: number = 0
): UnifiedTimeline {
  const events: TimelineEvent[] = [];

  for (const test of tests) {
    // Offensive event: TTP execution
    events.push({
      timestamp: test.executedAt,
      side: "offensive",
      type: "ttp_execution",
      mitreId: test.mitreId,
      description: `Executed ${test.mitreId} (${test.mitreName}) via ${test.executionMethod}`,
      source: "AC3 Platform",
      host: test.targetHost,
      detectionTestId: test.id,
      evidenceHash: test.evidenceHash || "",
    });

    // Defensive events from detection result
    if (test.detectionResult) {
      const dr = test.detectionResult;
      if (dr.detected && dr.timeToDetect !== undefined) {
        events.push({
          timestamp: test.executedAt + dr.timeToDetect,
          side: "defensive",
          type: "detection_alert",
          mitreId: test.mitreId,
          description: `${dr.detectedBy.join(", ")} detected ${test.mitreId}: ${dr.alertTitle || "Alert triggered"}`,
          source: dr.detectedBy.join(", "),
          host: test.targetHost,
          detectionTestId: test.id,
          evidenceHash: "",
        });
      }
      if (dr.timeToRespond !== undefined) {
        events.push({
          timestamp: test.executedAt + dr.timeToRespond,
          side: "defensive",
          type: "containment",
          mitreId: test.mitreId,
          description: `Containment action: ${dr.containmentAction || "Response initiated"}`,
          source: "SOC",
          host: test.targetHost,
          detectionTestId: test.id,
          evidenceHash: "",
        });
      }
      if (!dr.detected) {
        events.push({
          timestamp: test.detectionWindowEnd,
          side: "defensive",
          type: "negative_observation",
          mitreId: test.mitreId,
          description: `No detection observed for ${test.mitreId} within grace period`,
          source: "Observation",
          host: test.targetHost,
          detectionTestId: test.id,
          evidenceHash: "",
        });
      }
    }
  }

  // Sort by timestamp
  events.sort((a, b) => a.timestamp - b.timestamp);

  return {
    engagementId: tests[0]?.engagementId || 0,
    events,
    timeSyncMetadata: {
      ntpSource,
      platformClockSkew: platformSkew,
      customerClockSkew: customerSkew,
      syncVerified: Math.abs(platformSkew) < 1000 && Math.abs(customerSkew) < 1000,
    },
  };
}

// ─── Test Plan Generator ───────────────────────────────────────────────────

export function generateDefaultTestPlan(
  engagementId: number,
  operatorName: string,
  techniques: Array<{ mitreId: string; name: string; tactic: string }>,
  defensiveStack: DefensiveStackInventory
): PurpleTeamTestPlan {
  const now = Date.now();
  const version = `1.0.0-${Date.now()}`;

  return {
    id: `PT-${engagementId}-${Date.now()}`,
    version,
    engagementId,
    createdBy: operatorName,
    createdAt: now,
    lastModified: now,
    defensiveStack,
    detectionObjectives: [],
    exerciseWindow: {
      executionStart: now,
      executionEnd: now + 2 * 60 * 60 * 1000, // 2 hours default
      detectionObservationEnd: now + 26 * 60 * 60 * 1000, // 24hr observation after 2hr execution
    },
    techniques: techniques.map((t, i) => ({
      mitreId: t.mitreId,
      name: t.name,
      tactic: t.tactic,
      executionMethod: "TBD",
      targets: [],
      expectedIndicators: [],
      detectionCapabilityTested: "",
      authorized: false,
      approvedEvasionTechniques: [],
      executionOrder: i + 1,
      dependencies: [],
      estimatedDurationMs: 300000, // 5 min default
    })),
    successCriteria: [
      {
        id: "SC-001",
        description: "Overall detection rate exceeds 80%",
        metricType: "detection_rate",
        targetValue: 80,
        unit: "percentage",
        scope: "all",
      },
      {
        id: "SC-002",
        description: "Mean time to alert under 15 minutes",
        metricType: "time_to_alert",
        targetValue: 15,
        unit: "minutes",
        scope: "all",
      },
    ],
    vendorNotification: {
      required: true,
      confirmed: false,
    },
    replayability: {
      testPlanVersion: version,
      edrCatalogVersion: "1.0.0",
      platformVersion: "1.0.0",
      techniqueParamSnapshots: {},
      defensiveStackSnapshot: defensiveStack,
      ntpTimeSource: "pool.ntp.org",
      clockSkewDetected: 0,
    },
  };
}
