/**
 * roe-auto-engagement.ts — Auto-Engagement Designer
 * ═══════════════════════════════════════════════════
 * Takes parsed RoE/Test Plan document data and auto-creates:
 *   1. A fully-configured engagement
 *   2. A populated RoE document (with all 60+ fields)
 *   3. All personnel/POC records
 *   4. Communications protocol record
 *   5. Scope constraint record
 *   6. Links the roeScopeGuard for hard enforcement
 *
 * The result is a complete engagement that enforces the contracted
 * scope and RoE as guardrails throughout its lifecycle.
 */

import type { ParsedRoeDocument, ParsedPersonnel, ParsedCommsProtocol, ParsedScope, ParsedEngagementParams } from "./roe-document-parser";
import { linkUploadedDocToEngagement } from "./roe-document-parser";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface AutoEngagementResult {
  engagementId: number;
  roeDocumentId: number;
  personnelCreated: number;
  commsProtocolId: number | null;
  scopeConstraintId: number | null;
  warnings: string[];
}

// ─── Main Auto-Designer ─────────────────────────────────────────────────────

/**
 * Auto-design and create a complete engagement from parsed document data.
 * This is the main entry point called after document parsing completes.
 */
export async function autoDesignEngagement(
  parsed: ParsedRoeDocument,
  uploadedDocId: number,
  userId: number,
): Promise<AutoEngagementResult> {
  const warnings: string[] = [...parsed.warnings];
  const { getDb } = await import("./db");
  const db = await getDb();
  if (!db) throw new Error("Database not available");

  // ─── Step 1: Create the RoE Document ────────────────────────────────────
  const roeDocumentId = await createRoeDocumentFromParsed(parsed, userId);
  console.log(`[AutoEngagement] Created RoE document #${roeDocumentId}`);

  // ─── Step 2: Add Personnel to RoE ──────────────────────────────────────
  const personnelCreated = await addPersonnelFromParsed(parsed.personnel, roeDocumentId);
  console.log(`[AutoEngagement] Added ${personnelCreated} personnel to RoE #${roeDocumentId}`);

  // ─── Step 3: Create the Engagement ─────────────────────────────────────
  const engagementId = await createEngagementFromParsed(parsed, roeDocumentId, userId);
  console.log(`[AutoEngagement] Created engagement #${engagementId}`);

  // ─── Step 4: Create Comms Protocol ─────────────────────────────────────
  let commsProtocolId: number | null = null;
  if (parsed.commsProtocol && Object.keys(parsed.commsProtocol).length > 0) {
    commsProtocolId = await createCommsProtocol(parsed.commsProtocol, engagementId, roeDocumentId, uploadedDocId);
    console.log(`[AutoEngagement] Created comms protocol #${commsProtocolId}`);
  } else {
    warnings.push("No communications protocol extracted — add manually in engagement settings");
  }

  // ─── Step 5: Create Scope Constraints ──────────────────────────────────
  let scopeConstraintId: number | null = null;
  if (parsed.scope && Object.keys(parsed.scope).length > 0) {
    scopeConstraintId = await createScopeConstraints(parsed.scope, engagementId, roeDocumentId, uploadedDocId);
    console.log(`[AutoEngagement] Created scope constraints #${scopeConstraintId}`);
  } else {
    warnings.push("No scope constraints extracted — add manually in engagement settings");
  }

  // ─── Step 6: Set roeScopeGuard on Engagement Ops State ─────────────────
  await setRoeScopeGuard(engagementId, parsed.scope, roeDocumentId);

  // ─── Step 7: Link uploaded doc to created entities ─────────────────────
  await linkUploadedDocToEngagement(uploadedDocId, engagementId, roeDocumentId);

  // ─── Step 8: Log the auto-creation ─────────────────────────────────────
  const { logActivity } = await import("./db");
  await logActivity({
    userId,
    action: 'engagement_auto_created',
    details: `Auto-created engagement #${engagementId} from uploaded document #${uploadedDocId} (RoE #${roeDocumentId}, ${personnelCreated} personnel, comms: ${commsProtocolId ? 'yes' : 'no'}, scope: ${scopeConstraintId ? 'yes' : 'no'})`,
  });

  return {
    engagementId,
    roeDocumentId,
    personnelCreated,
    commsProtocolId,
    scopeConstraintId,
    warnings,
  };
}

// ─── Sub-Functions ──────────────────────────────────────────────────────────

/**
 * Create a fully-populated RoE document from parsed data.
 */
async function createRoeDocumentFromParsed(
  parsed: ParsedRoeDocument,
  userId: number,
): Promise<number> {
  const { getDb } = await import("./db");
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  const { roeDocuments } = await import("../drizzle/schema");

  const eng = parsed.engagement;
  const scope = parsed.scope;
  const comms = parsed.commsProtocol;

  const title = eng.engagementName
    ? `RoE — ${eng.engagementName}`
    : `RoE — ${eng.customerName || 'Imported'} ${eng.engagementType || 'Assessment'}`;

  const [result] = await db.insert(roeDocuments).values({
    title,
    status: 'draft',
    version: '1.0',
    organizationName: eng.organizationName || eng.customerName || null,
    organizationAddress: eng.organizationAddress || null,
    testingFirmName: eng.testingFirmName || 'AC3 — AceofCloud',
    testingFirmAddress: eng.testingFirmAddress || null,
    purpose: eng.purpose || eng.description || null,
    methodology: eng.methodology || null,
    assumptions: eng.assumptions || null,
    limitations: eng.limitations || null,
    risks: eng.risks || null,
    // Scope
    inScopeDomains: scope?.inScopeDomains?.length ? scope.inScopeDomains : null,
    outOfScopeDomains: scope?.outOfScopeDomains?.length ? scope.outOfScopeDomains : null,
    inScopeIpRanges: scope?.inScopeIpRanges?.length ? scope.inScopeIpRanges : null,
    outOfScopeIpRanges: scope?.outOfScopeIpRanges?.length ? scope.outOfScopeIpRanges : null,
    inScopeApplications: scope?.inScopeApplications?.length ? scope.inScopeApplications : null,
    cloudEnvironments: null,
    wirelessNetworks: null,
    physicalLocations: null,
    // Testing types & vectors
    testingTypes: scope?.allowedTestingTypes?.length ? scope.allowedTestingTypes : null,
    attackVectors: scope?.allowedAttackVectors?.length ? scope.allowedAttackVectors : null,
    socialEngineeringPretexts: null,
    // Permissions
    dosTestingAllowed: scope?.dosAllowed ? 1 : 0,
    physicalTestingAllowed: scope?.physicalAllowed ? 1 : 0,
    wirelessTestingAllowed: scope?.wirelessAllowed ? 1 : 0,
    socialEngineeringAllowed: scope?.socialEngineeringAllowed ? 1 : 0,
    credentialedTesting: scope?.credentialedTesting ? 1 : 0,
    fileModificationAllowed: scope?.fileModificationAllowed ? 1 : 0,
    fileInstallationAllowed: 0,
    pivotingAllowed: scope?.pivotingAllowed !== false ? 1 : 0,
    exfiltrationAllowed: scope?.exfiltrationAllowed ? 1 : 0,
    persistenceAllowed: scope?.persistenceAllowed ? 1 : 0,
    shunningPolicy: 'notify_first',
    // Testing window
    testingStartDate: scope?.testingStartDate || eng.startDate || null,
    testingEndDate: scope?.testingEndDate || eng.endDate || null,
    testingDays: comms?.testingDays?.length ? comms.testingDays : ["monday", "tuesday", "wednesday", "thursday", "friday"],
    testTimezone: comms?.testTimezone || "America/New_York",
    testingWindowStart: comms?.testingWindowStart || null,
    testingWindowEnd: comms?.testingWindowEnd || null,
    blackoutPeriods: comms?.blackoutPeriods?.length ? comms.blackoutPeriods : null,
    // Communications
    communicationFrequency: comms?.statusCheckInFrequency || 'daily',
    communicationMethod: comms?.statusCheckInMethod || 'secure_portal',
    statusReportFrequency: comms?.reportingCadence || 'daily',
    emergencyHaltCriteria: comms?.emergencyHaltProcedure || null,
    incidentResponseProcedure: null,
    resumptionProcedure: null,
    criticalFindingNotification: comms?.criticalFindingNotifyMethod
      ? `Notify within ${comms.criticalFindingNotifyWithin || '24 hours'} via ${comms.criticalFindingNotifyMethod}`
      : null,
    // Evidence & data handling
    dataHandlingProcedure: eng.dataHandlingProcedure || null,
    evidenceRetentionDays: eng.evidenceRetentionDays || 90,
    evidenceEncryptionRequired: eng.evidenceEncryptionRequired !== false ? 1 : 0,
    piiHandlingPolicy: eng.piiHandlingPolicy || null,
    evidenceDestructionMethod: (eng.evidenceDestructionMethod as any) || 'secure_delete',
    // Report
    reportDeliverables: eng.reportDeliverables?.length ? eng.reportDeliverables : null,
    reportFrequency: (eng.reportFrequency as any) || 'final_only',
    // Legal
    legalJurisdiction: eng.legalJurisdiction || null,
    liabilityWaiver: eng.liabilityWaiver || null,
    ndaRequired: eng.ndaRequired !== false ? 1 : 0,
    ndaReference: eng.ndaReference || null,
    complianceFrameworks: eng.complianceFrameworks?.length ? eng.complianceFrameworks : null,
    // FedRAMP
    fedrampCompliant: eng.fedrampCompliant ? 1 : 0,
    fedrampImpactLevel: (eng.fedrampImpactLevel as any) || 'not_applicable',
    serviceModel: (eng.serviceModel as any) || 'not_applicable',
    // Audit
    createdBy: userId,
    lastModifiedBy: userId,
  });

  return (result as any).insertId;
}

/**
 * Add all personnel/POCs from parsed data to the RoE document.
 */
async function addPersonnelFromParsed(
  personnel: ParsedPersonnel[],
  roeDocumentId: number,
): Promise<number> {
  if (!personnel || personnel.length === 0) return 0;

  const { getDb } = await import("./db");
  const db = await getDb();
  if (!db) return 0;
  const { roePersonnel } = await import("../drizzle/schema");

  let count = 0;
  for (const person of personnel) {
    try {
      await db.insert(roePersonnel).values({
        roeId: roeDocumentId,
        role: person.role as any,
        name: person.name,
        title: person.title || null,
        organization: person.organization || null,
        email: person.email || null,
        phone: person.phone || null,
        alternatePhone: person.alternatePhone || null,
        clearanceLevel: person.clearanceLevel || null,
        isPrimary: person.isPrimary ? 1 : 0,
      });
      count++;
    } catch (err) {
      console.warn(`[AutoEngagement] Failed to add personnel "${person.name}": ${err}`);
    }
  }
  return count;
}

/**
 * Create the engagement record from parsed data.
 */
async function createEngagementFromParsed(
  parsed: ParsedRoeDocument,
  roeDocumentId: number,
  userId: number,
): Promise<number> {
  const { createEngagement } = await import("./db");
  const eng = parsed.engagement;
  const scope = parsed.scope;

  // Build target domains string (comma-separated)
  const targetDomains = [
    ...(eng.targetDomains || []),
    ...(scope?.inScopeDomains || []),
  ].filter((v, i, a) => a.indexOf(v) === i); // deduplicate

  const targetIps = [
    ...(eng.targetIpRanges || []),
    ...(scope?.inScopeIpRanges || []),
  ].filter((v, i, a) => a.indexOf(v) === i);

  // Map document type to engagement type
  let engagementType = eng.engagementType || 'pentest';
  if (parsed.documentType === 'red_team_plan') engagementType = 'red_team';
  if (parsed.documentType === 'purple_team_plan') engagementType = 'purple_team';
  if (parsed.documentType === 'bug_bounty_scope') engagementType = 'pentest';

  const engagementName = eng.engagementName
    || `${eng.customerName || 'Imported'} — ${engagementType.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}`;

  const id = await createEngagement({
    name: engagementName,
    customerName: eng.customerName || 'Imported Customer',
    description: eng.description || eng.purpose || `Auto-created from uploaded ${parsed.documentType.replace(/_/g, ' ')} document`,
    engagementType: engagementType as any,
    status: 'planning',
    startDate: eng.startDate ? new Date(eng.startDate) : undefined,
    endDate: eng.endDate ? new Date(eng.endDate) : undefined,
    targetDomain: targetDomains.join(', ') || undefined,
    targetIpRange: targetIps.join(', ') || undefined,
    phishingDomain: eng.phishingDomain || undefined,
    roeDocumentId,
    notes: `Auto-created from uploaded document. Confidence: ${parsed.confidence}%. ${parsed.warnings.length > 0 ? 'Warnings: ' + parsed.warnings.join('; ') : ''}`,
    createdBy: userId,
  } as any);

  // Update the engagement with RoE scope and status
  const { getDb } = await import("./db");
  const db = await getDb();
  if (db) {
    const { engagements } = await import("../drizzle/schema");
    const { eq } = await import("drizzle-orm");

    const roeScope: any = {
      inScope: targetDomains.map(d => ({ type: 'domain', value: d }))
        .concat(targetIps.map(ip => ({ type: 'ip_range', value: ip }))),
      outOfScope: [
        ...(scope?.outOfScopeDomains || []).map(d => ({ type: 'domain', value: d })),
        ...(scope?.outOfScopeIpRanges || []).map(ip => ({ type: 'ip_range', value: ip })),
      ],
      testingTypes: scope?.allowedTestingTypes || [],
      restrictions: {
        dosAllowed: scope?.dosAllowed || false,
        socialEngineeringAllowed: scope?.socialEngineeringAllowed || false,
        physicalAllowed: scope?.physicalAllowed || false,
        wirelessAllowed: scope?.wirelessAllowed || false,
        pivotingAllowed: scope?.pivotingAllowed !== false,
        exfiltrationAllowed: scope?.exfiltrationAllowed || false,
        persistenceAllowed: scope?.persistenceAllowed || false,
      },
    };

    await db.update(engagements)
      .set({
        roeScope,
        roeStatus: 'draft',
      })
      .where(eq(engagements.id, id));
  }

  return id;
}

/**
 * Create the communications protocol record.
 */
async function createCommsProtocol(
  comms: ParsedCommsProtocol,
  engagementId: number,
  roeDocumentId: number,
  uploadedDocId: number,
): Promise<number> {
  const { getDb } = await import("./db");
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  const { engagementCommsProtocols } = await import("../drizzle/schema");

  const [result] = await db.insert(engagementCommsProtocols).values({
    engagementId,
    roeDocumentId,
    uploadedDocId,
    reportingCadence: comms.reportingCadence || null,
    reportingMethod: comms.reportingMethod || null,
    reportingRecipients: comms.reportingRecipients?.length ? comms.reportingRecipients : null,
    emergencyHaltProcedure: comms.emergencyHaltProcedure || null,
    deconflictionProcedure: comms.deconflictionProcedure || null,
    deconflictionContacts: comms.deconflictionContacts?.length ? comms.deconflictionContacts : null,
    deconflictionPhone: comms.deconflictionPhone || null,
    deconflictionEmail: comms.deconflictionEmail || null,
    escalationChain: comms.escalationChain?.length ? comms.escalationChain : null,
    escalationTimeframe: comms.escalationTimeframe || null,
    criticalFindingNotifyWithin: comms.criticalFindingNotifyWithin || null,
    criticalFindingNotifyMethod: comms.criticalFindingNotifyMethod || null,
    criticalFindingNotifyRecipients: comms.criticalFindingNotifyRecipients?.length ? comms.criticalFindingNotifyRecipients : null,
    testingWindowStart: comms.testingWindowStart || null,
    testingWindowEnd: comms.testingWindowEnd || null,
    testingDays: comms.testingDays?.length ? comms.testingDays : null,
    testTimezone: comms.testTimezone || null,
    blackoutPeriods: comms.blackoutPeriods?.length ? comms.blackoutPeriods : null,
    statusCheckInFrequency: comms.statusCheckInFrequency || null,
    statusCheckInMethod: comms.statusCheckInMethod || null,
    rawCommsSection: comms.rawCommsSection || null,
  });

  return (result as any).insertId;
}

/**
 * Create the scope constraints record.
 */
async function createScopeConstraints(
  scope: ParsedScope,
  engagementId: number,
  roeDocumentId: number,
  uploadedDocId: number,
): Promise<number> {
  const { getDb } = await import("./db");
  const db = await getDb();
  if (!db) throw new Error("Database not available");
  const { engagementScopeConstraints } = await import("../drizzle/schema");

  const [result] = await db.insert(engagementScopeConstraints).values({
    engagementId,
    roeDocumentId,
    uploadedDocId,
    inScopeDomains: scope.inScopeDomains?.length ? scope.inScopeDomains : null,
    outOfScopeDomains: scope.outOfScopeDomains?.length ? scope.outOfScopeDomains : null,
    inScopeIpRanges: scope.inScopeIpRanges?.length ? scope.inScopeIpRanges : null,
    outOfScopeIpRanges: scope.outOfScopeIpRanges?.length ? scope.outOfScopeIpRanges : null,
    inScopeApplications: scope.inScopeApplications?.length ? scope.inScopeApplications : null,
    outOfScopeApplications: scope.outOfScopeApplications?.length ? scope.outOfScopeApplications : null,
    inScopePorts: scope.inScopePorts?.length ? scope.inScopePorts : null,
    outOfScopePorts: scope.outOfScopePorts?.length ? scope.outOfScopePorts : null,
    allowedTestingTypes: scope.allowedTestingTypes?.length ? scope.allowedTestingTypes : null,
    disallowedTestingTypes: scope.disallowedTestingTypes?.length ? scope.disallowedTestingTypes : null,
    allowedAttackVectors: scope.allowedAttackVectors?.length ? scope.allowedAttackVectors : null,
    disallowedAttackVectors: scope.disallowedAttackVectors?.length ? scope.disallowedAttackVectors : null,
    dosAllowed: scope.dosAllowed ? 1 : 0,
    socialEngineeringAllowed: scope.socialEngineeringAllowed ? 1 : 0,
    physicalAllowed: scope.physicalAllowed ? 1 : 0,
    wirelessAllowed: scope.wirelessAllowed ? 1 : 0,
    pivotingAllowed: scope.pivotingAllowed !== false ? 1 : 0,
    exfiltrationAllowed: scope.exfiltrationAllowed ? 1 : 0,
    persistenceAllowed: scope.persistenceAllowed ? 1 : 0,
    fileModificationAllowed: scope.fileModificationAllowed ? 1 : 0,
    credentialedTesting: scope.credentialedTesting ? 1 : 0,
    testingStartDate: scope.testingStartDate || null,
    testingEndDate: scope.testingEndDate || null,
    rawScopeSection: scope.rawScopeSection || null,
  });

  return (result as any).insertId;
}

/**
 * Set the roeScopeGuard on the engagement's ops state for hard enforcement.
 * This ensures that all active scanning is gated by the contracted scope.
 */
async function setRoeScopeGuard(
  engagementId: number,
  scope: ParsedScope | undefined,
  roeDocumentId: number,
): Promise<void> {
  if (!scope) return;

  try {
    const { getOpsState, initOpsState } = await import("./lib/engagement-orchestrator");

    // Get or create ops state
    let state = getOpsState(engagementId);
    if (!state) {
      state = initOpsState(engagementId, 'pentest');
    }

    // Set the roeScopeGuard
    state.roeScopeGuard = {
      authorizedDomains: [
        ...(scope.inScopeDomains || []),
      ],
      authorizedIps: [
        ...(scope.inScopeIpRanges || []),
      ],
      roeStatus: 'draft',
    };

    console.log(`[AutoEngagement] Set roeScopeGuard for engagement #${engagementId}: ${state.roeScopeGuard.authorizedDomains.length} domains, ${state.roeScopeGuard.authorizedIps.length} IPs`);
  } catch (err) {
    console.warn(`[AutoEngagement] Failed to set roeScopeGuard (non-fatal): ${err}`);
  }
}
