/**
 * roe-document-parser.ts — RoE / Test Plan Document Parser
 * ═══════════════════════════════════════════════════════════
 * Accepts uploaded Word (.docx) and PDF documents containing approved
 * Rules of Engagement, Penetration Test Plans, or Red Team Test Plans.
 *
 * Pipeline:
 *   1. Text Extraction  — mammoth (docx) / pdf-parse (PDF)
 *   2. LLM Parsing       — structured extraction of engagement params,
 *                          POCs, comms protocols, scope, methodology
 *   3. Validation        — sanity checks on extracted data
 *   4. Persistence       — store parsed data + link to uploaded doc record
 *
 * The parsed output feeds directly into the auto-engagement designer
 * (roe-auto-engagement.ts) to create a fully-configured engagement.
 */

import { invokeLLM } from "./_core/llm";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface ParsedPersonnel {
  name: string;
  role: string;
  title?: string;
  organization?: string;
  email?: string;
  phone?: string;
  alternatePhone?: string;
  clearanceLevel?: string;
  isPrimary?: boolean;
}

export interface ParsedCommsProtocol {
  reportingCadence?: string;
  reportingMethod?: string;
  reportingRecipients?: string[];
  emergencyHaltProcedure?: string;
  deconflictionProcedure?: string;
  deconflictionContacts?: Array<{ name: string; phone?: string; email?: string; role?: string }>;
  deconflictionPhone?: string;
  deconflictionEmail?: string;
  escalationChain?: Array<{ level: number; contact: string; role?: string; phone?: string; email?: string; timeframe?: string }>;
  escalationTimeframe?: string;
  criticalFindingNotifyWithin?: string;
  criticalFindingNotifyMethod?: string;
  criticalFindingNotifyRecipients?: string[];
  testingWindowStart?: string;
  testingWindowEnd?: string;
  testingDays?: string[];
  testTimezone?: string;
  blackoutPeriods?: Array<{ start: string; end: string; reason?: string }>;
  statusCheckInFrequency?: string;
  statusCheckInMethod?: string;
  rawCommsSection?: string;
}

export interface ParsedScope {
  inScopeDomains?: string[];
  outOfScopeDomains?: string[];
  inScopeIpRanges?: string[];
  outOfScopeIpRanges?: string[];
  inScopeApplications?: string[];
  outOfScopeApplications?: string[];
  inScopePorts?: string[];
  outOfScopePorts?: string[];
  allowedTestingTypes?: string[];
  disallowedTestingTypes?: string[];
  allowedAttackVectors?: string[];
  disallowedAttackVectors?: string[];
  dosAllowed?: boolean;
  socialEngineeringAllowed?: boolean;
  physicalAllowed?: boolean;
  wirelessAllowed?: boolean;
  pivotingAllowed?: boolean;
  exfiltrationAllowed?: boolean;
  persistenceAllowed?: boolean;
  fileModificationAllowed?: boolean;
  credentialedTesting?: boolean;
  testingStartDate?: string;
  testingEndDate?: string;
  rawScopeSection?: string;
}

export interface ParsedEngagementParams {
  engagementName?: string;
  customerName?: string;
  testingFirmName?: string;
  engagementType?: 'red_team' | 'pentest' | 'purple_team' | 'phishing' | 'tabletop' | 'bug_bounty';
  description?: string;
  purpose?: string;
  methodology?: string;
  assumptions?: string;
  limitations?: string;
  risks?: string;
  startDate?: string;
  endDate?: string;
  targetDomains?: string[];
  targetIpRanges?: string[];
  phishingDomain?: string;
  // Legal / compliance
  legalJurisdiction?: string;
  ndaRequired?: boolean;
  ndaReference?: string;
  complianceFrameworks?: string[];
  liabilityWaiver?: string;
  // Evidence handling
  dataHandlingProcedure?: string;
  evidenceRetentionDays?: number;
  evidenceEncryptionRequired?: boolean;
  piiHandlingPolicy?: string;
  evidenceDestructionMethod?: string;
  // Report deliverables
  reportDeliverables?: string[];
  reportFrequency?: string;
  // FedRAMP specific
  fedrampCompliant?: boolean;
  fedrampImpactLevel?: string;
  serviceModel?: string;
  // Organization info
  organizationName?: string;
  organizationAddress?: string;
  testingFirmAddress?: string;
}

export interface ParsedRoeDocument {
  documentType: 'roe' | 'pentest_plan' | 'red_team_plan' | 'bug_bounty_scope' | 'purple_team_plan' | 'unknown';
  engagement: ParsedEngagementParams;
  personnel: ParsedPersonnel[];
  commsProtocol: ParsedCommsProtocol;
  scope: ParsedScope;
  confidence: number;
  warnings: string[];
  rawTextLength: number;
}

// ─── Text Extraction ────────────────────────────────────────────────────────

/**
 * Extract text from a Word (.docx) file buffer.
 */
export async function extractTextFromDocx(buffer: Buffer): Promise<string> {
  const mammoth = await import("mammoth");
  const result = await mammoth.extractRawText({ buffer });
  return result.value;
}

/**
 * Extract text from a PDF file buffer.
 */
export async function extractTextFromPdf(buffer: Buffer): Promise<string> {
  const pdfParse = (await import("pdf-parse")).default;
  const result = await pdfParse(buffer);
  return result.text;
}

/**
 * Extract text from a document buffer based on MIME type.
 */
export async function extractText(buffer: Buffer, mimeType: string): Promise<string> {
  if (mimeType === "application/pdf") {
    return extractTextFromPdf(buffer);
  }
  if (
    mimeType === "application/vnd.openxmlformats-officedocument.wordprocessingml.document" ||
    mimeType === "application/msword"
  ) {
    return extractTextFromDocx(buffer);
  }
  throw new Error(`Unsupported document type: ${mimeType}. Only PDF and Word (.docx) files are supported.`);
}

// ─── LLM-Powered Structured Extraction ──────────────────────────────────────

const ROE_EXTRACTION_SYSTEM_PROMPT = `You are an expert cybersecurity document analyst specializing in Rules of Engagement (RoE), Penetration Test Plans, and Red Team Test Plans.

Your task is to extract structured data from the provided document text. The document may be a military-style RoE, a commercial penetration test plan, a red team assessment plan, a bug bounty scope document, or a purple team exercise plan.

You MUST extract ALL of the following categories:

1. **Document Type**: Classify as roe, pentest_plan, red_team_plan, bug_bounty_scope, purple_team_plan, or unknown.

2. **Engagement Parameters**: Name, customer/organization, testing firm, type, description, purpose, methodology, assumptions, limitations, risks, dates, target domains/IPs, legal/compliance info, evidence handling, report deliverables, FedRAMP details.

3. **Personnel / Points of Contact**: Extract EVERY person mentioned with their name, role, title, organization, email, phone, alternate phone, clearance level. Map roles to: system_owner, ciso, cio, isso, authorizing_official, trusted_agent, test_lead, test_member, emergency_contact, legal_counsel, third_party_poc, incident_response_lead, customer_poc, project_manager. If a role doesn't match exactly, use the closest match.

4. **Communications Protocols**: Reporting cadence/method/recipients, emergency halt procedure, deconfliction procedure/contacts/phone/email, escalation chain (ordered by level with contacts and timeframes), critical finding notification requirements (timeframe, method, recipients), testing windows (start/end times, days, timezone), blackout periods, status check-in frequency/method. This section is CRITICAL — customers pay for specific comms protocols and they MUST be enforced.

5. **Scope**: In-scope and out-of-scope domains, IP ranges, applications, ports. Allowed and disallowed testing types and attack vectors. Specific permissions (DoS, social engineering, physical, wireless, pivoting, exfiltration, persistence, file modification, credentialed testing). Testing date boundaries.

**CRITICAL — Testing Permission Extraction Rules:**
- For each boolean permission field (dosAllowed, socialEngineeringAllowed, physicalAllowed, wirelessAllowed, pivotingAllowed, exfiltrationAllowed, persistenceAllowed, fileModificationAllowed, credentialedTesting), you MUST determine whether the document ALLOWS or DENIES that activity.
- Look for explicit statements like "authorized to perform", "permitted", "in scope", "will include", "testing will encompass" as indicators of ALLOWED (true).
- Look for explicit statements like "prohibited", "not authorized", "excluded", "will not perform", "out of scope" as indicators of DENIED (false).
- For Red Team plans: If the methodology describes performing lateral movement, credential harvesting, persistence mechanisms, data exfiltration simulation, or social engineering campaigns as part of the test plan objectives or phases, those permissions should be set to TRUE even if not stated in a separate "permissions" section.
- For Red Team plans: Activities described in threat emulation scenarios, kill chain phases, or ATT&CK technique mappings indicate those activities ARE authorized.
- Default assumption: If a Red Team plan describes performing an activity as part of its methodology but does not explicitly prohibit it, set the permission to TRUE.
- Only set a permission to FALSE if the document explicitly states that activity is prohibited, restricted, or out of scope.
- DoS testing is almost always explicitly prohibited — default to false unless clearly authorized.
- Physical and wireless testing require explicit authorization — default to false unless clearly stated.

Be thorough. If information is present in the document, extract it. If information is not present, omit the field (do not guess). Pay special attention to:
- Phone numbers and email addresses for all contacts
- Escalation chains with specific timeframes (e.g., "notify within 15 minutes")
- Deconfliction procedures and contacts
- Testing windows and blackout periods
- Specific scope boundaries (what is explicitly allowed vs. prohibited)
- Testing activities described in methodology/phases that imply permission (e.g., "Phase 3: Lateral Movement" implies pivotingAllowed=true)`;

const ROE_EXTRACTION_USER_PROMPT = `Extract all structured data from the following document text. Return ONLY valid JSON matching this schema:

{
  "documentType": "roe|pentest_plan|red_team_plan|bug_bounty_scope|purple_team_plan|unknown",
  "engagement": {
    "engagementName": "string",
    "customerName": "string",
    "testingFirmName": "string",
    "engagementType": "red_team|pentest|purple_team|phishing|tabletop|bug_bounty",
    "description": "string",
    "purpose": "string",
    "methodology": "string",
    "assumptions": "string",
    "limitations": "string",
    "risks": "string",
    "startDate": "YYYY-MM-DD",
    "endDate": "YYYY-MM-DD",
    "targetDomains": ["domain1.com", "domain2.com"],
    "targetIpRanges": ["10.0.0.0/24"],
    "phishingDomain": "string or null",
    "legalJurisdiction": "string",
    "ndaRequired": true,
    "ndaReference": "string",
    "complianceFrameworks": ["NIST 800-53", "PCI-DSS"],
    "liabilityWaiver": "string",
    "dataHandlingProcedure": "string",
    "evidenceRetentionDays": 90,
    "evidenceEncryptionRequired": true,
    "piiHandlingPolicy": "string",
    "evidenceDestructionMethod": "secure_delete|physical_destruction|crypto_erase",
    "reportDeliverables": ["Executive Summary", "Technical Report", "Remediation Plan"],
    "reportFrequency": "daily|weekly|final_only",
    "fedrampCompliant": false,
    "fedrampImpactLevel": "low|moderate|high|not_applicable",
    "serviceModel": "iaas|paas|saas|hybrid|not_applicable",
    "organizationName": "string",
    "organizationAddress": "string",
    "testingFirmAddress": "string"
  },
  "personnel": [
    {
      "name": "John Smith",
      "role": "system_owner|ciso|cio|isso|authorizing_official|trusted_agent|test_lead|test_member|emergency_contact|legal_counsel|third_party_poc|incident_response_lead|customer_poc|project_manager",
      "title": "Chief Information Security Officer",
      "organization": "Acme Corp",
      "email": "john@acme.com",
      "phone": "+1-555-0100",
      "alternatePhone": "+1-555-0101",
      "clearanceLevel": "Secret",
      "isPrimary": true
    }
  ],
  "commsProtocol": {
    "reportingCadence": "Weekly status reports every Friday",
    "reportingMethod": "Encrypted email via PGP",
    "reportingRecipients": ["ciso@acme.com", "pm@acme.com"],
    "emergencyHaltProcedure": "Call deconfliction hotline, cease all testing immediately",
    "deconflictionProcedure": "Contact deconfliction POC before any high-risk action",
    "deconflictionContacts": [{"name": "Jane Doe", "phone": "+1-555-0200", "email": "jane@acme.com", "role": "SOC Manager"}],
    "deconflictionPhone": "+1-555-0200",
    "deconflictionEmail": "deconfliction@acme.com",
    "escalationChain": [
      {"level": 1, "contact": "Test Lead", "role": "test_lead", "phone": "+1-555-0100", "timeframe": "immediate"},
      {"level": 2, "contact": "CISO", "role": "ciso", "phone": "+1-555-0200", "timeframe": "within 15 minutes"},
      {"level": 3, "contact": "CIO", "role": "cio", "phone": "+1-555-0300", "timeframe": "within 1 hour"}
    ],
    "escalationTimeframe": "15 minutes between levels",
    "criticalFindingNotifyWithin": "4 hours",
    "criticalFindingNotifyMethod": "Phone call followed by encrypted email",
    "criticalFindingNotifyRecipients": ["ciso@acme.com"],
    "testingWindowStart": "08:00",
    "testingWindowEnd": "18:00",
    "testingDays": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"],
    "testTimezone": "America/New_York",
    "blackoutPeriods": [{"start": "2026-04-15", "end": "2026-04-17", "reason": "Quarterly maintenance window"}],
    "statusCheckInFrequency": "Daily at 09:00",
    "statusCheckInMethod": "Secure portal update"
  },
  "scope": {
    "inScopeDomains": ["acme.com", "*.acme.com"],
    "outOfScopeDomains": ["mail.acme.com"],
    "inScopeIpRanges": ["10.0.0.0/24", "192.168.1.0/24"],
    "outOfScopeIpRanges": ["10.0.0.1/32"],
    "inScopeApplications": ["Customer Portal", "Admin Dashboard"],
    "outOfScopeApplications": ["Production Database"],
    "inScopePorts": ["80", "443", "8080", "22"],
    "outOfScopePorts": [],
    "allowedTestingTypes": ["network_pentest", "web_app_pentest", "social_engineering"],
    "disallowedTestingTypes": ["physical_pentest"],
    "allowedAttackVectors": ["remote_network", "web_application", "phishing"],
    "disallowedAttackVectors": ["physical_access"],
    "dosAllowed": false,
    "socialEngineeringAllowed": true,
    "physicalAllowed": false,
    "wirelessAllowed": false,
    "pivotingAllowed": true,
    "exfiltrationAllowed": false,
    "persistenceAllowed": false,
    "fileModificationAllowed": false,
    "credentialedTesting": true,
    "testingStartDate": "2026-05-01",
    "testingEndDate": "2026-05-31"
  },
  "confidence": 85,
  "warnings": ["Could not determine exact testing window timezone"]
}

DOCUMENT TEXT:
`;

/**
 * Parse extracted document text using LLM to produce structured data.
 * Handles very long documents by truncating to ~120K chars (well within context window).
 */
export async function parseDocumentWithLLM(text: string): Promise<ParsedRoeDocument> {
  // Truncate very long documents while preserving beginning and end
  const MAX_LEN = 120000;
  let docText = text;
  if (text.length > MAX_LEN) {
    const halfLen = Math.floor(MAX_LEN / 2);
    docText = text.slice(0, halfLen) + "\n\n[... document truncated for processing ...]\n\n" + text.slice(-halfLen);
  }

  const response = await invokeLLM({
    messages: [
      { role: "system", content: ROE_EXTRACTION_SYSTEM_PROMPT },
      { role: "user", content: ROE_EXTRACTION_USER_PROMPT + docText },
    ],
    response_format: {
      type: "json_schema",
      json_schema: {
        name: "roe_extraction",
        strict: false,
        schema: {
          type: "object",
          properties: {
            documentType: { type: "string" },
            engagement: { type: "object" },
            personnel: { type: "array", items: { type: "object" } },
            commsProtocol: { type: "object" },
            scope: { type: "object" },
            confidence: { type: "number" },
            warnings: { type: "array", items: { type: "string" } },
          },
          required: ["documentType", "engagement", "personnel", "commsProtocol", "scope", "confidence", "warnings"],
        },
      },
    },
    _caller: "roe-document-parser:parseDocumentWithLLM",
  } as any);

  const content = response.choices?.[0]?.message?.content;
  if (!content) {
    throw new Error("LLM returned empty response during document parsing");
  }

  const parsed = JSON.parse(content) as ParsedRoeDocument;
  parsed.rawTextLength = text.length;

  // Validate and clean up
  return validateParsedDocument(parsed);
}

// ─── Validation ─────────────────────────────────────────────────────────────

const VALID_ROLES = new Set([
  'system_owner', 'ciso', 'cio', 'isso', 'authorizing_official',
  'trusted_agent', 'test_lead', 'test_member', 'emergency_contact',
  'legal_counsel', 'third_party_poc', 'incident_response_lead',
  'customer_poc', 'project_manager',
]);

const VALID_DOC_TYPES = new Set([
  'roe', 'pentest_plan', 'red_team_plan', 'bug_bounty_scope', 'purple_team_plan', 'unknown',
]);

const VALID_ENGAGEMENT_TYPES = new Set([
  'red_team', 'pentest', 'purple_team', 'phishing', 'tabletop', 'bug_bounty',
]);

/**
 * Validate and clean up parsed document data.
 * Fixes common LLM output issues (wrong enum values, missing fields).
 */
export function validateParsedDocument(parsed: ParsedRoeDocument): ParsedRoeDocument {
  const warnings = [...(parsed.warnings || [])];

  // Validate document type
  if (!VALID_DOC_TYPES.has(parsed.documentType)) {
    warnings.push(`Invalid document type "${parsed.documentType}", defaulting to "unknown"`);
    parsed.documentType = 'unknown';
  }

  // Validate engagement type
  if (parsed.engagement?.engagementType && !VALID_ENGAGEMENT_TYPES.has(parsed.engagement.engagementType)) {
    // Try to map common variations
    const typeMap: Record<string, ParsedEngagementParams['engagementType']> = {
      'penetration_test': 'pentest',
      'penetration_testing': 'pentest',
      'pen_test': 'pentest',
      'red_teaming': 'red_team',
      'redteam': 'red_team',
      'purple_teaming': 'purple_team',
      'purpleteam': 'purple_team',
      'social_engineering': 'phishing',
      'bug_bounty_program': 'bug_bounty',
      'tabletop_exercise': 'tabletop',
    };
    const mapped = typeMap[parsed.engagement.engagementType.toLowerCase()];
    if (mapped) {
      parsed.engagement.engagementType = mapped;
    } else {
      warnings.push(`Could not map engagement type "${parsed.engagement.engagementType}", defaulting to "pentest"`);
      parsed.engagement.engagementType = 'pentest';
    }
  }

  // Validate personnel roles
  if (Array.isArray(parsed.personnel)) {
    for (const person of parsed.personnel) {
      if (person.role && !VALID_ROLES.has(person.role)) {
        // Try to map common role variations
        const roleMap: Record<string, string> = {
          'cto': 'ciso',
          'security_officer': 'isso',
          'information_security_officer': 'isso',
          'chief_security_officer': 'ciso',
          'lead_tester': 'test_lead',
          'tester': 'test_member',
          'pen_tester': 'test_member',
          'red_team_lead': 'test_lead',
          'red_team_member': 'test_member',
          'client_poc': 'customer_poc',
          'client_contact': 'customer_poc',
          'primary_contact': 'customer_poc',
          'technical_contact': 'customer_poc',
          'executive_sponsor': 'authorizing_official',
          'sponsor': 'authorizing_official',
          'attorney': 'legal_counsel',
          'lawyer': 'legal_counsel',
          'ir_lead': 'incident_response_lead',
          'soc_manager': 'incident_response_lead',
          'soc_lead': 'incident_response_lead',
          'vendor_poc': 'third_party_poc',
          'third_party_contact': 'third_party_poc',
          'pm': 'project_manager',
        };
        const mapped = roleMap[person.role.toLowerCase().replace(/\s+/g, '_')];
        if (mapped) {
          person.role = mapped;
        } else {
          warnings.push(`Unknown personnel role "${person.role}" for ${person.name}, defaulting to "customer_poc"`);
          person.role = 'customer_poc';
        }
      }
    }
  } else {
    parsed.personnel = [];
    warnings.push("No personnel/contacts found in document");
  }

  // Ensure arrays are arrays
  const ensureArray = (val: any): string[] => {
    if (Array.isArray(val)) return val.filter(v => typeof v === 'string' && v.trim());
    if (typeof val === 'string') return val.split(/[,;\n]+/).map(s => s.trim()).filter(Boolean);
    return [];
  };

  if (parsed.scope) {
    parsed.scope.inScopeDomains = ensureArray(parsed.scope.inScopeDomains);
    parsed.scope.outOfScopeDomains = ensureArray(parsed.scope.outOfScopeDomains);
    parsed.scope.inScopeIpRanges = ensureArray(parsed.scope.inScopeIpRanges);
    parsed.scope.outOfScopeIpRanges = ensureArray(parsed.scope.outOfScopeIpRanges);
    parsed.scope.inScopeApplications = ensureArray(parsed.scope.inScopeApplications);
    parsed.scope.outOfScopeApplications = ensureArray(parsed.scope.outOfScopeApplications);
  } else {
    parsed.scope = {};
    warnings.push("No scope information found in document");
  }

  if (!parsed.commsProtocol) {
    parsed.commsProtocol = {};
    warnings.push("No communications protocol information found in document");
  }

  if (!parsed.engagement) {
    parsed.engagement = {};
    warnings.push("No engagement parameters found in document");
  }

  // Validate confidence is a reasonable number
  if (typeof parsed.confidence !== 'number' || parsed.confidence < 0 || parsed.confidence > 100) {
    parsed.confidence = 50;
  }

  parsed.warnings = warnings;
  return parsed;
}

// ─── Full Pipeline ──────────────────────────────────────────────────────────

/**
 * Full document parsing pipeline:
 * 1. Extract text from document buffer
 * 2. Parse with LLM
 * 3. Validate and return structured data
 */
export async function parseRoeDocument(
  buffer: Buffer,
  mimeType: string,
  filename: string,
): Promise<{ text: string; parsed: ParsedRoeDocument }> {
  console.log(`[RoeParser] Starting parse of "${filename}" (${mimeType}, ${buffer.length} bytes)`);

  // Step 1: Extract text
  const text = await extractText(buffer, mimeType);
  console.log(`[RoeParser] Extracted ${text.length} chars from "${filename}"`);

  if (text.length < 100) {
    throw new Error(`Document "${filename}" appears to be empty or could not be read (only ${text.length} chars extracted)`);
  }

  // Step 2: LLM parsing
  const parsed = await parseDocumentWithLLM(text);
  console.log(`[RoeParser] Parsed "${filename}": type=${parsed.documentType}, personnel=${parsed.personnel.length}, confidence=${parsed.confidence}%`);

  // Step 3: Log warnings
  if (parsed.warnings.length > 0) {
    console.warn(`[RoeParser] Warnings for "${filename}": ${parsed.warnings.join("; ")}`);
  }

  return { text, parsed };
}

// ─── DB Persistence ─────────────────────────────────────────────────────────

/**
 * Persist an uploaded document record to the database.
 */
export async function persistUploadedDocument(params: {
  filename: string;
  mimeType: string;
  fileSize: number;
  storageUrl: string;
  storageKey: string;
  documentType: string;
  extractedText: string;
  parsedData: ParsedRoeDocument;
  uploadedBy: number;
}): Promise<number> {
  const { getDb } = await import("./db");
  const db = await getDb();
  if (!db) throw new Error("Database not available");

  const { uploadedRoeDocuments } = await import("../drizzle/schema");

  const result = await db.insert(uploadedRoeDocuments).values({
    filename: params.filename,
    mimeType: params.mimeType,
    fileSize: params.fileSize,
    storageUrl: params.storageUrl,
    storageKey: params.storageKey,
    documentType: params.documentType as any,
    extractedText: params.extractedText,
    extractedTextLength: params.extractedText.length,
    parsedData: params.parsedData as any,
    parseStatus: 'parsed' as any,
    parsedAt: new Date().toISOString(),
    uploadedBy: params.uploadedBy,
  });

  const insertId = (result as any)[0]?.insertId ?? (result as any).insertId;
  console.log(`[RoeParser] Persisted uploaded doc #${insertId}: "${params.filename}"`);
  return insertId;
}

/**
 * Update the uploaded document record with created engagement/RoE links.
 */
export async function linkUploadedDocToEngagement(
  uploadedDocId: number,
  engagementId: number,
  roeDocumentId: number,
): Promise<void> {
  const { getDb } = await import("./db");
  const db = await getDb();
  if (!db) return;

  const { uploadedRoeDocuments } = await import("../drizzle/schema");
  const { eq } = await import("drizzle-orm");

  await db.update(uploadedRoeDocuments)
    .set({
      createdEngagementId: engagementId,
      createdRoeDocumentId: roeDocumentId,
    })
    .where(eq(uploadedRoeDocuments.id, uploadedDocId));
}

/**
 * Mark an uploaded document as failed.
 */
export async function markUploadedDocFailed(
  uploadedDocId: number,
  error: string,
): Promise<void> {
  const { getDb } = await import("./db");
  const db = await getDb();
  if (!db) return;

  const { uploadedRoeDocuments } = await import("../drizzle/schema");
  const { eq } = await import("drizzle-orm");

  await db.update(uploadedRoeDocuments)
    .set({
      parseStatus: 'failed' as any,
      parseError: error,
    })
    .where(eq(uploadedRoeDocuments.id, uploadedDocId));
}
