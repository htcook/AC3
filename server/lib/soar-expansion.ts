/**
 * SOAR Connector Expansion — P3 Gap Remediation
 * 
 * Extends the existing SOAR connector system with:
 * - Additional platforms (Shuffle, TheHive, ServiceNow SecOps, IBM QRadar SOAR)
 * - Playbook template library for automated response
 * - Automated finding forwarding with severity-based routing
 * - Bidirectional sync (inbound webhook parsing)
 * - Platform-specific payload formatters
 * - Connector health monitoring
 */

// ─── Platform Registry ──────────────────────────────────────────────────────

export type SoarPlatform =
  | "splunk_soar"
  | "cortex_xsoar"
  | "swimlane"
  | "tines"
  | "shuffle"
  | "thehive"
  | "servicenow_secops"
  | "qradar_soar"
  | "custom";

export interface PlatformConfig {
  id: SoarPlatform;
  displayName: string;
  vendor: string;
  authType: "api_key" | "oauth2" | "basic" | "token" | "webhook_secret";
  supportsInbound: boolean;
  supportsOutbound: boolean;
  supportsBidirectional: boolean;
  webhookFormat: "json" | "cef" | "leef" | "custom";
  documentationUrl: string;
  requiredFields: string[];
  optionalFields: string[];
}

export const PLATFORM_REGISTRY: PlatformConfig[] = [
  {
    id: "splunk_soar",
    displayName: "Splunk SOAR (Phantom)",
    vendor: "Splunk",
    authType: "token",
    supportsInbound: true,
    supportsOutbound: true,
    supportsBidirectional: true,
    webhookFormat: "json",
    documentationUrl: "https://docs.splunk.com/Documentation/SOARonprem",
    requiredFields: ["webhookUrl", "authToken"],
    optionalFields: ["containerLabel", "severity", "sensitivity"],
  },
  {
    id: "cortex_xsoar",
    displayName: "Palo Alto Cortex XSOAR",
    vendor: "Palo Alto Networks",
    authType: "api_key",
    supportsInbound: true,
    supportsOutbound: true,
    supportsBidirectional: true,
    webhookFormat: "json",
    documentationUrl: "https://xsoar.pan.dev/docs/reference/api",
    requiredFields: ["webhookUrl", "apiKey"],
    optionalFields: ["incidentType", "playbookId", "severity"],
  },
  {
    id: "swimlane",
    displayName: "Swimlane Turbine",
    vendor: "Swimlane",
    authType: "api_key",
    supportsInbound: true,
    supportsOutbound: true,
    supportsBidirectional: true,
    webhookFormat: "json",
    documentationUrl: "https://docs.swimlane.com/turbine",
    requiredFields: ["webhookUrl", "apiKey"],
    optionalFields: ["applicationId", "recordType"],
  },
  {
    id: "tines",
    displayName: "Tines",
    vendor: "Tines",
    authType: "webhook_secret",
    supportsInbound: true,
    supportsOutbound: true,
    supportsBidirectional: true,
    webhookFormat: "json",
    documentationUrl: "https://www.tines.com/docs",
    requiredFields: ["webhookUrl"],
    optionalFields: ["storyId", "webhookSecret"],
  },
  {
    id: "shuffle",
    displayName: "Shuffle Automation",
    vendor: "Shuffle (Open Source)",
    authType: "api_key",
    supportsInbound: true,
    supportsOutbound: true,
    supportsBidirectional: true,
    webhookFormat: "json",
    documentationUrl: "https://shuffler.io/docs",
    requiredFields: ["webhookUrl", "apiKey"],
    optionalFields: ["workflowId", "executionArgument"],
  },
  {
    id: "thehive",
    displayName: "TheHive Project",
    vendor: "StrangeBee (Open Source)",
    authType: "api_key",
    supportsInbound: true,
    supportsOutbound: true,
    supportsBidirectional: true,
    webhookFormat: "json",
    documentationUrl: "https://docs.strangebee.com/thehive",
    requiredFields: ["webhookUrl", "apiKey"],
    optionalFields: ["caseTemplate", "alertType", "severity"],
  },
  {
    id: "servicenow_secops",
    displayName: "ServiceNow Security Operations",
    vendor: "ServiceNow",
    authType: "oauth2",
    supportsInbound: true,
    supportsOutbound: true,
    supportsBidirectional: true,
    webhookFormat: "json",
    documentationUrl: "https://docs.servicenow.com/bundle/security-operations",
    requiredFields: ["webhookUrl", "clientId", "clientSecret", "instanceUrl"],
    optionalFields: ["assignmentGroup", "category", "priority"],
  },
  {
    id: "qradar_soar",
    displayName: "IBM QRadar SOAR (Resilient)",
    vendor: "IBM",
    authType: "api_key",
    supportsInbound: true,
    supportsOutbound: true,
    supportsBidirectional: true,
    webhookFormat: "json",
    documentationUrl: "https://www.ibm.com/docs/en/qradar-soar",
    requiredFields: ["webhookUrl", "apiKey", "orgId"],
    optionalFields: ["incidentType", "severity", "workspace"],
  },
  {
    id: "custom",
    displayName: "Custom Webhook",
    vendor: "Custom",
    authType: "webhook_secret",
    supportsInbound: true,
    supportsOutbound: true,
    supportsBidirectional: false,
    webhookFormat: "json",
    documentationUrl: "",
    requiredFields: ["webhookUrl"],
    optionalFields: ["authHeader", "customHeaders"],
  },
];

export function getPlatformConfig(platform: SoarPlatform): PlatformConfig | undefined {
  return PLATFORM_REGISTRY.find(p => p.id === platform);
}

// ─── Playbook Template Library ──────────────────────────────────────────────

export type PlaybookCategory =
  | "incident_response"
  | "finding_triage"
  | "vulnerability_management"
  | "threat_hunting"
  | "compliance"
  | "notification";

export interface PlaybookTemplate {
  id: string;
  name: string;
  category: PlaybookCategory;
  description: string;
  triggerType: "finding_created" | "scan_completed" | "severity_threshold" | "manual" | "scheduled";
  triggerCondition: Record<string, any>;
  actions: PlaybookAction[];
  compatiblePlatforms: SoarPlatform[];
  estimatedDuration: string;
}

export interface PlaybookAction {
  order: number;
  type: "create_incident" | "enrich_ioc" | "notify" | "block_ip" | "quarantine" | "scan" | "update_ticket" | "custom_webhook";
  label: string;
  config: Record<string, any>;
  onFailure: "continue" | "abort" | "retry";
}

export const PLAYBOOK_TEMPLATES: PlaybookTemplate[] = [
  {
    id: "PB-IR-001",
    name: "Critical Finding Auto-Escalation",
    category: "incident_response",
    description: "Automatically creates an incident in the SOAR platform when a critical-severity finding is validated. Includes IOC enrichment and team notification.",
    triggerType: "severity_threshold",
    triggerCondition: { minSeverity: "critical", requiresValidation: true },
    actions: [
      { order: 1, type: "create_incident", label: "Create SOAR Incident", config: { severity: "critical", assignToOnCall: true }, onFailure: "retry" },
      { order: 2, type: "enrich_ioc", label: "Enrich IOCs from Finding", config: { sources: ["shodan", "censys", "virustotal"] }, onFailure: "continue" },
      { order: 3, type: "notify", label: "Alert Team Lead", config: { channel: "slack", template: "critical_finding" }, onFailure: "continue" },
    ],
    compatiblePlatforms: ["splunk_soar", "cortex_xsoar", "swimlane", "thehive", "qradar_soar", "servicenow_secops"],
    estimatedDuration: "30s",
  },
  {
    id: "PB-IR-002",
    name: "High-Severity Finding Triage",
    category: "finding_triage",
    description: "Routes high-severity findings through a triage workflow: deduplication, enrichment, risk scoring, and assignment to the appropriate remediation team.",
    triggerType: "severity_threshold",
    triggerCondition: { minSeverity: "high" },
    actions: [
      { order: 1, type: "enrich_ioc", label: "Deduplicate & Enrich", config: { dedup: true, enrichSources: ["nvd", "cve"] }, onFailure: "continue" },
      { order: 2, type: "create_incident", label: "Create Triage Ticket", config: { severity: "high", autoAssign: true }, onFailure: "retry" },
      { order: 3, type: "update_ticket", label: "Attach Evidence", config: { attachScreenshots: true, attachRawOutput: true }, onFailure: "continue" },
    ],
    compatiblePlatforms: ["splunk_soar", "cortex_xsoar", "swimlane", "tines", "shuffle", "thehive", "servicenow_secops", "qradar_soar"],
    estimatedDuration: "45s",
  },
  {
    id: "PB-VM-001",
    name: "Vulnerability Remediation Tracking",
    category: "vulnerability_management",
    description: "Creates remediation tickets for validated vulnerabilities with SLA tracking. Automatically re-scans after the remediation window to verify fixes.",
    triggerType: "scan_completed",
    triggerCondition: { scanType: "vulnerability", hasFindings: true },
    actions: [
      { order: 1, type: "create_incident", label: "Create Remediation Tickets", config: { perFinding: true, setSLA: true }, onFailure: "retry" },
      { order: 2, type: "notify", label: "Notify Asset Owners", config: { template: "remediation_required" }, onFailure: "continue" },
      { order: 3, type: "scan", label: "Schedule Verification Scan", config: { delayDays: 30, reuseProfile: true }, onFailure: "continue" },
    ],
    compatiblePlatforms: ["servicenow_secops", "cortex_xsoar", "swimlane", "qradar_soar"],
    estimatedDuration: "2m",
  },
  {
    id: "PB-TH-001",
    name: "Threat Intel Auto-Hunt",
    category: "threat_hunting",
    description: "When new threat intelligence is ingested, automatically searches engagement data for matching IOCs and creates investigation cases for hits.",
    triggerType: "finding_created",
    triggerCondition: { findingType: "threat_intel", autoHunt: true },
    actions: [
      { order: 1, type: "enrich_ioc", label: "Cross-Reference Engagement Data", config: { searchScope: "all_active_engagements" }, onFailure: "continue" },
      { order: 2, type: "create_incident", label: "Create Hunt Case", config: { type: "threat_hunt", priority: "high" }, onFailure: "retry" },
      { order: 3, type: "notify", label: "Alert Analysts", config: { channel: "threat_intel", template: "new_hunt" }, onFailure: "continue" },
    ],
    compatiblePlatforms: ["splunk_soar", "cortex_xsoar", "thehive", "shuffle"],
    estimatedDuration: "1m",
  },
  {
    id: "PB-CO-001",
    name: "Compliance Violation Alert",
    category: "compliance",
    description: "Triggers when a scan reveals compliance violations (NIST, CMMC, PCI-DSS). Creates compliance tickets with framework-specific remediation guidance.",
    triggerType: "finding_created",
    triggerCondition: { hasComplianceMapping: true, violationDetected: true },
    actions: [
      { order: 1, type: "create_incident", label: "Create Compliance Ticket", config: { type: "compliance_violation", includeFrameworkMapping: true }, onFailure: "retry" },
      { order: 2, type: "notify", label: "Alert Compliance Officer", config: { template: "compliance_violation", escalate: true }, onFailure: "continue" },
      { order: 3, type: "update_ticket", label: "Attach OSCAL Evidence", config: { generateOscalReport: true }, onFailure: "continue" },
    ],
    compatiblePlatforms: ["servicenow_secops", "cortex_xsoar", "swimlane", "qradar_soar"],
    estimatedDuration: "1m",
  },
  {
    id: "PB-NT-001",
    name: "Engagement Completion Summary",
    category: "notification",
    description: "When an engagement is marked complete, generates a summary report and pushes it to the SOAR platform as a closed case with full evidence chain.",
    triggerType: "manual",
    triggerCondition: { engagementStatus: "completed" },
    actions: [
      { order: 1, type: "update_ticket", label: "Attach Final Report", config: { includeExecutiveSummary: true, includeFindings: true }, onFailure: "continue" },
      { order: 2, type: "notify", label: "Notify Stakeholders", config: { template: "engagement_complete", includeMetrics: true }, onFailure: "continue" },
      { order: 3, type: "custom_webhook", label: "Archive to GRC", config: { archiveEvidence: true }, onFailure: "continue" },
    ],
    compatiblePlatforms: ["splunk_soar", "cortex_xsoar", "swimlane", "tines", "shuffle", "thehive", "servicenow_secops", "qradar_soar", "custom"],
    estimatedDuration: "30s",
  },
];

export function getPlaybooksForPlatform(platform: SoarPlatform): PlaybookTemplate[] {
  return PLAYBOOK_TEMPLATES.filter(p => p.compatiblePlatforms.includes(platform));
}

export function getPlaybooksByCategory(category: PlaybookCategory): PlaybookTemplate[] {
  return PLAYBOOK_TEMPLATES.filter(p => p.category === category);
}

// ─── Platform-Specific Payload Formatters ───────────────────────────────────

export interface FindingPayload {
  findingId: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  description: string;
  target: string;
  cveId?: string;
  cvssScore?: number;
  evidence?: string;
  engagementId?: string;
  engagementName?: string;
  mitreTechniqueId?: string;
  remediationGuidance?: string;
  validatedAt?: string;
}

export function formatPayloadForPlatform(platform: SoarPlatform, finding: FindingPayload): Record<string, any> {
  switch (platform) {
    case "splunk_soar":
      return {
        container: {
          name: `[Caldera] ${finding.title}`,
          description: finding.description,
          severity: mapSeverityToSplunk(finding.severity),
          label: "pentest_finding",
          source_data_identifier: finding.findingId,
          custom_fields: {
            target: finding.target,
            cve_id: finding.cveId || "",
            cvss_score: finding.cvssScore || 0,
            engagement_id: finding.engagementId || "",
            mitre_technique: finding.mitreTechniqueId || "",
          },
        },
        artifacts: finding.cveId ? [{
          cef: { cn1: finding.cvssScore, cs1: finding.cveId },
          label: "vulnerability",
          name: finding.cveId,
          type: "cve",
        }] : [],
      };

    case "cortex_xsoar":
      return {
        name: `[Caldera] ${finding.title}`,
        type: "Pentest Finding",
        severity: mapSeverityToXsoar(finding.severity),
        details: finding.description,
        CustomFields: {
          calderafindingid: finding.findingId,
          target: finding.target,
          cveid: finding.cveId || "",
          cvssscore: finding.cvssScore || 0,
          engagementid: finding.engagementId || "",
          mitretechnique: finding.mitreTechniqueId || "",
          remediationguidance: finding.remediationGuidance || "",
        },
        labels: [
          { type: "source", value: "caldera" },
          { type: "severity", value: finding.severity },
        ],
      };

    case "thehive":
      return {
        title: `[Caldera] ${finding.title}`,
        description: `${finding.description}\n\n**Target:** ${finding.target}\n**CVE:** ${finding.cveId || "N/A"}\n**CVSS:** ${finding.cvssScore || "N/A"}`,
        type: "external",
        source: "Caldera Platform",
        sourceRef: finding.findingId,
        severity: mapSeverityToTheHive(finding.severity),
        tags: [
          "caldera",
          `severity:${finding.severity}`,
          finding.cveId ? `cve:${finding.cveId}` : "",
          finding.mitreTechniqueId ? `mitre:${finding.mitreTechniqueId}` : "",
        ].filter(Boolean),
        customFields: {
          "caldera-target": { string: finding.target },
          "caldera-engagement": { string: finding.engagementId || "" },
        },
      };

    case "servicenow_secops":
      return {
        short_description: `[Caldera] ${finding.title}`,
        description: finding.description,
        priority: mapSeverityToServiceNow(finding.severity),
        category: "Vulnerability",
        subcategory: "Pentest Finding",
        u_source: "Caldera Platform",
        u_finding_id: finding.findingId,
        u_target: finding.target,
        u_cve_id: finding.cveId || "",
        u_cvss_score: String(finding.cvssScore || 0),
        u_engagement_id: finding.engagementId || "",
        u_remediation: finding.remediationGuidance || "",
      };

    case "qradar_soar":
      return {
        name: `[Caldera] ${finding.title}`,
        description: {
          format: "html",
          content: `<p>${finding.description}</p><p><strong>Target:</strong> ${finding.target}</p><p><strong>CVE:</strong> ${finding.cveId || "N/A"}</p>`,
        },
        discovered_date: finding.validatedAt ? new Date(finding.validatedAt).getTime() : Date.now(),
        severity_code: mapSeverityToQRadar(finding.severity),
        incident_type_ids: [1001], // Pentest Finding type
        properties: {
          caldera_finding_id: finding.findingId,
          target: finding.target,
          cvss_score: finding.cvssScore || 0,
          engagement_id: finding.engagementId || "",
        },
      };

    case "shuffle":
    case "tines":
    case "swimlane":
    default:
      // Generic JSON format for webhook-based platforms
      return {
        source: "caldera",
        event_type: "pentest_finding",
        timestamp: new Date().toISOString(),
        finding: {
          id: finding.findingId,
          title: finding.title,
          severity: finding.severity,
          description: finding.description,
          target: finding.target,
          cve_id: finding.cveId || null,
          cvss_score: finding.cvssScore || null,
          evidence: finding.evidence || null,
          engagement_id: finding.engagementId || null,
          engagement_name: finding.engagementName || null,
          mitre_technique_id: finding.mitreTechniqueId || null,
          remediation_guidance: finding.remediationGuidance || null,
          validated_at: finding.validatedAt || null,
        },
      };
  }
}

// ─── Severity Mappers ───────────────────────────────────────────────────────

function mapSeverityToSplunk(severity: string): string {
  const map: Record<string, string> = { critical: "high", high: "high", medium: "medium", low: "low", info: "low" };
  return map[severity] || "medium";
}

function mapSeverityToXsoar(severity: string): number {
  const map: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0.5 };
  return map[severity] || 2;
}

function mapSeverityToTheHive(severity: string): number {
  const map: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 1 };
  return map[severity] || 2;
}

function mapSeverityToServiceNow(severity: string): string {
  const map: Record<string, string> = { critical: "1", high: "2", medium: "3", low: "4", info: "4" };
  return map[severity] || "3";
}

function mapSeverityToQRadar(severity: string): { id: number; name: string } {
  const map: Record<string, { id: number; name: string }> = {
    critical: { id: 6, name: "Critical" },
    high: { id: 5, name: "High" },
    medium: { id: 4, name: "Medium" },
    low: { id: 3, name: "Low" },
    info: { id: 2, name: "Informational" },
  };
  return map[severity] || { id: 4, name: "Medium" };
}

// ─── Inbound Webhook Parser ─────────────────────────────────────────────────

export interface InboundEvent {
  source: SoarPlatform;
  eventType: "status_update" | "action_completed" | "escalation" | "closure" | "comment" | "unknown";
  externalId: string;
  status?: string;
  message?: string;
  metadata: Record<string, any>;
  receivedAt: string;
}

export function parseInboundWebhook(platform: SoarPlatform, body: Record<string, any>): InboundEvent {
  const base: InboundEvent = {
    source: platform,
    eventType: "unknown",
    externalId: "",
    metadata: body,
    receivedAt: new Date().toISOString(),
  };

  switch (platform) {
    case "splunk_soar":
      base.externalId = body.container_id?.toString() || body.id?.toString() || "";
      base.eventType = body.status === "closed" ? "closure" : body.action_result ? "action_completed" : "status_update";
      base.status = body.status;
      base.message = body.message || body.action_result?.message;
      break;

    case "cortex_xsoar":
      base.externalId = body.id?.toString() || body.incidentId?.toString() || "";
      base.eventType = body.type === "IncidentClosed" ? "closure" : body.type === "TaskCompleted" ? "action_completed" : "status_update";
      base.status = body.status;
      base.message = body.details;
      break;

    case "thehive":
      base.externalId = body.objectId?.toString() || body._id?.toString() || "";
      base.eventType = body.operation === "Delete" ? "closure" : body.operation === "Update" ? "status_update" : "comment";
      base.status = body.details?.status;
      base.message = body.details?.message || body.details?.description;
      break;

    case "servicenow_secops":
      base.externalId = body.sys_id?.toString() || body.number?.toString() || "";
      base.eventType = body.state === "7" ? "closure" : body.state === "6" ? "action_completed" : "status_update";
      base.status = body.state;
      base.message = body.work_notes || body.comments;
      break;

    default:
      base.externalId = body.id?.toString() || body.event_id?.toString() || "";
      base.eventType = body.event_type || "unknown";
      base.status = body.status;
      base.message = body.message;
  }

  return base;
}

// ─── Connector Health Monitor ───────────────────────────────────────────────

export interface ConnectorHealth {
  connectorId: number;
  platform: SoarPlatform;
  status: "healthy" | "degraded" | "unreachable" | "unknown";
  lastChecked: string;
  latencyMs: number;
  consecutiveFailures: number;
  lastSuccessAt?: string;
  lastFailureAt?: string;
  lastFailureReason?: string;
}

export async function checkConnectorHealth(webhookUrl: string, platform: SoarPlatform): Promise<{ status: ConnectorHealth["status"]; latencyMs: number; error?: string }> {
  const start = Date.now();
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);

    const response = await fetch(webhookUrl, {
      method: "HEAD",
      signal: controller.signal,
      headers: { "User-Agent": "Caldera-SOAR-HealthCheck/1.0" },
    });

    clearTimeout(timeout);
    const latencyMs = Date.now() - start;

    if (response.ok || response.status === 405) {
      // 405 Method Not Allowed is acceptable — endpoint exists but doesn't accept HEAD
      return { status: "healthy", latencyMs };
    } else if (response.status >= 500) {
      return { status: "degraded", latencyMs, error: `Server error: ${response.status}` };
    } else {
      return { status: "healthy", latencyMs }; // 4xx could be auth-required, which is expected
    }
  } catch (err: any) {
    const latencyMs = Date.now() - start;
    if (err.name === "AbortError") {
      return { status: "unreachable", latencyMs, error: "Connection timeout (10s)" };
    }
    return { status: "unreachable", latencyMs, error: err.message || "Connection failed" };
  }
}

// ─── Auto-Forward Engine ────────────────────────────────────────────────────

export interface ForwardingRule {
  id: string;
  name: string;
  connectorId: number;
  platform: SoarPlatform;
  enabled: boolean;
  triggerType: PlaybookTemplate["triggerType"];
  conditions: {
    minSeverity?: "critical" | "high" | "medium" | "low" | "info";
    engagementIds?: string[];
    findingTypes?: string[];
    cvePattern?: string;
    targetPattern?: string;
  };
  playbookId?: string;
  createdBy: string;
  createdAt: string;
}

export function evaluateForwardingRule(rule: ForwardingRule, finding: FindingPayload): boolean {
  const { conditions } = rule;
  if (!rule.enabled) return false;

  // Check severity threshold
  if (conditions.minSeverity) {
    const severityOrder = ["info", "low", "medium", "high", "critical"];
    const findingSev = severityOrder.indexOf(finding.severity);
    const minSev = severityOrder.indexOf(conditions.minSeverity);
    if (findingSev < minSev) return false;
  }

  // Check engagement filter
  if (conditions.engagementIds?.length && finding.engagementId) {
    if (!conditions.engagementIds.includes(finding.engagementId)) return false;
  }

  // Check CVE pattern
  if (conditions.cvePattern && finding.cveId) {
    const regex = new RegExp(conditions.cvePattern, "i");
    if (!regex.test(finding.cveId)) return false;
  }

  // Check target pattern
  if (conditions.targetPattern) {
    const regex = new RegExp(conditions.targetPattern, "i");
    if (!regex.test(finding.target)) return false;
  }

  return true;
}

/**
 * Process a finding through all active forwarding rules and return
 * the formatted payloads ready to dispatch.
 */
export function processForwardingRules(
  rules: ForwardingRule[],
  finding: FindingPayload
): Array<{ rule: ForwardingRule; payload: Record<string, any> }> {
  const results: Array<{ rule: ForwardingRule; payload: Record<string, any> }> = [];

  for (const rule of rules) {
    if (evaluateForwardingRule(rule, finding)) {
      const payload = formatPayloadForPlatform(rule.platform, finding);
      results.push({ rule, payload });
    }
  }

  return results;
}
