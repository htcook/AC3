/**
 * Client IP Disclosure System
 * 
 * Generates formal IP disclosure documents, sends client notifications,
 * and manages the approval gate that pauses engagements until the client
 * acknowledges receipt of the source IP list.
 * 
 * Features:
 * - Auto-generate IP Disclosure PDF with engagement details
 * - Email notification to client POC with IP list
 * - Approval gate — pause pipeline until client acknowledges
 * - Auto-append IP list to RoE as addendum
 * - Mid-engagement IP change notifications
 */

import { generateIpDisclosureData, type IpDisclosureData, type ProxyRegion } from "./proxy-fleet-manager";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface ClientContact {
  name: string;
  email: string;
  phone?: string;
  role: string;              // e.g. "CISO", "SOC Manager", "IT Director"
  organization: string;
}

export interface IpDisclosureDocument {
  id: string;
  engagementId: number;
  engagementName: string;
  version: number;           // Increments on IP rotation updates
  generatedAt: number;
  status: "draft" | "sent" | "acknowledged" | "expired";
  acknowledgedAt: number | null;
  acknowledgedBy: string | null;
  clientContacts: ClientContact[];
  disclosureData: IpDisclosureData;
  roeAddendumGenerated: boolean;
  markdownContent: string;
  changeLog: IpChangeNotification[];
}

export interface IpChangeNotification {
  timestamp: number;
  type: "initial" | "rotation" | "addition" | "removal";
  oldIp: string | null;
  newIp: string | null;
  region: ProxyRegion | null;
  reason: string;
  notificationSent: boolean;
}

export interface ApprovalGateStatus {
  engagementId: number;
  gateActive: boolean;
  disclosureDocId: string | null;
  clientAcknowledged: boolean;
  acknowledgedAt: number | null;
  blockedPhase: string | null;
  overrideBy: string | null;
  overrideReason: string | null;
}

// ─── In-Memory Registry ──────────────────────────────────────────────────────

const disclosureDocs = new Map<number, IpDisclosureDocument>();
const approvalGates = new Map<number, ApprovalGateStatus>();

// ─── Disclosure Document Generation ──────────────────────────────────────────

/**
 * Generate an IP disclosure document for an engagement.
 */
export function generateDisclosureDocument(
  engagementId: number,
  engagementName: string,
  clientContacts: ClientContact[],
  engagementDates: { startDate: string; endDate: string },
  scope: string[],
): IpDisclosureDocument {
  const disclosureData = generateIpDisclosureData(engagementId, engagementName);

  const docId = `ipd-${engagementId}-${Date.now().toString(36)}`;
  const now = Date.now();

  const markdownContent = buildDisclosureMarkdown({
    engagementId,
    engagementName,
    clientContacts,
    engagementDates,
    scope,
    disclosureData,
    generatedAt: now,
  });

  const doc: IpDisclosureDocument = {
    id: docId,
    engagementId,
    engagementName,
    version: 1,
    generatedAt: now,
    status: "draft",
    acknowledgedAt: null,
    acknowledgedBy: null,
    clientContacts,
    disclosureData: disclosureData || {
      engagementId,
      engagementName,
      fleetId: "pending",
      generatedAt: now,
      sourceIps: [],
      scanServerIp: process.env.SCAN_SERVER_HOST || null,
      calderaServerIp: null,
      expectedTrafficPatterns: [],
      whitelistInstructions: "",
    },
    roeAddendumGenerated: false,
    markdownContent,
    changeLog: [{
      timestamp: now,
      type: "initial",
      oldIp: null,
      newIp: null,
      region: null,
      reason: "Initial IP disclosure document generated",
      notificationSent: false,
    }],
  };

  disclosureDocs.set(engagementId, doc);
  return doc;
}

/**
 * Build the Markdown content for the IP disclosure document.
 */
function buildDisclosureMarkdown(opts: {
  engagementId: number;
  engagementName: string;
  clientContacts: ClientContact[];
  engagementDates: { startDate: string; endDate: string };
  scope: string[];
  disclosureData: IpDisclosureData | null;
  generatedAt: number;
}): string {
  const genDate = new Date(opts.generatedAt).toISOString();
  const ips = opts.disclosureData?.sourceIps || [];

  let md = `# IP Disclosure Document\n\n`;
  md += `**CONFIDENTIAL — FOR AUTHORIZED PERSONNEL ONLY**\n\n`;
  md += `---\n\n`;

  // Header
  md += `## Engagement Details\n\n`;
  md += `| Field | Value |\n|---|---|\n`;
  md += `| **Engagement ID** | ${opts.engagementId} |\n`;
  md += `| **Engagement Name** | ${opts.engagementName} |\n`;
  md += `| **Start Date** | ${opts.engagementDates.startDate} |\n`;
  md += `| **End Date** | ${opts.engagementDates.endDate} |\n`;
  md += `| **Document Generated** | ${genDate} |\n`;
  md += `| **Document Classification** | Confidential |\n\n`;

  // Client Contacts
  md += `## Client Points of Contact\n\n`;
  md += `| Name | Role | Email | Phone |\n|---|---|---|---|\n`;
  for (const c of opts.clientContacts) {
    md += `| ${c.name} | ${c.role} | ${c.email} | ${c.phone || "N/A"} |\n`;
  }
  md += `\n`;

  // Scope
  md += `## Engagement Scope\n\n`;
  md += `The following targets are in scope for this engagement:\n\n`;
  for (const s of opts.scope) {
    md += `- ${s}\n`;
  }
  md += `\n`;

  // Source IPs
  md += `## Source IP Addresses\n\n`;
  md += `The following IP addresses will be used as source addresses during the penetration test. `;
  md += `These IPs should be whitelisted in your WAF, IDS/IPS, and firewall rules for the duration of the engagement.\n\n`;
  md += `| IP Address | Region | Purpose | Expected Traffic | Target Ports |\n|---|---|---|---|---|\n`;
  for (const ip of ips) {
    md += `| \`${ip.ip}\` | ${ip.region} | ${ip.purpose} | ${ip.expectedTraffic} | ${ip.ports} |\n`;
  }
  md += `\n`;

  // Traffic Patterns
  md += `## Expected Traffic Patterns\n\n`;
  md += `During the engagement, the following types of traffic will originate from the source IPs listed above:\n\n`;
  const patterns = opts.disclosureData?.expectedTrafficPatterns || [];
  for (const p of patterns) {
    md += `- ${p}\n`;
  }
  md += `\n`;

  // Whitelist Instructions
  md += `## Whitelist Instructions\n\n`;
  md += opts.disclosureData?.whitelistInstructions || "";
  md += `\n\n`;

  // SOC/NOC Notification
  md += `## SOC/NOC Notification Requirements\n\n`;
  md += `Please ensure the following teams are notified before the engagement begins:\n\n`;
  md += `1. **Security Operations Center (SOC)** — Inform analysts that traffic from the listed IPs is authorized penetration testing. Provide this document as reference.\n`;
  md += `2. **Network Operations Center (NOC)** — Ensure network monitoring does not auto-block these IPs. Configure rate-limiting exceptions.\n`;
  md += `3. **Incident Response Team** — Brief the IR team that any alerts triggered by these IPs during the engagement window are expected.\n`;
  md += `4. **Third-Party Security Providers** — If you use managed security services (MSSP), notify them of the engagement dates and source IPs.\n\n`;

  // Acknowledgment
  md += `## Acknowledgment\n\n`;
  md += `By acknowledging this document, you confirm that:\n\n`;
  md += `- [ ] The source IPs have been whitelisted in WAF/IDS/IPS/firewall rules\n`;
  md += `- [ ] SOC/NOC teams have been notified\n`;
  md += `- [ ] Incident response team has been briefed\n`;
  md += `- [ ] Third-party security providers have been notified (if applicable)\n`;
  md += `- [ ] You authorize penetration testing from these IPs against the in-scope targets\n\n`;
  md += `**Acknowledged By:** ____________________________\n\n`;
  md += `**Date:** ____________________________\n\n`;
  md += `**Signature:** ____________________________\n\n`;

  // IP Change Policy
  md += `## IP Rotation Policy\n\n`;
  md += `During the engagement, source IPs may be rotated if they are detected and blocked by target defenses. `;
  md += `If an IP rotation occurs:\n\n`;
  md += `1. You will receive an immediate email notification with the new IP address\n`;
  md += `2. The client portal will be updated in real-time\n`;
  md += `3. An updated version of this document will be generated\n`;
  md += `4. The old IP will be decommissioned and destroyed\n\n`;
  md += `**Note:** IP rotations during the engagement are a normal part of red team operations and indicate that your defenses successfully detected our activity — this is a positive finding.\n\n`;

  md += `---\n\n`;
  md += `*This document was auto-generated by the Caldera Admin Dashboard engagement pipeline.*\n`;

  return md;
}

// ─── Approval Gate ───────────────────────────────────────────────────────────

/**
 * Activate the approval gate for an engagement.
 * The pipeline will pause at the specified phase until the client acknowledges.
 */
export function activateApprovalGate(
  engagementId: number,
  blockedPhase: string = "enumeration",
): ApprovalGateStatus {
  const doc = disclosureDocs.get(engagementId);

  const gate: ApprovalGateStatus = {
    engagementId,
    gateActive: true,
    disclosureDocId: doc?.id || null,
    clientAcknowledged: false,
    acknowledgedAt: null,
    blockedPhase,
    overrideBy: null,
    overrideReason: null,
  };

  approvalGates.set(engagementId, gate);
  return gate;
}

/**
 * Check if the approval gate allows the engagement to proceed.
 */
export function checkApprovalGate(engagementId: number): {
  allowed: boolean;
  reason: string;
} {
  const gate = approvalGates.get(engagementId);

  // No gate = allowed
  if (!gate || !gate.gateActive) {
    return { allowed: true, reason: "No approval gate active" };
  }

  // Client acknowledged
  if (gate.clientAcknowledged) {
    return { allowed: true, reason: `Client acknowledged at ${new Date(gate.acknowledgedAt!).toISOString()}` };
  }

  // Operator override
  if (gate.overrideBy) {
    return { allowed: true, reason: `Override by ${gate.overrideBy}: ${gate.overrideReason}` };
  }

  return {
    allowed: false,
    reason: `Waiting for client acknowledgment of IP disclosure document. Blocked at phase: ${gate.blockedPhase}`,
  };
}

/**
 * Record client acknowledgment of the IP disclosure.
 */
export function acknowledgeDisclosure(
  engagementId: number,
  acknowledgedBy: string,
): { success: boolean; error?: string } {
  const doc = disclosureDocs.get(engagementId);
  if (!doc) return { success: false, error: "No disclosure document found" };

  doc.status = "acknowledged";
  doc.acknowledgedAt = Date.now();
  doc.acknowledgedBy = acknowledgedBy;

  const gate = approvalGates.get(engagementId);
  if (gate) {
    gate.clientAcknowledged = true;
    gate.acknowledgedAt = Date.now();
  }

  return { success: true };
}

/**
 * Operator override of the approval gate (emergency bypass).
 */
export function overrideApprovalGate(
  engagementId: number,
  operatorName: string,
  reason: string,
): { success: boolean } {
  const gate = approvalGates.get(engagementId);
  if (!gate) return { success: false };

  gate.overrideBy = operatorName;
  gate.overrideReason = reason;

  return { success: true };
}

// ─── IP Change Notifications ─────────────────────────────────────────────────

/**
 * Record an IP change and generate a notification.
 */
export function recordIpChange(
  engagementId: number,
  change: {
    type: "rotation" | "addition" | "removal";
    oldIp: string | null;
    newIp: string | null;
    region: ProxyRegion | null;
    reason: string;
  },
): IpChangeNotification | null {
  const doc = disclosureDocs.get(engagementId);
  if (!doc) return null;

  const notification: IpChangeNotification = {
    timestamp: Date.now(),
    type: change.type,
    oldIp: change.oldIp,
    newIp: change.newIp,
    region: change.region,
    reason: change.reason,
    notificationSent: false,
  };

  doc.changeLog.push(notification);
  doc.version++;

  // Regenerate the markdown with updated IPs
  const disclosureData = generateIpDisclosureData(engagementId, doc.engagementName);
  if (disclosureData) {
    doc.disclosureData = disclosureData;
  }

  return notification;
}

/**
 * Mark a notification as sent (after email delivery).
 */
export function markNotificationSent(engagementId: number, notificationIndex: number): void {
  const doc = disclosureDocs.get(engagementId);
  if (doc && doc.changeLog[notificationIndex]) {
    doc.changeLog[notificationIndex].notificationSent = true;
  }
}

// ─── RoE Addendum ────────────────────────────────────────────────────────────

/**
 * Generate an RoE addendum with the IP disclosure data.
 */
export function generateRoeAddendum(engagementId: number): string | null {
  const doc = disclosureDocs.get(engagementId);
  if (!doc) return null;

  const ips = doc.disclosureData.sourceIps;
  const genDate = new Date().toISOString().split("T")[0];

  let addendum = `# Rules of Engagement — Addendum: Source IP Disclosure\n\n`;
  addendum += `**Engagement:** ${doc.engagementName} (ID: ${doc.engagementId})\n\n`;
  addendum += `**Date:** ${genDate}\n\n`;
  addendum += `**Addendum Version:** ${doc.version}\n\n`;
  addendum += `---\n\n`;
  addendum += `This addendum supplements the signed Rules of Engagement for the above engagement. `;
  addendum += `It discloses the source IP addresses that will be used during the penetration test.\n\n`;
  addendum += `## Authorized Source IPs\n\n`;
  addendum += `| IP Address | Region | Purpose |\n|---|---|---|\n`;
  for (const ip of ips) {
    addendum += `| \`${ip.ip}\` | ${ip.region} | ${ip.purpose} |\n`;
  }
  addendum += `\n`;

  if (doc.changeLog.length > 1) {
    addendum += `## IP Change History\n\n`;
    addendum += `| Date | Type | Old IP | New IP | Reason |\n|---|---|---|---|---|\n`;
    for (const change of doc.changeLog) {
      if (change.type === "initial") continue;
      addendum += `| ${new Date(change.timestamp).toISOString()} | ${change.type} | ${change.oldIp || "—"} | ${change.newIp || "—"} | ${change.reason} |\n`;
    }
    addendum += `\n`;
  }

  addendum += `## Authorization\n\n`;
  addendum += `By signing this addendum, the client authorizes penetration testing from the above IP addresses `;
  addendum += `against the in-scope targets defined in the original Rules of Engagement.\n\n`;
  addendum += `**Client Signature:** ____________________________\n\n`;
  addendum += `**Date:** ____________________________\n\n`;

  doc.roeAddendumGenerated = true;
  return addendum;
}

// ─── Getters ─────────────────────────────────────────────────────────────────

export function getDisclosureDocument(engagementId: number): IpDisclosureDocument | null {
  return disclosureDocs.get(engagementId) || null;
}

export function getApprovalGateStatus(engagementId: number): ApprovalGateStatus | null {
  return approvalGates.get(engagementId) || null;
}

export function getAllDisclosureDocuments(): IpDisclosureDocument[] {
  return Array.from(disclosureDocs.values());
}
