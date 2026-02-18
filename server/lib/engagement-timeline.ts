/**
 * Unified Engagement Timeline Aggregation Service
 * 
 * Merges events from all kill chain data sources into a single chronological
 * timeline view mapped to MITRE ATT&CK kill chain phases:
 * 
 * 1. Reconnaissance → domainRecon, domainIntelScans
 * 2. Weaponization → unifiedExploitCatalog, phishingDrafts (materialization)
 * 3. Delivery → GoPhish campaigns, typosquatDomains
 * 4. Exploitation → exploitJobs (Metasploit execution)
 * 5. Installation → exploitJobs.calderaAgentPaw (agent deployment)
 * 6. Command & Control → Caldera operations, agents
 * 7. Actions on Objectives → Caldera operation results, activityLogs
 */

import { getDb } from '../db';
import {
  engagements,
  domainRecon,
  domainIntelScans,
  phishingDrafts,
  campaignEngagements,
  typosquatDomains,
  exploitJobs,
  activityLogs,
  engagementPipelines,
  metasploitServers,
} from '../../drizzle/schema';
import { eq, desc, and, gte, lte, sql, or, isNotNull } from 'drizzle-orm';

// ─── Types ───────────────────────────────────────────────────────────────────

export type KillChainPhase =
  | 'reconnaissance'
  | 'weaponization'
  | 'delivery'
  | 'exploitation'
  | 'installation'
  | 'command_control'
  | 'actions_on_objectives';

export type EventSource =
  | 'domain_recon'
  | 'domain_intel_scan'
  | 'phishing_draft'
  | 'gophish_campaign'
  | 'typosquat_domain'
  | 'exploit_job'
  | 'caldera_operation'
  | 'caldera_agent'
  | 'activity_log'
  | 'engagement_pipeline';

export type EventSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export interface TimelineEvent {
  id: string;                    // Unique event ID: "{source}:{recordId}"
  engagementId: number | null;
  timestamp: number;             // Unix ms
  phase: KillChainPhase;
  source: EventSource;
  severity: EventSeverity;
  title: string;
  description: string;
  // Metadata
  icon: string;                  // Lucide icon name
  color: string;                 // Tailwind color class
  // Links
  sourceRecordId: number | string;
  targetDomain?: string;
  cveId?: string;
  msfModule?: string;
  calderaOperationId?: string;
  gophishCampaignId?: number;
  // Status
  status: 'pending' | 'running' | 'success' | 'failed' | 'info';
  // Detail data for drill-down
  details: Record<string, any>;
}

export interface TimelineFilter {
  engagementId?: number;
  phases?: KillChainPhase[];
  sources?: EventSource[];
  severity?: EventSeverity[];
  startDate?: number;
  endDate?: number;
  targetDomain?: string;
  limit?: number;
  offset?: number;
}

export interface TimelineStats {
  totalEvents: number;
  byPhase: Record<KillChainPhase, number>;
  bySource: Record<string, number>;
  bySeverity: Record<EventSeverity, number>;
  byStatus: Record<string, number>;
  // Kill chain coverage
  phasesReached: KillChainPhase[];
  furthestPhase: KillChainPhase | null;
  // Timing
  firstEventTime: number | null;
  lastEventTime: number | null;
  timeToFirstExploit: number | null;   // ms from first recon to first exploit
  timeToFirstAgent: number | null;     // ms from first recon to first agent
  timeToObjective: number | null;      // ms from first recon to first action on objective
}

export interface EngagementSummary {
  engagement: {
    id: number;
    name: string;
    customerName: string;
    type: string;
    status: string;
    targetDomain: string | null;
    startDate: number | null;
  };
  timeline: TimelineStats;
  killChainProgress: {
    phase: KillChainPhase;
    label: string;
    eventCount: number;
    status: 'not_started' | 'in_progress' | 'completed';
    firstEvent: number | null;
    lastEvent: number | null;
  }[];
  // Key metrics
  reconFindings: number;
  exploitsAttempted: number;
  exploitsSucceeded: number;
  agentsDeployed: number;
  phishingCampaigns: number;
  typosquatDomains: number;
}

// ─── Phase Mapping ───────────────────────────────────────────────────────────

const PHASE_ORDER: KillChainPhase[] = [
  'reconnaissance',
  'weaponization',
  'delivery',
  'exploitation',
  'installation',
  'command_control',
  'actions_on_objectives',
];

const PHASE_LABELS: Record<KillChainPhase, string> = {
  reconnaissance: 'Reconnaissance',
  weaponization: 'Weaponization',
  delivery: 'Delivery',
  exploitation: 'Exploitation',
  installation: 'Installation',
  command_control: 'Command & Control',
  actions_on_objectives: 'Actions on Objectives',
};

// ─── Event Collection Functions ──────────────────────────────────────────────

async function collectReconEvents(db: any, filter: TimelineFilter): Promise<TimelineEvent[]> {
  const events: TimelineEvent[] = [];

  try {
    // Domain Recon events
    let reconQuery = db.select().from(domainRecon);
    const reconConditions: any[] = [];
    if (filter.engagementId) reconConditions.push(eq(domainRecon.engagementId, filter.engagementId));
    if (filter.targetDomain) reconConditions.push(eq(domainRecon.domain, filter.targetDomain));
    if (filter.startDate) reconConditions.push(gte(domainRecon.createdAt, new Date(filter.startDate)));
    if (filter.endDate) reconConditions.push(lte(domainRecon.createdAt, new Date(filter.endDate)));
    if (reconConditions.length > 0) reconQuery = reconQuery.where(and(...reconConditions));
    const recons = await reconQuery.orderBy(desc(domainRecon.createdAt)).limit(filter.limit || 100);

    for (const r of recons) {
      const subdomainCount = Array.isArray(r.subdomains) ? r.subdomains.length : 0;
      const emailCount = Array.isArray(r.discoveredEmails) ? r.discoveredEmails.length : 0;
      events.push({
        id: `domain_recon:${r.id}`,
        engagementId: r.engagementId,
        timestamp: new Date(r.createdAt).getTime(),
        phase: 'reconnaissance',
        source: 'domain_recon',
        severity: r.spoofable ? 'high' : 'info',
        title: `Domain Recon: ${r.domain}`,
        description: `DNS analysis complete. ${subdomainCount} subdomains, ${emailCount} emails discovered. Spoofable: ${r.spoofable ? 'Yes' : 'No'} (score: ${r.spoofScore}/100)`,
        icon: 'Search',
        color: 'cyan',
        sourceRecordId: r.id,
        targetDomain: r.domain,
        status: r.scanStatus === 'completed' ? 'success' : r.scanStatus === 'failed' ? 'failed' : 'running',
        details: {
          domain: r.domain,
          spoofable: r.spoofable,
          spoofScore: r.spoofScore,
          subdomainCount,
          emailCount,
          mxRecords: r.mxRecords,
          spfRecord: r.spfRecord,
          dmarcRecord: r.dmarcRecord,
          scanStatus: r.scanStatus,
        },
      });
    }

    // Domain Intel Scans (deeper analysis)
    let scanQuery = db.select().from(domainIntelScans);
    const scanConditions: any[] = [];
    if (filter.engagementId) scanConditions.push(eq(domainIntelScans.engagementId, filter.engagementId));
    if (filter.targetDomain) scanConditions.push(eq(domainIntelScans.primaryDomain, filter.targetDomain));
    if (filter.startDate) scanConditions.push(gte(domainIntelScans.createdAt, new Date(filter.startDate)));
    if (filter.endDate) scanConditions.push(lte(domainIntelScans.createdAt, new Date(filter.endDate)));
    if (scanConditions.length > 0) scanQuery = scanQuery.where(and(...scanConditions));
    const scans = await scanQuery.orderBy(desc(domainIntelScans.createdAt)).limit(filter.limit || 50);

    for (const s of scans) {
      const riskBand = s.overallRiskBand || 'unknown';
      const severity: EventSeverity = riskBand === 'critical' ? 'critical' : riskBand === 'high' ? 'high' : riskBand === 'medium' ? 'medium' : 'low';
      events.push({
        id: `domain_intel_scan:${s.id}`,
        engagementId: s.engagementId,
        timestamp: new Date(s.createdAt).getTime(),
        phase: 'reconnaissance',
        source: 'domain_intel_scan',
        severity,
        title: `Intel Scan: ${s.primaryDomain}`,
        description: `Full domain intel scan. ${s.totalAssets || 0} assets, ${s.totalFindings || 0} findings. Risk: ${riskBand} (${s.overallRiskScore || 0}/100)`,
        icon: 'Radar',
        color: severity === 'critical' ? 'red' : severity === 'high' ? 'orange' : 'cyan',
        sourceRecordId: s.id,
        targetDomain: s.primaryDomain,
        status: s.status === 'completed' ? 'success' : s.status === 'failed' ? 'failed' : 'running',
        details: {
          primaryDomain: s.primaryDomain,
          totalAssets: s.totalAssets,
          totalFindings: s.totalFindings,
          overallRiskScore: s.overallRiskScore,
          overallRiskBand: s.overallRiskBand,
          sector: s.sector,
          status: s.status,
          executiveSummary: s.executiveSummary,
        },
      });
    }
  } catch (err: any) {
    console.error('[Timeline] Recon event collection error:', err.message);
  }

  return events;
}

async function collectWeaponizationEvents(db: any, filter: TimelineFilter): Promise<TimelineEvent[]> {
  const events: TimelineEvent[] = [];

  try {
    // Phishing draft materialization
    let draftQuery = db.select().from(phishingDrafts);
    const draftConditions: any[] = [];
    if (filter.engagementId) draftConditions.push(eq(phishingDrafts.engagementId, filter.engagementId));
    if (filter.targetDomain) draftConditions.push(eq(phishingDrafts.targetDomain, filter.targetDomain));
    if (filter.startDate) draftConditions.push(gte(phishingDrafts.createdAt, new Date(filter.startDate)));
    if (filter.endDate) draftConditions.push(lte(phishingDrafts.createdAt, new Date(filter.endDate)));
    if (draftConditions.length > 0) draftQuery = draftQuery.where(and(...draftConditions));
    const drafts = await draftQuery.orderBy(desc(phishingDrafts.createdAt)).limit(filter.limit || 100);

    for (const d of drafts) {
      const exploitCount = Array.isArray(d.phishingExploits) ? d.phishingExploits.length : 0;
      events.push({
        id: `phishing_draft:${d.id}`,
        engagementId: d.engagementId,
        timestamp: new Date(d.createdAt).getTime(),
        phase: 'weaponization',
        source: 'phishing_draft',
        severity: d.priority === 'critical' ? 'critical' : d.priority === 'high' ? 'high' : 'medium',
        title: `Campaign Materialized: ${d.campaignName}`,
        description: `${d.campaignType || 'phishing'} campaign created. ${exploitCount} exploit techniques matched. Status: ${d.status}`,
        icon: 'FileCode',
        color: 'yellow',
        sourceRecordId: d.id,
        targetDomain: d.targetDomain || undefined,
        status: d.status === 'deployed' || d.status === 'launched' ? 'success' : d.status === 'draft' || d.status === 'approved' ? 'pending' : 'info',
        details: {
          campaignName: d.campaignName,
          campaignType: d.campaignType,
          priority: d.priority,
          status: d.status,
          targetDomain: d.targetDomain,
          targetSector: d.targetSector,
          templateSubject: d.templateSubject,
          threatActorName: d.threatActorName,
          phishingExploitCount: exploitCount,
          hasExploitEnhancedLanding: !!d.exploitEnhancedLandingPage,
        },
      });
    }
  } catch (err: any) {
    console.error('[Timeline] Weaponization event collection error:', err.message);
  }

  return events;
}

async function collectDeliveryEvents(db: any, filter: TimelineFilter): Promise<TimelineEvent[]> {
  const events: TimelineEvent[] = [];

  try {
    // GoPhish campaign links
    let campQuery = db.select().from(campaignEngagements);
    const campConditions: any[] = [];
    if (filter.engagementId) campConditions.push(eq(campaignEngagements.engagementId, filter.engagementId));
    if (filter.startDate) campConditions.push(gte(campaignEngagements.createdAt, new Date(filter.startDate)));
    if (filter.endDate) campConditions.push(lte(campaignEngagements.createdAt, new Date(filter.endDate)));
    if (campConditions.length > 0) campQuery = campQuery.where(and(...campConditions));
    const campaigns = await campQuery.orderBy(desc(campaignEngagements.createdAt)).limit(filter.limit || 100);

    for (const c of campaigns) {
      events.push({
        id: `gophish_campaign:${c.id}`,
        engagementId: c.engagementId,
        timestamp: new Date(c.createdAt).getTime(),
        phase: 'delivery',
        source: 'gophish_campaign',
        severity: 'medium',
        title: `GoPhish Campaign: ${c.gophishCampaignName || `#${c.gophishCampaignId}`}`,
        description: `Phishing campaign launched via GoPhish (ID: ${c.gophishCampaignId})`,
        icon: 'Mail',
        color: 'emerald',
        sourceRecordId: c.id,
        gophishCampaignId: c.gophishCampaignId,
        calderaOperationId: c.calderaOperationId || undefined,
        status: 'success',
        details: {
          gophishCampaignId: c.gophishCampaignId,
          gophishCampaignName: c.gophishCampaignName,
          calderaOperationId: c.calderaOperationId,
          notes: c.notes,
        },
      });
    }

    // Typosquat domain purchases
    let typoQuery = db.select().from(typosquatDomains);
    const typoConditions: any[] = [];
    if (filter.engagementId) typoConditions.push(eq(typosquatDomains.engagementId, filter.engagementId));
    if (filter.startDate) typoConditions.push(gte(typosquatDomains.createdAt, new Date(filter.startDate)));
    if (filter.endDate) typoConditions.push(lte(typosquatDomains.createdAt, new Date(filter.endDate)));
    if (typoConditions.length > 0) typoQuery = typoQuery.where(and(...typoConditions));
    const typos = await typoQuery.orderBy(desc(typosquatDomains.createdAt)).limit(filter.limit || 100);

    for (const t of typos) {
      events.push({
        id: `typosquat_domain:${t.id}`,
        engagementId: t.engagementId,
        timestamp: new Date(t.createdAt).getTime(),
        phase: 'delivery',
        source: 'typosquat_domain',
        severity: t.status === 'active' ? 'high' : 'low',
        title: `Typosquat: ${t.permutedDomain}`,
        description: `Typosquat of ${t.originalDomain} (${t.technique}). Status: ${t.status}. DNS configured: ${t.dnsConfigured ? 'Yes' : 'No'}`,
        icon: 'Globe',
        color: 'purple',
        sourceRecordId: t.id,
        targetDomain: t.originalDomain,
        status: t.status === 'active' ? 'success' : t.status === 'purchased' ? 'running' : 'pending',
        details: {
          originalDomain: t.originalDomain,
          permutedDomain: t.permutedDomain,
          technique: t.technique,
          status: t.status,
          dnsConfigured: t.dnsConfigured,
          gophishProfileId: t.gophishProfileId,
          effectiveness: t.effectiveness,
        },
      });
    }
  } catch (err: any) {
    console.error('[Timeline] Delivery event collection error:', err.message);
  }

  return events;
}

async function collectExploitationEvents(db: any, filter: TimelineFilter): Promise<TimelineEvent[]> {
  const events: TimelineEvent[] = [];

  try {
    let jobQuery = db.select().from(exploitJobs);
    const jobConditions: any[] = [];
    if (filter.startDate) jobConditions.push(gte(exploitJobs.createdAt, new Date(filter.startDate)));
    if (filter.endDate) jobConditions.push(lte(exploitJobs.createdAt, new Date(filter.endDate)));
    if (filter.targetDomain) jobConditions.push(eq(exploitJobs.targetDomain, filter.targetDomain));
    if (jobConditions.length > 0) jobQuery = jobQuery.where(and(...jobConditions));
    const jobs = await jobQuery.orderBy(desc(exploitJobs.createdAt)).limit(filter.limit || 100);

    for (const j of jobs) {
      const isSuccess = j.status === 'success';
      const hasAgent = !!j.calderaAgentPaw;

      // Exploitation event
      events.push({
        id: `exploit_job:${j.id}`,
        engagementId: null,
        timestamp: new Date(j.startedAt || j.createdAt).getTime(),
        phase: 'exploitation',
        source: 'exploit_job',
        severity: isSuccess ? 'critical' : j.status === 'failed' ? 'low' : 'high',
        title: `MSF Exploit: ${j.exploitModule.split('/').slice(-2).join('/')}`,
        description: `${j.exploitModule} → ${j.targetIp}:${j.targetPort || '?'}. ${isSuccess ? 'SUCCESS' : j.status.toUpperCase()}${j.cveId ? ` (${j.cveId})` : ''}`,
        icon: 'Zap',
        color: isSuccess ? 'red' : 'orange',
        sourceRecordId: j.id,
        targetDomain: j.targetDomain || undefined,
        cveId: j.cveId || undefined,
        msfModule: j.exploitModule,
        status: isSuccess ? 'success' : j.status === 'failed' || j.status === 'aborted' || j.status === 'timeout' ? 'failed' : j.status === 'running' ? 'running' : 'pending',
        details: {
          exploitModule: j.exploitModule,
          payloadModule: j.payloadModule,
          targetIp: j.targetIp,
          targetPort: j.targetPort,
          cveId: j.cveId,
          status: j.status,
          msfJobId: j.msfJobId,
          msfSessionId: j.msfSessionId,
          sessionType: j.sessionType,
          result: j.result,
          errorMessage: j.errorMessage,
          scopeVerified: j.scopeVerified,
          approvedBy: j.approvedBy,
        },
      });

      // If agent was deployed, add Installation event
      if (hasAgent) {
        events.push({
          id: `exploit_job_agent:${j.id}`,
          engagementId: null,
          timestamp: new Date(j.completedAt || j.createdAt).getTime(),
          phase: 'installation',
          source: 'exploit_job',
          severity: 'critical',
          title: `Agent Deployed: ${j.calderaAgentPaw}`,
          description: `Caldera agent installed on ${j.targetIp} via ${j.exploitModule.split('/').slice(-2).join('/')}. Session type: ${j.sessionType || 'unknown'}`,
          icon: 'Bot',
          color: 'red',
          sourceRecordId: j.id,
          targetDomain: j.targetDomain || undefined,
          msfModule: j.exploitModule,
          status: 'success',
          details: {
            calderaAgentPaw: j.calderaAgentPaw,
            calderaStagerUrl: j.calderaStagerUrl,
            sessionType: j.sessionType,
            targetIp: j.targetIp,
            exploitModule: j.exploitModule,
          },
        });
      }
    }
  } catch (err: any) {
    console.error('[Timeline] Exploitation event collection error:', err.message);
  }

  return events;
}

async function collectC2Events(db: any, filter: TimelineFilter): Promise<TimelineEvent[]> {
  const events: TimelineEvent[] = [];

  try {
    // Activity logs related to Caldera operations
    let logQuery = db.select().from(activityLogs);
    const logConditions: any[] = [];
    logConditions.push(
      or(
        sql`${activityLogs.action} LIKE '%caldera%'`,
        sql`${activityLogs.action} LIKE '%operation%'`,
        sql`${activityLogs.action} LIKE '%agent%'`,
        sql`${activityLogs.action} LIKE '%ability%'`,
      )
    );
    if (filter.startDate) logConditions.push(gte(activityLogs.createdAt, new Date(filter.startDate)));
    if (filter.endDate) logConditions.push(lte(activityLogs.createdAt, new Date(filter.endDate)));
    if (logConditions.length > 0) logQuery = logQuery.where(and(...logConditions));
    const logs = await logQuery.orderBy(desc(activityLogs.createdAt)).limit(filter.limit || 200);

    for (const l of logs) {
      const action = l.action.toLowerCase();
      let phase: KillChainPhase = 'command_control';
      let icon = 'Radio';
      let color = 'violet';

      if (action.includes('operation') && action.includes('creat')) {
        phase = 'command_control';
        icon = 'Play';
      } else if (action.includes('agent')) {
        phase = 'installation';
        icon = 'Bot';
        color = 'red';
      } else if (action.includes('exfil') || action.includes('collect') || action.includes('impact')) {
        phase = 'actions_on_objectives';
        icon = 'Download';
        color = 'amber';
      }

      events.push({
        id: `activity_log:${l.id}`,
        engagementId: null,
        timestamp: new Date(l.createdAt).getTime(),
        phase,
        source: 'activity_log',
        severity: phase === 'actions_on_objectives' ? 'critical' : 'medium',
        title: l.action,
        description: l.details || l.action,
        icon,
        color,
        sourceRecordId: l.id,
        status: 'info',
        details: {
          action: l.action,
          details: l.details,
          userId: l.userId,
          serverId: l.serverId,
          ipAddress: l.ipAddress,
        },
      });
    }
  } catch (err: any) {
    console.error('[Timeline] C2 event collection error:', err.message);
  }

  return events;
}

async function collectPipelineEvents(db: any, filter: TimelineFilter): Promise<TimelineEvent[]> {
  const events: TimelineEvent[] = [];

  try {
    let pipeQuery = db.select().from(engagementPipelines);
    const pipeConditions: any[] = [];
    if (filter.engagementId) pipeConditions.push(eq(engagementPipelines.engagementId, filter.engagementId));
    if (filter.startDate) pipeConditions.push(gte(engagementPipelines.createdAt, new Date(filter.startDate)));
    if (filter.endDate) pipeConditions.push(lte(engagementPipelines.createdAt, new Date(filter.endDate)));
    if (pipeConditions.length > 0) pipeQuery = pipeQuery.where(and(...pipeConditions));
    const pipelines = await pipeQuery.orderBy(desc(engagementPipelines.createdAt)).limit(filter.limit || 50);

    for (const p of pipelines) {
      const stepLog = (p.stepLog as any[]) || [];
      events.push({
        id: `engagement_pipeline:${p.id}`,
        engagementId: p.engagementId,
        timestamp: new Date(p.createdAt).getTime(),
        phase: 'reconnaissance',
        source: 'engagement_pipeline',
        severity: 'medium',
        title: `Pipeline: ${p.name}`,
        description: `Engagement pipeline (${stepLog.filter((s: any) => s.status === 'complete').length}/${p.totalSteps || 6} steps complete). Status: ${p.status}`,
        icon: 'Workflow',
        color: 'blue',
        sourceRecordId: p.id,
        status: p.status === 'completed' ? 'success' : p.status === 'failed' ? 'failed' : p.status === 'pending' ? 'pending' : 'running',
        details: {
          name: p.name,
          status: p.status,
          targetDomains: p.targetDomains,
          currentStep: p.currentStep,
          totalSteps: p.totalSteps,
          stepLog,
          riskSummary: p.riskSummary,
          engagementId: p.engagementId,
        },
      });
    }
  } catch (err: any) {
    console.error('[Timeline] Pipeline event collection error:', err.message);
  }

  return events;
}

// ─── Main Aggregation ────────────────────────────────────────────────────────

export async function getEngagementTimeline(filter: TimelineFilter = {}): Promise<{
  events: TimelineEvent[];
  stats: TimelineStats;
}> {
  const db = await getDb();
  if (!db) return { events: [], stats: emptyStats() };

  // Check which phases to collect
  const collectAll = !filter.phases || filter.phases.length === 0;
  const shouldCollect = (phase: KillChainPhase) => collectAll || filter.phases!.includes(phase);

  // Collect events from all sources in parallel
  const [reconEvents, weaponEvents, deliveryEvents, exploitEvents, c2Events, pipelineEvents] = await Promise.all([
    shouldCollect('reconnaissance') ? collectReconEvents(db, filter) : Promise.resolve([]),
    shouldCollect('weaponization') ? collectWeaponizationEvents(db, filter) : Promise.resolve([]),
    shouldCollect('delivery') ? collectDeliveryEvents(db, filter) : Promise.resolve([]),
    (shouldCollect('exploitation') || shouldCollect('installation')) ? collectExploitationEvents(db, filter) : Promise.resolve([]),
    (shouldCollect('command_control') || shouldCollect('actions_on_objectives')) ? collectC2Events(db, filter) : Promise.resolve([]),
    collectAll ? collectPipelineEvents(db, filter) : Promise.resolve([]),
  ]);

  let allEvents = [
    ...reconEvents,
    ...weaponEvents,
    ...deliveryEvents,
    ...exploitEvents,
    ...c2Events,
    ...pipelineEvents,
  ];

  // Apply source filter
  if (filter.sources && filter.sources.length > 0) {
    allEvents = allEvents.filter(e => filter.sources!.includes(e.source));
  }

  // Apply severity filter
  if (filter.severity && filter.severity.length > 0) {
    allEvents = allEvents.filter(e => filter.severity!.includes(e.severity));
  }

  // Sort by timestamp descending (most recent first)
  allEvents.sort((a, b) => b.timestamp - a.timestamp);

  // Apply pagination
  const offset = filter.offset || 0;
  const limit = filter.limit || 500;
  const paginatedEvents = allEvents.slice(offset, offset + limit);

  // Compute stats from ALL events (before pagination)
  const stats = computeStats(allEvents);

  return { events: paginatedEvents, stats };
}

export async function getEngagementSummary(engagementId: number): Promise<EngagementSummary | null> {
  const db = await getDb();
  if (!db) return null;

  // Get engagement
  const [eng] = await db.select().from(engagements).where(eq(engagements.id, engagementId));
  if (!eng) return null;

  // Get timeline for this engagement
  const { events, stats } = await getEngagementTimeline({ engagementId });

  // Also get events by target domain if engagement has one
  let domainEvents: TimelineEvent[] = [];
  if (eng.targetDomain) {
    const domainResult = await getEngagementTimeline({ targetDomain: eng.targetDomain });
    domainEvents = domainResult.events.filter(e => !events.find(ex => ex.id === e.id));
  }

  const allEvents = [...events, ...domainEvents];
  const fullStats = computeStats(allEvents);

  // Build kill chain progress
  const killChainProgress = PHASE_ORDER.map(phase => {
    const phaseEvents = allEvents.filter(e => e.phase === phase);
    const timestamps = phaseEvents.map(e => e.timestamp).filter(Boolean);
    return {
      phase,
      label: PHASE_LABELS[phase],
      eventCount: phaseEvents.length,
      status: phaseEvents.length === 0 ? 'not_started' as const :
        phaseEvents.some(e => e.status === 'running') ? 'in_progress' as const : 'completed' as const,
      firstEvent: timestamps.length > 0 ? Math.min(...timestamps) : null,
      lastEvent: timestamps.length > 0 ? Math.max(...timestamps) : null,
    };
  });

  return {
    engagement: {
      id: eng.id,
      name: eng.name,
      customerName: eng.customerName,
      type: eng.engagementType,
      status: eng.status,
      targetDomain: eng.targetDomain,
      startDate: eng.startDate ? new Date(eng.startDate).getTime() : null,
    },
    timeline: fullStats,
    killChainProgress,
    reconFindings: allEvents.filter(e => e.phase === 'reconnaissance').length,
    exploitsAttempted: allEvents.filter(e => e.source === 'exploit_job').length,
    exploitsSucceeded: allEvents.filter(e => e.source === 'exploit_job' && e.status === 'success').length,
    agentsDeployed: allEvents.filter(e => e.phase === 'installation' && e.status === 'success').length,
    phishingCampaigns: allEvents.filter(e => e.source === 'gophish_campaign').length,
    typosquatDomains: allEvents.filter(e => e.source === 'typosquat_domain').length,
  };
}

// ─── Stats Helpers ───────────────────────────────────────────────────────────

function computeStats(events: TimelineEvent[]): TimelineStats {
  const byPhase: Record<KillChainPhase, number> = {
    reconnaissance: 0,
    weaponization: 0,
    delivery: 0,
    exploitation: 0,
    installation: 0,
    command_control: 0,
    actions_on_objectives: 0,
  };
  const bySource: Record<string, number> = {};
  const bySeverity: Record<EventSeverity, number> = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  const byStatus: Record<string, number> = {};

  let firstEventTime: number | null = null;
  let lastEventTime: number | null = null;
  let firstRecon: number | null = null;
  let firstExploit: number | null = null;
  let firstAgent: number | null = null;
  let firstObjective: number | null = null;

  for (const e of events) {
    byPhase[e.phase] = (byPhase[e.phase] || 0) + 1;
    bySource[e.source] = (bySource[e.source] || 0) + 1;
    bySeverity[e.severity] = (bySeverity[e.severity] || 0) + 1;
    byStatus[e.status] = (byStatus[e.status] || 0) + 1;

    if (firstEventTime === null || e.timestamp < firstEventTime) firstEventTime = e.timestamp;
    if (lastEventTime === null || e.timestamp > lastEventTime) lastEventTime = e.timestamp;

    if (e.phase === 'reconnaissance' && (firstRecon === null || e.timestamp < firstRecon)) firstRecon = e.timestamp;
    if (e.phase === 'exploitation' && (firstExploit === null || e.timestamp < firstExploit)) firstExploit = e.timestamp;
    if (e.phase === 'installation' && (firstAgent === null || e.timestamp < firstAgent)) firstAgent = e.timestamp;
    if (e.phase === 'actions_on_objectives' && (firstObjective === null || e.timestamp < firstObjective)) firstObjective = e.timestamp;
  }

  const phasesReached = PHASE_ORDER.filter(p => byPhase[p] > 0);
  const furthestPhase = phasesReached.length > 0 ? phasesReached[phasesReached.length - 1] : null;

  return {
    totalEvents: events.length,
    byPhase,
    bySource,
    bySeverity,
    byStatus,
    phasesReached,
    furthestPhase,
    firstEventTime,
    lastEventTime,
    timeToFirstExploit: firstRecon && firstExploit ? firstExploit - firstRecon : null,
    timeToFirstAgent: firstRecon && firstAgent ? firstAgent - firstRecon : null,
    timeToObjective: firstRecon && firstObjective ? firstObjective - firstRecon : null,
  };
}

function emptyStats(): TimelineStats {
  return {
    totalEvents: 0,
    byPhase: {
      reconnaissance: 0,
      weaponization: 0,
      delivery: 0,
      exploitation: 0,
      installation: 0,
      command_control: 0,
      actions_on_objectives: 0,
    },
    bySource: {},
    bySeverity: { info: 0, low: 0, medium: 0, high: 0, critical: 0 },
    byStatus: {},
    phasesReached: [],
    furthestPhase: null,
    firstEventTime: null,
    lastEventTime: null,
    timeToFirstExploit: null,
    timeToFirstAgent: null,
    timeToObjective: null,
  };
}
