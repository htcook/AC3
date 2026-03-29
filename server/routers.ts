import { COOKIE_NAME } from "@shared/const";
import { getSessionCookieOptions } from "./_core/cookies";
import { systemRouter } from "./_core/systemRouter";
import { publicProcedure, protectedProcedure, router } from "./_core/trpc";
import { ENV } from "./_core/env";
import { z } from "zod";
import { TRPCError } from "@trpc/server";
import * as db from "./db";
import jwt from "jsonwebtoken";
import type { InsertIocFeed } from "../drizzle/schema";
import { threatIntelRouter } from "./routers/threat-intel";
import { darkwebBridgeRouter } from "./routers/darkweb-bridge";
import { campaignArchetypeRouter } from "./routers/campaign-archetypes";
import { phishingOpsRouter } from "./routers/phishing";
import { metasploitCatalogRouter } from "./routers/metasploit-catalog";
import { engagementTimelineRouter } from "./routers/engagement-timeline";
import { stixExportRouter } from "./routers/stix-export";
import { clientPortalRouter } from "./routers/client-portal";
import { customerPortalRouter } from "./routers/customer-portal";
import { emulationPlaybooksRouter } from "./routers/emulation-playbooks";
import { evidenceRouter } from "./routers/evidence";
import { attackPathsRouter } from "./routers/attack-paths";
import { purpleTeamRouter } from "./routers/purple-team";
import { webhooksRouter } from "./routers/webhooks";
import { bugBountyRouter } from "./routers/bug-bounty";
import { scoringRouter } from "./routers/scoring";
import { accuracyEngineRouter } from "./routers/accuracy-engine";
import { sshKeysRouter } from "./routers/ssh-keys";
import { msfSessionsRouter } from "./routers/msf-sessions";
import { sessionRecordingsRouter } from "./routers/session-recordings";
import { postExploitPlaybooksRouter } from "./routers/post-exploit-playbooks";
import { fileTransfersRouter } from "./routers/file-transfers";
import { sessionAlerterRouter } from "./routers/session-alerter";
import { payloadGeneratorRouter } from "./routers/payload-generator";
import { evasionEngineRouter } from "./routers/evasion-engine";
import { siemConnectorsRouter } from "./routers/siem-connectors";
import { darkwebIntelRouter } from "./routers/darkweb-intel";
import { threatIntelTrainingRouter } from "./routers/threat-intel-training";
import { roeAuditRouter } from "./routers/roe-audit";
import { validationSchedulerRouter } from "./routers/validation-scheduler";
import { detectionRulesRouter } from "./routers/detection-rules";
import { cloudAttackPathsRouter } from "./routers/cloud-attack-paths";
import { adAttackSimRouter } from "./routers/ad-attack-sim";
import { edrValidationRouter } from "./routers/edr-validation";
import { complianceMapperRouter } from "./routers/compliance-mapper";
import { apiSecurityRouter } from "./routers/api-security";
import { cloudCredentialsRouter } from "./routers/cloud-credentials";
import { adDomainConnectorRouter } from "./routers/ad-domain-connector";
import { credentialAlertsRouter } from "./routers/credential-alerts";
import { adAttackPathGraphRouter } from "./routers/ad-attack-path-graph";
import { forestMapperRouter } from "./routers/forest-mapper";
import { bloodhoundImportRouter } from "./routers/bloodhound-import";
import { credentialAutoRotationRouter } from "./routers/credential-auto-rotation";
import { siemFeedbackRouter } from "./routers/siem-feedback";
import { accountAuthRouter } from "./routers/account-auth";
import { tenantRouter } from "./routers/tenants";
import { vulnScannerRouter } from "./routers/vuln-scanner";
import { riskTrendingRouter } from "./routers/risk-trending";
import { agentlessBASRouter } from "./routers/agentless-bas";
import { attackPathDiscoveryRouter } from "./routers/attack-path-discovery";
import { reportTemplatesRouter } from "./routers/report-templates";
import { emailSecurityRouter } from "./routers/email-security";
import { ngfwValidationRouter } from "./routers/ngfw-validation";
import { remediationVerificationRouter } from "./routers/remediation-verification";
import { cicdPipelineRouter } from "./routers/cicd-pipeline";
import { soarConnectorRouter } from "./routers/soar-connectors";
import { aiAttackPlannerRouter } from "./routers/ai-attack-planner";
import { corroborationEngineRouter } from "./routers/corroboration-engine";
import { nvdCveMatcherRouter } from "./routers/nvd-cve-matcher";
import { compensatingControlsRouter } from "./routers/compensating-controls";
import { preflightChecksRouter } from "./routers/preflight-checks";
import { activeVerificationRouter } from "./routers/active-verification";
import { exploitArsenalRouter } from "./routers/exploit-arsenal";
import { icsOtSecurityRouter } from "./routers/ics-ot-security";
import { webAppScanningRouter } from "./routers/web-app-scanning";
import { atomicRedTeamRouter } from "./routers/atomic-red-team";
import { sliverC2Router } from "./routers/sliver-c2";
import { manjusakaC2Router } from "./routers/manjusaka-c2";
import { nucleiScannerRouter } from "./routers/nuclei-scanner";
import { attackCoverageRouter } from "./routers/attack-coverage";
import { unifiedPipelineRouter } from "./routers/unified-pipeline";
import { roeBuilderRouter } from "./routers/roe-builder";
import { ksiEvidenceChainRouter } from "./routers/ksi-evidence-chain";
import { evidenceIntegrityRouter } from "./routers/evidence-integrity";
import { ksiValidationSchedulerRouter } from "./routers/ksi-validation-scheduler";
import { oscalExportRouter } from "./routers/oscal-export";
import { ksiAutoCollectorRouter } from "./routers/ksi-auto-collector";
import { ksiThreatMapRouter } from "./routers/ksi-threat-map";
import { configBaselineRouter } from "./routers/config-baseline";
import { attackVectorEngineRouter } from "./routers/attack-vector-engine";
import { ksiScheduledCollectionRouter } from "./routers/ksi-scheduled-collection";
import { engagementAutomationRouter } from "./routers/engagement-automation";
import { threatEnrichmentEngineRouter } from "./routers/threat-enrichment-engine";
import { infraWikiRouter } from "./routers/infra-wiki";
import { liveInfraRouter } from "./routers/live-infra";
import { discoveryEngineRouter } from "./routers/discovery-engine";
import { workflowRouter } from "./routers/workflow";
import { webCrawlerRouter } from "./routers/web-crawler";
import { vendorIntegrationsRouter } from "./routers/vendor-integrations";
import { agentManagerRouter } from "./routers/agent";
import { ssilRouter } from "./routers/ssil";
import { projectDiscoveryRouter } from "./routers/projectdiscovery";
import { knowledgeBaseRouter } from "./routers/knowledge-base";
import { knowledgeCacheRouter } from "./routers/knowledge-cache";
import { abilityGraphRouter } from "./routers/ability-graph";
import { aiSecurityValidationRouter } from "./routers/ai-security-validation";
import { serviceFingerprintRouter } from "./routers/service-fingerprinter";
import { amassRouter } from "./routers/amass";
import { scanforgeDiscoveryRouter } from "./routers/scanforge-discovery";
import { discoveryChainRouter } from "./routers/discovery-chain";
import { crawlPhishRouter } from "./routers/crawl-phish";
import { errorLogRouter, oemCredsRouter, aiChatRouter } from "./routers/error-log";
import { bugReportsRouter } from "./routers/bug-reports";
import { llmTelemetryRouter } from "./routers/llm-telemetry";
import { containerRegistryRouter } from "./routers/container-registry";
import { exploitationBridgeRouter } from "./routers/exploitation-bridge";
import { privescRouter } from "./routers/privesc";
import { opsecRiskRouter } from "./routers/opsec-risk";
import { lateralMovementRouter } from "./routers/lateral-movement";
import { engagementWorkflowRouter } from "./routers/engagement-workflow";
import { campaignAdvisorRouter } from "./routers/campaign-advisor";
import { reportExportRouter } from "./routers/report-export";
import { accountRouter } from "./routers/account-management";
import { samlRouter } from "./routers/saml-auth";
import { sessionRouter } from "./routers/session-management";
import { tenantManagementRouter } from "./routers/tenant-management";
import { tenantOnboardingRouter } from "./routers/tenant-onboarding";
import { complianceDashboardRouter } from "./routers/compliance-dashboard";
import { scanWebhooksRouter } from "./routers/scan-webhooks";
import { authAssessmentRouter } from "./routers/auth-assessment";
import { cloudSecurityValidationRouter } from "./routers/cloud-security-validation";
import { sigmaRulesRouter } from "./routers/sigma-rules";
import { c2ActorOrchestrationRouter } from "./routers/c2-actor-orchestration";
import { threatGroupKnowledgeRouter } from "./routers/threat-group-knowledge";
import { owaspCoverageRouter } from "./routers/owasp-coverage";
import { trainingLabRouter } from "./routers/training-lab";
import { socIntegrationHubRouter } from "./routers/soc-integration-hub";
import { cloudWorkloadTestingRouter } from "./routers/cloud-workload-testing";
import { llmReliabilityRouter } from "./routers/llm-reliability";
import { agentInstallerRouter } from "./routers/agent-installer";
import { msspAnalyticsRouter } from "./routers/mssp-analytics";
import { dataExfilSimulationRouter } from "./routers/data-exfil-simulation";
import { operatorCockpitRouter } from "./routers/operator-cockpit";
import { dastScannersRouter } from "./routers/dast-scanners";
import { packetAnalysisRouter } from "./routers/packet-analysis";
import { aiGovernanceRouter } from "./routers/ai-governance";
import { executiveDashboardRouter } from "./routers/executive-dashboard";
import { threatIntelMatchingRouter } from "./routers/threat-intel-matching";
import { graduationEngineRouter } from "./routers/graduation-engine";
import { remediationRouter } from "./routers/remediation";
import { c2KnowledgeBaseRouter } from "./routers/c2-knowledge-base";
import { empireRouter } from "./routers/empire";
import { safetyEngineRouter } from "./routers/safety-engine";
import { agentInternalScanningRouter } from "./routers/agent-internal-scanning";
import { phishingImpactRouter } from "./routers/phishing-impact";
import { soc2ComplianceRouter } from "./routers/soc2-compliance";
import { evidenceGalleryRouter } from "./routers/evidence-gallery";

// --- Extracted inline routers ---
import { authRouter, calderaAuthRouter } from "./routers/auth-core";
import { serverRouter, credentialsRouter } from "./routers/server-config";
import { calderaProxyRouter } from "./routers/caldera-proxy";
import { gophishProxyRouter } from "./routers/gophish-proxy";
import { calderaRouter, campaignRouter, campaignEngagementsRouter } from "./routers/caldera-ops";
import { activityRouter } from "./routers/activity";
import { engagementsRouter } from "./routers/engagements-core";
import { osintRouter, whoisRouter, typosquatRouter, monitorRouter } from "./routers/osint-core";
import { reportsRouter, templateGeneratorRouter } from "./routers/reports-core";
import { domainIntelRouter } from "./routers/domain-intel-core";
import { threatActorDbRouter, abilitiesLibraryRouter } from "./routers/threat-actor-db";
import { iocFeedRouter } from "./routers/ioc-feed";
import { engagementPipelineRouter } from "./routers/engagement-pipeline";
import { ttpEngineRouter } from "./routers/ttp-engine";
import { platformStatsRouter } from "./routers/platform-stats";
import { fipsStatusRouter } from "./routers/fips-status";
import { exploitCatalogRouter } from "./routers/exploit-catalog-core";
import { validationRouter } from "./routers/validation-core";
import { engagementOpsRouter } from "./routers/engagement-ops-core";
import { scanServerRouter } from "./routers/scan-server";
import { huntEngineRouter } from "./routers/hunt-engine";
import { reviewQueueRouter } from "./routers/review-queue";
import { jobQueueRouter } from "./routers/job-queue";
import { learningEngineRouter } from "./routers/learning-engine";
import { accuracyFeedbackRouter } from "./routers/accuracy-feedback";
import { emberAgentRouter } from "./routers/ember-agent";
import { emberTemplatesRouter } from "./routers/ember-templates";
import { testLabRouter } from "./routers/test-lab";
import { ac3ReportsRouter } from "./routers/ac3-reports";
import { engagementScanImportsRouter } from "./routers/engagement-scan-imports";
import { dfirLibraryRouter } from "./routers/dfir-library";
import { scanSchedulesRouter } from "./routers/scan-schedules";
import { agentRegistryRouter } from "./routers/agent-registry";
import { trainingDataDashboardRouter } from "./routers/training-data-dashboard";
import { labEngagementSeedRouter } from "./routers/lab-engagement-seed";
import { labEngagementSeedWave2Router } from "./routers/lab-engagement-seed-wave2";
import { agentLeaderboardRouter } from "./routers/agent-leaderboard";
import { realtimeMonitorRouter } from "./routers/realtime-monitor";
import { trainingDataReviewRouter } from "./routers/training-data-review";
import { liveTriggerTempRouter } from "./routers/live-trigger-temp"; // TEMP: commented out for production
import { campaignOrchestratorRouter } from "./routers/campaign-orchestrator";
import { scanforgeRouter } from "./routers/scanforge";
import { complianceExportsRouter } from "./routers/compliance-exports";
import { platformCredentialsRouter } from "./routers/platform-credentials";
import { testPlanApprovalRouter } from "./routers/test-plan-approval";

// Caldera session cookie name
const CALDERA_SESSION_COOKIE = 'caldera_session';

// Helper to get cookie options for Caldera session
function getCalderaCookieOptions(req: any, rememberMe = false) {
  const host = req.hostname || req.headers?.host || '';
  const isLocalhost = host.includes('localhost');
  const isManusPreview = host.includes('manus.space') || host.includes('manus.computer') || host.includes('manusvm.computer');
  
  // Use 'none' + secure for Manus preview iframe contexts (cross-origin)
  // Use 'lax' for everything else — works for top-level navigations (window.location.href)
  // IMPORTANT: Do NOT set explicit domain — let the browser default to the exact host.
  // Setting domain='.aceofcloud.io' can cause issues when served through a CNAME proxy.
  const sameSite = isManusPreview ? 'none' as const : 'lax' as const;
  
  const opts = {
    path: '/',
    httpOnly: true,
    secure: !isLocalhost,
    sameSite,
    maxAge: rememberMe ? 7 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000, // 7 days or 24 hours
  };
  console.log(`[Auth Cookie] host=${host}, sameSite=${sameSite}, secure=${opts.secure}, maxAge=${opts.maxAge}`);
  return opts;
}

// JWT secret for Caldera sessions (use env var in production)
const CALDERA_JWT_SECRET = process.env.CALDERA_JWT_SECRET || 'caldera-dashboard-secret-key-2024';

// Admin-only procedure
const adminProcedure = protectedProcedure.use(({ ctx, next }) => {
  if (ctx.user.role !== 'admin') {
    throw new TRPCError({ code: 'FORBIDDEN', message: 'Admin access required' });
  }
  return next({ ctx });
});

// GoPhish & Caldera API config from environment
const GOPHISH_URL = ENV.gophishBaseUrl;
const GOPHISH_API_KEY = ENV.gophishApiKey;
const CALDERA_BASE_URL = ENV.calderaBaseUrl;
const CALDERA_API_KEY = ENV.calderaApiKey;

async function fetchGophishAPI(endpoint: string, method: string = 'GET', data?: any) {
  try {
    // FIPS 140-3: Use FIPS HTTPS agent with self-signed cert support
    const { createFIPSHttpsAgent } = await import('./lib/fips-tls');
    const url = `${GOPHISH_URL}${endpoint}`;
    const options: RequestInit & { agent?: any } = {
      method,
      headers: {
        'Authorization': GOPHISH_API_KEY,
        'Content-Type': 'application/json',
      },
      signal: AbortSignal.timeout(15000),
    };
    if (url.startsWith('https://')) {
      // @ts-ignore - Node.js specific option
      options.agent = createFIPSHttpsAgent({ rejectUnauthorized: false });
    }
    if (data) options.body = JSON.stringify(data);
    
    const response = await fetch(url, options);
    if (!response.ok) {
      const errText = await response.text();
      console.error(`GoPhish API error (${endpoint}):`, response.status, errText);
      return null;
    }
    const text = await response.text();
    return text ? JSON.parse(text) : null;
  } catch (error) {
    console.error(`GoPhish API error (${endpoint}):`, error);
    return null;
  }
}

// Caldera API helper
async function fetchCalderaAPI(url: string, apiKey: string, endpoint: string) {
  try {
    const response = await fetch(`${url}${endpoint}`, {
      headers: { 'KEY': apiKey },
      signal: AbortSignal.timeout(30000), // 30 second timeout for large responses
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } catch (error) {
    console.error(`Caldera API error (${endpoint}):`, error);
    return null;
  }
}

export const appRouter = router({
  system: systemRouter,
  knowledgeBase: knowledgeBaseRouter,
  knowledgeCache: knowledgeCacheRouter,
  threatIntel: threatIntelRouter,
  darkwebBridge: darkwebBridgeRouter,
  campaignArchetypes: campaignArchetypeRouter,
  phishingOps: phishingOpsRouter,
  metasploit: metasploitCatalogRouter,
  sshKeys: sshKeysRouter,
  msfSessions: msfSessionsRouter,
  sessionRecordings: sessionRecordingsRouter,
  postExploitPlaybooks: postExploitPlaybooksRouter,
  fileTransfers: fileTransfersRouter,
  sessionAlerter: sessionAlerterRouter,
  payloadGenerator: payloadGeneratorRouter,
  engagementTimeline: engagementTimelineRouter,
  stixExport: stixExportRouter,
  clientPortal: clientPortalRouter,
  customerPortal: customerPortalRouter,
  emulationPlaybooks: emulationPlaybooksRouter,
  evidence: evidenceRouter,
  evidenceGallery: evidenceGalleryRouter,
  attackPaths: attackPathsRouter,
  purpleTeam: purpleTeamRouter,
  webhooks: webhooksRouter,
  bugBounty: bugBountyRouter,
  platformCredentials: platformCredentialsRouter,
  scoring: scoringRouter,
  accuracyEngine: accuracyEngineRouter,
  learningEngine: learningEngineRouter,
  accuracyFeedback: accuracyFeedbackRouter,
  evasionEngine: evasionEngineRouter,
  siemConnectors: siemConnectorsRouter,
  darkwebIntel: darkwebIntelRouter,
  threatIntelTraining: threatIntelTrainingRouter,
  roeAudit: roeAuditRouter,
  validationScheduler: validationSchedulerRouter,
  detectionRules: detectionRulesRouter,
  cloudAttackPaths: cloudAttackPathsRouter,
  adAttackSim: adAttackSimRouter,
  edrValidation: edrValidationRouter,
  complianceMapper: complianceMapperRouter,
  apiSecurity: apiSecurityRouter,
  cloudCredentials: cloudCredentialsRouter,
  adDomainConnector: adDomainConnectorRouter,
  credentialAlerts: credentialAlertsRouter,
  adAttackPathGraph: adAttackPathGraphRouter,
  forestMapper: forestMapperRouter,
  bloodhoundImport: bloodhoundImportRouter,
  credentialAutoRotation: credentialAutoRotationRouter,
  siemFeedback: siemFeedbackRouter,
  tenants: tenantRouter,
  vulnScanner: vulnScannerRouter,
  riskTrending: riskTrendingRouter,
  agentlessBAS: agentlessBASRouter,
  attackPathDiscovery: attackPathDiscoveryRouter,
  reportTemplates: reportTemplatesRouter,
  emailSecurity: emailSecurityRouter,
  ngfwValidation: ngfwValidationRouter,
  remediationVerification: remediationVerificationRouter,
  cicdPipeline: cicdPipelineRouter,
  soarConnector: soarConnectorRouter,
  aiAttackPlanner: aiAttackPlannerRouter,
  corroborationEngine: corroborationEngineRouter,
  nvdCveMatcher: nvdCveMatcherRouter,
  compensatingControls: compensatingControlsRouter,
  preflightChecks: preflightChecksRouter,
  activeVerification: activeVerificationRouter,
  exploitArsenal: exploitArsenalRouter,
  icsOtSecurity: icsOtSecurityRouter,
  webAppScanning: webAppScanningRouter,
  atomicRedTeam: atomicRedTeamRouter,
  sliverC2: sliverC2Router,
  manjusakaC2: manjusakaC2Router,
  nucleiScanner: nucleiScannerRouter,
  attackCoverage: attackCoverageRouter,
  unifiedPipeline: unifiedPipelineRouter,
  roeBuilder: roeBuilderRouter,
  ksiEvidenceChain: ksiEvidenceChainRouter,
  evidenceIntegrity: evidenceIntegrityRouter,
  ksiValidationScheduler: ksiValidationSchedulerRouter,
  oscalExport: oscalExportRouter,
  ksiAutoCollector: ksiAutoCollectorRouter,
  ksiThreatMap: ksiThreatMapRouter,
  configBaseline: configBaselineRouter,
  attackVectorEngine: attackVectorEngineRouter,
  ksiScheduledCollection: ksiScheduledCollectionRouter,
  engagementAutomation: engagementAutomationRouter,
  threatEnrichment: threatEnrichmentEngineRouter,
  infraWiki: infraWikiRouter,
  liveInfra: liveInfraRouter,
  discoveryEngine: discoveryEngineRouter,
  workflow: workflowRouter,
  webCrawler: webCrawlerRouter,
  vendorIntegrations: vendorIntegrationsRouter,
  agentManager: agentManagerRouter,
  ssil: ssilRouter,
  projectDiscovery: projectDiscoveryRouter,
  abilityGraph: abilityGraphRouter,
  aiSecurityValidation: aiSecurityValidationRouter,
  serviceFingerprint: serviceFingerprintRouter,
  amass: amassRouter,
  scanforgeDiscovery: scanforgeDiscoveryRouter,
  discoveryChain: discoveryChainRouter,
  crawlPhish: crawlPhishRouter,
  errorLog: errorLogRouter,
  bugReports: bugReportsRouter,
  oemCreds: oemCredsRouter,
  aiChat: aiChatRouter,
  containerRegistry: containerRegistryRouter,
  exploitationBridge: exploitationBridgeRouter,
  privesc: privescRouter,
  opsecRisk: opsecRiskRouter,
  lateralMovement: lateralMovementRouter,
  engagementWorkflow: engagementWorkflowRouter,
  campaignAdvisor: campaignAdvisorRouter,
  reportExport: reportExportRouter,
  
  auth: authRouter,

  // Server configuration management
  server: serverRouter,

  // Credential management
  credentials: credentialsRouter,

  // Direct Caldera API proxy (for DigitalOcean server)
  calderaProxy: calderaProxyRouter,

  // GoPhish API proxy
  gophishProxy: gophishProxyRouter,

  // Caldera API integration (database-backed)
  caldera: calderaRouter,

  // Account management (profiles, team, invitations, compliance)
  account: accountRouter,
  saml: samlRouter,
  sessions: sessionRouter,
  tenantManagement: tenantManagementRouter,
  tenantOnboarding: tenantOnboardingRouter,
  complianceDashboard: complianceDashboardRouter,
  scanWebhooks: scanWebhooksRouter,
  authAssessment: authAssessmentRouter,
  cloudSecurityValidation: cloudSecurityValidationRouter,
  sigmaRules: sigmaRulesRouter,
  c2ActorOrchestration: c2ActorOrchestrationRouter,

  // Campaign management
  campaign: campaignRouter,

  // Activity logs
  activity: activityRouter,

  // Caldera credential authentication
  accountAuth: accountAuthRouter,
  calderaAuth: calderaAuthRouter,

  // Campaign-Engagement linking
  campaignEngagements: campaignEngagementsRouter,

  // Engagement management
  engagements: engagementsRouter,

  // ==================== OSINT RECON ====================
  osint: osintRouter,

  // ==================== WHOIS & DOMAIN AVAILABILITY ====================
  whois: whoisRouter,

  // ==================== TYPOSQUAT DOMAIN PURCHASING & GOPHISH INTEGRATION ====================
  typosquat: typosquatRouter,

  // ==================== OSINT MONITORING ====================
  monitor: monitorRouter,

  // ==================== ENGAGEMENT REPORTS ====================
  reports: reportsRouter,

  // IOC-Driven GoPhish Template Generator
  templateGenerator: templateGeneratorRouter,

  // Domain Intel Pipeline
  domainIntel: domainIntelRouter,

  // ─── Threat Actor Database ──────────────────────────────────────────
  threatActorDb: threatActorDbRouter,

  // ─── Abilities Library ──────────────────────────────────────────────
  abilitiesLibrary: abilitiesLibraryRouter,

  // ─── IOC Feed Integration ───────────────────────────────────────────
  iocFeed: iocFeedRouter,

  // ─── Automated Engagement Pipeline ──────────────────────────────────
  engagementPipeline: engagementPipelineRouter,

  // ─── TTP Knowledge Engine ─────────────────────────────────────────────
  ttpEngine: ttpEngineRouter,

  // ─── Dynamic Platform Stats (public, for homepage) ──────────────────
  platformStats: platformStatsRouter,

  // ─── FIPS 140-3 Compliance Status ──────────────────────────────────
  fipsStatus: fipsStatusRouter,

  // ─── Exploit Catalog (browser + enrichment management) ─────────────
  exploitCatalog: exploitCatalogRouter,

  // ─── Autonomous Validation Engine ────────────────────────────────────────
  validation: validationRouter,

  // ── Engagement Ops: LLM-orchestrated autonomous execution engine ──────────
  engagementOps: engagementOpsRouter,

  // ─── Scan Server Health ──────────────────────────────────────────────────
  scanServer: scanServerRouter,

  // ─── LLM Telemetry Dashboard ────────────────────────────────────────────
  llmTelemetry: llmTelemetryRouter,

  // ─── Hunt Workflow Engine (DHS/GSA HACS-Compliant) ──────────────────────
  huntEngine: huntEngineRouter,
  // ─── Review Queue (Tier 2 Approval Workflow) ─────────────────────────────
  reviewQueue: reviewQueueRouter,
  // ─── Job Queue (Redis-backed DO worker dispatch) ────────────────────────
  jobQueue: jobQueueRouter,
  // ─── Threat Group Knowledge Base ────────────────────────────────────────
  threatGroupKnowledge: threatGroupKnowledgeRouter,
  // ─── OWASP Coverage Tracking & Export ───────────────────────────────────
  owaspCoverage: owaspCoverageRouter,
  trainingLab: trainingLabRouter,
  socIntegrationHub: socIntegrationHubRouter,
  cloudWorkloadTesting: cloudWorkloadTestingRouter,
  llmReliability: llmReliabilityRouter,
  agentInstaller: agentInstallerRouter,
  msspAnalytics: msspAnalyticsRouter,
  dataExfilSimulation: dataExfilSimulationRouter,
  operatorCockpit: operatorCockpitRouter,

  // ─── DAST Scanners & Service Audits (Nikto, Wapiti, Arachni, SSH, FTP) ─────
  dastScanners: dastScannersRouter,
  // ─── Packet Analysis & Manipulation (tcpdump, tshark, Scapy) ────────────────
  packetAnalysis: packetAnalysisRouter,
  // ─── AI Governance & Guardrails (NIST AI RMF, OMB M-24-10, DoD RAI) ────────
  aiGovernance: aiGovernanceRouter,
  executiveDashboard: executiveDashboardRouter,
  threatIntelMatching: threatIntelMatchingRouter,
  graduationEngine: graduationEngineRouter,
  remediation: remediationRouter,
  c2KnowledgeBase: c2KnowledgeBaseRouter,
  empire: empireRouter,
  // ─── Production-Safe Autonomous Mode ─────────────────────────────────────
  safetyEngine: safetyEngineRouter,
  // ─── Agent-Based Internal Scanning ─────────────────────────────────────────
  agentInternalScanning: agentInternalScanningRouter,
  // ─── Phishing Impact Testing ───────────────────────────────────────────────
  phishingImpact: phishingImpactRouter,
  // ─── SOC 2 / Enterprise Compliance ─────────────────────────────────────────
  soc2Compliance: soc2ComplianceRouter,
  // ─── Ember Agent System (AC3 Proprietary Agent) ─────────────────────────────
  ember: emberAgentRouter,
  emberTemplates: emberTemplatesRouter,
  // ─── Test Lab (Agent Testing, LLM Training, Graduation Bridge) ─────────────
  testLab: testLabRouter,
  // ─── AC3 Report Generator (FedRAMP-Compliant Pentest/Red Team Reports) ──────
  ac3Reports: ac3ReportsRouter,
  // ─── Engagement Scan Report Ingestion (Nessus, Qualys, Burp, ZAP, OpenVAS) ──
  engagementScanImports: engagementScanImportsRouter,
  dfirLibrary: dfirLibraryRouter,
  scanSchedules: scanSchedulesRouter,
  // ─── Agent Registry & NEXUS Pipeline (Offensive Agent Definitions + Code Gen) ──
  agentRegistry: agentRegistryRouter,
  // ─── Training Data Dashboard (Decision Logs, Training Examples, Telemetry Analytics) ──
  trainingData: trainingDataDashboardRouter,
  // ─── Lab Engagement Seed (Populate all LLM tables with realistic lab data) ──
  labSeed: labEngagementSeedRouter,
  labSeedWave2: labEngagementSeedWave2Router,
  // ─── Agent Performance Leaderboard ──
  agentLeaderboard: agentLeaderboardRouter,
  // ─── Real-Time Engagement Monitoring ──
  realtimeMonitor: realtimeMonitorRouter,
  // ─── Training Data Quality Review & JSONL Export ──
  trainingReview: trainingDataReviewRouter,
  // ─── TEMP: Live engagement trigger (commented out for production) ──
  liveTrigger: liveTriggerTempRouter,
  // ─── Campaign Orchestrator (Multi-stage Red Team Campaign Chaining) ──
  campaignOrchestrator: campaignOrchestratorRouter,
  // ─── ScanForge DAST Engine (Custom Vulnerability Scanner) ──────────────
  scanforge: scanforgeRouter,
  testPlanApproval: testPlanApprovalRouter,
  // ─── Compliance Exports (NVD CVE Lookup, NIST 800-53 Report, ATT&CK Navigator) ──
  complianceExports: complianceExportsRouter,
});
export type AppRouter = typeof appRouter;

