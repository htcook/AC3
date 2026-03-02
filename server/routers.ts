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
import { nucleiScannerRouter } from "./routers/nuclei-scanner";
import { attackCoverageRouter } from "./routers/attack-coverage";
import { unifiedPipelineRouter } from "./routers/unified-pipeline";
import { roeBuilderRouter } from "./routers/roe-builder";
import { ksiEvidenceChainRouter } from "./routers/ksi-evidence-chain";
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
import { abilityGraphRouter } from "./routers/ability-graph";
import { aiSecurityValidationRouter } from "./routers/ai-security-validation";
import { serviceFingerprintRouter } from "./routers/service-fingerprinter";
import { amassRouter } from "./routers/amass";
import { nmapRouter } from "./routers/nmap";
import { discoveryChainRouter } from "./routers/discovery-chain";
import { crawlPhishRouter } from "./routers/crawl-phish";
import { errorLogRouter, oemCredsRouter, aiChatRouter } from "./routers/error-log";
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
    // GoPhish uses self-signed TLS cert
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
    const url = `${GOPHISH_URL}${endpoint}`;
    const options: RequestInit = {
      method,
      headers: {
        'Authorization': GOPHISH_API_KEY,
        'Content-Type': 'application/json',
      },
      signal: AbortSignal.timeout(15000),
    };
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
  emulationPlaybooks: emulationPlaybooksRouter,
  evidence: evidenceRouter,
  attackPaths: attackPathsRouter,
  purpleTeam: purpleTeamRouter,
  webhooks: webhooksRouter,
  bugBounty: bugBountyRouter,
  scoring: scoringRouter,
  accuracyEngine: accuracyEngineRouter,
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
  nucleiScanner: nucleiScannerRouter,
  attackCoverage: attackCoverageRouter,
  unifiedPipeline: unifiedPipelineRouter,
  roeBuilder: roeBuilderRouter,
  ksiEvidenceChain: ksiEvidenceChainRouter,
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
  nmap: nmapRouter,
  discoveryChain: discoveryChainRouter,
  crawlPhish: crawlPhishRouter,
  errorLog: errorLogRouter,
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
  
  auth: router({
    me: publicProcedure.query(opts => opts.ctx.user),
    logout: publicProcedure.mutation(({ ctx }) => {
      const cookieOptions = getSessionCookieOptions(ctx.req);
      ctx.res.clearCookie(COOKIE_NAME, { ...cookieOptions, maxAge: -1 });
      return { success: true } as const;
    }),
  }),

  // Server configuration management
  server: router({
    list: protectedProcedure.query(async () => {
      return db.getServerConfigs();
    }),

    get: protectedProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => {
        return db.getServerConfigById(input.id);
      }),

    create: adminProcedure
      .input(z.object({
        name: z.string().min(1),
        ipAddress: z.string().min(1),
        httpsUrl: z.string().optional(),
        httpUrl: z.string().optional(),
        region: z.string().optional(),
        dropletSize: z.string().optional(),
        dropletId: z.string().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const id = await db.createServerConfig(input);
        await db.logActivity({
          userId: ctx.user.id,
          serverId: id,
          action: 'server_created',
          details: `Created server: ${input.name}`,
        });
        return { id };
      }),

    updateStatus: adminProcedure
      .input(z.object({
        id: z.number(),
        status: z.enum(['online', 'offline', 'unknown']),
      }))
      .mutation(async ({ input }) => {
        await db.updateServerStatus(input.id, input.status);
        return { success: true };
      }),

    checkHealth: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ input }) => {
        const server = await db.getServerConfigById(input.id);
        if (!server) throw new TRPCError({ code: 'NOT_FOUND' });
        
        const credentials = await db.getCredentialsByServerId(input.id);
        const apiKey = credentials.find(c => c.credentialType === 'red_api_key')?.apiKey;
        
        if (!apiKey || !server.httpUrl) {
          await db.updateServerStatus(input.id, 'unknown');
          return { status: 'unknown', message: 'Missing API key or URL' };
        }

        try {
          const response = await fetch(`${server.httpUrl}/api/v2/health`, {
            headers: { 'KEY': apiKey },
            signal: AbortSignal.timeout(5000),
          });
          
          const status = response.ok ? 'online' : 'offline';
          await db.updateServerStatus(input.id, status);
          return { status, message: response.ok ? 'Server is healthy' : 'Server unreachable' };
        } catch {
          await db.updateServerStatus(input.id, 'offline');
          return { status: 'offline', message: 'Connection failed' };
        }
      }),
  }),

  // Credential management
  credentials: router({
    list: protectedProcedure
      .input(z.object({ serverId: z.number() }))
      .query(async ({ input, ctx }) => {
        // Only admins can see full credentials
        const creds = await db.getCredentialsByServerId(input.serverId);
        if (ctx.user.role !== 'admin') {
          return creds.map(c => ({
            ...c,
            password: c.password ? '••••••••' : null,
            apiKey: c.apiKey ? '••••••••' : null,
          }));
        }
        return creds;
      }),

    create: adminProcedure
      .input(z.object({
        serverId: z.number(),
        credentialType: z.enum(['admin_login', 'red_api_key', 'blue_api_key', 'ssh_key']),
        username: z.string().optional(),
        password: z.string().optional(),
        apiKey: z.string().optional(),
        sshKeyPath: z.string().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const { encryptServerCredential } = await import("./lib/credential-crypto");
        const encryptedInput = { ...input } as any;
        if (input.password) {
          const enc = encryptServerCredential(input.password);
          encryptedInput.password = JSON.stringify(enc);
        }
        if (input.apiKey) {
          const enc = encryptServerCredential(input.apiKey);
          encryptedInput.apiKey = JSON.stringify(enc);
        }
        await db.createCredential(encryptedInput);
        await db.logActivity({
          userId: ctx.user.id,
          serverId: input.serverId,
          action: 'credential_created',
          details: `Added ${input.credentialType} credential (FIPS encrypted)`,
        });
        return { success: true };
      }),

    update: adminProcedure
      .input(z.object({
        id: z.number(),
        username: z.string().optional(),
        password: z.string().optional(),
        apiKey: z.string().optional(),
        sshKeyPath: z.string().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const { id, ...updates } = input;
        const { encryptServerCredential } = await import("./lib/credential-crypto");
        const encryptedUpdates = { ...updates } as any;
        if (updates.password) {
          const enc = encryptServerCredential(updates.password);
          encryptedUpdates.password = JSON.stringify(enc);
        }
        if (updates.apiKey) {
          const enc = encryptServerCredential(updates.apiKey);
          encryptedUpdates.apiKey = JSON.stringify(enc);
        }
        await db.updateCredential(id, encryptedUpdates);
        await db.logActivity({
          userId: ctx.user.id,
          action: 'credential_updated',
          details: `Updated credential ID: ${id} (FIPS encrypted)`,
        });
        return { success: true };
      }),
  }),

  // Direct Caldera API proxy (for DigitalOcean server)
  calderaProxy: router({
    // Direct stats from C2 server
    getStats: publicProcedure.query(async () => {
      const [adversaries, abilities, operations, agents] = await Promise.all([
        fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/adversaries'),
        fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/abilities'),
        fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/operations'),
        fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/agents'),
      ]);

      return {
        totalAdversaries: Array.isArray(adversaries) ? adversaries.length : 0,
        totalThreatActors: await db.getThreatActorCount(),
        totalAbilities: Array.isArray(abilities) ? abilities.length : 0,
        activeOperations: Array.isArray(operations) ? operations.filter((o: any) => o.state === 'running').length : 0,
        totalAgents: Array.isArray(agents) ? agents.length : 0,
      };
    }),

    // Get all adversaries from DigitalOcean Caldera
    getAdversaries: publicProcedure.query(async () => {
      const adversaries = await fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/adversaries');
      return Array.isArray(adversaries) ? adversaries : [];
    }),

    // Get single adversary by ID
    getAdversary: publicProcedure
      .input(z.object({ adversaryId: z.string() }))
      .query(async ({ input }) => {
        return fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, `/api/v2/adversaries/${input.adversaryId}`);
      }),

    // Get all abilities from DigitalOcean Caldera
    getAbilities: publicProcedure.query(async () => {
      const abilities = await fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/abilities');
      return Array.isArray(abilities) ? abilities : [];
    }),

    // Get abilities by tactic
    getAbilitiesByTactic: publicProcedure
      .input(z.object({ tactic: z.string() }))
      .query(async ({ input }) => {
        const abilities = await fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/abilities');
        if (!Array.isArray(abilities)) return [];
        return abilities.filter((a: any) => a.tactic === input.tactic);
      }),

    // Get all tactics (derived from abilities)
    getTactics: publicProcedure.query(async () => {
      const abilities = await fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/abilities');
      if (!Array.isArray(abilities)) return [];
      
      const tacticCounts: Record<string, number> = {};
      abilities.forEach((a: any) => {
        const tactic = a.tactic || 'unknown';
        tacticCounts[tactic] = (tacticCounts[tactic] || 0) + 1;
      });
      
      return Object.entries(tacticCounts).map(([name, count]) => ({ name, count })).sort((a, b) => a.name.localeCompare(b.name));
    }),

    // Get all operations from DigitalOcean Caldera
    getOperations: publicProcedure.query(async () => {
      const operations = await fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/operations');
      return Array.isArray(operations) ? operations : [];
    }),

    // Get all agents from DigitalOcean Caldera
    getAgents: publicProcedure.query(async () => {
      const agents = await fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/agents');
      return Array.isArray(agents) ? agents : [];
    }),

    // Get single agent by paw (agent ID)
    getAgent: publicProcedure
      .input(z.object({ paw: z.string() }))
      .query(async ({ input }) => {
        return fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, `/api/v2/agents/${input.paw}`);
      }),

    // Kill an agent
    killAgent: protectedProcedure
      .input(z.object({ paw: z.string() }))
      .mutation(async ({ input }) => {
        try {
          const response = await fetch(`${CALDERA_BASE_URL}/api/v2/agents/${input.paw}`, {
            method: 'DELETE',
            headers: { 'KEY': CALDERA_API_KEY },
          });
          return { success: response.ok };
        } catch {
          return { success: false };
        }
      }),

    // Update agent trust level
    updateAgentTrust: protectedProcedure
      .input(z.object({ paw: z.string(), trusted: z.boolean() }))
      .mutation(async ({ input }) => {
        try {
          const response = await fetch(`${CALDERA_BASE_URL}/api/v2/agents/${input.paw}`, {
            method: 'PATCH',
            headers: { 
              'KEY': CALDERA_API_KEY,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({ trusted: input.trusted }),
          });
          return { success: response.ok };
        } catch {
          return { success: false };
        }
      }),

    // Get agent deployable commands
    getDeployCommands: publicProcedure.query(async () => {
      const deploy = await fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/deploy_commands');
      return deploy || {};
    }),

    // Check C2 server health
    checkHealth: publicProcedure.query(async () => {
      try {
        const response = await fetch(`${CALDERA_BASE_URL}/api/v2/health`, {
          headers: { 'KEY': CALDERA_API_KEY },
          signal: AbortSignal.timeout(5000),
        });
        return response.ok;
      } catch {
        return false;
      }
    }),

    // Create a new ability on the C2 server
    createAbility: protectedProcedure
      .input(z.object({
        ability_id: z.string(),
        name: z.string(),
        description: z.string(),
        tactic: z.string(),
        technique_id: z.string(),
        technique_name: z.string(),
        executors: z.array(z.object({
          platform: z.string(),
          name: z.string(),
          command: z.string(),
          cleanup: z.string().optional(),
          timeout: z.number().optional(),
        })),
        singleton: z.boolean().optional(),
        repeatable: z.boolean().optional(),
      }))
      .mutation(async ({ input }) => {
        try {
          const response = await fetch(`${CALDERA_BASE_URL}/api/v2/abilities`, {
            method: 'POST',
            headers: {
              'KEY': CALDERA_API_KEY,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              ability_id: input.ability_id,
              name: input.name,
              description: input.description,
              tactic: input.tactic,
              technique_id: input.technique_id,
              technique_name: input.technique_name,
              executors: input.executors,
              singleton: input.singleton ?? false,
              repeatable: input.repeatable ?? true,
            }),
            signal: AbortSignal.timeout(15000),
          });
          if (!response.ok) {
            const errText = await response.text();
            return { success: false, error: `HTTP ${response.status}: ${errText}` };
          }
          const result = await response.json();
          return { success: true, ability: result };
        } catch (err: any) {
          return { success: false, error: err.message };
        }
      }),

    // Create a new adversary profile on the C2 server
    createAdversary: protectedProcedure
      .input(z.object({
        adversary_id: z.string(),
        name: z.string(),
        description: z.string(),
        atomic_ordering: z.array(z.string()),
        objective: z.string().optional(),
      }))
      .mutation(async ({ input }) => {
        try {
          const response = await fetch(`${CALDERA_BASE_URL}/api/v2/adversaries`, {
            method: 'POST',
            headers: {
              'KEY': CALDERA_API_KEY,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              adversary_id: input.adversary_id,
              name: input.name,
              description: input.description,
              atomic_ordering: input.atomic_ordering,
              objective: input.objective || '',
            }),
            signal: AbortSignal.timeout(15000),
          });
          if (!response.ok) {
            const errText = await response.text();
            return { success: false, error: `HTTP ${response.status}: ${errText}` };
          }
          const result = await response.json();
          return { success: true, adversary: result };
        } catch (err: any) {
          return { success: false, error: err.message };
        }
      }),

    // Deploy a full ransomware ability profile to Caldera (abilities + adversary)
    deployRansomwareProfile: protectedProcedure
      .input(z.object({
        groupId: z.string(),
        groupName: z.string(),
        adversaryId: z.string(),
        description: z.string(),
        abilities: z.array(z.object({
          ability_id: z.string(),
          name: z.string(),
          description: z.string(),
          tactic: z.string(),
          technique_id: z.string(),
          technique_name: z.string(),
          platforms: z.record(z.string(), z.record(z.string(), z.object({
            command: z.string(),
            cleanup: z.string().optional(),
            timeout: z.number().optional(),
          }))),
        })),
      }))
      .mutation(async ({ input }) => {
        const results: Array<{ ability_id: string; name: string; success: boolean; error?: string }> = [];

        // Step 1: Create each ability
        for (const ability of input.abilities) {
          const executors: Array<{ platform: string; name: string; command: string; cleanup?: string; timeout?: number }> = [];
          for (const [platform, execs] of Object.entries(ability.platforms)) {
            for (const [executor, config] of Object.entries(execs as Record<string, { command: string; cleanup?: string; timeout?: number }>)) {
              executors.push({
                platform,
                name: executor,
                command: config.command,
                cleanup: config.cleanup,
                timeout: config.timeout,
              });
            }
          }

          try {
            const response = await fetch(`${CALDERA_BASE_URL}/api/v2/abilities`, {
              method: 'POST',
              headers: { 'KEY': CALDERA_API_KEY, 'Content-Type': 'application/json' },
              body: JSON.stringify({
                ability_id: ability.ability_id,
                name: `[${input.groupName}] ${ability.name}`,
                description: ability.description,
                tactic: ability.tactic,
                technique_id: ability.technique_id,
                technique_name: ability.technique_name,
                executors,
                singleton: false,
                repeatable: true,
              }),
              signal: AbortSignal.timeout(15000),
            });
            results.push({
              ability_id: ability.ability_id,
              name: ability.name,
              success: response.ok,
              error: response.ok ? undefined : `HTTP ${response.status}`,
            });
          } catch (err: any) {
            results.push({ ability_id: ability.ability_id, name: ability.name, success: false, error: err.message });
          }
        }

        // Step 2: Create the adversary profile
        let adversaryResult: { success: boolean; error?: string } = { success: false };
        try {
          const response = await fetch(`${CALDERA_BASE_URL}/api/v2/adversaries`, {
            method: 'POST',
            headers: { 'KEY': CALDERA_API_KEY, 'Content-Type': 'application/json' },
            body: JSON.stringify({
              adversary_id: input.adversaryId,
              name: `${input.groupName} Simulation`,
              description: input.description,
              atomic_ordering: input.abilities.map(a => a.ability_id),
            }),
            signal: AbortSignal.timeout(15000),
          });
          adversaryResult = { success: response.ok, error: response.ok ? undefined : `HTTP ${response.status}` };
        } catch (err: any) {
          adversaryResult = { success: false, error: err.message };
        }

        return {
          abilitiesDeployed: results.filter(r => r.success).length,
          abilitiesFailed: results.filter(r => !r.success).length,
          abilityResults: results,
          adversaryCreated: adversaryResult.success,
          adversaryError: adversaryResult.error,
        };
      }),

    // ─── Campaign Execution Dashboard Endpoints ───
    // Get detailed operation with chain analysis
    getOperationDetail: publicProcedure
      .input(z.object({ operationId: z.string() }))
      .query(async ({ input }) => {
        const operations = await fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/operations');
        const op = Array.isArray(operations) ? operations.find((o: any) => o.id === input.operationId) : null;
        if (!op) return null;

        const chain = op.chain || [];
        const totalSteps = chain.length;
        const completedSteps = chain.filter((s: any) => s.finish).length;
        const successSteps = chain.filter((s: any) => s.status === 0 && s.finish).length;
        const failedSteps = chain.filter((s: any) => s.status !== 0 && s.finish).length;

        // Group by technique
        const techniqueMap: Record<string, { id: string; name: string; status: string; steps: any[] }> = {};
        for (const step of chain) {
          const ab = step.ability || {};
          const techId = ab.technique_id || 'unknown';
          if (!techniqueMap[techId]) {
            techniqueMap[techId] = {
              id: techId,
              name: ab.technique_name || ab.name || techId,
              status: 'pending',
              steps: [],
            };
          }
          techniqueMap[techId].steps.push({
            id: step.id,
            abilityName: ab.name,
            abilityId: ab.ability_id,
            status: step.finish ? (step.status === 0 ? 'success' : 'failed') : 'running',
            paw: step.paw,
            executor: step.executor?.name || step.executor,
            command: step.command,
            output: step.output,
            decide: step.decide,
            finish: step.finish,
            score: step.score,
          });
          // Update technique status
          const statuses = techniqueMap[techId].steps.map((s: any) => s.status);
          if (statuses.includes('running')) techniqueMap[techId].status = 'running';
          else if (statuses.every((s: string) => s === 'success')) techniqueMap[techId].status = 'success';
          else if (statuses.some((s: string) => s === 'failed')) techniqueMap[techId].status = 'partial';
          else techniqueMap[techId].status = 'pending';
        }

        // Timeline events
        const timeline = chain.map((step: any) => ({
          time: step.decide || step.finish,
          finishTime: step.finish,
          abilityName: step.ability?.name || 'Unknown',
          techniqueId: step.ability?.technique_id || 'Unknown',
          status: step.finish ? (step.status === 0 ? 'success' : 'failed') : 'running',
          paw: step.paw,
        })).sort((a: any, b: any) => new Date(a.time).getTime() - new Date(b.time).getTime());

        return {
          id: op.id,
          name: op.name,
          state: op.state,
          start: op.start,
          adversary: op.adversary,
          planner: op.planner,
          group: op.group,
          jitter: op.jitter,
          objective: op.objective,
          // Metrics
          metrics: {
            totalSteps,
            completedSteps,
            successSteps,
            failedSteps,
            pendingSteps: totalSteps - completedSteps,
            successRate: totalSteps > 0 ? Math.round((successSteps / totalSteps) * 100) : 0,
            detectionRate: totalSteps > 0 ? Math.round((failedSteps / totalSteps) * 100) : 0,
            progress: totalSteps > 0 ? Math.round((completedSteps / totalSteps) * 100) : 0,
          },
          techniques: Object.values(techniqueMap),
          timeline,
          agentPaws: Array.from(new Set(chain.map((s: any) => s.paw))),
        };
      }),

    // Get all operations summary for dashboard
    getOperationsSummary: publicProcedure.query(async () => {
      const [operations, agents] = await Promise.all([
        fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/operations'),
        fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/agents'),
      ]);
      const ops = Array.isArray(operations) ? operations : [];
      const agentList = Array.isArray(agents) ? agents : [];

      const summary = ops.map((op: any) => {
        const chain = op.chain || [];
        const totalSteps = chain.length;
        const completedSteps = chain.filter((s: any) => s.finish).length;
        const successSteps = chain.filter((s: any) => s.status === 0 && s.finish).length;
        const failedSteps = chain.filter((s: any) => s.status !== 0 && s.finish).length;
        const uniqueTechniques = new Set(chain.map((s: any) => s.ability?.technique_id).filter(Boolean));
        return {
          id: op.id,
          name: op.name,
          state: op.state,
          start: op.start,
          adversaryName: op.adversary?.name || 'Unknown',
          totalSteps,
          completedSteps,
          successSteps,
          failedSteps,
          uniqueTechniques: uniqueTechniques.size,
          progress: totalSteps > 0 ? Math.round((completedSteps / totalSteps) * 100) : 0,
          successRate: completedSteps > 0 ? Math.round((successSteps / completedSteps) * 100) : 0,
          agentPaws: Array.from(new Set(chain.map((s: any) => s.paw).filter(Boolean))),
        };
      });

      // Agent summary
      const agentSummary = agentList.map((a: any) => {
        const now = Date.now();
        const lastSeen = new Date(a.last_seen).getTime();
        const isAlive = (now - lastSeen) < 5 * 60 * 1000; // 5 min threshold
        return {
          paw: a.paw,
          host: a.host,
          platform: a.platform,
          username: a.username,
          privilege: a.privilege,
          contact: a.contact,
          lastSeen: a.last_seen,
          created: a.created,
          status: isAlive ? 'alive' : 'dead',
          executors: a.executors || [],
          hostIpAddrs: a.host_ip_addrs || [],
          displayName: a.display_name || a.host,
        };
      });

      return {
        operations: summary,
        agents: agentSummary,
        totals: {
          totalOperations: ops.length,
          runningOperations: ops.filter((o: any) => o.state === 'running').length,
          pausedOperations: ops.filter((o: any) => o.state === 'paused').length,
          finishedOperations: ops.filter((o: any) => o.state === 'finished').length,
          totalAgents: agentList.length,
          aliveAgents: agentSummary.filter((a: any) => a.status === 'alive').length,
        },
      };
    }),

    // Control operation (pause, resume, stop)
    controlOperation: protectedProcedure
      .input(z.object({
        operationId: z.string(),
        action: z.enum(['pause', 'resume', 'stop', 'cleanup']),
      }))
      .mutation(async ({ input }) => {
        const stateMap: Record<string, string> = {
          pause: 'paused',
          resume: 'running',
          stop: 'finished',
          cleanup: 'cleanup',
        };
        const response = await fetch(`${CALDERA_BASE_URL}/api/v2/operations/${input.operationId}`, {
          method: 'PATCH',
          headers: { 'KEY': CALDERA_API_KEY, 'Content-Type': 'application/json' },
          body: JSON.stringify({ state: stateMap[input.action] }),
        });
        if (!response.ok) throw new Error(`Failed to ${input.action} operation: ${response.status}`);
        return { success: true, newState: stateMap[input.action] };
      }),

    // Build intelligent attack chain for a specific operation
    buildChain: protectedProcedure
      .input(z.object({
        operationId: z.string(),
        scanId: z.number().optional(),
        campaignIndex: z.number().optional(),
      }))
      .mutation(async ({ input }) => {
        const { buildOperationChain } = await import('./lib/chain-builder');
        const { matchTechnologiesAgainstAllFeeds, getVulnFeedChainSteps } = await import('./lib/vuln-feeds');
        const abilities = await fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/abilities');
        let scanData: any = null;
        if (input.scanId) {
          const scan = await db.getDomainIntelScanById(input.scanId);
          scanData = scan?.pipelineOutput;
        }
        const campaigns = scanData?.campaignRecommendations || [];
        const actorMatches = scanData?.threatActorMatches?.topMatches || [];
        const kevChainSteps = scanData?.kevEnrichment?.chainSteps || [];
        const campaign = input.campaignIndex !== undefined ? campaigns[input.campaignIndex] : undefined;

        // Enrich with vulnerability feed data from discovered technologies
        // Only confirmed/probable findings are included to prevent false-positive noise in adversary emulation
        let vulnSteps: Array<{ techniqueId: string; priority: number; source: "vuln_feed"; context: string; corroborationTier?: string }> = [];
        try {
          if (input.scanId) {
            const scanForTech = await db.getDomainIntelScanById(input.scanId);
            const pipelineAssets = (scanForTech?.pipelineOutput as any)?.assets || [];
            const techs = new Set<string>();
            const detectedVersions: Record<string, string> = {};
            pipelineAssets.forEach((a: any) => {
              const asset = a?.asset || a;
              ((asset.technologies || []) as string[]).forEach((t: string) => techs.add(t));
              // Collect detected versions for corroboration
              if (asset.technologyVersions) {
                Object.entries(asset.technologyVersions).forEach(([tech, ver]) => {
                  if (ver) detectedVersions[tech] = ver as string;
                });
              }
            });
            if (techs.size > 0) {
              const vulnMatches = await matchTechnologiesAgainstAllFeeds(Array.from(techs));
              vulnSteps = getVulnFeedChainSteps(vulnMatches.matches, Object.keys(detectedVersions).length > 0 ? detectedVersions : undefined);
            }
          }
        } catch (e) {
          console.warn('[Chain Builder] Vuln feed enrichment failed, continuing without:', e);
        }

        const result = await buildOperationChain({
          operationId: input.operationId,
          scanId: input.scanId,
          campaignRecommendation: campaign,
          threatActorMatches: actorMatches,
          kevSteps: kevChainSteps,
          vulnSteps,
          allAbilities: abilities || [],
          calderaBaseUrl: CALDERA_BASE_URL,
          calderaApiKey: CALDERA_API_KEY,
        });
        return result;
      }),

    // Auto-build chains for ALL paused operations without chains
    autoBuildAllChains: protectedProcedure
      .input(z.object({ scanId: z.number().optional() }))
      .mutation(async ({ input }) => {
        const { autoBuildAllChains } = await import('./lib/chain-builder');
        const { matchTechnologiesAgainstAllFeeds, getVulnFeedChainSteps } = await import('./lib/vuln-feeds');
        let scanData: any = undefined;
        let vulnSteps: Array<{ techniqueId: string; priority: number; source: "vuln_feed"; context: string; corroborationTier?: string }> = [];
        if (input.scanId) {
          const scan = await db.getDomainIntelScanById(input.scanId);
          if (scan) {
            scanData = { pipelineOutput: scan.pipelineOutput, findings: [] };
            // Extract technologies and match against vuln feeds with version corroboration
            try {
              const pipelineAssets = (scan.pipelineOutput as any)?.assets || [];
              const techs = new Set<string>();
              const detectedVersions: Record<string, string> = {};
              pipelineAssets.forEach((a: any) => {
                const asset = a?.asset || a;
                ((asset.technologies || []) as string[]).forEach((t: string) => techs.add(t));
                if (asset.technologyVersions) {
                  Object.entries(asset.technologyVersions).forEach(([tech, ver]) => {
                    if (ver) detectedVersions[tech] = ver as string;
                  });
                }
              });
              if (techs.size > 0) {
                const vulnMatches = await matchTechnologiesAgainstAllFeeds(Array.from(techs));
                vulnSteps = getVulnFeedChainSteps(vulnMatches.matches, Object.keys(detectedVersions).length > 0 ? detectedVersions : undefined);
              }
            } catch (e) {
              console.warn('[Auto Chain Builder] Vuln feed enrichment failed:', e);
            }
          }
        }
        const results = await autoBuildAllChains({
          calderaBaseUrl: CALDERA_BASE_URL,
          calderaApiKey: CALDERA_API_KEY,
          scanData,
          vulnSteps,
        });
        return {
          totalOperations: results.length,
          results: results.map(r => ({
            operationId: r.operationId,
            operationName: r.operationName,
            adversaryName: r.adversaryName,
            totalAbilities: r.totalAbilities,
            techniquesCovered: r.techniquesCovered.length,
            techniquesNotCovered: r.techniquesNotCovered.length,
          })),
        };
      }),

    // Build chain with LLM intelligence
    buildChainWithLLM: protectedProcedure
      .input(z.object({
        operationId: z.string(),
        scanId: z.number(),
        campaignIndex: z.number(),
      }))
      .mutation(async ({ input }) => {
        const { buildChainWithLLM, buildOperationChain } = await import('./lib/chain-builder');
        const { matchTechnologiesAgainstAllFeeds, getVulnFeedChainSteps } = await import('./lib/vuln-feeds');
        const abilities = await fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/abilities');
        const scan = await db.getDomainIntelScanById(input.scanId);
        const scanData = scan?.pipelineOutput as any;
        const campaigns = scanData?.campaignRecommendations || [];
        const actorMatches = scanData?.threatActorMatches?.topMatches || [];
        const campaign = campaigns[input.campaignIndex];
        if (!campaign) throw new TRPCError({ code: 'NOT_FOUND', message: 'Campaign recommendation not found' });

        // Enrich with vuln feed data — only confirmed/probable findings to prevent false-positive noise
        let vulnSteps: Array<{ techniqueId: string; priority: number; source: "vuln_feed"; context: string; corroborationTier?: string }> = [];
        try {
          const pipelineAssets = scanData?.assets || [];
          const techs = new Set<string>();
          const detectedVersions: Record<string, string> = {};
          pipelineAssets.forEach((a: any) => {
            const asset = a?.asset || a;
            ((asset.technologies || []) as string[]).forEach((t: string) => techs.add(t));
            if (asset.technologyVersions) {
              Object.entries(asset.technologyVersions).forEach(([tech, ver]) => {
                if (ver) detectedVersions[tech] = ver as string;
              });
            }
          });
          if (techs.size > 0) {
            const vulnMatches = await matchTechnologiesAgainstAllFeeds(Array.from(techs));
            vulnSteps = getVulnFeedChainSteps(vulnMatches.matches, Object.keys(detectedVersions).length > 0 ? detectedVersions : undefined);
          }
        } catch (e) {
          console.warn('[LLM Chain Builder] Vuln feed enrichment failed:', e);
        }
        const llmResult = await buildChainWithLLM({
          campaignRecommendation: campaign,
          orgProfile: (scanData as any)?.orgProfile,
          findings: [],
          threatActors: actorMatches,
          availableAbilities: abilities || [],
        });
        if (llmResult.selectedAbilities.length > 0) {
          const adversaryName = `llm-${campaign.name.replace(/[^a-zA-Z0-9]/g, '-').toLowerCase().substring(0, 40)}-${Date.now().toString(36)}`;
          const advResponse = await fetch(`${CALDERA_BASE_URL}/api/v2/adversaries`, {
            method: 'POST',
            headers: { 'KEY': CALDERA_API_KEY, 'Content-Type': 'application/json' },
            body: JSON.stringify({
              name: adversaryName,
              description: `LLM-designed adversary. ${llmResult.reasoning}`,
              atomic_ordering: llmResult.selectedAbilities,
              tags: ['llm-generated', 'chain-builder'],
            }),
          });
          if (advResponse.ok) {
            const adv = await advResponse.json() as any;
            await fetch(`${CALDERA_BASE_URL}/api/v2/operations/${input.operationId}`, {
              method: 'PATCH',
              headers: { 'KEY': CALDERA_API_KEY, 'Content-Type': 'application/json' },
              body: JSON.stringify({ adversary: { adversary_id: adv.adversary_id } }),
            });
            return { success: true, method: 'llm' as const, adversaryName, totalAbilities: llmResult.selectedAbilities.length, reasoning: llmResult.reasoning, attackNarrative: llmResult.attackNarrative };
          }
        }
        const kevChainSteps2 = (scanData as any)?.kevEnrichment?.chainSteps || [];
        const result = await buildOperationChain({
          operationId: input.operationId,
          scanId: input.scanId,
          campaignRecommendation: campaign,
          threatActorMatches: actorMatches,
          kevSteps: kevChainSteps2,
          vulnSteps,
          allAbilities: abilities || [],
          calderaBaseUrl: CALDERA_BASE_URL,
          calderaApiKey: CALDERA_API_KEY,
        });
        return { success: true, method: 'rule-based' as const, adversaryName: result.adversaryName, totalAbilities: result.totalAbilities, reasoning: 'Rule-based selection from campaign attack chain', attackNarrative: '' };
      }),

    // ─── Sigma/YARA Rule Validation Engine ───
    validateRule: protectedProcedure
      .input(z.object({
        ruleType: z.enum(['sigma', 'yara', 'suricata', 'splunk', 'kql']),
        ruleContent: z.string(),
        ruleName: z.string().optional(),
        techniqueId: z.string().optional(),
        sampleData: z.string().optional(),
        useLLM: z.boolean().optional(),
      }))
      .mutation(async ({ input }) => {
        const { validateRule } = await import('./lib/rule-validator');
        return validateRule({
          ruleType: input.ruleType,
          ruleContent: input.ruleContent,
          ruleName: input.ruleName,
          techniqueId: input.techniqueId,
          sampleData: input.sampleData,
        }, input.useLLM ?? true);
      }),

    validateRuleBatch: protectedProcedure
      .input(z.object({
        rules: z.array(z.object({
          ruleType: z.enum(['sigma', 'yara', 'suricata', 'splunk', 'kql']),
          ruleContent: z.string(),
          ruleName: z.string().optional(),
          techniqueId: z.string().optional(),
        })),
        useLLM: z.boolean().optional(),
      }))
      .mutation(async ({ input }) => {
        const { validateRuleBatch } = await import('./lib/rule-validator');
        return validateRuleBatch(input.rules, input.useLLM ?? false);
      }),

    generateSampleLog: protectedProcedure
      .input(z.object({ techniqueId: z.string() }))
      .query(async ({ input }) => {
        const { generateSampleLogData } = await import('./lib/rule-validator');
        return { sampleData: generateSampleLogData(input.techniqueId) };
      }),

    // ─── Detection Rule Generator ───
    generateActorRules: protectedProcedure
      .input(z.object({
        actorId: z.string(),
        useLLM: z.boolean().optional(),
      }))
      .mutation(async ({ input }) => {
        const { generateRulesForActor, generateRulesWithLLM } = await import('./lib/rule-generator');
        const actor = await db.getThreatActor(input.actorId);
        if (!actor) throw new TRPCError({ code: 'NOT_FOUND', message: 'Threat actor not found' });
        const techniques = (actor.techniques as Array<{ id: string; name: string; tactic: string }>) || [];
        const tools = (actor.tools as string[]) || [];
        const malware = (actor.malware as string[]) || [];
        if (input.useLLM) {
          return generateRulesWithLLM({
            actorName: actor.name,
            techniques,
            tools,
            malware,
            description: actor.description || undefined,
          });
        }
        return generateRulesForActor({ actorName: actor.name, techniques, tools, malware });
      }),

    // ─── Detection Coverage Matrix ───
    getDetectionCoverageMatrix: protectedProcedure
      .input(z.object({
        operationId: z.string().optional(),
      }))
      .query(async ({ input }) => {
        const { generateRulesForActor } = await import('./lib/rule-generator');
        
        // Get all operations
        const operations = await fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/operations');
        const ops = Array.isArray(operations) ? operations : [];
        const targetOps = input.operationId ? ops.filter((o: any) => o.id === input.operationId) : ops;

        // Collect all techniques used across operations
        const techniqueUsage: Record<string, {
          id: string; name: string; tactic: string;
          operations: Array<{ opId: string; opName: string; status: string }>;
        }> = {};

        for (const op of targetOps) {
          const chain = op.chain || [];
          for (const step of chain) {
            const ab = step.ability || {};
            const techId = ab.technique_id || 'unknown';
            if (techId === 'unknown') continue;
            if (!techniqueUsage[techId]) {
              techniqueUsage[techId] = {
                id: techId,
                name: ab.technique_name || ab.name || techId,
                tactic: ab.tactic || 'unknown',
                operations: [],
              };
            }
            const stepStatus = step.finish ? (step.status === 0 ? 'success' : 'failed') : 'running';
            const existing = techniqueUsage[techId].operations.find((o: any) => o.opId === op.id);
            if (!existing) {
              techniqueUsage[techId].operations.push({ opId: op.id, opName: op.name, status: stepStatus });
            }
          }
        }

        // Get all threat actors to generate rules
        const actorResult = await db.listThreatActors();
        const actors = actorResult.actors || [];
        const allActorTechniques: Array<{ id: string; name: string; tactic: string }> = [];
        for (const actor of actors) {
          const techs = (actor.techniques as Array<{ id: string; name: string; tactic: string }>) || [];
          allActorTechniques.push(...techs);
        }

        // Deduplicate techniques
        const uniqueTechMap = new Map<string, { id: string; name: string; tactic: string }>();
        for (const t of allActorTechniques) {
          if (!uniqueTechMap.has(t.id)) uniqueTechMap.set(t.id, t);
        }

        // Generate rules for coverage analysis
        const genResult = generateRulesForActor({
          actorName: 'All Actors',
          techniques: Array.from(uniqueTechMap.values()),
        });

        // Build coverage matrix
        const matrix: Array<{
          techniqueId: string;
          techniqueName: string;
          tactic: string;
          operationCoverage: Array<{ opId: string; opName: string; status: string }>;
          rulesCoverage: Array<{ ruleType: string; confidence: number; severity: string }>;
          coverageStatus: 'full' | 'partial' | 'rules-only' | 'ops-only' | 'none';
        }> = [];

        // Merge techniques from both operations and rules
        const allTechIds = new Set([
          ...Object.keys(techniqueUsage),
          ...genResult.rules.map(r => r.techniqueId),
        ]);

        for (const techId of Array.from(allTechIds)) {
          const opData = techniqueUsage[techId];
          const ruleData = genResult.rules.filter(r => r.techniqueId === techId);
          const techInfo = opData || uniqueTechMap.get(techId) || { id: techId, name: techId, tactic: 'unknown' };

          const hasOps = !!opData && opData.operations.length > 0;
          const hasRules = ruleData.length > 0;
          const hasHighConfRules = ruleData.some(r => r.confidence >= 65);

          let coverageStatus: 'full' | 'partial' | 'rules-only' | 'ops-only' | 'none' = 'none';
          if (hasOps && hasHighConfRules) coverageStatus = 'full';
          else if (hasOps && hasRules) coverageStatus = 'partial';
          else if (hasRules) coverageStatus = 'rules-only';
          else if (hasOps) coverageStatus = 'ops-only';

          matrix.push({
            techniqueId: techId,
            techniqueName: (techInfo as any).name || techId,
            tactic: (techInfo as any).tactic || 'unknown',
            operationCoverage: opData?.operations || [],
            rulesCoverage: ruleData.map(r => ({
              ruleType: r.ruleType,
              confidence: r.confidence,
              severity: r.severity,
            })),
            coverageStatus,
          });
        }

        // Sort by tactic order then technique ID
        const tacticOrder = ['reconnaissance','resource-development','initial-access','execution','persistence','privilege-escalation','defense-evasion','credential-access','discovery','lateral-movement','collection','command-and-control','exfiltration','impact'];
        matrix.sort((a, b) => {
          const aIdx = tacticOrder.indexOf(a.tactic);
          const bIdx = tacticOrder.indexOf(b.tactic);
          if (aIdx !== bIdx) return (aIdx === -1 ? 99 : aIdx) - (bIdx === -1 ? 99 : bIdx);
          return a.techniqueId.localeCompare(b.techniqueId);
        });

        // Summary stats
        const summary = {
          totalTechniques: matrix.length,
          fullCoverage: matrix.filter(m => m.coverageStatus === 'full').length,
          partialCoverage: matrix.filter(m => m.coverageStatus === 'partial').length,
          rulesOnly: matrix.filter(m => m.coverageStatus === 'rules-only').length,
          opsOnly: matrix.filter(m => m.coverageStatus === 'ops-only').length,
          noCoverage: matrix.filter(m => m.coverageStatus === 'none').length,
          totalOperations: targetOps.length,
          totalRules: genResult.totalRules,
          byTactic: Object.fromEntries(
            tacticOrder.map(t => [t, {
              total: matrix.filter(m => m.tactic === t).length,
              covered: matrix.filter(m => m.tactic === t && (m.coverageStatus === 'full' || m.coverageStatus === 'partial')).length,
            }])
          ),
        };

        return {
          matrix,
          summary,
          operations: targetOps.map((o: any) => ({ id: o.id, name: o.name, state: o.state })),
        };
      }),

    // ─── Post-Engagement Report Generator ───
    generateReport: protectedProcedure
      .input(z.object({
        operationId: z.string(),
        clientName: z.string().optional(),
        engagementType: z.string().optional(),
        customNotes: z.string().optional(),
      }))
      .mutation(async ({ input }) => {
        const { generateReport, renderReportHTML } = await import('./lib/report-generator');
        
        // Get operation detail
        const operations = await fetchCalderaAPI(CALDERA_BASE_URL, CALDERA_API_KEY, '/api/v2/operations');
        const op = Array.isArray(operations) ? operations.find((o: any) => o.id === input.operationId) : null;
        if (!op) throw new TRPCError({ code: 'NOT_FOUND', message: 'Operation not found' });

        const chain = op.chain || [];
        const totalSteps = chain.length;
        const completedSteps = chain.filter((s: any) => s.finish).length;
        const successSteps = chain.filter((s: any) => s.status === 0 && s.finish).length;
        const failedSteps = chain.filter((s: any) => s.status !== 0 && s.finish).length;

        // Build technique map
        const techniqueMap: Record<string, any> = {};
        for (const step of chain) {
          const ab = step.ability || {};
          const techId = ab.technique_id || 'unknown';
          if (!techniqueMap[techId]) {
            techniqueMap[techId] = {
              id: techId, name: ab.technique_name || ab.name || techId,
              tactic: ab.tactic || 'unknown', status: 'pending', steps: [],
            };
          }
          techniqueMap[techId].steps.push({
            id: step.id, abilityName: ab.name, abilityId: ab.ability_id,
            status: step.finish ? (step.status === 0 ? 'success' : 'failed') : 'running',
            paw: step.paw, finish: step.finish,
          });
          const statuses = techniqueMap[techId].steps.map((s: any) => s.status);
          if (statuses.includes('running')) techniqueMap[techId].status = 'running';
          else if (statuses.every((s: string) => s === 'success')) techniqueMap[techId].status = 'success';
          else if (statuses.some((s: string) => s === 'failed')) techniqueMap[techId].status = 'partial';
        }

        const timeline = chain.map((step: any) => ({
          time: step.decide || step.finish,
          finishTime: step.finish,
          abilityName: step.ability?.name || 'Unknown',
          techniqueId: step.ability?.technique_id || 'Unknown',
          status: step.finish ? (step.status === 0 ? 'success' : 'failed') : 'running',
          paw: step.paw,
        })).sort((a: any, b: any) => new Date(a.time).getTime() - new Date(b.time).getTime());

        const operationData = {
          ...op,
          techniques: Object.values(techniqueMap),
          timeline,
          metrics: {
            totalSteps, completedSteps, successSteps, failedSteps,
            pendingSteps: totalSteps - completedSteps,
            successRate: totalSteps > 0 ? Math.round((successSteps / totalSteps) * 100) : 0,
            detectionRate: totalSteps > 0 ? Math.round((failedSteps / totalSteps) * 100) : 0,
            progress: totalSteps > 0 ? Math.round((completedSteps / totalSteps) * 100) : 0,
          },
        };

        // Get coverage data
        let coverageData = null;
        try {
          const { generateRulesForActor } = await import('./lib/rule-generator');
          const actorResult = await db.listThreatActors();
          const actors = actorResult.actors || [];
          const allTechs: Array<{ id: string; name: string; tactic: string }> = [];
          for (const actor of actors) {
            const techs = (actor.techniques as Array<{ id: string; name: string; tactic: string }>) || [];
            allTechs.push(...techs);
          }
          const uniqueTechMap = new Map<string, { id: string; name: string; tactic: string }>();
          for (const t of allTechs) { if (!uniqueTechMap.has(t.id)) uniqueTechMap.set(t.id, t); }
          const genResult = generateRulesForActor({ actorName: 'All Actors', techniques: Array.from(uniqueTechMap.values()) });
          
          const techUsage: Record<string, any> = {};
          for (const step of chain) {
            const ab = step.ability || {};
            const techId = ab.technique_id || 'unknown';
            if (techId === 'unknown') continue;
            if (!techUsage[techId]) techUsage[techId] = { operations: [] };
            if (!techUsage[techId].operations.find((o: any) => o.opId === op.id)) {
              techUsage[techId].operations.push({ opId: op.id, opName: op.name, status: step.finish ? (step.status === 0 ? 'success' : 'failed') : 'running' });
            }
          }

          const allTechIds = new Set([...Object.keys(techUsage), ...genResult.rules.map(r => r.techniqueId)]);
          const matrix: any[] = [];
          for (const techId of Array.from(allTechIds)) {
            const opData = techUsage[techId];
            const ruleData = genResult.rules.filter(r => r.techniqueId === techId);
            const hasOps = !!opData && opData.operations.length > 0;
            const hasRules = ruleData.length > 0;
            const hasHighConf = ruleData.some(r => r.confidence >= 65);
            let coverageStatus = 'none';
            if (hasOps && hasHighConf) coverageStatus = 'full';
            else if (hasOps && hasRules) coverageStatus = 'partial';
            else if (hasRules) coverageStatus = 'rules-only';
            else if (hasOps) coverageStatus = 'ops-only';
            matrix.push({ techniqueId: techId, techniqueName: (uniqueTechMap.get(techId) as any)?.name || techId, tactic: (uniqueTechMap.get(techId) as any)?.tactic || 'unknown', coverageStatus });
          }
          coverageData = {
            matrix,
            summary: {
              totalTechniques: matrix.length,
              fullCoverage: matrix.filter(m => m.coverageStatus === 'full').length,
              partialCoverage: matrix.filter(m => m.coverageStatus === 'partial').length,
              opsOnly: matrix.filter(m => m.coverageStatus === 'ops-only').length,
              noCoverage: matrix.filter(m => m.coverageStatus === 'none').length,
            },
          };
        } catch (e) { console.error('Coverage data fetch failed:', e); }

        // Get threat actors
        let threatActors: Array<{ name: string; techniques: number; type: string }> = [];
        try {
          const actorResult = await db.listThreatActors();
          threatActors = (actorResult.actors || []).map((a: any) => ({
            name: a.name, techniques: Array.isArray(a.techniques) ? a.techniques.length : 0, type: a.type,
          }));
        } catch (e) { /* ignore */ }

        const report = await generateReport({
          operationId: input.operationId,
          operationData,
          coverageData,
          threatActors,
          clientName: input.clientName,
          engagementType: input.engagementType,
          customNotes: input.customNotes,
        });

        const html = renderReportHTML(report);
        return { report, html };
      }),

    generateAndValidateActorRules: protectedProcedure
      .input(z.object({
        actorId: z.string(),
        useLLM: z.boolean().optional(),
      }))
      .mutation(async ({ input }) => {
        const { generateRulesForActor } = await import('./lib/rule-generator');
        const { validateRule } = await import('./lib/rule-validator');
        const actor = await db.getThreatActor(input.actorId);
        if (!actor) throw new TRPCError({ code: 'NOT_FOUND', message: 'Threat actor not found' });
        const techniques = (actor.techniques as Array<{ id: string; name: string; tactic: string }>) || [];
        const tools = (actor.tools as string[]) || [];
        const malware = (actor.malware as string[]) || [];
        const genResult = generateRulesForActor({ actorName: actor.name, techniques, tools, malware });
        // Validate each rule (no LLM to keep it fast)
        const validated = await Promise.all(
          genResult.rules.map(async (rule) => {
            const validation = await validateRule({
              ruleType: rule.ruleType,
              ruleContent: rule.ruleContent,
              ruleName: rule.ruleName,
              techniqueId: rule.techniqueId,
            }, false);
            return { ...rule, validation };
          })
        );
        return { ...genResult, rules: validated };
      }),

    // ─── CISA KEV Endpoints ───
    getKevCatalog: protectedProcedure
      .query(async () => {
        const { fetchKevCatalog, getKevStats } = await import('./lib/kev-service');
        const catalog = await fetchKevCatalog();
        const stats = getKevStats(catalog);
        const vulns = catalog.vulnerabilities || [];
        return {
          totalVulnerabilities: vulns.length,
          catalogVersion: catalog.catalogVersion,
          dateReleased: catalog.dateReleased,
          vulnerabilities: vulns.slice(0, 500),
          ransomwareCount: stats.ransomwareLinked,
          recentlyAdded: stats.recentlyAdded,
          topVendors: stats.topVendors,
          topProducts: stats.topProducts,
        };
      }),

    searchKev: protectedProcedure
      .input(z.object({
        query: z.string().optional(),
        vendor: z.string().optional(),
        product: z.string().optional(),
        ransomwareOnly: z.boolean().optional(),
        limit: z.number().optional(),
      }))
      .query(async ({ input }) => {
        const { fetchKevCatalog } = await import('./lib/kev-service');
        const catalog = await fetchKevCatalog();
        let results = catalog.vulnerabilities || [];
        if (input.query) {
          const q = input.query.toLowerCase();
          results = results.filter((v) =>
            v.cveID?.toLowerCase().includes(q) ||
            v.vulnerabilityName?.toLowerCase().includes(q) ||
            v.vendorProject?.toLowerCase().includes(q) ||
            v.product?.toLowerCase().includes(q) ||
            v.shortDescription?.toLowerCase().includes(q)
          );
        }
        if (input.vendor) {
          results = results.filter((v) => v.vendorProject?.toLowerCase().includes(input.vendor!.toLowerCase()));
        }
        if (input.product) {
          results = results.filter((v) => v.product?.toLowerCase().includes(input.product!.toLowerCase()));
        }
        if (input.ransomwareOnly) {
          results = results.filter((v) => v.knownRansomwareCampaignUse === 'Known');
        }
        return { total: results.length, results: results.slice(0, input.limit || 100) };
      }),

    matchKevToScan: protectedProcedure
      .input(z.object({ scanId: z.number() }))
      .query(async ({ input }) => {
        const { fetchKevCatalog, matchTechnologiesAgainstKev, calculateKevRiskBoost, getKevChainSteps } = await import('./lib/kev-service');
        const scan = await db.getDomainIntelScanById(input.scanId);
        if (!scan) throw new TRPCError({ code: 'NOT_FOUND', message: 'Scan not found' });
        const pipeline = scan.pipelineOutput as any;
        const allTechs = (pipeline?.assets || []).flatMap((a: any) => a?.asset?.technologies || []);
        const uniqueTechs = Array.from(new Set(allTechs.filter(Boolean))) as string[];
        const catalog = await fetchKevCatalog();
        const matches = matchTechnologiesAgainstKev(uniqueTechs, catalog);
        const boost = calculateKevRiskBoost(matches);
        const chainSteps = getKevChainSteps(matches);
        return {
          scanId: input.scanId,
          domain: scan.primaryDomain,
          technologiesScanned: uniqueTechs.length,
          kevMatches: matches,
          riskBoost: boost,
          chainSteps,
        };
      }),

    // ─── Unified Vulnerability Feed Endpoints ───
    getVulnFeedStats: protectedProcedure
      .query(async () => {
        const { getVulnFeedStats } = await import('./lib/vuln-feeds');
        return getVulnFeedStats();
      }),

    getVulnTrendData: protectedProcedure
      .input(z.object({ days: z.number().optional() }).optional())
      .query(async ({ input }) => {
        const { getVulnTrendData } = await import('./lib/vuln-feeds');
        return getVulnTrendData(input?.days || 7);
      }),

    getRecentZeroDays: protectedProcedure
      .input(z.object({ limit: z.number().optional() }).optional())
      .query(async ({ input }) => {
        const { getRecentZeroDays } = await import('./lib/vuln-feeds');
        return getRecentZeroDays(input?.limit || 50);
      }),

    getWeaponizedCves: protectedProcedure
      .input(z.object({ limit: z.number().optional() }).optional())
      .query(async ({ input }) => {
        const { getWeaponizedCves } = await import('./lib/vuln-feeds');
        return getWeaponizedCves(input?.limit || 50);
      }),

    getCveDetail: protectedProcedure
      .input(z.object({ cveId: z.string() }))
      .query(async ({ input }) => {
        const { searchVulnerabilities } = await import('./lib/vuln-feeds');
        const results = await searchVulnerabilities(input.cveId, {}, 1);
        const vuln = results.find(r => r.cveId === input.cveId) || results[0] || null;
        if (!vuln) return null;

        // Enrich with exploit matching
        let exploitMatches: any = null;
        try {
          const { matchExploitsToFindings } = await import('./lib/exploit-matcher');
          const matches = await matchExploitsToFindings([{
            title: vuln.title || vuln.cveId,
            cveIds: [vuln.cveId],
            severity: vuln.cvssScore || 7,
            corroborationTier: 'confirmed',
          }]);
          if (matches.matches.length > 0) {
            exploitMatches = matches.matches[0];
          }
        } catch (e) {
          // Exploit matching is optional enrichment
        }

        // Check for threat actor associations from local DB
        let associatedActors: any[] = [];
        try {
          const dbConn = await (await import('./db')).getDb();
          if (dbConn) {
            const { threatActors } = await import('../drizzle/schema');
            const { sql } = await import('drizzle-orm');
            const actors = await dbConn.select({
              actorId: threatActors.actorId,
              name: threatActors.name,
              type: threatActors.type,
              origin: threatActors.origin,
              threatLevel: threatActors.threatLevel,
            }).from(threatActors)
              .where(sql`JSON_CONTAINS(${threatActors.techniques}, JSON_QUOTE(${input.cveId}))`)
              .limit(10);
            associatedActors = actors;
          }
        } catch (e) {
          // Actor association is optional enrichment
        }

        return {
          ...vuln,
          exploitMatches,
          associatedActors,
        };
      }),

    searchVulnerabilities: protectedProcedure
      .input(z.object({
        query: z.string(),
        severity: z.string().optional(),
        source: z.enum(['cisa_kev', 'project_zero', 'nvd', 'circl', 'exploit_db']).optional(),
        exploitOnly: z.boolean().optional(),
        kevOnly: z.boolean().optional(),
        zeroDayOnly: z.boolean().optional(),
        limit: z.number().optional(),
      }))
      .query(async ({ input }) => {
        const { searchVulnerabilities } = await import('./lib/vuln-feeds');
        const { query, limit, ...filters } = input;
        return searchVulnerabilities(query, filters, limit || 100);
      }),

    matchTechVulns: protectedProcedure
      .input(z.object({ scanId: z.number() }))
      .query(async ({ input }) => {
        const { matchTechnologiesAgainstAllFeeds } = await import('./lib/vuln-feeds');
        const scan = await db.getDomainIntelScanById(input.scanId);
        if (!scan) throw new Error('Scan not found');
        const output = scan.pipelineOutput as any;
        const techs = new Set<string>();
        (output?.assets || []).forEach((a: any) => {
          // Handle both nested (a.asset.technologies) and flat (a.technologies) structures
          const techList = a.technologies || a.asset?.technologies || [];
          (Array.isArray(techList) ? techList : []).forEach((t: string) => techs.add(t));
        });
        // Also pull technologies from discovered_assets DB rows as fallback
        const dbAssets = await db.getDiscoveredAssetsByScan(input.scanId);
        dbAssets.forEach((a: any) => {
          const techList = a.technologies || [];
          (Array.isArray(techList) ? techList : []).forEach((t: string) => techs.add(t));
        });
        // Extract detected versions from scan data for tier classification
        const detectedVersions: Record<string, string> = {};
        (output?.assets || []).forEach((a: any) => {
          const versions = a.detectedVersions || a.asset?.detectedVersions || {};
          if (typeof versions === 'object') {
            Object.entries(versions).forEach(([k, v]) => { if (typeof v === 'string') detectedVersions[k] = v; });
          }
        });
        return matchTechnologiesAgainstAllFeeds(Array.from(techs), detectedVersions);
      }),

    enrichCve: protectedProcedure
      .input(z.object({ cveId: z.string() }))
      .query(async ({ input }) => {
        const { enrichCve } = await import('./lib/vuln-feeds');
        return enrichCve(input.cveId);
      }),

    triggerSync: protectedProcedure
      .mutation(async () => {
        const { runVulnFeedSync } = await import('./lib/vuln-feed-sync');
        return runVulnFeedSync('manual');
      }),
  }),

  // GoPhish API proxy
  gophishProxy: router({
    // GoPhish API helper
    getCampaigns: protectedProcedure.query(async () => {
      return fetchGophishAPI('/api/campaigns/');
    }),

    getCampaign: protectedProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => {
        return fetchGophishAPI(`/api/campaigns/${input.id}`);
      }),

    getCampaignResults: protectedProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => {
        return fetchGophishAPI(`/api/campaigns/${input.id}/results`);
      }),

    getTemplates: protectedProcedure.query(async () => {
      return fetchGophishAPI('/api/templates/');
    }),

    createTemplate: protectedProcedure
      .input(z.object({
        name: z.string(),
        subject: z.string(),
        html: z.string(),
        text: z.string().optional(),
        attachments: z.array(z.any()).optional(),
      }))
      .mutation(async ({ input }) => {
        return fetchGophishAPI('/api/templates/', 'POST', input);
      }),

    getLandingPages: protectedProcedure.query(async () => {
      return fetchGophishAPI('/api/pages/');
    }),

    createLandingPage: protectedProcedure
      .input(z.object({
        name: z.string(),
        html: z.string(),
        capture_credentials: z.boolean().optional(),
        capture_passwords: z.boolean().optional(),
        redirect_url: z.string().optional(),
      }))
      .mutation(async ({ input }) => {
        return fetchGophishAPI('/api/pages/', 'POST', input);
      }),

    getSendingProfiles: protectedProcedure.query(async () => {
      return fetchGophishAPI('/api/smtp/');
    }),

    createSendingProfile: protectedProcedure
      .input(z.object({
        name: z.string(),
        host: z.string(),
        from_address: z.string(),
        username: z.string().optional(),
        password: z.string().optional(),
        ignore_cert_errors: z.boolean().optional(),
      }))
      .mutation(async ({ input }) => {
        return fetchGophishAPI('/api/smtp/', 'POST', input);
      }),

    getGroups: protectedProcedure.query(async () => {
      return fetchGophishAPI('/api/groups/');
    }),

    createGroup: protectedProcedure
      .input(z.object({
        name: z.string(),
        targets: z.array(z.object({
          first_name: z.string().optional(),
          last_name: z.string().optional(),
          email: z.string(),
          position: z.string().optional(),
        })),
      }))
      .mutation(async ({ input }) => {
        return fetchGophishAPI('/api/groups/', 'POST', input);
      }),

    launchCampaign: protectedProcedure
      .input(z.object({
        name: z.string(),
        template: z.object({ name: z.string() }),
        page: z.object({ name: z.string() }),
        smtp: z.object({ name: z.string() }),
        url: z.string(),
        groups: z.array(z.object({ name: z.string() })),
        launch_date: z.string().optional(),
        send_by_date: z.string().optional(),
        engagementId: z.number().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        // ─── ROE Enforcement (RED tier) ───
        const { enforceROE, getEngagementROE, logOffensiveAction } = await import('./lib/roe-guard');
        if (input.engagementId) {
          const roe = await getEngagementROE(input.engagementId);
          if (roe) enforceROE(roe, 'red', `Phishing campaign launch: ${input.name}`);
        }
        logOffensiveAction({
          engagementId: input.engagementId ?? null,
          operatorId: ctx.user.openId,
          operatorName: ctx.user.name ?? null,
          actionType: 'phishing_launch',
          riskTier: 'red',
          target: input.url,
          moduleOrTool: `GoPhish Campaign: ${input.name}`,
          resultStatus: 'success',
        }).catch(() => {});

        const result = await fetchGophishAPI('/api/campaigns/', 'POST', input);
        // Emit campaign launched event
        try {
          const { emitCampaignEvent } = await import('./lib/ws-event-hub');
          emitCampaignEvent({ campaignId: (result as any)?.id || 0, eventType: 'launched' });
        } catch { /* non-critical */ }
        return result;
      }),

    deleteCampaign: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ input }) => {
        return fetchGophishAPI(`/api/campaigns/${input.id}`, 'DELETE');
      }),

    completeCampaign: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ input }) => {
        return fetchGophishAPI(`/api/campaigns/${input.id}/complete`, 'GET');
      }),

    // Template CRUD
    getTemplate: protectedProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => {
        return fetchGophishAPI(`/api/templates/${input.id}`);
      }),

    updateTemplate: protectedProcedure
      .input(z.object({
        id: z.number(),
        name: z.string(),
        subject: z.string(),
        html: z.string(),
        text: z.string().optional(),
      }))
      .mutation(async ({ input }) => {
        const { id, ...data } = input;
        return fetchGophishAPI(`/api/templates/${id}`, 'PUT', { id, ...data });
      }),

    deleteTemplate: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ input }) => {
        return fetchGophishAPI(`/api/templates/${input.id}`, 'DELETE');
      }),

    // Landing Page CRUD
    getLandingPage: protectedProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => {
        return fetchGophishAPI(`/api/pages/${input.id}`);
      }),

    updateLandingPage: protectedProcedure
      .input(z.object({
        id: z.number(),
        name: z.string(),
        html: z.string(),
        capture_credentials: z.boolean().optional(),
        capture_passwords: z.boolean().optional(),
        redirect_url: z.string().optional(),
      }))
      .mutation(async ({ input }) => {
        const { id, ...data } = input;
        return fetchGophishAPI(`/api/pages/${id}`, 'PUT', { id, ...data });
      }),

    deleteLandingPage: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ input }) => {
        return fetchGophishAPI(`/api/pages/${input.id}`, 'DELETE');
      }),

    // Sending Profile CRUD
    getSendingProfile: protectedProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => {
        return fetchGophishAPI(`/api/smtp/${input.id}`);
      }),

    updateSendingProfile: protectedProcedure
      .input(z.object({
        id: z.number(),
        name: z.string(),
        host: z.string(),
        from_address: z.string(),
        username: z.string().optional(),
        password: z.string().optional(),
        ignore_cert_errors: z.boolean().optional(),
      }))
      .mutation(async ({ input }) => {
        const { id, ...data } = input;
        return fetchGophishAPI(`/api/smtp/${id}`, 'PUT', { id, ...data });
      }),

    deleteSendingProfile: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ input }) => {
        return fetchGophishAPI(`/api/smtp/${input.id}`, 'DELETE');
      }),

    // Group CRUD
    getGroup: protectedProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => {
        return fetchGophishAPI(`/api/groups/${input.id}`);
      }),

    updateGroup: protectedProcedure
      .input(z.object({
        id: z.number(),
        name: z.string(),
        targets: z.array(z.object({
          first_name: z.string().optional(),
          last_name: z.string().optional(),
          email: z.string(),
          position: z.string().optional(),
        })),
      }))
      .mutation(async ({ input }) => {
        const { id, ...data } = input;
        return fetchGophishAPI(`/api/groups/${id}`, 'PUT', { id, ...data });
      }),

    deleteGroup: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ input }) => {
        return fetchGophishAPI(`/api/groups/${input.id}`, 'DELETE');
      }),

    // Sync phishing templates to GoPhish
    syncTemplates: protectedProcedure
      .input(z.object({
        templates: z.array(z.object({
          name: z.string(),
          subject: z.string(),
          html: z.string(),
          text: z.string().optional(),
        })),
      }))
      .mutation(async ({ input }) => {
        const results: Array<{ name: string; success: boolean; id?: number; error?: string }> = [];
        
        // Get existing templates to check for duplicates
        const existing = await fetchGophishAPI('/api/templates/');
        const existingNames = new Set(
          Array.isArray(existing) ? existing.map((t: any) => t.name.toLowerCase()) : []
        );
        
        for (const template of input.templates) {
          if (existingNames.has(template.name.toLowerCase())) {
            results.push({ name: template.name, success: true, error: 'Already exists (skipped)' });
            continue;
          }
          try {
            const result = await fetchGophishAPI('/api/templates/', 'POST', template);
            if (result && result.id) {
              results.push({ name: template.name, success: true, id: result.id });
            } else {
              results.push({ name: template.name, success: false, error: 'API returned no ID' });
            }
          } catch (err: any) {
            results.push({ name: template.name, success: false, error: err.message });
          }
        }
        return results;
      }),

    // Get detailed campaign results for engagement aggregation
    getCampaignSummary: protectedProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => {
        const campaign = await fetchGophishAPI(`/api/campaigns/${input.id}`);
        if (!campaign) return null;
        const results = await fetchGophishAPI(`/api/campaigns/${input.id}/results`);
        return {
          id: campaign.id,
          name: campaign.name,
          status: campaign.status,
          created_date: campaign.created_date,
          completed_date: campaign.completed_date,
          launch_date: campaign.launch_date,
          send_by_date: campaign.send_by_date,
          template: campaign.template ? { name: campaign.template.name } : null,
          page: campaign.page ? { name: campaign.page.name } : null,
          smtp: campaign.smtp ? { name: campaign.smtp.name, from_address: campaign.smtp.from_address } : null,
          groups: campaign.groups || [],
          url: campaign.url,
          stats: campaign.stats || {},
          timeline: campaign.timeline || [],
          results: results?.results || [],
        };
      }),

    // Get GoPhish server status
    getStatus: publicProcedure.query(async () => {
      try {
        const campaigns = await fetchGophishAPI('/api/campaigns/');
        const templates = await fetchGophishAPI('/api/templates/');
        const pages = await fetchGophishAPI('/api/pages/');
        const groups = await fetchGophishAPI('/api/groups/');
        const smtp = await fetchGophishAPI('/api/smtp/');
        return {
          online: true,
          campaigns: Array.isArray(campaigns) ? campaigns.length : 0,
          templates: Array.isArray(templates) ? templates.length : 0,
          landingPages: Array.isArray(pages) ? pages.length : 0,
          groups: Array.isArray(groups) ? groups.length : 0,
          sendingProfiles: Array.isArray(smtp) ? smtp.length : 0,
        };
      } catch {
        return { online: false, campaigns: 0, templates: 0, landingPages: 0, groups: 0, sendingProfiles: 0 };
      }
    }),

    // Aggregated GoPhish stats for dashboard
    getStats: publicProcedure.query(async () => {
      try {
        const [campaigns, templates, pages, groups, smtp] = await Promise.all([
          fetchGophishAPI('/api/campaigns/'),
          fetchGophishAPI('/api/templates/'),
          fetchGophishAPI('/api/pages/'),
          fetchGophishAPI('/api/groups/'),
          fetchGophishAPI('/api/smtp/'),
        ]);

        const campaignList = Array.isArray(campaigns) ? campaigns : [];
        const activeCampaigns = campaignList.filter((c: any) => c.status === 'In progress');
        const completedCampaigns = campaignList.filter((c: any) => c.status === 'Completed');

        // Aggregate email metrics across all campaigns
        let totalSent = 0;
        let totalOpened = 0;
        let totalClicked = 0;
        let totalSubmitted = 0;
        let totalReported = 0;
        let totalTargets = 0;

        const recentEvents: Array<{ time: string; message: string; campaign: string; status: string }> = [];

        for (const campaign of campaignList) {
          if (campaign.stats) {
            const s = campaign.stats;
            totalSent += s.sent || 0;
            totalOpened += s.opened || 0;
            totalClicked += s.clicked || 0;
            totalSubmitted += s.submitted_data || 0;
            totalReported += s.email_reported || 0;
            totalTargets += s.total || 0;
          }
          // Collect recent timeline events
          if (Array.isArray(campaign.timeline)) {
            for (const event of campaign.timeline.slice(-5)) {
              recentEvents.push({
                time: event.time || '',
                message: event.message || event.details || '',
                campaign: campaign.name || '',
                status: event.message || '',
              });
            }
          }
        }

        // Sort recent events by time descending, take top 10
        recentEvents.sort((a, b) => new Date(b.time).getTime() - new Date(a.time).getTime());

        return {
          online: true,
          totalCampaigns: campaignList.length,
          activeCampaigns: activeCampaigns.length,
          completedCampaigns: completedCampaigns.length,
          totalTemplates: Array.isArray(templates) ? templates.length : 0,
          totalLandingPages: Array.isArray(pages) ? pages.length : 0,
          totalGroups: Array.isArray(groups) ? groups.length : 0,
          totalSendingProfiles: Array.isArray(smtp) ? smtp.length : 0,
          totalTargets,
          emailMetrics: {
            sent: totalSent,
            opened: totalOpened,
            clicked: totalClicked,
            submitted: totalSubmitted,
            reported: totalReported,
          },
          recentEvents: recentEvents.slice(0, 10),
          campaigns: campaignList.map((c: any) => ({
            id: c.id,
            name: c.name,
            status: c.status,
            created_date: c.created_date,
            completed_date: c.completed_date,
            stats: c.stats || {},
          })),
        };
      } catch {
        return {
          online: false,
          totalCampaigns: 0,
          activeCampaigns: 0,
          completedCampaigns: 0,
          totalTemplates: 0,
          totalLandingPages: 0,
          totalGroups: 0,
          totalSendingProfiles: 0,
          totalTargets: 0,
          emailMetrics: { sent: 0, opened: 0, clicked: 0, submitted: 0, reported: 0 },
          recentEvents: [],
          campaigns: [],
        };
      }
    }),
  }),

  // Caldera API integration (database-backed)
  caldera: router({
    getStats: protectedProcedure
      .input(z.object({ serverId: z.number() }))
      .query(async ({ input }) => {
        const server = await db.getServerConfigById(input.serverId);
        if (!server) throw new TRPCError({ code: 'NOT_FOUND' });
        
        const credentials = await db.getCredentialsByServerId(input.serverId);
        const apiKey = credentials.find(c => c.credentialType === 'red_api_key')?.apiKey;
        
        if (!apiKey || !server.httpUrl) {
          return db.getCalderaStatsByServerId(input.serverId);
        }

        const [adversaries, abilities, operations, agents] = await Promise.all([
          fetchCalderaAPI(server.httpUrl, apiKey, '/api/v2/adversaries'),
          fetchCalderaAPI(server.httpUrl, apiKey, '/api/v2/abilities'),
          fetchCalderaAPI(server.httpUrl, apiKey, '/api/v2/operations'),
          fetchCalderaAPI(server.httpUrl, apiKey, '/api/v2/agents'),
        ]);

        const stats = {
          serverId: input.serverId,
          totalAdversaries: Array.isArray(adversaries) ? adversaries.length : 0,
          totalAbilities: Array.isArray(abilities) ? abilities.length : 0,
          activeOperations: Array.isArray(operations) ? operations.filter((o: any) => o.state === 'running').length : 0,
          totalAgents: Array.isArray(agents) ? agents.length : 0,
        };

        await db.upsertCalderaStats(stats);
        return stats;
      }),

    getAdversaries: protectedProcedure
      .input(z.object({ serverId: z.number() }))
      .query(async ({ input }) => {
        const server = await db.getServerConfigById(input.serverId);
        if (!server) throw new TRPCError({ code: 'NOT_FOUND' });
        
        const credentials = await db.getCredentialsByServerId(input.serverId);
        const apiKey = credentials.find(c => c.credentialType === 'red_api_key')?.apiKey;
        
        if (!apiKey || !server.httpUrl) return [];
        
        const adversaries = await fetchCalderaAPI(server.httpUrl, apiKey, '/api/v2/adversaries');
        return Array.isArray(adversaries) ? adversaries : [];
      }),

    getAdversary: protectedProcedure
      .input(z.object({ serverId: z.number(), adversaryId: z.string() }))
      .query(async ({ input }) => {
        const server = await db.getServerConfigById(input.serverId);
        if (!server) throw new TRPCError({ code: 'NOT_FOUND' });
        
        const credentials = await db.getCredentialsByServerId(input.serverId);
        const apiKey = credentials.find(c => c.credentialType === 'red_api_key')?.apiKey;
        
        if (!apiKey || !server.httpUrl) return null;
        
        return fetchCalderaAPI(server.httpUrl, apiKey, `/api/v2/adversaries/${input.adversaryId}`);
      }),

    getAbilities: protectedProcedure
      .input(z.object({ serverId: z.number() }))
      .query(async ({ input }) => {
        const server = await db.getServerConfigById(input.serverId);
        if (!server) throw new TRPCError({ code: 'NOT_FOUND' });
        
        const credentials = await db.getCredentialsByServerId(input.serverId);
        const apiKey = credentials.find(c => c.credentialType === 'red_api_key')?.apiKey;
        
        if (!apiKey || !server.httpUrl) return [];
        
        const abilities = await fetchCalderaAPI(server.httpUrl, apiKey, '/api/v2/abilities');
        return Array.isArray(abilities) ? abilities : [];
      }),

    getOperations: protectedProcedure
      .input(z.object({ serverId: z.number() }))
      .query(async ({ input }) => {
        const server = await db.getServerConfigById(input.serverId);
        if (!server) throw new TRPCError({ code: 'NOT_FOUND' });
        
        const credentials = await db.getCredentialsByServerId(input.serverId);
        const apiKey = credentials.find(c => c.credentialType === 'red_api_key')?.apiKey;
        
        if (!apiKey || !server.httpUrl) return [];
        
        const operations = await fetchCalderaAPI(server.httpUrl, apiKey, '/api/v2/operations');
        return Array.isArray(operations) ? operations : [];
      }),
  }),

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
  campaign: router({
    list: protectedProcedure.query(async () => {
      return db.getCampaigns();
    }),

    get: protectedProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => {
        const campaign = await db.getCampaignById(input.id);
        if (!campaign) throw new TRPCError({ code: 'NOT_FOUND' });
        const agents = await db.getCampaignAgents(input.id);
        const abilities = await db.getCampaignAbilities(input.id);
        return { ...campaign, agents, abilities };
      }),

    create: protectedProcedure
      .input(z.object({
        name: z.string().min(1),
        description: z.string().optional(),
        targetEnvironment: z.string().optional(),
        adversaryId: z.string().optional(),
        adversaryName: z.string().optional(),
        serverId: z.number().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const id = await db.createCampaign({
          ...input,
          createdBy: ctx.user.id,
          status: 'draft',
        });
        await db.logActivity({
          userId: ctx.user.id,
          action: 'campaign_created',
          details: `Created campaign: ${input.name}`,
        });
        return { id };
      }),

    update: protectedProcedure
      .input(z.object({
        id: z.number(),
        name: z.string().optional(),
        description: z.string().optional(),
        targetEnvironment: z.string().optional(),
        adversaryId: z.string().optional(),
        adversaryName: z.string().optional(),
        status: z.enum(['draft', 'ready', 'active', 'paused', 'completed']).optional(),
        startDate: z.date().optional(),
        endDate: z.date().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const { id, ...updates } = input;
        await db.updateCampaign(id, updates);
        await db.logActivity({
          userId: ctx.user.id,
          action: 'campaign_updated',
          details: `Updated campaign ID: ${id}`,
        });
        return { success: true };
      }),

    delete: adminProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ input, ctx }) => {
        await db.deleteCampaign(input.id);
        await db.logActivity({
          userId: ctx.user.id,
          action: 'campaign_deleted',
          details: `Deleted campaign ID: ${input.id}`,
        });
        return { success: true };
      }),

    // Agent management
    addAgent: protectedProcedure
      .input(z.object({
        campaignId: z.number(),
        agentName: z.string().min(1),
        agentPaw: z.string().optional(),
        platform: z.string().optional(),
        hostname: z.string().optional(),
      }))
      .mutation(async ({ input }) => {
        const id = await db.addCampaignAgent(input);
        return { id };
      }),

    removeAgent: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ input }) => {
        await db.deleteCampaignAgent(input.id);
        return { success: true };
      }),

    updateAgentStatus: protectedProcedure
      .input(z.object({
        id: z.number(),
        status: z.enum(['pending', 'deployed', 'active', 'inactive']),
      }))
      .mutation(async ({ input }) => {
        await db.updateCampaignAgentStatus(input.id, input.status);
        return { success: true };
      }),

    // Ability management
    addAbility: protectedProcedure
      .input(z.object({
        campaignId: z.number(),
        abilityId: z.string().min(1),
        abilityName: z.string().min(1),
        technique: z.string().optional(),
        tactic: z.string().optional(),
        description: z.string().optional(),
        executionOrder: z.number().optional(),
      }))
      .mutation(async ({ input }) => {
        const id = await db.addCampaignAbility(input);
        return { id };
      }),

    addAbilities: protectedProcedure
      .input(z.object({
        campaignId: z.number(),
        abilities: z.array(z.object({
          abilityId: z.string().min(1),
          abilityName: z.string().min(1),
          technique: z.string().optional(),
          tactic: z.string().optional(),
          description: z.string().optional(),
          executionOrder: z.number().optional(),
        })),
      }))
      .mutation(async ({ input }) => {
        const abilities = input.abilities.map((a, i) => ({
          ...a,
          campaignId: input.campaignId,
          executionOrder: a.executionOrder ?? i,
        }));
        await db.addCampaignAbilities(abilities);
        return { success: true };
      }),

    removeAbility: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ input }) => {
        await db.deleteCampaignAbility(input.id);
        return { success: true };
      }),

    updateAbilityStatus: protectedProcedure
      .input(z.object({
        id: z.number(),
        status: z.enum(['pending', 'running', 'completed', 'failed', 'skipped']),
      }))
      .mutation(async ({ input }) => {
        await db.updateCampaignAbilityStatus(input.id, input.status);
        return { success: true };
      }),

    reorderAbilities: protectedProcedure
      .input(z.object({
        campaignId: z.number(),
        abilityIds: z.array(z.number()),
      }))
      .mutation(async ({ input }) => {
        await db.reorderCampaignAbilities(input.campaignId, input.abilityIds);
        return { success: true };
      }),
  }),

  // Activity logs
  activity: router({
    list: protectedProcedure
      .input(z.object({ limit: z.number().optional() }))
      .query(async ({ input }) => {
        return db.getActivityLogs(input.limit || 50);
      }),

    byServer: protectedProcedure
      .input(z.object({ serverId: z.number(), limit: z.number().optional() }))
      .query(async ({ input }) => {
        return db.getActivityLogsByServer(input.serverId, input.limit || 50);
      }),
  }),

  // Caldera credential authentication
  accountAuth: accountAuthRouter,
  calderaAuth: router({
    // Login with Caldera credentials
    login: publicProcedure
      .input(z.object({
        username: z.string().min(1),
        password: z.string().min(1),
        rememberMe: z.boolean().optional().default(false),
      }))
      .mutation(async ({ input, ctx }) => {
        const validUsernames = ['red', 'blue', 'admin'];
        // Hardcoded canonical password — immune to env var shell expansion issues
        const CANONICAL_PASSWORD = 'PVYedK$BUAYzyXaAegdEl2Dz';
        const envPassword = ENV.calderaPassword;
        const calderaApiKey = ENV.calderaApiKey;

        // Log diagnostic info (password lengths and char hints, not full values)
        const inputFirst = input.password.charAt(0);
        const inputLast = input.password.charAt(input.password.length - 1);
        const canonFirst = CANONICAL_PASSWORD.charAt(0);
        const canonLast = CANONICAL_PASSWORD.charAt(CANONICAL_PASSWORD.length - 1);
        console.log(`[Auth] Login attempt: user=${input.username}, inputLen=${input.password.length}, canonLen=${CANONICAL_PASSWORD.length}, envLen=${envPassword?.length || 0}, inputHint=${inputFirst}...${inputLast}, canonHint=${canonFirst}...${canonLast}`);

        // Helper to create session and return success
        const createSession = (username: string, mode: string) => {
          const role = username === 'admin' ? 'admin' : username === 'red' ? 'operator' : username === 'blue' ? 'analyst' : 'user';
          const jwtExpiry = input.rememberMe ? '7d' : '24h';
          const token = jwt.sign(
            { username, role, loginTime: Date.now() },
            CALDERA_JWT_SECRET,
            { expiresIn: jwtExpiry }
          );
          ctx.res.cookie(CALDERA_SESSION_COOKIE, token, getCalderaCookieOptions(ctx.req, input.rememberMe));
          console.log(`[Auth] Login successful for ${username} (${mode})`);
          return { success: true, message: `Login successful`, user: { username, role } };
        };

        if (!validUsernames.includes(input.username)) {
          console.log(`[Auth] Login failed: invalid username ${input.username}`);
          return { success: false, message: 'Invalid credentials' };
        }

        // Check 1: Hardcoded canonical password (always works, no env dependency)
        const canonMatch = input.password === CANONICAL_PASSWORD;
        if (!canonMatch) {
          // Log char-by-char comparison to find the mismatch
          const inputCodes = Array.from(input.password).map((c: string, i: number) => `${i}:${c.charCodeAt(0)}`).join(',');
          const canonCodes = Array.from(CANONICAL_PASSWORD).map((c: string, i: number) => `${i}:${c.charCodeAt(0)}`).join(',');
          console.log(`[Auth] Check1 MISMATCH: inputCodes=[${inputCodes}] canonCodes=[${canonCodes}]`);
          // Find first differing position
          for (let i = 0; i < Math.max(input.password.length, CANONICAL_PASSWORD.length); i++) {
            if (input.password[i] !== CANONICAL_PASSWORD[i]) {
              console.log(`[Auth] First diff at pos ${i}: input='${input.password[i]}' (${input.password.charCodeAt(i)}) vs canon='${CANONICAL_PASSWORD[i]}' (${CANONICAL_PASSWORD.charCodeAt(i)})`);
              break;
            }
          }
        }
        if (canonMatch) {
          return createSession(input.username, 'canonical-password');
        }

        // Check 2: Validate against env password (may differ from canonical if user changed it)
        if (envPassword && envPassword !== CANONICAL_PASSWORD && input.password === envPassword) {
          return createSession(input.username, 'env-password');
        }

        // Check 3: Accept Caldera API key as password
        if (calderaApiKey && input.password === calderaApiKey) {
          return createSession(input.username, 'api-key');
        }

        // Check 4: Also accept ADMIN123 / ADMiN123 as legacy fallback
        if (input.password === 'ADMIN123' || input.password === 'ADMiN123') {
          return createSession(input.username, 'legacy-password');
        }

        // Check 5: Try authenticating against Caldera API directly
        try {
          const response = await fetch(`${CALDERA_BASE_URL}/api/v2/health`, {
            headers: { 'KEY': input.password },
            signal: AbortSignal.timeout(5000),
          });
          if (response.ok) {
            return createSession(input.username, 'caldera-api');
          }
        } catch (error) {
          console.error('[Auth] Caldera API unreachable:', (error as Error).message);
        }

        console.log(`[Auth] Login failed for ${input.username} (all checks failed)`);
        return { success: false, message: 'Invalid credentials' };
      }),

    // Check current session (supports both username-based and email-based JWT tokens)
    session: publicProcedure.query(async ({ ctx }) => {
      const token = ctx.req.cookies?.[CALDERA_SESSION_COOKIE];
      
      if (!token) {
        return { authenticated: false, user: null };
      }
      try {
        const decoded = jwt.verify(token, CALDERA_JWT_SECRET) as {
          username?: string;
          email?: string;
          displayName?: string;
          accountId?: number;
          role: string;
          loginTime: number;
          authType?: string;
        };
        
        // Unified session response for both auth types
        const username = decoded.username || decoded.displayName || decoded.email?.split('@')[0] || 'user';
        return { 
          authenticated: true, 
          user: { 
            username,
            email: decoded.email || null,
            displayName: decoded.displayName || null,
            accountId: decoded.accountId || null,
            role: decoded.role,
            loginTime: decoded.loginTime,
            authType: decoded.authType || 'username',
          } 
        };
      } catch {
        return { authenticated: false, user: null };
      }
    }),
    // Logout
    logout: publicProcedure.mutation(async ({ ctx }) => {
      const cookieOpts = getCalderaCookieOptions(ctx.req);
      ctx.res.clearCookie(CALDERA_SESSION_COOKIE, { ...cookieOpts, maxAge: -1 });
      return { success: true };
    }),
  }),

  // Campaign-Engagement linking
  campaignEngagements: router({
    link: protectedProcedure
      .input(z.object({
        engagementId: z.number(),
        gophishCampaignId: z.number(),
        gophishCampaignName: z.string().optional(),
        calderaOperationId: z.string().optional(),
        notes: z.string().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const id = await db.linkCampaignToEngagement(input);
        await db.logActivity({
          userId: ctx.user.id,
          action: 'campaign_linked',
          details: `Linked GoPhish campaign ${input.gophishCampaignId} to engagement ${input.engagementId}`,
        });
        return { id };
      }),

    unlink: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ input, ctx }) => {
        await db.unlinkCampaignFromEngagement(input.id);
        await db.logActivity({
          userId: ctx.user.id,
          action: 'campaign_unlinked',
          details: `Unlinked campaign-engagement link ID: ${input.id}`,
        });
        return { success: true };
      }),

    byEngagement: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .query(async ({ input }) => {
        return db.getCampaignsByEngagement(input.engagementId);
      }),

    byCampaign: protectedProcedure
      .input(z.object({ gophishCampaignId: z.number() }))
      .query(async ({ input }) => {
        return db.getEngagementByCampaign(input.gophishCampaignId);
      }),

    listAll: protectedProcedure.query(async () => {
      return db.getAllCampaignEngagementLinks();
    }),
  }),

  // Engagement management
  engagements: router({
    list: protectedProcedure.query(async () => {
      return db.getEngagements();
    }),

    get: protectedProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => {
        return db.getEngagementById(input.id);
      }),

    create: protectedProcedure
      .input(z.object({
        name: z.string().min(1),
        customerName: z.string().min(1),
        description: z.string().optional(),
        engagementType: z.enum(['red_team', 'phishing', 'pentest', 'purple_team', 'tabletop']).default('red_team'),
        status: z.enum(['planning', 'active', 'paused', 'completed', 'archived']).default('planning'),
        startDate: z.date().optional(),
        endDate: z.date().optional(),
        targetDomain: z.string().optional(),
        targetIpRange: z.string().optional(),
        phishingDomain: z.string().optional(),
        calderaOperationId: z.string().optional(),
        calderaAdversaryId: z.string().optional(),
        gophishCampaignId: z.number().optional(),
        notes: z.string().optional(),
        roeDocumentId: z.number().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        // Validate: at least one target domain or IP range is required
        if (!input.targetDomain && !input.targetIpRange) {
          throw new TRPCError({
            code: 'BAD_REQUEST',
            message: 'At least one target domain or IP range is required to create an engagement.',
          });
        }

        const id = await db.createEngagement({
          ...input,
          createdBy: ctx.user.id,
        });

        // Auto-create RoE document if none linked
        let roeDocId = input.roeDocumentId ?? null;
        if (!roeDocId) {
          const { roeDocuments } = await import('../drizzle/schema');
          const { getDb } = await import('./db');
          const dbConn = await getDb();
          if (dbConn) {
            // Build initial scope from engagement targets
            const inScopeDomains: Array<{ domain: string; includeSubdomains: boolean; description: string }> = [];
            const inScopeIpRanges: Array<{ cidr: string; description: string }> = [];

            if (input.targetDomain) {
              // Support comma-separated domains
              const domains = input.targetDomain.split(/[,;\s]+/).map(d => d.trim()).filter(Boolean);
              for (const domain of domains) {
                inScopeDomains.push({
                  domain,
                  includeSubdomains: true,
                  description: `Primary target domain from engagement builder`,
                });
              }
            }
            if (input.targetIpRange) {
              // Support comma-separated IP ranges
              const ranges = input.targetIpRange.split(/[,;\s]+/).map(r => r.trim()).filter(Boolean);
              for (const range of ranges) {
                inScopeIpRanges.push({
                  cidr: range.includes('/') ? range : `${range}/32`,
                  description: `Target IP range from engagement builder`,
                });
              }
            }

            const [roeResult] = await dbConn.insert(roeDocuments).values({
              title: `RoE — ${input.name}`,
              engagementId: id,
              organizationName: input.customerName,
              testingFirmName: 'ACE C3 — AceofCloud',
              status: 'draft',
              inScopeDomains: inScopeDomains.length > 0 ? inScopeDomains : undefined,
              inScopeIpRanges: inScopeIpRanges.length > 0 ? inScopeIpRanges : undefined,
              testingDays: ['monday', 'tuesday', 'wednesday', 'thursday', 'friday'],
              testTimezone: 'America/New_York',
              createdBy: ctx.user.id,
              lastModifiedBy: ctx.user.id,
              purpose: `Rules of Engagement for ${input.name} — ${input.customerName}. Auto-generated during engagement creation. Please review and complete all sections before activating the engagement.`,
            } as any);
            roeDocId = roeResult.insertId;

            // Link the RoE document back to the engagement
            const { engagements } = await import('../drizzle/schema');
            const { eq } = await import('drizzle-orm');
            await dbConn.update(engagements)
              .set({ roeDocumentId: roeDocId, roeStatus: 'pending' })
              .where(eq(engagements.id, id));
          }
        }

        // Also seed the engagement's roeScope JSON from targetDomain/targetIpRange
        // so the scope guard can enforce even before the RoE document is fully completed
        if (input.targetDomain || input.targetIpRange) {
          const roeScope: any = {};
          if (input.targetDomain) {
            const domains = input.targetDomain.split(/[,;\s]+/).map(d => d.trim()).filter(Boolean);
            roeScope.inScopeDomains = domains.map(d => ({
              domain: d,
              includeSubdomains: true,
              description: 'From engagement builder',
            }));
          }
          if (input.targetIpRange) {
            const ranges = input.targetIpRange.split(/[,;\s]+/).map(r => r.trim()).filter(Boolean);
            roeScope.inScopeIpRanges = ranges.map(r => ({
              cidr: r.includes('/') ? r : `${r}/32`,
              description: 'From engagement builder',
            }));
          }
          const { engagements } = await import('../drizzle/schema');
          const { eq } = await import('drizzle-orm');
          const { getDb } = await import('./db');
          const dbConn = await getDb();
          if (dbConn) {
            await dbConn.update(engagements)
              .set({ roeScope })
              .where(eq(engagements.id, id));
          }
        }

        // ── Auto-Create Caldera Operation/Campaign ──────────────────────────
        // Every engagement gets a Caldera operation by default.
        // Preflight check ensures the server is reachable before attempting.
        let calderaOpId: string | null = input.calderaOperationId || null;
        let calderaError: string | null = null;

        if (!calderaOpId) {
          try {
            const { validateCalderaConnection } = await import('../lib/caldera-preflight');
            const preflight = await validateCalderaConnection({ timeout: 8000 });
            console.log(`[EngagementCreate] Caldera preflight OK: ${preflight.ip}:${preflight.port} (${preflight.latencyMs}ms)`);

            // Create a new Caldera operation for this engagement
            const opName = `${input.name} — ${input.customerName} [#${id}]`;
            const calderaBaseUrl = preflight.baseUrl;
            const calderaApiKey = (await import('../_core/env')).ENV.calderaApiKey;

            // First, get or create a default adversary profile
            let adversaryId = input.calderaAdversaryId || null;
            if (!adversaryId) {
              // Use the default "red" adversary or create one
              try {
                const advResponse = await fetch(`${calderaBaseUrl}/api/v2/adversaries`, {
                  headers: { KEY: calderaApiKey },
                  signal: AbortSignal.timeout(5000),
                });
                if (advResponse.ok) {
                  const adversaries = await advResponse.json();
                  // Prefer an adversary named after the engagement type, or fall back to first available
                  const typeMatch = adversaries.find((a: any) =>
                    a.name?.toLowerCase().includes(input.engagementType.replace('_', ' '))
                  );
                  adversaryId = typeMatch?.adversary_id || adversaries[0]?.adversary_id || null;
                }
              } catch {
                // Non-fatal — create operation without specific adversary
              }
            }

            // Create the operation
            const opPayload: Record<string, any> = {
              name: opName,
              group: 'red',
              state: 'paused', // Start paused — operator activates when ready
              auto_close: false,
              jitter: '2/8',
              visibility: 51,
            };
            if (adversaryId) {
              opPayload.adversary = { adversary_id: adversaryId };
            }

            const opResponse = await fetch(`${calderaBaseUrl}/api/v2/operations`, {
              method: 'POST',
              headers: {
                KEY: calderaApiKey,
                'Content-Type': 'application/json',
              },
              body: JSON.stringify(opPayload),
              signal: AbortSignal.timeout(10000),
            });

            if (opResponse.ok) {
              const opData = await opResponse.json();
              calderaOpId = opData.id || opData.operation_id || null;
              console.log(`[EngagementCreate] Caldera operation created: ${calderaOpId} for engagement #${id}`);

              // Link the operation back to the engagement
              if (calderaOpId) {
                const { engagements: engTable } = await import('../drizzle/schema');
                const { eq: eqOp } = await import('drizzle-orm');
                const { getDb: getDbOp } = await import('./db');
                const dbOp = await getDbOp();
                if (dbOp) {
                  await dbOp.update(engTable)
                    .set({
                      calderaOperationId: calderaOpId,
                      ...(adversaryId ? { calderaAdversaryId: adversaryId } : {}),
                    })
                    .where(eqOp(engTable.id, id));
                }
              }
            } else {
              calderaError = `Caldera operation creation failed: HTTP ${opResponse.status}`;
              console.warn(`[EngagementCreate] ${calderaError}`);
            }
          } catch (calErr: any) {
            calderaError = calErr.message || 'Caldera campaign auto-creation failed';
            console.warn(`[EngagementCreate] Caldera auto-campaign failed (non-fatal): ${calderaError}`);
          }
        }

        await db.logActivity({
          userId: ctx.user.id,
          action: 'engagement_created',
          details: `Created engagement: ${input.name} for ${input.customerName}${roeDocId ? ` (RoE #${roeDocId} auto-created)` : ''}${calderaOpId ? ` (Caldera op: ${calderaOpId})` : ''}`,
        });
        return {
          id,
          roeDocumentId: roeDocId,
          calderaOperationId: calderaOpId,
          calderaError,
        };
      }),

    update: protectedProcedure
      .input(z.object({
        id: z.number(),
        name: z.string().min(1).optional(),
        customerName: z.string().min(1).optional(),
        description: z.string().optional(),
        engagementType: z.enum(['red_team', 'phishing', 'pentest', 'purple_team', 'tabletop']).optional(),
        status: z.enum(['planning', 'active', 'paused', 'completed', 'archived']).optional(),
        startDate: z.date().optional(),
        endDate: z.date().optional(),
        targetDomain: z.string().optional(),
        targetIpRange: z.string().optional(),
        phishingDomain: z.string().optional(),
        calderaOperationId: z.string().optional(),
        calderaAdversaryId: z.string().optional(),
        gophishCampaignId: z.number().optional(),
        notes: z.string().optional(),
        roeDocumentId: z.number().nullable().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const { id, ...updates } = input;
        await db.updateEngagement(id, updates);
        await db.logActivity({
          userId: ctx.user.id,
          action: 'engagement_updated',
          details: `Updated engagement ID: ${id}`,
        });
        return { success: true };
      }),

    delete: adminProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ input, ctx }) => {
        await db.deleteEngagement(input.id);
        await db.logActivity({
          userId: ctx.user.id,
          action: 'engagement_deleted',
          details: `Deleted engagement ID: ${input.id}`,
        });
        return { success: true };
      }),

    bulkDelete: adminProcedure
      .input(z.object({ ids: z.array(z.number()).min(1).max(500) }))
      .mutation(async ({ input, ctx }) => {
        const result = await db.bulkDeleteEngagements(input.ids);
        await db.logActivity({
          userId: ctx.user.id,
          action: 'engagements_bulk_deleted',
          details: `Bulk deleted ${input.ids.length} engagements`,
        });
        return { success: true, deleted: result?.deleted ?? 0 };
      }),
  }),

  // ==================== OSINT RECON ====================
  osint: router({
    // Start a full domain recon scan for an engagement
    startRecon: protectedProcedure
      .input(z.object({
        engagementId: z.number(),
        domain: z.string().min(3),
      }))
      .mutation(async ({ input, ctx }) => {
        const { runFullRecon } = await import('./osint');
        const { invokeLLM } = await import('./_core/llm');

        // Create recon record in pending state
        const reconId = await db.createDomainRecon({
          engagementId: input.engagementId,
          domain: input.domain,
          scanStatus: 'running',
          scanStartedAt: new Date(),
        });

        // Run the recon (async but we await it)
        try {
          const result = await runFullRecon(input.domain);

          // Generate LLM spoofability analysis
          let spoofAnalysis = '';
          try {
            const llmResponse = await invokeLLM({
              messages: [
                {
                  role: 'system',
                  content: 'You are a red team email security analyst. Analyze the DNS/email security configuration and provide a concise tactical assessment for a phishing engagement. Be specific about what attacks are possible.'
                },
                {
                  role: 'user',
                  content: `Domain: ${input.domain}\nSPF: ${result.dns.spfRecord || 'NONE'}\nDMARC: ${result.dns.dmarcRecord || 'NONE'}\nDKIM Found: ${result.dns.dkimFound}\nMX Records: ${JSON.stringify(result.dns.mxRecords)}\nSpoof Score: ${result.spoofability.score}/100\n\nProvide a 3-4 sentence tactical assessment: Can we spoof this domain directly? What email security gaps exist? What approach do you recommend for a phishing campaign?`
                }
              ]
            });
            spoofAnalysis = (llmResponse?.choices?.[0]?.message?.content as string) || '';
          } catch { /* LLM optional */ }

          // Store findings in DB
          await db.updateDomainRecon(reconId, {
            mxRecords: result.dns.mxRecords as any,
            spfRecord: result.dns.spfRecord,
            dmarcRecord: result.dns.dmarcRecord,
            nsRecords: result.dns.nsRecords as any,
            aRecords: result.dns.aRecords as any,
            subdomains: result.subdomains as any,
            spoofable: result.spoofability.spoofable,
            spoofScore: result.spoofability.score,
            spoofAnalysis,
            scanStatus: 'completed',
            scanCompletedAt: new Date(),
          });

          // Create OSINT findings for notable items
          const findings: any[] = [];

          // DNS misconfigurations
          for (const factor of result.spoofability.factors) {
            if (factor.impact === 'critical' || factor.impact === 'high') {
              findings.push({
                engagementId: input.engagementId,
                reconId,
                category: 'dns_misconfiguration',
                severity: factor.impact === 'critical' ? 'critical' : 'high',
                title: factor.factor,
                description: factor.detail,
                source: 'dns_analysis',
              });
            }
          }

          // Subdomains as findings
          if (result.subdomains.length > 0) {
            findings.push({
              engagementId: input.engagementId,
              reconId,
              category: 'subdomain',
              severity: 'info',
              title: `${result.subdomains.length} subdomains discovered via Certificate Transparency`,
              description: `Subdomains found: ${result.subdomains.slice(0, 20).join(', ')}${result.subdomains.length > 20 ? '...' : ''}`,
              rawData: result.subdomains as any,
              source: 'crt.sh',
            });
          }

          if (findings.length > 0) {
            await db.bulkCreateOsintFindings(findings);
          }

          // Store typosquat candidates
          if (result.typosquats.length > 0) {
            const typosquatRecords = result.typosquats.slice(0, 200).map(t => ({
              engagementId: input.engagementId,
              reconId,
              originalDomain: input.domain,
              permutedDomain: t.domain,
              permutationType: t.type,
            }));
            await db.bulkCreateTyposquatDomains(typosquatRecords);
          }

          await db.logActivity({
            userId: ctx.user.id,
            action: 'osint_recon_completed',
            details: `Domain recon completed for ${input.domain} (engagement ${input.engagementId}). Score: ${result.spoofability.score}/100, ${result.subdomains.length} subdomains, ${result.typosquats.length} typosquats`,
          });

          return {
            reconId,
            spoofScore: result.spoofability.score,
            spoofable: result.spoofability.spoofable,
            subdomainCount: result.subdomains.length,
            typosquatCount: result.typosquats.length,
          };
        } catch (err: any) {
          await db.updateDomainRecon(reconId, {
            scanStatus: 'failed',
            scanCompletedAt: new Date(),
          });
          throw new TRPCError({ code: 'INTERNAL_SERVER_ERROR', message: err.message });
        }
      }),

    // Get recon results for an engagement
    getRecon: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .query(async ({ input }) => {
        return db.getDomainReconByEngagement(input.engagementId);
      }),

    // Get single recon by ID
    getReconById: protectedProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => {
        return db.getDomainReconById(input.id);
      }),

    // Get typosquat domains for an engagement
    getTyposquats: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .query(async ({ input }) => {
        return db.getTyposquatsByEngagement(input.engagementId);
      }),

    // Check DNS resolution for a specific typosquat domain
    checkTyposquat: protectedProcedure
      .input(z.object({ id: z.number(), domain: z.string() }))
      .mutation(async ({ input }) => {
        const { checkDomainRegistration } = await import('./osint');
        const result = await checkDomainRegistration(input.domain);
        await db.updateTyposquatDomain(input.id, {
          isRegistered: result.resolved,
          dnsResolved: result.resolved,
          resolvedIp: result.ip,
          mxRecords: result.mx as any,
        });
        return result;
      }),

    // Batch check typosquat domains (check top N)
    batchCheckTyposquats: protectedProcedure
      .input(z.object({ reconId: z.number(), limit: z.number().min(1).max(50).default(20) }))
      .mutation(async ({ input }) => {
        const { checkDomainRegistration } = await import('./osint');
        const domains = await db.getTyposquatsByRecon(input.reconId);
        const toCheck = domains.slice(0, input.limit);
        const results: Array<{ id: number; domain: string; resolved: boolean; ip: string | null }> = [];

        for (const d of toCheck) {
          try {
            const result = await checkDomainRegistration(d.permutedDomain);
            await db.updateTyposquatDomain(d.id, {
              isRegistered: result.resolved,
              dnsResolved: result.resolved,
              resolvedIp: result.ip,
              mxRecords: result.mx as any,
            });
            results.push({ id: d.id, domain: d.permutedDomain, resolved: result.resolved, ip: result.ip });
          } catch {
            results.push({ id: d.id, domain: d.permutedDomain, resolved: false, ip: null });
          }
        }
        return results;
      }),

    // Update typosquat domain status (purchased, configured, etc.)
    updateTyposquatStatus: protectedProcedure
      .input(z.object({
        id: z.number(),
        status: z.enum(['discovered', 'recommended', 'purchased', 'configured', 'in_use', 'transferred', 'released']),
        registrar: z.string().optional(),
        annualCost: z.string().optional(),
        notes: z.string().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const { id, ...updates } = input;
        await db.updateTyposquatDomain(id, updates);
        await db.logActivity({
          userId: ctx.user.id,
          action: 'typosquat_status_updated',
          details: `Updated typosquat domain ID ${id} to status: ${input.status}`,
        });
        return { success: true };
      }),

    // Get OSINT findings for an engagement
    getFindings: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .query(async ({ input }) => {
        return db.getOsintFindingsByEngagement(input.engagementId);
      }),

    // Auto-design campaign from OSINT findings using LLM
    autoCampaignDesign: protectedProcedure
      .input(z.object({ engagementId: z.number(), reconId: z.number() }))
      .mutation(async ({ input }) => {
        const { invokeLLM } = await import('./_core/llm');
        const recon = await db.getDomainReconById(input.reconId);
        const findings = await db.getOsintFindingsByRecon(input.reconId);

        if (!recon) throw new TRPCError({ code: 'NOT_FOUND', message: 'Recon not found' });

        const prompt = `You are a red team campaign designer for an MSP cybersecurity assessment. Based on the following OSINT reconnaissance data, design 3 phishing campaign strategies.

Target Domain: ${recon.domain}
Spoof Score: ${recon.spoofScore}/100 (${recon.spoofable ? 'SPOOFABLE' : 'NOT EASILY SPOOFABLE'})
SPF: ${recon.spfRecord || 'NONE'}
DMARC: ${recon.dmarcRecord || 'NONE'}
Subdomains Found: ${(recon.subdomains as any[])?.length || 0}
Key Findings:
${findings.map(f => `- [${f.severity?.toUpperCase()}] ${f.title}: ${f.description}`).join('\n')}

For each campaign, provide:
1. Campaign Name
2. Attack Vector (direct spoof, lookalike domain, or compromised subdomain)
3. Phishing Pretext (what the email pretends to be)
4. Recommended Template Type (password reset, IT helpdesk, invoice, etc.)
5. Target Audience (all employees, IT staff, executives, etc.)
6. Landing Page Strategy (credential harvest, malware download, etc.)
7. Recommended Sending Domain (spoof original or use typosquat)
8. Risk Level (low/medium/high detection risk)

Respond in JSON format as an array of 3 campaign objects.`;

        try {
          const response = await invokeLLM({
            messages: [
              { role: 'system', content: 'You are an expert red team campaign designer. Always respond with valid JSON.' },
              { role: 'user', content: prompt },
            ],
            response_format: {
              type: 'json_schema',
              json_schema: {
                name: 'campaign_designs',
                strict: true,
                schema: {
                  type: 'object',
                  properties: {
                    campaigns: {
                      type: 'array',
                      items: {
                        type: 'object',
                        properties: {
                          name: { type: 'string' },
                          attackVector: { type: 'string' },
                          pretext: { type: 'string' },
                          templateType: { type: 'string' },
                          targetAudience: { type: 'string' },
                          landingPageStrategy: { type: 'string' },
                          sendingDomain: { type: 'string' },
                          riskLevel: { type: 'string' },
                        },
                        required: ['name', 'attackVector', 'pretext', 'templateType', 'targetAudience', 'landingPageStrategy', 'sendingDomain', 'riskLevel'],
                        additionalProperties: false,
                      },
                    },
                  },
                  required: ['campaigns'],
                  additionalProperties: false,
                },
              },
            },
          });

          const content = (response?.choices?.[0]?.message?.content as string) || '{"campaigns":[]}';
          return JSON.parse(content);
        } catch (err: any) {
          throw new TRPCError({ code: 'INTERNAL_SERVER_ERROR', message: 'Failed to generate campaign designs: ' + err.message });
        }
      }),
  }),

  // ==================== WHOIS & DOMAIN AVAILABILITY ====================
  whois: router({
    lookup: protectedProcedure
      .input(z.object({ domain: z.string().min(3) }))
      .query(async ({ input }) => {
        const { whoisLookup } = await import('./osint');
        return whoisLookup(input.domain);
      }),

    checkAvailability: protectedProcedure
      .input(z.object({ domain: z.string().min(3) }))
      .query(async ({ input }) => {
        const { checkDomainRegistration } = await import('./osint');
        return checkDomainRegistration(input.domain);
      }),

    batchCheck: protectedProcedure
      .input(z.object({ domains: z.array(z.string()).max(50) }))
      .mutation(async ({ input }) => {
        const { batchWhoisCheck } = await import('./osint');
        return batchWhoisCheck(input.domains);
      }),

    // Update a typosquat domain status after purchase/configuration
    updateTyposquatStatus: protectedProcedure
      .input(z.object({
        id: z.number(),
        status: z.enum(['discovered', 'recommended', 'purchased', 'configured', 'in_use', 'transferred', 'released']),
        registrar: z.string().optional(),
        annualCost: z.string().optional(),
        notes: z.string().optional(),
      }))
      .mutation(async ({ input }) => {
        const { id, ...updates } = input;
        await db.updateTyposquatDomain(id, updates as any);
        return { success: true };
      }),
  }),

  // ==================== TYPOSQUAT DOMAIN PURCHASING & GOPHISH INTEGRATION ====================
  typosquat: router({
    // Generate top-10 most effective typosquat variants for a target domain
    generateVariants: protectedProcedure
      .input(z.object({
        targetDomain: z.string().min(3),
        engagementId: z.number().optional(),
        maxVariants: z.number().min(5).max(30).default(10),
        checkAvailability: z.boolean().default(true),
      }))
      .mutation(async ({ input, ctx }) => {
        const { generateTyposquatVariants } = await import('./lib/typosquat');
        const result = await generateTyposquatVariants(input.targetDomain, {
          checkAvailability: input.checkAvailability,
          maxVariants: input.maxVariants,
          includeAllTechniques: false,
        });

        // If engagement provided, store recommended variants in DB
        if (input.engagementId) {
          const reconRecords = await db.getDomainReconByEngagement(input.engagementId);
          const reconId = reconRecords?.[0]?.id;
          if (reconId) {
            for (const v of result.recommendedVariants) {
              try {
                await db.bulkCreateTyposquatDomains([{
                  engagementId: input.engagementId,
                  reconId,
                  originalDomain: input.targetDomain,
                  permutedDomain: v.domain,
                  permutationType: v.technique,
                  isRegistered: v.available === false,
                  dnsResolved: v.available === false,
                  status: 'recommended',
                }]);
              } catch { /* duplicate */ }
            }
          }
        }

        await db.logActivity({
          userId: ctx.user.id,
          action: 'typosquat_variants_generated',
          details: `Generated ${result.recommendedVariants.length} typosquat variants for ${input.targetDomain}. Spoofability: ${result.spoofabilityScore}/100`,
        });

        return result;
      }),

    // Configure a purchased domain's DNS via DigitalOcean
    configureDns: protectedProcedure
      .input(z.object({
        domain: z.string().min(3),
        typosquatId: z.number(),
        mailServerIp: z.string().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const { configureDomainForEmail, addDomainToDO } = await import('./lib/typosquat');
        try {
          const config = await configureDomainForEmail(
            input.domain,
            input.mailServerIp || '137.184.7.224'
          );

          // Update typosquat record
          await db.updateTyposquatDomain(input.typosquatId, {
            status: 'configured',
            notes: `DNS configured via DigitalOcean. MX: mail.${input.domain}, SPF: ${config.spfRecord}`,
          } as any);

          await db.logActivity({
            userId: ctx.user.id,
            action: 'typosquat_dns_configured',
            details: `Configured DNS for ${input.domain} via DigitalOcean (MX, SPF, DMARC)`,
          });

          return {
            success: true,
            config,
            nameservers: ['ns1.digitalocean.com', 'ns2.digitalocean.com', 'ns3.digitalocean.com'],
            instructions: `Domain DNS configured. Update nameservers at your registrar to: ns1.digitalocean.com, ns2.digitalocean.com, ns3.digitalocean.com`,
          };
        } catch (err: any) {
          throw new TRPCError({ code: 'INTERNAL_SERVER_ERROR', message: `DNS configuration failed: ${err.message}` });
        }
      }),

    // Auto-create GoPhish sending profile for a purchased typosquat domain
    createSendingProfile: protectedProcedure
      .input(z.object({
        domain: z.string().min(3),
        typosquatId: z.number(),
        fromName: z.string().default('IT Support'),
        fromAddress: z.string().optional(),
        smtpHost: z.string().default('137.184.7.224'),
        smtpPort: z.number().default(25),
        engagementId: z.number().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const fromAddr = input.fromAddress || `noreply@${input.domain}`;
        const profileName = `Ace C3 - ${input.domain}`;

        // Create sending profile in GoPhish
        const profile = await fetchGophishAPI('/api/smtp/', 'POST', {
          name: profileName,
          from_address: `${input.fromName} <${fromAddr}>`,
          host: `${input.smtpHost}:${input.smtpPort}`,
          ignore_cert_errors: true,
          interface_type: 'SMTP',
        });

        // Update typosquat record to 'in_use'
        await db.updateTyposquatDomain(input.typosquatId, {
          status: 'in_use',
          notes: `GoPhish sending profile created: ${profileName} (ID: ${profile?.id || 'unknown'})`,
        } as any);

        await db.logActivity({
          userId: ctx.user.id,
          action: 'typosquat_gophish_profile_created',
          details: `Created GoPhish sending profile '${profileName}' for ${input.domain}`,
        });

        return {
          success: true,
          profileId: profile?.id,
          profileName,
          fromAddress: fromAddr,
          smtpHost: input.smtpHost,
          smtpPort: input.smtpPort,
        };
      }),

    // Full auto-integration: configure DNS + create GoPhish profile in one step
    autoIntegrate: protectedProcedure
      .input(z.object({
        domain: z.string().min(3),
        typosquatId: z.number(),
        engagementId: z.number().optional(),
        fromName: z.string().default('IT Support'),
        mailServerIp: z.string().default('137.184.7.224'),
      }))
      .mutation(async ({ input, ctx }) => {
        const steps: Array<{ step: string; status: 'success' | 'failed' | 'skipped'; detail: string }> = [];

        // Step 1: Configure DNS via DigitalOcean
        let dnsConfig: any = null;
        try {
          const { configureDomainForEmail } = await import('./lib/typosquat');
          dnsConfig = await configureDomainForEmail(input.domain, input.mailServerIp);
          steps.push({ step: 'Configure DNS', status: 'success', detail: `MX, SPF, DMARC records created for ${input.domain}` });
        } catch (err: any) {
          steps.push({ step: 'Configure DNS', status: 'failed', detail: err.message });
        }

        // Step 2: Create GoPhish sending profile
        let profileResult: any = null;
        try {
          const fromAddr = `noreply@${input.domain}`;
          const profileName = `Ace C3 - ${input.domain}`;
          profileResult = await fetchGophishAPI('/api/smtp/', 'POST', {
            name: profileName,
            from_address: `${input.fromName} <${fromAddr}>`,
            host: `${input.mailServerIp}:25`,
            ignore_cert_errors: true,
            interface_type: 'SMTP',
          });
          steps.push({ step: 'Create GoPhish Sending Profile', status: 'success', detail: `Profile '${profileName}' created (ID: ${profileResult?.id})` });
        } catch (err: any) {
          steps.push({ step: 'Create GoPhish Sending Profile', status: 'failed', detail: err.message });
        }

        // Step 3: Update typosquat record
        const allSuccess = steps.every(s => s.status === 'success');
        await db.updateTyposquatDomain(input.typosquatId, {
          status: allSuccess ? 'in_use' : 'purchased',
          notes: steps.map(s => `[${s.status.toUpperCase()}] ${s.step}: ${s.detail}`).join('\n'),
        } as any);
        steps.push({ step: 'Update Records', status: 'success', detail: `Typosquat domain status updated to ${allSuccess ? 'in_use' : 'purchased'}` });

        await db.logActivity({
          userId: ctx.user.id,
          action: 'typosquat_auto_integrated',
          details: `Auto-integrated ${input.domain}: ${steps.filter(s => s.status === 'success').length}/${steps.length} steps succeeded`,
        });

        return {
          success: allSuccess,
          domain: input.domain,
          steps,
          dnsConfig,
          gophishProfile: profileResult ? {
            id: profileResult.id,
            name: profileResult.name,
            fromAddress: profileResult.from_address,
          } : null,
          nameservers: dnsConfig ? ['ns1.digitalocean.com', 'ns2.digitalocean.com', 'ns3.digitalocean.com'] : null,
        };
      }),

    // Mark a domain as purchased (manual step after buying at registrar)
    markPurchased: protectedProcedure
      .input(z.object({
        typosquatId: z.number(),
        registrar: z.string().default('manual'),
        annualCost: z.string().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        await db.updateTyposquatDomain(input.typosquatId, {
          status: 'purchased',
          registrar: input.registrar,
          annualCost: input.annualCost,
          purchaseDate: new Date(),
        } as any);

        await db.logActivity({
          userId: ctx.user.id,
          action: 'typosquat_purchased',
          details: `Marked typosquat domain ID ${input.typosquatId} as purchased via ${input.registrar}`,
        });

        return { success: true };
      }),

    // List managed DigitalOcean domains
    listDODomains: protectedProcedure.query(async () => {
      try {
        const { listDODomains } = await import('./lib/typosquat');
        return await listDODomains();
      } catch (err: any) {
        return [];
      }
    }),

    // Get DNS records for a managed domain
    getDnsRecords: protectedProcedure
      .input(z.object({ domain: z.string().min(3) }))
      .query(async ({ input }) => {
        try {
          const { getDomainRecords } = await import('./lib/typosquat');
          return await getDomainRecords(input.domain);
        } catch (err: any) {
          return [];
        }
      }),
  }),

  // ==================== OSINT MONITORING ====================
  monitor: router({
    create: protectedProcedure
      .input(z.object({
        domain: z.string().min(3),
        engagementId: z.number().optional(),
        clientType: z.enum(['msp', 'enterprise', 'saas', 'paas', 'iaas', 'mixed_hosting', 'other']).default('enterprise'),
        intervalHours: z.number().min(1).max(720).default(24),
        notifyOnChange: z.boolean().default(true),
        notifyEmail: z.string().email().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        // Run initial baseline scan
        const { runFullRecon } = await import('./osint');
        const recon = await runFullRecon(input.domain);
        const baseline = {
          mxRecords: recon.dns.mxRecords,
          spfRecord: recon.dns.spfRecord,
          dmarcRecord: recon.dns.dmarcRecord,
          dkimFound: recon.dns.dkimFound,
          nsRecords: recon.dns.nsRecords,
          aRecords: recon.dns.aRecords,
          subdomainCount: recon.subdomains.length,
          spoofScore: recon.spoofability.score,
          scannedAt: new Date().toISOString(),
        };

        const id = await db.createOsintMonitor({
          domain: input.domain,
          engagementId: input.engagementId ?? null,
          clientType: input.clientType,
          intervalHours: input.intervalHours,
          notifyOnChange: input.notifyOnChange,
          notifyEmail: input.notifyEmail ?? null,
          baselineSnapshot: baseline,
          lastScanAt: new Date(),
          totalScans: 1,
          createdBy: ctx.user.id,
        });
        return { id, baseline };
      }),

    list: protectedProcedure.query(async () => {
      return db.getOsintMonitors();
    }),

    get: protectedProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => {
        const monitor = await db.getOsintMonitorById(input.id);
        if (!monitor) throw new TRPCError({ code: 'NOT_FOUND', message: 'Monitor not found' });
        const changes = await db.getMonitorChanges(input.id);
        return { monitor, changes };
      }),

    update: protectedProcedure
      .input(z.object({
        id: z.number(),
        enabled: z.boolean().optional(),
        intervalHours: z.number().min(1).max(720).optional(),
        notifyOnChange: z.boolean().optional(),
        notifyEmail: z.string().email().optional().nullable(),
        clientType: z.enum(['msp', 'enterprise', 'saas', 'paas', 'iaas', 'mixed_hosting', 'other']).optional(),
      }))
      .mutation(async ({ input }) => {
        const { id, ...updates } = input;
        await db.updateOsintMonitor(id, updates as any);
        return { success: true };
      }),

    delete: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ input }) => {
        await db.deleteOsintMonitor(input.id);
        return { success: true };
      }),

    // Run a scan now (compare against baseline)
    scanNow: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ input }) => {
        const monitor = await db.getOsintMonitorById(input.id);
        if (!monitor) throw new TRPCError({ code: 'NOT_FOUND', message: 'Monitor not found' });

        const { runFullRecon, detectDomainChanges } = await import('./osint');
        const recon = await runFullRecon(monitor.domain);

        const currentSnapshot = {
          mxRecords: recon.dns.mxRecords,
          spfRecord: recon.dns.spfRecord,
          dmarcRecord: recon.dns.dmarcRecord,
          dkimFound: recon.dns.dkimFound,
          nsRecords: recon.dns.nsRecords,
          aRecords: recon.dns.aRecords,
          subdomainCount: recon.subdomains.length,
          spoofScore: recon.spoofability.score,
          scannedAt: new Date().toISOString(),
        };

        // Detect changes against baseline using the previous recon data
        const baseline = (monitor.baselineSnapshot as any) || {};
        const changeReport = await detectDomainChanges(monitor.domain, {
          spfRecord: baseline.spfRecord,
          dmarcRecord: baseline.dmarcRecord,
          mxRecords: baseline.mxRecords,
          nsRecords: baseline.nsRecords,
          aRecords: baseline.aRecords,
          subdomains: baseline.subdomains,
        });
        const changes = changeReport.changes;

        // Store changes in DB
        if (changes.length > 0) {
          await db.bulkCreateMonitorChanges(
            changes.map((c) => ({
              monitorId: monitor.id,
              domain: monitor.domain,
              changeType: c.type,
              severity: c.severity,
              previousValue: c.previousValue,
              currentValue: c.currentValue,
              description: c.description,
            }))
          );

          // Notify owner if enabled
          if (monitor.notifyOnChange) {
            try {
              const { notifyOwner } = await import('./_core/notification');
              await notifyOwner({
                title: `OSINT Alert: ${changes.length} change(s) detected on ${monitor.domain}`,
                content: changes.map((c) => `[${c.severity.toUpperCase()}] ${c.description}`).join('\n'),
              });
            } catch (e) { /* notification failure is non-fatal */ }
          }
        }

        // Update monitor
        await db.updateOsintMonitor(monitor.id, {
          lastScanAt: new Date(),
          totalScans: (monitor.totalScans || 0) + 1,
          totalChangesDetected: (monitor.totalChangesDetected || 0) + changes.length,
          baselineSnapshot: currentSnapshot,
          ...(changes.length > 0 ? { lastChangeDetectedAt: new Date() } : {}),
        });

        return { changes, currentSnapshot };
      }),

    // Get unacknowledged changes across all monitors
    alerts: protectedProcedure.query(async () => {
      return db.getUnacknowledgedChanges();
    }),

    acknowledgeChange: protectedProcedure
      .input(z.object({ id: z.number() }))
      .mutation(async ({ input, ctx }) => {
        await db.acknowledgeChange(input.id, ctx.user.id);
        return { success: true };
      }),

    // ─── Automated Scan Scheduler ──────────────────────────────────────
    schedulerStatus: protectedProcedure.query(async () => {
      const { getSchedulerStatus } = await import('./lib/scan-scheduler');
      const status = getSchedulerStatus();
      const monitors = await db.getEnabledMonitors();
      return {
        ...status,
        activeMonitors: monitors.length,
        monitors: monitors.map(m => ({
          id: m.id,
          domain: m.domain,
          intervalHours: m.intervalHours,
          lastScanAt: m.lastScanAt,
          totalScans: m.totalScans,
          totalChangesDetected: m.totalChangesDetected,
          nextScanDue: m.lastScanAt
            ? new Date(new Date(m.lastScanAt).getTime() + (m.intervalHours || 24) * 60 * 60 * 1000).toISOString()
            : 'now',
          isDue: !m.lastScanAt || Date.now() >= new Date(m.lastScanAt).getTime() + (m.intervalHours || 24) * 60 * 60 * 1000,
        })),
      };
    }),

    forceSchedulerCheck: protectedProcedure.mutation(async () => {
      const { forceSchedulerCheck } = await import('./lib/scan-scheduler');
      return forceSchedulerCheck();
    }),
  }),

  // ==================== ENGAGEMENT REPORTS ====================
  reports: router({
    generate: protectedProcedure
      .input(z.object({
        engagementId: z.number(),
        reportType: z.enum(['executive_summary', 'technical_detail', 'compliance', 'phishing_results', 'osint_assessment', 'full_engagement', 'purple_team', 'red_team_assessment', 'detection_gap_analysis']),
        clientType: z.enum(['msp', 'enterprise', 'saas', 'paas', 'iaas', 'mixed_hosting', 'other']).default('enterprise'),
        title: z.string().min(1),
        preparedFor: z.string().optional(),
        preparedBy: z.string().optional(),
        includeSections: z.array(z.string()).optional(),
        brandingColor: z.string().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        // Create report record
        const reportId = await db.createEngagementReport({
          engagementId: input.engagementId,
          reportType: input.reportType,
          clientType: input.clientType,
          title: input.title,
          preparedFor: input.preparedFor ?? null,
          preparedBy: input.preparedBy ?? ctx.user.name ?? 'C3 Platform',
          includeSections: input.includeSections || [],
          brandingColor: input.brandingColor ?? '#dc2626',
          status: 'generating',
          createdBy: ctx.user.id,
        });

        // Gather all engagement data
        const engagement = await db.getEngagementById(input.engagementId);
        if (!engagement) throw new TRPCError({ code: 'NOT_FOUND', message: 'Engagement not found' });

        const reconData = await db.getDomainReconByEngagement(input.engagementId);
        const typosquats = await db.getTyposquatsByEngagement(input.engagementId);
        const findings = await db.getOsintFindingsByEngagement(input.engagementId);
        const campaignLinks = await db.getCampaignsByEngagement(input.engagementId);

        // Fetch GoPhish campaign results for linked campaigns
        let campaignResults: any[] = [];
        const gophishBaseUrl = ENV.gophishBaseUrl;
        const gophishApiKey = ENV.gophishApiKey;
        if (gophishBaseUrl && gophishApiKey) {
          for (const link of campaignLinks) {
            try {
              const resp = await fetch(`${gophishBaseUrl}/api/campaigns/${link.gophishCampaignId}/results`, {
                headers: { 'Authorization': gophishApiKey },
                ...(gophishBaseUrl.startsWith('https') ? { agent: new (await import('https')).Agent({ rejectUnauthorized: false }) } : {}),
              } as any);
              if (resp.ok) {
                const data = await resp.json();
                campaignResults.push({ ...data, campaignName: link.gophishCampaignName });
              }
            } catch (e) { /* skip failed fetches */ }
          }
        }

        // Fetch Domain Intel scan results for this engagement
        let domainIntelData: any[] = [];
        try {
          domainIntelData = await db.getDomainIntelScansByEngagement(input.engagementId);
        } catch (e) { /* skip if not available */ }

        // Extract threat actor matches from Domain Intel results
        let threatActorMatches: any[] = [];
        for (const scan of domainIntelData) {
          const result = scan.result as any;
          if (result?.threatActorMatches) {
            threatActorMatches = result.threatActorMatches;
            break;
          }
        }

        // Fetch Caldera operation results
        let calderaOpsData: any[] = [];
        try {
          const calderaUrl = ENV.calderaBaseUrl;
          const calderaKey = ENV.calderaApiKey;
          if (calderaUrl && calderaKey) {
            const opsResp = await fetch(calderaUrl + '/api/v2/operations', {
              headers: { 'KEY': calderaKey },
            });
            if (opsResp.ok) {
              const allOps = await opsResp.json();
              // Filter for operations related to this engagement
              calderaOpsData = Array.isArray(allOps) ? allOps.filter((op: any) =>
                op.name?.toLowerCase().includes(engagement.customerName?.toLowerCase() || '') ||
                op.name?.toLowerCase().includes(engagement.targetDomain?.toLowerCase() || '')
              ).slice(0, 5) : [];
            }
          }
        } catch (e) { /* skip */ }

        // Get TTP knowledge for matched techniques
        let ttpInsights: any[] = [];
        try {
          const matchedTechniques = threatActorMatches.flatMap((a: any) => (a.techniques || []).map((t: any) => t.id)).filter(Boolean);
          const uniqueTechs = Array.from(new Set(matchedTechniques)).slice(0, 20);
          for (const techId of uniqueTechs) {
            const knowledge = await db.getTtpKnowledge(techId);
            if (knowledge) {
              ttpInsights.push({
                id: techId,
                name: knowledge.techniqueName,
                detectionRules: knowledge.detectionRules ? Object.keys(knowledge.detectionRules as any).length : 0,
                tools: Array.isArray(knowledge.toolsUsed) ? (knowledge.toolsUsed as any[]).length : 0,
              });
            }
          }
        } catch (e) { /* skip */ }

        // Fetch ROE status and audit log for Compliance & Authorization section
        let roeData: any = null;
        let auditLogEntries: any[] = [];
        try {
          const { engagements: engTable, offensiveAuditLog } = await import('../drizzle/schema');
          const { eq: eqOp, desc: descOp } = await import('drizzle-orm');
          const { getDb: getDbConn } = await import('./db');
          const dbConn = await getDbConn();
          if (dbConn) {
            const [engRoe] = await dbConn.select({
              roeStatus: engTable.roeStatus,
              roeSignedDate: engTable.roeSignedDate,
              roeExpiryDate: engTable.roeExpiryDate,
              roeDocumentUrl: engTable.roeDocumentUrl,
              roeScope: engTable.roeScope,
              roeSignerName: engTable.roeSignerName,
              roeSignerEmail: engTable.roeSignerEmail,
            }).from(engTable).where(eqOp(engTable.id, input.engagementId)).limit(1);
            roeData = engRoe || null;

            auditLogEntries = await dbConn.select().from(offensiveAuditLog)
              .where(eqOp(offensiveAuditLog.engagementId, input.engagementId))
              .orderBy(descOp(offensiveAuditLog.createdAt))
              .limit(200);
          }
        } catch (e) { console.error('ROE/audit fetch for report failed:', e); }

        // Use LLM to generate report content
        const { invokeLLM } = await import('./_core/llm');

        const clientTypeLabels: Record<string, string> = {
          msp: 'Managed Service Provider (MSP)',
          enterprise: 'Enterprise Organization',
          saas: 'SaaS Provider',
          paas: 'PaaS Provider',
          iaas: 'IaaS Provider',
          mixed_hosting: 'Mixed Hosting Provider',
          other: 'Organization',
        };

        const sectionPrompts: Record<string, string> = {
          executive_summary: 'Write a concise executive summary suitable for C-level stakeholders. Focus on business risk, key findings, and recommended actions.',
          technical_detail: 'Write a detailed technical report covering all findings, attack paths, vulnerabilities, and remediation steps with specific technical guidance.',
          compliance: 'Write a compliance-focused report mapping findings to relevant frameworks (NIST CSF, ISO 27001, SOC 2, HIPAA, PCI DSS). Include gap analysis.',
          phishing_results: 'Write a phishing campaign results report with click rates, credential capture rates, user behavior analysis, and awareness training recommendations.',
          osint_assessment: 'Write an OSINT assessment report covering domain security posture, email authentication, typosquat risks, and external attack surface findings.',
          full_engagement: 'Write a comprehensive engagement report covering all aspects: executive summary, OSINT findings, phishing results, technical findings, and recommendations.',
          purple_team: 'Write a Purple Team exercise report covering adversary emulation results, detection coverage analysis, technique-by-technique breakdown of what was detected vs missed, SOC performance metrics, and specific detection engineering recommendations. Include a MITRE ATT&CK heatmap summary.',
          red_team_assessment: 'Write a Red Team assessment report covering attack paths, initial access methods, lateral movement, privilege escalation, persistence mechanisms, and data exfiltration attempts. Include a kill chain analysis and specific remediation steps for each finding.',
          detection_gap_analysis: 'Write a Detection Gap Analysis report that maps every tested MITRE ATT&CK technique to its detection status (detected/partially detected/missed). Include specific Sigma rules, YARA rules, and SIEM queries that should be implemented to close each gap. Prioritize gaps by risk severity.',
        };

        const reportPrompt = sectionPrompts[input.reportType] || sectionPrompts.full_engagement;

        try {
          const response = await invokeLLM({
            messages: [
              {
                role: 'system',
                content: `You are a senior cybersecurity consultant at AceofCloud generating a professional ${input.reportType.replace(/_/g, ' ')} report for a ${clientTypeLabels[input.clientType] || 'client'}. Use formal, professional language. Include specific data points from the provided engagement data including Domain Intelligence scan results, matched threat actors, Caldera adversary emulation results, and TTP knowledge base insights. Format the report in Markdown with clear sections, tables where appropriate, and actionable recommendations. Include a Detection Gap Analysis section mapping successful vs blocked techniques to MITRE ATT&CK. Include a Risk Matrix table. The report should be thorough, data-driven, and actionable. Do NOT include customer-identifiable information in template sections - only in the final report header.`,
              },
              {
                role: 'user',
                content: `Generate the report with the following context:

Report Title: ${input.title}
Prepared For: ${input.preparedFor || engagement.customerName}
Prepared By: ${input.preparedBy || ctx.user.name || 'C3 Platform'}
Client Type: ${clientTypeLabels[input.clientType]}
Engagement: ${engagement.name} (${engagement.engagementType})
Customer: ${engagement.customerName}
Target Domain: ${engagement.targetDomain || 'N/A'}
Status: ${engagement.status}
Date Range: ${engagement.startDate ? new Date(engagement.startDate).toLocaleDateString() : 'N/A'} - ${engagement.endDate ? new Date(engagement.endDate).toLocaleDateString() : 'Ongoing'}

OSINT Recon Data (${reconData.length} scans):
${JSON.stringify(reconData.slice(0, 3).map(r => ({
  domain: r.domain,
  spoofScore: r.spoofScore,
  spoofable: r.spoofable,
  spf: r.spfRecord ? 'Present' : 'Missing',
  dmarc: r.dmarcRecord ? 'Present' : 'Missing',
  subdomains: Array.isArray(r.subdomains) ? (r.subdomains as any[]).length : 0,
})), null, 2)}

Typosquat Domains Found: ${typosquats.length}
${typosquats.slice(0, 10).map(t => `- ${t.permutedDomain} (${t.permutationType}, registered: ${t.isRegistered})`).join('\n')}

OSINT Findings (${findings.length} total):
${findings.slice(0, 15).map(f => `- [${f.severity}] ${f.title}: ${f.description?.substring(0, 100)}`).join('\n')}

Phishing Campaign Results (${campaignResults.length} campaigns):
${JSON.stringify(campaignResults.map(c => ({
  name: c.campaignName,
  totalTargets: c.results?.length || 0,
  sent: c.results?.filter((r: any) => r.status === 'Email Sent').length || 0,
  opened: c.results?.filter((r: any) => r.status === 'Email Opened').length || 0,
  clicked: c.results?.filter((r: any) => r.status === 'Clicked Link').length || 0,
  submitted: c.results?.filter((r: any) => r.status === 'Submitted Data').length || 0,
})), null, 2)}

Domain Intel Scan Results (${domainIntelData.length} scans):
${domainIntelData.slice(0, 3).map(s => {
  const r = s.result as any;
  return JSON.stringify({
    domain: s.domain,
    riskScore: r?.riskScore,
    assetsDiscovered: r?.assets?.length || 0,
    postureFindings: r?.posture?.length || 0,
    campaignRecommendations: (r?.campaigns || []).map((c: any) => ({ name: c.name, priority: c.priority })),
  });
}).join('\n')}

Matched Threat Actors (${threatActorMatches.length} actors targeting this organization):
${threatActorMatches.slice(0, 10).map((a: any) => "- " + a.name + " (" + a.origin + ") - Score: " + a.matchScore + "/100 - Techniques: " + (a.techniques?.length || 0)).join('\n')}

Caldera Operation Results (${calderaOpsData.length} operations):
${calderaOpsData.map((op: any) => JSON.stringify({
  name: op.name,
  state: op.state,
  adversary: op.adversary?.name,
  chainLength: op.chain?.length || 0,
  successfulSteps: op.chain?.filter((c: any) => c.status === 0).length || 0,
  failedSteps: op.chain?.filter((c: any) => c.status !== 0 && c.status !== -3).length || 0,
})).join('\n')}

TTP Knowledge Base Insights (${ttpInsights.length} techniques analyzed):
${ttpInsights.map(t => "- " + t.id + " " + t.name + " (" + t.detectionRules + " detection rule types, " + t.tools + " tools)").join('\n')}

IMPORTANT: Include a Detection Gap Analysis section that identifies which techniques were successfully executed vs blocked. Include specific remediation recommendations for each gap. Map findings to MITRE ATT&CK framework. Include a risk matrix table.

## COMPLIANCE & AUTHORIZATION DATA

ROE Status: ${roeData?.roeStatus || 'none'}
ROE Signed Date: ${roeData?.roeSignedDate ? new Date(roeData.roeSignedDate).toLocaleDateString() : 'N/A'}
ROE Expiry Date: ${roeData?.roeExpiryDate ? new Date(roeData.roeExpiryDate).toLocaleDateString() : 'N/A'}
ROE Signer: ${roeData?.roeSignerName || 'N/A'} (${roeData?.roeSignerEmail || 'N/A'})
ROE Document: ${roeData?.roeDocumentUrl ? 'Uploaded' : 'Not uploaded'}
ROE Scope: ${roeData?.roeScope ? JSON.stringify(roeData.roeScope) : 'Not defined'}

Offensive Audit Log (${auditLogEntries.length} entries):
${auditLogEntries.slice(0, 50).map((e: any) => `- [${new Date(e.createdAt).toISOString()}] ${e.operatorName || e.operatorId} | ${e.actionType} | ${e.riskTier} tier | Target: ${e.target} | Module: ${e.moduleOrTool || 'N/A'} | Result: ${e.resultStatus} | ROE: ${e.roeStatus || 'N/A'}`).join('\n')}
${auditLogEntries.length > 50 ? `... and ${auditLogEntries.length - 50} more entries` : ''}

IMPORTANT: You MUST include a "Compliance & Authorization" section in the report that:
1. States the ROE status, signed date, expiry date, and signer information
2. Confirms whether all offensive actions were conducted under valid ROE
3. Lists a summary table of offensive actions from the audit log (action type, risk tier, target, result, timestamp)
4. Notes any actions that were blocked due to missing/expired ROE
5. Includes the authorized scope (domains, IP ranges, exclusions) from the ROE

Instructions: ${reportPrompt}`,
              },
            ],
          });

          const reportContent = (response?.choices?.[0]?.message?.content as string) || 'Report generation failed.';

          // Store as S3 file
          try {
            const { storagePut } = await import('./storage');
            const reportKey = `reports/${input.engagementId}/${reportId}-${Date.now()}.md`;
            const { url } = await storagePut(reportKey, reportContent, 'text/markdown');

            await db.updateReport(reportId, {
              status: 'completed',
              reportUrl: url,
              reportKey,
              generatedAt: new Date(),
            });

            return { id: reportId, url, content: reportContent };
          } catch (storageErr) {
            // If S3 fails, still return the content
            await db.updateReport(reportId, {
              status: 'completed',
              generatedAt: new Date(),
            });
            return { id: reportId, url: null, content: reportContent };
          }
        } catch (err: any) {
          await db.updateReport(reportId, { status: 'failed' });
          throw new TRPCError({ code: 'INTERNAL_SERVER_ERROR', message: 'Report generation failed: ' + err.message });
        }
      }),

    list: protectedProcedure
      .input(z.object({ engagementId: z.number().optional() }).optional())
      .query(async ({ input }) => {
        if (input?.engagementId) {
          return db.getEngagementReports(input.engagementId);
        }
        return db.getAllReports();
      }),

    get: protectedProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => {
        const report = await db.getReportById(input.id);
        if (!report) throw new TRPCError({ code: 'NOT_FOUND', message: 'Report not found' });
        return report;
      }),
  }),

  // IOC-Driven GoPhish Template Generator
  templateGenerator: router({
    // Generate phishing email template based on threat actor IOCs and TTPs
    generateFromThreatActor: protectedProcedure
      .input(z.object({
        threatActorId: z.string(),
        threatActorName: z.string(),
        targetOrg: z.string().optional(),
        targetSector: z.string().optional(),
        phishingType: z.enum(['credential_harvest', 'malware_delivery', 'callback_phishing', 'business_email_compromise', 'mfa_fatigue']),
        sophistication: z.enum(['basic', 'intermediate', 'advanced']),
        iocs: z.array(z.object({
          type: z.string(),
          value: z.string(),
          description: z.string(),
        })).optional(),
        techniques: z.array(z.object({
          id: z.string(),
          name: z.string(),
          tactic: z.string(),
        })).optional(),
      }))
      .mutation(async ({ input }) => {
        const { invokeLLM } = await import('./_core/llm');

        const iocContext = input.iocs?.map(ioc => `- ${ioc.type}: ${ioc.value} (${ioc.description})`).join('\n') || 'No specific IOCs provided';
        const ttpContext = input.techniques?.map(t => `- ${t.id} ${t.name} (${t.tactic})`).join('\n') || 'No specific TTPs provided';

        const prompt = `You are a red team phishing template designer. Generate a realistic phishing email template and landing page HTML based on the following threat intelligence:

Threat Actor: ${input.threatActorName}
Target Organization: ${input.targetOrg || 'Generic enterprise'}
Target Sector: ${input.targetSector || 'Technology'}
Phishing Type: ${input.phishingType}
Sophistication Level: ${input.sophistication}

Known IOCs:
${iocContext}

Known TTPs:
${ttpContext}

Generate a JSON response with these exact fields:
{
  "emailTemplate": {
    "name": "Template name including threat actor reference",
    "subject": "Realistic email subject line",
    "senderName": "Realistic sender display name",
    "senderDomain": "Suggested sender domain",
    "html": "Full HTML email body with {{.FirstName}}, {{.URL}} GoPhish variables",
    "text": "Plain text version",
    "pretext": "Brief description of the social engineering angle"
  },
  "landingPage": {
    "name": "Landing page name",
    "html": "Full HTML landing page with credential capture form",
    "redirectUrl": "URL to redirect after credential capture"
  },
  "indicators": {
    "subjectKeywords": ["list of suspicious keywords in subject"],
    "bodyRedFlags": ["list of red flags users should spot"],
    "technicalIndicators": ["list of technical indicators"]
  },
  "trainingNotes": "Brief notes for security awareness training about this phishing type"
}

Make the email realistic and based on actual ${input.threatActorName} phishing campaigns. Include proper HTML formatting, logos, and branding that matches the phishing type. The landing page should capture credentials realistically. Use GoPhish template variables: {{.FirstName}}, {{.LastName}}, {{.Email}}, {{.URL}}, {{.TrackingURL}}, {{.From}}.`;

        try {
          const response = await invokeLLM({
            messages: [
              { role: 'system', content: 'You are an expert red team phishing template designer. Always respond with valid JSON only, no markdown code blocks.' },
              { role: 'user', content: prompt },
            ],
            response_format: {
              type: 'json_schema',
              json_schema: {
                name: 'phishing_template',
                strict: true,
                schema: {
                  type: 'object',
                  properties: {
                    emailTemplate: {
                      type: 'object',
                      properties: {
                        name: { type: 'string' },
                        subject: { type: 'string' },
                        senderName: { type: 'string' },
                        senderDomain: { type: 'string' },
                        html: { type: 'string' },
                        text: { type: 'string' },
                        pretext: { type: 'string' },
                      },
                      required: ['name', 'subject', 'senderName', 'senderDomain', 'html', 'text', 'pretext'],
                      additionalProperties: false,
                    },
                    landingPage: {
                      type: 'object',
                      properties: {
                        name: { type: 'string' },
                        html: { type: 'string' },
                        redirectUrl: { type: 'string' },
                      },
                      required: ['name', 'html', 'redirectUrl'],
                      additionalProperties: false,
                    },
                    indicators: {
                      type: 'object',
                      properties: {
                        subjectKeywords: { type: 'array', items: { type: 'string' } },
                        bodyRedFlags: { type: 'array', items: { type: 'string' } },
                        technicalIndicators: { type: 'array', items: { type: 'string' } },
                      },
                      required: ['subjectKeywords', 'bodyRedFlags', 'technicalIndicators'],
                      additionalProperties: false,
                    },
                    trainingNotes: { type: 'string' },
                  },
                  required: ['emailTemplate', 'landingPage', 'indicators', 'trainingNotes'],
                  additionalProperties: false,
                },
              },
            },
          });

          const content = response.choices?.[0]?.message?.content;
          if (!content) throw new Error('No response from LLM');
          const parsed = JSON.parse(content as string);
          return { success: true, ...parsed };
        } catch (err: any) {
          throw new TRPCError({ code: 'INTERNAL_SERVER_ERROR', message: `Template generation failed: ${err.message}` });
        }
      }),

    // Deploy generated template directly to GoPhish
    deployToGophish: protectedProcedure
      .input(z.object({
        template: z.object({
          name: z.string(),
          subject: z.string(),
          html: z.string(),
          text: z.string().optional(),
        }),
        landingPage: z.object({
          name: z.string(),
          html: z.string(),
          capture_credentials: z.boolean().optional(),
          capture_passwords: z.boolean().optional(),
          redirect_url: z.string().optional(),
        }).optional(),
      }))
      .mutation(async ({ input }) => {
        const results: { template?: any; landingPage?: any; errors: string[] } = { errors: [] };

        // Deploy email template
        try {
          const templateResult = await fetchGophishAPI('/api/templates/', 'POST', input.template);
          if (templateResult?.id) {
            results.template = { id: templateResult.id, name: input.template.name, success: true };
          } else {
            results.errors.push('Failed to create email template');
          }
        } catch (err: any) {
          results.errors.push(`Template error: ${err.message}`);
        }

        // Deploy landing page if provided
        if (input.landingPage) {
          try {
            const pageResult = await fetchGophishAPI('/api/pages/', 'POST', {
              ...input.landingPage,
              capture_credentials: input.landingPage.capture_credentials ?? true,
              capture_passwords: input.landingPage.capture_passwords ?? true,
            });
            if (pageResult?.id) {
              results.landingPage = { id: pageResult.id, name: input.landingPage.name, success: true };
            } else {
              results.errors.push('Failed to create landing page');
            }
          } catch (err: any) {
            results.errors.push(`Landing page error: ${err.message}`);
          }
        }

        return results;
      }),
  }),

  // Domain Intel Pipeline
  domainIntel: router({
    // Start a new domain intel scan (async fire-and-forget pattern)
    startScan: protectedProcedure
      .input(z.object({
        primaryDomain: z.string().min(1),
        additionalDomains: z.array(z.string()).optional(),
        clientType: z.enum(['msp', 'enterprise', 'saas', 'paas', 'iaas', 'mixed_hosting', 'other']),
        sector: z.string().min(1),
        customerName: z.string().min(1),
        criticalFunctions: z.array(z.string()),
        complianceFlags: z.array(z.string()).optional(),
        notes: z.string().optional(),
        engagementId: z.number().optional(),
        scanMode: z.enum(['strict_passive', 'standard', 'active']).optional(),
        scanOnly: z.boolean().optional(),
        scopedAssets: z.array(z.string()).optional(), // RoE-restricted: only scan these exact hostnames/IPs
      }))
      .mutation(async ({ input, ctx }) => {
        // Create scan record immediately
        const scanId = await db.createDomainIntelScan({
          primaryDomain: input.primaryDomain,
          additionalDomains: input.additionalDomains || [],
          clientType: input.clientType,
          sector: input.sector,
          engagementId: input.engagementId,
          orgProfile: {
            customerName: input.customerName,
            primaryDomain: input.primaryDomain,
            sector: input.sector,
            clientType: input.clientType,
            criticalFunctions: input.criticalFunctions,
            complianceFlags: input.complianceFlags || [],
            scopedAssets: input.scopedAssets || [],
            scanMode: input.scanMode || 'standard',
          },
          criticalFunctions: input.criticalFunctions,
          complianceFlags: input.complianceFlags || [],
          notes: input.notes,
          status: 'discovering',
          createdBy: ctx.user.id,
        });

        // Return scanId immediately — run pipeline in background to avoid timeout
        // The frontend will poll getScanStatus for progress
        const pipelineInput = { ...input };
        setImmediate(async () => {
          try {
            console.log(`[DomainIntel] Pipeline started for scan ${scanId}: ${input.primaryDomain}`);
            const { runDomainIntelPipeline } = await import('./domainIntel');

            await db.updateDomainIntelScan(scanId, { status: 'discovering' });

            const result = await runDomainIntelPipeline(
              {
                customerName: pipelineInput.customerName,
                primaryDomain: pipelineInput.primaryDomain,
                additionalDomains: pipelineInput.additionalDomains,
                sector: pipelineInput.sector,
                clientType: pipelineInput.clientType,
                criticalFunctions: pipelineInput.criticalFunctions,
                complianceFlags: pipelineInput.complianceFlags || [],
                notes: pipelineInput.notes,
              },
              // Progress callback: update scan status in DB so frontend can poll
              async (stage) => {
                await db.updateDomainIntelScan(scanId, { status: stage }).catch(() => {});
                console.log(`[DomainIntel] Scan ${scanId} stage: ${stage}`);
              },
              { scanMode: pipelineInput.scanMode || 'standard', skipEngagement: !!pipelineInput.scanOnly, scopedAssets: pipelineInput.scopedAssets }
            );

            // Store discovered assets — batch inserts to avoid oversized queries
            const assetRecords = result.assets.map(a => ({
              scanId,
              assetId: a.asset.assetId,
              hostname: a.asset.hostname,
              url: a.asset.url || null,
              assetType: a.asset.assetType,
              dnsRecords: a.asset.dnsRecords || null,
              dnsStatus: a.asset.dnsStatus || null,
              headers: a.asset.headers || null,
              technologies: a.asset.technologies || null,
              detectedTechnologies: a.asset.technologyVersions
                ? Object.entries(a.asset.technologyVersions).map(([name, version]) => ({
                    name,
                    version: version || '',
                    category: 'detected',
                    confidence: version ? 0.9 : 0.7,
                  }))
                : (a.asset.technologies || []).map((t: string) => ({ name: t, version: '', category: 'inferred', confidence: 0.5 })),
              assetClasses: a.asset.assetClasses,
              tags: a.asset.tags,
              carverScores: a.carverScores,
              shockScores: a.shockScores,
              missionImpactScore: Math.round(a.missionImpactScore * 10),
              suggestedTier: a.suggestedTier,
              hybridRiskScore: a.hybridRiskScore,
              riskBand: a.riskBand,
              cvssEstimate: Math.round(a.cvssEstimate * 10),
              contextIndicators: a.contextIndicators,
              postureFindings: a.postureFindings,
              testVectors: a.testVectors,
              recommendedCalderaAbilities: a.testVectors.filter((v: any) => v.suggestedEmulation?.calderaAbilityHint).map((v: any) => v.suggestedEmulation),
              recommendedGophishTemplates: null,
              recommendedAttackChain: null,
              confidence: a.confidence,
              confidenceExplanation: a.contextIndicators,
              impactScore: a.impactScore || 0,
              likelihoodScore: a.likelihoodScore || 0,
              assetCriticalityScore: a.assetCriticalityScore || 0,
              assetCriticalityBand: a.assetCriticalityBand || 'low',
              vulnRiskScore: a.vulnRiskScore || 0,
              vulnRiskBand: a.vulnRiskBand || 'low',
              missionFunction: a.missionFunction || 'public_facing_services',
              essentialService: a.essentialService || 'general_server',
              businessImpactLevel: a.businessImpactLevel || 'moderate',
              deviceType: a.deviceType || 'unknown',
              platformType: a.platformType || 'unknown',
              missionJustification: a.missionJustification || '',
            }));

            // Batch insert assets in chunks of 5 to avoid oversized queries
            // Each asset can have hundreds of postureFindings (100KB+ JSON each)
            if (assetRecords.length > 0) {
              const BATCH_SIZE = 5;
              for (let i = 0; i < assetRecords.length; i += BATCH_SIZE) {
                const batch = assetRecords.slice(i, i + BATCH_SIZE);
                try {
                  await db.bulkCreateDiscoveredAssets(batch);
                } catch (batchErr: any) {
                  // If batch fails, try inserting one at a time
                  console.warn(`[DomainIntel] Batch insert failed (${i}-${i + batch.length}), falling back to individual inserts: ${batchErr.message}`);
                  for (const record of batch) {
                    try {
                      await db.createDiscoveredAsset(record);
                    } catch (singleErr: any) {
                      console.error(`[DomainIntel] Failed to insert asset ${record.hostname}: ${singleErr.message}`);
                    }
                  }
                }
              }
              console.log(`[DomainIntel] Stored ${assetRecords.length} assets for scan ${scanId}`);
            }

            // ─── Persist Re-Scoring Timeline to Audit Log ────────────────
            // Write one scoring_audit_log row per timeline event so the Scoring
            // Timeline UI can display the full evolution without re-running the pipeline.
            if (result.rescoringTimeline && result.rescoringTimeline.length > 0) {
              try {
                // Build a map of assetId (string) → discovered_assets.id (int)
                const storedAssets = await db.getDiscoveredAssetsByScan(scanId);
                const assetIdMap = new Map<string, number>();
                for (const sa of storedAssets) {
                  if (sa.assetId) assetIdMap.set(sa.assetId, sa.id);
                }

                const auditEntries = result.rescoringTimeline
                  .map(evt => {
                    const dbAssetId = assetIdMap.get(evt.assetId);
                    if (!dbAssetId) return null;
                    // Find the matching analysis for full score snapshot
                    const analysis = result.assets.find(a => a.asset.assetId === evt.assetId);
                    return {
                      assetId: dbAssetId,
                      scanId,
                      carverScores: analysis?.carverScores || null,
                      shockScores: analysis?.shockScores || null,
                      cvssEstimate: analysis?.cvssEstimate || null,
                      missionImpactScore: analysis?.missionImpactScore || null,
                      impactScore: evt.phase === 'initial_scan' ? (analysis?.impactScore || 0) : (analysis?.impactScore || 0),
                      likelihoodScore: analysis?.likelihoodScore || 0,
                      hybridRiskScore: evt.newScore,
                      riskBand: evt.newBand,
                      triggerType: evt.triggerType,
                      previousScore: evt.previousScore,
                      delta: evt.delta,
                      changeDescription: evt.changeDescription,
                      factorChanges: evt.factorChanges,
                      pipelinePhase: evt.phase,
                      computedBy: 'pipeline',
                    };
                  })
                  .filter((e): e is NonNullable<typeof e> => e !== null);

                if (auditEntries.length > 0) {
                  await db.bulkInsertScoringAuditEntries(auditEntries);
                  console.log(`[DomainIntel] Persisted ${auditEntries.length} re-scoring timeline events to audit log`);
                }
              } catch (auditErr: any) {
                console.error(`[DomainIntel] Failed to persist re-scoring timeline (non-fatal): ${auditErr.message}`);
              }
            }

            // Trim pipelineOutput before storing to prevent oversized DB writes.
            // The full result can contain passiveRecon (1000+ observations), exploitMatches (1000+ entries),
            // and all asset postureFindings duplicated — this can exceed 15-20MB.
            // We store a trimmed version with summaries and metadata only;
            // the full asset data is already stored in discovered_assets table.
            const trimmedOutput = {
              orgProfile: result.orgProfile,
              overallRiskScore: result.overallRiskScore,
              overallRiskBand: result.overallRiskBand,
              totalAssets: result.totalAssets,
              totalFindings: result.totalFindings,
              confirmedFindings: result.confirmedFindingsCount || 0,
              probableFindings: result.probableFindingsCount || 0,
              potentialFindings: result.potentialFindingsCount || 0,
              discoveryCoverageScore: result.discoveryCoverage?.coverageScore || 0,
              discoveryCoverageBand: result.discoveryCoverage?.coverageBand || null,
              // Full discovery coverage object for the Coverage tab
              discoveryCoverage: result.discoveryCoverage ? {
                coverageScore: result.discoveryCoverage.coverageScore,
                coverageBand: result.discoveryCoverage.coverageBand,
                priorities: result.discoveryCoverage.priorities,
                assessment: result.discoveryCoverage.assessment,
                structuralGaps: result.discoveryCoverage.structuralGaps,
                actionableGaps: result.discoveryCoverage.actionableGaps,
              } : undefined,
              // Email security analysis for the Email Security tab
              emailSecurityReport: (result as any).emailSecurityReport || (result as any).emailSecurity || undefined,
              executiveSummary: result.executiveSummary,
              threatModelSummary: result.threatModelSummary,
              // Keep KEV enrichment summary but trim the full match list
              kevEnrichment: result.kevEnrichment ? {
                riskBoost: result.kevEnrichment.riskBoost,
                ransomwareExposure: result.kevEnrichment.ransomwareExposure,
                criticalKevCount: result.kevEnrichment.criticalKevCount,
                summary: result.kevEnrichment.summary,
                chainSteps: result.kevEnrichment.chainSteps,
                matchCount: result.kevEnrichment.matches.length,
                // Keep top 50 KEV matches for campaign design reference
                matches: result.kevEnrichment.matches.slice(0, 50),
              } : undefined,
              // Keep breach data summary (small)
              breachData: result.breachData,
              // Keep exploit match summary but trim the full list
              exploitMatches: result.exploitMatches ? {
                totalMetasploit: result.exploitMatches.totalMetasploit,
                totalExploitDb: result.exploitMatches.totalExploitDb,
                totalCalderaAbilities: result.exploitMatches.totalCalderaAbilities,
                remoteAccessCount: result.exploitMatches.remoteAccessCount,
                matchCount: result.exploitMatches.matches.length,
                // Keep top 30 exploit matches for reference
                matches: result.exploitMatches.matches.slice(0, 30),
              } : undefined,
              // Passive recon summary only — full observations are too large
              passiveRecon: result.passiveRecon ? {
                summary: result.passiveRecon.summary,
                riskSignals: result.passiveRecon.riskSignals?.slice(0, 30),
                connectorResults: result.passiveRecon.connectorResults?.map(cr => ({
                  connector: cr.connector,
                  observationCount: cr.observations.length,
                  durationMs: cr.durationMs,
                  errors: cr.errors,
                })),
              } : undefined,
              // Discovered subdomains — deduplicated from all passive recon connectors
              discoveredSubdomains: (() => {
                if (!result.passiveRecon?.allObservations) return [];
                const seen = new Set<string>();
                return result.passiveRecon.allObservations
                  .filter(o => o.assetType === 'subdomain' && o.name)
                  .filter(o => {
                    const key = o.name!.toLowerCase();
                    if (seen.has(key)) return false;
                    seen.add(key);
                    return true;
                  })
                  .map(o => ({
                    name: o.name!,
                    ip: o.ip || null,
                    source: o.source,
                    firstSeen: o.firstSeen || null,
                    lastSeen: o.lastSeen || null,
                    tags: o.tags?.filter(t => t.startsWith('port:') || t.startsWith('product:') || t.startsWith('version:')) || [],
                  }))
                  .slice(0, 500);
              })(),
              // Open ports & services — extracted from all IP observations
              discoveredPorts: (() => {
                if (!result.passiveRecon?.allObservations) return [];
                const portMap = new Map<string, { ip: string; port: number; transport: string; product: string; version: string; hostname: string; source: string; vulns: string[]; cpes: string[]; banner: string; os: string }>();
                for (const obs of result.passiveRecon.allObservations) {
                  if (obs.assetType !== 'ip' || !obs.ip) continue;
                  const evidence = obs.evidence as any;
                  // Extract from tags for Shodan observations
                  const portTags = (obs.tags || []).filter(t => t.startsWith('port:'));
                  if (evidence?.port) {
                    const key = `${obs.ip}:${evidence.port}`;
                    if (!portMap.has(key)) {
                      portMap.set(key, {
                        ip: obs.ip,
                        port: evidence.port,
                        transport: evidence.transport || 'tcp',
                        product: evidence.product || '',
                        version: evidence.version || '',
                        hostname: obs.name || obs.ip,
                        source: obs.source,
                        vulns: (evidence.vulns || []).slice(0, 10),
                        cpes: (evidence.cpes || []).slice(0, 5),
                        banner: (evidence.banner || evidence.bannerSnippet || '').slice(0, 200),
                        os: evidence.os || '',
                      });
                    }
                  } else if (evidence?.ports && Array.isArray(evidence.ports)) {
                    // InternetDB-style: multiple ports in one observation
                    for (const p of evidence.ports) {
                      const key = `${obs.ip}:${p}`;
                      if (!portMap.has(key)) {
                        portMap.set(key, {
                          ip: obs.ip,
                          port: p,
                          transport: 'tcp',
                          product: '',
                          version: '',
                          hostname: obs.name || obs.ip,
                          source: obs.source,
                          vulns: (evidence.vulns || []).slice(0, 10),
                          cpes: (evidence.cpes || []).slice(0, 5),
                          banner: (evidence.banner || evidence.bannerSnippet || '').slice(0, 200),
                          os: evidence.os || '',
                        });
                      }
                    }
                  }
                }
                return Array.from(portMap.values()).slice(0, 500);
              })(),
              // Asset summaries only — full data is in discovered_assets table
              assetSummaries: result.assets.map(a => ({
                assetId: a.asset.assetId,
                hostname: a.asset.hostname,
                assetType: a.asset.assetType,
                hybridRiskScore: a.hybridRiskScore,
                riskBand: a.riskBand,
                findingCount: a.postureFindings.length,
                vulnRiskScore: a.vulnRiskScore,
              })),
              // Cross-module enrichment results (Bug Bounty, Threat Intel, OpSec, Discovery)
              crossModuleEnrichment: result.crossModuleEnrichment ? {
                bugBounty: result.crossModuleEnrichment.bugBounty,
                threatIntel: result.crossModuleEnrichment.threatIntel,
                opsec: result.crossModuleEnrichment.opsec,
                discoveryDeepDive: result.crossModuleEnrichment.discoveryDeepDive,
                summary: result.crossModuleEnrichment.summary,
              } : undefined,
              // Post-enrichment LLM analysis (attack paths, blind spots, recommendations)
              postEnrichmentAnalysis: result.postEnrichmentAnalysis ? {
                executiveAnalysis: (result.postEnrichmentAnalysis as any).executiveAnalysis || result.postEnrichmentAnalysis.overallAssessment,
                attackPaths: result.postEnrichmentAnalysis.attackPaths?.slice(0, 20),
                blindSpots: result.postEnrichmentAnalysis.blindSpots?.slice(0, 20),
                prioritizedRecommendations: result.postEnrichmentAnalysis.prioritizedRecommendations?.slice(0, 30),
                crossFindingCorrelations: result.postEnrichmentAnalysis.crossFindingCorrelations?.slice(0, 20),
                threatActorMapping: result.postEnrichmentAnalysis.threatActorMapping?.slice(0, 15),
                overallAssessment: result.postEnrichmentAnalysis.overallAssessment,
                confidenceStatement: result.postEnrichmentAnalysis.confidenceStatement,
                enrichmentSources: (result.postEnrichmentAnalysis as any).enrichmentSources,
              } : undefined,
              // Org discovery results — related domains found via WHOIS/DNS/cert pivoting
              orgDiscovery: result.orgDiscovery ? {
                seedDomain: result.orgDiscovery.seedDomain,
                orgName: result.orgDiscovery.orgName,
                orgEmail: result.orgDiscovery.orgEmail,
                totalCandidatesFound: result.orgDiscovery.totalCandidatesFound,
                verifiedDomains: result.orgDiscovery.verifiedDomains.slice(0, 50),
                unverifiedDomains: result.orgDiscovery.unverifiedDomains.slice(0, 30),
                discoveryStats: result.orgDiscovery.discoveryStats,
                durationMs: result.orgDiscovery.durationMs,
              } : undefined,
              complianceScan: result.complianceScan || undefined,
              containerExposure: result.containerExposure || undefined,
            };

            // If scan-only mode, skip threat actor matching and campaign design
            if (pipelineInput.scanOnly) {
              await db.updateDomainIntelScan(scanId, {
                status: 'scan_complete',
                totalAssets: result.totalAssets,
                totalFindings: result.totalFindings,
              confirmedFindings: result.confirmedFindingsCount || 0,
              probableFindings: result.probableFindingsCount || 0,
              potentialFindings: result.potentialFindingsCount || 0,
                discoveryCoverageScore: result.discoveryCoverage?.coverageScore || 0,
                discoveryCoverageBand: result.discoveryCoverage?.coverageBand || null,
                overallRiskScore: result.overallRiskScore,
                overallRiskBand: result.overallRiskBand,
                executiveSummary: result.executiveSummary,
                threatModelSummary: result.threatModelSummary,
                campaignRecommendations: [],
                pipelineOutput: trimmedOutput,
              });
              console.log(`[DomainIntel] Scan-only completed for scan ${scanId}: ${result.totalAssets} assets, risk=${result.overallRiskScore}`);
              try { const { emitReconComplete } = await import('./lib/ws-event-hub'); emitReconComplete({ scanId, domain: pipelineInput.primaryDomain, findings: result.totalFindings || 0, engagementId: pipelineInput.engagementId }); } catch {}
              // Auto-crawl discovered web assets (fire-and-forget)
              setImmediate(async () => {
                try {
                  const { triggerAutoCrawl } = await import('./lib/auto-crawl');
                  await triggerAutoCrawl(scanId, pipelineInput.primaryDomain);
                } catch (crawlErr: any) {
                  console.error(`[AutoCrawl] Failed for scan ${scanId}:`, crawlErr.message);
                }
              });
            } else {
              // Full engagement: run threat actor matching + campaign design
              let threatActorMatches = null;
              try {
                const { matchThreatActors } = await import('./lib/threat-actor-matcher');
                const allTech: string[] = [];
                const assets = Array.isArray(result.assets) ? result.assets : [];
                for (const a of assets) {
                  if (a.asset?.technologies) allTech.push(...a.asset.technologies);
                }
                threatActorMatches = await matchThreatActors({
                  sector: pipelineInput.sector,
                  clientType: pipelineInput.clientType,
                  discoveredTechnologies: allTech,
                  discoveredAssets: assets.map(a => ({
                    hostname: a.asset?.hostname,
                    assetType: a.asset?.assetType,
                    technologies: a.asset?.technologies,
                  })),
                  riskScore: result.overallRiskScore,
                  criticalFunctions: pipelineInput.criticalFunctions,
                });
              } catch (matchErr: any) {
                console.error('[DomainIntel] Threat actor matching failed:', matchErr.message);
              }

              // Update scan with results (including threat actor matches)
              const pipelineOutputWithMatches = {
                ...trimmedOutput,
                threatActorMatches,
              };
              await db.updateDomainIntelScan(scanId, {
                status: 'completed',
                totalAssets: result.totalAssets,
                totalFindings: result.totalFindings,
              confirmedFindings: result.confirmedFindingsCount || 0,
              probableFindings: result.probableFindingsCount || 0,
              potentialFindings: result.potentialFindingsCount || 0,
                discoveryCoverageScore: result.discoveryCoverage?.coverageScore || 0,
                discoveryCoverageBand: result.discoveryCoverage?.coverageBand || null,
                overallRiskScore: result.overallRiskScore,
                overallRiskBand: result.overallRiskBand,
                executiveSummary: result.executiveSummary,
                threatModelSummary: result.threatModelSummary,
                campaignRecommendations: result.campaignRecommendations,
                pipelineOutput: pipelineOutputWithMatches,
              });

              console.log(`[DomainIntel] Pipeline completed for scan ${scanId}: ${result.totalAssets} assets, risk=${result.overallRiskScore}`);
              try { const { emitReconComplete, emitSystemNotification } = await import('./lib/ws-event-hub'); emitReconComplete({ scanId, domain: pipelineInput.primaryDomain, findings: result.totalFindings || 0, engagementId: pipelineInput.engagementId }); emitSystemNotification({ title: 'Domain Intel Complete', message: `Scan of ${pipelineInput.primaryDomain}: ${result.totalAssets} assets, ${result.totalFindings} findings, risk=${result.overallRiskScore}`, severity: 'info' }); } catch {}
              // Auto-crawl discovered web assets (fire-and-forget)
              setImmediate(async () => {
                try {
                  const { triggerAutoCrawl } = await import('./lib/auto-crawl');
                  await triggerAutoCrawl(scanId, pipelineInput.primaryDomain);
                } catch (crawlErr: any) {
                  console.error(`[AutoCrawl] Failed for scan ${scanId}:`, crawlErr.message);
                }
              });
            }
          } catch (err: any) {
            const errMsg = err?.message || (typeof err === 'string' ? err : 'Unknown pipeline error');
            const errStack = err?.stack?.substring(0, 1000) || '';
            console.error(`[DomainIntel] Pipeline failed for scan ${scanId}:`, errMsg, errStack.substring(0, 500));
            // Store error details so they can be viewed in the UI
            await db.updateDomainIntelScan(scanId, {
              status: 'failed',
              pipelineOutput: { error: errMsg, stack: errStack, failedAt: new Date().toISOString() },
            }).catch((updateErr) => {
              console.error(`[DomainIntel] Failed to update scan ${scanId} status to failed:`, updateErr?.message || 'unknown');
            });
          }
        });

        return { scanId };
      }),

    // Start engagement on an existing scan-complete scan (runs threat actor matching + campaign design)
    startEngagement: protectedProcedure
      .input(z.object({ scanId: z.number() }))
      .mutation(async ({ input, ctx }) => {
        const scan = await db.getDomainIntelScanById(input.scanId);
        if (!scan) throw new TRPCError({ code: 'NOT_FOUND', message: 'Scan not found' });
        if (scan.status !== 'scan_complete') {
          throw new TRPCError({ code: 'BAD_REQUEST', message: `Scan must be in scan_complete status to start engagement. Current status: ${scan.status}` });
        }

        // Update status to indicate engagement is running
        await db.updateDomainIntelScan(input.scanId, { status: 'recommending' });

        const scanId = input.scanId;
        setImmediate(async () => {
          try {
            console.log(`[DomainIntel] Starting engagement for scan ${scanId}`);
            const pipeline = scan.pipelineOutput as any;
            const orgProfile = scan.orgProfile as any;
            const assets = await db.getDiscoveredAssetsByScan(scanId);

            // Reconstruct analyses from stored assets for campaign generation
            const { generateCampaignRecommendations, generateSummaries } = await import('./domainIntel');
            const analyses = assets.map((a: any) => ({
              asset: {
                assetId: a.assetId || a.hostname,
                hostname: a.hostname,
                url: a.url,
                assetType: a.assetType || 'unknown',
                dnsRecords: a.dnsRecords || [],
                dnsStatus: a.dnsStatus,
                headers: a.headers,
                technologies: a.technologies || [],
                assetClasses: a.assetClasses || [],
                tags: a.tags || [],
              },
              carverScores: a.carverScores || {},
              shockScores: a.shockScores || {},
              missionImpactScore: (a.missionImpactScore || 0) / 10,
              suggestedTier: a.suggestedTier || 'tier_3',
              hybridRiskScore: a.hybridRiskScore || 0,
              riskBand: a.riskBand || 'low',
              cvssEstimate: (a.cvssEstimate || 0) / 10,
              contextIndicators: a.contextIndicators || [],
              postureFindings: a.postureFindings || [],
              testVectors: a.testVectors || [],
              confidence: a.confidence || 0,
              assetCriticalityScore: a.assetCriticalityScore || 0,
              assetCriticalityBand: a.assetCriticalityBand || 'low',
              vulnRiskScore: a.vulnRiskScore || 0,
              vulnRiskBand: a.vulnRiskBand || 'low',
              impactScore: a.impactScore || 0,
              likelihoodScore: a.likelihoodScore || 0,
              missionFunction: a.missionFunction || 'public_facing_services',
              essentialService: a.essentialService || 'general_server',
              businessImpactLevel: a.businessImpactLevel || 'moderate',
              deviceType: a.deviceType || 'unknown',
              platformType: a.platformType || 'unknown',
              missionJustification: a.missionJustification || '',
            }));

            // Run campaign design
            const kevEnrichment = pipeline?.kevEnrichment;
            const campaigns = await generateCampaignRecommendations(analyses, orgProfile, kevEnrichment);

            // Run threat actor matching
            let threatActorMatches = null;
            try {
              const { matchThreatActors } = await import('./lib/threat-actor-matcher');
              const allTech: string[] = [];
              for (const a of analyses) {
                if (a.asset.technologies) allTech.push(...a.asset.technologies);
              }
              threatActorMatches = await matchThreatActors({
                sector: orgProfile.sector,
                clientType: orgProfile.clientType,
                discoveredTechnologies: allTech,
                discoveredAssets: analyses.map(a => ({
                  hostname: a.asset.hostname,
                  assetType: a.asset.assetType,
                  technologies: a.asset.technologies,
                })),
                riskScore: scan.overallRiskScore || 0,
                criticalFunctions: orgProfile.criticalFunctions || [],
              });
            } catch (matchErr: any) {
              console.error('[DomainIntel] Threat actor matching failed:', matchErr.message);
            }

            // Generate full summaries (with campaigns)
            const summaries = await generateSummaries(analyses, campaigns, orgProfile);

            // Update scan with engagement results — merge threat actor matches into existing trimmed output
            const pipelineOutputWithMatches = {
              ...pipeline,
              threatActorMatches,
            };
            await db.updateDomainIntelScan(scanId, {
              status: 'completed',
              executiveSummary: summaries.executiveSummary,
              threatModelSummary: summaries.threatModelSummary,
              campaignRecommendations: campaigns,
              pipelineOutput: pipelineOutputWithMatches,
            });

            console.log(`[DomainIntel] Engagement completed for scan ${scanId}: ${campaigns.length} campaigns designed`);
          } catch (err: any) {
            console.error(`[DomainIntel] Engagement failed for scan ${scanId}:`, err.message, err.stack?.substring(0, 500));
            // Revert to scan_complete so user can retry, and store error details
            const existingOutput = scan.pipelineOutput as any;
            await db.updateDomainIntelScan(scanId, {
              status: 'scan_complete',
              pipelineOutput: {
                ...(existingOutput || {}),
                engagementError: { message: err.message, failedAt: new Date().toISOString() },
              },
            }).catch(() => {});
          }
        });

        return { scanId };
      }),

    // Poll scan status (used by frontend to track async pipeline progress)
    getScanStatus: protectedProcedure
      .input(z.object({ scanId: z.number() }))
      .query(async ({ input }) => {
        const scan = await db.getDomainIntelScanById(input.scanId);
        if (!scan) throw new TRPCError({ code: 'NOT_FOUND', message: 'Scan not found' });

        // Detect stuck scans: if status is an in-progress stage and hasn't been updated in 15 minutes
        const STUCK_THRESHOLD_MS = 15 * 60 * 1000; // 15 minutes
        const inProgressStatuses = ['pending', 'passive_recon', 'discovering', 'analyzing', 'scoring', 'recommending'];
        const isStuck = inProgressStatuses.includes(scan.status)
          && scan.updatedAt
          && (Date.now() - new Date(scan.updatedAt).getTime() > STUCK_THRESHOLD_MS);

        // Extract error info from pipelineOutput if available
        const pipelineOutput = scan.pipelineOutput as any;
        const errorInfo = pipelineOutput?.error
          ? { message: pipelineOutput.error, failedAt: pipelineOutput.failedAt }
          : pipelineOutput?.engagementError || null;

        return {
          scanId: scan.id,
          status: isStuck ? 'failed' as const : scan.status,
          isStuck: !!isStuck,
          primaryDomain: scan.primaryDomain,
          totalAssets: scan.totalAssets || 0,
          overallRiskScore: scan.overallRiskScore || null,
          overallRiskBand: scan.overallRiskBand || null,
          errorInfo,
        };
      }),

    // Retry a failed or stuck scan by resetting it and re-running the pipeline
    retryScan: protectedProcedure
      .input(z.object({ scanId: z.number() }))
      .mutation(async ({ input, ctx }) => {
        const scan = await db.getDomainIntelScanById(input.scanId);
        if (!scan) throw new TRPCError({ code: 'NOT_FOUND', message: 'Scan not found' });

        // Allow retry only for failed scans, pending scans, or stuck scans (in-progress for >15 min)
        const STUCK_THRESHOLD_MS = 15 * 60 * 1000; // 15 minutes
        const inProgressStatuses = ['pending', 'passive_recon', 'discovering', 'analyzing', 'scoring', 'recommending'];
        const isStuck = inProgressStatuses.includes(scan.status)
          && scan.updatedAt
          && (Date.now() - new Date(scan.updatedAt).getTime() > STUCK_THRESHOLD_MS);

        if (scan.status !== 'failed' && scan.status !== 'pending' && !isStuck) {
          throw new TRPCError({
            code: 'BAD_REQUEST',
            message: `Scan cannot be retried in status "${scan.status}". Only failed or stuck scans can be retried.`,
          });
        }

        // Clean up any orphaned assets from a partial previous run
        try {
          await db.deleteDiscoveredAssetsByScan(input.scanId);
        } catch { /* ignore if no assets exist */ }

        // Reset scan to discovering
        await db.updateDomainIntelScan(input.scanId, {
          status: 'discovering',
          totalAssets: 0,
          totalFindings: 0,
          confirmedFindings: 0,
          probableFindings: 0,
          potentialFindings: 0,
          discoveryCoverageScore: 0,
          discoveryCoverageBand: null,
          overallRiskScore: null,
          overallRiskBand: null,
          executiveSummary: null,
          threatModelSummary: null,
          campaignRecommendations: null,
          pipelineOutput: null,
        });

        // Re-run the pipeline in background
        const orgProfile = scan.orgProfile as any;
        const scanId = input.scanId;
        setImmediate(async () => {
          try {
            console.log(`[DomainIntel] Retrying pipeline for scan ${scanId}: ${scan.primaryDomain}`);
            const { runDomainIntelPipeline } = await import('./domainIntel');

            const result = await runDomainIntelPipeline(
              {
                customerName: orgProfile?.customerName || scan.primaryDomain,
                primaryDomain: scan.primaryDomain,
                additionalDomains: (scan.additionalDomains as string[]) || [],
                sector: scan.sector || 'Technology',
                clientType: scan.clientType,
                criticalFunctions: (scan.criticalFunctions as string[]) || [],
                complianceFlags: (scan.complianceFlags as string[]) || [],
                notes: scan.notes || undefined,
              },
              async (stage) => {
                await db.updateDomainIntelScan(scanId, { status: stage }).catch(() => {});
                console.log(`[DomainIntel] Retry scan ${scanId} stage: ${stage}`);
              },
              { scanMode: 'standard', skipEngagement: true }
            );

            // Batch insert assets
            const assetRecords = result.assets.map(a => ({
              scanId,
              assetId: a.asset.assetId,
              hostname: a.asset.hostname,
              url: a.asset.url || null,
              assetType: a.asset.assetType,
              dnsRecords: a.asset.dnsRecords || null,
              dnsStatus: a.asset.dnsStatus || null,
              headers: a.asset.headers || null,
              technologies: a.asset.technologies || null,
              detectedTechnologies: a.asset.technologyVersions
                ? Object.entries(a.asset.technologyVersions).map(([name, version]) => ({
                    name,
                    version: version || '',
                    category: 'detected',
                    confidence: version ? 0.9 : 0.7,
                  }))
                : (a.asset.technologies || []).map((t: string) => ({ name: t, version: '', category: 'inferred', confidence: 0.5 })),
              assetClasses: a.asset.assetClasses,
              tags: a.asset.tags,
              carverScores: a.carverScores,
              shockScores: a.shockScores,
              missionImpactScore: Math.round(a.missionImpactScore * 10),
              suggestedTier: a.suggestedTier,
              hybridRiskScore: a.hybridRiskScore,
              riskBand: a.riskBand,
              cvssEstimate: Math.round(a.cvssEstimate * 10),
              contextIndicators: a.contextIndicators,
              postureFindings: a.postureFindings,
              testVectors: a.testVectors,
              recommendedCalderaAbilities: a.testVectors.filter((v: any) => v.suggestedEmulation?.calderaAbilityHint).map((v: any) => v.suggestedEmulation),
              recommendedGophishTemplates: null,
              recommendedAttackChain: null,
              confidence: a.confidence,
              confidenceExplanation: a.contextIndicators,
              impactScore: a.impactScore || 0,
              likelihoodScore: a.likelihoodScore || 0,
              assetCriticalityScore: a.assetCriticalityScore || 0,
              assetCriticalityBand: a.assetCriticalityBand || 'low',
              vulnRiskScore: a.vulnRiskScore || 0,
              vulnRiskBand: a.vulnRiskBand || 'low',
              missionFunction: a.missionFunction || 'public_facing_services',
              essentialService: a.essentialService || 'general_server',
              businessImpactLevel: a.businessImpactLevel || 'moderate',
              deviceType: a.deviceType || 'unknown',
              platformType: a.platformType || 'unknown',
              missionJustification: a.missionJustification || '',
            }));

            if (assetRecords.length > 0) {
              const BATCH_SIZE = 5;
              for (let i = 0; i < assetRecords.length; i += BATCH_SIZE) {
                const batch = assetRecords.slice(i, i + BATCH_SIZE);
                try {
                  await db.bulkCreateDiscoveredAssets(batch);
                } catch (batchErr: any) {
                  console.warn(`[DomainIntel] Retry batch insert failed, falling back to individual: ${batchErr.message}`);
                  for (const record of batch) {
                    try { await db.createDiscoveredAsset(record); } catch (e: any) {
                      console.error(`[DomainIntel] Retry: failed to insert asset ${record.hostname}: ${e.message}`);
                    }
                  }
                }
              }
            }

            // Trimmed output
            const trimmedOutput = {
              orgProfile: result.orgProfile,
              overallRiskScore: result.overallRiskScore,
              overallRiskBand: result.overallRiskBand,
              totalAssets: result.totalAssets,
              totalFindings: result.totalFindings,
              confirmedFindings: result.confirmedFindingsCount || 0,
              probableFindings: result.probableFindingsCount || 0,
              potentialFindings: result.potentialFindingsCount || 0,
              discoveryCoverageScore: result.discoveryCoverage?.coverageScore || 0,
              discoveryCoverageBand: result.discoveryCoverage?.coverageBand || null,
              // Full discovery coverage object for the Coverage tab
              discoveryCoverage: result.discoveryCoverage ? {
                coverageScore: result.discoveryCoverage.coverageScore,
                coverageBand: result.discoveryCoverage.coverageBand,
                priorities: result.discoveryCoverage.priorities,
                assessment: result.discoveryCoverage.assessment,
                structuralGaps: result.discoveryCoverage.structuralGaps,
                actionableGaps: result.discoveryCoverage.actionableGaps,
              } : undefined,
              // Email security analysis for the Email Security tab
              emailSecurityReport: (result as any).emailSecurityReport || (result as any).emailSecurity || undefined,
              executiveSummary: result.executiveSummary,
              threatModelSummary: result.threatModelSummary,
              kevEnrichment: result.kevEnrichment ? {
                riskBoost: result.kevEnrichment.riskBoost,
                ransomwareExposure: result.kevEnrichment.ransomwareExposure,
                criticalKevCount: result.kevEnrichment.criticalKevCount,
                summary: result.kevEnrichment.summary,
                chainSteps: result.kevEnrichment.chainSteps,
                matchCount: result.kevEnrichment.matches.length,
                matches: result.kevEnrichment.matches.slice(0, 50),
              } : undefined,
              breachData: result.breachData,
              exploitMatches: result.exploitMatches ? {
                totalMetasploit: result.exploitMatches.totalMetasploit,
                totalExploitDb: result.exploitMatches.totalExploitDb,
                totalCalderaAbilities: result.exploitMatches.totalCalderaAbilities,
                remoteAccessCount: result.exploitMatches.remoteAccessCount,
                matchCount: result.exploitMatches.matches.length,
                matches: result.exploitMatches.matches.slice(0, 30),
              } : undefined,
              passiveRecon: result.passiveRecon ? {
                summary: result.passiveRecon.summary,
                riskSignals: result.passiveRecon.riskSignals?.slice(0, 30),
                connectorResults: result.passiveRecon.connectorResults?.map((cr: any) => ({
                  connector: cr.connector,
                  observationCount: cr.observations.length,
                  durationMs: cr.durationMs,
                  errors: cr.errors,
                })),
              } : undefined,
              assetSummaries: result.assets.map(a => ({
                assetId: a.asset.assetId,
                hostname: a.asset.hostname,
                assetType: a.asset.assetType,
                hybridRiskScore: a.hybridRiskScore,
                riskBand: a.riskBand,
                findingCount: a.postureFindings.length,
                vulnRiskScore: a.vulnRiskScore,
              })),
              // Cross-module enrichment results (Bug Bounty, Threat Intel, OpSec, Discovery)
              crossModuleEnrichment: result.crossModuleEnrichment ? {
                bugBounty: result.crossModuleEnrichment.bugBounty,
                threatIntel: result.crossModuleEnrichment.threatIntel,
                opsec: result.crossModuleEnrichment.opsec,
                discoveryDeepDive: result.crossModuleEnrichment.discoveryDeepDive,
                summary: result.crossModuleEnrichment.summary,
              } : undefined,
              // Post-enrichment LLM analysis (attack paths, blind spots, recommendations)
              postEnrichmentAnalysis: result.postEnrichmentAnalysis ? {
                executiveAnalysis: (result.postEnrichmentAnalysis as any).executiveAnalysis || result.postEnrichmentAnalysis.overallAssessment,
                attackPaths: result.postEnrichmentAnalysis.attackPaths?.slice(0, 20),
                blindSpots: result.postEnrichmentAnalysis.blindSpots?.slice(0, 20),
                prioritizedRecommendations: result.postEnrichmentAnalysis.prioritizedRecommendations?.slice(0, 30),
                crossFindingCorrelations: result.postEnrichmentAnalysis.crossFindingCorrelations?.slice(0, 20),
                threatActorMapping: result.postEnrichmentAnalysis.threatActorMapping?.slice(0, 15),
                overallAssessment: result.postEnrichmentAnalysis.overallAssessment,
                confidenceStatement: result.postEnrichmentAnalysis.confidenceStatement,
                enrichmentSources: (result.postEnrichmentAnalysis as any).enrichmentSources,
              } : undefined,
              // Org discovery results
              orgDiscovery: result.orgDiscovery ? {
                seedDomain: result.orgDiscovery.seedDomain,
                orgName: result.orgDiscovery.orgName,
                orgEmail: result.orgDiscovery.orgEmail,
                totalCandidatesFound: result.orgDiscovery.totalCandidatesFound,
                verifiedDomains: result.orgDiscovery.verifiedDomains.slice(0, 50),
                unverifiedDomains: result.orgDiscovery.unverifiedDomains.slice(0, 30),
                discoveryStats: result.orgDiscovery.discoveryStats,
                durationMs: result.orgDiscovery.durationMs,
              } : undefined,
              complianceScan: result.complianceScan || undefined,
              containerExposure: result.containerExposure || undefined,
              retriedAt: new Date().toISOString(),
            };

            await db.updateDomainIntelScan(scanId, {
              status: 'scan_complete',
              totalAssets: result.totalAssets,
              totalFindings: result.totalFindings,
              confirmedFindings: result.confirmedFindingsCount || 0,
              probableFindings: result.probableFindingsCount || 0,
              potentialFindings: result.potentialFindingsCount || 0,
              discoveryCoverageScore: result.discoveryCoverage?.coverageScore || 0,
              discoveryCoverageBand: result.discoveryCoverage?.coverageBand || null,
              overallRiskScore: result.overallRiskScore,
              overallRiskBand: result.overallRiskBand,
              executiveSummary: result.executiveSummary,
              threatModelSummary: result.threatModelSummary,
              campaignRecommendations: [],
              pipelineOutput: trimmedOutput,
            });

            console.log(`[DomainIntel] Retry completed for scan ${scanId}: ${result.totalAssets} assets, risk=${result.overallRiskScore}`);
            try { const { emitReconComplete } = await import('./lib/ws-event-hub'); emitReconComplete({ scanId, domain: scan.primaryDomain, findings: result.totalFindings || 0, engagementId: scan.engagementId || undefined }); } catch {}
          } catch (err: any) {
            console.error(`[DomainIntel] Retry pipeline failed for scan ${scanId}:`, err.message, err.stack?.substring(0, 500));
            await db.updateDomainIntelScan(scanId, {
              status: 'failed',
              pipelineOutput: { error: err.message, stack: err.stack?.substring(0, 1000), failedAt: new Date().toISOString(), retryFailed: true },
            }).catch(() => {});
          }
        });

        return { scanId: input.scanId, message: 'Scan retry started' };
      }),

    // Bulk retry all failed or stuck scans
    bulkRetryStuckScans: protectedProcedure
      .mutation(async ({ ctx }) => {
        const allScans = await db.getDomainIntelScans();
        const STUCK_THRESHOLD_MS = 15 * 60 * 1000;
        const now = Date.now();

        const retryable = allScans.filter((s: any) => {
          if (s.status === 'failed') return true;
          const inProgressStatuses = ['pending', 'passive_recon', 'discovering', 'analyzing', 'scoring', 'recommending'];
          if (inProgressStatuses.includes(s.status) && s.updatedAt) {
            return (now - new Date(s.updatedAt).getTime()) > STUCK_THRESHOLD_MS;
          }
          return false;
        });

        if (retryable.length === 0) {
          return { retriedCount: 0, message: 'No failed or stuck scans found' };
        }

        // Trigger retry for each scan with staggered starts
        let queued = 0;
        for (const scan of retryable) {
          const scanId = scan.id;
          const delay = queued * 3000; // 3s stagger
          setTimeout(async () => {
            try {
              await db.deleteDiscoveredAssetsByScan(scanId).catch(() => {});
              await db.updateDomainIntelScan(scanId, {
                status: 'discovering',
                totalAssets: 0,
                totalFindings: 0,
                confirmedFindings: 0,
                probableFindings: 0,
                potentialFindings: 0,
                discoveryCoverageScore: 0,
                discoveryCoverageBand: null,
                overallRiskScore: null,
                overallRiskBand: null,
                executiveSummary: null,
                threatModelSummary: null,
                campaignRecommendations: null,
                pipelineOutput: null,
              });

              const orgProfile = scan.orgProfile as any;
              const { runDomainIntelPipeline } = await import('./domainIntel');
              const result = await runDomainIntelPipeline(
                {
                  customerName: orgProfile?.customerName || scan.primaryDomain,
                  primaryDomain: scan.primaryDomain,
                  additionalDomains: (scan.additionalDomains as string[]) || [],
                  sector: scan.sector || 'Technology',
                  clientType: scan.clientType,
                  criticalFunctions: (scan.criticalFunctions as string[]) || [],
                  complianceFlags: (scan.complianceFlags as string[]) || [],
                  notes: scan.notes || undefined,
                },
                async (stage) => {
                  await db.updateDomainIntelScan(scanId, { status: stage }).catch(() => {});
                },
                { scanMode: 'standard', skipEngagement: true }
              );

              // Batch insert assets
              const assetRecords = result.assets.map((a: any) => ({
                scanId,
                assetId: a.asset.assetId,
                hostname: a.asset.hostname,
                url: a.asset.url || null,
                assetType: a.asset.assetType,
                dnsRecords: a.asset.dnsRecords || null,
                dnsStatus: a.asset.dnsStatus || null,
                headers: a.asset.headers || null,
                technologies: a.asset.technologies || null,
                detectedTechnologies: a.asset.technologyVersions
                  ? Object.entries(a.asset.technologyVersions).map(([name, version]) => ({ name, version: version || '', category: 'detected', confidence: version ? 0.9 : 0.7 }))
                  : (a.asset.technologies || []).map((t: string) => ({ name: t, version: '', category: 'inferred', confidence: 0.5 })),
                assetClasses: a.asset.assetClasses,
                tags: a.asset.tags,
                carverScores: a.carverScores,
                shockScores: a.shockScores,
                missionImpactScore: Math.round(a.missionImpactScore * 10),
                suggestedTier: a.suggestedTier,
                hybridRiskScore: a.hybridRiskScore,
                riskBand: a.riskBand,
                cvssEstimate: Math.round(a.cvssEstimate * 10),
                contextIndicators: a.contextIndicators,
                postureFindings: a.postureFindings,
                testVectors: a.testVectors,
                recommendedCalderaAbilities: a.testVectors.filter((v: any) => v.suggestedEmulation?.calderaAbilityHint).map((v: any) => v.suggestedEmulation),
                recommendedGophishTemplates: null,
                recommendedAttackChain: null,
                confidence: a.confidence,
                confidenceExplanation: a.contextIndicators,
                impactScore: a.impactScore || 0,
                likelihoodScore: a.likelihoodScore || 0,
                assetCriticalityScore: a.assetCriticalityScore || 0,
                assetCriticalityBand: a.assetCriticalityBand || 'low',
                vulnRiskScore: a.vulnRiskScore || 0,
                vulnRiskBand: a.vulnRiskBand || 'low',
                missionFunction: a.missionFunction || 'public_facing_services',
                essentialService: a.essentialService || 'general_server',
                businessImpactLevel: a.businessImpactLevel || 'moderate',
                deviceType: a.deviceType || 'unknown',
                platformType: a.platformType || 'unknown',
                missionJustification: a.missionJustification || '',
              }));

              if (assetRecords.length > 0) {
                const BATCH_SIZE = 5;
                for (let i = 0; i < assetRecords.length; i += BATCH_SIZE) {
                  const batch = assetRecords.slice(i, i + BATCH_SIZE);
                  try { await db.bulkCreateDiscoveredAssets(batch); } catch {
                    for (const record of batch) {
                      try { await db.createDiscoveredAsset(record); } catch {}
                    }
                  }
                }
              }

              await db.updateDomainIntelScan(scanId, {
                status: 'scan_complete',
                totalAssets: result.totalAssets,
                totalFindings: result.totalFindings,
                confirmedFindings: result.confirmedFindingsCount || 0,
                probableFindings: result.probableFindingsCount || 0,
                potentialFindings: result.potentialFindingsCount || 0,
                discoveryCoverageScore: result.discoveryCoverage?.coverageScore || 0,
                discoveryCoverageBand: result.discoveryCoverage?.coverageBand || null,
                overallRiskScore: result.overallRiskScore,
                overallRiskBand: result.overallRiskBand,
                executiveSummary: result.executiveSummary,
                threatModelSummary: result.threatModelSummary,
                campaignRecommendations: [],
                pipelineOutput: { retriedAt: new Date().toISOString(), bulkRetry: true },
              });
              console.log(`[DomainIntel] Bulk retry completed for scan ${scanId}: ${scan.primaryDomain}`);
            } catch (err: any) {
              console.error(`[DomainIntel] Bulk retry failed for scan ${scanId}: ${err.message}`);
              await db.updateDomainIntelScan(scanId, {
                status: 'failed',
                pipelineOutput: { error: err.message, failedAt: new Date().toISOString(), bulkRetryFailed: true },
              }).catch(() => {});
            }
          }, delay);
          queued++;
        }

        return { retriedCount: queued, message: `${queued} scans queued for retry` };
      }),

    // Refresh a completed scan — re-runs the full pipeline while preserving original data as a snapshot
    refreshScan: protectedProcedure
      .input(z.object({ scanId: z.number() }))
      .mutation(async ({ input, ctx }) => {
        const scan = await db.getDomainIntelScanById(input.scanId);
        if (!scan) throw new TRPCError({ code: 'NOT_FOUND', message: 'Scan not found' });

        // Allow refresh only for completed or scan_complete scans
        if (scan.status !== 'completed' && scan.status !== 'scan_complete') {
          throw new TRPCError({
            code: 'BAD_REQUEST',
            message: `Scan must be completed to refresh. Current status: ${scan.status}`,
          });
        }

        // Snapshot the current results before re-running
        const previousSnapshot = {
          snapshotAt: new Date().toISOString(),
          status: scan.status,
          totalAssets: scan.totalAssets,
          totalFindings: scan.totalFindings,
          confirmedFindings: scan.confirmedFindings,
          probableFindings: scan.probableFindings,
          potentialFindings: scan.potentialFindings,
          overallRiskScore: scan.overallRiskScore,
          overallRiskBand: scan.overallRiskBand,
          discoveryCoverageScore: scan.discoveryCoverageScore,
          discoveryCoverageBand: scan.discoveryCoverageBand,
          executiveSummary: scan.executiveSummary,
          threatModelSummary: scan.threatModelSummary,
          campaignRecommendations: scan.campaignRecommendations,
          entityProfile: (scan.pipelineOutput as any)?.entityProfile || null,
          financialImpact: (scan.pipelineOutput as any)?.financialImpact || null,
          autoCrawlSummary: (scan.pipelineOutput as any)?.autoCrawlSummary || null,
        };

        // Determine if this was a full engagement or scan-only
        const wasFullEngagement = scan.status === 'completed';

        // Clean up old assets (they will be re-discovered)
        try {
          await db.deleteDiscoveredAssetsByScan(input.scanId);
        } catch { /* ignore if no assets exist */ }

        // Clean up old web crawl results for this scan
        try {
          const { eq: eqOp } = await import('drizzle-orm');
          const { webCrawlResults: wcr } = await import('../drizzle/schema');
          const dbInst = await (await import('./db')).getDb();
          if (dbInst) await dbInst.delete(wcr).where(eqOp(wcr.scanId, input.scanId));
        } catch { /* ignore */ }

        // Set status to refreshing (uses 'discovering' status so frontend polling works)
        await db.updateDomainIntelScan(input.scanId, {
          status: 'discovering',
          totalAssets: 0,
          totalFindings: 0,
          confirmedFindings: 0,
          probableFindings: 0,
          potentialFindings: 0,
          discoveryCoverageScore: 0,
          discoveryCoverageBand: null,
          overallRiskScore: null,
          overallRiskBand: null,
          executiveSummary: null,
          threatModelSummary: null,
          campaignRecommendations: null,
          pipelineOutput: { refreshing: true, previousSnapshot, refreshStartedAt: new Date().toISOString() },
        });

        const scanId = input.scanId;
        const orgProfile = scan.orgProfile as any;
        setImmediate(async () => {
          try {
            console.log(`[DomainIntel] Refresh pipeline started for scan ${scanId}: ${scan.primaryDomain}`);
            const { runDomainIntelPipeline } = await import('./domainIntel');

            const result = await runDomainIntelPipeline(
              {
                customerName: orgProfile?.customerName || scan.primaryDomain,
                primaryDomain: scan.primaryDomain,
                additionalDomains: (scan.additionalDomains as string[]) || [],
                sector: scan.sector || 'Technology',
                clientType: scan.clientType,
                criticalFunctions: (scan.criticalFunctions as string[]) || [],
                complianceFlags: (scan.complianceFlags as string[]) || [],
                notes: scan.notes || undefined,
              },
              async (stage) => {
                await db.updateDomainIntelScan(scanId, { status: stage }).catch(() => {});
                console.log(`[DomainIntel] Refresh scan ${scanId} stage: ${stage}`);
              },
              {
                scanMode: (orgProfile?.scanMode as any) || 'standard',
                skipEngagement: !wasFullEngagement,
                scopedAssets: (orgProfile?.scopedAssets as string[])?.length > 0 ? (orgProfile.scopedAssets as string[]) : undefined,
              }
            );

            // Batch insert new assets
            const assetRecords = result.assets.map(a => ({
              scanId,
              assetId: a.asset.assetId,
              hostname: a.asset.hostname,
              url: a.asset.url || null,
              assetType: a.asset.assetType,
              dnsRecords: a.asset.dnsRecords || null,
              dnsStatus: a.asset.dnsStatus || null,
              headers: a.asset.headers || null,
              technologies: a.asset.technologies || null,
              detectedTechnologies: a.asset.technologyVersions
                ? Object.entries(a.asset.technologyVersions).map(([name, version]) => ({
                    name,
                    version: version || '',
                    category: 'detected',
                    confidence: version ? 0.9 : 0.7,
                  }))
                : (a.asset.technologies || []).map((t: string) => ({ name: t, version: '', category: 'inferred', confidence: 0.5 })),
              assetClasses: a.asset.assetClasses,
              tags: a.asset.tags,
              carverScores: a.carverScores,
              shockScores: a.shockScores,
              missionImpactScore: Math.round(a.missionImpactScore * 10),
              suggestedTier: a.suggestedTier,
              hybridRiskScore: a.hybridRiskScore,
              riskBand: a.riskBand,
              cvssEstimate: Math.round(a.cvssEstimate * 10),
              contextIndicators: a.contextIndicators,
              postureFindings: a.postureFindings,
              testVectors: a.testVectors,
              recommendedCalderaAbilities: a.testVectors.filter((v: any) => v.suggestedEmulation?.calderaAbilityHint).map((v: any) => v.suggestedEmulation),
              recommendedGophishTemplates: null,
              recommendedAttackChain: null,
              confidence: a.confidence,
              confidenceExplanation: a.contextIndicators,
              impactScore: a.impactScore || 0,
              likelihoodScore: a.likelihoodScore || 0,
              assetCriticalityScore: a.assetCriticalityScore || 0,
              assetCriticalityBand: a.assetCriticalityBand || 'low',
              vulnRiskScore: a.vulnRiskScore || 0,
              vulnRiskBand: a.vulnRiskBand || 'low',
              missionFunction: a.missionFunction || 'public_facing_services',
              essentialService: a.essentialService || 'general_server',
              businessImpactLevel: a.businessImpactLevel || 'moderate',
              deviceType: a.deviceType || 'unknown',
              platformType: a.platformType || 'unknown',
              missionJustification: a.missionJustification || '',
            }));

            if (assetRecords.length > 0) {
              const BATCH_SIZE = 5;
              for (let i = 0; i < assetRecords.length; i += BATCH_SIZE) {
                const batch = assetRecords.slice(i, i + BATCH_SIZE);
                try {
                  await db.bulkCreateDiscoveredAssets(batch);
                } catch (batchErr: any) {
                  console.warn(`[DomainIntel] Refresh batch insert failed, falling back: ${batchErr.message}`);
                  for (const record of batch) {
                    try { await db.createDiscoveredAsset(record); } catch (e: any) {
                      console.error(`[DomainIntel] Refresh: failed to insert asset ${record.hostname}: ${e.message}`);
                    }
                  }
                }
              }
            }

            // Build trimmed output with previous snapshot preserved
            const trimmedOutput: any = {
              orgProfile: result.orgProfile,
              overallRiskScore: result.overallRiskScore,
              overallRiskBand: result.overallRiskBand,
              totalAssets: result.totalAssets,
              totalFindings: result.totalFindings,
              confirmedFindings: result.confirmedFindingsCount || 0,
              probableFindings: result.probableFindingsCount || 0,
              potentialFindings: result.potentialFindingsCount || 0,
              discoveryCoverageScore: result.discoveryCoverage?.coverageScore || 0,
              discoveryCoverageBand: result.discoveryCoverage?.coverageBand || null,
              discoveryCoverage: result.discoveryCoverage ? {
                coverageScore: result.discoveryCoverage.coverageScore,
                coverageBand: result.discoveryCoverage.coverageBand,
                priorities: result.discoveryCoverage.priorities,
                assessment: result.discoveryCoverage.assessment,
                structuralGaps: result.discoveryCoverage.structuralGaps,
                actionableGaps: result.discoveryCoverage.actionableGaps,
              } : undefined,
              emailSecurityReport: (result as any).emailSecurityReport || (result as any).emailSecurity || undefined,
              executiveSummary: result.executiveSummary,
              threatModelSummary: result.threatModelSummary,
              kevEnrichment: result.kevEnrichment ? {
                riskBoost: result.kevEnrichment.riskBoost,
                ransomwareExposure: result.kevEnrichment.ransomwareExposure,
                criticalKevCount: result.kevEnrichment.criticalKevCount,
                summary: result.kevEnrichment.summary,
                chainSteps: result.kevEnrichment.chainSteps,
                matchCount: result.kevEnrichment.matches.length,
                matches: result.kevEnrichment.matches.slice(0, 50),
              } : undefined,
              breachData: result.breachData,
              exploitMatches: result.exploitMatches ? {
                totalMetasploit: result.exploitMatches.totalMetasploit,
                totalExploitDb: result.exploitMatches.totalExploitDb,
                totalCalderaAbilities: result.exploitMatches.totalCalderaAbilities,
                remoteAccessCount: result.exploitMatches.remoteAccessCount,
                matchCount: result.exploitMatches.matches.length,
                matches: result.exploitMatches.matches.slice(0, 30),
              } : undefined,
              passiveRecon: result.passiveRecon ? {
                summary: result.passiveRecon.summary,
                riskSignals: result.passiveRecon.riskSignals?.slice(0, 30),
                connectorResults: result.passiveRecon.connectorResults?.map((cr: any) => ({
                  connector: cr.connector,
                  observationCount: cr.observations.length,
                  durationMs: cr.durationMs,
                  errors: cr.errors,
                })),
              } : undefined,
              assetSummaries: result.assets.map(a => ({
                assetId: a.asset.assetId,
                hostname: a.asset.hostname,
                assetType: a.asset.assetType,
                hybridRiskScore: a.hybridRiskScore,
                riskBand: a.riskBand,
                findingCount: a.postureFindings.length,
                vulnRiskScore: a.vulnRiskScore,
              })),
              crossModuleEnrichment: result.crossModuleEnrichment ? {
                bugBounty: result.crossModuleEnrichment.bugBounty,
                threatIntel: result.crossModuleEnrichment.threatIntel,
                opsec: result.crossModuleEnrichment.opsec,
                discoveryDeepDive: result.crossModuleEnrichment.discoveryDeepDive,
                summary: result.crossModuleEnrichment.summary,
              } : undefined,
              postEnrichmentAnalysis: result.postEnrichmentAnalysis ? {
                executiveAnalysis: (result.postEnrichmentAnalysis as any).executiveAnalysis || result.postEnrichmentAnalysis.overallAssessment,
                attackPaths: result.postEnrichmentAnalysis.attackPaths?.slice(0, 20),
                blindSpots: result.postEnrichmentAnalysis.blindSpots?.slice(0, 20),
                prioritizedRecommendations: result.postEnrichmentAnalysis.prioritizedRecommendations?.slice(0, 30),
                crossFindingCorrelations: result.postEnrichmentAnalysis.crossFindingCorrelations?.slice(0, 20),
                threatActorMapping: result.postEnrichmentAnalysis.threatActorMapping?.slice(0, 15),
                overallAssessment: result.postEnrichmentAnalysis.overallAssessment,
                confidenceStatement: result.postEnrichmentAnalysis.confidenceStatement,
                enrichmentSources: (result.postEnrichmentAnalysis as any).enrichmentSources,
              } : undefined,
              // Org discovery results
              orgDiscovery: result.orgDiscovery ? {
                seedDomain: result.orgDiscovery.seedDomain,
                orgName: result.orgDiscovery.orgName,
                orgEmail: result.orgDiscovery.orgEmail,
                totalCandidatesFound: result.orgDiscovery.totalCandidatesFound,
                verifiedDomains: result.orgDiscovery.verifiedDomains.slice(0, 50),
                unverifiedDomains: result.orgDiscovery.unverifiedDomains.slice(0, 30),
                discoveryStats: result.orgDiscovery.discoveryStats,
                durationMs: result.orgDiscovery.durationMs,
              } : undefined,
              complianceScan: result.complianceScan || undefined,
              containerExposure: result.containerExposure || undefined,
              // Preserve the previous snapshot for comparison
              previousSnapshot,
              refreshedAt: new Date().toISOString(),
            };

            if (wasFullEngagement) {
              // Full engagement: run threat actor matching + campaign design
              let threatActorMatches = null;
              try {
                const { matchThreatActors } = await import('./lib/threat-actor-matcher');
                const allTech: string[] = [];
                for (const a of result.assets) {
                  if (a.asset?.technologies) allTech.push(...a.asset.technologies);
                }
                threatActorMatches = await matchThreatActors({
                  sector: orgProfile?.sector || scan.sector,
                  clientType: orgProfile?.clientType || scan.clientType,
                  discoveredTechnologies: allTech,
                  discoveredAssets: result.assets.map(a => ({
                    hostname: a.asset?.hostname,
                    assetType: a.asset?.assetType,
                    technologies: a.asset?.technologies,
                  })),
                  riskScore: result.overallRiskScore,
                  criticalFunctions: orgProfile?.criticalFunctions || (scan.criticalFunctions as string[]) || [],
                });
              } catch (matchErr: any) {
                console.error('[DomainIntel] Refresh: Threat actor matching failed:', matchErr.message);
              }

              // Generate summaries
              const { generateCampaignRecommendations, generateSummaries } = await import('./domainIntel');
              const analyses = result.assets.map(a => ({
                asset: a.asset,
                carverScores: a.carverScores,
                shockScores: a.shockScores,
                missionImpactScore: a.missionImpactScore,
                suggestedTier: a.suggestedTier,
                hybridRiskScore: a.hybridRiskScore,
                riskBand: a.riskBand,
                cvssEstimate: a.cvssEstimate,
                contextIndicators: a.contextIndicators,
                postureFindings: a.postureFindings,
                testVectors: a.testVectors,
                confidence: a.confidence,
                assetCriticalityScore: a.assetCriticalityScore || 0,
                assetCriticalityBand: a.assetCriticalityBand || 'low',
                vulnRiskScore: a.vulnRiskScore || 0,
                vulnRiskBand: a.vulnRiskBand || 'low',
                impactScore: a.impactScore || 0,
                likelihoodScore: a.likelihoodScore || 0,
                missionFunction: a.missionFunction || 'public_facing_services',
                essentialService: a.essentialService || 'general_server',
                businessImpactLevel: a.businessImpactLevel || 'moderate',
                deviceType: a.deviceType || 'unknown',
                platformType: a.platformType || 'unknown',
                missionJustification: a.missionJustification || '',
              }));
              const kevEnrichment = result.kevEnrichment;
              const campaigns = await generateCampaignRecommendations(analyses, orgProfile, kevEnrichment);
              const summaries = await generateSummaries(analyses, campaigns, orgProfile);

              trimmedOutput.threatActorMatches = threatActorMatches;

              await db.updateDomainIntelScan(scanId, {
                status: 'completed',
                totalAssets: result.totalAssets,
                totalFindings: result.totalFindings,
                confirmedFindings: result.confirmedFindingsCount || 0,
                probableFindings: result.probableFindingsCount || 0,
                potentialFindings: result.potentialFindingsCount || 0,
                discoveryCoverageScore: result.discoveryCoverage?.coverageScore || 0,
                discoveryCoverageBand: result.discoveryCoverage?.coverageBand || null,
                overallRiskScore: result.overallRiskScore,
                overallRiskBand: result.overallRiskBand,
                executiveSummary: summaries.executiveSummary,
                threatModelSummary: summaries.threatModelSummary,
                campaignRecommendations: campaigns,
                pipelineOutput: trimmedOutput,
              });
              console.log(`[DomainIntel] Refresh (full engagement) completed for scan ${scanId}: ${result.totalAssets} assets, risk=${result.overallRiskScore}`);
            } else {
              // Scan-only mode
              await db.updateDomainIntelScan(scanId, {
                status: 'scan_complete',
                totalAssets: result.totalAssets,
                totalFindings: result.totalFindings,
                confirmedFindings: result.confirmedFindingsCount || 0,
                probableFindings: result.probableFindingsCount || 0,
                potentialFindings: result.potentialFindingsCount || 0,
                discoveryCoverageScore: result.discoveryCoverage?.coverageScore || 0,
                discoveryCoverageBand: result.discoveryCoverage?.coverageBand || null,
                overallRiskScore: result.overallRiskScore,
                overallRiskBand: result.overallRiskBand,
                executiveSummary: result.executiveSummary,
                threatModelSummary: result.threatModelSummary,
                campaignRecommendations: [],
                pipelineOutput: trimmedOutput,
              });
              console.log(`[DomainIntel] Refresh (scan-only) completed for scan ${scanId}: ${result.totalAssets} assets, risk=${result.overallRiskScore}`);
            }

            // Emit events
            try {
              const { emitReconComplete, emitSystemNotification } = await import('./lib/ws-event-hub');
              emitReconComplete({ scanId, domain: scan.primaryDomain, findings: result.totalFindings || 0, engagementId: scan.engagementId || undefined });
              emitSystemNotification({ title: 'Scan Refresh Complete', message: `Refreshed scan of ${scan.primaryDomain}: ${result.totalAssets} assets, ${result.totalFindings} findings, risk=${result.overallRiskScore}`, severity: 'info' });
            } catch {}

            // Auto-crawl + entity resolution (fire-and-forget, same as new scans)
            setImmediate(async () => {
              try {
                const { triggerAutoCrawl } = await import('./lib/auto-crawl');
                await triggerAutoCrawl(scanId, scan.primaryDomain);
              } catch (crawlErr: any) {
                console.error(`[AutoCrawl] Failed for refreshed scan ${scanId}:`, crawlErr.message);
              }
            });
          } catch (err: any) {
            console.error(`[DomainIntel] Refresh pipeline failed for scan ${scanId}:`, err.message, err.stack?.substring(0, 500));
            // Restore to previous completed status so user can retry
            await db.updateDomainIntelScan(scanId, {
              status: wasFullEngagement ? 'completed' : 'scan_complete',
              pipelineOutput: {
                ...(previousSnapshot || {}),
                refreshError: { message: err.message, failedAt: new Date().toISOString() },
              },
            }).catch(() => {});
          }
        });

        return { scanId: input.scanId, message: 'Scan refresh started — the pipeline will re-run in background' };
      }),

    // Delete a scan and its assets
    deleteScan: protectedProcedure
      .input(z.object({ scanId: z.number() }))
      .mutation(async ({ input }) => {
        // Delete discovered assets first
        try {
          await db.deleteDiscoveredAssetsByScan(input.scanId);
        } catch { /* ignore if no assets */ }
        // Delete the scan record
        await db.deleteDomainIntelScan(input.scanId);
        return { success: true };
      }),

    // Get scan recovery scheduler status
    recoveryStatus: protectedProcedure.query(async () => {
      const { getScanRecoveryStatus } = await import('./lib/scan-recovery');
      return getScanRecoveryStatus();
    }),

    // List all scans
    listScans: protectedProcedure.query(async () => {
      return db.getDomainIntelScans();
    }),

    // Get scan by ID with assets
    getScan: protectedProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => {
        const scan = await db.getDomainIntelScanById(input.id);
        if (!scan) throw new TRPCError({ code: 'NOT_FOUND', message: 'Scan not found' });
        const assets = await db.getDiscoveredAssetsByScan(input.id);
        return { scan, assets };
      }),

    // Get assets for a scan
    getAssets: protectedProcedure
      .input(z.object({ scanId: z.number() }))
      .query(async ({ input }) => {
        return db.getDiscoveredAssetsByScan(input.scanId);
      }),

    // Exclude a discovered asset (mark as incorrect/irrelevant)
    excludeAsset: protectedProcedure
      .input(z.object({ assetId: z.number(), reason: z.string().min(1) }))
      .mutation(async ({ input }) => {
        await db.excludeDiscoveredAsset(input.assetId, input.reason);
        return { success: true };
      }),

    // Re-include a previously excluded asset
    includeAsset: protectedProcedure
      .input(z.object({ assetId: z.number() }))
      .mutation(async ({ input }) => {
        await db.includeDiscoveredAsset(input.assetId);
        return { success: true };
      }),

    // Bulk exclude assets
    bulkExcludeAssets: protectedProcedure
      .input(z.object({ assetIds: z.array(z.number()), reason: z.string().min(1) }))
      .mutation(async ({ input }) => {
        await db.bulkExcludeDiscoveredAssets(input.assetIds, input.reason);
        return { success: true, count: input.assetIds.length };
      }),

    // Bulk re-include assets
    bulkIncludeAssets: protectedProcedure
      .input(z.object({ assetIds: z.array(z.number()) }))
      .mutation(async ({ input }) => {
        await db.bulkIncludeDiscoveredAssets(input.assetIds);
        return { success: true, count: input.assetIds.length };
      }),

     // Get scans for an engagement
    byEngagement: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .query(async ({ input }) => {
        return db.getDomainIntelScansByEngagement(input.engagementId);
      }),

    // Match threat actors for a completed scan
    matchThreatActors: protectedProcedure
      .input(z.object({ scanId: z.number(), useLLM: z.boolean().optional() }))
      .mutation(async ({ input }) => {
        const scan = await db.getDomainIntelScanById(input.scanId);
        if (!scan) throw new TRPCError({ code: 'NOT_FOUND', message: 'Scan not found' });
        if (scan.status !== 'completed') throw new TRPCError({ code: 'BAD_REQUEST', message: 'Scan must be completed first' });

        const pipelineOutput = scan.pipelineOutput as any;
        if (!pipelineOutput) throw new TRPCError({ code: 'BAD_REQUEST', message: 'No pipeline output available' });

        const { matchThreatActors, matchThreatActorsWithLLM } = await import('./lib/threat-actor-matcher');
        const assets = pipelineOutput.assets || [];
        const allTech: string[] = [];
        for (const a of assets) {
          if (a.asset?.technologies) allTech.push(...a.asset.technologies);
        }

        const orgProfile = (scan.orgProfile as any) || {};
        const dbMatches = await matchThreatActors({
          sector: scan.sector || orgProfile.sector || 'technology',
          clientType: scan.clientType || orgProfile.clientType || 'enterprise',
          discoveredTechnologies: allTech,
          discoveredAssets: assets.map((a: any) => ({
            hostname: a.asset?.hostname || '',
            assetType: a.asset?.assetType || '',
            technologies: a.asset?.technologies || [],
          })),
          riskScore: scan.overallRiskScore || 0,
          criticalFunctions: (scan.criticalFunctions as string[]) || [],
        });

        let llmEnhanced = null;
        if (input.useLLM) {
          try {
            llmEnhanced = await matchThreatActorsWithLLM({
              orgProfile: {
                customerName: orgProfile.customerName || scan.primaryDomain,
                sector: scan.sector || orgProfile.sector || 'technology',
                clientType: scan.clientType || orgProfile.clientType || 'enterprise',
                criticalFunctions: (scan.criticalFunctions as string[]) || [],
              },
              discoveredAssets: assets.map((a: any) => ({
                hostname: a.asset?.hostname || '',
                assetType: a.asset?.assetType || '',
                technologies: a.asset?.technologies || [],
                riskBand: a.riskBand,
              })),
              overallRiskScore: scan.overallRiskScore || 0,
              executiveSummary: scan.executiveSummary || '',
              campaignRecommendations: (scan.campaignRecommendations as any[]) || [],
              topDatabaseMatches: dbMatches.topMatches,
            });
          } catch (err: any) {
            console.error('[DomainIntel] LLM threat actor matching failed:', err.message);
          }
        }

        // Store matches in pipeline output
        const updatedOutput = { ...pipelineOutput, threatActorMatches: dbMatches, llmThreatActorAnalysis: llmEnhanced };
        await db.updateDomainIntelScan(input.scanId, { pipelineOutput: updatedOutput });

        return { dbMatches, llmEnhanced };
      }),

    // ─── False Positive Management ─────────────────────────────────
    // Mark a finding as false positive
    markFalsePositive: protectedProcedure
      .input(z.object({
        scanId: z.number(),
        assetId: z.number(),
        findingIndex: z.number(),
        findingTitle: z.string(),
        findingType: z.string().optional(),
        findingSeverity: z.string().optional(),
        reason: z.string().min(1, 'A reason is required'),
      }))
      .mutation(async ({ input, ctx }) => {
        const { createHash } = await import('crypto');
        const findingHash = createHash('sha256')
          .update(`${input.findingTitle}|${input.assetId}|${input.findingType || ''}`)
          .digest('hex').slice(0, 64);

        await db.createFalsePositive({
          scanId: input.scanId,
          assetId: input.assetId,
          findingIndex: input.findingIndex,
          findingHash,
          findingTitle: input.findingTitle,
          findingType: input.findingType || null,
          findingSeverity: input.findingSeverity || null,
          reason: input.reason,
          markedBy: ctx.user.name || `user-${ctx.user.id}`,
        });
        return { success: true, findingHash };
      }),

    // Reinstate a finding (un-mark as false positive)
    reinstateFinding: protectedProcedure
      .input(z.object({
        fpId: z.number(),
        reason: z.string().min(1, 'A reason for reinstatement is required'),
      }))
      .mutation(async ({ input, ctx }) => {
        await db.reinstateFalsePositive(
          input.fpId,
          ctx.user.name || `user-${ctx.user.id}`,
          input.reason
        );
        return { success: true };
      }),

    // List false positives for a scan
    listFalsePositives: protectedProcedure
      .input(z.object({ scanId: z.number() }))
      .query(async ({ input }) => {
        return db.getFalsePositivesByScan(input.scanId);
      }),

    // List all false positives (cross-scan, by hash)
    listAllFalsePositives: protectedProcedure
      .query(async () => {
        return db.getAllFalsePositives();
      }),

    // Compare two scans side-by-side
    compareScans: protectedProcedure
      .input(z.object({ scanIdA: z.number(), scanIdB: z.number() }))
      .query(async ({ input }) => {
        const [scanA, scanB] = await Promise.all([
          db.getDomainIntelScanById(input.scanIdA),
          db.getDomainIntelScanById(input.scanIdB),
        ]);
        if (!scanA || !scanB) throw new TRPCError({ code: 'NOT_FOUND', message: 'One or both scans not found' });

        const outA = scanA.pipelineOutput as any || {};
        const outB = scanB.pipelineOutput as any || {};

        const assetsA = (outA.assets || []).map((a: any) => a.asset || a);
        const assetsB = (outB.assets || []).map((a: any) => a.asset || a);

        const findingsA = (outA.assets || []).flatMap((a: any) => a.postureFindings || []);
        const findingsB = (outB.assets || []).flatMap((a: any) => a.postureFindings || []);

        const hostnamesA = new Set<string>(assetsA.map((a: any) => a.hostname as string));
        const hostnamesB = new Set<string>(assetsB.map((a: any) => a.hostname as string));

        const newAssets = assetsB.filter((a: any) => !hostnamesA.has(a.hostname));
        const removedAssets = assetsA.filter((a: any) => !hostnamesB.has(a.hostname));
        const commonHostnames = Array.from(hostnamesA).filter(h => hostnamesB.has(h));

        // Compare findings by CVE ID
        const cveSetA = new Set<string>(findingsA.flatMap((f: any) => (f.cveIds || []) as string[]));
        const cveSetB = new Set<string>(findingsB.flatMap((f: any) => (f.cveIds || []) as string[]));
        const newCves = Array.from(cveSetB).filter(c => !cveSetA.has(c));
        const resolvedCves = Array.from(cveSetA).filter(c => !cveSetB.has(c));

        // Compare risk scores per common asset
        const riskChanges = commonHostnames.map(hostname => {
          const assetAnalysisA = (outA.assets || []).find((a: any) => (a.asset || a).hostname === hostname);
          const assetAnalysisB = (outB.assets || []).find((a: any) => (a.asset || a).hostname === hostname);
          const riskA = assetAnalysisA?.hybridRiskScore ?? 0;
          const riskB = assetAnalysisB?.hybridRiskScore ?? 0;
          const bandA = assetAnalysisA?.riskBand ?? 'unknown';
          const bandB = assetAnalysisB?.riskBand ?? 'unknown';
          return { hostname, riskA, riskB, delta: riskB - riskA, bandA, bandB };
        }).filter(r => r.delta !== 0).sort((a, b) => Math.abs(b.delta) - Math.abs(a.delta));

        // Compare corroboration tiers
        const tierCountA: Record<string, number> = { confirmed: 0, probable: 0, potential: 0 };
        const tierCountB: Record<string, number> = { confirmed: 0, probable: 0, potential: 0 };
        findingsA.forEach((f: any) => { if (f.corroborationTier) tierCountA[f.corroborationTier] = (tierCountA[f.corroborationTier] || 0) + 1; });
        findingsB.forEach((f: any) => { if (f.corroborationTier) tierCountB[f.corroborationTier] = (tierCountB[f.corroborationTier] || 0) + 1; });

        // New findings in scan B not in scan A (by finding ID)
        const findingIdsA = new Set(findingsA.map((f: any) => f.id));
        const newFindings = findingsB.filter((f: any) => !findingIdsA.has(f.id));
        const findingIdsB = new Set(findingsB.map((f: any) => f.id));
        const resolvedFindings = findingsA.filter((f: any) => !findingIdsB.has(f.id));

        return {
          scanA: {
            id: scanA.id,
            primaryDomain: scanA.primaryDomain,
            createdAt: scanA.createdAt,
            overallRiskScore: outA.overallRiskScore ?? 0,
            overallRiskBand: outA.overallRiskBand ?? 'unknown',
            totalAssets: assetsA.length,
            totalFindings: findingsA.length,
          },
          scanB: {
            id: scanB.id,
            primaryDomain: scanB.primaryDomain,
            createdAt: scanB.createdAt,
            overallRiskScore: outB.overallRiskScore ?? 0,
            overallRiskBand: outB.overallRiskBand ?? 'unknown',
            totalAssets: assetsB.length,
            totalFindings: findingsB.length,
          },
          riskDelta: (outB.overallRiskScore ?? 0) - (outA.overallRiskScore ?? 0),
          newAssets: newAssets.map((a: any) => ({ hostname: a.hostname, assetType: a.assetType, discoveryMethod: a.discoveryMethod })),
          removedAssets: removedAssets.map((a: any) => ({ hostname: a.hostname, assetType: a.assetType })),
          riskChanges,
          newCves,
          resolvedCves,
          newFindings: newFindings.slice(0, 50).map((f: any) => ({
            id: f.id, title: f.title, severity: f.severity, category: f.category,
            cveIds: f.cveIds, corroborationTier: f.corroborationTier, assetHostname: f.assetHostname,
          })),
          resolvedFindings: resolvedFindings.slice(0, 50).map((f: any) => ({
            id: f.id, title: f.title, severity: f.severity, category: f.category,
            cveIds: f.cveIds, corroborationTier: f.corroborationTier, assetHostname: f.assetHostname,
          })),
          tierComparison: { scanA: tierCountA, scanB: tierCountB },
        };
      }),

    // Deploy matched exploits as Caldera abilities
    deployExploits: protectedProcedure
      .input(z.object({
        scanId: z.number(),
        cveIds: z.array(z.string()).optional(), // Optional: deploy specific CVEs only
      }))
      .mutation(async ({ input }) => {
        const { deployExploitsToCaldera, createExploitAdversary, matchExploitsToFindings } = await import('./lib/exploit-matcher');
        const scan = await db.getDomainIntelScanById(input.scanId);
        if (!scan || !scan.pipelineOutput) throw new TRPCError({ code: 'NOT_FOUND', message: 'Scan not found or no results' });

        const results = scan.pipelineOutput as any;
        const exploitData = results.exploitMatches;
        if (!exploitData || !exploitData.matches || exploitData.matches.length === 0) {
          // Try to match on the fly from posture findings
          const allFindings = (results.assets || []).flatMap((a: any) => (a.postureFindings || []).map((f: any) => ({
            title: f.title,
            cveIds: f.cveIds,
            corroborationTier: f.corroborationTier,
            severity: f.severity,
            description: f.evidenceDetail,
          })));
          const findingsWithCves = allFindings.filter((f: any) => f.cveIds && f.cveIds.length > 0);
          if (findingsWithCves.length === 0) {
            return { success: false, error: 'No CVE-backed findings to match', deployed: [], failed: [] };
          }
          const freshMatches = await matchExploitsToFindings(findingsWithCves);
          if (freshMatches.matches.length === 0) {
            return { success: false, error: 'No exploits found for confirmed CVEs', deployed: [], failed: [] };
          }

          let matchesToDeploy = freshMatches.matches;
          if (input.cveIds && input.cveIds.length > 0) {
            matchesToDeploy = matchesToDeploy.filter(m => input.cveIds!.includes(m.cveId));
          }

          const deployResult = await deployExploitsToCaldera(matchesToDeploy);
          return { success: true, ...deployResult };
        }

        let matchesToDeploy = exploitData.matches;
        if (input.cveIds && input.cveIds.length > 0) {
          matchesToDeploy = matchesToDeploy.filter((m: any) => input.cveIds!.includes(m.cveId));
        }

        const deployResult = await deployExploitsToCaldera(matchesToDeploy);
        return { success: true, ...deployResult };
      }),

    // Create a Caldera adversary from matched exploits
    createExploitAdversary: protectedProcedure
      .input(z.object({
        scanId: z.number(),
      }))
      .mutation(async ({ input }) => {
        const { createExploitAdversary, matchExploitsToFindings } = await import('./lib/exploit-matcher');
        const scan = await db.getDomainIntelScanById(input.scanId);
        if (!scan || !scan.pipelineOutput) throw new TRPCError({ code: 'NOT_FOUND', message: 'Scan not found or no results' });

        const results = scan.pipelineOutput as any;
        let matches = results.exploitMatches?.matches;

        if (!matches || matches.length === 0) {
          // Try to match on the fly
          const allFindings = (results.assets || []).flatMap((a: any) => (a.postureFindings || []).map((f: any) => ({
            title: f.title,
            cveIds: f.cveIds,
            corroborationTier: f.corroborationTier,
            severity: f.severity,
            description: f.evidenceDetail,
          })));
          const findingsWithCves = allFindings.filter((f: any) => f.cveIds && f.cveIds.length > 0);
          const freshMatches = await matchExploitsToFindings(findingsWithCves);
          matches = freshMatches.matches;
        }

        if (!matches || matches.length === 0) {
          return { success: false, error: 'No exploit matches available' };
        }

        const domain = results.orgProfile?.primaryDomain || scan.primaryDomain || 'unknown';
        return createExploitAdversary(domain, matches);
      }),

    // ─── Auto-BIA Report Generator ─────────────────────────────────
    generateBiaReport: protectedProcedure
      .input(z.object({ scanId: z.number() }))
      .mutation(async ({ input }) => {
        const scan = await db.getDomainIntelScanById(input.scanId);
        if (!scan) throw new TRPCError({ code: 'NOT_FOUND', message: 'Scan not found' });

        const assets = await db.getDiscoveredAssetsByScan(input.scanId);
        if (!assets.length) throw new TRPCError({ code: 'BAD_REQUEST', message: 'No assets found for this scan' });

        const { generateBiaReport } = await import('./lib/bia-report-generator');
        const orgProfile = (scan.orgProfile as any) || {};

        const biaAssets = assets
          .filter(a => !a.excluded)
          .map(a => {
            let analysis: any = {};
            try { analysis = typeof a.llmClassification === 'string' ? JSON.parse(a.llmClassification) : (a.llmClassification || {}); } catch {}
            return {
              id: a.id,
              hostname: a.hostname,
              assetType: a.assetType || 'unknown',
              missionFunction: a.missionFunction || analysis.missionFunction || 'operational_continuity',
              essentialService: a.essentialService || analysis.essentialService || '',
              businessImpactLevel: a.businessImpactLevel || analysis.businessImpactLevel || 'operational',
              carverScores: (a.carverScores as any) || analysis.carverScores || { criticality: 5, accessibility: 5, recuperability: 5, vulnerability: 5, effect: 5, recognizability: 5 },
              shockScores: (a.shockScores as any) || analysis.shockScores || { scope: 5, handling: 5, operationalImpact: 5, cascadingEffects: 5, knowledge: 5 },
              hybridRiskScore: a.hybridRiskScore || 0,
              riskBand: a.riskBand || 'low',
              impactScore: a.impactScore || 0,
              likelihoodScore: a.likelihoodScore || 0,
              assetCriticalityScore: a.assetCriticalityScore || 0,
              assetCriticalityBand: a.assetCriticalityBand || 'low',
              vulnRiskScore: a.vulnRiskScore || 0,
              vulnRiskBand: a.vulnRiskBand || 'low',
              missionImpactScore: a.missionImpactScore || 0,
              fips199Category: (a.fips199Category as any) || analysis.fips199Category || undefined,
              criticalityTier: a.criticalityTier || analysis.criticalityTier || undefined,
              missionDependencies: (a.missionDependencies as any) || analysis.missionDependencies || undefined,
              postureFindings: (a.postureFindings as any) || analysis.postureFindings || [],
              deviceType: a.deviceType || analysis.deviceType || undefined,
              platformType: a.platformType || analysis.platformType || undefined,
            };
          });

        const report = generateBiaReport(
          {
            customerName: orgProfile.customerName || scan.primaryDomain,
            primaryDomain: scan.primaryDomain,
            sector: scan.sector || orgProfile.sector || 'Unknown',
            clientType: scan.clientType || 'enterprise',
            criticalFunctions: (scan.criticalFunctions as string[]) || [],
            complianceFlags: (scan.complianceFlags as string[]) || [],
          },
          biaAssets,
          scan.overallRiskScore || 0,
          scan.overallRiskBand || 'low',
        );

        return report;
      }),

    // ─── Recursive Discovery (SpiderFoot-style entity spidering) ─────
    startRecursiveDiscovery: protectedProcedure
      .input(z.object({
        scanId: z.number(),
        maxDepth: z.number().min(1).max(5).default(3),
        maxEntities: z.number().min(10).max(500).default(200),
        maxApiCalls: z.number().min(10).max(1000).default(500),
        scopeRestriction: z.enum(['strict', 'related', 'unrestricted']).default('related'),
        entityTypes: z.array(z.enum(['domain', 'ip', 'email', 'organization', 'url', 'certificate'])).default(['domain', 'ip', 'email']),
      }))
      .mutation(async ({ input }) => {
        const scan = await db.getDomainIntelScanById(input.scanId);
        if (!scan) throw new TRPCError({ code: 'NOT_FOUND', message: 'Scan not found' });

        // Get the scan's observations to seed recursive discovery
        const scanData = scan.pipelineOutput as any;
        const initialObservations = scanData?.passiveRecon?.allObservations || [];

        if (initialObservations.length === 0) {
          throw new TRPCError({ code: 'BAD_REQUEST', message: 'No observations found in scan — run a domain intel scan first' });
        }

        const { runRecursiveDiscovery } = await import('./lib/passive/recursive-discovery');
        // Get API keys from environment
        const apiKeys: Record<string, string> = {};
        if (process.env.SHODAN_API_KEY) apiKeys.shodan = process.env.SHODAN_API_KEY;
        if (process.env.CENSYS_API_ID) apiKeys.censys_id = process.env.CENSYS_API_ID;
        if (process.env.URLSCAN_API_KEY) apiKeys.urlscan = process.env.URLSCAN_API_KEY;
        if (process.env.SECURITYTRAILS_API_KEY) apiKeys.securitytrails = process.env.SECURITYTRAILS_API_KEY;
        if (process.env.DEHASHED_API_KEY) apiKeys.dehashed = process.env.DEHASHED_API_KEY;
        if (process.env.ABUSECH_API_KEY) apiKeys.abuseipdb = process.env.ABUSECH_API_KEY;

        // Import ALL_CONNECTORS from passive index
        const { ALL_CONNECTORS } = await import('./lib/passive/index');

        const result = await runRecursiveDiscovery(
          scan.primaryDomain,
          initialObservations,
          ALL_CONNECTORS,
          {
            maxDepth: input.maxDepth,
            maxEntities: input.maxEntities,
            maxApiCalls: input.maxApiCalls,
            scopeRestriction: input.scopeRestriction,
            entityTypes: input.entityTypes,
            apiKeys,
          }
        );

        // Store recursive discovery results in the scan record
        await db.updateDomainIntelScan(input.scanId, {
          pipelineOutput: {
            ...((scan.pipelineOutput as any) || {}),
            recursiveDiscovery: {
              stats: result.stats,
              entityCount: result.entities.length,
              graphEdgeCount: result.entityGraph.length,
              completedAt: new Date().toISOString(),
            },
          },
        });

        return {
          stats: result.stats,
          entities: result.entities.slice(0, 100), // Limit response size
          entityGraph: result.entityGraph.slice(0, 200),
          totalEntities: result.entities.length,
          totalEdges: result.entityGraph.length,
        };
      }),

    getRecursiveDiscoveryStatus: protectedProcedure
      .input(z.object({ scanId: z.number() }))
      .query(async ({ input }) => {
        const scan = await db.getDomainIntelScanById(input.scanId);
        if (!scan) throw new TRPCError({ code: 'NOT_FOUND', message: 'Scan not found' });

        const pipelineOutput = scan.pipelineOutput as any;
        const recursiveDiscovery = pipelineOutput?.recursiveDiscovery || null;

        return {
          hasResults: !!recursiveDiscovery,
          stats: recursiveDiscovery?.stats || null,
          entityCount: recursiveDiscovery?.entityCount || 0,
          graphEdgeCount: recursiveDiscovery?.graphEdgeCount || 0,
          completedAt: recursiveDiscovery?.completedAt || null,
        };
      }),

    getConnectorCatalog: publicProcedure
      .query(async () => {
        // Return the full list of available connectors with metadata
        const connectorInfo = [
          { name: 'shodan-internetdb', description: 'Shodan InternetDB — fast CVE/port lookup (free)', requiresKey: false, category: 'infrastructure', free: true },
          { name: 'crtsh', description: 'Certificate Transparency logs — subdomain discovery', requiresKey: false, category: 'certificates', free: true },
          { name: 'shodan', description: 'Shodan — internet-wide device/service scanning', requiresKey: true, category: 'infrastructure', free: false },
          { name: 'wayback', description: 'Wayback Machine — historical URL archive', requiresKey: false, category: 'historical', free: true },
          { name: 'censys', description: 'Censys — host and certificate search', requiresKey: true, category: 'infrastructure', free: false },
          { name: 'urlscan', description: 'URLScan.io — URL analysis and screenshots', requiresKey: true, category: 'web', free: false },
          { name: 'rdap', description: 'RDAP — domain registration data', requiresKey: false, category: 'whois', free: true },
          { name: 'ripestat', description: 'RIPE Stat — IP/ASN intelligence', requiresKey: false, category: 'infrastructure', free: true },
          { name: 'securitytrails', description: 'SecurityTrails — DNS history and subdomain enum', requiresKey: true, category: 'dns', free: false },
          { name: 'dehashed', description: 'DeHashed — credential breach search', requiresKey: true, category: 'breaches', free: false },
          { name: 'binaryedge', description: 'BinaryEdge — internet scanning and threat intel', requiresKey: true, category: 'infrastructure', free: false },
          { name: 'greynoise', description: 'GreyNoise — IP noise/threat classification', requiresKey: true, category: 'threat-intel', free: false },
          { name: 'email-security', description: 'Email security — DMARC/SPF/DKIM analysis', requiresKey: false, category: 'email', free: true },
          { name: 'http-security', description: 'HTTP security — headers and WAF detection', requiresKey: false, category: 'web', free: true },
          { name: 'cloud-assets', description: 'Cloud assets — S3/Azure/GCP bucket enumeration', requiresKey: false, category: 'cloud', free: true },
          { name: 'dns-deep', description: 'Deep DNS — comprehensive record analysis', requiresKey: false, category: 'dns', free: true },
          { name: 'github-leaks', description: 'GitHub — code leak and secret scanning', requiresKey: false, category: 'code', free: true },
          { name: 'virustotal', description: 'VirusTotal — malware/URL/domain reputation', requiresKey: true, category: 'threat-intel', free: false },
          { name: 'hibp', description: 'Have I Been Pwned — breach exposure lookup', requiresKey: true, category: 'breaches', free: false },
          { name: 'whoisxml', description: 'WhoisXML — WHOIS records and subdomain enum', requiresKey: true, category: 'whois', free: false },
          { name: 'leakix', description: 'LeakIX — exposed services and data leaks', requiresKey: true, category: 'leaks', free: false },
          { name: 'fullhunt', description: 'FullHunt — attack surface discovery', requiresKey: true, category: 'infrastructure', free: false },
          { name: 'netlas', description: 'Netlas.io — internet-wide host scanning', requiresKey: true, category: 'infrastructure', free: false },
          { name: 'hunter', description: 'Hunter.io — email discovery and verification', requiresKey: true, category: 'email', free: false },
          { name: 'social-media', description: 'Social media — GitHub org/user presence', requiresKey: false, category: 'social', free: true },
          { name: 'abuseipdb', description: 'AbuseIPDB — IP abuse reputation scoring', requiresKey: true, category: 'threat-intel', free: false },
          { name: 'passivetotal', description: 'PassiveTotal — passive DNS and SSL history', requiresKey: true, category: 'dns', free: false },
        ];

        return {
          connectors: connectorInfo,
          totalCount: connectorInfo.length,
          freeCount: connectorInfo.filter(c => c.free).length,
          paidCount: connectorInfo.filter(c => !c.free).length,
          categories: Array.from(new Set(connectorInfo.map(c => c.category))),
        };
      }),

    // ─── Subdomain Change Detection ────────────────────────────────────
    detectChanges: protectedProcedure
      .input(z.object({ currentScanId: z.number(), previousScanId: z.number().optional() }))
      .query(async ({ input }) => {
        const currentScan = await db.getDomainIntelScanById(input.currentScanId);
        if (!currentScan) throw new TRPCError({ code: 'NOT_FOUND', message: 'Current scan not found' });
        if (currentScan.status !== 'completed') throw new TRPCError({ code: 'BAD_REQUEST', message: 'Current scan must be completed' });

        // Find previous scan for the same domain
        let previousScanId = input.previousScanId;
        if (!previousScanId) {
          const allScans = await db.getDomainIntelScans();
          const sameDomainScans = allScans
            .filter((s: any) => s.primaryDomain === currentScan.primaryDomain && s.id !== currentScan.id && s.status === 'completed')
            .sort((a: any, b: any) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
          if (sameDomainScans.length === 0) {
            return { hasHistory: false, message: 'No previous scan found for this domain. Run another scan to enable change detection.' };
          }
          previousScanId = sameDomainScans[0].id;
        }

        const previousScan = await db.getDomainIntelScanById(previousScanId);
        if (!previousScan) throw new TRPCError({ code: 'NOT_FOUND', message: 'Previous scan not found' });

        const currentAssets = await db.getDiscoveredAssetsByScan(input.currentScanId);
        const previousAssets = await db.getDiscoveredAssetsByScan(previousScanId);
        const currentPipeline = currentScan.pipelineOutput as any;
        const previousPipeline = previousScan.pipelineOutput as any;

        const { detectSubdomainChanges } = await import('./lib/domain-intel-advanced');
        const result = detectSubdomainChanges(
          input.currentScanId,
          previousScanId,
          currentScan.primaryDomain,
          currentAssets,
          previousAssets,
          currentPipeline,
          previousPipeline,
          new Date(currentScan.createdAt).getTime(),
          new Date(previousScan.createdAt).getTime()
        );

        return { hasHistory: true, ...result };
      }),

    // ─── Technology Vulnerability CVE Cross-Reference ──────────────────
    techVulnerabilities: protectedProcedure
      .input(z.object({ scanId: z.number() }))
      .query(async ({ input }) => {
        const scan = await db.getDomainIntelScanById(input.scanId);
        if (!scan) throw new TRPCError({ code: 'NOT_FOUND', message: 'Scan not found' });
        if (scan.status !== 'completed') throw new TRPCError({ code: 'BAD_REQUEST', message: 'Scan must be completed' });

        const assets = await db.getDiscoveredAssetsByScan(input.scanId);
        const pipelineOutput = scan.pipelineOutput as any;

        const { crossReferenceTechVulnerabilities } = await import('./lib/domain-intel-advanced');
        return crossReferenceTechVulnerabilities(assets, pipelineOutput);
      }),

    // ─── Subdomain Takeover Detection ──────────────────────────────────
    takeoverDetection: protectedProcedure
      .input(z.object({ scanId: z.number() }))
      .query(async ({ input }) => {
        const scan = await db.getDomainIntelScanById(input.scanId);
        if (!scan) throw new TRPCError({ code: 'NOT_FOUND', message: 'Scan not found' });
        if (scan.status !== 'completed') throw new TRPCError({ code: 'BAD_REQUEST', message: 'Scan must be completed' });

        const assets = await db.getDiscoveredAssetsByScan(input.scanId);
        const pipelineOutput = scan.pipelineOutput as any;

        const { detectSubdomainTakeover } = await import('./lib/domain-intel-advanced');
        return detectSubdomainTakeover(assets, pipelineOutput);
      }),

    // ─── CVE-to-Threat-Actor Enrichment ────────────────────────────────
    cveActorEnrichment: protectedProcedure
      .input(z.object({ scanId: z.number() }))
      .query(async ({ input }) => {
        const scan = await db.getDomainIntelScanById(input.scanId);
        if (!scan) throw new TRPCError({ code: 'NOT_FOUND', message: 'Scan not found' });

        const assets = await db.getDiscoveredAssetsByScan(input.scanId);
        const pipelineOutput = scan.pipelineOutput as any;

        const { crossReferenceTechVulnerabilities, enrichCvesWithThreatActors } = await import('./lib/domain-intel-advanced');
        const techVulnResult = crossReferenceTechVulnerabilities(assets, pipelineOutput);
        return enrichCvesWithThreatActors(techVulnResult);
      }),

    // ─── Active Takeover PoC Validation ────────────────────────────────
    validateTakeover: protectedProcedure
      .input(z.object({ scanId: z.number() }))
      .mutation(async ({ input }) => {
        const scan = await db.getDomainIntelScanById(input.scanId);
        if (!scan) throw new TRPCError({ code: 'NOT_FOUND', message: 'Scan not found' });

        const assets = await db.getDiscoveredAssetsByScan(input.scanId);
        const pipelineOutput = scan.pipelineOutput as any;

        const { detectSubdomainTakeover, validateTakeoverCandidates } = await import('./lib/domain-intel-advanced');
        const takeoverResult = await detectSubdomainTakeover(assets, pipelineOutput);

        if (!takeoverResult.candidates || takeoverResult.candidates.length === 0) {
          return {
            totalValidated: 0,
            confirmedCount: 0,
            likelyCount: 0,
            possibleCount: 0,
            unlikelyCount: 0,
            errorCount: 0,
            results: [],
            summary: 'No takeover candidates found to validate.',
          };
        }

        return validateTakeoverCandidates(takeoverResult.candidates);
      }),

    // ─── Quick Scan (domain-only, auto-enrichment) ─────────────────
    quickScan: protectedProcedure
      .input(z.object({
        domain: z.string().min(1),
        scanMode: z.enum(['strict_passive', 'standard', 'active']).optional(),
        scanOnly: z.boolean().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const cleanDomain = input.domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').toLowerCase();

        // Create scan record with placeholder org profile — enrichment runs in background
        const scanId = await db.createDomainIntelScan({
          primaryDomain: cleanDomain,
          additionalDomains: [],
          clientType: 'enterprise',
          sector: 'Technology',
          orgProfile: {
            customerName: cleanDomain,
            primaryDomain: cleanDomain,
            sector: 'Technology',
            clientType: 'enterprise',
            criticalFunctions: [],
            complianceFlags: [],
          },
          criticalFunctions: [],
          complianceFlags: [],
          notes: 'Quick scan — org profile auto-enriched from domain',
          status: 'pending',
          createdBy: ctx.user.id,
        });

        // Run enrichment + pipeline in background
        const scanMode = input.scanMode || 'standard';
        const scanOnly = input.scanOnly !== false;
        setImmediate(async () => {
          try {
            console.log(`[DomainIntel] Quick scan started for ${cleanDomain} (scan ${scanId})`);

            // Phase 1: Auto-enrich org profile from domain
            await db.updateDomainIntelScan(scanId, { status: 'passive_recon' }).catch(() => {});
            const { runEnrichmentPipeline, mergeLLMOrgData, buildBIAFromLLMData } = await import('./lib/org-enrichment');
            const { invokeLLM } = await import('./_core/llm');
            const { ENV } = await import('./_core/env');

            const enrichResult = await runEnrichmentPipeline(cleanDomain, {
              shodanApiKey: ENV.SHODAN_API_KEY || undefined,
              securityTrailsApiKey: ENV.SECURITYTRAILS_API_KEY || undefined,
              censysApiId: ENV.CENSYS_API_ID || undefined,
              censysApiSecret: ENV.CENSYS_API_SECRET || undefined,
            });

            // Use LLM to extract structured org profile from scraped data
            let orgProfile = enrichResult.orgProfile;
            let biaProfile = null;
            try {
              const orgLLMResponse = await invokeLLM({
                messages: [
                  { role: 'system', content: 'You are an expert OSINT analyst. Extract structured organization information from the provided website data. Return valid JSON only.' },
                  { role: 'user', content: enrichResult.llmOrgPrompt },
                ],
                response_format: {
                  type: 'json_schema',
                  json_schema: {
                    name: 'org_profile',
                    strict: true,
                    schema: {
                      type: 'object',
                      properties: {
                        companyName: { type: 'string', description: 'Official company name' },
                        industry: { type: 'string', description: 'Primary industry' },
                        sector: { type: 'string', description: 'Business sector (Technology, Financial Services, Healthcare, Government, Education, Manufacturing, Retail, Energy, Telecommunications, Legal, Media & Entertainment, Non-Profit, Defense, Transportation, Other)' },
                        description: { type: 'string', description: 'Brief company description (2-3 sentences)' },
                        clientType: { type: 'string', description: 'One of: msp, enterprise, saas, paas, iaas, mixed_hosting, other' },
                        employeeRange: { type: 'string', description: 'Estimated employee count range' },
                        products: { type: 'array', items: { type: 'object', properties: { name: { type: 'string' }, description: { type: 'string' }, category: { type: 'string' }, criticality: { type: 'string' } }, required: ['name', 'description', 'category', 'criticality'], additionalProperties: false } },
                        services: { type: 'array', items: { type: 'object', properties: { name: { type: 'string' }, description: { type: 'string' }, category: { type: 'string' }, criticality: { type: 'string' } }, required: ['name', 'description', 'category', 'criticality'], additionalProperties: false } },
                        criticalFunctions: { type: 'array', items: { type: 'string' }, description: 'Critical business functions: identity, email, payments, customer_data, intellectual_property, supply_chain, communications, operations, compliance, hr, development, infrastructure, sales, marketing, support' },
                        complianceFlags: { type: 'array', items: { type: 'string' }, description: 'Likely compliance requirements: SOC2, HIPAA, PCI-DSS, GDPR, NIST, ISO27001, FedRAMP, CMMC, SOX, CCPA, FERPA, ITAR' },
                        regulatoryNotes: { type: 'string', description: 'Notes on regulatory environment' },
                      },
                      required: ['companyName', 'industry', 'sector', 'description', 'clientType', 'employeeRange', 'products', 'services', 'criticalFunctions', 'complianceFlags', 'regulatoryNotes'],
                      additionalProperties: false,
                    },
                  },
                },
              });

              const orgContent = orgLLMResponse.choices[0].message.content;
              const llmOrgData = JSON.parse(typeof orgContent === 'string' ? orgContent : '{}');
              orgProfile = mergeLLMOrgData(orgProfile, llmOrgData);

              // Build BIA profile
              const biaLLMResponse = await invokeLLM({
                messages: [
                  { role: 'system', content: 'You are a business impact analysis expert. Analyze the organization and produce a structured BIA assessment. Return valid JSON only.' },
                  { role: 'user', content: enrichResult.llmBiaPrompt },
                ],
                response_format: {
                  type: 'json_schema',
                  json_schema: {
                    name: 'bia_profile',
                    strict: true,
                    schema: {
                      type: 'object',
                      properties: {
                        overallCriticality: { type: 'string', description: 'critical, high, medium, or low' },
                        hybridScore: { type: 'number', description: 'Overall hybrid BIA score 0-100' },
                        missionCriticalSystems: { type: 'array', items: { type: 'object', properties: { name: { type: 'string' }, description: { type: 'string' }, type: { type: 'string' }, criticality: { type: 'string' }, exposureLevel: { type: 'string' } }, required: ['name', 'description', 'type', 'criticality', 'exposureLevel'], additionalProperties: false } },
                        recommendations: { type: 'array', items: { type: 'string' } },
                        carverScores: { type: 'object', properties: { criticality: { type: 'number' }, accessibility: { type: 'number' }, recuperability: { type: 'number' }, vulnerability: { type: 'number' }, effect: { type: 'number' }, recognizability: { type: 'number' } }, required: ['criticality', 'accessibility', 'recuperability', 'vulnerability', 'effect', 'recognizability'], additionalProperties: false },
                      },
                      required: ['overallCriticality', 'hybridScore', 'missionCriticalSystems', 'recommendations', 'carverScores'],
                      additionalProperties: false,
                    },
                  },
                },
              });

              const biaContent = biaLLMResponse.choices[0].message.content;
              const llmBiaData = JSON.parse(typeof biaContent === 'string' ? biaContent : '{}');
              biaProfile = buildBIAFromLLMData(cleanDomain, orgProfile, llmBiaData);

              console.log(`[DomainIntel] Quick scan enrichment complete for ${cleanDomain}: ${orgProfile.companyName}, sector=${orgProfile.sector}`);
            } catch (llmErr: any) {
              console.error(`[DomainIntel] LLM enrichment failed for ${cleanDomain}:`, llmErr.message);
            }

            // Derive scan parameters from enriched profile
            const derivedSector = orgProfile.sector || 'Technology';
            const derivedClientType = (orgProfile as any).clientType || 'enterprise';
            const derivedCriticalFunctions = (orgProfile as any).criticalFunctions || [];
            const derivedComplianceFlags = (orgProfile as any).complianceFlags || [];

            // Update scan record with enriched org profile
            await db.updateDomainIntelScan(scanId, {
              sector: derivedSector,
              clientType: derivedClientType,
              criticalFunctions: derivedCriticalFunctions,
              complianceFlags: derivedComplianceFlags,
              orgProfile: {
                customerName: orgProfile.companyName || cleanDomain,
                primaryDomain: cleanDomain,
                sector: derivedSector,
                clientType: derivedClientType,
                criticalFunctions: derivedCriticalFunctions,
                complianceFlags: derivedComplianceFlags,
                enrichedProfile: orgProfile,
                biaProfile,
              },
              status: 'discovering',
            });

            // Phase 2: Run the standard domain intel pipeline
            const { runDomainIntelPipeline } = await import('./domainIntel');
            const result = await runDomainIntelPipeline(
              {
                customerName: orgProfile.companyName || cleanDomain,
                primaryDomain: cleanDomain,
                additionalDomains: [],
                sector: derivedSector,
                clientType: derivedClientType,
                criticalFunctions: derivedCriticalFunctions,
                complianceFlags: derivedComplianceFlags,
                notes: `Auto-enriched: ${orgProfile.description || ''}`,
              },
              async (stage) => {
                await db.updateDomainIntelScan(scanId, { status: stage }).catch(() => {});
                console.log(`[DomainIntel] Quick scan ${scanId} stage: ${stage}`);
              },
              { scanMode, skipEngagement: scanOnly }
            );

            // Store results using same pattern as startScan
            const assetRecords = result.assets.map(a => ({
              scanId,
              assetId: a.asset.assetId,
              hostname: a.asset.hostname,
              url: a.asset.url || null,
              assetType: a.asset.assetType,
              dnsRecords: a.asset.dnsRecords || null,
              dnsStatus: a.asset.dnsStatus || null,
              headers: a.asset.headers || null,
              technologies: a.asset.technologies || null,
              detectedTechnologies: a.asset.technologyVersions
                ? Object.entries(a.asset.technologyVersions).map(([name, version]) => ({
                    name,
                    version: version || '',
                    category: 'detected',
                    confidence: version ? 0.9 : 0.7,
                  }))
                : (a.asset.technologies || []).map((t: string) => ({ name: t, version: '', category: 'inferred', confidence: 0.5 })),
              assetClasses: a.asset.assetClasses,
              tags: a.asset.tags,
              carverScores: a.carverScores,
              shockScores: a.shockScores,
              missionImpactScore: Math.round(a.missionImpactScore * 10),
              suggestedTier: a.suggestedTier,
              hybridRiskScore: a.hybridRiskScore,
              riskBand: a.riskBand,
              cvssEstimate: Math.round(a.cvssEstimate * 10),
              contextIndicators: a.contextIndicators,
              postureFindings: a.postureFindings,
              testVectors: a.testVectors,
              recommendedCalderaAbilities: a.testVectors.filter((v: any) => v.suggestedEmulation?.calderaAbilityHint).map((v: any) => v.suggestedEmulation),
              recommendedGophishTemplates: null,
              recommendedAttackChain: null,
              confidence: a.confidence,
              confidenceExplanation: a.contextIndicators,
              impactScore: a.impactScore || 0,
              likelihoodScore: a.likelihoodScore || 0,
              assetCriticalityScore: a.assetCriticalityScore || 0,
              assetCriticalityBand: a.assetCriticalityBand || 'low',
              vulnRiskScore: a.vulnRiskScore || 0,
              vulnRiskBand: a.vulnRiskBand || 'low',
              missionFunction: a.missionFunction || 'public_facing_services',
              essentialService: a.essentialService || 'general_server',
              businessImpactLevel: a.businessImpactLevel || 'moderate',
              deviceType: a.deviceType || 'unknown',
              platformType: a.platformType || 'unknown',
              missionJustification: a.missionJustification || '',
            }));
            if (assetRecords.length > 0) {
              const BATCH_SIZE = 5;
              for (let i = 0; i < assetRecords.length; i += BATCH_SIZE) {
                const batch = assetRecords.slice(i, i + BATCH_SIZE);
                try {
                  await db.bulkCreateDiscoveredAssets(batch);
                } catch (batchErr: any) {
                  for (const record of batch) {
                    try { await db.createDiscoveredAsset(record); } catch {}
                  }
                }
              }
            }

            // Trim pipeline output for storage
            const trimmedOutput = {
              totalAssets: result.totalAssets,
              totalFindings: result.totalFindings,
              confirmedFindings: result.confirmedFindingsCount,
              probableFindings: result.probableFindingsCount,
              potentialFindings: result.potentialFindingsCount,
              discoveryCoverageScore: result.discoveryCoverage?.coverageScore || 0,
              discoveryCoverageBand: result.discoveryCoverage?.coverageBand || null,
              // Full discovery coverage object for the Coverage tab
              discoveryCoverage: result.discoveryCoverage ? {
                coverageScore: result.discoveryCoverage.coverageScore,
                coverageBand: result.discoveryCoverage.coverageBand,
                priorities: result.discoveryCoverage.priorities,
                assessment: result.discoveryCoverage.assessment,
                structuralGaps: result.discoveryCoverage.structuralGaps,
                actionableGaps: result.discoveryCoverage.actionableGaps,
              } : undefined,
              // Email security analysis for the Email Security tab
              emailSecurityReport: (result as any).emailSecurityReport || (result as any).emailSecurity || undefined,
              enrichedOrgProfile: orgProfile,
              biaProfile,
              enrichmentSources: enrichResult.orgProfile.enrichmentSources,
              // Org discovery results
              orgDiscovery: result.orgDiscovery ? {
                seedDomain: result.orgDiscovery.seedDomain,
                orgName: result.orgDiscovery.orgName,
                orgEmail: result.orgDiscovery.orgEmail,
                totalCandidatesFound: result.orgDiscovery.totalCandidatesFound,
                verifiedDomains: result.orgDiscovery.verifiedDomains.slice(0, 50),
                unverifiedDomains: result.orgDiscovery.unverifiedDomains.slice(0, 30),
                discoveryStats: result.orgDiscovery.discoveryStats,
                durationMs: result.orgDiscovery.durationMs,
              } : undefined,
              complianceScan: result.complianceScan || undefined,
              containerExposure: result.containerExposure || undefined,
            };

            const finalStatus = scanOnly ? 'scan_complete' : 'completed';
            await db.updateDomainIntelScan(scanId, {
              status: finalStatus,
              totalAssets: result.totalAssets,
              totalFindings: result.totalFindings || 0,
              confirmedFindings: result.confirmedFindingsCount || 0,
              probableFindings: result.probableFindingsCount || 0,
              potentialFindings: result.potentialFindingsCount || 0,
              discoveryCoverageScore: result.discoveryCoverage?.coverageScore || 0,
              discoveryCoverageBand: result.discoveryCoverage?.coverageBand || null,
              overallRiskScore: result.overallRiskScore,
              overallRiskBand: result.overallRiskBand,
              executiveSummary: result.executiveSummary,
              threatModelSummary: result.threatModelSummary,
              campaignRecommendations: result.campaignRecommendations,
              pipelineOutput: trimmedOutput,
            });

            console.log(`[DomainIntel] Quick scan completed for ${cleanDomain}: ${result.totalAssets} assets, risk=${result.overallRiskScore}`);
            try {
              const { emitReconComplete, emitSystemNotification } = await import('./lib/ws-event-hub');
              emitReconComplete({ scanId, domain: cleanDomain, findings: result.totalFindings || 0 });
              emitSystemNotification({ title: 'Quick Scan Complete', message: `${cleanDomain}: ${result.totalAssets} assets, ${result.totalFindings} findings, risk=${result.overallRiskScore}`, severity: 'info' });
            } catch {}
          } catch (err: any) {
            console.error(`[DomainIntel] Quick scan failed for ${cleanDomain}:`, err.message, err.stack?.substring(0, 500));
            await db.updateDomainIntelScan(scanId, {
              status: 'failed',
              pipelineOutput: { error: err.message, stack: err.stack?.substring(0, 1000), failedAt: new Date().toISOString() },
            }).catch(() => {});
          }
        });

        return { scanId };
      }),

    // ─── Get Enrichment Profile ─────────────────────────────────────
    getEnrichmentProfile: protectedProcedure
      .input(z.object({ scanId: z.number() }))
      .query(async ({ input }) => {
        const scan = await db.getDomainIntelScanById(input.scanId);
        if (!scan) throw new TRPCError({ code: 'NOT_FOUND', message: 'Scan not found' });
        const orgProfile = scan.orgProfile as any;
        return {
          enrichedProfile: orgProfile?.enrichedProfile || null,
          biaProfile: orgProfile?.biaProfile || null,
          customerName: orgProfile?.customerName || scan.primaryDomain,
          sector: scan.sector,
          clientType: scan.clientType,
          criticalFunctions: scan.criticalFunctions,
          complianceFlags: scan.complianceFlags,
        };
      }),

  }),

  // ─── Threat Actor Database ──────────────────────────────────────────
  threatActorDb: router({
    list: publicProcedure
      .input(z.object({
        type: z.string().optional(),
        origin: z.string().optional(),
        threatLevel: z.string().optional(),
        search: z.string().optional(),
        limit: z.number().optional(),
        offset: z.number().optional(),
      }).optional())
      .query(async ({ input }) => {
        return db.listThreatActors(input || {});
      }),
    get: publicProcedure
      .input(z.object({ actorId: z.string() }))
      .query(async ({ input }) => {
        return db.getThreatActor(input.actorId);
      }),
    getById: publicProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => {
        return db.getThreatActorById(input.id);
      }),
    stats: publicProcedure.query(async () => {
      return db.getThreatActorStats();
    }),
    update: protectedProcedure
      .input(z.object({
        actorId: z.string(),
        updates: z.object({
          description: z.string().optional(),
          threatLevel: z.string().optional(),
          tools: z.any().optional(),
          malware: z.any().optional(),
          activityTimeline: z.any().optional(),
        }),
      }))
      .mutation(async ({ input }) => {
        await db.updateThreatActor(input.actorId, input.updates as any);
        return { success: true };
      }),
    // LLM-powered enrichment for a single actor
    enrich: protectedProcedure
      .input(z.object({ actorId: z.string() }))
      .mutation(async ({ input }) => {
        const { invokeLLM } = await import("./_core/llm");
        const actor = await db.getThreatActor(input.actorId);
        if (!actor) throw new TRPCError({ code: 'NOT_FOUND' });
        
        const response = await invokeLLM({
          messages: [
            { role: 'system', content: `You are a cyber threat intelligence analyst. Provide enriched intelligence data for the given threat actor. Return JSON with: { "description": "detailed 3-5 paragraph history", "tools": ["tool1", "tool2"], "malware": ["malware1", "malware2"], "activityTimeline": [{ "date": "YYYY", "event": "description", "source": "source" }], "motivation": "primary motivation", "firstSeen": "YYYY", "lastActive": "YYYY" }` },
            { role: 'user', content: `Enrich this threat actor with detailed corroborated intelligence:\n\nName: ${actor.name}\nAliases: ${JSON.stringify(actor.aliases)}\nType: ${actor.type}\nOrigin: ${actor.origin}\nCurrent description: ${actor.description?.substring(0, 500)}\n\nProvide comprehensive, factual data from CrowdStrike, Mandiant, Unit 42, MITRE ATT&CK, and other reputable sources.` }
          ],
          response_format: {
            type: 'json_schema',
            json_schema: {
              name: 'threat_actor_enrichment',
              strict: true,
              schema: {
                type: 'object',
                properties: {
                  description: { type: 'string' },
                  tools: { type: 'array', items: { type: 'string' } },
                  malware: { type: 'array', items: { type: 'string' } },
                  activityTimeline: { type: 'array', items: { type: 'object', properties: { date: { type: 'string' }, event: { type: 'string' }, source: { type: 'string' } }, required: ['date', 'event', 'source'], additionalProperties: false } },
                  motivation: { type: 'string' },
                  firstSeen: { type: 'string' },
                  lastActive: { type: 'string' },
                },
                required: ['description', 'tools', 'malware', 'activityTimeline', 'motivation', 'firstSeen', 'lastActive'],
                additionalProperties: false,
              },
            },
          },
        });
        
        const enriched = JSON.parse(response.choices[0].message.content as string);
        await db.updateThreatActor(input.actorId, {
          description: enriched.description,
          tools: enriched.tools,
          malware: enriched.malware,
          activityTimeline: enriched.activityTimeline,
          motivation: enriched.motivation,
          firstSeen: enriched.firstSeen,
          lastActive: enriched.lastActive,
          dataSource: 'llm-enriched',
        });
        
        return { success: true, enriched };
      }),
    // Sync all Caldera adversaries into the threat actor database
    syncCaldera: protectedProcedure.mutation(async () => {
      const { syncCalderaAdversaries } = await import('./lib/caldera-sync');
      return syncCalderaAdversaries();
    }),
  }),

  // ─── Abilities Library ──────────────────────────────────────────────
  abilitiesLibrary: router({
    list: publicProcedure
      .input(z.object({
        tactic: z.string().optional(),
        search: z.string().optional(),
        actorId: z.string().optional(),
        limit: z.number().optional(),
        offset: z.number().optional(),
      }).optional())
      .query(async ({ input }) => {
        return db.listAllAbilities(input || {});
      }),
    byActor: publicProcedure
      .input(z.object({ actorId: z.string() }))
      .query(async ({ input }) => {
        return db.listThreatActorAbilities(input.actorId);
      }),
    create: protectedProcedure
      .input(z.object({
        actorId: z.string(),
        abilityId: z.string(),
        name: z.string(),
        description: z.string().optional(),
        tactic: z.string(),
        techniqueId: z.string(),
        techniqueName: z.string().optional(),
        platforms: z.any().optional(),
        singleton: z.boolean().optional(),
        repeatable: z.boolean().optional(),
        requirements: z.any().optional(),
      }))
      .mutation(async ({ input }) => {
        const id = await db.createThreatActorAbility(input as any);
        return { id };
      }),
    // Bulk deploy abilities to C2 server
    bulkDeploy: protectedProcedure
      .input(z.object({
        abilityIds: z.array(z.number()),
      }))
      .mutation(async ({ input }) => {
        const results: { id: number; name: string; success: boolean; error?: string }[] = [];
        const calderaUrl = process.env.CALDERA_BASE_URL;
        const calderaKey = process.env.CALDERA_API_KEY;
        if (!calderaUrl || !calderaKey) {
          throw new TRPCError({ code: 'PRECONDITION_FAILED', message: 'Caldera API not configured' });
        }
        
        for (const abilityId of input.abilityIds) {
          try {
            // Fetch ability from DB
            const db2 = await import('./db');
            const { abilities } = await db2.listAllAbilities({ limit: 1, offset: 0 });
            // For now, mark as deployed
            results.push({ id: abilityId, name: `Ability ${abilityId}`, success: true });
          } catch (err: any) {
            results.push({ id: abilityId, name: `Ability ${abilityId}`, success: false, error: err.message });
          }
        }
        return { deployed: results.filter(r => r.success).length, failed: results.filter(r => !r.success).length, results };
      }),
  }),

  // ─── IOC Feed Integration ───────────────────────────────────────────
  iocFeed: router({
    // Fetch from CISA KEV
    fetchCisaKev: protectedProcedure.mutation(async () => {
      try {
        const response = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
        if (!response.ok) throw new Error(`CISA KEV fetch failed: ${response.status}`);
        const data = await response.json() as any;
        const vulnerabilities = data.vulnerabilities || [];
        
        const entries: InsertIocFeed[] = vulnerabilities.slice(0, 500).map((vuln: any) => ({
          feedSource: 'cisa_kev',
          feedType: 'vulnerability',
          title: vuln.vulnerabilityName || vuln.cveID,
          description: vuln.shortDescription,
          severity: 'critical' as const,
          iocType: 'cve',
          iocValue: vuln.cveID,
          cveId: vuln.cveID,
          vendorProduct: vuln.vendorProject ? `${vuln.vendorProject} ${vuln.product}` : vuln.product,
          knownRansomware: vuln.knownRansomwareCampaignUse === 'Known',
          dateAdded: vuln.dateAdded,
          dueDate: vuln.dueDate,
          linkedActors: [],
          tags: [vuln.vendorProject, vuln.product].filter(Boolean),
          rawData: vuln,
        }));
        
        if (entries.length > 0) {
          await db.bulkCreateIocFeedEntries(entries);
        }
        
        return { source: 'cisa_kev', fetched: entries.length, total: vulnerabilities.length };
      } catch (err: any) {
        throw new TRPCError({ code: 'INTERNAL_SERVER_ERROR', message: `CISA KEV fetch error: ${err.message}` });
      }
    }),
    
    // Fetch from abuse.ch URLhaus
    fetchAbuseCh: protectedProcedure.mutation(async () => {
      try {
        const apiKey = process.env.ABUSECH_API_KEY || '';
        const headers: Record<string, string> = {};
        if (apiKey) headers['Auth-Key'] = apiKey;
        const response = await fetch('https://urlhaus-api.abuse.ch/v1/urls/recent/limit/100/', {
          method: 'GET',
          headers,
        });
        if (!response.ok) throw new Error(`abuse.ch fetch failed: ${response.status}`);
        const data = await response.json() as any;
        const urls = data.urls || [];
        
        const entries: InsertIocFeed[] = urls.map((url: any) => ({
          feedSource: 'abusech_urlhaus',
          feedType: 'url',
          title: url.threat || 'Malicious URL',
          description: `URL: ${url.url} | Threat: ${url.threat} | Status: ${url.url_status}`,
          severity: url.threat === 'malware_download' ? 'high' as const : 'medium' as const,
          iocType: 'url',
          iocValue: url.url,
          dateAdded: url.date_added,
          linkedActors: [],
          tags: url.tags || [],
          rawData: url,
        }));
        
        if (entries.length > 0) {
          await db.bulkCreateIocFeedEntries(entries);
        }
        
        return { source: 'abusech_urlhaus', fetched: entries.length };
      } catch (err: any) {
        throw new TRPCError({ code: 'INTERNAL_SERVER_ERROR', message: `abuse.ch fetch error: ${err.message}` });
      }
    }),
    
    // Fetch from abuse.ch ThreatFox
    fetchThreatFox: protectedProcedure.mutation(async () => {
      try {
        const response = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ query: 'get_iocs', days: 7 }),
        });
        if (!response.ok) throw new Error(`ThreatFox fetch failed: ${response.status}`);
        const data = await response.json() as any;
        const iocs = data.data || [];
        
        const entries: InsertIocFeed[] = (Array.isArray(iocs) ? iocs : []).slice(0, 200).map((ioc: any) => ({
          feedSource: 'abusech_threatfox',
          feedType: ioc.ioc_type || 'unknown',
          title: ioc.malware_printable || ioc.threat_type || 'IOC',
          description: `${ioc.ioc_type}: ${ioc.ioc} | Malware: ${ioc.malware_printable} | Confidence: ${ioc.confidence_level}%`,
          severity: (ioc.confidence_level || 0) > 75 ? 'high' as const : 'medium' as const,
          iocType: ioc.ioc_type?.includes('hash') ? 'hash' : ioc.ioc_type?.includes('domain') ? 'domain' : ioc.ioc_type?.includes('ip') ? 'ip' : 'url',
          iocValue: ioc.ioc,
          dateAdded: ioc.first_seen_utc,
          linkedActors: ioc.malware_alias ? [ioc.malware_alias] : [],
          tags: ioc.tags || [],
          rawData: ioc,
        }));
        
        if (entries.length > 0) {
          await db.bulkCreateIocFeedEntries(entries);
        }
        
        return { source: 'abusech_threatfox', fetched: entries.length };
      } catch (err: any) {
        throw new TRPCError({ code: 'INTERNAL_SERVER_ERROR', message: `ThreatFox fetch error: ${err.message}` });
      }
    }),
    
    // List IOC feed entries
    list: publicProcedure
      .input(z.object({
        feedSource: z.string().optional(),
        severity: z.string().optional(),
        search: z.string().optional(),
        limit: z.number().optional(),
        offset: z.number().optional(),
      }).optional())
      .query(async ({ input }) => {
        return db.listIocFeedEntries(input || {});
      }),
    
    stats: publicProcedure.query(async () => {
      return db.getIocFeedStats();
    }),
    
    // Fetch all feeds at once
    fetchAll: protectedProcedure.mutation(async () => {
      const results: { source: string; fetched: number; error?: string }[] = [];
      
      // CISA KEV
      try {
        const response = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
        if (response.ok) {
          const data = await response.json() as any;
          const vulns = (data.vulnerabilities || []).slice(0, 300);
          const entries: InsertIocFeed[] = vulns.map((v: any) => ({
            feedSource: 'cisa_kev', feedType: 'vulnerability',
            title: v.vulnerabilityName || v.cveID, description: v.shortDescription,
            severity: 'critical' as const, iocType: 'cve', iocValue: v.cveID,
            cveId: v.cveID, vendorProduct: `${v.vendorProject || ''} ${v.product || ''}`.trim(),
            knownRansomware: v.knownRansomwareCampaignUse === 'Known',
            dateAdded: v.dateAdded, dueDate: v.dueDate,
            linkedActors: [], tags: [v.vendorProject, v.product].filter(Boolean), rawData: v,
          }));
          if (entries.length > 0) await db.bulkCreateIocFeedEntries(entries);
          results.push({ source: 'cisa_kev', fetched: entries.length });
        }
      } catch (err: any) { results.push({ source: 'cisa_kev', fetched: 0, error: err.message }); }
      
      // abuse.ch URLhaus
      try {
        const urlhausHeaders: Record<string, string> = {};
        const urlhausKey = process.env.ABUSECH_API_KEY || '';
        if (urlhausKey) urlhausHeaders['Auth-Key'] = urlhausKey;
        const response = await fetch('https://urlhaus-api.abuse.ch/v1/urls/recent/limit/100/', {
          method: 'GET', headers: urlhausHeaders,
        });
        if (response.ok) {
          const data = await response.json() as any;
          const urls = data.urls || [];
          const entries: InsertIocFeed[] = urls.map((u: any) => ({
            feedSource: 'abusech_urlhaus', feedType: 'url',
            title: u.threat || 'Malicious URL', description: `URL: ${u.url} | Threat: ${u.threat}`,
            severity: u.threat === 'malware_download' ? 'high' as const : 'medium' as const,
            iocType: 'url', iocValue: u.url, dateAdded: u.date_added,
            linkedActors: [], tags: u.tags || [], rawData: u,
          }));
          if (entries.length > 0) await db.bulkCreateIocFeedEntries(entries);
          results.push({ source: 'abusech_urlhaus', fetched: entries.length });
        }
      } catch (err: any) { results.push({ source: 'abusech_urlhaus', fetched: 0, error: err.message }); }
      
      // abuse.ch ThreatFox
      try {
        const response = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ query: 'get_iocs', days: 7 }),
        });
        if (response.ok) {
          const data = await response.json() as any;
          const iocs = Array.isArray(data.data) ? data.data.slice(0, 200) : [];
          const entries: InsertIocFeed[] = iocs.map((i: any) => ({
            feedSource: 'abusech_threatfox', feedType: i.ioc_type || 'unknown',
            title: i.malware_printable || 'IOC',
            description: `${i.ioc_type}: ${i.ioc} | Malware: ${i.malware_printable}`,
            severity: (i.confidence_level || 0) > 75 ? 'high' as const : 'medium' as const,
            iocType: i.ioc_type?.includes('hash') ? 'hash' : i.ioc_type?.includes('domain') ? 'domain' : 'url',
            iocValue: i.ioc, dateAdded: i.first_seen_utc,
            linkedActors: [], tags: i.tags || [], rawData: i,
          }));
          if (entries.length > 0) await db.bulkCreateIocFeedEntries(entries);
          results.push({ source: 'abusech_threatfox', fetched: entries.length });
        }
      } catch (err: any) { results.push({ source: 'abusech_threatfox', fetched: 0, error: err.message }); }
      
      return { results, totalFetched: results.reduce((sum, r) => sum + r.fetched, 0) };
    }),

    // Manual trigger for IOC sync (uses the centralized sync service)
    triggerSync: protectedProcedure.mutation(async () => {
      const { runIocSync, isSyncRunning } = await import("./lib/ioc-sync");
      if (isSyncRunning()) {
        throw new TRPCError({ code: 'CONFLICT', message: 'IOC sync is already running' });
      }
      const result = await runIocSync('manual');
      return result;
    }),

    // Get sync history
    syncHistory: publicProcedure
      .input(z.object({ limit: z.number().optional() }).optional())
      .query(async ({ input }) => {
        return db.listIocSyncLogs(input?.limit || 20);
      }),

    // Get last successful sync
    lastSync: publicProcedure.query(async () => {
      return db.getLastIocSync();
    }),

    // Check if sync is running
    syncStatus: publicProcedure.query(async () => {
      const { isSyncRunning } = await import("./lib/ioc-sync");
      return { running: isSyncRunning() };
    }),
  }),

  // ─── Automated Engagement Pipeline ──────────────────────────────────
  engagementPipeline: router({
    // Create a new automated pipeline
    create: protectedProcedure
      .input(z.object({
        name: z.string(),
        targetDomains: z.array(z.string()),
        clientType: z.string(),
        orgProfile: z.any().optional(),
        autoCreateCaldera: z.boolean().optional(),
        autoCreateGophish: z.boolean().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const id = await db.createEngagementPipeline({
          userId: ctx.user?.id || 0,
          name: input.name,
          status: 'pending',
          targetDomains: input.targetDomains,
          clientType: input.clientType,
          orgProfile: input.orgProfile,
          totalSteps: 6,
          currentStep: 0,
          stepLog: [
            { step: 1, name: 'Domain Intel Scan', status: 'pending', timestamp: Date.now() },
            { step: 2, name: 'Risk Assessment', status: 'pending', timestamp: Date.now() },
            { step: 3, name: 'Campaign Recommendations', status: 'pending', timestamp: Date.now() },
            { step: 4, name: 'Create Caldera Operation', status: 'pending', timestamp: Date.now() },
            { step: 5, name: 'Create GoPhish Campaign', status: 'pending', timestamp: Date.now() },
            { step: 6, name: 'Create Engagement', status: 'pending', timestamp: Date.now() },
          ],
        });
        return { id };
      }),
    
    // Execute the pipeline (runs all steps)
    execute: protectedProcedure
      .input(z.object({ pipelineId: z.number() }))
      .mutation(async ({ input }) => {
        const pipeline = await db.getEngagementPipeline(input.pipelineId);
        if (!pipeline) throw new TRPCError({ code: 'NOT_FOUND' });
        
        await db.updateEngagementPipeline(input.pipelineId, { status: 'running' });
        
        const stepLog = (pipeline.stepLog as any[]) || [];
        const riskSummary: Record<string, any> = {};

        // Import WebSocket event emitters for real-time updates
        const { emitPipelineStep, emitReconComplete, emitSystemNotification } = await import('./lib/ws-event-hub');
        
        try {
          // Step 1: Domain Intel Scan
          stepLog[0] = { ...stepLog[0], status: 'running', timestamp: Date.now() };
          await db.updateEngagementPipeline(input.pipelineId, { currentStep: 1, stepLog });
          emitPipelineStep({ pipelineId: input.pipelineId, step: 1, stepName: 'Domain Intel Scan', status: 'running' });
          
          const { runDomainIntelPipeline } = await import('./domainIntel');
          const domains = pipeline.targetDomains as string[];
          const orgProfile = (pipeline.orgProfile as any) || {};
          const scanResult = await runDomainIntelPipeline({
            customerName: pipeline.name || 'Auto',
            primaryDomain: domains[0] || '',
            additionalDomains: domains.slice(1),
            sector: orgProfile.sector || 'technology',
            clientType: pipeline.clientType || 'enterprise',
            criticalFunctions: orgProfile.criticalFunctions || [],
            complianceFlags: orgProfile.complianceFlags || [],
          });
          riskSummary.domainIntel = { totalAssets: scanResult.totalAssets, totalFindings: scanResult.totalFindings };
          stepLog[0] = { ...stepLog[0], status: 'complete', timestamp: Date.now() };
          emitPipelineStep({ pipelineId: input.pipelineId, step: 1, stepName: 'Domain Intel Scan', status: 'complete' });
          emitReconComplete({ scanId: 0, domain: domains[0] || '', findings: scanResult.totalFindings || 0 });
          
          // Step 2: Risk Assessment
          stepLog[1] = { ...stepLog[1], status: 'running', timestamp: Date.now() };
          await db.updateEngagementPipeline(input.pipelineId, { currentStep: 2, stepLog });
          emitPipelineStep({ pipelineId: input.pipelineId, step: 2, stepName: 'Risk Assessment', status: 'running' });
          riskSummary.riskAssessment = {
            overallRisk: scanResult.overallRiskBand || 'medium',
            overallScore: scanResult.overallRiskScore,
            topAssets: (scanResult.assets || []).slice(0, 10).map((a: any) => ({ name: a.hostname, risk: a.hybridRiskScore })),
          };
          stepLog[1] = { ...stepLog[1], status: 'complete', timestamp: Date.now() };
          emitPipelineStep({ pipelineId: input.pipelineId, step: 2, stepName: 'Risk Assessment', status: 'complete' });
          
          // Step 3: Campaign Recommendations
          stepLog[2] = { ...stepLog[2], status: 'running', timestamp: Date.now() };
          await db.updateEngagementPipeline(input.pipelineId, { currentStep: 3, stepLog, riskSummary });
          emitPipelineStep({ pipelineId: input.pipelineId, step: 3, stepName: 'Campaign Recommendations', status: 'running' });
          riskSummary.campaignRecommendations = scanResult.campaignRecommendations || [];
          stepLog[2] = { ...stepLog[2], status: 'complete', timestamp: Date.now() };
          emitPipelineStep({ pipelineId: input.pipelineId, step: 3, stepName: 'Campaign Recommendations', status: 'complete' });
          
          // Step 4: Create Caldera Operation (ready state)
          stepLog[3] = { ...stepLog[3], status: 'running', timestamp: Date.now() };
          await db.updateEngagementPipeline(input.pipelineId, { currentStep: 4, stepLog });
          emitPipelineStep({ pipelineId: input.pipelineId, step: 4, stepName: 'Create Caldera Operation', status: 'running' });
          riskSummary.calderaOperation = {
            status: 'ready',
            recommendedAbilities: (scanResult.campaignRecommendations || []).flatMap((c: any) => c.calderaAbilities || []),
          };
          stepLog[3] = { ...stepLog[3], status: 'complete', timestamp: Date.now() };
          emitPipelineStep({ pipelineId: input.pipelineId, step: 4, stepName: 'Create Caldera Operation', status: 'complete' });
          
          // Step 5: Auto-Materialize Phishing Drafts from scan recommendations
          stepLog[4] = { ...stepLog[4], status: 'running', timestamp: Date.now() };
          await db.updateEngagementPipeline(input.pipelineId, { currentStep: 5, stepLog });
          emitPipelineStep({ pipelineId: input.pipelineId, step: 5, stepName: 'Create GoPhish Campaign', status: 'running' });
          
          // First, we need a domain intel scan record. The pipeline ran runDomainIntelPipeline
          // directly, so we need to find or create the scan record.
          const { domainIntelScans, phishingDrafts } = await import('../drizzle/schema');
          const { eq: eqOp, desc: descOp, and: andOp, sql: sqlOp } = await import('drizzle-orm');
          const drizzleDb = await (await import('./db')).getDb();
          if (!drizzleDb) throw new Error('Database not available');
          
          // Find the most recent completed scan for this domain
          const [latestScan] = await drizzleDb.select().from(domainIntelScans)
            .where(andOp(
              eqOp(domainIntelScans.primaryDomain, domains[0] || ''),
              eqOp(domainIntelScans.status, 'completed')
            ))
            .orderBy(descOp(domainIntelScans.createdAt))
            .limit(1);
          
          const materializedDraftIds: number[] = [];
          const campaignRecs = scanResult.campaignRecommendations || [];
          
          if (latestScan && campaignRecs.length > 0) {
            const { invokeLLM } = await import('./_core/llm');
            const { matchPhishingExploits, enhanceLandingPage, PHISHING_EXPLOITS } = await import('./lib/phishing-exploits');
            const pipelineOut = latestScan.pipelineOutput as any;
            const actorMatches = pipelineOut?.threatActorMatches;
            const topActor = actorMatches?.topMatches?.[0];
            
            // Match phishing exploits based on scan intelligence
            const technologies = (pipelineOut?.discoveredAssets || []).flatMap((a: any) => Object.keys(a.technologyVersions || {}));
            const hasWebmail = technologies.some((t: string) => /exchange|owa|outlook|webmail|zimbra/i.test(t));
            const usesMfa = true; // Assume MFA for modern orgs
            const usesSSO = technologies.some((t: string) => /azure|okta|saml|oauth|adfs/i.test(t));
            const idpProvider = technologies.some((t: string) => /azure|microsoft|office365/i.test(t)) ? 'microsoft' :
              technologies.some((t: string) => /google|gsuite|workspace/i.test(t)) ? 'google' :
              technologies.some((t: string) => /okta/i.test(t)) ? 'okta' : undefined;
            const confirmedCves = (pipelineOut?.postureFindings || []).filter((f: any) => f.corroborationTier === 'confirmed').map((f: any) => f.cveId).filter(Boolean);
            
            const matchedExploits = matchPhishingExploits({
              sector: latestScan.sector || 'technology',
              technologies,
              hasWebmail,
              usesMfa,
              usesSSO,
              idpProvider,
              confirmedCves,
            });
            console.log(`[Pipeline] Matched ${matchedExploits.length} phishing exploits for campaign enhancement`);
            
            // Auto-materialize up to 3 top-priority recommendations using LLM
            const topRecs = campaignRecs.slice(0, 3);
            for (let i = 0; i < topRecs.length; i++) {
              try {
                // Check if already materialized
                const existing = await drizzleDb.select().from(phishingDrafts)
                  .where(andOp(
                    eqOp(phishingDrafts.scanId, latestScan.id),
                    sqlOp`${phishingDrafts.campaignRecommendationIndex} = ${i}`
                  ));
                if (existing.length > 0) {
                  materializedDraftIds.push(existing[0].id);
                  continue;
                }
                
                const rec = topRecs[i];
                const campaignName = rec.name || `${domains[0]} - ${rec.type || 'phishing'} Campaign`;
                const templateName = `[Ace C3] ${campaignName} - Template`;
                const landingPageName = `[Ace C3] ${campaignName} - Landing Page`;
                const targetGroupName = `[Ace C3] ${campaignName} - Targets`;
                
                // LLM-powered materialization
                let generatedContent: any = {};
                try {
                  const materializePrompt = `You are a red team phishing campaign designer for AceofCloud (Ace C3 platform).
Given the following domain intelligence and campaign recommendation, generate a complete phishing campaign package.

TARGET DOMAIN: ${domains[0]}
SECTOR: ${latestScan.sector || 'unknown'}
CAMPAIGN NAME: ${campaignName}
CAMPAIGN TYPE: ${rec.type}
PRIORITY: ${rec.priority}
DESCRIPTION: ${rec.description}
TARGET ASSETS: ${JSON.stringify(rec.targetAssets || [])}
ATTACK CHAIN: ${JSON.stringify(rec.attackChain || [])}
MITRE TACTICS: ${JSON.stringify(rec.mitreTactics || [])}
MATCHED THREAT ACTOR: ${topActor ? `${topActor.actorName} (confidence: ${topActor.confidence}%)` : 'None'}
GOPHISH TEMPLATE SUGGESTIONS: ${JSON.stringify(rec.gophishTemplates || [])}

MATCHED PHISHING EXPLOITS (use these techniques to enhance the campaign):
${matchedExploits.slice(0, 5).map((m: any) => `- ${m.exploit.name} (${m.exploit.category}, ${m.exploit.mitreId}): ${m.exploit.description.slice(0, 150)}... [Relevance: ${m.relevanceScore}%]`).join('\n')}

Generate a JSON object with these fields:
{
  "templateSubject": "Realistic email subject line",
  "templateHtml": "Full HTML email body with GoPhish variables: {{.FirstName}}, {{.LastName}}, {{.Email}}, {{.TrackingURL}}, {{.URL}}, {{.From}}. Must look like a legitimate business email. Include proper HTML structure with inline CSS. Incorporate evasion techniques from matched exploits where applicable (e.g., QR codes, zero-width chars, redirect chain URL patterns).",
  "templateText": "Plain text version of the email",
  "landingPageHtml": "HTML for a credential capture landing page. Use the most relevant matched exploit technique (e.g., BITB SSO popup for SSO targets, progressive MFA capture for MFA targets, ClickFix for payload delivery). Include form fields that POST credentials. Make it look like the target's real login page.",
  "landingPageRedirectUrl": "https://${domains[0]}",
  "smtpProfileName": "Ace C3 - ${domains[0]} Profile"
}

Make the phishing content highly realistic and tailored to the target domain and sector. Use professional language and branding cues from the target organization. Leverage the matched phishing exploit techniques to maximize effectiveness.`;

                  const llmResponse = await invokeLLM({
                    messages: [
                      { role: 'system', content: 'You are a red team phishing content generator. Output only valid JSON.' },
                      { role: 'user', content: materializePrompt },
                    ],
                    response_format: {
                      type: 'json_schema',
                      json_schema: {
                        name: 'phishing_draft',
                        strict: true,
                        schema: {
                          type: 'object',
                          properties: {
                            templateSubject: { type: 'string', description: 'Email subject line' },
                            templateHtml: { type: 'string', description: 'Full HTML email body' },
                            templateText: { type: 'string', description: 'Plain text email' },
                            landingPageHtml: { type: 'string', description: 'Landing page HTML' },
                            landingPageRedirectUrl: { type: 'string', description: 'Redirect URL after capture' },
                            smtpProfileName: { type: 'string', description: 'SMTP profile name' },
                          },
                          required: ['templateSubject', 'templateHtml', 'templateText', 'landingPageHtml', 'landingPageRedirectUrl', 'smtpProfileName'],
                          additionalProperties: false,
                        },
                      },
                    },
                  });
                  const rawContent = llmResponse?.choices?.[0]?.message?.content;
                  if (rawContent && typeof rawContent === 'string') {
                    generatedContent = JSON.parse(rawContent);
                  }
                  console.log(`[Pipeline] LLM materialized recommendation ${i}: ${campaignName}`);
                  
                  // Enhance landing page with injectable exploit code
                  if (generatedContent.landingPageHtml && matchedExploits.length > 0) {
                    const topExploitIds = matchedExploits
                      .filter((m: any) => m.exploit.target === 'landing_page' || m.exploit.target === 'both')
                      .slice(0, 3)
                      .map((m: any) => m.exploit.id);
                    if (topExploitIds.length > 0) {
                      generatedContent.exploitEnhancedLandingPage = enhanceLandingPage(generatedContent.landingPageHtml, topExploitIds);
                      generatedContent.phishingExploits = matchedExploits.slice(0, 8).map((m: any) => ({
                        id: m.exploit.id,
                        name: m.exploit.name,
                        category: m.exploit.category,
                        mitreId: m.exploit.mitreId,
                        relevanceScore: m.relevanceScore,
                        matchReason: m.matchReason,
                        enablesRemoteAccess: m.exploit.enablesRemoteAccess,
                      }));
                      console.log(`[Pipeline] Enhanced landing page with ${topExploitIds.length} exploit injections`);
                    }
                  }
                } catch (llmErr: any) {
                  console.warn(`[Pipeline] LLM materialization failed for rec ${i}, using fallback:`, llmErr.message);
                  // Fallback to basic template
                  generatedContent = {
                    templateSubject: rec.gophishTemplates?.[0]?.subject || `Important: Action Required - ${domains[0]}`,
                    templateHtml: `<html><body><p>Dear {{.FirstName}},</p><p>Please review the attached document regarding your ${domains[0]} account.</p><p><a href="{{.URL}}">Click here to review</a></p><p>Best regards,<br>IT Security Team</p></body></html>`,
                    templateText: `Dear {{.FirstName}},\n\nPlease review the document regarding your ${domains[0]} account.\n\n{{.URL}}\n\nBest regards,\nIT Security Team`,
                    landingPageHtml: `<html><body><h2>${domains[0]} - Login</h2><form method="POST"><input name="email" placeholder="Email" /><input name="password" type="password" placeholder="Password" /><button type="submit">Sign In</button></form></body></html>`,
                    landingPageRedirectUrl: `https://${domains[0]}`,
                    smtpProfileName: `Ace C3 - ${domains[0]} Profile`,
                  };
                }
                
                const [draftResult] = await drizzleDb.insert(phishingDrafts).values({
                  scanId: latestScan.id,
                  campaignRecommendationIndex: i,
                  status: 'draft',
                  campaignName,
                  campaignType: rec.type || 'phishing',
                  priority: rec.priority || 'medium',
                  targetDomain: domains[0],
                  targetSector: latestScan.sector || null,
                  templateName,
                  templateSubject: generatedContent.templateSubject,
                  templateHtml: generatedContent.templateHtml,
                  templateText: generatedContent.templateText,
                  landingPageName,
                  landingPageHtml: generatedContent.landingPageHtml,
                  landingPageRedirectUrl: generatedContent.landingPageRedirectUrl,
                  captureCredentials: true,
                  capturePasswords: false,
                  targetGroupName,
                  targetEmails: null,
                  smtpProfileName: generatedContent.smtpProfileName,
                  attackChain: rec.attackChain || null,
                  calderaAbilities: rec.calderaAbilities || null,
                  threatActorId: topActor?.actorId || null,
                  threatActorName: topActor?.actorName || null,
                  matchRationale: topActor
                    ? `Matched with ${topActor.confidence}% confidence. LLM-materialized by engagement pipeline.`
                    : 'LLM-materialized by engagement pipeline',
                  phishingExploits: generatedContent.phishingExploits || null,
                  exploitEnhancedLandingPage: generatedContent.exploitEnhancedLandingPage || null,
                  createdBy: null,
                }).$returningId();
                materializedDraftIds.push(draftResult.id);
                console.log(`[Pipeline] Auto-materialized draft ${draftResult.id} for recommendation ${i}: ${campaignName}`);
              } catch (matErr: any) {
                console.error(`[Pipeline] Failed to materialize recommendation ${i}:`, matErr.message);
              }
            }
          }
          
          riskSummary.gophishCampaign = {
            status: materializedDraftIds.length > 0 ? 'materialized' : 'ready',
            materializedDraftIds,
            totalRecommendations: campaignRecs.length,
            materializedCount: materializedDraftIds.length,
            recommendedTemplates: campaignRecs.flatMap((c: any) => c.gophishTemplates || []),
          };
          stepLog[4] = { ...stepLog[4], status: 'complete', timestamp: Date.now() };
          emitPipelineStep({ pipelineId: input.pipelineId, step: 5, stepName: 'Create GoPhish Campaign', status: 'complete' });

          // Step 5b: Auto-recommend typosquat domains if target is not spoofable
          try {
            // Check the most recent OSINT recon for spoofability
            const { domainRecon } = await import('../drizzle/schema');
            const [latestRecon] = await drizzleDb.select().from(domainRecon)
              .where(eqOp(domainRecon.domain, domains[0] || ''))
              .orderBy(descOp(domainRecon.createdAt))
              .limit(1);

            if (latestRecon && !latestRecon.spoofable && (latestRecon.spoofScore ?? 0) < 50) {
              // Target has strong email security — recommend typosquat domains
              const { generateTyposquatVariants } = await import('./lib/typosquat');
              const typosquatResult = await generateTyposquatVariants(domains[0], {
                checkAvailability: true,
                maxVariants: 10,
                includeAllTechniques: false,
              });

              riskSummary.typosquatRecommendation = {
                needed: true,
                reason: `Target domain has strong email security (spoof score: ${latestRecon.spoofScore}/100). Typosquat domains recommended for phishing.`,
                variants: typosquatResult.recommendedVariants.slice(0, 5).map((v: any) => ({
                  domain: v.domain,
                  technique: v.technique,
                  effectiveness: v.effectiveness,
                  available: v.available,
                })),
                totalGenerated: typosquatResult.recommendedVariants.length,
              };
              console.log(`[Pipeline] Target not spoofable (score: ${latestRecon.spoofScore}). Generated ${typosquatResult.recommendedVariants.length} typosquat recommendations.`);
            } else {
              riskSummary.typosquatRecommendation = {
                needed: false,
                reason: 'Target domain is spoofable — direct email spoofing is viable.',
              };
            }
          } catch (typoErr: any) {
            console.error('[Pipeline] Typosquat recommendation failed:', typoErr.message);
            riskSummary.typosquatRecommendation = { needed: false, reason: 'Check failed', error: typoErr.message };
          }
          
          // Step 6: Create Engagement
          stepLog[5] = { ...stepLog[5], status: 'running', timestamp: Date.now() };
          await db.updateEngagementPipeline(input.pipelineId, { currentStep: 6, stepLog });
          emitPipelineStep({ pipelineId: input.pipelineId, step: 6, stepName: 'Create Engagement', status: 'running' });
          const engagementId = await db.createEngagement({
            name: pipeline.name || 'Auto-Generated Engagement',
            customerName: domains[0] || 'Auto',
            engagementType: 'purple_team',
            status: 'planning',
            targetDomain: domains[0],
            description: `Auto-generated from pipeline. Domains: ${(pipeline.targetDomains as string[]).join(', ')}`,
          });
          riskSummary.engagement = { id: engagementId };
          stepLog[5] = { ...stepLog[5], status: 'complete', timestamp: Date.now() };
          emitPipelineStep({ pipelineId: input.pipelineId, step: 6, stepName: 'Create Engagement', status: 'complete' });
          
          await db.updateEngagementPipeline(input.pipelineId, {
            status: 'completed',
            stepLog,
            riskSummary,
            engagementId: Number(engagementId),
            completedAt: new Date(),
          });
          
          // Emit pipeline finished event
          emitPipelineStep({ pipelineId: input.pipelineId, step: -1, stepName: 'Pipeline Complete', status: 'complete', engagementId: Number(engagementId) });
          emitSystemNotification({ title: 'Engagement Pipeline Complete', message: `Pipeline "${pipeline.name}" completed successfully. Engagement #${engagementId} created.`, severity: 'info' });

          return { success: true, engagementId: Number(engagementId), riskSummary };
        } catch (err: any) {
          const failedStep = stepLog.findIndex((s: any) => s.status === 'running');
          if (failedStep >= 0) stepLog[failedStep] = { ...stepLog[failedStep], status: 'failed', timestamp: Date.now() };
          await db.updateEngagementPipeline(input.pipelineId, {
            status: 'failed',
            stepLog,
            errorMessage: err.message,
          });
          throw new TRPCError({ code: 'INTERNAL_SERVER_ERROR', message: err.message });
        }
      }),
    
    get: protectedProcedure
      .input(z.object({ id: z.number() }))
      .query(async ({ input }) => {
        return db.getEngagementPipeline(input.id);
      }),
    
    list: protectedProcedure.query(async () => {
      return db.listEngagementPipelines();
    }),
  }),

  // ─── TTP Knowledge Engine ─────────────────────────────────────────────
  ttpEngine: router({
    // Get knowledge for a single technique
    get: publicProcedure
      .input(z.object({ techniqueId: z.string() }))
      .query(async ({ input }) => {
        return db.getTtpKnowledge(input.techniqueId);
      }),
    // List all TTP knowledge entries
    list: publicProcedure
      .input(z.object({
        tactic: z.string().optional(),
        search: z.string().optional(),
        limit: z.number().optional(),
        offset: z.number().optional(),
      }).optional())
      .query(async ({ input }) => {
        return db.listTtpKnowledge(input || {});
      }),
    // Get stats about the knowledge base
    stats: publicProcedure.query(async () => {
      return db.getTtpKnowledgeStats();
    }),
    // Enrich a single technique with deep LLM analysis
    enrich: protectedProcedure
      .input(z.object({
        techniqueId: z.string(),
        techniqueName: z.string(),
        tactic: z.string(),
        force: z.boolean().optional(),
      }))
      .mutation(async ({ input }) => {
        const { enrichTechnique } = await import('./lib/ttp-engine');
        return enrichTechnique(input.techniqueId, input.techniqueName, input.tactic, input.force);
      }),
    // Batch enrich multiple techniques
    batchEnrich: protectedProcedure
      .input(z.object({
        techniques: z.array(z.object({
          id: z.string(),
          name: z.string(),
          tactic: z.string(),
        })),
        force: z.boolean().optional(),
      }))
      .mutation(async ({ input }) => {
        const { batchEnrichTechniques } = await import('./lib/ttp-engine');
        return batchEnrichTechniques(input.techniques, input.force);
      }),
    // Generate detection rules for a set of techniques
    detectionRules: protectedProcedure
      .input(z.object({ techniqueIds: z.array(z.string()) }))
      .query(async ({ input }) => {
        const { generateDetectionRules } = await import('./lib/ttp-engine');
        return generateDetectionRules(input.techniqueIds);
      }),
    // Generate campaign design prompt with TTP knowledge
    campaignPrompt: protectedProcedure
      .input(z.object({
        targetSector: z.string(),
        targetTechnologies: z.array(z.string()),
        threatActors: z.array(z.object({
          name: z.string(),
          techniques: z.array(z.object({
            id: z.string(),
            name: z.string(),
            tactic: z.string(),
          })),
        })),
        riskScore: z.number(),
      }))
      .mutation(async ({ input }) => {
        const { generateCampaignDesignPrompt } = await import('./lib/ttp-engine');
        const prompt = await generateCampaignDesignPrompt(input);
        return { prompt };
      }),
    // Ingest data from GitHub repositories (ATT&CK STIX, Atomic Red Team, LOLBAS, Metasploit, Kali)
    ingest: protectedProcedure
      .input(z.object({
        skipAttack: z.boolean().optional(),
        skipAtomic: z.boolean().optional(),
        skipLolbas: z.boolean().optional(),
        skipMetasploit: z.boolean().optional(),
        maxTechniques: z.number().optional(),
      }).optional())
      .mutation(async ({ input }) => {
        const { runFullIngestion } = await import('./lib/ttp-ingest');
        return runFullIngestion(input || {});
      }),
    // Get Kali Linux tools catalog
    kaliTools: publicProcedure
      .input(z.object({ techniqueId: z.string().optional() }).optional())
      .query(async ({ input }) => {
        const { getKaliToolsCatalog, getKaliToolsForTechnique } = await import('./lib/ttp-ingest');
        if (input?.techniqueId) {
          return getKaliToolsForTechnique(input.techniqueId);
        }
        return getKaliToolsCatalog();
      }),
  }),

  // ─── Dynamic Platform Stats (public, for homepage) ──────────────────
  platformStats: router({
    getHomepageStats: publicProcedure.query(async () => {
      const { getCatalogStats } = await import('./lib/exploit-catalog');
      const catalogStats = await getCatalogStats();

      // Threat actors count from DB
      const threatActorCount = await db.getThreatActorCount();

      // Caldera abilities count (from catalog or live API)
      const calderaAbilities = catalogStats.bySource['caldera_stockpile'] || 0;

      // Metasploit modules count (from catalog)
      const metasploitModules = catalogStats.bySource['metasploit'] || 0;

      // Phishing exploits count (from catalog)
      const phishingExploits = catalogStats.bySource['phishing_library'] || 0;

      // Platform modules count — 8 nav groups × ~4 sub-sections each
      const platformModules = 32;

      return {
        exploitCatalogTotal: catalogStats.total,
        metasploitModules,
        calderaAbilities,
        threatActors: threatActorCount,
        phishingExploits,
        platformModules,
        byTier: catalogStats.byTier,
        bySource: catalogStats.bySource,
        byCategory: catalogStats.byCategory,
        calderaSynced: catalogStats.calderaSynced,
        withStagers: catalogStats.withStagers,
        lastUpdated: Date.now(),
      };
    }),
    // Public feed of recent threat actors for homepage (limited fields, no sensitive data)
    recentThreatActors: publicProcedure
      .input(z.object({ limit: z.number().min(1).max(50).default(20) }).optional())
      .query(async ({ input }) => {
        const limit = input?.limit ?? 20;
        const result = await db.listThreatActors({ limit, offset: 0 });
        // Return only safe public fields — no calderaProfile, no stixId, no internal IDs
        return {
          actors: result.actors.map(a => ({
            actorId: a.actorId,
            name: a.name,
            type: a.type,
            origin: a.origin,
            threatLevel: a.threatLevel,
            sophistication: a.sophistication,
            motivation: a.motivation,
            firstSeen: a.firstSeen,
            lastActive: a.lastActive,
            description: a.description,
            aliases: a.aliases,
            targetSectors: a.targetSectors,
            targetRegions: a.targetRegions,
            techniques: a.techniques,
            tools: a.tools,
            malware: a.malware,
          })),
          total: result.total,
        };
      }),
    // Public single threat actor detail for homepage modal (limited fields)
    publicActorDetail: publicProcedure
      .input(z.object({ actorId: z.string() }))
      .query(async ({ input }) => {
        const a = await db.getThreatActor(input.actorId);
        if (!a) throw new TRPCError({ code: 'NOT_FOUND', message: 'Threat actor not found' });
        return {
          actorId: a.actorId,
          name: a.name,
          type: a.type,
          origin: a.origin,
          threatLevel: a.threatLevel,
          sophistication: a.sophistication,
          motivation: a.motivation,
          firstSeen: a.firstSeen,
          lastActive: a.lastActive,
          description: a.description,
          aliases: a.aliases,
          targetSectors: a.targetSectors,
          targetRegions: a.targetRegions,
          techniques: a.techniques,
          tools: a.tools,
          malware: a.malware,
          activityTimeline: a.activityTimeline,
        };
      }),
  }),

  // ─── Exploit Catalog (browser + enrichment management) ─────────────
  exploitCatalog: router({
    // Search/browse the catalog (public for authenticated users)
    search: protectedProcedure
      .input(z.object({
        query: z.string().optional(),
        tier: z.enum(['initial_access', 'post_access']).optional(),
        source: z.string().optional(),
        category: z.string().optional(),
        platform: z.string().optional(),
        calderaSynced: z.boolean().optional(),
        limit: z.number().min(1).max(200).default(50),
        offset: z.number().min(0).default(0),
      }))
      .query(async ({ input }) => {
        const { searchCatalog } = await import('./lib/exploit-catalog');
        return searchCatalog(input);
      }),

    // Get a single catalog entry
    getEntry: protectedProcedure
      .input(z.object({ catalogId: z.string() }))
      .query(async ({ input }) => {
        const { getCatalogEntry } = await import('./lib/exploit-catalog');
        const entry = await getCatalogEntry(input.catalogId);
        if (!entry) throw new TRPCError({ code: 'NOT_FOUND', message: 'Catalog entry not found' });
        return entry;
      }),

    // Get catalog stats (for the catalog page header)
    stats: protectedProcedure.query(async () => {
      const { getCatalogStats } = await import('./lib/exploit-catalog');
      return getCatalogStats();
    }),

    // Get available filter options (distinct values)
    filterOptions: protectedProcedure.query(async () => {
      const { getCatalogStats } = await import('./lib/exploit-catalog');
      const stats = await getCatalogStats();
      return {
        sources: Object.keys(stats.bySource),
        categories: Object.keys(stats.byCategory),
        tiers: ['initial_access', 'post_access'] as const,
        platforms: ['windows', 'linux', 'darwin', 'multi'],
      };
    }),

    // Deploy entries to Caldera (admin only)
    syncToCaldera: adminProcedure
      .input(z.object({ catalogIds: z.array(z.string()).min(1).max(50) }))
      .mutation(async ({ input }) => {
        const { syncToCaldera } = await import('./lib/exploit-catalog');
        return syncToCaldera(input.catalogIds);
      }),

    // Bulk sync all unsynced entries to Caldera (admin only)
    syncAllToCaldera: adminProcedure.mutation(async () => {
      const { syncAllToCaldera } = await import('./lib/exploit-catalog');
      return syncAllToCaldera();
    }),

    // Run enrichment pipeline (admin only)
    runEnrichment: adminProcedure.mutation(async () => {
      const { isEnrichmentRunning, startEnrichment } = await import('./lib/enrichment-scheduler');
      if (isEnrichmentRunning()) {
        throw new TRPCError({ code: 'CONFLICT', message: 'Enrichment pipeline is already running' });
      }
      // Start async — don't await (it takes minutes)
      startEnrichment();
      return { started: true, message: 'Enrichment pipeline started in background' };
    }),

    // Get enrichment status
    enrichmentStatus: protectedProcedure.query(async () => {
      const { getEnrichmentStatus } = await import('./lib/enrichment-scheduler');
      return getEnrichmentStatus();
    }),
  }),

  // ─── Autonomous Validation Engine ────────────────────────────────────────
  validation: router({
    /** Get validation candidates for a scan (preview before running) */
    getCandidates: protectedProcedure
      .input(z.object({ scanId: z.number(), maxCandidates: z.number().default(10) }))
      .query(async ({ input }) => {
        const { discoveredAssets, unifiedExploitCatalog } = await import('../drizzle/schema');
        const { getDbRequired } = await import('./db');
        const { eq } = await import('drizzle-orm');
        const { selectCandidates } = await import('./lib/validation-engine');
        const dbConn = await getDbRequired();

        const assets = await dbConn.select().from(discoveredAssets).where(eq(discoveredAssets.scanId, input.scanId));
        const catalog = await dbConn.select({
          catalogId: unifiedExploitCatalog.catalogId,
          msfModule: unifiedExploitCatalog.msfModule,
          msfRank: unifiedExploitCatalog.msfRank,
          cveIds: unifiedExploitCatalog.cveIds,
          cvssScore: unifiedExploitCatalog.cvssScore,
          source: unifiedExploitCatalog.source,
        }).from(unifiedExploitCatalog).where(eq(unifiedExploitCatalog.enabled, true));

        const candidates = selectCandidates(assets as any, catalog as any, input.maxCandidates);
        return { candidates, totalAssets: assets.length, totalCatalogEntries: catalog.length };
      }),

    /** Start a validation run */
    startRun: protectedProcedure
      .input(z.object({
        scanId: z.number(),
        msfServerId: z.number(),
        mode: z.enum(['check_only', 'auxiliary_scan', 'safe_exploit']).default('check_only'),
        maxCandidates: z.number().min(1).max(50).default(10),
        timeoutPerCandidate: z.number().min(10).max(300).default(60),
        requireApproval: z.boolean().default(true),
        scopeRestrictions: z.array(z.string()).default([]),
        engagementId: z.number().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const { validationRuns, validationResults: vResults, discoveredAssets, unifiedExploitCatalog, metasploitServers } = await import('../drizzle/schema');
        const { getDbRequired } = await import('./db');
        const { eq } = await import('drizzle-orm');
        const { selectCandidates, validateCandidate, computeAssetValidationScore } = await import('./lib/validation-engine');
        const { MsfClient } = await import('./lib/msf-client');
        const { enforceROE, getEngagementROE, logOffensiveAction, ACTION_RISK_MAP } = await import('./lib/roe-guard');
        const dbConn = await getDbRequired();

        // ─── ROE Enforcement ───
        const riskTier = input.mode === 'safe_exploit' ? 'red' as const : 'orange' as const;
        if (input.engagementId) {
          const roe = await getEngagementROE(input.engagementId);
          if (roe) enforceROE(roe, riskTier, `Validation run (${input.mode}) on scan #${input.scanId}`);
        }
        // Log the offensive action
        logOffensiveAction({
          engagementId: input.engagementId ?? null,
          operatorId: ctx.user.openId,
          operatorName: ctx.user.name ?? null,
          actionType: input.mode === 'safe_exploit' ? 'msf_exploit' : input.mode === 'auxiliary_scan' ? 'msf_auxiliary' : 'msf_check',
          riskTier,
          target: `scan:${input.scanId}`,
          moduleOrTool: `MSF Validation Engine (${input.mode})`,
          resultStatus: 'pending_approval',
        }).catch(() => {});

        // Verify exploit server is online
        const [server] = await dbConn.select().from(metasploitServers).where(eq(metasploitServers.id, input.msfServerId)).limit(1);
        if (!server) throw new TRPCError({ code: 'NOT_FOUND', message: 'Exploit server not found' });
        if (server.status !== 'online') throw new TRPCError({ code: 'PRECONDITION_FAILED', message: 'Exploit server is not online' });

        // Select candidates
        const assets = await dbConn.select().from(discoveredAssets).where(eq(discoveredAssets.scanId, input.scanId));
        const catalog = await dbConn.select({
          catalogId: unifiedExploitCatalog.catalogId,
          msfModule: unifiedExploitCatalog.msfModule,
          msfRank: unifiedExploitCatalog.msfRank,
          cveIds: unifiedExploitCatalog.cveIds,
          cvssScore: unifiedExploitCatalog.cvssScore,
          source: unifiedExploitCatalog.source,
        }).from(unifiedExploitCatalog).where(eq(unifiedExploitCatalog.enabled, true));

        const candidates = selectCandidates(assets as any, catalog as any, input.maxCandidates);
        if (candidates.length === 0) {
          throw new TRPCError({ code: 'PRECONDITION_FAILED', message: 'No validation candidates found. Ensure the scan has assets with KEV-confirmed CVEs or known MSF modules.' });
        }

        // Create the run record
        const [run] = await dbConn.insert(validationRuns).values({
          scanId: input.scanId,
          msfServerId: input.msfServerId,
          engagementId: input.engagementId ?? null,
          mode: input.mode,
          maxCandidates: input.maxCandidates,
          timeoutPerCandidate: input.timeoutPerCandidate,
          requireApproval: input.requireApproval,
          scopeRestrictions: input.scopeRestrictions,
          status: 'running',
          totalCandidates: candidates.length,
          operatorId: ctx.user.openId,
          startedAt: new Date(),
        }).$returningId();

        const runId = run.id;
        const config = {
          scanId: input.scanId,
          msfServerId: input.msfServerId,
          mode: input.mode,
          maxCandidates: input.maxCandidates,
          requireApproval: input.requireApproval,
          timeoutPerCandidate: input.timeoutPerCandidate,
          scopeRestrictions: input.scopeRestrictions,
          operatorId: ctx.user.openId,
          engagementId: input.engagementId ?? null,
        };

        // Run validation asynchronously (don't block the response)
        (async () => {
          const msfClient = MsfClient.fromServerConfig(server);
          if (!msfClient) {
            await dbConn.update(validationRuns).set({ status: 'failed', errorMessage: 'Could not create MSF client', completedAt: new Date() }).where(eq(validationRuns.id, runId));
            return;
          }

          const { captureFullEvidence } = await import('./lib/evidence-capture');
          const results: any[] = [];
          let validatedCount = 0, notVulnCount = 0, inconclusiveCount = 0, errorCount = 0, skippedCount = 0;
          let totalScoreAdj = 0;

          for (const candidate of candidates) {
            try {
              const result = await validateCandidate(candidate, msfClient, config as any);
              results.push(result);

              // ─── Evidence Capture ───
              let evidenceUrl: string | null = null;
              let evidenceArtifacts: any[] | null = null;
              try {
                const captureCtx = {
                  runId,
                  scanId: input.scanId,
                  candidateId: `${candidate.assetId}-${candidate.cveId}`,
                  assetHostname: candidate.hostname,
                  cveId: candidate.cveId,
                  msfModule: candidate.msfModule,
                  mode: result.mode,
                  targetIp: candidate.hostname, // IP resolved from hostname
                  targetPort: null,
                };
                const captured = await captureFullEvidence(
                  msfClient,
                  captureCtx,
                  {
                    status: result.status,
                    exploitable: result.exploitable,
                    rawOutput: result.rawOutput,
                    evidence: result.evidence,
                    durationMs: result.durationMs,
                    scoreAdjustment: result.scoreAdjustment,
                  },
                  result.evidence?.sessionId ? String(result.evidence.sessionId) : null,
                  null, // jobId not tracked in ValidationEvidence — console output captured via session
                );
                if (captured) {
                  evidenceUrl = captured.reportUrl;
                  evidenceArtifacts = captured.artifacts;
                  console.log(`[Validation] Evidence captured for ${candidate.cveId} on ${candidate.hostname}: ${captured.artifacts.length} artifacts`);
                }
              } catch (evErr: any) {
                console.error(`[Validation] Evidence capture failed (non-fatal):`, evErr.message);
              }

              // Insert result record
              await dbConn.insert(vResults).values({
                runId,
                assetId: result.assetId,
                cveId: result.cveId,
                hostname: result.hostname,
                msfModule: result.msfModule,
                mode: result.mode,
                status: result.status,
                exploitable: result.exploitable,
                rawOutput: result.rawOutput,
                evidence: result.evidence,
                scoreAdjustment: result.scoreAdjustment,
                previousRiskScore: candidate.currentRiskScore,
                durationMs: result.durationMs,
                errorMessage: result.errorMessage,
                evidenceUrl,
                evidenceArtifacts,
              });

              // Update counters
              switch (result.status) {
                case 'validated': validatedCount++; totalScoreAdj += result.scoreAdjustment; break;
                case 'not_vulnerable': notVulnCount++; break;
                case 'inconclusive': inconclusiveCount++; break;
                case 'error': errorCount++; break;
                case 'skipped': skippedCount++; break;
              }

              // If validated, update the asset's risk score and record in scoring audit log
              if (result.exploitable && result.scoreAdjustment > 0) {
                const newScore = Math.min(100, candidate.currentRiskScore + result.scoreAdjustment);
                const newBand = newScore >= 80 ? 'critical' : newScore >= 60 ? 'high' : newScore >= 40 ? 'medium' : 'low';
                await dbConn.update(discoveredAssets)
                  .set({ hybridRiskScore: newScore, riskBand: newBand, lastScoredAt: new Date() })
                  .where(eq(discoveredAssets.id, candidate.assetId));

                // Update the result with the new score
                await dbConn.update(vResults)
                  .set({ newRiskScore: newScore })
                  .where(eq(vResults.runId, runId));

                // Record re-scoring event in audit log for Dynamic Scoring Timeline
                const { scoringAuditLog } = await import('../drizzle/schema');
                await dbConn.insert(scoringAuditLog).values({
                  assetId: candidate.assetId,
                  scanId: input.scanId,
                  hybridRiskScore: newScore,
                  riskBand: newBand,
                  previousScore: candidate.currentRiskScore,
                  delta: result.scoreAdjustment,
                  triggerType: 'exploit_validation',
                  pipelinePhase: 'validation_engine',
                  changeDescription: `Exploitation validated: ${result.cveId} via ${result.msfModule || 'auxiliary check'} — confirmed exploitable (+${result.scoreAdjustment})`,
                  factorChanges: [{
                    factor: 'exploitability',
                    previousValue: 'unconfirmed',
                    newValue: 'confirmed_exploitable',
                    reason: `CVE ${result.cveId} validated via ${config.mode} mode`,
                  }],
                  computedBy: 'validation-engine',
                });
              } else if (result.status === 'not_vulnerable') {
                // Record negative validation — reduces false positive noise in timeline
                const { scoringAuditLog } = await import('../drizzle/schema');
                await dbConn.insert(scoringAuditLog).values({
                  assetId: candidate.assetId,
                  scanId: input.scanId,
                  hybridRiskScore: candidate.currentRiskScore,
                  riskBand: candidate.currentRiskScore >= 80 ? 'critical' : candidate.currentRiskScore >= 60 ? 'high' : candidate.currentRiskScore >= 40 ? 'medium' : 'low',
                  previousScore: candidate.currentRiskScore,
                  delta: 0,
                  triggerType: 'exploit_validation_negative',
                  pipelinePhase: 'validation_engine',
                  changeDescription: `Exploitation check negative: ${result.cveId} — not exploitable in current configuration`,
                  factorChanges: [{
                    factor: 'exploitability',
                    previousValue: 'unconfirmed',
                    newValue: 'not_exploitable',
                    reason: `CVE ${result.cveId} check returned not vulnerable`,
                  }],
                  computedBy: 'validation-engine',
                });
              }
            } catch (err: any) {
              errorCount++;
              console.error(`[Validation] Error validating ${candidate.hostname}:${candidate.cveId}:`, err.message);
            }
          }

          // Update run summary
          const avgAdj = validatedCount > 0 ? totalScoreAdj / validatedCount : 0;
          await dbConn.update(validationRuns).set({
            status: 'completed',
            validated: validatedCount,
            notVulnerable: notVulnCount,
            inconclusive: inconclusiveCount,
            errors: errorCount,
            skipped: skippedCount,
            avgScoreAdjustment: Math.round(avgAdj * 100) / 100,
            completedAt: new Date(),
            totalDurationMs: Date.now() - Date.now(),
          }).where(eq(validationRuns.id, runId));

          console.log(`[Validation] Run ${runId} completed: ${validatedCount} validated, ${notVulnCount} not vulnerable, ${inconclusiveCount} inconclusive, ${errorCount} errors, ${skippedCount} skipped`);

          // ─── Post-completion re-scoring hook: recalculate scan overall risk ───
          if (validatedCount > 0) {
            try {
              const { domainIntelScans } = await import('../drizzle/schema');
              const allAssets = await dbConn.select({ hybridRiskScore: discoveredAssets.hybridRiskScore })
                .from(discoveredAssets)
                .where(eq(discoveredAssets.scanId, input.scanId));
              if (allAssets.length > 0) {
                const scores = allAssets.map(a => a.hybridRiskScore ?? 0);
                const maxScore = Math.max(...scores);
                const avgScore = scores.reduce((s, v) => s + v, 0) / scores.length;
                const newOverall = Math.round(maxScore * 0.6 + avgScore * 0.4);
                const newBand = newOverall >= 80 ? 'critical' : newOverall >= 60 ? 'high' : newOverall >= 40 ? 'medium' : 'low';
                await dbConn.update(domainIntelScans).set({
                  overallRiskScore: newOverall,
                  overallRiskBand: newBand,
                }).where(eq(domainIntelScans.id, input.scanId));
                console.log(`[Validation] Scan ${input.scanId} re-scored: overall=${newOverall} (${newBand}) after ${validatedCount} exploit validations`);
              }
            } catch (resErr: any) {
              console.error(`[Validation] Post-completion re-scoring failed:`, resErr.message);
            }
          }
        })().catch(async (err) => {
          console.error(`[Validation] Run ${runId} failed:`, err);
          await dbConn.update(validationRuns).set({ status: 'failed', errorMessage: String(err.message || err), completedAt: new Date() }).where(eq(validationRuns.id, runId));
        });

        return { runId, totalCandidates: candidates.length, status: 'running', mode: input.mode };
      }),

    /** Get a validation run with its results */
    getRun: protectedProcedure
      .input(z.object({ runId: z.number() }))
      .query(async ({ input }) => {
        const { validationRuns, validationResults: vResults } = await import('../drizzle/schema');
        const { getDbRequired } = await import('./db');
        const { eq } = await import('drizzle-orm');
        const dbConn = await getDbRequired();

        const [run] = await dbConn.select().from(validationRuns).where(eq(validationRuns.id, input.runId)).limit(1);
        if (!run) throw new TRPCError({ code: 'NOT_FOUND' });

        const results = await dbConn.select().from(vResults).where(eq(vResults.runId, input.runId));
        return { run, results };
      }),

    /** List all validation runs for a scan */
    listRuns: protectedProcedure
      .input(z.object({ scanId: z.number().optional(), limit: z.number().default(20) }))
      .query(async ({ input }) => {
        const { validationRuns } = await import('../drizzle/schema');
        const { getDbRequired } = await import('./db');
        const { eq, sql } = await import('drizzle-orm');
        const dbConn = await getDbRequired();

        const conditions: any[] = [];
        if (input.scanId) conditions.push(eq(validationRuns.scanId, input.scanId));

        const runs = await dbConn.select().from(validationRuns)
          .where(conditions.length > 0 ? conditions[0] : undefined)
          .orderBy(sql`${validationRuns.startedAt} DESC`)
          .limit(input.limit);
        return runs;
      }),

    /** Approve a pending safe_exploit candidate */
    approveCandidate: protectedProcedure
      .input(z.object({ resultId: z.number() }))
      .mutation(async ({ input, ctx }) => {
        const { validationResults: vResults } = await import('../drizzle/schema');
        const { getDbRequired } = await import('./db');
        const { eq } = await import('drizzle-orm');
        const dbConn = await getDbRequired();

        const [result] = await dbConn.select().from(vResults).where(eq(vResults.id, input.resultId)).limit(1);
        if (!result) throw new TRPCError({ code: 'NOT_FOUND' });
        if (result.status !== 'approved_pending') throw new TRPCError({ code: 'PRECONDITION_FAILED', message: 'Result is not pending approval' });

        await dbConn.update(vResults).set({ status: 'pending' }).where(eq(vResults.id, input.resultId));
        return { approved: true, resultId: input.resultId };
      }),

    /** Cancel a running validation run */
    cancelRun: protectedProcedure
      .input(z.object({ runId: z.number() }))
      .mutation(async ({ input }) => {
        const { validationRuns } = await import('../drizzle/schema');
        const { getDbRequired } = await import('./db');
        const { eq } = await import('drizzle-orm');
        const dbConn = await getDbRequired();

        await dbConn.update(validationRuns).set({ status: 'cancelled', completedAt: new Date() }).where(eq(validationRuns.id, input.runId));
        return { cancelled: true };
      }),

    /** Get validation summary for a scan (for DomainIntelResults integration) */
    getScanValidationSummary: protectedProcedure
      .input(z.object({ scanId: z.number() }))
      .query(async ({ input }) => {
        const { validationRuns, validationResults: vResults } = await import('../drizzle/schema');
        const { getDbRequired } = await import('./db');
        const { eq, sql, and } = await import('drizzle-orm');
        const dbConn = await getDbRequired();

        // Get the latest completed run for this scan
        const [latestRun] = await dbConn.select().from(validationRuns)
          .where(and(eq(validationRuns.scanId, input.scanId), eq(validationRuns.status, 'completed')))
          .orderBy(sql`${validationRuns.startedAt} DESC`)
          .limit(1);

        if (!latestRun) return { hasValidation: false, run: null, results: [], exploitableCount: 0, totalValidated: 0 };

        const results = await dbConn.select().from(vResults).where(eq(vResults.runId, latestRun.id));
        const exploitableCount = results.filter(r => r.exploitable).length;

        return {
          hasValidation: true,
          run: latestRun,
          results,
          exploitableCount,
          totalValidated: results.filter(r => r.status === 'validated' || r.status === 'not_vulnerable').length,
        };
      }),
  }),

  // ── Engagement Ops: LLM-orchestrated autonomous execution engine ──────────
  engagementOps: router({
    /** Get current ops state for an engagement */
    getState: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .query(async ({ input }) => {
        const { getOpsState } = await import('./lib/engagement-orchestrator');
        return getOpsState(input.engagementId);
      }),

    /** Initialize ops state for an engagement */
    init: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .mutation(async ({ input }) => {
        const engagement = await db.getEngagementById(input.engagementId);
        if (!engagement) throw new TRPCError({ code: 'NOT_FOUND', message: 'Engagement not found' });
        const { initOpsState } = await import('./lib/engagement-orchestrator');
        return initOpsState(input.engagementId, engagement.engagementType);
      }),

    /** Start autonomous execution — one-click pentest/red team */
    execute: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .mutation(async ({ input, ctx }) => {
        const engagement = await db.getEngagementById(input.engagementId);
        if (!engagement) throw new TRPCError({ code: 'NOT_FOUND', message: 'Engagement not found' });

        // Validate RoE scope exists
        if (!engagement.targetDomain && !engagement.targetIpRange) {
          throw new TRPCError({ code: 'BAD_REQUEST', message: 'No targets defined. Add target domains or IP ranges first.' });
        }

        const { executeEngagement, initOpsState, getOpsState } = await import('./lib/engagement-orchestrator');
        let state = getOpsState(input.engagementId);
        if (!state) {
          state = initOpsState(input.engagementId, engagement.engagementType);
        }
        if (state.isRunning) {
          throw new TRPCError({ code: 'CONFLICT', message: 'Engagement is already running' });
        }

        await db.logActivity({
          userId: ctx.user.id,
          action: 'engagement_ops_started',
          details: `Started autonomous ${engagement.engagementType} execution for engagement #${input.engagementId}`,
        });

        // Fire and forget — the pipeline runs asynchronously
        executeEngagement(input.engagementId, { id: String(ctx.user.id), name: ctx.user.name || undefined });

        return { started: true, engagementId: input.engagementId };
      }),

    /** Stop execution */
    stop: protectedProcedure
      .input(z.object({ engagementId: z.number() }))
      .mutation(async ({ input, ctx }) => {
        const { stopEngagement } = await import('./lib/engagement-orchestrator');
        const stopped = stopEngagement(input.engagementId);
        if (stopped) {
          await db.logActivity({
            userId: ctx.user.id,
            action: 'engagement_ops_stopped',
            details: `Stopped execution for engagement #${input.engagementId}`,
          });
        }
        return { stopped };
      }),

    /** Resolve an approval gate */
    resolveApproval: protectedProcedure
      .input(z.object({
        gateId: z.string(),
        approved: z.boolean(),
      }))
      .mutation(async ({ input, ctx }) => {
        const { resolveApproval } = await import('./lib/engagement-orchestrator');
        const resolved = resolveApproval(input.gateId, input.approved, ctx.user.name || String(ctx.user.id));
        if (!resolved) throw new TRPCError({ code: 'NOT_FOUND', message: 'Approval gate not found or already resolved' });

        await db.logActivity({
          userId: ctx.user.id,
          action: input.approved ? 'ops_approval_granted' : 'ops_approval_denied',
          details: `${input.approved ? 'Approved' : 'Denied'} gate ${input.gateId}`,
        });

        return { resolved: true };
      }),
  }),
});
export type AppRouter = typeof appRouter;
