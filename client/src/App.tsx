import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { Route, Switch, Redirect, useLocation } from "wouter";
import { ErrorBoundary, PageErrorBoundary } from "./components/ErrorBoundary";
import { ThemeProvider } from "./contexts/ThemeContext";
import { trpc } from "@/lib/trpc";
import { Skeleton } from "@/components/ui/skeleton";
import { lazy, Suspense, useEffect } from "react";

/**
 * Wrapper around React.lazy that auto-recovers from stale chunk errors.
 * When a deployment ships new chunk hashes but the browser has a cached index.html
 * referencing old hashes, dynamic imports will 404. This wrapper detects that
 * and forces a single page reload to fetch the fresh index.html.
 */
function lazyWithRetry<T extends React.ComponentType<any>>(
  factory: () => Promise<{ default: T }>
): React.LazyExoticComponent<T> {
  return lazy(() =>
    factory().catch((err: any) => {
      const isChunkError =
        err?.message?.includes("Failed to fetch dynamically imported module") ||
        err?.message?.includes("Importing a module script failed") ||
        err?.message?.includes("Loading chunk") ||
        err?.message?.includes("Loading CSS chunk") ||
        err?.message?.includes("is not a valid JavaScript MIME type") ||
        err?.message?.includes("before initialization") ||
        err?.name === "ChunkLoadError" ||
        (err?.name === "TypeError" && err?.message?.includes("module"));

      if (isChunkError) {
        // Only reload once per session to avoid infinite reload loops
        const reloadKey = "__ac3_chunk_reload";
        const lastReload = sessionStorage.getItem(reloadKey);
        const now = Date.now();
        if (!lastReload || now - parseInt(lastReload, 10) > 30000) {
          sessionStorage.setItem(reloadKey, String(now));
          console.warn("[AC3] Stale chunk detected, reloading page...", err.message);
          window.location.reload();
        }
      }
      // Re-throw so ErrorBoundary still catches if reload didn't help
      throw err;
    })
  );
}

const GlobalAiChat = lazyWithRetry(() => import("./components/GlobalAiChat").then(m => ({ default: m.GlobalAiChat })));
const CommandPalette = lazyWithRetry(() => import("./components/CommandPalette").then(m => ({ default: m.CommandPalette })));
const DashboardLayout = lazyWithRetry(() => import("./components/DashboardLayout"));
const SessionTimeoutMonitor = lazyWithRetry(() => import("./components/SessionTimeoutMonitor").then(m => ({ default: m.SessionTimeoutMonitor })));
import { useErrorCapture } from "./hooks/useErrorCapture";
import { EngagementProvider } from "./contexts/EngagementContext";

// ─── Lazy-loaded pages (reduces initial bundle / HTTP requests) ──────────────
const Home = lazyWithRetry(() => import("./pages/Home"));
const Login = lazyWithRetry(() => import("./pages/Login"));
const NotFound = lazyWithRetry(() => import("./pages/NotFound"));
const Dashboard = lazyWithRetry(() => import("./pages/Dashboard"));
const AdversaryDetail = lazyWithRetry(() => import("./pages/AdversaryDetail"));
const Team = lazyWithRetry(() => import("./pages/Team"));
const Activity = lazyWithRetry(() => import("./pages/Activity"));
const Campaigns = lazyWithRetry(() => import("./pages/Campaigns"));
const CampaignDetail = lazyWithRetry(() => import("./pages/CampaignDetail"));
const Agents = lazyWithRetry(() => import("./pages/Agents"));
const AgentDeploy = lazyWithRetry(() => import("./pages/AgentDeploy"));
const OperationMonitor = lazyWithRetry(() => import("./pages/OperationMonitor"));
const ReportGenerator = lazyWithRetry(() => import("./pages/ReportGenerator"));
const OperationDetail = lazyWithRetry(() => import("./pages/OperationDetail"));
const GoPhish = lazyWithRetry(() => import("./pages/GoPhish"));
const PhishingOperations = lazyWithRetry(() => import("./pages/PhishingOperations"));
const GoPhishGuide = lazyWithRetry(() => import("./pages/GoPhishGuide"));
const CalderaGuide = lazyWithRetry(() => import("./pages/CalderaGuide"));
const ComplianceFrameworks = lazyWithRetry(() => import("./pages/ComplianceFrameworks"));
const InfraReference = lazyWithRetry(() => import("./pages/InfraReference"));
const TemplateLibrary = lazyWithRetry(() => import("./pages/TemplateLibrary"));
const Engagements = lazyWithRetry(() => import("./pages/Engagements"));
const CampaignWizard = lazyWithRetry(() => import("./pages/CampaignWizard"));
const CampaignOrchestrator = lazyWithRetry(() => import("./pages/CampaignOrchestrator"));
const EngagementResults = lazyWithRetry(() => import("./pages/EngagementResults"));
const OsintRecon = lazyWithRetry(() => import("./pages/OsintRecon"));
const DomainIntel = lazyWithRetry(() => import("./pages/DomainIntel"));
const DomainIntelResults = lazyWithRetry(() => import("./pages/DomainIntelResults"));
const ScanScheduler = lazyWithRetry(() => import("./pages/ScanScheduler"));
const TemplateGenerator = lazyWithRetry(() => import("./pages/TemplateGenerator"));
const AbilitiesLibrary = lazyWithRetry(() => import("./pages/AbilitiesLibrary"));
const IOCFeed = lazyWithRetry(() => import("./pages/IOCFeed"));
const EngagementPipeline = lazyWithRetry(() => import("./pages/EngagementPipeline"));
const EngagementOps = lazyWithRetry(() => import("./pages/EngagementOps"));
const ThreatActorDetail = lazyWithRetry(() => import("./pages/ThreatActorDetail"));
const TtpKnowledge = lazyWithRetry(() => import("./pages/TtpKnowledge"));
const CampaignExecution = lazyWithRetry(() => import("./pages/CampaignExecution"));
const RuleValidator = lazyWithRetry(() => import("./pages/RuleValidator"));
const DetectionCoverage = lazyWithRetry(() => import("./pages/DetectionCoverage"));
const PostEngagementReport = lazyWithRetry(() => import("./pages/PostEngagementReport"));
const LandingPageBuilder = lazyWithRetry(() => import("./pages/LandingPageBuilder"));
const DiscoveryCuration = lazyWithRetry(() => import("./pages/DiscoveryCuration"));
const KevDashboard = lazyWithRetry(() => import("./pages/KevDashboard"));
const ScanComparison = lazyWithRetry(() => import("./pages/ScanComparison"));
const ThreatCatalog = lazyWithRetry(() => import("./pages/ThreatCatalog"));
const ThreatActorCatalogDetail = lazyWithRetry(() => import("./pages/ThreatActorCatalogDetail"));
const DarkwebIntel = lazyWithRetry(() => import("./pages/DarkwebIntel"));
const BreachEvents = lazyWithRetry(() => import("./pages/BreachEvents"));
const ThreatIntelHub = lazyWithRetry(() => import("./pages/ThreatIntelHub"));
const ThreatGroupBrowser = lazyWithRetry(() => import("./pages/ThreatGroupBrowser"));
const TrainingLab = lazyWithRetry(() => import("./pages/TrainingLab"));
const CampaignArchetypes = lazyWithRetry(() => import("./pages/CampaignArchetypes"));
const ExploitArsenal = lazyWithRetry(() => import("./pages/ExploitArsenal"));
const ExploitKnowledge = lazyWithRetry(() => import("./pages/ExploitKnowledge"));
const CustomExploitRepository = lazyWithRetry(() => import("./pages/CustomExploitRepository"));
const MsfServers = lazyWithRetry(() => import("./pages/MsfServers"));
const SshKeyManager = lazyWithRetry(() => import("./pages/SshKeyManager"));
const MsfSessions = lazyWithRetry(() => import("./pages/MsfSessions"));
const SessionRecordings = lazyWithRetry(() => import("./pages/SessionRecordings"));
const PostExploitPlaybooks = lazyWithRetry(() => import("./pages/PostExploitPlaybooks"));
const FileTransfers = lazyWithRetry(() => import("./pages/FileTransfers"));
const PayloadGenerator = lazyWithRetry(() => import("./pages/PayloadGenerator"));
const EngagementTimeline = lazyWithRetry(() => import("./pages/EngagementTimeline"));
const StixExport = lazyWithRetry(() => import("./pages/StixExport"));
const ClientPortal = lazyWithRetry(() => import("./pages/ClientPortal"));
const CustomerPortalLogin = lazyWithRetry(() => import("./pages/CustomerPortalLogin"));
const CustomerPortalDashboard = lazyWithRetry(() => import("./pages/CustomerPortalDashboard"));
const CustomerAccounts = lazyWithRetry(() => import("./pages/CustomerAccounts"));
const EmulationPlaybooks = lazyWithRetry(() => import("./pages/EmulationPlaybooks"));
const EvidenceCollection = lazyWithRetry(() => import("./pages/EvidenceCollection"));
const EvidenceGallery = lazyWithRetry(() => import("./pages/EvidenceGallery"));
const EvidenceIntegrity = lazyWithRetry(() => import("./pages/EvidenceIntegrity"));
const AttackPaths = lazyWithRetry(() => import("./pages/AttackPaths"));
const PurpleTeam = lazyWithRetry(() => import("./pages/PurpleTeam"));
const Webhooks = lazyWithRetry(() => import("./pages/Webhooks"));
const BugBountyHub = lazyWithRetry(() => import("./pages/BugBountyHub"));
const ScoringHub = lazyWithRetry(() => import("./pages/ScoringHub"));
const BiaReport = lazyWithRetry(() => import("./pages/BiaReport"));
const ValidationEngine = lazyWithRetry(() => import("./pages/ValidationEngine"));
const EvasionEngine = lazyWithRetry(() => import("./pages/EvasionEngine"));
const SiemConnectors = lazyWithRetry(() => import("./pages/SiemConnectors"));
const ScanHistory = lazyWithRetry(() => import("./pages/ScanHistory"));
const TrainingDashboard = lazyWithRetry(() => import("./pages/TrainingDashboard"));
const BatchTraining = lazyWithRetry(() => import("./pages/BatchTraining"));
const TrainingDataDashboard = lazyWithRetry(() => import("./pages/TrainingDataDashboard"));
const ScanSchedules = lazyWithRetry(() => import("./pages/ScanSchedules"));
const AuditLog = lazyWithRetry(() => import("./pages/AuditLog"));
const ValidationScheduler = lazyWithRetry(() => import("./pages/ValidationScheduler"));
const CloudAttackPaths = lazyWithRetry(() => import("./pages/CloudAttackPaths"));
const ADAttackSim = lazyWithRetry(() => import("./pages/ADAttackSim"));
const EDRValidation = lazyWithRetry(() => import("./pages/EDRValidation"));
const ComplianceMapper = lazyWithRetry(() => import("./pages/ComplianceMapper"));
const APISecurityTesting = lazyWithRetry(() => import("./pages/APISecurityTesting"));
const CloudCredentials = lazyWithRetry(() => import("./pages/CloudCredentials"));
const ADDomainConnector = lazyWithRetry(() => import("./pages/ADDomainConnector"));
const CredentialAlerts = lazyWithRetry(() => import("./pages/CredentialAlerts"));
const ADAttackPathGraph = lazyWithRetry(() => import("./pages/ADAttackPathGraph"));
const ForestMapper = lazyWithRetry(() => import("./pages/ForestMapper"));
const BloodHoundImport = lazyWithRetry(() => import("./pages/BloodHoundImport"));
const CredentialAutoRotation = lazyWithRetry(() => import("./pages/CredentialAutoRotation"));
const SiemFeedback = lazyWithRetry(() => import("./pages/SiemFeedback"));
const Tenants = lazyWithRetry(() => import("./pages/Tenants"));
const VulnScanner = lazyWithRetry(() => import("./pages/VulnScanner"));
const RiskTrending = lazyWithRetry(() => import("./pages/RiskTrending"));
const AgentlessBAS = lazyWithRetry(() => import("./pages/AgentlessBAS"));
const AttackPathDiscovery = lazyWithRetry(() => import("./pages/AttackPathDiscovery"));
const ReportTemplates = lazyWithRetry(() => import("./pages/ReportTemplates"));
const Ac3Reports = lazyWithRetry(() => import("./pages/Ac3Reports"));
const EmailSecurity = lazyWithRetry(() => import("./pages/EmailSecurity"));
const NgfwValidation = lazyWithRetry(() => import("./pages/NgfwValidation"));
const RemediationVerification = lazyWithRetry(() => import("./pages/RemediationVerification"));
const CicdPipeline = lazyWithRetry(() => import("./pages/CicdPipeline"));
const SoarConnectors = lazyWithRetry(() => import("./pages/SoarConnectors"));
const AiAttackPlanner = lazyWithRetry(() => import("./pages/AiAttackPlanner"));
const CorroborationEngine = lazyWithRetry(() => import("./pages/CorroborationEngine"));
const NvdCveMatcher = lazyWithRetry(() => import("./pages/NvdCveMatcher"));
const ZeroDayTracker = lazyWithRetry(() => import("./pages/ZeroDayTracker"));
const CompensatingControls = lazyWithRetry(() => import("./pages/CompensatingControls"));
const PreFlightChecks = lazyWithRetry(() => import("./pages/PreFlightChecks"));
const ActiveVerification = lazyWithRetry(() => import("./pages/ActiveVerification"));
const IcsOtSecurity = lazyWithRetry(() => import("./pages/IcsOtSecurity"));
const WebAppScanner = lazyWithRetry(() => import("./pages/WebAppScanner"));
const CredentialAttacks = lazyWithRetry(() => import("./pages/CredentialAttacks"));
const ZapProxySessions = lazyWithRetry(() => import("./pages/ZapProxySessions"));
const PentestReport = lazyWithRetry(() => import("./pages/PentestReport"));
const AtomicRedTeam = lazyWithRetry(() => import("./pages/AtomicRedTeam"));
const SliverC2 = lazyWithRetry(() => import("./pages/SliverC2"));
const NucleiScanner = lazyWithRetry(() => import("./pages/NucleiScanner"));
const AmassScanner = lazyWithRetry(() => import("./pages/AmassScanner"));
const AttackCoverage = lazyWithRetry(() => import("./pages/AttackCoverage"));
const UnifiedPipeline = lazyWithRetry(() => import("./pages/UnifiedPipeline"));
const RoeBuilder = lazyWithRetry(() => import("./pages/RoeBuilder"));
const KsiDashboard = lazyWithRetry(() => import("./pages/KsiDashboard"));
const KsiEvidenceChain = lazyWithRetry(() => import("./pages/KsiEvidenceChain"));
const KsiValidation = lazyWithRetry(() => import("./pages/KsiValidation"));
const OscalExport = lazyWithRetry(() => import("./pages/OscalExport"));
const ThreePaoReview = lazyWithRetry(() => import("./pages/ThreePaoReview"));
const KsiDetail = lazyWithRetry(() => import("./pages/KsiDetail"));
const KsiAutoCollector = lazyWithRetry(() => import("./pages/KsiAutoCollector"));
const KsiThreatMap = lazyWithRetry(() => import("./pages/KsiThreatMap"));
const ConfigBaseline = lazyWithRetry(() => import("./pages/ConfigBaseline"));
const AttackVectorEngine = lazyWithRetry(() => import("./pages/AttackVectorEngine"));
const ScheduledCollection = lazyWithRetry(() => import("./pages/ScheduledCollection"));
const EngagementAutomation = lazyWithRetry(() => import("./pages/EngagementAutomation"));
const ThreatEnrichment = lazyWithRetry(() => import("./pages/ThreatEnrichment"));
const InfraWiki = lazyWithRetry(() => import("./pages/InfraWiki"));
const LiveInfra = lazyWithRetry(() => import("./pages/LiveInfra"));
const Workflows = lazyWithRetry(() => import("./pages/Workflows"));
const WebCrawler = lazyWithRetry(() => import("./pages/WebCrawler"));
const VendorIntegrations = lazyWithRetry(() => import("./pages/VendorIntegrations"));
const AgentManagerPage = lazyWithRetry(() => import("./pages/AgentManager"));
const AgentManagement = lazyWithRetry(() => import("./pages/AgentManagement"));
const FIPSCompliance = lazyWithRetry(() => import("./pages/FIPSCompliance"));
const SSILDashboard = lazyWithRetry(() => import("./pages/SSILDashboard"));
const SSILPolicies = lazyWithRetry(() => import("./pages/SSILPolicies"));
const SSILGuardrails = lazyWithRetry(() => import("./pages/SSILGuardrails"));
const SSILObservations = lazyWithRetry(() => import("./pages/SSILObservations"));
const SSILRiskCardDetail = lazyWithRetry(() => import("./pages/SSILRiskCardDetail"));
const SSILAlertRules = lazyWithRetry(() => import("./pages/SSILAlertRules"));
const SSILCorrelation = lazyWithRetry(() => import("./pages/SSILCorrelation"));
const SubfinderPage = lazyWithRetry(() => import("./pages/SubfinderPage"));
const HttpxPage = lazyWithRetry(() => import("./pages/HttpxPage"));
const NaabuPage = lazyWithRetry(() => import("./pages/NaabuPage"));
const AbilityGraphPage = lazyWithRetry(() => import("./pages/AbilityGraph"));
const GraphComparePage = lazyWithRetry(() => import("./pages/GraphCompare"));
const C2CommandCenter = lazyWithRetry(() => import("./pages/C2CommandCenter"));
const ThreatActorCrawler = lazyWithRetry(() => import("./pages/ThreatActorCrawler"));
const AISecurityValidation = lazyWithRetry(() => import("./pages/AISecurityValidation"));
const DiscoveryChain = lazyWithRetry(() => import("./pages/DiscoveryChain"));
const ErrorDashboard = lazyWithRetry(() => import("./pages/ErrorDashboard"));
const BugReportDashboard = lazyWithRetry(() => import("./pages/BugReportDashboard"));
const OemCredentials = lazyWithRetry(() => import("./pages/OemCredentials"));

// Hub pages (consolidated tab navigation)
const DiscoveryToolkitHub = lazyWithRetry(() => import("./pages/DiscoveryToolkitHub"));
const VulnScanningHub = lazyWithRetry(() => import("./pages/VulnScanningHub"));
const ScanManagementHub = lazyWithRetry(() => import("./pages/ScanManagementHub"));
const ADSecurityHub = lazyWithRetry(() => import("./pages/ADSecurityHub"));
const RiskCenterHub = lazyWithRetry(() => import("./pages/RiskCenterHub"));
const AutomationHub = lazyWithRetry(() => import("./pages/AutomationHub"));
const DefenseTestingHub = lazyWithRetry(() => import("./pages/DefenseTestingHub"));
const C2Hub = lazyWithRetry(() => import("./pages/C2Hub"));
const PhishingAssetsHub = lazyWithRetry(() => import("./pages/PhishingAssetsHub"));
const CredentialCenterHub = lazyWithRetry(() => import("./pages/CredentialCenterHub"));
const DataExportHub = lazyWithRetry(() => import("./pages/DataExportHub"));
const KsiHub = lazyWithRetry(() => import("./pages/KsiHub"));
const ComplianceHub = lazyWithRetry(() => import("./pages/ComplianceHub"));
const ReportsHub = lazyWithRetry(() => import("./pages/ReportsHub"));
const GuidesHub = lazyWithRetry(() => import("./pages/GuidesHub"));
const IntegrationsHub = lazyWithRetry(() => import("./pages/IntegrationsHub"));
const SSILHub = lazyWithRetry(() => import("./pages/SSILHub"));
const InfrastructureHub = lazyWithRetry(() => import("./pages/InfrastructureHub"));
const TeamHub = lazyWithRetry(() => import("./pages/TeamHub"));
const DetectionHub = lazyWithRetry(() => import("./pages/DetectionHub"));
const BatchDomainScanner = lazyWithRetry(() => import("./pages/BatchDomainScanner"));
const OpsecDashboard = lazyWithRetry(() => import("./pages/OpsecDashboard"));
const KillChainVisualizer = lazyWithRetry(() => import("./pages/KillChainVisualizer"));
const LateralMovement = lazyWithRetry(() => import("./pages/LateralMovement"));
const ExploitationBridge = lazyWithRetry(() => import("./pages/ExploitationBridge"));
const PrivilegeEscalation = lazyWithRetry(() => import("./pages/PrivilegeEscalation"));
const CampaignAdvisor = lazyWithRetry(() => import("./pages/CampaignAdvisor"));
const ExportCenter = lazyWithRetry(() => import("./pages/ExportCenter"));
const ScanServerHealth = lazyWithRetry(() => import("./pages/ScanServerHealth"));
const RoleHome = lazyWithRetry(() => import("./pages/home/RoleHome"));
const ToolComparison = lazyWithRetry(() => import("./pages/ToolComparison"));
const AccountSettings = lazyWithRetry(() => import("./pages/AccountSettings"));
const TeamManagementPage = lazyWithRetry(() => import("./pages/TeamManagement"));
const AcceptInvite = lazyWithRetry(() => import("./pages/AcceptInvite"));
const SamlConfig = lazyWithRetry(() => import("./pages/SamlConfig"));
const SessionManagement = lazyWithRetry(() => import("./pages/SessionManagement"));
const TenantOnboarding = lazyWithRetry(() => import("./pages/TenantOnboarding"));
const ComplianceDashboard = lazyWithRetry(() => import("./pages/ComplianceDashboard"));
const ScanWebhooks = lazyWithRetry(() => import("./pages/ScanWebhooks"));
const AuthAssessment = lazyWithRetry(() => import("./pages/AuthAssessment"));
const AuthPipeline = lazyWithRetry(() => import("./pages/AuthPipeline"));
const CloudSecurityValidation = lazyWithRetry(() => import("./pages/CloudSecurityValidation"));
const SigmaRuleGenerator = lazyWithRetry(() => import("./pages/SigmaRuleGenerator"));
const ControlTesting = lazyWithRetry(() => import("./pages/ControlTesting"));
const LlmTelemetry = lazyWithRetry(() => import("./pages/LlmTelemetry"));
const HuntDashboard = lazyWithRetry(() => import("./pages/HuntDashboard"));
const ReviewQueue = lazyWithRetry(() => import("./pages/ReviewQueue"));
const JobQueueDashboard = lazyWithRetry(() => import("./pages/JobQueueDashboard"));
const SocIntegrationHub = lazyWithRetry(() => import("./pages/SocIntegrationHub"));
const CloudWorkloadTesting = lazyWithRetry(() => import("./pages/CloudWorkloadTesting"));
const LlmReliabilityDashboard = lazyWithRetry(() => import("./pages/LlmReliabilityDashboard"));
const AgentInstallerGenerator = lazyWithRetry(() => import("./pages/AgentInstallerGenerator"));
const MsspAnalyticsDashboard = lazyWithRetry(() => import("./pages/MsspAnalyticsDashboard"));
const DataExfilSimulation = lazyWithRetry(() => import("./pages/DataExfilSimulation"));
const KnowledgeBase = lazyWithRetry(() => import("./pages/KnowledgeBase"));
const LlmLearning = lazyWithRetry(() => import("./pages/LlmLearning"));
const LearningDashboard = lazyWithRetry(() => import("./pages/LearningDashboard"));
const ExploitLearning = lazyWithRetry(() => import("./pages/ExploitLearning"));
const DastScanners = lazyWithRetry(() => import("./pages/DastScanners"));
const UnifiedFindings = lazyWithRetry(() => import("./pages/UnifiedFindings"));
const PacketAnalysis = lazyWithRetry(() => import("./pages/PacketAnalysis"));
const AIGovernance = lazyWithRetry(() => import("./pages/AIGovernance"));
const ExecutiveDashboard = lazyWithRetry(() => import("./pages/ExecutiveDashboard"));
const ThreatGroupProfile = lazyWithRetry(() => import("./pages/ThreatGroupProfile"));
const GraduationEngine = lazyWithRetry(() => import("./pages/GraduationEngine"));
const RemediationTracking = lazyWithRetry(() => import("./pages/RemediationTracking"));
const SafetyDashboard = lazyWithRetry(() => import("./pages/SafetyDashboard"));
const AgentInternalScanning = lazyWithRetry(() => import("./pages/AgentInternalScanning"));
const PhishingImpactTesting = lazyWithRetry(() => import("./pages/PhishingImpactTesting"));
const SOC2Compliance = lazyWithRetry(() => import("./pages/SOC2Compliance"));
const C2KnowledgeBase = lazyWithRetry(() => import("./pages/C2KnowledgeBase"));
const ServerAccess = lazyWithRetry(() => import("./pages/ServerAccess"));
const EmpirePage = lazyWithRetry(() => import("./pages/EmpirePage"));
const EmberFleetOverview = lazyWithRetry(() => import("./pages/EmberFleetOverview"));
const EmberDeploy = lazyWithRetry(() => import("./pages/EmberDeploy"));
const EmberTaskConsole = lazyWithRetry(() => import("./pages/EmberTaskConsole"));
const EmberPayloadArmory = lazyWithRetry(() => import("./pages/EmberPayloadArmory"));
const EmberSwarmControl = lazyWithRetry(() => import("./pages/EmberSwarmControl"));
const EmberIntelligence = lazyWithRetry(() => import("./pages/EmberIntelligence"));
const EmberCapabilities = lazyWithRetry(() => import("./pages/EmberCapabilities"));
const EmberCognitiveEngine = lazyWithRetry(() => import("./pages/EmberCognitiveEngine"));
const TestLabDashboard = lazyWithRetry(() => import("./pages/TestLabDashboard"));
const TestLabEnvironments = lazyWithRetry(() => import("./pages/TestLabEnvironments"));
const TestLabScenarios = lazyWithRetry(() => import("./pages/TestLabScenarios"));
const TestLabImplant = lazyWithRetry(() => import("./pages/TestLabImplant"));
const TestLabTraining = lazyWithRetry(() => import("./pages/TestLabTraining"));
const TestLabGraduation = lazyWithRetry(() => import("./pages/TestLabGraduation"));
const DfirLibrary = lazyWithRetry(() => import("./pages/DfirLibrary"));
const AgentRegistryPage = lazyWithRetry(() => import("./pages/AgentRegistry"));
const NexusPipelinePage = lazyWithRetry(() => import("./pages/NexusPipeline"));
const AgentLeaderboard = lazyWithRetry(() => import("./pages/AgentLeaderboard"));
const RealtimeMonitor = lazyWithRetry(() => import("./pages/RealtimeMonitor"));
const TrainingDataReview = lazyWithRetry(() => import("./pages/TrainingDataReview"));
const TestPlanReview = lazyWithRetry(() => import("./pages/TestPlanReview"));
const ScanForgeDashboard = lazyWithRetry(() => import("./pages/ScanForgeDashboard"));
const LicenseManagement = lazyWithRetry(() => import("./pages/LicenseManagement"));
const UpdateManager = lazyWithRetry(() => import("./pages/UpdateManager"));
const CustomerPortalSelfService = lazyWithRetry(() => import("./pages/CustomerPortalSelfService"));

// ─── Loading fallback ────────────────────────────────────────────────────────
function PageLoader() {
  return (
    <div className="min-h-screen bg-background flex items-center justify-center">
      <div className="text-center space-y-4">
        <Skeleton className="w-16 h-16 rounded-full mx-auto" />
        <Skeleton className="w-48 h-4 mx-auto" />
        <p className="text-muted-foreground text-sm">Loading...</p>
      </div>
    </div>
  );
}

// Protected route wrapper that requires authentication
function ProtectedRoute({ component: Component, pageName }: { component: React.ComponentType; pageName?: string }) {
  const [location, setLocation] = useLocation();
  const { data: session, isLoading } = trpc.calderaAuth.session.useQuery(undefined, {
    staleTime: 30_000, // Cache session for 30s to avoid redundant auth checks
    refetchOnWindowFocus: false,
  });

  // Use optimistic auth: if we have a caldera session cookie, render immediately
  // while the session query validates in the background
  const hasSessionCookie = typeof document !== 'undefined' && document.cookie.includes('caldera_session');

  useEffect(() => {
    if (!isLoading && !session?.authenticated && !hasSessionCookie) {
      const returnTo = encodeURIComponent(location);
      setLocation(`/login?returnTo=${returnTo}`);
    }
  }, [isLoading, session, setLocation, location, hasSessionCookie]);

  // Show loading only if we have NO cached session AND no cookie hint
  if (isLoading && !hasSessionCookie) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center space-y-4">
          <Skeleton className="w-16 h-16 rounded-full mx-auto" />
          <Skeleton className="w-48 h-4 mx-auto" />
          <p className="text-muted-foreground text-sm">Verifying authentication...</p>
        </div>
      </div>
    );
  }

  if (!isLoading && !session?.authenticated) {
    return null;
  }

  return (
    <PageErrorBoundary pageName={pageName ?? Component.displayName ?? Component.name ?? 'Page'}>
      <Component />
    </PageErrorBoundary>
  );
}

function Router() {
  const [location] = useLocation();
  // Routes that should NOT have the sidebar
  const noSidebarRoutes = ["/", "/overview", "/login", "/404"];
  const isPortalRoute = location.startsWith("/portal/") || location.startsWith("/customer-");
  const showSidebar = !noSidebarRoutes.includes(location) && !isPortalRoute;

  const routeContent = (
    <Suspense fallback={<PageLoader />}>
      <Switch>
        <Route path="/">
          <PageErrorBoundary pageName="Home"><Home /></PageErrorBoundary>
        </Route>
        <Route path="/overview">
          <PageErrorBoundary pageName="Overview"><Home /></PageErrorBoundary>
        </Route>
        <Route path="/home">
          <ProtectedRoute component={RoleHome} pageName="RoleHome" />
        </Route>
        <Route path="/tool-comparison">
          <ProtectedRoute component={ToolComparison} pageName="ToolComparison" />
        </Route>
        <Route path="/login">{() => <PageErrorBoundary pageName="Login"><Login /></PageErrorBoundary>}</Route>
        <Route path="/dashboard">
          <ProtectedRoute component={Dashboard} />
        </Route>
        <Route path="/workflows">
          <ProtectedRoute component={Workflows} />
        </Route>
        <Route path="/engagements">
          <ProtectedRoute component={Engagements} />
        </Route>
        <Route path="/engagements/new">
          <ProtectedRoute component={Engagements} />
        </Route>
        <Route path="/credentials">
          <Redirect to="/infra-reference" />
        </Route>
        <Route path="/adversaries">
          <Redirect to="/threat-catalog" />
        </Route>
        <Route path="/adversaries/:id">
          {(params) => <ProtectedRoute component={() => <AdversaryDetail />} />}
        </Route>
        <Route path="/team">
          <ProtectedRoute component={TeamManagementPage} />
        </Route>
        <Route path="/account-settings">
          <ProtectedRoute component={AccountSettings} />
        </Route>
        <Route path="/invitations">
          <ProtectedRoute component={AcceptInvite} />
        </Route>
        <Route path="/saml-config">
          <ProtectedRoute component={SamlConfig} />
        </Route>
        <Route path="/sessions">
          <ProtectedRoute component={SessionManagement} />
        </Route>
        <Route path="/onboarding">
          <ProtectedRoute component={TenantOnboarding} />
        </Route>
        <Route path="/customer-accounts">
          <ProtectedRoute component={CustomerAccounts} />
        </Route>
        <Route path="/compliance-dashboard">
          <ProtectedRoute component={ComplianceDashboard} />
        </Route>
        <Route path="/scan-webhooks">
          <ProtectedRoute component={ScanWebhooks} />
        </Route>
        <Route path="/activity">
          <ProtectedRoute component={Activity} />
        </Route>
        <Route path="/campaigns">
          {() => { window.location.href = '/engagements'; return null; }}
        </Route>
        <Route path="/campaigns/:id">
          {(params) => <ProtectedRoute component={() => <CampaignDetail />} />}
        </Route>
        <Route path="/agents">
          <ProtectedRoute component={Agents} />
        </Route>
        <Route path="/agents/deploy">
          <ProtectedRoute component={AgentDeploy} />
        </Route>
        <Route path="/operations/monitor">
          <ProtectedRoute component={OperationMonitor} />
        </Route>
        <Route path="/operations/:id">
          {(params) => <ProtectedRoute component={() => <OperationDetail />} />}
        </Route>
        <Route path="/reports/generate">
          <ProtectedRoute component={ReportsHub} />
        </Route>
        <Route path="/phishing-ops">
          <ProtectedRoute component={PhishingOperations} />
        </Route>
        <Route path="/gophish">
          <Redirect to="/phishing-ops" />
        </Route>
        <Route path="/guide/gophish">
          <ProtectedRoute component={GuidesHub} />
        </Route>
        <Route path="/guide/caldera">
          <ProtectedRoute component={CalderaGuide} />
        </Route>
        <Route path="/reports">
          <Redirect to="/reports/generate" />
        </Route>
        <Route path="/reports/security">
          <Redirect to="/reports/generate" />
        </Route>
        <Route path="/reports/engagement">
          <Redirect to="/reports/generate" />
        </Route>
        <Route path="/apt-library">
          <Redirect to="/threat-catalog" />
        </Route>
        <Route path="/compliance">
          <ProtectedRoute component={ComplianceHub} />
        </Route>
        <Route path="/infrastructure">
          <Redirect to="/infra-reference" />
        </Route>
        <Route path="/infra-reference">
          <ProtectedRoute component={InfraReference} />
        </Route>
        <Route path="/templates">
          <ProtectedRoute component={TemplateLibrary} />
        </Route>
        <Route path="/campaign-wizard">
          <ProtectedRoute component={CampaignWizard} />
        </Route>
        <Route path="/campaign-orchestrator">
          <ProtectedRoute component={CampaignOrchestrator} />
        </Route>
        <Route path="/campaign-orchestrator/:id">
          <ProtectedRoute component={CampaignOrchestrator} />
        </Route>
        <Route path="/domain-recon">
          <Redirect to="/domain-intel" />
        </Route>
        <Route path="/osint-monitor">
          <Redirect to="/domain-intel" />
        </Route>
        <Route path="/domain-intel">
          <ProtectedRoute component={DomainIntel} />
        </Route>
        <Route path="/domain-intel/history">
          <ProtectedRoute component={ScanHistory} />
        </Route>
        <Route path="/domain-intel/curate/:scanId">
          {() => <ProtectedRoute component={DiscoveryCuration} />}
        </Route>
        <Route path="/domain-intel/:id">
          {() => <ProtectedRoute component={DomainIntelResults} />}
        </Route>
        <Route path="/web-crawler">
          <ProtectedRoute component={WebCrawler} />
        </Route>
        <Route path="/web-crawler/:id">
          {() => <ProtectedRoute component={WebCrawler} />}
        </Route>
        <Route path="/vendor-integrations">
          <ProtectedRoute component={VendorIntegrations} />
        </Route>
        <Route path="/scan-scheduler">
          <ProtectedRoute component={ScanManagementHub} />
        </Route>
        <Route path="/template-generator">
          <ProtectedRoute component={TemplateGenerator} />
        </Route>
        <Route path="/abilities-library">
          <ProtectedRoute component={AbilitiesLibrary} />
        </Route>
        <Route path="/ioc-feed">
          <ProtectedRoute component={IOCFeed} />
        </Route>
        <Route path="/engagement-pipeline">
          <ProtectedRoute component={EngagementPipeline} />
        </Route>
        <Route path="/threat-actors">
          <Redirect to="/threat-catalog" />
        </Route>
        <Route path="/threat-actors/:id">
          {() => <ProtectedRoute component={ThreatActorDetail} />}
        </Route>
        <Route path="/ttp-knowledge">
          <ProtectedRoute component={TtpKnowledge} />
        </Route>
        <Route path="/knowledge-base">
          <ProtectedRoute component={KnowledgeBase} />
        </Route>
        <Route path="/llm-learning">
          <ProtectedRoute component={LlmLearning} />
        </Route>
        <Route path="/learning-dashboard">
          <ProtectedRoute component={LearningDashboard} />
        </Route>
        <Route path="/exploit-learning">
          <ProtectedRoute component={ExploitLearning} />
        </Route>
        <Route path="/campaign-execution">
          <ProtectedRoute component={CampaignExecution} />
        </Route>
        <Route path="/rule-validator">
          <ProtectedRoute component={RuleValidator} />
        </Route>
        <Route path="/detection-coverage">
          <ProtectedRoute component={DetectionHub} />
        </Route>
        <Route path="/kev-catalog">
          <ProtectedRoute component={KevDashboard} />
        </Route>
        <Route path="/scan-compare">
          <ProtectedRoute component={ScanComparison} />
        </Route>
        <Route path="/vuln-intel">
          <ProtectedRoute component={KevDashboard} />
        </Route>
        <Route path="/threat-intel-hub">
          <ProtectedRoute component={ThreatIntelHub} />
        </Route>
        <Route path="/threat-group-browser">
          <ProtectedRoute component={ThreatGroupBrowser} />
        </Route>
        <Route path="/threat-catalog">
          <ProtectedRoute component={ThreatCatalog} />
        </Route>
        <Route path="/threat-catalog/:id">
          {() => <ProtectedRoute component={ThreatActorCatalogDetail} />}
        </Route>
        <Route path="/ransomware-groups">
          <Redirect to="/threat-catalog" />
        </Route>
        <Route path="/ransomware-groups/:name">
          <Redirect to="/threat-catalog" />
        </Route>
        <Route path="/darkweb-intel">
          <ProtectedRoute component={DarkwebIntel} />
        </Route>
        <Route path="/breach-events">
          <ProtectedRoute component={BreachEvents} />
        </Route>
        <Route path="/phishing-exploit-catalog">
          <Redirect to="/exploit-catalog" />
        </Route>
        <Route path="/exploit-arsenal">
          <Redirect to="/exploit-catalog" />
        </Route>
        <Route path="/exploit-knowledge">
          <ProtectedRoute component={ExploitKnowledge} />
        </Route>
        <Route path="/exploit-catalog">
          <ProtectedRoute component={ExploitArsenal} />
        </Route>
        <Route path="/custom-exploits">
          <ProtectedRoute component={CustomExploitRepository} />
        </Route>
        <Route path="/validation-engine">
          <ProtectedRoute component={ValidationEngine} />
        </Route>
        <Route path="/msf-servers">
          <ProtectedRoute component={MsfServers} />
        </Route>
        <Route path="/ssh-keys">
          <ProtectedRoute component={SshKeyManager} />
        </Route>
        <Route path="/msf-sessions">
          <ProtectedRoute component={MsfSessions} />
        </Route>
        <Route path="/session-recordings">
          <ProtectedRoute component={SessionRecordings} />
        </Route>
        <Route path="/post-exploit-playbooks">
          <ProtectedRoute component={PostExploitPlaybooks} />
        </Route>
        <Route path="/file-transfers">
          <ProtectedRoute component={FileTransfers} />
        </Route>
        <Route path="/payload-generator">
          <ProtectedRoute component={PayloadGenerator} />
        </Route>
        <Route path="/engagement-timeline">
          <ProtectedRoute component={EngagementTimeline} />
        </Route>
        <Route path="/stix-export">
          <ProtectedRoute component={DataExportHub} />
        </Route>
        <Route path="/campaign-archetypes">
          <ProtectedRoute component={CampaignArchetypes} />
        </Route>
        <Route path="/post-engagement-report">
          <ProtectedRoute component={PostEngagementReport} />
        </Route>
        <Route path="/landing-page-builder">
          <ProtectedRoute component={PhishingAssetsHub} />
        </Route>
        <Route path="/engagements/:id/results">
          {() => <ProtectedRoute component={EngagementResults} />}
        </Route>
        <Route path="/engagements/:id/recon">
          {() => <ProtectedRoute component={OsintRecon} />}
        </Route>
        <Route path="/engagement-ops/:id">
          {() => <ProtectedRoute component={EngagementOps} />}
        </Route>
        <Route path="/engagement-ops">
          {() => <ProtectedRoute component={EngagementOps} />}
        </Route>
        <Route path="/emulation-playbooks">
          <ProtectedRoute component={EmulationPlaybooks} />
        </Route>
        <Route path="/evidence">
          <ProtectedRoute component={EvidenceCollection} />
        </Route>
        <Route path="/evidence-gallery">
          <ProtectedRoute component={EvidenceGallery} />
        </Route>
        <Route path="/evidence-integrity">
          <ProtectedRoute component={EvidenceIntegrity} />
        </Route>
        <Route path="/attack-paths">
          <ProtectedRoute component={AttackPaths} />
        </Route>
        <Route path="/purple-team">
          <ProtectedRoute component={PurpleTeam} />
        </Route>
        <Route path="/evasion-engine">
          <ProtectedRoute component={EvasionEngine} />
        </Route>
        <Route path="/training-dashboard">
          <ProtectedRoute component={TrainingDashboard} />
        </Route>
        <Route path="/batch-training">
          <ProtectedRoute component={BatchTraining} />
        </Route>
        <Route path="/training-data-dashboard">
          <ProtectedRoute component={TrainingDataDashboard} />
        </Route>
        <Route path="/scan-schedules">
          <ProtectedRoute component={ScanSchedules} />
        </Route>
        <Route path="/audit-log">
          <ProtectedRoute component={AuditLog} />
        </Route>
        <Route path="/continuous-validation">
          <ProtectedRoute component={ValidationScheduler} />
        </Route>
        <Route path="/siem-connectors">
          <ProtectedRoute component={IntegrationsHub} />
        </Route>
        <Route path="/webhooks">
          <ProtectedRoute component={Webhooks} />
        </Route>
        <Route path="/bug-bounty">
          <ProtectedRoute component={BugBountyHub} />
        </Route>
        <Route path="/scoring">
          <ProtectedRoute component={RiskCenterHub} />
        </Route>
        <Route path="/batch-scanner">
          <ProtectedRoute component={BatchDomainScanner} />
        </Route>
        <Route path="/bia-report">
          <ProtectedRoute component={BiaReport} />
        </Route>
        <Route path="/portal/:token" component={ClientPortal} />
        <Route path="/customer-login" component={CustomerPortalLogin} />
        <Route path="/customer-portal" component={CustomerPortalDashboard} />
        <Route path="/cloud-attack-paths">
          <ProtectedRoute component={CloudAttackPaths} />
        </Route>
        <Route path="/ics-ot-security">
          <ProtectedRoute component={IcsOtSecurity} />
        </Route>
        <Route path="/ad-attack-sim">
          <ProtectedRoute component={ADSecurityHub} />
        </Route>
        <Route path="/edr-validation">
          <ProtectedRoute component={DefenseTestingHub} />
        </Route>
        <Route path="/compliance-mapper">
          <ProtectedRoute component={ComplianceMapper} />
        </Route>
        <Route path="/api-security-testing">
          <ProtectedRoute component={APISecurityTesting} />
        </Route>
        <Route path="/cloud-credentials">
          <ProtectedRoute component={CredentialCenterHub} />
        </Route>
        <Route path="/ad-domain-connector">
          <ProtectedRoute component={ADDomainConnector} />
        </Route>
        <Route path="/credential-alerts">
          <ProtectedRoute component={CredentialAlerts} />
        </Route>
        <Route path="/dfir-library">
          <ProtectedRoute component={DfirLibrary} />
        </Route>
        <Route path="/ad-attack-path-graph">
          <ProtectedRoute component={ADAttackPathGraph} />
        </Route>
        <Route path="/forest-mapper">
          <ProtectedRoute component={ForestMapper} />
        </Route>
        <Route path="/bloodhound-import">
          <ProtectedRoute component={BloodHoundImport} />
        </Route>
        <Route path="/credential-auto-rotation">
          <ProtectedRoute component={CredentialAutoRotation} />
        </Route>
        <Route path="/siem-feedback">
          <ProtectedRoute component={SiemFeedback} />
        </Route>
        <Route path="/tenants">
          <ProtectedRoute component={Tenants} />
        </Route>
        <Route path="/vuln-scanner">
          <ProtectedRoute component={VulnScanner} />
        </Route>
        <Route path="/risk-trending">
          <ProtectedRoute component={RiskTrending} />
        </Route>
        <Route path="/agentless-bas">
          <ProtectedRoute component={AgentlessBAS} />
        </Route>
        <Route path="/attack-path-discovery">
          <ProtectedRoute component={AttackPathDiscovery} />
        </Route>
        <Route path="/ac3-reports">
          <ProtectedRoute component={Ac3Reports} />
        </Route>
        <Route path="/report-templates">
          <ProtectedRoute component={ReportTemplates} />
        </Route>
        <Route path="/email-security">
          <ProtectedRoute component={EmailSecurity} />
        </Route>
        <Route path="/ngfw-validation">
          <ProtectedRoute component={NgfwValidation} />
        </Route>
        <Route path="/remediation-verification">
          <ProtectedRoute component={RemediationVerification} />
        </Route>
        <Route path="/cicd-pipeline">
          <ProtectedRoute component={CicdPipeline} />
        </Route>
        <Route path="/soar-connectors">
          <ProtectedRoute component={SoarConnectors} />
        </Route>
        <Route path="/ai-attack-planner">
          <ProtectedRoute component={AiAttackPlanner} />
        </Route>
        <Route path="/corroboration-engine">
          <ProtectedRoute component={CorroborationEngine} />
        </Route>
        <Route path="/nvd-cve-matcher">
          <ProtectedRoute component={NvdCveMatcher} />
        </Route>
        <Route path="/zero-day-tracker">
          <ProtectedRoute component={ZeroDayTracker} />
        </Route>
        <Route path="/compensating-controls">
          <ProtectedRoute component={CompensatingControls} />
        </Route>
        <Route path="/control-testing">
          <ProtectedRoute component={ControlTesting} />
        </Route>
        <Route path="/preflight-checks">
          <ProtectedRoute component={PreFlightChecks} />
        </Route>
        <Route path="/active-verification">
          <ProtectedRoute component={ActiveVerification} />
        </Route>
        <Route path="/web-app-scanner">
          <ProtectedRoute component={WebAppScanner} />
        </Route>
        <Route path="/credential-attacks">
          <ProtectedRoute component={CredentialAttacks} />
        </Route>
        <Route path="/auth-assessment">
          <ProtectedRoute component={AuthAssessment} />
        </Route>
        <Route path="/auth-pipeline">
          <ProtectedRoute component={AuthPipeline} />
        </Route>
        <Route path="/cloud-security-validation">
          <ProtectedRoute component={CloudSecurityValidation} />
        </Route>
        <Route path="/sigma-rules">
          <ProtectedRoute component={SigmaRuleGenerator} />
        </Route>
        <Route path="/zap-proxy">
          <ProtectedRoute component={ZapProxySessions} />
        </Route>
        <Route path="/pentest-report">
          <ProtectedRoute component={PentestReport} />
        </Route>
        <Route path="/atomic-red-team">
          <ProtectedRoute component={AtomicRedTeam} />
        </Route>
        <Route path="/sliver-c2">
          <ProtectedRoute component={SliverC2} />
        </Route>
        <Route path="/nuclei-scanner">
          <ProtectedRoute component={VulnScanningHub} />
        </Route>
        <Route path="/amass-scanner">
          <ProtectedRoute component={AmassScanner} />
        </Route>
        <Route path="/attack-coverage">
          <ProtectedRoute component={AttackCoverage} />
        </Route>
        <Route path="/unified-pipeline">
          <ProtectedRoute component={UnifiedPipeline} />
        </Route>
        <Route path="/roe-builder">
          <ProtectedRoute component={RoeBuilder} />
        </Route>
        <Route path="/ksi-dashboard">
          <ProtectedRoute component={KsiHub} />
        </Route>
        <Route path="/ksi-evidence-chain">
          <ProtectedRoute component={KsiEvidenceChain} />
        </Route>
        <Route path="/ksi-validation">
          <ProtectedRoute component={KsiValidation} />
        </Route>
        <Route path="/oscal-export">
          <ProtectedRoute component={OscalExport} />
        </Route>
        <Route path="/3pao-review">
          <ProtectedRoute component={ThreePaoReview} />
        </Route>
        <Route path="/ksi/:ksiId">
          <ProtectedRoute component={KsiDetail} />
        </Route>
        <Route path="/ksi-auto-collector">
          <ProtectedRoute component={KsiAutoCollector} />
        </Route>
        <Route path="/ksi-threat-map">
          <ProtectedRoute component={KsiThreatMap} />
        </Route>
        <Route path="/config-baseline">
          <ProtectedRoute component={ConfigBaseline} />
        </Route>
        <Route path="/attack-vector-engine">
          <ProtectedRoute component={AttackVectorEngine} />
        </Route>
        <Route path="/scheduled-collection">
          <ProtectedRoute component={ScheduledCollection} />
        </Route>
        <Route path="/engagement-automation">
          <ProtectedRoute component={AutomationHub} />
        </Route>
        <Route path="/threat-enrichment">
          <ProtectedRoute component={ThreatEnrichment} />
        </Route>
        <Route path="/infra-wiki">
          <ProtectedRoute component={InfraWiki} />
        </Route>
        <Route path="/live-infra">
          <ProtectedRoute component={InfrastructureHub} />
        </Route>
        <Route path="/agent-management">
          <ProtectedRoute component={AgentManagement} />
        </Route>
        <Route path="/agent-manager">
          <ProtectedRoute component={AgentManagerPage} />
        </Route>
        <Route path="/fips-compliance">
          <ProtectedRoute component={FIPSCompliance} />
        </Route>
        <Route path="/ssil">
          <ProtectedRoute component={SSILHub} />
        </Route>
        <Route path="/ssil/policies">
          <ProtectedRoute component={SSILPolicies} />
        </Route>
        <Route path="/ssil/guardrails">
          <ProtectedRoute component={SSILGuardrails} />
        </Route>
        <Route path="/ssil/observations">
          <ProtectedRoute component={SSILObservations} />
        </Route>
        <Route path="/ssil/alerts">
          <ProtectedRoute component={SSILAlertRules} />
        </Route>
        <Route path="/ssil/correlation">
          <ProtectedRoute component={SSILCorrelation} />
        </Route>
        <Route path="/ssil/risk-card/:riskId">
          <ProtectedRoute component={SSILRiskCardDetail} />
        </Route>
        <Route path="/tools/subfinder">
          <ProtectedRoute component={DiscoveryToolkitHub} />
        </Route>
        <Route path="/tools/httpx">
          <ProtectedRoute component={HttpxPage} />
        </Route>
        <Route path="/tools/naabu">
          <ProtectedRoute component={NaabuPage} />
        </Route>
        <Route path="/ability-graph">
          <ProtectedRoute component={AbilityGraphPage} />
        </Route>
        <Route path="/ability-graph/:graphId">
          {() => <ProtectedRoute component={AbilityGraphPage} />}
        </Route>
        <Route path="/ability-graph-compare">
          <ProtectedRoute component={GraphComparePage} />
        </Route>
        <Route path="/c2-knowledge-base">
          <ProtectedRoute component={C2KnowledgeBase} />
        </Route>
        <Route path="/server-access">
          <ProtectedRoute component={ServerAccess} />
        </Route>
        <Route path="/empire">
          <ProtectedRoute component={EmpirePage} />
        </Route>
        <Route path="/c2-command-center">
          <ProtectedRoute component={C2Hub} />
        </Route>
        <Route path="/threat-actor-crawler">
          <ProtectedRoute component={ThreatActorCrawler} />
        </Route>
        <Route path="/ai-security-validation">
          <ProtectedRoute component={AISecurityValidation} />
        </Route>
        <Route path="/discovery-chain">
          <ProtectedRoute component={DiscoveryChain} />
        </Route>
        <Route path="/error-dashboard">
          <ProtectedRoute component={ErrorDashboard} />
        </Route>
        <Route path="/bug-reports">
          <ProtectedRoute component={BugReportDashboard} />
        </Route>
        <Route path="/oem-credentials">
          <ProtectedRoute component={OemCredentials} />
        </Route>
        <Route path="/opsec-dashboard">
          <ProtectedRoute component={OpsecDashboard} />
        </Route>
        <Route path="/kill-chain">
          <ProtectedRoute component={KillChainVisualizer} />
        </Route>
        <Route path="/lateral-movement">
          <ProtectedRoute component={LateralMovement} />
        </Route>
        <Route path="/exploitation-bridge">
          <ProtectedRoute component={ExploitationBridge} />
        </Route>
        <Route path="/privilege-escalation">
          <ProtectedRoute component={PrivilegeEscalation} />
        </Route>
        <Route path="/campaign-advisor">
          <ProtectedRoute component={CampaignAdvisor} />
        </Route>
        <Route path="/export-center">
          <ProtectedRoute component={ExportCenter} />
        </Route>
        <Route path="/scan-server">
          <ProtectedRoute component={ScanServerHealth} />
        </Route>
        <Route path="/llm-telemetry">
          <ProtectedRoute component={LlmTelemetry} />
        </Route>
        <Route path="/hunt-ops">
          <ProtectedRoute component={HuntDashboard} />
        </Route>
        <Route path="/training-lab">
          <ProtectedRoute component={TrainingLab} />
        </Route>
        <Route path="/review-queue">
          <ProtectedRoute component={ReviewQueue} />
        </Route>
        <Route path="/job-queue">
          <ProtectedRoute component={JobQueueDashboard} />
        </Route>
        <Route path="/soc-integration-hub">
          <ProtectedRoute component={SocIntegrationHub} />
        </Route>
        <Route path="/cloud-workload-testing">
          <ProtectedRoute component={CloudWorkloadTesting} />
        </Route>
        <Route path="/llm-reliability">
          <ProtectedRoute component={LlmReliabilityDashboard} />
        </Route>
        <Route path="/agent-installer">
          <ProtectedRoute component={AgentInstallerGenerator} />
        </Route>
        <Route path="/mssp-analytics">
          <ProtectedRoute component={MsspAnalyticsDashboard} />
        </Route>
        <Route path="/data-exfil-simulation">
          <ProtectedRoute component={DataExfilSimulation} />
        </Route>
        <Route path="/dast-scanners">
          <ProtectedRoute component={DastScanners} />
        </Route>
        <Route path="/unified-findings">
          <ProtectedRoute component={UnifiedFindings} />
        </Route>
        <Route path="/packet-analysis">
          <ProtectedRoute component={PacketAnalysis} />
        </Route>
        <Route path="/ai-governance">
          <ProtectedRoute component={AIGovernance} />
        </Route>
        <Route path="/executive-dashboard">
          <ProtectedRoute component={ExecutiveDashboard} />
        </Route>
        <Route path="/threat-group/:id">
          <ProtectedRoute component={ThreatGroupProfile} />
        </Route>
        <Route path="/graduation-engine">
          <ProtectedRoute component={GraduationEngine} />
        </Route>
        <Route path="/agent-registry">
          <ProtectedRoute component={AgentRegistryPage} />
        </Route>
        <Route path="/nexus-pipeline">
          <ProtectedRoute component={NexusPipelinePage} />
        </Route>
        <Route path="/agent-leaderboard">
          <ProtectedRoute component={AgentLeaderboard} />
        </Route>
        <Route path="/realtime-monitor">
          <ProtectedRoute component={RealtimeMonitor} />
        </Route>
        <Route path="/test-plan/:planId">
          {() => <PageErrorBoundary pageName="TestPlanReview"><TestPlanReview /></PageErrorBoundary>}
        </Route>
        <Route path="/training-data-review">
          <ProtectedRoute component={TrainingDataReview} />
        </Route>
        <Route path="/remediation-tracking">
          <ProtectedRoute component={RemediationTracking} />
        </Route>
        <Route path="/safety-dashboard">
          <ProtectedRoute component={SafetyDashboard} />
        </Route>
        <Route path="/agent-internal-scanning">
          <ProtectedRoute component={AgentInternalScanning} />
        </Route>
        <Route path="/phishing-impact-testing">
          <ProtectedRoute component={PhishingImpactTesting} />
        </Route>
        <Route path="/soc2-compliance">
          <ProtectedRoute component={SOC2Compliance} />
        </Route>
        <Route path="/ember">
          <ProtectedRoute component={EmberFleetOverview} />
        </Route>
        <Route path="/ember/deploy">
          <ProtectedRoute component={EmberDeploy} />
        </Route>
        <Route path="/ember/tasks">
          <ProtectedRoute component={EmberTaskConsole} />
        </Route>
        <Route path="/ember/payloads">
          <ProtectedRoute component={EmberPayloadArmory} />
        </Route>
        <Route path="/ember/swarm">
          <ProtectedRoute component={EmberSwarmControl} />
        </Route>
        <Route path="/ember/intelligence">
          <ProtectedRoute component={EmberIntelligence} />
        </Route>
        <Route path="/ember/capabilities">
          <ProtectedRoute component={EmberCapabilities} />
        </Route>
        <Route path="/ember/cognitive">
          <ProtectedRoute component={EmberCognitiveEngine} />
        </Route>
        <Route path="/test-lab">
          <ProtectedRoute component={TestLabDashboard} />
        </Route>
        <Route path="/test-lab/environments">
          <ProtectedRoute component={TestLabEnvironments} />
        </Route>
        <Route path="/test-lab/scenarios">
          <ProtectedRoute component={TestLabScenarios} />
        </Route>
        <Route path="/test-lab/implant">
          <ProtectedRoute component={TestLabImplant} />
        </Route>
        <Route path="/test-lab/training">
          <ProtectedRoute component={TestLabTraining} />
        </Route>
        <Route path="/test-lab/graduation">
          <ProtectedRoute component={TestLabGraduation} />
        </Route>
        <Route path="/scanforge-dashboard">
          <ProtectedRoute component={ScanForgeDashboard} pageName="ScanForgeDashboard" />
        </Route>
        <Route path="/admin/licenses">
          <ProtectedRoute component={LicenseManagement} pageName="LicenseManagement" />
        </Route>
        <Route path="/admin/updates">
          <ProtectedRoute component={UpdateManager} pageName="UpdateManager" />
        </Route>
        <Route path="/my-portal">
          <ProtectedRoute component={CustomerPortalSelfService} pageName="CustomerPortalSelfService" />
        </Route>
        <Route path="/404" component={NotFound} />
        <Route component={NotFound} />
      </Switch>
    </Suspense>
  );

  if (showSidebar) {
    return (
      <Suspense fallback={<PageLoader />}>
        <DashboardLayout>{routeContent}</DashboardLayout>
      </Suspense>
    );
  }

  return routeContent;
}

function App() {
  useErrorCapture();

  return (
    <ErrorBoundary scope="app-root">
      <ThemeProvider defaultTheme="dark">
        <EngagementProvider>
          <TooltipProvider>
            <Toaster />
            <Router />
            <Suspense fallback={null}>
              <CommandPalette />
            </Suspense>
            <Suspense fallback={null}>
              <GlobalAiChat />
            </Suspense>
            <Suspense fallback={null}>
              <SessionTimeoutMonitor />
            </Suspense>
          </TooltipProvider>
        </EngagementProvider>
      </ThemeProvider>
    </ErrorBoundary>
  );
}

export default App;
