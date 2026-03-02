import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { Route, Switch, Redirect, useLocation } from "wouter";
import { ErrorBoundary, PageErrorBoundary } from "./components/ErrorBoundary";
import { ThemeProvider } from "./contexts/ThemeContext";
import { trpc } from "@/lib/trpc";
import { Skeleton } from "@/components/ui/skeleton";
import { lazy, Suspense, useEffect } from "react";
import { GlobalAiChat } from "./components/GlobalAiChat";
import { useErrorCapture } from "./hooks/useErrorCapture";
import { EngagementProvider } from "./contexts/EngagementContext";

// ─── Lazy-loaded pages (reduces initial bundle / HTTP requests) ──────────────
const Home = lazy(() => import("./pages/Home"));
const Login = lazy(() => import("./pages/Login"));
const NotFound = lazy(() => import("./pages/NotFound"));
const Dashboard = lazy(() => import("./pages/Dashboard"));
const AdversaryDetail = lazy(() => import("./pages/AdversaryDetail"));
const Team = lazy(() => import("./pages/Team"));
const Activity = lazy(() => import("./pages/Activity"));
const Campaigns = lazy(() => import("./pages/Campaigns"));
const CampaignDetail = lazy(() => import("./pages/CampaignDetail"));
const Agents = lazy(() => import("./pages/Agents"));
const AgentDeploy = lazy(() => import("./pages/AgentDeploy"));
const OperationMonitor = lazy(() => import("./pages/OperationMonitor"));
const ReportGenerator = lazy(() => import("./pages/ReportGenerator"));
const OperationDetail = lazy(() => import("./pages/OperationDetail"));
const GoPhish = lazy(() => import("./pages/GoPhish"));
const PhishingOperations = lazy(() => import("./pages/PhishingOperations"));
const GoPhishGuide = lazy(() => import("./pages/GoPhishGuide"));
const CalderaGuide = lazy(() => import("./pages/CalderaGuide"));
const ComplianceFrameworks = lazy(() => import("./pages/ComplianceFrameworks"));
const InfraReference = lazy(() => import("./pages/InfraReference"));
const TemplateLibrary = lazy(() => import("./pages/TemplateLibrary"));
const Engagements = lazy(() => import("./pages/Engagements"));
const CampaignWizard = lazy(() => import("./pages/CampaignWizard"));
const EngagementResults = lazy(() => import("./pages/EngagementResults"));
const OsintRecon = lazy(() => import("./pages/OsintRecon"));
const DomainIntel = lazy(() => import("./pages/DomainIntel"));
const DomainIntelResults = lazy(() => import("./pages/DomainIntelResults"));
const ScanScheduler = lazy(() => import("./pages/ScanScheduler"));
const TemplateGenerator = lazy(() => import("./pages/TemplateGenerator"));
const AbilitiesLibrary = lazy(() => import("./pages/AbilitiesLibrary"));
const IOCFeed = lazy(() => import("./pages/IOCFeed"));
const EngagementPipeline = lazy(() => import("./pages/EngagementPipeline"));
const EngagementOps = lazy(() => import("./pages/EngagementOps"));
const ThreatActorDetail = lazy(() => import("./pages/ThreatActorDetail"));
const TtpKnowledge = lazy(() => import("./pages/TtpKnowledge"));
const CampaignExecution = lazy(() => import("./pages/CampaignExecution"));
const RuleValidator = lazy(() => import("./pages/RuleValidator"));
const DetectionCoverage = lazy(() => import("./pages/DetectionCoverage"));
const PostEngagementReport = lazy(() => import("./pages/PostEngagementReport"));
const LandingPageBuilder = lazy(() => import("./pages/LandingPageBuilder"));
const DiscoveryCuration = lazy(() => import("./pages/DiscoveryCuration"));
const KevDashboard = lazy(() => import("./pages/KevDashboard"));
const ScanComparison = lazy(() => import("./pages/ScanComparison"));
const ThreatCatalog = lazy(() => import("./pages/ThreatCatalog"));
const ThreatActorCatalogDetail = lazy(() => import("./pages/ThreatActorCatalogDetail"));
const DarkwebIntel = lazy(() => import("./pages/DarkwebIntel"));
const ThreatIntelHub = lazy(() => import("./pages/ThreatIntelHub"));
const CampaignArchetypes = lazy(() => import("./pages/CampaignArchetypes"));
const ExploitArsenal = lazy(() => import("./pages/ExploitArsenal"));
const MsfServers = lazy(() => import("./pages/MsfServers"));
const SshKeyManager = lazy(() => import("./pages/SshKeyManager"));
const MsfSessions = lazy(() => import("./pages/MsfSessions"));
const SessionRecordings = lazy(() => import("./pages/SessionRecordings"));
const PostExploitPlaybooks = lazy(() => import("./pages/PostExploitPlaybooks"));
const FileTransfers = lazy(() => import("./pages/FileTransfers"));
const PayloadGenerator = lazy(() => import("./pages/PayloadGenerator"));
const EngagementTimeline = lazy(() => import("./pages/EngagementTimeline"));
const StixExport = lazy(() => import("./pages/StixExport"));
const ClientPortal = lazy(() => import("./pages/ClientPortal"));
const EmulationPlaybooks = lazy(() => import("./pages/EmulationPlaybooks"));
const EvidenceCollection = lazy(() => import("./pages/EvidenceCollection"));
const AttackPaths = lazy(() => import("./pages/AttackPaths"));
const PurpleTeam = lazy(() => import("./pages/PurpleTeam"));
const Webhooks = lazy(() => import("./pages/Webhooks"));
const BugBountyHub = lazy(() => import("./pages/BugBountyHub"));
const ScoringHub = lazy(() => import("./pages/ScoringHub"));
const BiaReport = lazy(() => import("./pages/BiaReport"));
const ValidationEngine = lazy(() => import("./pages/ValidationEngine"));
const EvasionEngine = lazy(() => import("./pages/EvasionEngine"));
const SiemConnectors = lazy(() => import("./pages/SiemConnectors"));
const ScanHistory = lazy(() => import("./pages/ScanHistory"));
const TrainingDashboard = lazy(() => import("./pages/TrainingDashboard"));
const AuditLog = lazy(() => import("./pages/AuditLog"));
const ValidationScheduler = lazy(() => import("./pages/ValidationScheduler"));
const CloudAttackPaths = lazy(() => import("./pages/CloudAttackPaths"));
const ADAttackSim = lazy(() => import("./pages/ADAttackSim"));
const EDRValidation = lazy(() => import("./pages/EDRValidation"));
const ComplianceMapper = lazy(() => import("./pages/ComplianceMapper"));
const APISecurityTesting = lazy(() => import("./pages/APISecurityTesting"));
const CloudCredentials = lazy(() => import("./pages/CloudCredentials"));
const ADDomainConnector = lazy(() => import("./pages/ADDomainConnector"));
const CredentialAlerts = lazy(() => import("./pages/CredentialAlerts"));
const ADAttackPathGraph = lazy(() => import("./pages/ADAttackPathGraph"));
const ForestMapper = lazy(() => import("./pages/ForestMapper"));
const BloodHoundImport = lazy(() => import("./pages/BloodHoundImport"));
const CredentialAutoRotation = lazy(() => import("./pages/CredentialAutoRotation"));
const SiemFeedback = lazy(() => import("./pages/SiemFeedback"));
const Tenants = lazy(() => import("./pages/Tenants"));
const VulnScanner = lazy(() => import("./pages/VulnScanner"));
const RiskTrending = lazy(() => import("./pages/RiskTrending"));
const AgentlessBAS = lazy(() => import("./pages/AgentlessBAS"));
const AttackPathDiscovery = lazy(() => import("./pages/AttackPathDiscovery"));
const ReportTemplates = lazy(() => import("./pages/ReportTemplates"));
const EmailSecurity = lazy(() => import("./pages/EmailSecurity"));
const NgfwValidation = lazy(() => import("./pages/NgfwValidation"));
const RemediationVerification = lazy(() => import("./pages/RemediationVerification"));
const CicdPipeline = lazy(() => import("./pages/CicdPipeline"));
const SoarConnectors = lazy(() => import("./pages/SoarConnectors"));
const AiAttackPlanner = lazy(() => import("./pages/AiAttackPlanner"));
const CorroborationEngine = lazy(() => import("./pages/CorroborationEngine"));
const NvdCveMatcher = lazy(() => import("./pages/NvdCveMatcher"));
const CompensatingControls = lazy(() => import("./pages/CompensatingControls"));
const PreFlightChecks = lazy(() => import("./pages/PreFlightChecks"));
const ActiveVerification = lazy(() => import("./pages/ActiveVerification"));
const IcsOtSecurity = lazy(() => import("./pages/IcsOtSecurity"));
const WebAppScanner = lazy(() => import("./pages/WebAppScanner"));
const CredentialAttacks = lazy(() => import("./pages/CredentialAttacks"));
const ZapProxySessions = lazy(() => import("./pages/ZapProxySessions"));
const PentestReport = lazy(() => import("./pages/PentestReport"));
const AtomicRedTeam = lazy(() => import("./pages/AtomicRedTeam"));
const SliverC2 = lazy(() => import("./pages/SliverC2"));
const NucleiScanner = lazy(() => import("./pages/NucleiScanner"));
const AttackCoverage = lazy(() => import("./pages/AttackCoverage"));
const UnifiedPipeline = lazy(() => import("./pages/UnifiedPipeline"));
const RoeBuilder = lazy(() => import("./pages/RoeBuilder"));
const KsiDashboard = lazy(() => import("./pages/KsiDashboard"));
const KsiEvidenceChain = lazy(() => import("./pages/KsiEvidenceChain"));
const KsiValidation = lazy(() => import("./pages/KsiValidation"));
const OscalExport = lazy(() => import("./pages/OscalExport"));
const KsiAutoCollector = lazy(() => import("./pages/KsiAutoCollector"));
const KsiThreatMap = lazy(() => import("./pages/KsiThreatMap"));
const ConfigBaseline = lazy(() => import("./pages/ConfigBaseline"));
const AttackVectorEngine = lazy(() => import("./pages/AttackVectorEngine"));
const ScheduledCollection = lazy(() => import("./pages/ScheduledCollection"));
const EngagementAutomation = lazy(() => import("./pages/EngagementAutomation"));
const ThreatEnrichment = lazy(() => import("./pages/ThreatEnrichment"));
const InfraWiki = lazy(() => import("./pages/InfraWiki"));
const LiveInfra = lazy(() => import("./pages/LiveInfra"));
const Workflows = lazy(() => import("./pages/Workflows"));
const WebCrawler = lazy(() => import("./pages/WebCrawler"));
const VendorIntegrations = lazy(() => import("./pages/VendorIntegrations"));
const AgentManagerPage = lazy(() => import("./pages/AgentManager"));
const FIPSCompliance = lazy(() => import("./pages/FIPSCompliance"));
const SSILDashboard = lazy(() => import("./pages/SSILDashboard"));
const SSILPolicies = lazy(() => import("./pages/SSILPolicies"));
const SSILGuardrails = lazy(() => import("./pages/SSILGuardrails"));
const SSILObservations = lazy(() => import("./pages/SSILObservations"));
const SSILRiskCardDetail = lazy(() => import("./pages/SSILRiskCardDetail"));
const SSILAlertRules = lazy(() => import("./pages/SSILAlertRules"));
const SSILCorrelation = lazy(() => import("./pages/SSILCorrelation"));
const SubfinderPage = lazy(() => import("./pages/SubfinderPage"));
const HttpxPage = lazy(() => import("./pages/HttpxPage"));
const NaabuPage = lazy(() => import("./pages/NaabuPage"));
const AbilityGraphPage = lazy(() => import("./pages/AbilityGraph"));
const GraphComparePage = lazy(() => import("./pages/GraphCompare"));
const C2CommandCenter = lazy(() => import("./pages/C2CommandCenter"));
const ThreatActorCrawler = lazy(() => import("./pages/ThreatActorCrawler"));
const AISecurityValidation = lazy(() => import("./pages/AISecurityValidation"));
const DiscoveryChain = lazy(() => import("./pages/DiscoveryChain"));
const ErrorDashboard = lazy(() => import("./pages/ErrorDashboard"));
const OemCredentials = lazy(() => import("./pages/OemCredentials"));

// Hub pages (consolidated tab navigation)
const DiscoveryToolkitHub = lazy(() => import("./pages/DiscoveryToolkitHub"));
const VulnScanningHub = lazy(() => import("./pages/VulnScanningHub"));
const ScanManagementHub = lazy(() => import("./pages/ScanManagementHub"));
const ADSecurityHub = lazy(() => import("./pages/ADSecurityHub"));
const RiskCenterHub = lazy(() => import("./pages/RiskCenterHub"));
const AutomationHub = lazy(() => import("./pages/AutomationHub"));
const DefenseTestingHub = lazy(() => import("./pages/DefenseTestingHub"));
const C2Hub = lazy(() => import("./pages/C2Hub"));
const PhishingAssetsHub = lazy(() => import("./pages/PhishingAssetsHub"));
const CredentialCenterHub = lazy(() => import("./pages/CredentialCenterHub"));
const DataExportHub = lazy(() => import("./pages/DataExportHub"));
const KsiHub = lazy(() => import("./pages/KsiHub"));
const ComplianceHub = lazy(() => import("./pages/ComplianceHub"));
const ReportsHub = lazy(() => import("./pages/ReportsHub"));
const GuidesHub = lazy(() => import("./pages/GuidesHub"));
const IntegrationsHub = lazy(() => import("./pages/IntegrationsHub"));
const SSILHub = lazy(() => import("./pages/SSILHub"));
const InfrastructureHub = lazy(() => import("./pages/InfrastructureHub"));
const TeamHub = lazy(() => import("./pages/TeamHub"));
const DetectionHub = lazy(() => import("./pages/DetectionHub"));
const BatchDomainScanner = lazy(() => import("./pages/BatchDomainScanner"));
const OpsecDashboard = lazy(() => import("./pages/OpsecDashboard"));
const KillChainVisualizer = lazy(() => import("./pages/KillChainVisualizer"));
const LateralMovement = lazy(() => import("./pages/LateralMovement"));
const ExploitationBridge = lazy(() => import("./pages/ExploitationBridge"));
const PrivilegeEscalation = lazy(() => import("./pages/PrivilegeEscalation"));
const CampaignAdvisor = lazy(() => import("./pages/CampaignAdvisor"));
const ExportCenter = lazy(() => import("./pages/ExportCenter"));
const ScanServerHealth = lazy(() => import("./pages/ScanServerHealth"));
const RoleHome = lazy(() => import("./pages/home/RoleHome"));
const ToolComparison = lazy(() => import("./pages/ToolComparison"));
const AccountSettings = lazy(() => import("./pages/AccountSettings"));
const TeamManagementPage = lazy(() => import("./pages/TeamManagement"));
const AcceptInvite = lazy(() => import("./pages/AcceptInvite"));
const SamlConfig = lazy(() => import("./pages/SamlConfig"));
const SessionManagement = lazy(() => import("./pages/SessionManagement"));
const TenantOnboarding = lazy(() => import("./pages/TenantOnboarding"));
const ComplianceDashboard = lazy(() => import("./pages/ComplianceDashboard"));
const ScanWebhooks = lazy(() => import("./pages/ScanWebhooks"));
const AuthAssessment = lazy(() => import("./pages/AuthAssessment"));
const AuthPipeline = lazy(() => import("./pages/AuthPipeline"));
const CloudSecurityValidation = lazy(() => import("./pages/CloudSecurityValidation"));
const SigmaRuleGenerator = lazy(() => import("./pages/SigmaRuleGenerator"));
const ControlTesting = lazy(() => import("./pages/ControlTesting"));

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
  const [, setLocation] = useLocation();
  const { data: session, isLoading } = trpc.calderaAuth.session.useQuery();

  useEffect(() => {
    if (!isLoading && !session?.authenticated) {
      setLocation("/login");
    }
  }, [isLoading, session, setLocation]);

  if (isLoading) {
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

  if (!session?.authenticated) {
    return null;
  }

  return (
    <PageErrorBoundary pageName={pageName ?? Component.displayName ?? Component.name ?? 'Page'}>
      <Component />
    </PageErrorBoundary>
  );
}

function Router() {
  return (
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
        <Route path="/reports/security">
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
        <Route path="/phishing-exploit-catalog">
          <Redirect to="/exploit-catalog" />
        </Route>
        <Route path="/exploit-arsenal">
          <Redirect to="/exploit-catalog" />
        </Route>
        <Route path="/exploit-catalog">
          <ProtectedRoute component={ExploitArsenal} />
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
        <Route path="/404" component={NotFound} />
        <Route component={NotFound} />
      </Switch>
    </Suspense>
  );
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
            <GlobalAiChat />
          </TooltipProvider>
        </EngagementProvider>
      </ThemeProvider>
    </ErrorBoundary>
  );
}

export default App;
