import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { Route, Switch, Redirect, useLocation } from "wouter";
import ErrorBoundary from "./components/ErrorBoundary";
import { ThemeProvider } from "./contexts/ThemeContext";
import { trpc } from "@/lib/trpc";
import { Skeleton } from "@/components/ui/skeleton";
import { lazy, Suspense, useEffect } from "react";

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
const TemplateGenerator = lazy(() => import("./pages/TemplateGenerator"));
const AbilitiesLibrary = lazy(() => import("./pages/AbilitiesLibrary"));
const IOCFeed = lazy(() => import("./pages/IOCFeed"));
const EngagementPipeline = lazy(() => import("./pages/EngagementPipeline"));
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
function ProtectedRoute({ component: Component }: { component: React.ComponentType }) {
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

  return <Component />;
}

function Router() {
  return (
    <Suspense fallback={<PageLoader />}>
      <Switch>
        <Route path="/" component={Home} />
        <Route path="/login" component={Login} />
        <Route path="/dashboard">
          <ProtectedRoute component={Dashboard} />
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
          <ProtectedRoute component={Team} />
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
          <ProtectedRoute component={ReportGenerator} />
        </Route>
        <Route path="/phishing-ops">
          <ProtectedRoute component={PhishingOperations} />
        </Route>
        <Route path="/gophish">
          <Redirect to="/phishing-ops" />
        </Route>
        <Route path="/guide/gophish">
          <ProtectedRoute component={GoPhishGuide} />
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
          <ProtectedRoute component={ComplianceFrameworks} />
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
          <ProtectedRoute component={DetectionCoverage} />
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
          <ProtectedRoute component={StixExport} />
        </Route>
        <Route path="/campaign-archetypes">
          <ProtectedRoute component={CampaignArchetypes} />
        </Route>
        <Route path="/post-engagement-report">
          <ProtectedRoute component={PostEngagementReport} />
        </Route>
        <Route path="/landing-page-builder">
          <ProtectedRoute component={LandingPageBuilder} />
        </Route>
        <Route path="/engagements/:id/results">
          {() => <ProtectedRoute component={EngagementResults} />}
        </Route>
        <Route path="/engagements/:id/recon">
          {() => <ProtectedRoute component={OsintRecon} />}
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
          <ProtectedRoute component={SiemConnectors} />
        </Route>
        <Route path="/webhooks">
          <ProtectedRoute component={Webhooks} />
        </Route>
        <Route path="/bug-bounty">
          <ProtectedRoute component={BugBountyHub} />
        </Route>
        <Route path="/scoring">
          <ProtectedRoute component={ScoringHub} />
        </Route>
        <Route path="/bia-report">
          <ProtectedRoute component={BiaReport} />
        </Route>
        <Route path="/portal/:token" component={ClientPortal} />
        <Route path="/cloud-attack-paths">
          <ProtectedRoute component={CloudAttackPaths} />
        </Route>
        <Route path="/ad-attack-sim">
          <ProtectedRoute component={ADAttackSim} />
        </Route>
        <Route path="/edr-validation">
          <ProtectedRoute component={EDRValidation} />
        </Route>
        <Route path="/compliance-mapper">
          <ProtectedRoute component={ComplianceMapper} />
        </Route>
        <Route path="/api-security-testing">
          <ProtectedRoute component={APISecurityTesting} />
        </Route>
        <Route path="/cloud-credentials">
          <ProtectedRoute component={CloudCredentials} />
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
        <Route path="/404" component={NotFound} />
        <Route component={NotFound} />
      </Switch>
    </Suspense>
  );
}

function App() {
  return (
    <ErrorBoundary>
      <ThemeProvider defaultTheme="dark">
        <TooltipProvider>
          <Toaster />
          <Router />
        </TooltipProvider>
      </ThemeProvider>
    </ErrorBoundary>
  );
}

export default App;
