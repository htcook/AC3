import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import NotFound from "@/pages/NotFound";
import { Route, Switch, Redirect, useLocation } from "wouter";
import ErrorBoundary from "./components/ErrorBoundary";
import { ThemeProvider } from "./contexts/ThemeContext";
import Home from "./pages/Home";
import Dashboard from "./pages/Dashboard";
import Credentials from "./pages/Credentials";
import Adversaries from "./pages/Adversaries";
import AdversaryDetail from "./pages/AdversaryDetail";
import Team from "./pages/Team";
import Activity from "./pages/Activity";
import Campaigns from "./pages/Campaigns";
import CampaignDetail from "./pages/CampaignDetail";
import Agents from "./pages/Agents";
import AgentDeploy from "./pages/AgentDeploy";
import OperationMonitor from "./pages/OperationMonitor";
import ReportGenerator from "./pages/ReportGenerator";
import OperationDetail from "./pages/OperationDetail";
import GoPhish from "./pages/GoPhish";
import GoPhishGuide from "./pages/GoPhishGuide";
import CalderaGuide from "./pages/CalderaGuide";
import SecurityReport from "./pages/SecurityReport";
import APTLibrary from "./pages/APTLibrary";
import ComplianceFrameworks from "./pages/ComplianceFrameworks";
import InfraReference from "./pages/InfraReference";
import TemplateLibrary from "./pages/TemplateLibrary";
import Engagements from "./pages/Engagements";
import CampaignWizard from "./pages/CampaignWizard";
import EngagementResults from "./pages/EngagementResults";
import OsintRecon from "./pages/OsintRecon";
import DomainRecon from "./pages/DomainRecon";
import OsintMonitor from "./pages/OsintMonitor";
import DomainIntel from "./pages/DomainIntel";
import DomainIntelResults from "./pages/DomainIntelResults";
import TemplateGenerator from "./pages/TemplateGenerator";
import AbilitiesLibrary from "./pages/AbilitiesLibrary";
import IOCFeed from "./pages/IOCFeed";
import EngagementPipeline from "./pages/EngagementPipeline";
import ThreatActors from "./pages/ThreatActors";
import ThreatActorDetail from "./pages/ThreatActorDetail";
import TtpKnowledge from "./pages/TtpKnowledge";
import CampaignExecution from "./pages/CampaignExecution";
import RuleValidator from "./pages/RuleValidator";
import DetectionCoverage from "./pages/DetectionCoverage";
import PostEngagementReport from "./pages/PostEngagementReport";
import LandingPageBuilder from "./pages/LandingPageBuilder";
import DiscoveryCuration from "./pages/DiscoveryCuration";
import KevDashboard from "./pages/KevDashboard";
import ScanComparison from "./pages/ScanComparison";
import ThreatCatalog from "./pages/ThreatCatalog";
import ThreatActorCatalogDetail from "./pages/ThreatActorCatalogDetail";
import RansomwareGroups from "./pages/RansomwareGroups";
import RansomwareGroupDetail from "./pages/RansomwareGroupDetail";
import DarkwebIntel from "./pages/DarkwebIntel";
import CampaignArchetypes from "./pages/CampaignArchetypes";
import Login from "./pages/Login";
import { trpc } from "@/lib/trpc";
import { Skeleton } from "@/components/ui/skeleton";

import { useEffect } from "react";

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
    <Switch>
      <Route path="/" component={Home} />
      <Route path="/login" component={Login} />
      <Route path="/dashboard">
        <ProtectedRoute component={Dashboard} />
      </Route>
      <Route path="/engagements">
        <ProtectedRoute component={Engagements} />
      </Route>
      <Route path="/credentials">
        <ProtectedRoute component={Credentials} />
      </Route>
      <Route path="/adversaries">
        <ProtectedRoute component={Adversaries} />
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
        <ProtectedRoute component={Campaigns} />
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
      <Route path="/gophish">
        <ProtectedRoute component={GoPhish} />
      </Route>
      <Route path="/guide/gophish">
        <ProtectedRoute component={GoPhishGuide} />
      </Route>
      <Route path="/guide/caldera">
        <ProtectedRoute component={CalderaGuide} />
      </Route>
      <Route path="/reports/security">
        <ProtectedRoute component={SecurityReport} />
      </Route>
      <Route path="/apt-library">
        <ProtectedRoute component={APTLibrary} />
      </Route>
      <Route path="/compliance">
        <ProtectedRoute component={ComplianceFrameworks} />
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
        <ProtectedRoute component={DomainRecon} />
      </Route>
      <Route path="/osint-monitor">
        <ProtectedRoute component={OsintMonitor} />
      </Route>
      <Route path="/domain-intel">
        <ProtectedRoute component={DomainIntel} />
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
        <ProtectedRoute component={ThreatActors} />
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
      <Route path="/threat-catalog">
        <ProtectedRoute component={ThreatCatalog} />
      </Route>
      <Route path="/threat-catalog/:id">
        {() => <ProtectedRoute component={ThreatActorCatalogDetail} />}
      </Route>
      <Route path="/ransomware-groups">
        <ProtectedRoute component={RansomwareGroups} />
      </Route>
      <Route path="/ransomware-groups/:name">
        {() => <ProtectedRoute component={RansomwareGroupDetail} />}
      </Route>
      <Route path="/darkweb-intel">
        <ProtectedRoute component={DarkwebIntel} />
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
      <Route path="/404" component={NotFound} />
      <Route component={NotFound} />
    </Switch>
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
