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
