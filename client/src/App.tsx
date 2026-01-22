import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import NotFound from "@/pages/NotFound";
import { Route, Switch } from "wouter";
import ErrorBoundary from "./components/ErrorBoundary";
import { ThemeProvider } from "./contexts/ThemeContext";
import Home from "./pages/Home";
import Dashboard from "./pages/Dashboard";
import Credentials from "./pages/Credentials";
import Adversaries from "./pages/Adversaries";
import AdversaryDetail from "./pages/AdversaryDetail";
import Team from "./pages/Team";
import Activity from "./pages/Activity";

function Router() {
  return (
    <Switch>
      <Route path="/" component={Home} />
      <Route path="/dashboard" component={Dashboard} />
      <Route path="/credentials" component={Credentials} />
      <Route path="/adversaries" component={Adversaries} />
      <Route path="/adversaries/:id" component={AdversaryDetail} />
      <Route path="/team" component={Team} />
      <Route path="/activity" component={Activity} />
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
