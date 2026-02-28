import AppShell from "@/components/AppShell";
import HubTabs from "@/components/HubTabs";
import React, { lazy } from "react";
import { ShieldCheck, Shield, Cpu, Server, Mail, Brain, FileCheck, CheckCircle2, Wrench } from "lucide-react";

const EDRValidation = lazy(() => import("./EDRValidation"));
const AgentlessBAS = lazy(() => import("./AgentlessBAS"));
const NgfwValidation = lazy(() => import("./NgfwValidation"));
const EmailSecurity = lazy(() => import("./EmailSecurity"));
const AISecurityValidation = lazy(() => import("./AISecurityValidation"));
const RuleValidator = lazy(() => import("./RuleValidator"));
const ActiveVerification = lazy(() => import("./ActiveVerification"));
const RemediationVerification = lazy(() => import("./RemediationVerification"));

const DefenseTestingHub = () => {
  const tabs = [
    { id: "edr", label: "EDR Validation", icon: Shield, component: EDRValidation },
    { id: "agentless", label: "Agentless BAS", icon: Cpu, component: AgentlessBAS },
    { id: "ngfw", label: "NGFW Testing", icon: Server, component: NgfwValidation },
    { id: "email", label: "Email Security", icon: Mail, component: EmailSecurity },
    { id: "ai", label: "AI Security", icon: Brain, component: AISecurityValidation },
    { id: "rules", label: "Rule Validator", icon: FileCheck, component: RuleValidator },
    { id: "active", label: "Active Verification", icon: CheckCircle2, component: ActiveVerification },
    { id: "remediation", label: "Remediation Verify", icon: Wrench, component: RemediationVerification },
  ];

  return (
    <AppShell activePath="/edr-validation">
      <div className="w-full">
        <div className="flex items-center space-x-2 mb-4">
          <ShieldCheck className="w-6 h-6" />
          <h1 className="text-2xl font-display tracking-wider">Defense Testing</h1>
        </div>
        <p className="text-muted-foreground mb-6">
          EDR, firewall, email security, and AI security validation
        </p>
        <HubTabs tabs={tabs} storageKey="defense-testing" />
      </div>
    </AppShell>
  );
};

export default DefenseTestingHub;
