import React, { ComponentType, lazy, LazyExoticComponent } from 'react';
import AppShell from '@/components/AppShell';
import HubTabs from '@/components/HubTabs';
import { BarChart3, FileText, Shield, Eye, AlertTriangle, GitBranch } from 'lucide-react';

const SSILDashboard = lazy(() => import('./SSILDashboard'));
const SSILPolicies = lazy(() => import('./SSILPolicies'));
const SSILGuardrails = lazy(() => import('./SSILGuardrails'));
const SSILObservations = lazy(() => import('./SSILObservations'));
const SSILAlertRules = lazy(() => import('./SSILAlertRules'));
const SSILCorrelation = lazy(() => import('./SSILCorrelation'));

const tabs: { id: string; label: string; icon?: ComponentType<{className?:string}>; component: LazyExoticComponent<ComponentType<any>> | ComponentType<any> }[] = [
  { id: 'dashboard', label: 'Dashboard', icon: BarChart3, component: SSILDashboard },
  { id: 'policies', label: 'Policies', icon: FileText, component: SSILPolicies },
  { id: 'guardrails', label: 'LLM Guardrails', icon: Shield, component: SSILGuardrails },
  { id: 'observations', label: 'Observations', icon: Eye, component: SSILObservations },
  { id: 'alerts', label: 'Alert Rules', icon: AlertTriangle, component: SSILAlertRules },
  { id: 'correlation', label: 'Correlation', icon: GitBranch, component: SSILCorrelation },
];

export default function SSILHub() {
  return (
    <AppShell activePath="/ssil">
      <div className="w-full">
        <div className="mb-4">
          <h1 className="text-2xl font-bold tracking-wider font-display">SSIL</h1>
          <p className="text-sm text-muted-foreground">
            Security scanning, policies, guardrails, observations, and correlation
          </p>
        </div>
        <HubTabs tabs={tabs} storageKey="ssil-hub" />
      </div>
    </AppShell>
  );
}
