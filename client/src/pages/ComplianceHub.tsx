
import AppShell from '@/components/AppShell';
import HubTabs from '@/components/HubTabs';
import {
  ClipboardCheck,
  ArrowLeftRight,
  Lock,
  Settings,
} from 'lucide-react';
import React, { lazy } from 'react';

const ComplianceFrameworks = lazy(() => import('./ComplianceFrameworks'));
const ComplianceMapper = lazy(() => import('./ComplianceMapper'));
const FIPSCompliance = lazy(() => import('./FIPSCompliance'));
const ConfigBaseline = lazy(() => import('./ConfigBaseline'));

const ComplianceHub = () => {
  const tabs = [
    {
      id: 'frameworks',
      label: 'Frameworks',
      icon: ClipboardCheck,
      component: ComplianceFrameworks,
    },
    {
      id: 'mapper',
      label: 'Mapper',
      icon: ArrowLeftRight,
      component: ComplianceMapper,
    },
    {
      id: 'fips',
      label: 'FIPS',
      icon: Lock,
      component: FIPSCompliance,
    },
    {
      id: 'baseline',
      label: 'Config Baseline',
      icon: Settings,
      component: ConfigBaseline,
    },
  ];

  return (
    <AppShell activePath="/compliance">
      <div className="w-full">
        <div className="flex items-center gap-4 pb-4 text-foreground">
          <ClipboardCheck className="h-8 w-8" />
          <div>
            <h1 className="font-display text-2xl tracking-wider">
              Compliance Center
            </h1>
            <p className="text-sm text-muted-foreground">
              Compliance frameworks, mapping, FIPS, and configuration baselines
            </p>
          </div>
        </div>
        <HubTabs tabs={tabs} storageKey="compliance-center" />
      </div>
    </AppShell>
  );
};

export default ComplianceHub;
