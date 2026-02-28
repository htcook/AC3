import React, { lazy, Suspense } from 'react';
import AppShell from '@/components/AppShell';
import HubTabs from '@/components/HubTabs';
import { Workflow, Rocket, GitBranch } from 'lucide-react';

const EngagementAutomation = lazy(() => import('./EngagementAutomation'));
const CampaignExecution = lazy(() => import('./CampaignExecution'));
const EngagementPipeline = lazy(() => import('./EngagementPipeline'));

const tabs = [
  {
    id: 'automation',
    label: 'Automation',
    icon: Workflow,
    component: EngagementAutomation,
  },
  {
    id: 'execution',
    label: 'Campaign Exec',
    icon: Rocket,
    component: CampaignExecution,
  },
  {
    id: 'pipeline',
    label: 'Auto Pipeline',
    icon: GitBranch,
    component: EngagementPipeline,
  },
];

export default function AutomationHub() {
  return (
    <AppShell activePath="/engagement-automation">
      <div className="w-full">
        <div className="mb-4">
          <h1 className="text-2xl font-bold tracking-wider font-display">
            <Workflow className="inline-block w-6 h-6 mr-2" />
            Automation Hub
          </h1>
          <p className="text-muted-foreground">
            Engagement automation, campaign execution, and pipeline orchestration
          </p>
        </div>
        <Suspense fallback={<div>Loading...</div>}>
          <HubTabs tabs={tabs} storageKey="automation-hub" />
        </Suspense>
      </div>
    </AppShell>
  );
}
