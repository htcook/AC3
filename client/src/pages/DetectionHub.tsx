
import AppShell from '@/components/AppShell';
import HubTabs from '@/components/HubTabs';
import { Eye, Swords } from 'lucide-react';
import React, { lazy } from 'react';

const DetectionCoverage = lazy(() => import('./DetectionCoverage'));
const PurpleTeam = lazy(() => import('./PurpleTeam'));

const DetectionHub = () => {
  const tabs = [
    {
      id: 'coverage',
      label: 'Coverage Matrix',
      icon: Eye,
      component: DetectionCoverage,
    },
    {
      id: 'purple',
      label: 'Purple Team',
      icon: Swords,
      component: PurpleTeam,
    },
  ];

  return (
    <AppShell activePath="/detection-coverage">
      <div className="flex items-center mb-4">
        <Eye className="w-6 h-6 mr-2" />
        <h1 className="font-display tracking-wider text-2xl">Detection Coverage</h1>
      </div>
      <p className="mb-6">Detection coverage matrix and purple team exercises</p>
      <HubTabs tabs={tabs} storageKey="detection-hub" />
    </AppShell>
  );
};

export default DetectionHub;
