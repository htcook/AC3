import React, { lazy } from 'react';
import AppShell from '@/components/AppShell';
import HubTabs from '@/components/HubTabs';
import { Clock, ArrowLeftRight, ScrollText } from 'lucide-react';

const ScanScheduler = lazy(() => import('./ScanScheduler'));
const ScanComparison = lazy(() => import('./ScanComparison'));
const ScanHistory = lazy(() => import('./ScanHistory'));

const tabs = [
  { id: 'scheduler', label: 'Scheduler', icon: Clock, component: ScanScheduler },
  { id: 'compare', label: 'Compare', icon: ArrowLeftRight, component: ScanComparison },
  { id: 'history', label: 'History', icon: ScrollText, component: ScanHistory },
];

export default function ScanManagementHub() {
  return (
    <AppShell activePath="/scan-scheduler">
      <div className="flex items-center mb-4">
        <Clock className="w-6 h-6 mr-2" />
        <h1 className="text-2xl font-display tracking-wider">Scan Management</h1>
      </div>
      <p className="mb-6 text-gray-500">Schedule, compare, and review scan history</p>
      <HubTabs tabs={tabs} storageKey="scan-management" />
    </AppShell>
  );
}
