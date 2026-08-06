import React, { ComponentType, lazy, LazyExoticComponent } from 'react';
import { FileJson, FileText } from 'lucide-react';

import AppShell from '@/components/AppShell';
import HubTabs from '@/components/HubTabs';

const StixExport = lazy(() => import('./StixExport'));
const OscalExport = lazy(() => import('./OscalExport'));

const tabs: { id: string; label: string; icon?: ComponentType<{className?:string}>; component: LazyExoticComponent<ComponentType<any>> | ComponentType<any> }[] = [
  {
    id: 'stix',
    label: 'STIX/TAXII Export',
    icon: FileJson,
    component: StixExport,
  },
  {
    id: 'oscal',
    label: 'OSCAL Export',
    icon: FileText,
    component: OscalExport,
  },
];

const DataExportHub: React.FC = () => {
  return (
    <AppShell activePath="/stix-export">
      <div className="w-full">
        <div className="flex items-center space-x-2">
          <FileJson className="h-6 w-6" />
          <h1 className="font-display text-2xl font-bold tracking-wider">Data Export</h1>
        </div>
        <p className="mt-2 text-gray-500">
          STIX/TAXII and OSCAL export for threat intelligence sharing
        </p>
        <div className="mt-6">
          <HubTabs tabs={tabs} storageKey="data-export" />
        </div>
      </div>
    </AppShell>
  );
};

export default DataExportHub;
