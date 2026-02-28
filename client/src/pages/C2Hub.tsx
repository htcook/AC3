
import React, { lazy, LazyExoticComponent, ComponentType } from 'react';
import AppShell from '@/components/AppShell';
import HubTabs from '@/components/HubTabs';
import { Terminal, Server, Cpu } from 'lucide-react';

const C2CommandCenter = lazy(() => import('./C2CommandCenter'));
const MsfServers = lazy(() => import('./MsfServers'));
const SliverC2 = lazy(() => import('./SliverC2'));

const tabs: { id: string; label: string; icon?: ComponentType<{className?:string}>; component: LazyExoticComponent<ComponentType<any>> | ComponentType<any> }[] = [
  { id: 'c2', label: 'C2 Command Center', component: C2CommandCenter, icon: Terminal },
  { id: 'msf', label: 'MSF Servers', component: MsfServers, icon: Server },
  { id: 'sliver', label: 'Sliver C2', component: SliverC2, icon: Cpu },
];

const C2Hub: React.FC = () => {
  return (
    <AppShell activePath="/c2-command-center">
      <div className="flex items-center space-x-4 p-4">
        <Terminal className="h-10 w-10" />
        <div>
          <h1 className="font-display text-2xl font-bold tracking-wider">C2 Command Hub</h1>
          <p className="text-muted-foreground">Command and control server management across frameworks</p>
        </div>
      </div>
      <HubTabs tabs={tabs} storageKey="c2-hub" />
    </AppShell>
  );
};

export default C2Hub;
