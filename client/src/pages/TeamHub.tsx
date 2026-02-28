import React, { lazy, ComponentType, LazyExoticComponent } from 'react';
import AppShell from '@/components/AppShell';
import HubTabs from '@/components/HubTabs';
import { Users, Building, Activity } from 'lucide-react';

const Team = lazy(() => import('./Team'));
const Tenants = lazy(() => import('./Tenants'));
const ActivityTab = lazy(() => import('./Activity'));

const tabs: { id: string; label: string; icon?: ComponentType<{className?:string}>; component: LazyExoticComponent<ComponentType<any>> | ComponentType<any> }[] = [
  {
    id: 'team',
    label: 'Team',
    icon: Users,
    component: Team,
  },
  {
    id: 'tenants',
    label: 'Tenants',
    icon: Building,
    component: Tenants,
  },
  {
    id: 'activity',
    label: 'Activity',
    icon: Activity,
    component: ActivityTab,
  },
];

const TeamHub = () => {
  return (
    <AppShell activePath="/team">
      <div className="flex items-center mb-4">
        <Users className="w-6 h-6 mr-2" />
        <div>
          <h1 className="text-lg font-semibold font-display tracking-wider">Team Management</h1>
          <p className="text-sm text-gray-500">Team members, tenant management, and activity logs</p>
        </div>
      </div>
      <HubTabs tabs={tabs} storageKey="team-hub" />
    </AppShell>
  );
};

export default TeamHub;
