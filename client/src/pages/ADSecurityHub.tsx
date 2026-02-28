import AppShell from "@/components/AppShell";
import HubTabs from "@/components/HubTabs";
import React, { lazy } from "react";
import {
  Shield, Swords, Database, GitBranch, Layers, Upload, Search
} from "lucide-react";

const ADAttackSim = lazy(() => import('./ADAttackSim'));
const ADDomainConnector = lazy(() => import('./ADDomainConnector'));
const ADAttackPathGraph = lazy(() => import('./ADAttackPathGraph'));
const ForestMapper = lazy(() => import('./ForestMapper'));
const BloodHoundImport = lazy(() => import('./BloodHoundImport'));
const AttackPathDiscovery = lazy(() => import('./AttackPathDiscovery'));

const ADSecurityHub = () => {
  const tabs = [
    { id: 'attack-sim', label: 'Attack Simulation', icon: Swords, component: ADAttackSim },
    { id: 'connector', label: 'Domain Connector', icon: Database, component: ADDomainConnector },
    { id: 'path-graph', label: 'Path Graph', icon: GitBranch, component: ADAttackPathGraph },
    { id: 'forest', label: 'Forest Mapper', icon: Layers, component: ForestMapper },
    { id: 'bloodhound', label: 'BloodHound Import', icon: Upload, component: BloodHoundImport },
    { id: 'discovery', label: 'Path Discovery', icon: Search, component: AttackPathDiscovery },
  ];

  return (
    <AppShell activePath="/ad-attack-sim">
      <div className="w-full">
        <div className="flex items-center space-x-2 mb-4">
          <Shield className="w-6 h-6" />
          <h1 className="text-2xl font-display tracking-wider">AD Security</h1>
        </div>
        <p className="text-gray-500 mb-6">Active Directory attack simulation, domain analysis, and path discovery</p>
        <HubTabs tabs={tabs} storageKey="ad-security" />
      </div>
    </AppShell>
  );
};

export default ADSecurityHub;
