import React, { lazy } from 'react';
import { BookOpen, Cpu, Layers, Zap } from 'lucide-react';
import AppShell from '@/components/AppShell';
import HubTabs from '@/components/HubTabs';

const GoPhishGuide = lazy(() => import('./GoPhishGuide'));
const CalderaGuide = lazy(() => import('./CalderaGuide'));
const CampaignArchetypes = lazy(() => import('./CampaignArchetypes'));
const AbilitiesLibrary = lazy(() => import('./AbilitiesLibrary'));

const GuidesHub = () => {
  const tabs = [
    { id: 'gophish', label: 'Phishing Ops Guide', icon: BookOpen, component: GoPhishGuide },
    { id: 'caldera', label: 'Emulation Guide', icon: Cpu, component: CalderaGuide },
    { id: 'archetypes', label: 'Archetypes', icon: Layers, component: CampaignArchetypes },
    { id: 'abilities', label: 'Abilities', icon: Zap, component: AbilitiesLibrary },
  ];

  return (
    <AppShell activePath="/guide/gophish">
      <div className="flex items-center mb-4">
        <BookOpen className="w-6 h-6 mr-2" />
        <h1 className="text-2xl font-display tracking-wider">Guides & Knowledge</h1>
      </div>
      <p className="text-muted-foreground mb-6">Operational guides, template libraries, and ability references</p>
      <HubTabs tabs={tabs} storageKey="guides-hub" />
    </AppShell>
  );
};

export default GuidesHub;
