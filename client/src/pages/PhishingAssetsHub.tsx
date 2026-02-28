import React, { lazy } from 'react';
import { Palette, FileText } from 'lucide-react';
import AppShell from '@/components/AppShell';
import HubTabs from '@/components/HubTabs';

const LandingPageBuilder = lazy(() => import('./LandingPageBuilder'));
const TemplateGenerator = lazy(() => import('./TemplateGenerator'));

const PhishingAssetsHub: React.FC = () => {
  const tabs = [
    {
      id: 'pages',
      label: 'Page Builder',
      icon: Palette,
      component: LandingPageBuilder,
    },
    {
      id: 'templates',
      label: 'Template Generator',
      icon: FileText,
      component: TemplateGenerator,
    },
  ];

  return (
    <AppShell activePath="/landing-page-builder">
      <div className="w-full">
        <div className="flex items-center space-x-2 mb-4">
          <Palette className="w-6 h-6" />
          <h1 className="text-2xl font-display tracking-wider">Phishing Assets</h1>
        </div>
        <p className="text-muted-foreground mb-6">
          Landing page builder and email template generator
        </p>
        <HubTabs tabs={tabs} storageKey="phishing-assets" />
      </div>
    </AppShell>
  );
};

export default PhishingAssetsHub;
