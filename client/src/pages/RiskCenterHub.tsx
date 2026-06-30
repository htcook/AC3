import React, { ComponentType, lazy, LazyExoticComponent } from 'react';
import { BarChart3, CheckCircle2, Database, TrendingUp, Workflow } from 'lucide-react';

import AppShell from '@/components/AppShell';
import HubTabs from '@/components/HubTabs';

const ScoringHub = lazy(() => import('./ScoringHub'));
const RiskTrending = lazy(() => import('./RiskTrending'));
const CorroborationEngine = lazy(() => import('./CorroborationEngine'));
const NvdCveMatcher = lazy(() => import('./NvdCveMatcher'));
const UnifiedPipeline = lazy(() => import('./UnifiedPipeline'));

const tabs: {
  id: string;
  label: string;
  icon?: ComponentType<{ className?: string }>;
  component: LazyExoticComponent<ComponentType<any>> | ComponentType<any>;
}[] = [
  { id: 'scoring', label: 'Risk Scoring', icon: BarChart3, component: ScoringHub },
  { id: 'trending', label: 'Trending', icon: TrendingUp, component: RiskTrending },
  { id: 'corroboration', label: 'Corroboration', icon: CheckCircle2, component: CorroborationEngine },
  { id: 'nvd', label: 'NVD CVE Matcher', icon: Database, component: NvdCveMatcher },
  { id: 'pipeline', label: 'Unified Pipeline', icon: Workflow, component: UnifiedPipeline },
];

export default function RiskCenterHub() {
  return (
    <AppShell activePath="/scoring">
      <div className="flex items-center">
        <div className="pr-4">
          <BarChart3 size={48} />
        </div>
        <div>
          <h1 className="font-display text-4xl tracking-wider">Risk Center</h1>
          <p className="text-lg text-gray-500">
            Risk scoring, trending analysis, corroboration, and vulnerability matching
          </p>
        </div>
      </div>
      <HubTabs tabs={tabs} storageKey="risk-center" />
    </AppShell>
  );
}
