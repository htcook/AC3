
import React, { lazy, Suspense, ComponentType, LazyExoticComponent } from 'react';
import AppShell from '@/components/AppShell';
import HubTabs from '@/components/HubTabs';
import { Bug, ShieldAlert, Plug, ShieldCheck, Box } from 'lucide-react';

const NucleiScanner = lazy(() => import('./NucleiScanner'));
const VulnScanner = lazy(() => import('./VulnScanner'));
const ScannerApiIntegration = lazy(() => import('./ScannerApiIntegration'));
const ComplianceScanner = lazy(() => import('./ComplianceScanner'));
const ContainerRegistry = lazy(() => import('./ContainerRegistry'));

const tabs: { id: string; label: string; icon?: ComponentType<{className?:string}>; component: LazyExoticComponent<ComponentType<any>> | ComponentType<any> }[] = [
  { id: 'nuclei', label: 'Nuclei Scanner', icon: Bug, component: NucleiScanner },
  { id: 'vuln', label: 'Vuln Scanner', icon: ShieldAlert, component: VulnScanner },
  { id: 'scanner-api', label: 'Scanner API', icon: Plug, component: ScannerApiIntegration },
  { id: 'compliance', label: 'Compliance', icon: ShieldCheck, component: ComplianceScanner },
  { id: 'container-registry', label: 'Container Registry', icon: Box, component: ContainerRegistry },
];

const VulnScanningHub = () => {
  return (
    <AppShell activePath="/nuclei-scanner">
      <div className="flex flex-col h-full">
        <div className="shrink-0">
          <div className="flex items-center space-x-2">
            <Bug className="w-6 h-6" />
            <h1 className="text-2xl font-bold font-display tracking-wider">Vulnerability Scanning</h1>
          </div>
          <p className="text-muted-foreground mt-1">
            Nuclei template scanning, vulnerability assessment, scanner integration, compliance auditing, and container registry scanning
          </p>
        </div>
        <div className="flex-grow mt-6">
          <Suspense fallback={<div>Loading...</div>}>
            <HubTabs tabs={tabs} storageKey="vuln-scanning" />
          </Suspense>
        </div>
      </div>
    </AppShell>
  );
};

export default VulnScanningHub;
